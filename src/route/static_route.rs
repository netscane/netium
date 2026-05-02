//! StaticRouter — evaluates configured routing rules (field, chinasites, chinaip, privateip, all).
//!
//! Rules are compiled at build time into efficient matchers. The thread-local
//! cache maps destinations directly to outbound tags.

use std::cell::RefCell;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use lru::LruCache;

use crate::app::metrics::{ROUTER_DECISIONS_TOTAL, ROUTER_RULE_MATCH_DURATION};
use crate::common::{Address, Metadata, Network};
use crate::geoip::GeoIpDb;
use crate::geosite::DomainEntry;

use super::matchers::{DomainMatcherBuilder, IpMatcherBuilder, PortMatcher, DomainMatcher, IpMatcher};
use super::rule::{Rule, RuleType};
use super::stats::{RuleStat, RuleStatsSnapshot};
use super::Router;

// ============================================================================
// StaticRule — a single compiled static rule
// ============================================================================

pub struct StaticRule {
    pub(crate) outbound_tag: String,
    pub(crate) is_catch_all: bool,
    pub(crate) inbound_tag: Vec<String>,
    pub(crate) protocol: Vec<String>,
    pub(crate) network: Vec<Network>,
    pub(crate) domain_matcher: Option<DomainMatcher>,
    pub(crate) ip_matcher: Option<IpMatcher>,
    pub(crate) port_matcher: Option<PortMatcher>,
}

impl StaticRule {
    pub fn select(&self, metadata: &Metadata) -> Option<String> {
        if self.is_catch_all {
            if self.check_metadata_filters(metadata) {
                return Some(self.outbound_tag.clone());
            }
            return None;
        }

        if !self.check_metadata_filters(metadata) {
            return None;
        }

        let has_domain = self.domain_matcher.is_some();
        let has_ip = self.ip_matcher.is_some();

        if !has_domain && !has_ip && self.port_matcher.is_none() {
            return Some(self.outbound_tag.clone());
        }

        if let Some(pm) = &self.port_matcher {
            if !pm.matches(metadata.destination.port()) {
                return None;
            }
        }

        let address_matches = match &metadata.destination {
            Address::Domain(domain, _) => {
                if let Some(dm) = &self.domain_matcher {
                    dm.matches(domain)
                } else {
                    !has_ip
                }
            }
            Address::Socket(addr) => {
                if let Some(im) = &self.ip_matcher {
                    im.matches(addr.ip())
                } else {
                    !has_domain
                }
            }
        };

        if address_matches {
            Some(self.outbound_tag.clone())
        } else {
            None
        }
    }

    fn check_metadata_filters(&self, metadata: &Metadata) -> bool {
        if !self.inbound_tag.is_empty()
            && !self
                .inbound_tag
                .iter()
                .any(|t| t.as_str() == &*metadata.inbound_tag)
        {
            return false;
        }
        if !self.protocol.is_empty() && !self.protocol.iter().any(|p| p == &metadata.protocol) {
            return false;
        }
        if !self.network.is_empty() && !self.network.contains(&metadata.network) {
            return false;
        }
        true
    }
}

// ============================================================================
// Route cache (thread-local, zero contention)
// ============================================================================

const ROUTE_CACHE_SIZE: usize = 4096;

thread_local! {
    static ROUTE_CACHE: RefCell<LruCache<String, String>> = RefCell::new(
        LruCache::new(std::num::NonZeroUsize::new(ROUTE_CACHE_SIZE).unwrap())
    );
}

// ============================================================================
// Metric handles
// ============================================================================

struct MetricHandles {
    duration: prometheus::Histogram,
}

// ============================================================================
// StaticRouter
// ============================================================================

pub struct StaticRouter {
    rules: Vec<StaticRule>,
    labels: Vec<String>,

    metric_handles: Vec<MetricHandles>,
    stats: Arc<Vec<RuleStat>>,
}

impl Router for StaticRouter {
    fn try_select(&self, metadata: &Metadata) -> Option<String> {
        ROUTER_DECISIONS_TOTAL.inc();

        let cache_key = Self::cache_key(&metadata.destination);
        let cached = ROUTE_CACHE.with(|cell| cell.borrow_mut().get(&cache_key).cloned());

        if let Some(outbound) = cached {
            return Some(outbound);
        }

        let select_start = Instant::now();

        for (i, rule) in self.rules.iter().enumerate() {
            let result = rule.select(metadata);

            self.stats[i].eval_count.fetch_add(1, Ordering::Relaxed);

            if let Some(outbound) = result {
                let stat = &self.stats[i];
                stat.hits.fetch_add(1, Ordering::Relaxed);

                let elapsed_ns = select_start.elapsed().as_nanos() as u64;
                stat.match_time_ns.fetch_add(elapsed_ns, Ordering::Relaxed);
                stat.max_ns.fetch_max(elapsed_ns, Ordering::Relaxed);

                let count = stat.eval_count.load(Ordering::Relaxed);
                if count % 16 == 0 {
                    self.metric_handles[i]
                        .duration
                        .observe(elapsed_ns as f64 / 1_000_000_000.0);
                }

                ROUTE_CACHE.with(|cell| {
                    cell.borrow_mut().put(cache_key.clone(), outbound.clone());
                });

                return Some(outbound);
            }
        }

        None
    }
}

impl StaticRouter {
    fn cache_key(addr: &Address) -> String {
        match addr {
            Address::Domain(domain, port) => format!("{}:{}", domain, port),
            Address::Socket(sa) => sa.to_string(),
        }
    }

    pub fn get_stats(&self) -> Vec<RuleStatsSnapshot> {
        let total: u64 = self
            .stats
            .iter()
            .map(|s| s.hits.load(Ordering::Relaxed))
            .sum();

        let mut result = Vec::with_capacity(self.rules.len());

        for i in 0..self.rules.len() {
            let stat = &self.stats[i];
            let hits = stat.hits.load(Ordering::Relaxed);
            let total_ns = stat.match_time_ns.load(Ordering::Relaxed);
            let evals = stat.eval_count.load(Ordering::Relaxed);
            let max_ns = stat.max_ns.load(Ordering::Relaxed);

            result.push(RuleStatsSnapshot {
                rule_desc: self.labels[i].clone(),
                hits,
                percent: if total > 0 { hits as f64 / total as f64 * 100.0 } else { 0.0 },
                avg_match_time_us: if evals > 0 { total_ns as f64 / evals as f64 / 1000.0 } else { 0.0 },
                max_match_time_us: max_ns as f64 / 1000.0,
            });
        }

        result
    }

    pub fn total_hits(&self) -> u64 {
        self.stats.iter().map(|s| s.hits.load(Ordering::Relaxed)).sum()
    }

    pub fn export_to_prometheus(&self) {
        use crate::app::metrics::{ROUTER_RULE_HITS, ROUTER_RULE_MATCH_AVG, ROUTER_RULE_MATCH_MAX};

        for (i, label) in self.labels.iter().enumerate() {
            let stat = &self.stats[i];
            let hits = stat.hits.load(Ordering::Relaxed);
            let total_ns = stat.match_time_ns.load(Ordering::Relaxed);
            let evals = stat.eval_count.load(Ordering::Relaxed);
            let max_ns = stat.max_ns.load(Ordering::Relaxed);

            ROUTER_RULE_HITS.with_label_values(&[label]).set(hits as f64);
            ROUTER_RULE_MATCH_MAX.with_label_values(&[label]).set(max_ns as f64 / 1_000_000_000.0);

            let avg_secs = if evals > 0 {
                total_ns as f64 / evals as f64 / 1_000_000_000.0
            } else {
                0.0
            };
            ROUTER_RULE_MATCH_AVG.with_label_values(&[label]).set(avg_secs);
        }
    }

    pub fn reset_stats(&self) {
        for stat in self.stats.iter() {
            stat.hits.store(0, Ordering::Relaxed);
            stat.match_time_ns.store(0, Ordering::Relaxed);
            stat.eval_count.store(0, Ordering::Relaxed);
            stat.max_ns.store(0, Ordering::Relaxed);
        }
    }
}

// ============================================================================
// StaticRouterBuilder
// ============================================================================

pub struct StaticRouterBuilder {
    raw_rules: Vec<Rule>,
    geosite: crate::geosite::GeoSite,
    geoip: Arc<GeoIpDb>,
}

impl StaticRouterBuilder {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            raw_rules: rules,
            geosite: crate::geosite::GeoSite::with_builtin(),
            geoip: Arc::new(GeoIpDb::default()),
        }
    }

    pub fn with_geosite(mut self, geosite: crate::geosite::GeoSite) -> Self {
        self.geosite = geosite;
        self
    }

    pub fn with_geoip(mut self, geoip: GeoIpDb) -> Self {
        self.geoip = Arc::new(geoip);
        self
    }

    pub fn build(self) -> StaticRouter {
        let mut compiled_rules: Vec<StaticRule> = Vec::with_capacity(self.raw_rules.len());
        let mut labels = Vec::with_capacity(self.raw_rules.len());

        for (i, rule) in self.raw_rules.iter().enumerate() {
            labels.push(rule.label.clone().unwrap_or_else(|| format!("rule_{}", i + 1)));
            compiled_rules.push(self.compile_static(rule));
        }

        let metric_handles: Vec<MetricHandles> = labels
            .iter()
            .map(|label| MetricHandles {
                duration: ROUTER_RULE_MATCH_DURATION.with_label_values(&[label]),
            })
            .collect();

        let stats: Vec<RuleStat> = compiled_rules.iter().map(|_| RuleStat::default()).collect();

        tracing::info!("StaticRouter built: {} rules compiled", compiled_rules.len());

        StaticRouter {
            rules: compiled_rules,
            labels,
            metric_handles,
            stats: Arc::new(stats),
        }
    }

    fn compile_static(&self, rule: &Rule) -> StaticRule {
        let domain_matcher = self.build_domain_matcher(rule);
        let ip_matcher = self.build_ip_matcher(rule);
        let port_matcher = rule.port.as_deref().and_then(PortMatcher::build);

        StaticRule {
            outbound_tag: rule.outbound_tag.clone(),
            is_catch_all: rule.rule_type == RuleType::All,
            inbound_tag: rule.inbound_tag.clone(),
            protocol: rule.protocol.clone(),
            network: rule.network.clone(),
            domain_matcher,
            ip_matcher,
            port_matcher,
        }
    }

    fn build_domain_matcher(&self, rule: &Rule) -> Option<super::matchers::DomainMatcher> {
        let mut b = DomainMatcherBuilder::new();
        match rule.rule_type {
            RuleType::ChinaSites => {
                for site in &["cn", "geolocation-cn"] {
                    self.expand_geosite_into(&mut b, site);
                }
            }
            RuleType::Field => {
                for pattern in &rule.domain {
                    if let Some(site) = pattern.strip_prefix("geosite:") {
                        self.expand_geosite_into(&mut b, site);
                    } else if let Some(d) = pattern.strip_prefix("domain:") {
                        b.add_suffix(d);
                    } else if let Some(d) = pattern.strip_prefix("full:") {
                        b.add_exact(d);
                    } else if let Some(kw) = pattern.strip_prefix("keyword:") {
                        b.add_keyword(kw);
                    } else if let Some(re) = pattern.strip_prefix("regexp:") {
                        b.add_regex(re);
                    } else {
                        b.add_keyword(pattern);
                    }
                }
            }
            _ => {}
        }
        b.build()
    }

    fn expand_geosite_into(&self, b: &mut DomainMatcherBuilder, site: &str) {
        if let Some(entries) = self.geosite.get(site) {
            for entry in entries {
                match entry {
                    DomainEntry::Domain(d) => b.add_suffix(d),
                    DomainEntry::Full(d) => b.add_exact(d),
                    DomainEntry::Keyword(kw) => b.add_keyword(kw),
                    DomainEntry::Regex(re) => b.add_regex(re),
                }
            }
        }
    }

    fn build_ip_matcher(&self, rule: &Rule) -> Option<super::matchers::IpMatcher> {
        let mut b = IpMatcherBuilder::new();
        match rule.rule_type {
            RuleType::ChinaIp => self.expand_geoip_into(&mut b, "CN"),
            RuleType::PrivateIp => {
                for cidr in &["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16","0.0.0.0/8","fc00::/7","fe80::/10","::1/128"] {
                    if let Ok(net) = cidr.parse() { b.add_cidr(net); }
                }
            }
            RuleType::Field => {
                for pattern in &rule.ip {
                    if let Some(code) = pattern.strip_prefix("geoip:") {
                        self.expand_geoip_into(&mut b, code);
                    } else if pattern.contains('/') {
                        if let Ok(net) = pattern.parse() { b.add_cidr(net); }
                    } else if let Ok(ip) = pattern.parse() { b.add_exact(ip); }
                }
            }
            _ => {}
        }
        b.build()
    }

    fn expand_geoip_into(&self, b: &mut IpMatcherBuilder, country_code: &str) {
        b.add_geoip_check(country_code, Arc::clone(&self.geoip));
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(dest: &str, port: u16) -> Metadata {
        Metadata::new(Address::domain(dest, port))
    }

    #[test]
    fn test_domain_rule() {
        let rules = vec![Rule {
            domain: vec!["domain:google.com".to_string()],
            outbound_tag: "proxy".to_string(),
            ..Default::default()
        }];
        let router = StaticRouterBuilder::new(rules).build();
        assert_eq!(router.try_select(&meta("www.google.com", 443)), Some("proxy".into()));
        assert_eq!(router.try_select(&meta("example.com", 443)), None);
    }

    #[test]
    fn test_catch_all() {
        let rules = vec![
            Rule { domain: vec!["domain:google.com".to_string()], outbound_tag: "proxy".to_string(), ..Default::default() },
            Rule { rule_type: RuleType::All, outbound_tag: "direct".to_string(), ..Default::default() },
        ];
        let router = StaticRouterBuilder::new(rules).build();
        assert_eq!(router.try_select(&meta("www.google.com", 443)), Some("proxy".into()));
        assert_eq!(router.try_select(&meta("example.com", 80)), Some("direct".into()));
    }
}
