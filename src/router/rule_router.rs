//! Rule-based Router
//!
//! Each routing rule composes condition matchers (domain, IP, port).
//! A rule matches when ALL its matchers agree (AND logic).
//!
//! Architecture:
//! ```text
//! select(metadata) →
//!   for each RoutingRule:
//!     if all matchers pass → return outbound_tag
//!   return default_outbound
//! ```

use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use prometheus::{Gauge, Histogram, IntCounter};

use crate::app::metrics::{
    ROUTER_DECISIONS_TOTAL, ROUTER_RULE_HITS, ROUTER_RULE_MATCH_DURATION, ROUTER_RULE_MATCH_MAX,
};
use crate::common::{Address, Metadata, Network};
use crate::geoip::GeoIpDb;
use crate::geosite::DomainEntry;

use super::matchers::{DomainMatcher, DomainMatcherBuilder, IpMatcher, IpMatcherBuilder, PortMatcher};
use super::stats::{RuleStat, RuleStatsSnapshot};
use super::Router;

// ============================================================================
// Rule Types
// ============================================================================

#[derive(Debug, Clone, Default, PartialEq)]
pub enum RuleType {
    #[default]
    Field,
    ChinaSites,
    ChinaIp,
    PrivateIp,
    All,
}

impl RuleType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "field" => Self::Field,
            "chinasites" | "china_sites" | "china-sites" => Self::ChinaSites,
            "chinaip" | "china_ip" | "china-ip" => Self::ChinaIp,
            "privateip" | "private_ip" | "private-ip" | "private" => Self::PrivateIp,
            "all" | "any" | "*" => Self::All,
            _ => Self::Field,
        }
    }
}

// ============================================================================
// Rule Definition (config input)
// ============================================================================

/// Raw rule definition from config — used to build compiled RoutingRule.
#[derive(Debug, Clone, Default)]
pub struct Rule {
    pub rule_type: RuleType,
    pub label: Option<String>,
    pub inbound_tag: Vec<String>,
    pub protocol: Vec<String>,
    pub network: Vec<Network>,
    pub domain: Vec<String>,
    pub ip: Vec<String>,
    pub port: Option<String>,
    pub outbound_tag: String,
}

// ============================================================================
// Compiled Routing Rule
// ============================================================================

/// A compiled routing rule with optimized matchers.
struct RoutingRule {
    outbound_tag: String,
    is_catch_all: bool,

    // Metadata filters
    inbound_tag: Vec<String>,
    protocol: Vec<String>,
    network: Vec<Network>,

    // Condition matchers (None = don't check this dimension)
    domain_matcher: Option<DomainMatcher>,
    ip_matcher: Option<IpMatcher>,
    port_matcher: Option<PortMatcher>,
}

impl RoutingRule {
    /// Check if this rule matches the given metadata.
    fn matches(&self, metadata: &Metadata) -> bool {
        if self.is_catch_all {
            return self.check_metadata_filters(metadata);
        }

        if !self.check_metadata_filters(metadata) {
            return false;
        }

        let has_domain = self.domain_matcher.is_some();
        let has_ip = self.ip_matcher.is_some();

        // If no domain/IP matchers, this is a metadata-only rule (matches all addresses)
        if !has_domain && !has_ip && self.port_matcher.is_none() {
            return true;
        }

        // Check port
        if let Some(pm) = &self.port_matcher {
            if !pm.matches(metadata.destination.port()) {
                return false;
            }
        }

        // Check address-specific matchers
        match &metadata.destination {
            Address::Domain(domain, _) => {
                if let Some(dm) = &self.domain_matcher {
                    dm.matches(domain)
                } else {
                    !has_ip // no domain matcher but has IP matcher → skip
                }
            }
            Address::Socket(addr) => {
                if let Some(im) = &self.ip_matcher {
                    im.matches(addr.ip())
                } else {
                    !has_domain
                }
            }
        }
    }

    fn check_metadata_filters(&self, metadata: &Metadata) -> bool {
        if !self.inbound_tag.is_empty()
            && !self.inbound_tag.iter().any(|t| t.as_str() == &*metadata.inbound_tag)
        {
            return false;
        }
        if !self.protocol.is_empty()
            && !self.protocol.iter().any(|p| p == &metadata.protocol)
        {
            return false;
        }
        if !self.network.is_empty() && !self.network.contains(&metadata.network) {
            return false;
        }
        true
    }
}

// ============================================================================
// Pre-cached Prometheus handles
// ============================================================================

struct MetricHandles {
    duration: Histogram,
    max_gauge: Gauge,
    hits: IntCounter,
}

// ============================================================================
// RuleRouter
// ============================================================================

pub struct RuleRouter {
    rules: Vec<RoutingRule>,
    default_outbound: String,

    // Prometheus
    metric_handles: Vec<MetricHandles>,
    default_hit_counter: IntCounter,

    // Stats
    stats: Arc<Vec<RuleStat>>,
    default_hits: Arc<AtomicU64>,
}

/// Builder for RuleRouter — separates construction from usage.
pub struct RuleRouterBuilder {
    raw_rules: Vec<Rule>,
    default_outbound: String,
    geosite: crate::geosite::GeoSite,
    geoip: Arc<GeoIpDb>,
}

impl RuleRouterBuilder {
    pub fn new(rules: Vec<Rule>, default_outbound: impl Into<String>) -> Self {
        Self {
            raw_rules: rules,
            default_outbound: default_outbound.into(),
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

    /// Compile raw rules into optimized RoutingRules and build the router.
    pub fn build(self) -> RuleRouter {
        let mut compiled_rules = Vec::with_capacity(self.raw_rules.len());
        let mut labels = Vec::with_capacity(self.raw_rules.len());

        for (i, rule) in self.raw_rules.iter().enumerate() {
            let label = rule.label.clone()
                .unwrap_or_else(|| format!("rule_{}", i + 1));
            labels.push(label);
            compiled_rules.push(self.compile_rule(rule));
        }

        let metric_handles: Vec<MetricHandles> = labels.iter()
            .map(|label| MetricHandles {
                duration: ROUTER_RULE_MATCH_DURATION.with_label_values(&[label]),
                max_gauge: ROUTER_RULE_MATCH_MAX.with_label_values(&[label]),
                hits: ROUTER_RULE_HITS.with_label_values(&[label]),
            })
            .collect();

        let stats: Vec<RuleStat> = compiled_rules.iter().map(|_| RuleStat::default()).collect();

        tracing::info!("Router built: {} rules compiled", compiled_rules.len());

        RuleRouter {
            rules: compiled_rules,
            default_outbound: self.default_outbound,
            metric_handles,
            default_hit_counter: ROUTER_RULE_HITS.with_label_values(&["default"]),
            stats: Arc::new(stats),
            default_hits: Arc::new(AtomicU64::new(0)),
        }
    }

    fn compile_rule(&self, rule: &Rule) -> RoutingRule {
        let domain_matcher = self.build_domain_matcher(rule);
        let ip_matcher = self.build_ip_matcher(rule);
        let port_matcher = rule.port.as_deref().and_then(PortMatcher::build);

        RoutingRule {
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

    fn build_domain_matcher(&self, rule: &Rule) -> Option<DomainMatcher> {
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
                        b.add_keyword(pattern); // plain → keyword
                    }
                }
            }
            _ => {}
        }

        b.build()
    }

    /// Resolve geosite entries and feed into DomainMatcherBuilder.
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

    fn build_ip_matcher(&self, rule: &Rule) -> Option<IpMatcher> {
        let mut b = IpMatcherBuilder::new();

        match rule.rule_type {
            RuleType::ChinaIp => {
                self.expand_geoip_into(&mut b, "CN");
            }
            RuleType::PrivateIp => {
                for cidr in &[
                    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                    "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
                    "fc00::/7", "fe80::/10", "::1/128",
                ] {
                    if let Ok(net) = cidr.parse() {
                        b.add_cidr(net);
                    }
                }
            }
            RuleType::Field => {
                for pattern in &rule.ip {
                    if let Some(code) = pattern.strip_prefix("geoip:") {
                        self.expand_geoip_into(&mut b, code);
                    } else if pattern.contains('/') {
                        if let Ok(net) = pattern.parse() {
                            b.add_cidr(net);
                        }
                    } else if let Ok(ip) = pattern.parse() {
                        b.add_exact(ip);
                    }
                }
            }
            _ => {}
        }

        b.build()
    }

    /// Resolve geoip CIDRs and feed into IpMatcherBuilder.
    fn expand_geoip_into(&self, b: &mut IpMatcherBuilder, country_code: &str) {
        // GeoIpDb stores sorted CIDR sets — extract all as ipnet::IpNet
        // For now, delegate to GeoIpDb at runtime via a wrapper.
        // TODO: extract raw CIDRs from GeoIpDb at build time
        //
        // Since GeoIpDb already has binary-search optimized storage,
        // we wrap it as a single "virtual CIDR" check at match time.
        // This is a pragmatic compromise — the IpMatcher is still pure,
        // it just delegates geoip checks through a stored Arc.
        b.add_geoip_check(country_code, Arc::clone(&self.geoip));
    }
}

// ============================================================================
// Router implementation
// ============================================================================

impl Router for RuleRouter {
    fn select(&self, metadata: &Metadata) -> &str {
        ROUTER_DECISIONS_TOTAL.inc();

        for (i, rule) in self.rules.iter().enumerate() {
            let start = Instant::now();
            let matched = rule.matches(metadata);
            let elapsed = start.elapsed();

            self.stats[i].match_time_ns.fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
            self.stats[i].eval_count.fetch_add(1, Ordering::Relaxed);

            let handles = &self.metric_handles[i];
            let secs = elapsed.as_secs_f64();
            handles.duration.observe(secs);
            if secs > handles.max_gauge.get() {
                handles.max_gauge.set(secs);
            }

            if matched {
                self.stats[i].hits.fetch_add(1, Ordering::Relaxed);
                handles.hits.inc();
                return &rule.outbound_tag;
            }
        }

        self.default_hits.fetch_add(1, Ordering::Relaxed);
        self.default_hit_counter.inc();
        &self.default_outbound
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// Stats access
// ============================================================================

impl RuleRouter {
    pub fn get_stats(&self) -> Vec<RuleStatsSnapshot> {
        let total: u64 = self.stats.iter()
            .map(|s| s.hits.load(Ordering::Relaxed))
            .sum::<u64>()
            + self.default_hits.load(Ordering::Relaxed);

        let mut result = Vec::with_capacity(self.rules.len() + 1);

        for (i, rule) in self.rules.iter().enumerate() {
            let hits = self.stats[i].hits.load(Ordering::Relaxed);
            let total_ns = self.stats[i].match_time_ns.load(Ordering::Relaxed);
            let evals = self.stats[i].eval_count.load(Ordering::Relaxed);

            result.push(RuleStatsSnapshot {
                rule_desc: rule.outbound_tag.clone(),
                hits,
                percent: if total > 0 { hits as f64 / total as f64 * 100.0 } else { 0.0 },
                avg_match_time_us: if evals > 0 { total_ns as f64 / evals as f64 / 1000.0 } else { 0.0 },
                total_match_time_us: total_ns as f64 / 1000.0,
            });
        }

        let dh = self.default_hits.load(Ordering::Relaxed);
        result.push(RuleStatsSnapshot {
            rule_desc: format!("default -> {}", self.default_outbound),
            hits: dh,
            percent: if total > 0 { dh as f64 / total as f64 * 100.0 } else { 0.0 },
            avg_match_time_us: 0.0,
            total_match_time_us: 0.0,
        });

        result
    }

    pub fn total_hits(&self) -> u64 {
        self.stats.iter().map(|s| s.hits.load(Ordering::Relaxed)).sum::<u64>()
            + self.default_hits.load(Ordering::Relaxed)
    }

    pub fn reset_stats(&self) {
        for stat in self.stats.iter() {
            stat.hits.store(0, Ordering::Relaxed);
            stat.match_time_ns.store(0, Ordering::Relaxed);
            stat.eval_count.store(0, Ordering::Relaxed);
        }
        self.default_hits.store(0, Ordering::Relaxed);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_rule() {
        let rules = vec![Rule {
            domain: vec!["domain:google.com".to_string()],
            outbound_tag: "proxy".to_string(),
            ..Default::default()
        }];

        let router = RuleRouterBuilder::new(rules, "direct").build();

        assert_eq!(router.select(&Metadata::new(Address::domain("www.google.com", 443))), "proxy");
        assert_eq!(router.select(&Metadata::new(Address::domain("example.com", 443))), "direct");
    }

    #[test]
    fn test_port_rule() {
        let rules = vec![Rule {
            port: Some("443".to_string()),
            outbound_tag: "proxy".to_string(),
            ..Default::default()
        }];

        let router = RuleRouterBuilder::new(rules, "direct").build();

        assert_eq!(router.select(&Metadata::new(Address::domain("example.com", 443))), "proxy");
        assert_eq!(router.select(&Metadata::new(Address::domain("example.com", 80))), "direct");
    }

    #[test]
    fn test_catch_all() {
        let rules = vec![
            Rule {
                domain: vec!["domain:google.com".to_string()],
                outbound_tag: "proxy".to_string(),
                ..Default::default()
            },
            Rule {
                rule_type: RuleType::All,
                outbound_tag: "direct".to_string(),
                ..Default::default()
            },
        ];

        let router = RuleRouterBuilder::new(rules, "fallback").build();

        assert_eq!(router.select(&Metadata::new(Address::domain("www.google.com", 443))), "proxy");
        assert_eq!(router.select(&Metadata::new(Address::domain("example.com", 80))), "direct");
    }

    #[test]
    fn test_stats() {
        let rules = vec![
            Rule {
                domain: vec!["domain:google.com".to_string()],
                outbound_tag: "proxy".to_string(),
                ..Default::default()
            },
            Rule {
                rule_type: RuleType::All,
                outbound_tag: "direct".to_string(),
                ..Default::default()
            },
        ];

        let router = RuleRouterBuilder::new(rules, "fallback").build();

        for _ in 0..3 {
            router.select(&Metadata::new(Address::domain("www.google.com", 443)));
        }
        for _ in 0..7 {
            router.select(&Metadata::new(Address::domain("example.com", 80)));
        }

        let stats = router.get_stats();
        assert_eq!(stats[0].hits, 3);
        assert_eq!(stats[1].hits, 7);
        assert_eq!(router.total_hits(), 10);

        router.reset_stats();
        assert_eq!(router.total_hits(), 0);
    }
}
