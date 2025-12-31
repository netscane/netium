//! Rule-based Router implementation

use std::any::Any;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::app::metrics::{ROUTER_RULE_HITS, ROUTER_RULE_MATCH_DURATION, ROUTER_DECISIONS_TOTAL};
use crate::common::{Address, Metadata, Network};
use crate::geoip::GeoIpMatcher;
use crate::geosite::GeoSiteMatcher;

use super::Router;

/// Rule type - determines how the rule is evaluated
#[derive(Debug, Clone, Default, PartialEq)]
pub enum RuleType {
    /// Match based on specified fields (domain, ip, port, etc.)
    #[default]
    Field,
    /// Match all Chinese domains (shortcut for geosite:cn)
    ChinaSites,
    /// Match all Chinese IPs (shortcut for geoip:CN)
    ChinaIp,
    /// Match private/LAN IPs (10.x, 172.16.x, 192.168.x, etc.)
    PrivateIp,
    /// Match all traffic (catch-all rule)
    All,
}

impl RuleType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "field" => RuleType::Field,
            "chinasites" | "china_sites" | "china-sites" => RuleType::ChinaSites,
            "chinaip" | "china_ip" | "china-ip" => RuleType::ChinaIp,
            "privateip" | "private_ip" | "private-ip" | "private" => RuleType::PrivateIp,
            "all" | "any" | "*" => RuleType::All,
            _ => RuleType::Field,
        }
    }
}

/// Routing rule
#[derive(Debug, Clone, Default)]
pub struct Rule {
    /// Rule type
    pub rule_type: RuleType,
    /// Match inbound tags
    pub inbound_tag: Vec<String>,
    /// Match protocols
    pub protocol: Vec<String>,
    /// Match networks
    pub network: Vec<Network>,
    /// Match domain patterns
    pub domain: Vec<String>,
    /// Match IP patterns
    pub ip: Vec<String>,
    /// Match port patterns
    pub port: Option<String>,
    /// Target outbound tag
    pub outbound_tag: String,
}

/// Statistics for a single rule
#[derive(Debug)]
pub struct RuleStat {
    /// Number of times this rule was hit
    pub hits: AtomicU64,
    /// Total time spent matching this rule (in nanoseconds)
    pub match_time_ns: AtomicU64,
    /// Number of times this rule was evaluated (for avg calculation)
    pub eval_count: AtomicU64,
}

impl Default for RuleStat {
    fn default() -> Self {
        Self {
            hits: AtomicU64::new(0),
            match_time_ns: AtomicU64::new(0),
            eval_count: AtomicU64::new(0),
        }
    }
}

impl Clone for RuleStat {
    fn clone(&self) -> Self {
        Self {
            hits: AtomicU64::new(self.hits.load(Ordering::Relaxed)),
            match_time_ns: AtomicU64::new(self.match_time_ns.load(Ordering::Relaxed)),
            eval_count: AtomicU64::new(self.eval_count.load(Ordering::Relaxed)),
        }
    }
}

/// Snapshot of rule statistics for reporting
#[derive(Debug, Clone)]
pub struct RuleStatsSnapshot {
    /// Rule description (type + outbound)
    pub rule_desc: String,
    /// Number of hits
    pub hits: u64,
    /// Percentage of total hits
    pub percent: f64,
    /// Average match time in microseconds
    pub avg_match_time_us: f64,
    /// Total match time in microseconds
    pub total_match_time_us: f64,
}

/// Rule-based router
pub struct RuleRouter {
    rules: Vec<Rule>,
    default_outbound: String,
    geosite: GeoSiteMatcher,
    geoip: GeoIpMatcher,
    /// Statistics for each rule (same index as rules)
    stats: Arc<Vec<RuleStat>>,
    /// Hits for default outbound (no rule matched)
    default_hits: Arc<AtomicU64>,
}

impl RuleRouter {
    pub fn new(rules: Vec<Rule>, default_outbound: impl Into<String>) -> Self {
        let stats: Vec<RuleStat> = rules.iter().map(|_| RuleStat::default()).collect();
        Self {
            rules,
            default_outbound: default_outbound.into(),
            geosite: GeoSiteMatcher::new(),
            geoip: GeoIpMatcher::default(),
            stats: Arc::new(stats),
            default_hits: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn with_geosite(mut self, geosite: GeoSiteMatcher) -> Self {
        self.geosite = geosite;
        self
    }

    pub fn with_geoip(mut self, geoip: GeoIpMatcher) -> Self {
        self.geoip = geoip;
        self
    }

    /// Get statistics snapshot for all rules
    pub fn get_stats(&self) -> Vec<RuleStatsSnapshot> {
        let total: u64 = self.stats.iter()
            .map(|s| s.hits.load(Ordering::Relaxed))
            .sum::<u64>()
            + self.default_hits.load(Ordering::Relaxed);

        let mut result = Vec::with_capacity(self.rules.len() + 1);

        for (i, rule) in self.rules.iter().enumerate() {
            let hits = self.stats[i].hits.load(Ordering::Relaxed);
            let percent = if total > 0 {
                (hits as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            let total_time_ns = self.stats[i].match_time_ns.load(Ordering::Relaxed);
            let eval_count = self.stats[i].eval_count.load(Ordering::Relaxed);
            let avg_match_time_us = if eval_count > 0 {
                (total_time_ns as f64 / eval_count as f64) / 1000.0
            } else {
                0.0
            };
            let total_match_time_us = total_time_ns as f64 / 1000.0;

            let rule_desc = format!("{:?} -> {}", rule.rule_type, rule.outbound_tag);
            result.push(RuleStatsSnapshot {
                rule_desc,
                hits,
                percent,
                avg_match_time_us,
                total_match_time_us,
            });
        }

        // Add default outbound stats
        let default_hits = self.default_hits.load(Ordering::Relaxed);
        let default_percent = if total > 0 {
            (default_hits as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        result.push(RuleStatsSnapshot {
            rule_desc: format!("default -> {}", self.default_outbound),
            hits: default_hits,
            percent: default_percent,
            avg_match_time_us: 0.0,
            total_match_time_us: 0.0,
        });

        result
    }

    /// Get total number of routing decisions made
    pub fn total_hits(&self) -> u64 {
        self.stats.iter()
            .map(|s| s.hits.load(Ordering::Relaxed))
            .sum::<u64>()
            + self.default_hits.load(Ordering::Relaxed)
    }

    /// Reset all statistics
    pub fn reset_stats(&self) {
        for stat in self.stats.iter() {
            stat.hits.store(0, Ordering::Relaxed);
            stat.match_time_ns.store(0, Ordering::Relaxed);
            stat.eval_count.store(0, Ordering::Relaxed);
        }
        self.default_hits.store(0, Ordering::Relaxed);
    }

    /// Print statistics to log
    pub fn log_stats(&self) {
        let stats = self.get_stats();
        let total = self.total_hits();
        
        tracing::info!("=== Routing Statistics (total: {}) ===", total);
        for (i, stat) in stats.iter().enumerate() {
            if i < self.rules.len() {
                tracing::info!(
                    "  Rule {}: {} | hits: {} ({:.2}%) | avg: {:.2}µs, total: {:.2}ms",
                    i + 1,
                    stat.rule_desc,
                    stat.hits,
                    stat.percent,
                    stat.avg_match_time_us,
                    stat.total_match_time_us / 1000.0
                );
            } else {
                tracing::info!(
                    "  Default: {} | hits: {} ({:.2}%)",
                    stat.rule_desc,
                    stat.hits,
                    stat.percent
                );
            }
        }
    }

    /// Check if a rule matches the metadata
    fn match_rule(&self, rule: &Rule, metadata: &Metadata) -> bool {
        // Check inbound tag
        if !rule.inbound_tag.is_empty()
            && !rule.inbound_tag.iter().any(|t| t == &metadata.inbound_tag)
        {
            return false;
        }

        // Check protocol
        if !rule.protocol.is_empty() && !rule.protocol.iter().any(|p| p == &metadata.protocol) {
            return false;
        }

        // Check network
        if !rule.network.is_empty() && !rule.network.contains(&metadata.network) {
            return false;
        }

        // Check port
        if let Some(port_pattern) = &rule.port {
            if !self.match_port(port_pattern, metadata.destination.port()) {
                return false;
            }
        }

        // Handle special rule types
        match rule.rule_type {
            RuleType::All => return true,
            RuleType::ChinaSites => {
                if let Address::Domain(domain, _) = &metadata.destination {
                    // Use geosite cn and geolocation-cn categories with suffix matching
                    // This treats Full entries as Domain entries (suffix match)
                    // so that subdomains like api.bilibili.com match bilibili.com
                    return self.geosite.is_china_domain(domain);
                }
                return false;
            }
            RuleType::ChinaIp => {
                if let Address::Socket(addr) = &metadata.destination {
                    return self.geoip.matches("CN", addr.ip());
                }
                return false;
            }
            RuleType::PrivateIp => {
                if let Address::Socket(addr) = &metadata.destination {
                    return self.is_private_ip(addr.ip());
                }
                return false;
            }
            RuleType::Field => {
                // Continue with field-based matching below
            }
        }

        // Check domain/IP for Field type
        let has_domain_rules = !rule.domain.is_empty();
        let has_ip_rules = !rule.ip.is_empty();

        if !has_domain_rules && !has_ip_rules {
            return true;
        }

        match &metadata.destination {
            Address::Domain(domain, _) => {
                if has_domain_rules {
                    self.match_domain(&rule.domain, domain)
                } else {
                    false
                }
            }
            Address::Socket(addr) => {
                if has_ip_rules {
                    self.match_ip(&rule.ip, addr.ip())
                } else {
                    false
                }
            }
        }
    }

    /// Check if IP is private/LAN address
    fn is_private_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_private()           // 10.x, 172.16-31.x, 192.168.x
                    || ipv4.is_loopback()   // 127.x
                    || ipv4.is_link_local() // 169.254.x
                    || ipv4.is_broadcast()  // 255.255.255.255
                    || ipv4.octets()[0] == 0 // 0.x (current network)
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback()          // ::1
                    || ipv6.is_unspecified() // ::
                    // Check for link-local (fe80::/10)
                    || (ipv6.segments()[0] & 0xffc0) == 0xfe80
                    // Check for unique local (fc00::/7)
                    || (ipv6.segments()[0] & 0xfe00) == 0xfc00
            }
        }
    }

    /// Match port pattern (e.g., "80", "80,443", "1000-2000")
    fn match_port(&self, pattern: &str, port: u16) -> bool {
        for part in pattern.split(',') {
            let part = part.trim();
            if part.contains('-') {
                let range: Vec<&str> = part.split('-').collect();
                if range.len() == 2 {
                    if let (Ok(start), Ok(end)) = (range[0].parse::<u16>(), range[1].parse::<u16>())
                    {
                        if port >= start && port <= end {
                            return true;
                        }
                    }
                }
            } else if let Ok(p) = part.parse::<u16>() {
                if port == p {
                    return true;
                }
            }
        }
        false
    }

    /// Match domain patterns
    fn match_domain(&self, patterns: &[String], domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        for pattern in patterns {
            if pattern.starts_with("geosite:") {
                let site = &pattern[8..];
                if self.geosite.matches(site, &domain_lower) {
                    return true;
                }
            } else if pattern.starts_with("domain:") {
                let target = &pattern[7..];
                if domain_lower == target || domain_lower.ends_with(&format!(".{}", target)) {
                    return true;
                }
            } else if pattern.starts_with("full:") {
                let target = &pattern[5..];
                if domain_lower == target {
                    return true;
                }
            } else if pattern.starts_with("regexp:") {
                let regex_str = &pattern[7..];
                if let Ok(re) = regex::Regex::new(regex_str) {
                    if re.is_match(&domain_lower) {
                        return true;
                    }
                }
            } else if pattern.starts_with("keyword:") {
                let keyword = &pattern[8..];
                if domain_lower.contains(keyword) {
                    return true;
                }
            } else {
                // Plain domain match (substring)
                if domain_lower.contains(pattern) {
                    return true;
                }
            }
        }

        false
    }

    /// Match IP patterns
    fn match_ip(&self, patterns: &[String], ip: IpAddr) -> bool {
        for pattern in patterns {
            if pattern.starts_with("geoip:") {
                let country_code = &pattern[6..];
                if self.geoip.matches(country_code, ip) {
                    return true;
                }
                continue;
            }

            // CIDR matching
            if pattern.contains('/') {
                if let Ok(network) = pattern.parse::<ipnet::IpNet>() {
                    if network.contains(&ip) {
                        return true;
                    }
                }
            } else {
                // Exact IP match
                if let Ok(target_ip) = pattern.parse::<IpAddr>() {
                    if ip == target_ip {
                        return true;
                    }
                }
            }
        }

        false
    }
}

impl Router for RuleRouter {
    fn select(&self, metadata: &Metadata) -> &str {
        ROUTER_DECISIONS_TOTAL.inc();
        
        for (i, rule) in self.rules.iter().enumerate() {
            let start = Instant::now();
            let matched = self.match_rule(rule, metadata);
            let elapsed = start.elapsed();
            let elapsed_ns = elapsed.as_nanos() as u64;
            
            // Record evaluation time (internal stats)
            self.stats[i].match_time_ns.fetch_add(elapsed_ns, Ordering::Relaxed);
            self.stats[i].eval_count.fetch_add(1, Ordering::Relaxed);
            
            // Record to Prometheus
            let rule_label = format!("rule_{}", i + 1);
            ROUTER_RULE_MATCH_DURATION
                .with_label_values(&[&rule_label])
                .observe(elapsed.as_secs_f64());
            
            if matched {
                // Record hit
                self.stats[i].hits.fetch_add(1, Ordering::Relaxed);
                ROUTER_RULE_HITS.with_label_values(&[&rule_label]).inc();
                return &rule.outbound_tag;
            }
        }

        // Record default hit
        self.default_hits.fetch_add(1, Ordering::Relaxed);
        ROUTER_RULE_HITS.with_label_values(&["default"]).inc();
        &self.default_outbound
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Default for RuleRouter {
    fn default() -> Self {
        Self {
            rules: vec![],
            default_outbound: "direct".to_string(),
            geosite: GeoSiteMatcher::new(),
            geoip: GeoIpMatcher::new(),
            stats: Arc::new(vec![]),
            default_hits: Arc::new(AtomicU64::new(0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_router() {
        let router = super::super::StaticRouter::new("proxy");
        let metadata = Metadata::new(Address::domain("example.com", 443));
        assert_eq!(router.select(&metadata), "proxy");
    }

    #[test]
    fn test_rule_router_domain() {
        let rules = vec![Rule {
            domain: vec!["domain:google.com".to_string()],
            outbound_tag: "proxy".to_string(),
            ..Default::default()
        }];

        let router = RuleRouter::new(rules, "direct");

        let meta1 = Metadata::new(Address::domain("www.google.com", 443));
        assert_eq!(router.select(&meta1), "proxy");

        let meta2 = Metadata::new(Address::domain("example.com", 443));
        assert_eq!(router.select(&meta2), "direct");
    }

    #[test]
    fn test_rule_router_port() {
        let rules = vec![Rule {
            port: Some("443".to_string()),
            outbound_tag: "proxy".to_string(),
            ..Default::default()
        }];

        let router = RuleRouter::new(rules, "direct");

        let meta1 = Metadata::new(Address::domain("example.com", 443));
        assert_eq!(router.select(&meta1), "proxy");

        let meta2 = Metadata::new(Address::domain("example.com", 80));
        assert_eq!(router.select(&meta2), "direct");
    }

    #[test]
    fn test_rule_stats() {
        let rules = vec![
            Rule {
                rule_type: RuleType::Field,
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

        let router = RuleRouter::new(rules, "fallback");

        // Simulate traffic
        for _ in 0..3 {
            router.select(&Metadata::new(Address::domain("www.google.com", 443)));
        }
        for _ in 0..7 {
            router.select(&Metadata::new(Address::domain("example.com", 80)));
        }

        // Check stats
        let stats = router.get_stats();
        assert_eq!(stats.len(), 3); // 2 rules + default

        // Rule 1 (google.com -> proxy): 3 hits, 30%
        assert_eq!(stats[0].hits, 3);
        assert!((stats[0].percent - 30.0).abs() < 0.1);

        // Rule 2 (all -> direct): 7 hits, 70%
        assert_eq!(stats[1].hits, 7);
        assert!((stats[1].percent - 70.0).abs() < 0.1);

        // Default: 0 hits
        assert_eq!(stats[2].hits, 0);

        // Total
        assert_eq!(router.total_hits(), 10);

        // Reset
        router.reset_stats();
        assert_eq!(router.total_hits(), 0);
    }
}
