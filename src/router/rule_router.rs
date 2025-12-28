//! Rule-based Router implementation

use std::net::IpAddr;

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

/// Rule-based router
pub struct RuleRouter {
    rules: Vec<Rule>,
    default_outbound: String,
    geosite: GeoSiteMatcher,
    geoip: GeoIpMatcher,
}

impl RuleRouter {
    pub fn new(rules: Vec<Rule>, default_outbound: impl Into<String>) -> Self {
        Self {
            rules,
            default_outbound: default_outbound.into(),
            geosite: GeoSiteMatcher::new(),
            geoip: GeoIpMatcher::default(),
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
                    return self.geosite.matches("cn", domain);
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
        for rule in &self.rules {
            if self.match_rule(rule, metadata) {
                return &rule.outbound_tag;
            }
        }

        &self.default_outbound
    }
}

impl Default for RuleRouter {
    fn default() -> Self {
        Self {
            rules: vec![],
            default_outbound: "direct".to_string(),
            geosite: GeoSiteMatcher::new(),
            geoip: GeoIpMatcher::new(),
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
}
