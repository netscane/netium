//! Condition matchers for routing rules
//!
//! Each matcher tests one dimension of a connection:
//! - `DomainMatcher`: domain patterns (trie + keyword + regex)
//! - `IpMatcher`: IP/CIDR ranges
//! - `PortMatcher`: port ranges
//!
//! Matchers are pure — they only contain resolved data, no external dependencies.
//! Pattern resolution (geosite:xxx, geoip:CN) is done by the builder.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use regex::{RegexSet, RegexSetBuilder};

use crate::geoip::GeoIpDb;

use super::domain_trie::DomainTrie;

// ============================================================================
// DomainMatcher
// ============================================================================

/// Matches domains using four strategies (checked in order):
/// 1. HashSet for exact match (O(1))
/// 2. Trie for suffix match (O(label_count))
/// 3. Keywords for substring match
/// 4. RegexSet for pattern match (cached to avoid repeated DFA execution)
pub struct DomainMatcher {
    exact: HashSet<String>,
    suffix: DomainTrie,
    keywords: Vec<String>,
    regex_set: Option<RegexSet>,
    /// Cache for regex results — only allocated when regex_set is Some.
    /// Key: lowercased domain, Value: regex matched or not.
    regex_cache: Option<Mutex<HashMap<String, bool>>>,
}

const REGEX_CACHE_MAX: usize = 8192;

/// Builder that accumulates domain patterns, then compiles into DomainMatcher.
pub struct DomainMatcherBuilder {
    exact: HashSet<String>,
    suffix: DomainTrie,
    keywords: Vec<String>,
    regex_patterns: Vec<String>,
}

impl DomainMatcherBuilder {
    pub fn new() -> Self {
        Self {
            exact: HashSet::new(),
            suffix: DomainTrie::new(),
            keywords: Vec::new(),
            regex_patterns: Vec::new(),
        }
    }

    /// Add an exact match (full: rule). Matches only this exact domain.
    pub fn add_exact(&mut self, domain: &str) {
        self.exact.insert(domain.to_lowercase());
    }

    /// Add a suffix match (domain: rule). Matches domain and all subdomains.
    pub fn add_suffix(&mut self, domain: &str) {
        self.suffix.insert(&domain.to_lowercase());
    }

    /// Add a keyword substring match.
    pub fn add_keyword(&mut self, keyword: &str) {
        self.keywords.push(keyword.to_lowercase());
    }

    /// Add a regex pattern.
    pub fn add_regex(&mut self, pattern: &str) {
        self.regex_patterns.push(pattern.to_string());
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.suffix.is_empty()
            && self.keywords.is_empty()
            && self.regex_patterns.is_empty()
    }

    pub fn build(self) -> Option<DomainMatcher> {
        if self.is_empty() {
            return None;
        }

        let regex_set = if self.regex_patterns.is_empty() {
            None
        } else {
            // Use larger DFA cache (8MB) to avoid NFA fallback on complex pattern sets.
            // Default 2MB is too small for 40+ regex patterns, causing p99 spikes.
            let set = RegexSetBuilder::new(&self.regex_patterns)
                .dfa_size_limit(8 * 1024 * 1024)
                .size_limit(16 * 1024 * 1024)
                .build()
                .ok();

            // Warmup: force DFA compilation at build time, not at first request.
            // Without this, the first regex match triggers lazy DFA compilation (~400µs).
            if let Some(ref s) = set {
                let _ = s.is_match("warmup.example.com");
                let _ = s.is_match("x.ap-beijing-1.myqcloud.com");
                let _ = s.is_match("cdn1-epicgames-42.file.myqcloud.com");
            }

            set
        };

        let regex_cache = if regex_set.is_some() {
            Some(Mutex::new(HashMap::with_capacity(256)))
        } else {
            None
        };

        Some(DomainMatcher {
            exact: self.exact,
            suffix: self.suffix,
            keywords: self.keywords,
            regex_set,
            regex_cache,
        })
    }
}

impl DomainMatcher {
    pub fn matches(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // 1. Exact match — O(1) HashSet lookup
        if self.exact.contains(&domain_lower) {
            return true;
        }

        // 2. Suffix match — O(label_count) trie walk
        if self.suffix.contains(&domain_lower) {
            return true;
        }

        // 3. Keyword substring match
        for kw in &self.keywords {
            if domain_lower.contains(kw.as_str()) {
                return true;
            }
        }

        // 4. Regex match (with cache to avoid ~50µs DFA cost on repeated domains)
        if let (Some(set), Some(cache)) = (&self.regex_set, &self.regex_cache) {
            // Fast path: check cache first
            {
                let guard = cache.lock();
                if let Some(&hit) = guard.get(&domain_lower) {
                    return hit;
                }
            }

            // Slow path: run regex, then cache result
            let matched = set.is_match(&domain_lower);
            {
                let mut guard = cache.lock();
                if guard.len() >= REGEX_CACHE_MAX {
                    guard.clear(); // simple eviction
                }
                guard.insert(domain_lower, matched);
            }
            return matched;
        }

        false
    }
}

// ============================================================================
// IpMatcher
// ============================================================================

/// Matches IP addresses against CIDR ranges, exact IPs, and GeoIP datasets.
pub struct IpMatcher {
    cidrs: Vec<ipnet::IpNet>,
    exact_ips: Vec<IpAddr>,
    /// GeoIP checks: (country_code, dataset)
    geoip_checks: Vec<(String, Arc<GeoIpDb>)>,
}

/// Builder that accumulates IP patterns.
pub struct IpMatcherBuilder {
    cidrs: Vec<ipnet::IpNet>,
    exact_ips: Vec<IpAddr>,
    geoip_checks: Vec<(String, Arc<GeoIpDb>)>,
}

impl IpMatcherBuilder {
    pub fn new() -> Self {
        Self { cidrs: Vec::new(), exact_ips: Vec::new(), geoip_checks: Vec::new() }
    }

    pub fn add_cidr(&mut self, cidr: ipnet::IpNet) {
        self.cidrs.push(cidr);
    }

    pub fn add_exact(&mut self, ip: IpAddr) {
        self.exact_ips.push(ip);
    }

    /// Add a GeoIP country check with its dataset.
    pub fn add_geoip_check(&mut self, country_code: &str, geoip: Arc<GeoIpDb>) {
        self.geoip_checks.push((country_code.to_uppercase(), geoip));
    }

    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty() && self.exact_ips.is_empty() && self.geoip_checks.is_empty()
    }

    pub fn build(self) -> Option<IpMatcher> {
        if self.is_empty() {
            return None;
        }
        Some(IpMatcher {
            cidrs: self.cidrs,
            exact_ips: self.exact_ips,
            geoip_checks: self.geoip_checks,
        })
    }
}

impl IpMatcher {
    pub fn matches(&self, ip: IpAddr) -> bool {
        for (code, geoip) in &self.geoip_checks {
            if geoip.contains(code, ip) {
                return true;
            }
        }

        for cidr in &self.cidrs {
            if cidr.contains(&ip) {
                return true;
            }
        }

        self.exact_ips.contains(&ip)
    }
}

// ============================================================================
// PortMatcher
// ============================================================================

/// Matches port numbers against ranges and exact values.
pub struct PortMatcher {
    ranges: Vec<(u16, u16)>,
    exact: Vec<u16>,
}

impl PortMatcher {
    /// Build from port pattern string (e.g., "80,443,1000-2000").
    pub fn build(pattern: &str) -> Option<Self> {
        let mut ranges = Vec::new();
        let mut exact = Vec::new();

        for part in pattern.split(',') {
            let part = part.trim();
            if part.is_empty() { continue; }

            if let Some((start, end)) = part.split_once('-') {
                if let (Ok(s), Ok(e)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                    ranges.push((s, e));
                }
            } else if let Ok(p) = part.parse::<u16>() {
                exact.push(p);
            }
        }

        if ranges.is_empty() && exact.is_empty() {
            return None;
        }
        Some(Self { ranges, exact })
    }

    pub fn matches(&self, port: u16) -> bool {
        if self.exact.contains(&port) {
            return true;
        }
        self.ranges.iter().any(|&(s, e)| port >= s && port <= e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_matcher() {
        let m = PortMatcher::build("80,443,1000-2000").unwrap();
        assert!(m.matches(80));
        assert!(m.matches(443));
        assert!(m.matches(1500));
        assert!(!m.matches(8080));
    }

    #[test]
    fn test_ip_matcher() {
        let mut b = IpMatcherBuilder::new();
        b.add_cidr("10.0.0.0/8".parse().unwrap());
        b.add_exact("192.168.1.1".parse().unwrap());
        let m = b.build().unwrap();

        assert!(m.matches("10.1.2.3".parse().unwrap()));
        assert!(m.matches("192.168.1.1".parse().unwrap()));
        assert!(!m.matches("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_ip_matcher_geoip() {
        let mut b = IpMatcherBuilder::new();
        b.add_geoip_check("CN", Arc::new(GeoIpDb::new()));
        let m = b.build().unwrap();
        // Empty GeoIP database — nothing matches
        assert!(!m.matches("223.5.5.5".parse().unwrap()));
    }

    #[test]
    fn test_domain_matcher() {
        let mut b = DomainMatcherBuilder::new();
        b.add_suffix("google.com");
        b.add_exact("exact.example.com");
        b.add_keyword("facebook");
        let m = b.build().unwrap();

        assert!(m.matches("www.google.com"));
        assert!(m.matches("google.com"));
        assert!(!m.matches("notgoogle.com"));
        assert!(m.matches("exact.example.com"));
        assert!(!m.matches("www.exact.example.com"));
        assert!(m.matches("m.facebook.com"));
    }
}
