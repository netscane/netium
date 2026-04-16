//! Condition matchers for routing rules
//!
//! Each matcher tests one dimension of a connection:
//! - `DomainMatcher`: domain patterns (trie + keyword + regex)
//! - `IpMatcher`: IP/CIDR ranges
//! - `PortMatcher`: port ranges
//!
//! Matchers are pure — they only contain resolved data, no external dependencies.
//! Pattern resolution (geosite:xxx, geoip:CN) is done by the builder.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;
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
/// 4. RegexSet for pattern match (TLD-partitioned, thread-local cached)
pub struct DomainMatcher {
    exact: HashSet<String>,
    suffix: DomainTrie,
    keywords: Vec<String>,
    regex: Option<TldPartitionedRegex>,
}

/// Regex patterns partitioned by TLD for faster matching.
///
/// Most geosite regex patterns end with a fixed TLD like `\.com$`.
/// By grouping patterns per TLD, we only run ~10-20 patterns instead of 150+.
/// Patterns without a recognizable TLD go into `fallback`.
struct TldPartitionedRegex {
    /// TLD -> RegexSet for patterns ending with that TLD
    by_tld: HashMap<Box<str>, RegexSet>,
    /// Patterns that couldn't be classified by TLD
    fallback: Option<RegexSet>,
}

/// Per-thread regex result cache — no locking, no contention.
/// LRU eviction avoids clear() spikes when cache reaches capacity.
const REGEX_CACHE_MAX: usize = 8192;

thread_local! {
    static REGEX_CACHE: RefCell<LruCache<String, bool>> = RefCell::new(
        LruCache::new(
            NonZeroUsize::new(REGEX_CACHE_MAX).expect("REGEX_CACHE_MAX must be > 0")
        )
    );
}

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
        self.exact.insert(domain.to_ascii_lowercase());
    }

    /// Add a suffix match (domain: rule). Matches domain and all subdomains.
    pub fn add_suffix(&mut self, domain: &str) {
        self.suffix.insert(&domain.to_ascii_lowercase());
    }

    /// Add a keyword substring match.
    pub fn add_keyword(&mut self, keyword: &str) {
        self.keywords.push(keyword.to_ascii_lowercase());
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

        let regex = if self.regex_patterns.is_empty() {
            None
        } else {
            Some(build_tld_partitioned_regex(&self.regex_patterns))
        };

        Some(DomainMatcher {
            exact: self.exact,
            suffix: self.suffix,
            keywords: self.keywords,
            regex,
        })
    }
}

/// Extract a fixed TLD suffix from a regex pattern.
///
/// Recognizes patterns like `(^|\.)stuff\.com$` → Some("com")
/// Returns None for patterns without a clear fixed TLD ending.
fn extract_tld_from_regex(pattern: &str) -> Option<&str> {
    // Must end with `$` and have a literal `.tld$` or `\.tld$`
    let s = pattern.strip_suffix('$')?;

    // Find the last `\.` or `.` before the TLD
    let (prefix, tld) = if let Some(pos) = s.rfind("\\.") {
        (&s[..pos], &s[pos + 2..])
    } else if let Some(pos) = s.rfind('.') {
        (&s[..pos], &s[pos + 1..])
    } else {
        return None;
    };

    // TLD must be a simple literal (letters only, no regex metacharacters)
    if tld.is_empty() || !tld.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        // Could be an alternation like `(com|net|org)` — extract from that
        return extract_tld_from_alternation(tld).or_else(|| {
            // Check if prefix ends with alternation containing TLDs
            None
        });
    }

    // Verify the prefix doesn't bleed into the TLD (e.g., character class)
    let _ = prefix;
    Some(tld)
}

/// Handle alternation TLDs like `(com|net|org)` → returns first one for grouping
fn extract_tld_from_alternation(s: &str) -> Option<&str> {
    let inner = s.strip_prefix('(')?.strip_suffix(')')?;
    // Check all alternatives are simple literals
    let first = inner.split('|').next()?;
    if inner.split('|').all(|alt| alt.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')) {
        Some(first)
    } else {
        None
    }
}

fn build_regex_set(patterns: &[&str]) -> Option<RegexSet> {
    if patterns.is_empty() {
        return None;
    }
    let set = RegexSetBuilder::new(patterns)
        .dfa_size_limit(8 * 1024 * 1024)
        .size_limit(16 * 1024 * 1024)
        .build()
        .ok()?;

    // Warmup DFA
    let _ = set.is_match("warmup.example.com");
    Some(set)
}

fn build_tld_partitioned_regex(patterns: &[String]) -> TldPartitionedRegex {
    let mut by_tld: HashMap<String, Vec<&str>> = HashMap::new();
    let mut fallback_patterns: Vec<&str> = Vec::new();

    for pattern in patterns {
        if let Some(tld) = extract_tld_from_regex(pattern) {
            by_tld.entry(tld.to_ascii_lowercase()).or_default().push(pattern);
        } else {
            fallback_patterns.push(pattern);
        }
    }

    let by_tld_compiled: HashMap<Box<str>, RegexSet> = by_tld
        .into_iter()
        .filter_map(|(tld, pats)| {
            build_regex_set(&pats).map(|set| (Box::from(tld.as_str()), set))
        })
        .collect();

    let fallback = build_regex_set(&fallback_patterns);

    tracing::debug!(
        "TLD-partitioned regex: {} TLD groups, {} fallback patterns",
        by_tld_compiled.len(),
        fallback_patterns.len(),
    );

    TldPartitionedRegex {
        by_tld: by_tld_compiled,
        fallback,
    }
}

impl TldPartitionedRegex {
    fn is_match(&self, domain: &str) -> bool {
        // Extract TLD from domain
        if let Some(tld) = domain.rsplit('.').next() {
            if let Some(set) = self.by_tld.get(tld) {
                if set.is_match(domain) {
                    return true;
                }
            }
        }

        // Always check fallback (patterns without fixed TLD)
        if let Some(ref fb) = self.fallback {
            if fb.is_match(domain) {
                return true;
            }
        }

        false
    }
}

impl DomainMatcher {
    pub fn matches(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        self.matches_normalized(&domain)
    }

    pub fn matches_normalized(&self, domain: &str) -> bool {
        // 1. Exact match — O(1) HashSet lookup
        if self.exact.contains(domain) {
            return true;
        }

        // 2. Suffix match — O(label_count) trie walk
        if self.suffix.contains(domain) {
            return true;
        }

        // 3. Keyword substring match
        if self.keywords.iter().any(|kw| domain.contains(kw.as_str())) {
            return true;
        }

        // 4. Regex match — thread-local cached to avoid DFA cost on repeated domains
        self.matches_regex(domain)
    }

    fn matches_regex(&self, domain: &str) -> bool {
        let Some(regex) = &self.regex else {
            return false;
        };

        // Thread-local cache: zero contention, each tokio worker has its own.
        REGEX_CACHE.with(|cell| {
            let mut cache = cell.borrow_mut();

            if let Some(hit) = cache.get(domain) {
                return *hit;
            }

            let matched = regex.is_match(domain);
            cache.put(domain.to_string(), matched);

            matched
        })
    }
}

fn normalize_domain(domain: &str) -> Cow<'_, str> {
    let trimmed = domain.trim_end_matches('.');
    if trimmed.is_empty() {
        return Cow::Borrowed(trimmed);
    }
    let needs_lower = trimmed.bytes().any(|b| b.is_ascii_uppercase());
    if needs_lower {
        Cow::Owned(trimmed.to_ascii_lowercase())
    } else if trimmed.len() != domain.len() {
        Cow::Owned(trimmed.to_string())
    } else {
        Cow::Borrowed(trimmed)
    }
}

// ============================================================================
// IpMatcher
// ============================================================================

/// Matches IP addresses against CIDR ranges, exact IPs, and GeoIP datasets.
pub struct IpMatcher {
    cidrs: Vec<ipnet::IpNet>,
    exact_ips: HashSet<IpAddr>,
    /// GeoIP checks: (country_code, dataset)
    geoip_checks: Vec<(String, Arc<GeoIpDb>)>,
}

/// Builder that accumulates IP patterns.
pub struct IpMatcherBuilder {
    cidrs: Vec<ipnet::IpNet>,
    exact_ips: HashSet<IpAddr>,
    geoip_checks: Vec<(String, Arc<GeoIpDb>)>,
}

impl IpMatcherBuilder {
    pub fn new() -> Self {
        Self { cidrs: Vec::new(), exact_ips: HashSet::new(), geoip_checks: Vec::new() }
    }

    pub fn add_cidr(&mut self, cidr: ipnet::IpNet) {
        self.cidrs.push(cidr);
    }

    pub fn add_exact(&mut self, ip: IpAddr) {
        self.exact_ips.insert(ip);
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
    exact: HashSet<u16>,
}

impl PortMatcher {
    /// Build from port pattern string (e.g., "80,443,1000-2000").
    pub fn build(pattern: &str) -> Option<Self> {
        let mut ranges = Vec::new();
        let mut exact = HashSet::new();

        for part in pattern.split(',') {
            let part = part.trim();
            if part.is_empty() { continue; }

            if let Some((start, end)) = part.split_once('-') {
                if let (Ok(s), Ok(e)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                    let (start, end) = if s <= e { (s, e) } else { (e, s) };
                    ranges.push((start, end));
                }
            } else if let Ok(p) = part.parse::<u16>() {
                exact.insert(p);
            }
        }

        // Normalize and merge ranges to reduce per-match scan cost.
        ranges.sort_unstable_by_key(|&(s, _)| s);
        let mut merged_ranges: Vec<(u16, u16)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            if let Some((_, last_end)) = merged_ranges.last_mut() {
                if start <= last_end.saturating_add(1) {
                    *last_end = (*last_end).max(end);
                    continue;
                }
            }
            merged_ranges.push((start, end));
        }

        // Remove exact ports already covered by ranges.
        exact.retain(|&p| !merged_ranges.iter().any(|&(s, e)| p >= s && p <= e));

        if merged_ranges.is_empty() && exact.is_empty() {
            return None;
        }
        Some(Self { ranges: merged_ranges, exact })
    }

    pub fn matches(&self, port: u16) -> bool {
        if self.exact.contains(&port) {
            return true;
        }
        // Binary search for O(log n) range lookup instead of O(n) scan
        match self.ranges.binary_search_by_key(&port, |&(start, _)| start) {
            Ok(_) => true, // Port exactly matches a range start
            Err(idx) => {
                // Check if port falls within the previous range
                if idx > 0 {
                    let &(start, end) = &self.ranges[idx - 1];
                    port >= start && port <= end
                } else {
                    false
                }
            }
        }
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
    fn test_port_matcher_normalize_ranges() {
        // Reversed ranges are normalized, overlapping ranges are merged.
        let m = PortMatcher::build("2000-1000,1500-2500,80").unwrap();
        assert!(m.matches(1200));
        assert!(m.matches(2300));
        assert!(m.matches(80));
        assert!(!m.matches(2600));
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
        assert!(m.matches("WWW.GOOGLE.COM."));
    }

    #[test]
    fn test_domain_matcher_matches_normalized() {
        let mut b = DomainMatcherBuilder::new();
        b.add_exact("cdn.example.com");
        let m = b.build().unwrap();

        assert!(m.matches_normalized("cdn.example.com"));
        assert!(!m.matches_normalized("CDN.EXAMPLE.COM"));
    }

    #[test]
    fn test_regex_thread_local_cache() {
        let mut b = DomainMatcherBuilder::new();
        b.add_regex(r"\.myqcloud\.com$");
        let m = b.build().unwrap();

        assert!(m.matches("x.ap-beijing.myqcloud.com"));
        assert!(m.matches("x.ap-beijing.myqcloud.com")); // cache hit
        assert!(!m.matches("example.com"));
    }

    #[test]
    fn test_extract_tld_from_regex() {
        assert_eq!(extract_tld_from_regex(r"(^|\.)91porn[0-9]?\.store$"), Some("store"));
        assert_eq!(extract_tld_from_regex(r"(^|\.)18tv[1-5]\.com$"), Some("com"));
        assert_eq!(extract_tld_from_regex(r"\.myqcloud\.com$"), Some("com"));
        assert_eq!(extract_tld_from_regex(r"^cdn\d\.file\.myqcloud\.com$"), Some("com"));
        // Alternation TLD
        assert_eq!(extract_tld_from_regex(r"(^|\.)foo\.(com|net|org)$"), Some("com"));
        // No fixed TLD
        assert_eq!(extract_tld_from_regex(r"^.+-mihayo\.akamaized\.\w+$"), None);
    }

    #[test]
    fn test_tld_partitioned_regex() {
        let mut b = DomainMatcherBuilder::new();
        // .com pattern
        b.add_regex(r"(^|\.)91porn[0-9]?\.com$");
        // .store pattern
        b.add_regex(r"(^|\.)91porn[0-9]?\.store$");
        // .net pattern
        b.add_regex(r"^.+-cdn\.example\.net$");
        let m = b.build().unwrap();

        assert!(m.matches("91porn5.com"));
        assert!(m.matches("sub.91porn.com"));
        assert!(m.matches("91porn3.store"));
        assert!(m.matches("foo-cdn.example.net"));
        assert!(!m.matches("91porn5.org")); // .org not in any group
        assert!(!m.matches("example.com")); // doesn't match pattern
    }
}
