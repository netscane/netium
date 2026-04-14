//! GeoSite module for domain-based routing
//!
//! Uses geosite-rs crate to parse V2Ray geosite.dat files.
//! Implements inverted index for fast domain lookup.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use geosite_rs::{Domain, decode_geosite};
use tracing::{debug, warn};

use crate::error::{Error, Result};

/// Domain entry with match type
/// Based on V2Ray domain-list-community format:
/// - domain: → subdomain/suffix match (matches domain and all subdomains)
/// - full: → exact match (matches only the exact domain)
/// - keyword: → substring match (matches if domain contains the keyword)
/// - regexp: → regex match
#[derive(Debug, Clone)]
pub enum DomainEntry {
    /// Domain suffix match (domain and subdomains)
    /// e.g., "example.com" matches "example.com" and "www.example.com"
    Domain(String),
    /// Full domain match (exact)
    /// e.g., "example.com" only matches "example.com"
    Full(String),
    /// Keyword/substring match
    /// e.g., "google" matches "google.com", "www.google.com", "googleapis.com"
    Keyword(String),
    /// Regex match
    Regex(String),
}

impl DomainEntry {
    /// Check if domain matches this entry
    pub fn matches(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        match self {
            DomainEntry::Domain(s) => {
                // Suffix match: matches domain and all subdomains
                domain_lower == *s
                    || (domain_lower.len() > s.len()
                        && domain_lower.ends_with(s.as_str())
                        && domain_lower.as_bytes()[domain_lower.len() - s.len() - 1] == b'.')
            }
            DomainEntry::Full(s) => {
                domain_lower == *s
            }
            DomainEntry::Keyword(s) => {
                domain_lower.contains(s)
            }
            DomainEntry::Regex(pattern) => {
                if let Ok(re) = regex::Regex::new(pattern) {
                    re.is_match(&domain_lower)
                } else {
                    false
                }
            }
        }
    }

    /// Check if domain matches this entry, treating Full as Domain (suffix match)
    pub fn matches_as_suffix(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        match self {
            DomainEntry::Domain(s) | DomainEntry::Full(s) => {
                domain_lower == *s
                    || (domain_lower.len() > s.len()
                        && domain_lower.ends_with(s.as_str())
                        && domain_lower.as_bytes()[domain_lower.len() - s.len() - 1] == b'.')
            }
            DomainEntry::Keyword(s) => domain_lower.contains(s),
            DomainEntry::Regex(pattern) => {
                if let Ok(re) = regex::Regex::new(pattern) {
                    re.is_match(&domain_lower)
                } else {
                    false
                }
            }
        }
    }
}

impl From<&Domain> for DomainEntry {
    fn from(domain: &Domain) -> Self {
        let value = domain.value.to_lowercase();
        // V2Ray protobuf Domain.Type definition (from v2ray-core/app/router/routercommon/common.proto):
        // 0 = Plain (Keyword - substring match)
        // 1 = Regex (regular expression)
        // 2 = RootDomain (Domain - suffix match, matches domain and subdomains)
        // 3 = Full (exact match only)
        // Note: geosite-rs library has incorrect mapping in geosite_to_hashmap(), we use correct V2Ray mapping here
        match domain.r#type {
            0 => DomainEntry::Keyword(value),                    // Plain/Keyword - substring match
            1 => DomainEntry::Regex(domain.value.clone()),       // Regex (keep original case)
            2 => DomainEntry::Domain(value),                     // RootDomain - suffix match
            3 => DomainEntry::Full(value),                       // Full - exact match
            _ => DomainEntry::Domain(value),                     // Default to domain suffix
        }
    }
}

/// GeoSite database with inverted index for fast lookup
#[derive(Debug, Default)]
pub struct GeoSite {
    /// Map of site tag to domain entries (for iteration/debugging)
    sites: HashMap<String, Vec<DomainEntry>>,
    
    /// Inverted index: exact domain -> set of site tags
    /// For Full entries: "example.com" -> {"cn", "geolocation-cn"}
    exact_index: HashMap<String, HashSet<String>>,
    
    /// Inverted index: domain suffix -> set of site tags  
    /// For Domain entries: "bilibili.com" -> {"cn", "bilibili"}
    /// Matches "bilibili.com" and "*.bilibili.com"
    suffix_index: HashMap<String, HashSet<String>>,
    
    /// Per-site keywords: site_tag -> list of keywords
    keyword_index: HashMap<String, Vec<String>>,
    
    /// Per-site regexes: site_tag -> compiled RegexSet for batch matching
    regex_index: HashMap<String, regex::RegexSet>,
}

impl GeoSite {
    /// Create empty GeoSite
    pub fn new() -> Self {
        Self::default()
    }

    /// Build RegexSet from patterns, skipping invalid ones
    fn build_regex_set(patterns: &[String]) -> Option<regex::RegexSet> {
        let valid: Vec<&str> = patterns.iter()
            .filter(|p| regex::Regex::new(p).is_ok())
            .map(|p| p.as_str())
            .collect();
        if valid.is_empty() {
            return None;
        }
        regex::RegexSet::new(&valid).ok()
    }

    /// Rebuild inverted index from sites
    fn rebuild_index(&mut self) {
        self.exact_index.clear();
        self.suffix_index.clear();
        self.keyword_index.clear();
        self.regex_index.clear();

        // Collect regex patterns per site first, then batch-compile
        let mut regex_patterns: HashMap<String, Vec<String>> = HashMap::new();

        for (site, entries) in &self.sites {
            for entry in entries {
                match entry {
                    DomainEntry::Full(domain) => {
                        self.exact_index
                            .entry(domain.clone())
                            .or_default()
                            .insert(site.clone());
                    }
                    DomainEntry::Domain(domain) => {
                        self.suffix_index
                            .entry(domain.clone())
                            .or_default()
                            .insert(site.clone());
                    }
                    DomainEntry::Keyword(keyword) => {
                        self.keyword_index
                            .entry(site.clone())
                            .or_default()
                            .push(keyword.clone());
                    }
                    DomainEntry::Regex(pattern) => {
                        regex_patterns
                            .entry(site.clone())
                            .or_default()
                            .push(pattern.clone());
                    }
                }
            }
        }

        // Build RegexSet per site
        for (site, patterns) in &regex_patterns {
            if let Some(set) = Self::build_regex_set(patterns) {
                self.regex_index.insert(site.clone(), set);
            }
        }
        
        debug!(
            "GeoSite index built: {} exact, {} suffix, {} keyword sites, {} regex sites",
            self.exact_index.len(),
            self.suffix_index.len(),
            self.keyword_index.len(),
            self.regex_index.len()
        );
    }

    /// Load from V2Ray geosite.dat file using geosite-rs
    pub fn load_from_dat(path: &Path) -> Result<Self> {
        if !path.exists() {
            debug!("GeoSite file not found: {:?}", path);
            return Ok(Self::new());
        }

        let data = fs::read(path).map_err(Error::Io)?;
        
        let geosite_list = decode_geosite(&data)
            .map_err(|e| Error::Config(format!("Failed to parse geosite.dat: {}", e)))?;

        let mut geosite = Self::new();
        
        for site in &geosite_list.entry {
            let name = site.country_code.to_lowercase();
            let entries: Vec<DomainEntry> = site.domain.iter().map(DomainEntry::from).collect();
            debug!("Loaded geosite:{} with {} domains", name, entries.len());
            geosite.sites.insert(name, entries);
        }

        // Build inverted index
        geosite.rebuild_index();

        debug!("Loaded {} sites from {:?}", geosite.sites.len(), path);
        Ok(geosite)
    }

    /// Merge builtin sites into this GeoSite (skips existing sites).
    pub fn merge_builtin(&mut self) {
        let builtin = Self::with_builtin();
        for site in builtin.sites() {
            if self.get(site).is_none() {
                if let Some(entries) = builtin.get(site) {
                    self.add_site(site, entries.clone());
                }
            }
        }
    }

    /// Try to load from common locations, merging builtin sites.
    pub fn load_default() -> Self {
        let paths = [
            "geosite.dat",
            "/usr/share/v2ray/geosite.dat",
            "/usr/local/share/v2ray/geosite.dat",
            "/var/lib/v2ray/geosite.dat",
        ];

        for path in paths {
            let path = Path::new(path);
            if path.exists() {
                debug!("Found geosite.dat at {:?}", path);
                match Self::load_from_dat(path) {
                    Ok(mut geosite) if !geosite.sites.is_empty() => {
                        let cn_count = geosite.get("cn").map(|v| v.len()).unwrap_or(0);
                        debug!("Loaded GeoSite from {:?}: {} sites, cn has {} domains", 
                            path, geosite.sites.len(), cn_count);
                        geosite.merge_builtin();
                        return geosite;
                    }
                    Err(e) => {
                        warn!("Failed to load GeoSite from {:?}: {}", path, e);
                    }
                    _ => {
                        debug!("GeoSite from {:?} is empty", path);
                    }
                }
            }
        }

        warn!("No geosite.dat found, using builtin sites (limited coverage)");
        Self::with_builtin()
    }

    /// Load from directory containing text files
    /// Each file is named after the site (e.g., google.txt, cn.txt)
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        let mut geosite = Self::new();

        if !dir.exists() {
            return Ok(geosite);
        }

        for entry in fs::read_dir(dir).map_err(Error::Io)? {
            let entry = entry.map_err(Error::Io)?;
            let path = entry.path();

            if path.extension().map_or(false, |ext| ext == "txt") {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    let domains = Self::parse_text_file(&path)?;
                    geosite.add_site(name, domains);
                }
            }
        }

        Ok(geosite)
    }

    /// Parse text file with domain list
    fn parse_text_file(path: &Path) -> Result<Vec<DomainEntry>> {
        let content = fs::read_to_string(path).map_err(Error::Io)?;
        let mut entries = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let entry = if let Some(domain) = line.strip_prefix("full:") {
                DomainEntry::Full(domain.to_lowercase())
            } else if let Some(domain) = line.strip_prefix("domain:") {
                DomainEntry::Domain(domain.to_lowercase())
            } else if let Some(keyword) = line.strip_prefix("keyword:") {
                DomainEntry::Keyword(keyword.to_lowercase())
            } else if let Some(pattern) = line.strip_prefix("regexp:") {
                DomainEntry::Regex(pattern.to_string())
            } else {
                // Default to domain match
                DomainEntry::Domain(line.to_lowercase())
            };

            entries.push(entry);
        }

        Ok(entries)
    }

    /// Get domains for a site
    pub fn get(&self, site: &str) -> Option<&Vec<DomainEntry>> {
        self.sites.get(&site.to_lowercase())
    }

    /// Iterate domain suffixes without allocation.
    /// e.g., "www.api.bilibili.com" yields:
    ///   "www.api.bilibili.com", "api.bilibili.com", "bilibili.com", "com"
    fn for_each_suffix(domain: &str, mut f: impl FnMut(&str) -> bool) {
        if f(domain) { return; }
        let mut remaining = domain;
        while let Some(pos) = remaining.find('.') {
            remaining = &remaining[pos + 1..];
            if !remaining.is_empty() && f(remaining) {
                return;
            }
        }
    }

    /// Core matching function
    /// - `full_as_suffix`: if true, treat Full entries as suffix match
    /// - `site_filter`: closure to check if a site matches
    fn matches_internal<F>(&self, domain: &str, full_as_suffix: bool, site_filter: F) -> bool
    where
        F: Fn(&str) -> bool,
    {
        let domain_lower = domain.to_lowercase();

        // Check exact_index (Full entries)
        if full_as_suffix {
            let mut found = false;
            Self::for_each_suffix(&domain_lower, |suffix| {
                if let Some(sites) = self.exact_index.get(suffix) {
                    if sites.iter().any(|s| site_filter(s)) {
                        found = true;
                        return true; // early exit
                    }
                }
                false
            });
            if found { return true; }
        } else if let Some(sites) = self.exact_index.get(&domain_lower) {
            if sites.iter().any(|s| site_filter(s)) {
                return true;
            }
        }

        // Check suffix_index (Domain entries) - always suffix match
        {
            let mut found = false;
            Self::for_each_suffix(&domain_lower, |suffix| {
                if let Some(sites) = self.suffix_index.get(suffix) {
                    if sites.iter().any(|s| site_filter(s)) {
                        found = true;
                        return true;
                    }
                }
                false
            });
            if found { return true; }
        }

        // Check keywords — only for sites that pass the filter
        for (site, keywords) in &self.keyword_index {
            if site_filter(site) {
                for keyword in keywords {
                    if domain_lower.contains(keyword.as_str()) {
                        return true;
                    }
                }
            }
        }

        // Check regexes — only for sites that pass the filter
        for (site, regex_set) in &self.regex_index {
            if site_filter(site) && regex_set.is_match(&domain_lower) {
                return true;
            }
        }

        false
    }

    /// Check if a domain matches a site (Full entries require exact match)
    pub fn matches(&self, site: &str, domain: &str) -> bool {
        let site_lower = site.to_lowercase();
        self.matches_internal(domain, false, |s| s == site_lower)
    }

    /// Check if a domain matches a site (Full entries treated as suffix match)
    pub fn matches_as_suffix(&self, site: &str, domain: &str) -> bool {
        let site_lower = site.to_lowercase();
        self.matches_internal(domain, true, |s| s == site_lower)
    }

    /// Check if a domain matches any of the given sites (Full entries treated as suffix match)
    pub fn matches_any(&self, sites: &[&str], domain: &str) -> bool {
        let sites_lower: HashSet<String> = sites.iter().map(|s| s.to_lowercase()).collect();
        self.matches_internal(domain, true, |s| sites_lower.contains(s))
    }

    /// List all available sites
    pub fn sites(&self) -> impl Iterator<Item = &String> {
        self.sites.keys()
    }

    /// Add entries for a site programmatically (also updates index)
    pub fn add_site(&mut self, name: &str, entries: Vec<DomainEntry>) {
        let name_lower = name.to_lowercase();
        let mut regex_patterns = Vec::new();

        for entry in &entries {
            match entry {
                DomainEntry::Full(domain) => {
                    self.exact_index.entry(domain.clone()).or_default().insert(name_lower.clone());
                }
                DomainEntry::Domain(domain) => {
                    self.suffix_index.entry(domain.clone()).or_default().insert(name_lower.clone());
                }
                DomainEntry::Keyword(keyword) => {
                    self.keyword_index.entry(name_lower.clone()).or_default().push(keyword.clone());
                }
                DomainEntry::Regex(pattern) => {
                    regex_patterns.push(pattern.clone());
                }
            }
        }

        if let Some(set) = Self::build_regex_set(&regex_patterns) {
            self.regex_index.insert(name_lower.clone(), set);
        }

        self.sites.insert(name_lower, entries);
    }

    /// Create with built-in common sites
    pub fn with_builtin() -> Self {
        let mut geosite = Self::new();

        // Google
        geosite.add_site("google", vec![
            DomainEntry::Domain("google.com".to_string()),
            DomainEntry::Domain("google.com.hk".to_string()),
            DomainEntry::Domain("googleapis.com".to_string()),
            DomainEntry::Domain("googleusercontent.com".to_string()),
            DomainEntry::Domain("googlevideo.com".to_string()),
            DomainEntry::Domain("gstatic.com".to_string()),
            DomainEntry::Domain("ggpht.com".to_string()),
            DomainEntry::Domain("youtube.com".to_string()),
            DomainEntry::Domain("ytimg.com".to_string()),
            DomainEntry::Domain("youtu.be".to_string()),
            DomainEntry::Domain("gmail.com".to_string()),
            DomainEntry::Domain("googlemail.com".to_string()),
            DomainEntry::Domain("google.co.jp".to_string()),
            DomainEntry::Domain("google.co.uk".to_string()),
            DomainEntry::Domain("blogger.com".to_string()),
            DomainEntry::Domain("blogspot.com".to_string()),
        ]);

        // Facebook
        geosite.add_site("facebook", vec![
            DomainEntry::Domain("facebook.com".to_string()),
            DomainEntry::Domain("fb.com".to_string()),
            DomainEntry::Domain("fbcdn.net".to_string()),
            DomainEntry::Domain("instagram.com".to_string()),
            DomainEntry::Domain("cdninstagram.com".to_string()),
            DomainEntry::Domain("whatsapp.com".to_string()),
            DomainEntry::Domain("whatsapp.net".to_string()),
            DomainEntry::Domain("messenger.com".to_string()),
        ]);

        // Twitter/X
        geosite.add_site("twitter", vec![
            DomainEntry::Domain("twitter.com".to_string()),
            DomainEntry::Domain("x.com".to_string()),
            DomainEntry::Domain("twimg.com".to_string()),
            DomainEntry::Domain("t.co".to_string()),
            DomainEntry::Domain("tweetdeck.com".to_string()),
        ]);

        // Telegram
        geosite.add_site("telegram", vec![
            DomainEntry::Domain("telegram.org".to_string()),
            DomainEntry::Domain("telegram.me".to_string()),
            DomainEntry::Domain("t.me".to_string()),
            DomainEntry::Domain("telesco.pe".to_string()),
        ]);

        // Netflix
        geosite.add_site("netflix", vec![
            DomainEntry::Domain("netflix.com".to_string()),
            DomainEntry::Domain("netflix.net".to_string()),
            DomainEntry::Domain("nflximg.com".to_string()),
            DomainEntry::Domain("nflximg.net".to_string()),
            DomainEntry::Domain("nflxvideo.net".to_string()),
            DomainEntry::Domain("nflxso.net".to_string()),
            DomainEntry::Domain("nflxext.com".to_string()),
        ]);

        // OpenAI / ChatGPT
        geosite.add_site("openai", vec![
            DomainEntry::Domain("openai.com".to_string()),
            DomainEntry::Domain("chatgpt.com".to_string()),
            DomainEntry::Domain("oaistatic.com".to_string()),
            DomainEntry::Domain("oaiusercontent.com".to_string()),
        ]);

        // GitHub
        geosite.add_site("github", vec![
            DomainEntry::Domain("github.com".to_string()),
            DomainEntry::Domain("github.io".to_string()),
            DomainEntry::Domain("githubapp.com".to_string()),
            DomainEntry::Domain("githubassets.com".to_string()),
            DomainEntry::Domain("githubusercontent.com".to_string()),
        ]);

        // China domains (common)
        geosite.add_site("cn", vec![
            DomainEntry::Domain("cn".to_string()),
            DomainEntry::Domain("baidu.com".to_string()),
            DomainEntry::Domain("bdstatic.com".to_string()),
            DomainEntry::Domain("qq.com".to_string()),
            DomainEntry::Domain("gtimg.cn".to_string()),
            DomainEntry::Domain("weixin.qq.com".to_string()),
            DomainEntry::Domain("wechat.com".to_string()),
            DomainEntry::Domain("taobao.com".to_string()),
            DomainEntry::Domain("tmall.com".to_string()),
            DomainEntry::Domain("alicdn.com".to_string()),
            DomainEntry::Domain("alipay.com".to_string()),
            DomainEntry::Domain("alibaba.com".to_string()),
            DomainEntry::Domain("aliyun.com".to_string()),
            DomainEntry::Domain("aliyuncs.com".to_string()),
            DomainEntry::Domain("jd.com".to_string()),
            DomainEntry::Domain("360.cn".to_string()),
            DomainEntry::Domain("163.com".to_string()),
            DomainEntry::Domain("126.com".to_string()),
            DomainEntry::Domain("netease.com".to_string()),
            DomainEntry::Domain("weibo.com".to_string()),
            DomainEntry::Domain("sina.com.cn".to_string()),
            DomainEntry::Domain("sohu.com".to_string()),
            DomainEntry::Domain("douyin.com".to_string()),
            DomainEntry::Domain("toutiao.com".to_string()),
            DomainEntry::Domain("bytedance.com".to_string()),
            DomainEntry::Domain("bilibili.com".to_string()),
            DomainEntry::Domain("bilivideo.com".to_string()),
            DomainEntry::Domain("zhihu.com".to_string()),
            DomainEntry::Domain("douban.com".to_string()),
            DomainEntry::Domain("meituan.com".to_string()),
            DomainEntry::Domain("dianping.com".to_string()),
            DomainEntry::Domain("ctrip.com".to_string()),
            DomainEntry::Domain("pinduoduo.com".to_string()),
            DomainEntry::Domain("xiaomi.com".to_string()),
            DomainEntry::Domain("huawei.com".to_string()),
            DomainEntry::Domain("tencent.com".to_string()),
            DomainEntry::Domain("csdn.net".to_string()),
            DomainEntry::Domain("cnblogs.com".to_string()),
            DomainEntry::Domain("jianshu.com".to_string()),
        ]);

        // Private/LAN
        geosite.add_site("private", vec![
            DomainEntry::Domain("localhost".to_string()),
            DomainEntry::Domain("local".to_string()),
            DomainEntry::Domain("lan".to_string()),
            DomainEntry::Full("localhost".to_string()),
            DomainEntry::Regex(r"^[^.]+$".to_string()), // Single-label names
        ]);

        // Ads (common ad domains)
        geosite.add_site("ads", vec![
            DomainEntry::Domain("doubleclick.net".to_string()),
            DomainEntry::Domain("googlesyndication.com".to_string()),
            DomainEntry::Domain("googleadservices.com".to_string()),
            DomainEntry::Domain("adnxs.com".to_string()),
            DomainEntry::Domain("adsrvr.org".to_string()),
            DomainEntry::Domain("advertising.com".to_string()),
            DomainEntry::Keyword("adserver".to_string()),
            DomainEntry::Keyword("adservice".to_string()),
        ]);

        geosite
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_entry_matches() {
        let domain = DomainEntry::Domain("google.com".to_string());
        assert!(domain.matches("google.com"));
        assert!(domain.matches("www.google.com"));
        assert!(domain.matches("mail.google.com"));
        assert!(!domain.matches("notgoogle.com"));

        let full = DomainEntry::Full("example.com".to_string());
        assert!(full.matches("example.com"));
        assert!(!full.matches("www.example.com"));

        let keyword = DomainEntry::Keyword("facebook".to_string());
        assert!(keyword.matches("facebook.com"));
        assert!(keyword.matches("m.facebook.com"));
        assert!(keyword.matches("facebookcdn.net"));
    }

    #[test]
    fn test_builtin_geosite() {
        let geosite = GeoSite::with_builtin();

        assert!(geosite.matches("google", "www.google.com"));
        assert!(geosite.matches("google", "youtube.com"));
        assert!(geosite.matches("cn", "baidu.com"));
        assert!(geosite.matches("cn", "www.qq.com"));
        assert!(!geosite.matches("cn", "google.com"));
    }

    #[test]
    fn test_matches_as_suffix() {
        let mut geosite = GeoSite::new();
        
        // Add a Full entry (exact match in normal mode)
        geosite.add_site("test", vec![
            DomainEntry::Full("example.com".to_string()),
        ]);
        
        // Normal matches: Full should only match exactly
        assert!(geosite.matches("test", "example.com"));
        assert!(!geosite.matches("test", "www.example.com"));
        assert!(!geosite.matches("test", "sub.example.com"));
        
        // matches_as_suffix: Full should match subdomains too
        assert!(geosite.matches_as_suffix("test", "example.com"));
        assert!(geosite.matches_as_suffix("test", "www.example.com"));
        assert!(geosite.matches_as_suffix("test", "sub.example.com"));
    }

    #[test]
    fn test_load_special_data() {
        use std::path::Path;
        
        let path = Path::new("/home/netium/geosite.dat");
        if !path.exists() {
            println!("geosite.dat not found, skipping test");
            return;
        }
        
        // Load raw data to check actual type values
        let data = std::fs::read(path).unwrap();
        let geosite_list = geosite_rs::decode_geosite(&data).unwrap();
        
        // Find bilibili category and print raw type values
        for site in &geosite_list.entry {
            if site.country_code.to_lowercase() == "bilibili" {
                println!("\nRaw bilibili entries (first 10):");
                for domain in site.domain.iter().take(10) {
                    println!("  type={}, value={}", domain.r#type, domain.value);
                }
                break;
            }
        }
        
        let geosite = GeoSite::load_from_dat(path).unwrap();
        let site_count = geosite.sites().count();
        assert!(site_count > 0, "Should load sites from geosite.dat");
        
        // Test bilibili in different categories
        println!("\napi.bilibili.com in cn: {}", geosite.matches("cn", "api.bilibili.com"));
        println!("api.bilibili.com in geolocation-cn: {}", geosite.matches("geolocation-cn", "api.bilibili.com"));
        println!("api.bilibili.com in bilibili: {}", geosite.matches("bilibili", "api.bilibili.com"));
        
        // Test with suffix matching
        println!("\nWith suffix matching:");
        println!("api.bilibili.com in cn: {}", geosite.matches_as_suffix("cn", "api.bilibili.com"));
        println!("api.bilibili.com in geolocation-cn: {}", geosite.matches_as_suffix("geolocation-cn", "api.bilibili.com"));
        
        // Check bilibili category entries
        if let Some(entries) = geosite.get("bilibili") {
            println!("\nBilibili category has {} entries (parsed):", entries.len());
            for entry in entries.iter().take(5) {
                println!("  {:?}", entry);
            }
        }

        // Print index stats
        println!("\nIndex stats:");
        println!("  exact_index entries: {}", geosite.exact_index.len());
        println!("  suffix_index entries: {}", geosite.suffix_index.len());
        println!("  keyword sites: {}", geosite.keyword_index.len());
        println!("  regex sites: {}", geosite.regex_index.len());

        // Print keyword/regex counts per category for perf analysis
        println!("\nTop keyword categories:");
        let mut kw_counts: Vec<_> = geosite.keyword_index.iter()
            .map(|(site, kws)| (site.as_str(), kws.len()))
            .collect();
        kw_counts.sort_by(|a, b| b.1.cmp(&a.1));
        for (site, count) in kw_counts.iter().take(10) {
            println!("  {}: {} keywords", site, count);
        }

        println!("\nTop regex categories:");
        let mut re_counts: Vec<_> = geosite.regex_index.iter()
            .map(|(site, res)| (site.as_str(), res.len()))
            .collect();
        re_counts.sort_by(|a, b| b.1.cmp(&a.1));
        for (site, count) in re_counts.iter().take(10) {
            println!("  {}: {} regexes", site, count);
        }

        let total_keywords: usize = geosite.keyword_index.values().map(|v| v.len()).sum();
        let total_regexes: usize = geosite.regex_index.values().map(|v| v.len()).sum();
        println!("\nTotal: {} keywords, {} regexes", total_keywords, total_regexes);

        // Show cn/geolocation-cn keyword counts (chinasites path)
        let cn_kw = geosite.keyword_index.get("cn").map(|v| v.len()).unwrap_or(0);
        let geocn_kw = geosite.keyword_index.get("geolocation-cn").map(|v| v.len()).unwrap_or(0);
        let ads_kw = geosite.keyword_index.get("category-ads-all").map(|v| v.len()).unwrap_or(0);
        println!("\nChinaSites keywords: cn={}, geolocation-cn={}", cn_kw, geocn_kw);
        println!("Ads keywords: category-ads-all={}", ads_kw);
    }

    #[test]
    fn test_domain_suffixes() {
        let mut suffixes = Vec::new();
        GeoSite::for_each_suffix("www.api.bilibili.com", |s| {
            suffixes.push(s.to_string());
            false
        });
        assert_eq!(suffixes, vec![
            "www.api.bilibili.com",
            "api.bilibili.com", 
            "bilibili.com",
            "com"
        ]);

        let mut suffixes = Vec::new();
        GeoSite::for_each_suffix("example.com", |s| {
            suffixes.push(s.to_string());
            false
        });
        assert_eq!(suffixes, vec!["example.com", "com"]);

        let mut suffixes = Vec::new();
        GeoSite::for_each_suffix("localhost", |s| {
            suffixes.push(s.to_string());
            false
        });
        assert_eq!(suffixes, vec!["localhost"]);
    }
}
