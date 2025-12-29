//! GeoSite module for domain-based routing
//!
//! Uses geosite-rs crate to parse V2Ray geosite.dat files.
//! Implements inverted index for fast domain lookup.

mod matcher;

pub use matcher::GeoSiteMatcher;

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
                domain_lower == *s || domain_lower.ends_with(&format!(".{}", s))
            }
            DomainEntry::Full(s) => {
                // Exact match only
                domain_lower == *s
            }
            DomainEntry::Keyword(s) => {
                // Substring/keyword match
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
    /// This is useful for matching subdomains of exact-match entries
    pub fn matches_as_suffix(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        match self {
            DomainEntry::Domain(s) | DomainEntry::Full(s) => {
                // Treat Full as Domain (suffix match)
                domain_lower == *s || domain_lower.ends_with(&format!(".{}", s))
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
        // geosite-rs domain types (from geosite_to_hashmap in geosite-rs):
        // 0 = DOMAIN-KEYWORD (Plain/Keyword - substring match)
        // 1 = DOMAIN-SUFFIX (Domain - suffix match)
        // 2 = DOMAIN (Full - exact match)
        // 3 = DOMAIN-REGEX (Regex)
        match domain.r#type {
            0 => DomainEntry::Keyword(value),                    // Keyword/substring match
            1 => DomainEntry::Domain(value),                     // Domain suffix match
            2 => DomainEntry::Full(value),                       // Full exact match
            3 => DomainEntry::Regex(domain.value.clone()),       // Regex (keep original case)
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
    
    /// Keywords that need substring matching (site_tag, keyword)
    keywords: Vec<(String, String)>,
    
    /// Regex patterns that need regex matching (site_tag, pattern, compiled_regex)
    regexes: Vec<(String, regex::Regex)>,
}

impl GeoSite {
    /// Create empty GeoSite
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a single entry to the inverted index
    fn index_entry(&mut self, site: &str, entry: &DomainEntry) {
        match entry {
            DomainEntry::Full(domain) => {
                self.exact_index
                    .entry(domain.clone())
                    .or_default()
                    .insert(site.to_string());
            }
            DomainEntry::Domain(domain) => {
                self.suffix_index
                    .entry(domain.clone())
                    .or_default()
                    .insert(site.to_string());
            }
            DomainEntry::Keyword(keyword) => {
                self.keywords.push((site.to_string(), keyword.clone()));
            }
            DomainEntry::Regex(pattern) => {
                if let Ok(re) = regex::Regex::new(pattern) {
                    self.regexes.push((site.to_string(), re));
                }
            }
        }
    }

    /// Rebuild inverted index from sites
    fn rebuild_index(&mut self) {
        self.exact_index.clear();
        self.suffix_index.clear();
        self.keywords.clear();
        self.regexes.clear();

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
                        self.keywords.push((site.clone(), keyword.clone()));
                    }
                    DomainEntry::Regex(pattern) => {
                        if let Ok(re) = regex::Regex::new(pattern) {
                            self.regexes.push((site.clone(), re));
                        }
                    }
                }
            }
        }
        
        debug!(
            "GeoSite index built: {} exact, {} suffix, {} keywords, {} regexes",
            self.exact_index.len(),
            self.suffix_index.len(),
            self.keywords.len(),
            self.regexes.len()
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

    /// Try to load from common locations
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
                    Ok(geosite) if !geosite.sites.is_empty() => {
                        let cn_count = geosite.get("cn").map(|v| v.len()).unwrap_or(0);
                        debug!("Loaded GeoSite from {:?}: {} sites, cn has {} domains", 
                            path, geosite.sites.len(), cn_count);
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

    /// Extract domain suffixes for lookup
    /// e.g., "www.api.bilibili.com" -> ["www.api.bilibili.com", "api.bilibili.com", "bilibili.com", "com"]
    fn domain_suffixes(domain: &str) -> Vec<&str> {
        let mut suffixes = vec![domain];
        let mut remaining = domain;
        while let Some(pos) = remaining.find('.') {
            remaining = &remaining[pos + 1..];
            if !remaining.is_empty() {
                suffixes.push(remaining);
            }
        }
        suffixes
    }

    /// Check if a domain matches a site using inverted index
    pub fn matches(&self, site: &str, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        let site_lower = site.to_lowercase();

        // 1. Check exact match index (Full entries)
        if let Some(sites) = self.exact_index.get(&domain_lower) {
            if sites.contains(&site_lower) {
                return true;
            }
        }

        // 2. Check suffix match index (Domain entries)
        // Try each suffix of the domain
        for suffix in Self::domain_suffixes(&domain_lower) {
            if let Some(sites) = self.suffix_index.get(suffix) {
                if sites.contains(&site_lower) {
                    return true;
                }
            }
        }

        // 3. Check keywords (need to iterate)
        for (kw_site, keyword) in &self.keywords {
            if kw_site == &site_lower && domain_lower.contains(keyword) {
                return true;
            }
        }

        // 4. Check regexes (need to iterate)
        for (re_site, re) in &self.regexes {
            if re_site == &site_lower && re.is_match(&domain_lower) {
                return true;
            }
        }

        false
    }

    /// Check if a domain matches a site, treating Full entries as suffix match
    /// Uses inverted index for fast lookup
    pub fn matches_as_suffix(&self, site: &str, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        let site_lower = site.to_lowercase();

        // For suffix matching, both exact_index and suffix_index use suffix matching
        for suffix in Self::domain_suffixes(&domain_lower) {
            // Check exact index (Full entries treated as suffix)
            if let Some(sites) = self.exact_index.get(suffix) {
                if sites.contains(&site_lower) {
                    return true;
                }
            }
            // Check suffix index (Domain entries)
            if let Some(sites) = self.suffix_index.get(suffix) {
                if sites.contains(&site_lower) {
                    return true;
                }
            }
        }

        // Check keywords
        for (kw_site, keyword) in &self.keywords {
            if kw_site == &site_lower && domain_lower.contains(keyword) {
                return true;
            }
        }

        // Check regexes
        for (re_site, re) in &self.regexes {
            if re_site == &site_lower && re.is_match(&domain_lower) {
                return true;
            }
        }

        false
    }

    /// Check if a domain matches any of the given sites (with suffix matching)
    pub fn matches_any_as_suffix(&self, sites: &[&str], domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        let sites_lower: HashSet<String> = sites.iter().map(|s| s.to_lowercase()).collect();

        // Check both indexes with suffix matching
        for suffix in Self::domain_suffixes(&domain_lower) {
            if let Some(matched_sites) = self.exact_index.get(suffix) {
                if matched_sites.iter().any(|s| sites_lower.contains(s)) {
                    return true;
                }
            }
            if let Some(matched_sites) = self.suffix_index.get(suffix) {
                if matched_sites.iter().any(|s| sites_lower.contains(s)) {
                    return true;
                }
            }
        }

        // Check keywords
        for (kw_site, keyword) in &self.keywords {
            if sites_lower.contains(kw_site) && domain_lower.contains(keyword) {
                return true;
            }
        }

        // Check regexes
        for (re_site, re) in &self.regexes {
            if sites_lower.contains(re_site) && re.is_match(&domain_lower) {
                return true;
            }
        }

        false
    }

    /// List all available sites
    pub fn sites(&self) -> impl Iterator<Item = &String> {
        self.sites.keys()
    }

    /// Add entries for a site programmatically (also updates index)
    pub fn add_site(&mut self, name: &str, entries: Vec<DomainEntry>) {
        let name_lower = name.to_lowercase();
        // Update index for each entry
        for entry in &entries {
            self.index_entry(&name_lower, entry);
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
        println!("  keywords: {}", geosite.keywords.len());
        println!("  regexes: {}", geosite.regexes.len());
    }

    #[test]
    fn test_domain_suffixes() {
        let suffixes = GeoSite::domain_suffixes("www.api.bilibili.com");
        assert_eq!(suffixes, vec![
            "www.api.bilibili.com",
            "api.bilibili.com", 
            "bilibili.com",
            "com"
        ]);

        let suffixes = GeoSite::domain_suffixes("example.com");
        assert_eq!(suffixes, vec!["example.com", "com"]);

        let suffixes = GeoSite::domain_suffixes("localhost");
        assert_eq!(suffixes, vec!["localhost"]);
    }
}
