//! GeoSite module for domain-based routing
//!
//! Uses geosite-rs crate to parse V2Ray geosite.dat files.

mod matcher;

pub use matcher::GeoSiteMatcher;

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use geosite_rs::{Domain, decode_geosite};
use tracing::{debug, warn};

use crate::error::{Error, Result};

/// Domain entry with match type
#[derive(Debug, Clone)]
pub enum DomainEntry {
    /// Plain domain (substring match)
    Plain(String),
    /// Domain suffix match (domain and subdomains)
    Domain(String),
    /// Full domain match
    Full(String),
    /// Keyword match
    Keyword(String),
    /// Regex match
    Regex(String),
}

impl DomainEntry {
    /// Check if domain matches this entry
    pub fn matches(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        match self {
            DomainEntry::Plain(s) => domain_lower.contains(s),
            DomainEntry::Domain(s) => {
                domain_lower == *s || domain_lower.ends_with(&format!(".{}", s))
            }
            DomainEntry::Full(s) => domain_lower == *s,
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
        // geosite-rs domain types:
        // 0 = Plain (keyword match)
        // 1 = Domain (suffix match) - note: this is Regex in v2ray proto but Domain in geosite-rs
        // 2 = Full (exact match)
        // 3 = Regex
        match domain.r#type {
            0 => DomainEntry::Keyword(value),  // Plain/Keyword
            1 => DomainEntry::Domain(value),   // Domain suffix
            2 => DomainEntry::Full(value),     // Full exact match
            3 => DomainEntry::Regex(domain.value.clone()), // Regex (keep original case)
            _ => DomainEntry::Domain(value),   // Default to domain
        }
    }
}

/// GeoSite database
#[derive(Debug, Default)]
pub struct GeoSite {
    /// Map of site tag to domain entries
    sites: HashMap<String, Vec<DomainEntry>>,
}

impl GeoSite {
    /// Create empty GeoSite
    pub fn new() -> Self {
        Self::default()
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
                match Self::load_from_dat(path) {
                    Ok(geosite) if !geosite.sites.is_empty() => {
                        debug!("Loaded GeoSite from {:?}", path);
                        return geosite;
                    }
                    Err(e) => {
                        warn!("Failed to load GeoSite from {:?}: {}", path, e);
                    }
                    _ => {}
                }
            }
        }

        debug!("No geosite.dat found, using builtin sites");
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
                    geosite.sites.insert(name.to_lowercase(), domains);
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

    /// Check if a domain matches a site
    pub fn matches(&self, site: &str, domain: &str) -> bool {
        if let Some(entries) = self.get(site) {
            entries.iter().any(|e| e.matches(domain))
        } else {
            false
        }
    }

    /// List all available sites
    pub fn sites(&self) -> impl Iterator<Item = &String> {
        self.sites.keys()
    }

    /// Add entries for a site programmatically
    pub fn add_site(&mut self, name: &str, entries: Vec<DomainEntry>) {
        self.sites.insert(name.to_lowercase(), entries);
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
    fn test_load_special_data() {
        use std::path::Path;
        
        let geosite = GeoSite::load_from_dat(Path::new("/home/netium/geosite.dat")).unwrap();
        let site_count = geosite.sites().count();
        assert!(site_count > 0, "Should load sites from geosite.dat");
        
        // Verify common categories exist
        assert!(geosite.sites().any(|s| s == "google"), "Should have google category");
        assert!(geosite.sites().any(|s| s == "cn"), "Should have cn category");
        
        // Test domain matching (exact domains depend on geosite.dat content)
        // google.com is typically a "full" match in geosite data
        assert!(geosite.matches("google", "google.com"), "google.com should match google");
        
        // cn category should contain Chinese domains
        assert!(geosite.matches("cn", "baidu.com"), "baidu.com should match cn");
    }
}
