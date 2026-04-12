//! GeoSite matcher for router integration with LRU cache

use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use lru::LruCache;
use parking_lot::Mutex;
use tracing::debug;

use crate::error::Result;

use super::GeoSite;

/// Default cache size for domain lookups
const DEFAULT_CACHE_SIZE: usize = 8192;

/// Thread-safe GeoSite matcher with LRU cache
#[derive(Clone)]
pub struct GeoSiteMatcher {
    geosite: Arc<GeoSite>,
    /// LRU cache for general matches: (site, domain) -> matched
    match_cache: Arc<Mutex<LruCache<(String, String), bool>>>,
    /// LRU cache for is_china_domain results: domain -> is_china
    china_cache: Arc<Mutex<LruCache<String, bool>>>,
}

impl GeoSiteMatcher {
    fn new_caches(size: usize) -> (Arc<Mutex<LruCache<(String, String), bool>>>, Arc<Mutex<LruCache<String, bool>>>) {
        let cap = NonZeroUsize::new(size.max(1)).unwrap();
        (
            Arc::new(Mutex::new(LruCache::new(cap))),
            Arc::new(Mutex::new(LruCache::new(cap))),
        )
    }

    /// Create with builtin sites
    pub fn new() -> Self {
        let (match_cache, china_cache) = Self::new_caches(DEFAULT_CACHE_SIZE);
        Self {
            geosite: Arc::new(GeoSite::with_builtin()),
            match_cache,
            china_cache,
        }
    }

    /// Create with custom cache size
    pub fn with_cache_size(cache_size: usize) -> Self {
        let (match_cache, china_cache) = Self::new_caches(cache_size);
        Self {
            geosite: Arc::new(GeoSite::with_builtin()),
            match_cache,
            china_cache,
        }
    }

    /// Create from geosite.dat file
    pub fn from_dat(path: &Path) -> Result<Self> {
        let mut geosite = GeoSite::load_from_dat(path)?;
        
        // Merge with builtin if dat doesn't have certain sites
        let builtin = GeoSite::with_builtin();
        for site in builtin.sites() {
            if geosite.get(site).is_none() {
                if let Some(entries) = builtin.get(site) {
                    geosite.add_site(site, entries.clone());
                }
            }
        }
        
        let (match_cache, china_cache) = Self::new_caches(DEFAULT_CACHE_SIZE);
        Ok(Self {
            geosite: Arc::new(geosite),
            match_cache,
            china_cache,
        })
    }

    /// Create from directory of text files
    pub fn from_dir(path: &Path) -> Result<Self> {
        let mut geosite = GeoSite::load_from_dir(path)?;
        
        // Merge with builtin
        let builtin = GeoSite::with_builtin();
        for site in builtin.sites() {
            if geosite.get(site).is_none() {
                if let Some(entries) = builtin.get(site) {
                    geosite.add_site(site, entries.clone());
                }
            }
        }
        
        let (match_cache, china_cache) = Self::new_caches(DEFAULT_CACHE_SIZE);
        Ok(Self {
            geosite: Arc::new(geosite),
            match_cache,
            china_cache,
        })
    }

    /// Load from default locations or use builtin
    pub fn load_default() -> Self {
        let (match_cache, china_cache) = Self::new_caches(DEFAULT_CACHE_SIZE);
        Self {
            geosite: Arc::new(GeoSite::load_default()),
            match_cache,
            china_cache,
        }
    }

    /// Check if domain matches a geosite (with LRU cache)
    pub fn matches(&self, site: &str, domain: &str) -> bool {
        let site_lower = site.to_lowercase();
        let domain_lower = domain.to_lowercase();
        let key = (site_lower, domain_lower);

        // Check cache
        {
            let mut cache = self.match_cache.lock();
            if let Some(&result) = cache.get(&key) {
                return result;
            }
        }

        let result = self.geosite.matches(&key.0, &key.1);

        // Store in cache
        {
            let mut cache = self.match_cache.lock();
            cache.put(key, result);
        }

        result
    }

    /// Check if domain matches a geosite, treating Full entries as suffix match
    pub fn matches_as_suffix(&self, site: &str, domain: &str) -> bool {
        self.geosite.matches_as_suffix(site, domain)
    }

    /// Check if domain matches any of the given sites (with suffix matching)
    pub fn matches_any(&self, sites: &[&str], domain: &str) -> bool {
        self.geosite.matches_any(sites, domain)
    }

    /// Check if domain is a China domain (with LRU cache)
    /// Uses cn and geolocation-cn categories with suffix matching
    pub fn is_china_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        
        // Check cache first
        {
            let mut cache = self.china_cache.lock();
            if let Some(&is_china) = cache.get(&domain_lower) {
                return is_china;
            }
        }
        
        // Cache miss - perform actual lookup
        let is_china = self.geosite.matches_any(&["cn", "geolocation-cn"], &domain_lower);
        
        // Store in cache
        {
            let mut cache = self.china_cache.lock();
            cache.put(domain_lower, is_china);
        }
        
        is_china
    }

    /// Get cache statistics: (china_cache_len, capacity)
    pub fn cache_stats(&self) -> (usize, usize) {
        let china = self.china_cache.lock();
        (china.len(), china.cap().get())
    }

    /// Get match cache statistics
    pub fn match_cache_stats(&self) -> (usize, usize) {
        let cache = self.match_cache.lock();
        (cache.len(), cache.cap().get())
    }

    /// Clear all caches
    pub fn clear_cache(&self) {
        self.china_cache.lock().clear();
        self.match_cache.lock().clear();
        debug!("GeoSite caches cleared");
    }

    /// List available sites
    pub fn available_sites(&self) -> Vec<String> {
        self.geosite.sites().cloned().collect()
    }
}

impl Default for GeoSiteMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_hit() {
        let matcher = GeoSiteMatcher::with_cache_size(100);
        
        // First call - cache miss
        let result1 = matcher.is_china_domain("www.baidu.com");
        let (len1, _) = matcher.cache_stats();
        assert_eq!(len1, 1);
        
        // Second call - cache hit (same domain)
        let result2 = matcher.is_china_domain("www.baidu.com");
        let (len2, _) = matcher.cache_stats();
        assert_eq!(len2, 1); // Still 1, no new entry
        
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_cache_different_domains() {
        let matcher = GeoSiteMatcher::with_cache_size(100);
        
        matcher.is_china_domain("www.baidu.com");
        matcher.is_china_domain("www.google.com");
        matcher.is_china_domain("api.bilibili.com");
        
        let (len, _) = matcher.cache_stats();
        assert_eq!(len, 3);
    }

    #[test]
    fn test_cache_clear() {
        let matcher = GeoSiteMatcher::with_cache_size(100);
        
        matcher.is_china_domain("www.baidu.com");
        matcher.is_china_domain("www.google.com");
        
        let (len1, _) = matcher.cache_stats();
        assert_eq!(len1, 2);
        
        matcher.clear_cache();
        
        let (len2, _) = matcher.cache_stats();
        assert_eq!(len2, 0);
    }
}
