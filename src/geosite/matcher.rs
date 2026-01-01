//! GeoSite matcher for router integration with LRU cache

use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Arc, Mutex};

use lru::LruCache;
use tracing::debug;

use crate::error::Result;

use super::GeoSite;

/// Default cache size for domain lookups
const DEFAULT_CACHE_SIZE: usize = 4096;

/// Cache entry for is_china_domain results
#[derive(Clone, Copy)]
struct CacheEntry {
    is_china: bool,
}

/// Thread-safe GeoSite matcher with LRU cache
#[derive(Clone)]
pub struct GeoSiteMatcher {
    geosite: Arc<GeoSite>,
    /// LRU cache for is_china_domain results: domain -> is_china
    china_cache: Arc<Mutex<LruCache<String, CacheEntry>>>,
}

impl GeoSiteMatcher {
    /// Create with builtin sites
    pub fn new() -> Self {
        Self {
            geosite: Arc::new(GeoSite::with_builtin()),
            china_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap(),
            ))),
        }
    }

    /// Create with custom cache size
    pub fn with_cache_size(cache_size: usize) -> Self {
        let size = NonZeroUsize::new(cache_size.max(1)).unwrap();
        Self {
            geosite: Arc::new(GeoSite::with_builtin()),
            china_cache: Arc::new(Mutex::new(LruCache::new(size))),
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
        
        Ok(Self {
            geosite: Arc::new(geosite),
            china_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap(),
            ))),
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
        
        Ok(Self {
            geosite: Arc::new(geosite),
            china_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap(),
            ))),
        })
    }

    /// Load from default locations or use builtin
    pub fn load_default() -> Self {
        Self {
            geosite: Arc::new(GeoSite::load_default()),
            china_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap(),
            ))),
        }
    }

    /// Check if domain matches a geosite
    pub fn matches(&self, site: &str, domain: &str) -> bool {
        self.geosite.matches(site, domain)
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
            let mut cache = self.china_cache.lock().unwrap();
            if let Some(entry) = cache.get(&domain_lower) {
                return entry.is_china;
            }
        }
        
        // Cache miss - perform actual lookup
        let is_china = self.geosite.matches_any(&["cn", "geolocation-cn"], &domain_lower);
        
        // Store in cache
        {
            let mut cache = self.china_cache.lock().unwrap();
            cache.put(domain_lower, CacheEntry { is_china });
        }
        
        is_china
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let cache = self.china_cache.lock().unwrap();
        (cache.len(), cache.cap().get())
    }

    /// Clear the cache
    pub fn clear_cache(&self) {
        let mut cache = self.china_cache.lock().unwrap();
        cache.clear();
        debug!("GeoSite cache cleared");
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
