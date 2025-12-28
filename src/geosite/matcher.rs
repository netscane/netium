//! GeoSite matcher for router integration

use std::path::Path;
use std::sync::Arc;

use crate::error::Result;

use super::GeoSite;

/// Thread-safe GeoSite matcher
#[derive(Clone)]
pub struct GeoSiteMatcher {
    geosite: Arc<GeoSite>,
}

impl GeoSiteMatcher {
    /// Create with builtin sites
    pub fn new() -> Self {
        Self {
            geosite: Arc::new(GeoSite::with_builtin()),
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
        })
    }

    /// Load from default locations or use builtin
    pub fn load_default() -> Self {
        Self {
            geosite: Arc::new(GeoSite::load_default()),
        }
    }

    /// Check if domain matches a geosite
    pub fn matches(&self, site: &str, domain: &str) -> bool {
        self.geosite.matches(site, domain)
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
