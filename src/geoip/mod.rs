//! GeoIP module - IP geolocation using V2Ray geoip.dat format
//!
//! Supports V2Ray geoip.dat protobuf format via geosite-rs crate

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use geosite_rs::{decode_geoip, Cidr};
use tracing::{debug, warn};

/// CIDR entry for IP matching
#[derive(Clone)]
struct CidrEntry {
    ip: IpAddr,
    prefix: u8,
}

impl CidrEntry {
    fn from_cidr(cidr: &Cidr) -> Option<Self> {
        let ip = match cidr.ip.len() {
            4 => {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&cidr.ip);
                IpAddr::V4(Ipv4Addr::from(bytes))
            }
            16 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&cidr.ip);
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => return None,
        };
        Some(Self {
            ip,
            prefix: cidr.prefix as u8,
        })
    }

    fn contains(&self, addr: IpAddr) -> bool {
        match (self.ip, addr) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let net_bits = u32::from(net);
                let ip_bits = u32::from(ip);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    !0u32 << (32 - self.prefix)
                };
                (net_bits & mask) == (ip_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let net_bits = u128::from(net);
                let ip_bits = u128::from(ip);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    !0u128 << (128 - self.prefix)
                };
                (net_bits & mask) == (ip_bits & mask)
            }
            _ => false, // IPv4 vs IPv6 mismatch
        }
    }
}

/// GeoIP matcher using V2Ray geoip.dat format
#[derive(Clone, Default)]
pub struct GeoIpMatcher {
    /// Country code -> list of CIDR entries
    countries: HashMap<String, Vec<CidrEntry>>,
}

impl GeoIpMatcher {
    /// Create a new empty GeoIP matcher
    pub fn new() -> Self {
        Self {
            countries: HashMap::new(),
        }
    }

    /// Load GeoIP database from V2Ray geoip.dat file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(format!("GeoIP file not found: {:?}", path));
        }

        let data = fs::read(path).map_err(|e| format!("Failed to read geoip.dat: {}", e))?;

        let geoip_list =
            decode_geoip(&data).map_err(|e| format!("Failed to parse geoip.dat: {}", e))?;

        let mut matcher = Self::new();

        for entry in &geoip_list.entry {
            let country_code = entry.country_code.to_uppercase();
            let cidrs: Vec<CidrEntry> = entry
                .cidr
                .iter()
                .filter_map(CidrEntry::from_cidr)
                .collect();

            debug!(
                "Loaded geoip:{} with {} CIDRs",
                country_code,
                cidrs.len()
            );
            matcher.countries.insert(country_code, cidrs);
        }

        debug!(
            "Loaded {} countries from {:?}",
            matcher.countries.len(),
            path
        );
        Ok(matcher)
    }

    /// Try to load GeoIP database from common locations
    pub fn load_default() -> Self {
        let paths = [
            "geoip.dat",
            "/usr/share/v2ray/geoip.dat",
            "/usr/local/share/v2ray/geoip.dat",
            "/var/lib/v2ray/geoip.dat",
        ];

        for path in paths {
            if Path::new(path).exists() {
                match Self::load(path) {
                    Ok(matcher) => {
                        debug!("Loaded GeoIP database from {}", path);
                        return matcher;
                    }
                    Err(e) => {
                        warn!("Failed to load GeoIP database from {}: {}", path, e);
                    }
                }
            }
        }

        debug!("No GeoIP database found, geoip: rules will not match");
        Self::new()
    }

    /// Check if an IP address belongs to a country
    ///
    /// Country code should be ISO 3166-1 alpha-2 (e.g., "CN", "US", "JP")
    pub fn matches(&self, country_code: &str, ip: IpAddr) -> bool {
        let country_code_upper = country_code.to_uppercase();

        if let Some(cidrs) = self.countries.get(&country_code_upper) {
            for cidr in cidrs {
                if cidr.contains(ip) {
                    return true;
                }
            }
        }

        false
    }

    /// Get the country code for an IP address
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        for (country, cidrs) in &self.countries {
            for cidr in cidrs {
                if cidr.contains(ip) {
                    return Some(country.clone());
                }
            }
        }
        None
    }

    /// Check if database is loaded
    pub fn is_loaded(&self) -> bool {
        !self.countries.is_empty()
    }

    /// Get list of loaded country codes
    pub fn countries(&self) -> Vec<&str> {
        self.countries.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geoip_no_database() {
        let matcher = GeoIpMatcher::new();
        assert!(!matcher.is_loaded());
        assert!(!matcher.matches("CN", IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    /* 
    #[test]
    fn test_load_sped_database() {
        let matcher = GeoIpMatcher::load("/home/netium/geoip.dat").unwrap();
        assert!(matcher.is_loaded());
        // 1.1.1.1 is Cloudflare (US/AU), not CN
        assert!(!matcher.matches("CN", IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        // 223.5.5.5 is Alibaba DNS (CN)
        assert!(matcher.matches("CN", IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5))));
        // 8.8.8.8 is Google DNS (US)
        assert!(matcher.matches("US", IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
    */

    #[test]
    fn test_cidr_contains_v4() {
        let cidr = CidrEntry {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
            prefix: 16,
        };
        assert!(cidr.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(cidr.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255))));
        assert!(!cidr.contains(IpAddr::V4(Ipv4Addr::new(192, 169, 0, 1))));
    }

    #[test]
    fn test_cidr_contains_v6() {
        let cidr = CidrEntry {
            ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            prefix: 32,
        };
        assert!(cidr.contains(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 1
        ))));
        assert!(!cidr.contains(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb9, 0, 0, 0, 0, 0, 1
        ))));
    }
}
