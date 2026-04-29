//! GeoIP module - IP geolocation using V2Ray geoip.dat format
//!
//! Supports V2Ray geoip.dat protobuf format via geosite-rs crate.
//! Uses sorted CIDR lists with binary search for O(log N) lookup.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use geosite_rs::decode_geoip;
use tracing::{debug, warn};

/// Sorted IPv4 CIDR list for binary search
#[derive(Clone, Default)]
struct Ipv4CidrSet {
    /// Sorted by (network_start, prefix) — each entry is (masked_start, prefix_len)
    entries: Vec<(u32, u8)>,
}

impl Ipv4CidrSet {
    fn from_cidrs(cidrs: impl Iterator<Item = (Ipv4Addr, u8)>) -> Self {
        let mut entries: Vec<(u32, u8)> = cidrs
            .map(|(ip, prefix)| {
                let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                (u32::from(ip) & mask, prefix)
            })
            .collect();
        entries.sort_unstable();
        entries.dedup();
        Self { entries }
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        let ip_bits = u32::from(ip);
        // Binary search: find the rightmost entry whose network_start <= ip_bits
        let idx = self.entries.partition_point(|&(start, _)| start <= ip_bits);
        if idx == 0 {
            return false;
        }
        // Check candidates backwards (there may be multiple CIDRs with same start)
        for i in (0..idx).rev() {
            let (start, prefix) = self.entries[i];
            let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
            if (ip_bits & mask) == start {
                return true;
            }
            // If this entry's start is far below, no earlier entry can match
            if start < (ip_bits & (!0u32 << 1)) {
                break;
            }
        }
        false
    }
}

/// Sorted IPv6 CIDR list for binary search
#[derive(Clone, Default)]
struct Ipv6CidrSet {
    entries: Vec<(u128, u8)>,
}

impl Ipv6CidrSet {
    fn from_cidrs(cidrs: impl Iterator<Item = (Ipv6Addr, u8)>) -> Self {
        let mut entries: Vec<(u128, u8)> = cidrs
            .map(|(ip, prefix)| {
                let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
                (u128::from(ip) & mask, prefix)
            })
            .collect();
        entries.sort_unstable();
        entries.dedup();
        Self { entries }
    }

    fn contains(&self, ip: Ipv6Addr) -> bool {
        let ip_bits = u128::from(ip);
        let idx = self.entries.partition_point(|&(start, _)| start <= ip_bits);
        if idx == 0 {
            return false;
        }
        for i in (0..idx).rev() {
            let (start, prefix) = self.entries[i];
            let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
            if (ip_bits & mask) == start {
                return true;
            }
            if start < (ip_bits & (!0u128 << 1)) {
                break;
            }
        }
        false
    }
}

/// Per-country IP sets split by address family
#[derive(Clone, Default)]
struct CountryCidrs {
    v4: Ipv4CidrSet,
    v6: Ipv6CidrSet,
}

/// GeoIP database using V2Ray geoip.dat format.
///
/// Pure data provider — no matching policy, just IP-to-country lookup.
#[derive(Clone, Default)]
pub struct GeoIpDb {
    countries: HashMap<String, CountryCidrs>,
}

impl GeoIpDb {
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

        let mut db = Self::new();

        for entry in &geoip_list.entry {
            let country_code = entry.country_code.to_uppercase();

            let mut v4_cidrs = Vec::new();
            let mut v6_cidrs = Vec::new();

            for cidr in &entry.cidr {
                match cidr.ip.len() {
                    4 => {
                        let mut bytes = [0u8; 4];
                        bytes.copy_from_slice(&cidr.ip);
                        v4_cidrs.push((Ipv4Addr::from(bytes), cidr.prefix as u8));
                    }
                    16 => {
                        let mut bytes = [0u8; 16];
                        bytes.copy_from_slice(&cidr.ip);
                        v6_cidrs.push((Ipv6Addr::from(bytes), cidr.prefix as u8));
                    }
                    _ => {}
                }
            }

            let total = v4_cidrs.len() + v6_cidrs.len();
            debug!("Loaded geoip:{} with {} CIDRs", country_code, total);

            db.countries.insert(country_code, CountryCidrs {
                v4: Ipv4CidrSet::from_cidrs(v4_cidrs.into_iter()),
                v6: Ipv6CidrSet::from_cidrs(v6_cidrs.into_iter()),
            });
        }

        debug!("Loaded {} countries from {:?}", db.countries.len(), path);
        Ok(db)
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
                    Ok(db) => {
                        debug!("Loaded GeoIP database from {}", path);
                        return db;
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

    /// Check if an IP address belongs to a country.
    ///
    /// Country code: ISO 3166-1 alpha-2 (e.g., "CN", "US", "JP")
    pub fn contains(&self, country_code: &str, ip: IpAddr) -> bool {
        let country = self.countries.get(country_code).or_else(|| {
            let upper = country_code.to_uppercase();
            self.countries.get(&upper)
        });

        if let Some(cidrs) = country {
            match ip {
                IpAddr::V4(v4) => cidrs.v4.contains(v4),
                IpAddr::V6(v6) => cidrs.v6.contains(v6),
            }
        } else {
            false
        }
    }

    /// Get the country code for an IP address
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        for (country, cidrs) in &self.countries {
            let found = match ip {
                IpAddr::V4(v4) => cidrs.v4.contains(v4),
                IpAddr::V6(v6) => cidrs.v6.contains(v6),
            };
            if found {
                return Some(country.clone());
            }
        }
        None
    }

    pub fn is_loaded(&self) -> bool {
        !self.countries.is_empty()
    }

    pub fn countries(&self) -> Vec<&str> {
        self.countries.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geoip_no_database() {
        let db = GeoIpDb::new();
        assert!(!db.is_loaded());
        assert!(!db.contains("CN", IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn test_ipv4_cidr_set() {
        let set = Ipv4CidrSet::from_cidrs(
            vec![
                (Ipv4Addr::new(192, 168, 0, 0), 16),
                (Ipv4Addr::new(10, 0, 0, 0), 8),
            ]
            .into_iter(),
        );
        assert!(set.contains(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(set.contains(Ipv4Addr::new(192, 168, 255, 255)));
        assert!(!set.contains(Ipv4Addr::new(192, 169, 0, 1)));
        assert!(set.contains(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(!set.contains(Ipv4Addr::new(11, 0, 0, 1)));
    }

    #[test]
    fn test_ipv6_cidr_set() {
        let set = Ipv6CidrSet::from_cidrs(
            vec![(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32)].into_iter(),
        );
        assert!(set.contains(Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 1)));
        assert!(!set.contains(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_check_cn_ips() {
        let db = GeoIpDb::load("geoip.dat").unwrap();
        assert!(db.is_loaded());

        let test_ips = [
            ("27.44.122.97", true),
            ("101.35.212.35", true),
            ("114.110.97.97", true),
            ("123.234.3.135", true),
            // known CN
            ("223.5.5.5", true),
            // known non-CN
            ("1.1.1.1", false),
            ("8.8.8.8", false),
        ];

        for (ip_str, expect_cn) in &test_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            let result = db.contains("CN", ip);
            println!("{}: CN={} (expected={})", ip_str, result, expect_cn);
            assert_eq!(result, *expect_cn, "IP {} expected CN={} but got {}", ip_str, expect_cn, result);
        }
    }
}
