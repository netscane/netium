//! Dynamic routing rules — user-managed rules that can be added/edited/removed at runtime.
//!
//! The DynamicRuleManager persists individual rule items to a JSON file and
//! compiles them into efficient matchers grouped by outbound tag. Matchers are
//! rebuilt whenever items are added, updated, removed, or reloaded.

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ipnet::IpNet;
use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::common::{Address, Metadata};
use crate::error::{Error, Result};

use super::matchers::{
    DomainMatcher, DomainMatcherBuilder, IpMatcher, IpMatcherBuilder, PortMatcher,
};
use super::Router;

// ============================================================================
// Match types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DynamicRuleMatchType {
    Exact,
    Domain,
    Wildcard,
    Regex,
    Ip,
    Cidr,
}

// ============================================================================
// DynamicRule — individual user rule item (persisted to JSON)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicRule {
    pub id: String,
    pub enabled: bool,
    pub match_type: DynamicRuleMatchType,
    pub pattern: String,
    #[serde(default)]
    pub port: Option<u16>,
    pub outbound: String,
    pub priority: i32,
    #[serde(default)]
    pub comment: String,
    pub created_at: u64,
    pub updated_at: u64,
}

// ============================================================================
// API input / update types
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct DynamicRuleInput {
    pub enabled: Option<bool>,
    pub match_type: DynamicRuleMatchType,
    pub pattern: String,
    pub port: Option<u16>,
    pub outbound: String,
    pub priority: Option<i32>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DynamicRuleUpdate {
    pub id: String,
    pub enabled: Option<bool>,
    pub match_type: Option<DynamicRuleMatchType>,
    pub pattern: Option<String>,
    pub port: Option<Option<u16>>,
    pub outbound: Option<String>,
    pub priority: Option<i32>,
    pub comment: Option<String>,
}

// ============================================================================
// Persistence format
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DynamicRuleFile {
    version: u32,
    rules: Vec<DynamicRule>,
}

impl Default for DynamicRuleFile {
    fn default() -> Self {
        Self {
            version: 1,
            rules: Vec::new(),
        }
    }
}

// ============================================================================
// Compiled matchers — built from DynamicRule items, grouped by outbound
// ============================================================================

struct CompiledGroup {
    outbound: String,
    priority: i32,
    domain_matcher: Option<DomainMatcher>,
    ip_matcher: Option<IpMatcher>,
    port_matcher: Option<PortMatcher>,
}

/// Compiled form of all dynamic rule items, sorted by priority.
struct CompiledDynamic {
    groups: Vec<CompiledGroup>,
}

impl std::fmt::Debug for CompiledDynamic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledDynamic")
            .field("groups", &self.groups.len())
            .finish()
    }
}

impl CompiledDynamic {
    fn from_items(items: &[DynamicRule]) -> Self {
        let enabled: Vec<&DynamicRule> = items.iter().filter(|r| r.enabled).collect();

        // Group items by (outbound, port) — rules with different port constraints
        // must NOT be merged into the same group.
        let mut by_key: HashMap<(&str, Option<u16>), Vec<&DynamicRule>> = HashMap::new();
        for item in &enabled {
            by_key
                .entry((item.outbound.as_str(), item.port))
                .or_default()
                .push(item);
        }

        // For each group, build compiled matchers
        let mut groups: Vec<CompiledGroup> = by_key
            .into_iter()
            .map(|((outbound, port), rules)| {
                let max_priority = rules.iter().map(|r| r.priority).max().unwrap_or(100);

                let mut domain_builder = DomainMatcherBuilder::new();
                let mut ip_builder = IpMatcherBuilder::new();

                for rule in &rules {
                    match rule.match_type {
                        DynamicRuleMatchType::Exact => {
                            if rule.pattern.parse::<IpAddr>().is_ok() {
                                if let Ok(ip) = rule.pattern.parse() {
                                    ip_builder.add_exact(ip);
                                }
                            } else {
                                domain_builder.add_exact(&rule.pattern);
                            }
                        }
                        DynamicRuleMatchType::Domain => {
                            domain_builder.add_suffix(&rule.pattern);
                        }
                        DynamicRuleMatchType::Wildcard => {
                            let escaped =
                                regex::escape(&rule.pattern).replace("\\*", "[^.]+");
                            domain_builder.add_regex(&format!("^{}$", escaped));
                        }
                        DynamicRuleMatchType::Regex => {
                            domain_builder.add_regex(&rule.pattern);
                        }
                        DynamicRuleMatchType::Ip => {
                            if let Ok(ip) = rule.pattern.parse() {
                                ip_builder.add_exact(ip);
                            }
                        }
                        DynamicRuleMatchType::Cidr => {
                            if let Ok(net) = rule.pattern.parse() {
                                ip_builder.add_cidr(net);
                            }
                        }
                    }
                }

                CompiledGroup {
                    outbound: outbound.to_string(),
                    priority: max_priority,
                    domain_matcher: domain_builder.build(),
                    ip_matcher: ip_builder.build(),
                    port_matcher: port.and_then(|p| PortMatcher::build(&p.to_string())),
                }
            })
            .collect();

        // Sort groups by priority ascending — lower priority processed first,
        // higher priority rules override by matching last.
        groups.sort_by(|a, b| a.priority.cmp(&b.priority));
        CompiledDynamic { groups }
    }

    fn match_outbound(&self, metadata: &Metadata) -> Option<String> {
        let mut outbound = None;
        for group in &self.groups {
            // Check port
            if let Some(pm) = &group.port_matcher {
                if !pm.matches(metadata.destination.port()) {
                    continue;
                }
            }

            let matched = match &metadata.destination {
                Address::Domain(domain, _) => group
                    .domain_matcher
                    .as_ref()
                    .map(|dm| dm.matches(domain))
                    .unwrap_or(false),
                Address::Socket(addr) => group
                    .ip_matcher
                    .as_ref()
                    .map(|im| im.matches(addr.ip()))
                    .unwrap_or(false),
            };

            if matched {
                outbound = Some(group.outbound.clone());
            }
        }
        outbound
    }
}

// ============================================================================
// DynamicRuleManager
// ============================================================================

#[derive(Debug)]
pub struct DynamicRuleManager {
    path: PathBuf,
    items: RwLock<Vec<DynamicRule>>,
    compiled: RwLock<CompiledDynamic>,
}

impl DynamicRuleManager {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let items = sort_rules(load_rules(&path)?);
        let compiled = CompiledDynamic::from_items(&items);
        Ok(Self {
            path,
            items: RwLock::new(items),
            compiled: RwLock::new(compiled),
        })
    }

    fn rebuild(&self) {
        let items = self.items.read();
        *self.compiled.write() = CompiledDynamic::from_items(&items);
    }

    pub fn list(&self) -> Vec<DynamicRule> {
        self.items.read().clone()
    }

    pub fn add(&self, input: DynamicRuleInput) -> Result<DynamicRule> {
        validate_rule(&input.match_type, &input.pattern, input.port)?;

        let now = unix_secs();
        let rule = DynamicRule {
            id: Uuid::new_v4().to_string(),
            enabled: input.enabled.unwrap_or(true),
            match_type: input.match_type,
            pattern: input.pattern,
            port: input.port,
            outbound: input.outbound,
            priority: input.priority.unwrap_or(100),
            comment: input.comment.unwrap_or_default(),
            created_at: now,
            updated_at: now,
        };

        {
            let mut items = self.items.write();
            items.push(rule.clone());
            *items = sort_rules(std::mem::take(&mut *items));
            save_rules(&self.path, &items)?;
        }
        self.rebuild();
        Ok(rule)
    }

    pub fn update(&self, update: DynamicRuleUpdate) -> Result<DynamicRule> {
        let mut items = self.items.write();
        let rule = items
            .iter_mut()
            .find(|r| r.id == update.id)
            .ok_or_else(|| Error::Config(format!("dynamic rule not found: {}", update.id)))?;

        let next_match_type = update
            .match_type
            .clone()
            .unwrap_or_else(|| rule.match_type.clone());
        let next_pattern = update
            .pattern
            .clone()
            .unwrap_or_else(|| rule.pattern.clone());
        let next_port = update.port.unwrap_or(rule.port);
        validate_rule(&next_match_type, &next_pattern, next_port)?;

        if let Some(enabled) = update.enabled {
            rule.enabled = enabled;
        }
        rule.match_type = next_match_type;
        rule.pattern = next_pattern;
        rule.port = next_port;
        if let Some(outbound) = update.outbound {
            rule.outbound = outbound;
        }
        if let Some(priority) = update.priority {
            rule.priority = priority;
        }
        if let Some(comment) = update.comment {
            rule.comment = comment;
        }
        rule.updated_at = unix_secs();

        let updated = rule.clone();
        *items = sort_rules(std::mem::take(&mut *items));
        save_rules(&self.path, &items)?;
        drop(items);
        self.rebuild();
        Ok(updated)
    }

    pub fn remove(&self, id: &str) -> Result<()> {
        let mut items = self.items.write();
        let before = items.len();
        items.retain(|r| r.id != id);
        if items.len() == before {
            return Err(Error::Config(format!("dynamic rule not found: {}", id)));
        }
        save_rules(&self.path, &items)?;
        drop(items);
        self.rebuild();
        Ok(())
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<DynamicRule> {
        self.update(DynamicRuleUpdate {
            id: id.to_string(),
            enabled: Some(enabled),
            match_type: None,
            pattern: None,
            port: None,
            outbound: None,
            priority: None,
            comment: None,
        })
    }

    pub fn reload(&self) -> Result<Vec<DynamicRule>> {
        let items = sort_rules(load_rules(&self.path)?);
        *self.items.write() = items.clone();
        *self.compiled.write() = CompiledDynamic::from_items(&items);
        Ok(items)
    }

    pub fn match_outbound(&self, metadata: &Metadata) -> Option<String> {
        self.compiled.read().match_outbound(metadata)
    }
}

// ============================================================================
// DynamicRouter — wraps DynamicRuleManager as a Router
// ============================================================================

/// A Router backed by the dynamic rule manager. Its `try_select` returns the
/// outbound if any dynamic rule item matches, or `None` to let the next router
/// in the chain decide.
pub struct DynamicRouter {
    manager: Arc<DynamicRuleManager>,
}

impl DynamicRouter {
    pub fn new(manager: Arc<DynamicRuleManager>) -> Self {
        Self { manager }
    }
}

impl Router for DynamicRouter {
    fn try_select(&self, metadata: &Metadata) -> Option<String> {
        self.manager.match_outbound(metadata)
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn sort_rules(mut rules: Vec<DynamicRule>) -> Vec<DynamicRule> {
    rules.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.created_at.cmp(&b.created_at))
            .then_with(|| a.id.cmp(&b.id))
    });
    rules
}

fn load_rules(path: &Path) -> Result<Vec<DynamicRule>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(path)?;
    let file: DynamicRuleFile = serde_json::from_str(&content)
        .map_err(|e| Error::Config(format!("failed to parse dynamic rules: {}", e)))?;
    Ok(file.rules)
}

fn save_rules(path: &Path, rules: &[DynamicRule]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }

    let file = DynamicRuleFile {
        version: 1,
        rules: rules.to_vec(),
    };
    let json = serde_json::to_string_pretty(&file)
        .map_err(|e| Error::Config(format!("failed to encode dynamic rules: {}", e)))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, json)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn validate_rule(
    match_type: &DynamicRuleMatchType,
    pattern: &str,
    _port: Option<u16>,
) -> Result<()> {
    if pattern.trim().is_empty() {
        return Err(Error::Config(
            "dynamic rule pattern cannot be empty".to_string(),
        ));
    }

    match match_type {
        DynamicRuleMatchType::Regex => {
            Regex::new(pattern)
                .map_err(|e| Error::Config(format!("invalid dynamic rule regex: {}", e)))?;
        }
        DynamicRuleMatchType::Ip => {
            pattern
                .parse::<IpAddr>()
                .map_err(|e| Error::Config(format!("invalid dynamic rule ip: {}", e)))?;
        }
        DynamicRuleMatchType::Cidr => {
            pattern
                .parse::<IpNet>()
                .map_err(|e| Error::Config(format!("invalid dynamic rule cidr: {}", e)))?;
        }
        _ => {}
    }

    Ok(())
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Address;

    #[test]
    fn domain_rule_matches_via_manager() {
        let mgr = unseeded_manager(vec![DynamicRule {
            id: "1".to_string(),
            enabled: true,
            match_type: DynamicRuleMatchType::Domain,
            pattern: "example.com".to_string(),
            port: None,
            outbound: "direct".to_string(),
            priority: 100,
            comment: String::new(),
            created_at: 0,
            updated_at: 0,
        }]);

        assert_eq!(
            mgr.match_outbound(&Metadata::new(Address::domain("example.com", 443))),
            Some("direct".to_string())
        );
        assert_eq!(
            mgr.match_outbound(&Metadata::new(Address::domain("api.example.com", 443))),
            Some("direct".to_string())
        );
        assert_eq!(
            mgr.match_outbound(&Metadata::new(Address::domain("other.com", 443))),
            None
        );
    }

    #[test]
    fn port_filter_via_manager() {
        let mgr = unseeded_manager(vec![DynamicRule {
            id: "1".to_string(),
            enabled: true,
            match_type: DynamicRuleMatchType::Domain,
            pattern: "example.com".to_string(),
            port: Some(443),
            outbound: "proxy".to_string(),
            priority: 100,
            comment: String::new(),
            created_at: 0,
            updated_at: 0,
        }]);

        assert_eq!(
            mgr.match_outbound(&Metadata::new(Address::domain("example.com", 443))),
            Some("proxy".to_string())
        );
        assert_eq!(
            mgr.match_outbound(&Metadata::new(Address::domain("example.com", 80))),
            None
        );
    }

    #[test]
    fn disabled_rule_skipped() {
        let mgr = unseeded_manager(vec![DynamicRule {
            id: "1".to_string(),
            enabled: false,
            match_type: DynamicRuleMatchType::Domain,
            pattern: "example.com".to_string(),
            port: None,
            outbound: "direct".to_string(),
            priority: 100,
            comment: String::new(),
            created_at: 0,
            updated_at: 0,
        }]);

        assert_eq!(
            mgr.match_outbound(&Metadata::new(Address::domain("example.com", 443))),
            None
        );
    }

    #[test]
    fn priority_order_is_respected() {
        let mgr = unseeded_manager(vec![
            DynamicRule {
                id: "1".to_string(),
                enabled: true,
                match_type: DynamicRuleMatchType::Domain,
                pattern: "example.com".to_string(),
                port: None,
                outbound: "low".to_string(),
                priority: 50,
                comment: String::new(),
                created_at: 0,
                updated_at: 0,
            },
            DynamicRule {
                id: "2".to_string(),
                enabled: true,
                match_type: DynamicRuleMatchType::Exact,
                pattern: "example.com".to_string(),
                port: None,
                outbound: "high".to_string(),
                priority: 200,
                comment: String::new(),
                created_at: 0,
                updated_at: 0,
            },
        ]);

        assert_eq!(
            mgr.match_outbound(&Metadata::new(Address::domain("example.com", 443))),
            Some("high".to_string())
        );
    }

    #[test]
    fn cidr_matches_ip_on_any_port() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        // Simulate the bug scenario: a domain rule with port=443 and a CIDR rule
        // with port=None on the same outbound. The CIDR rule must still match
        // IP requests on port 80.
        let mgr = unseeded_manager(vec![
            DynamicRule {
                id: "1".to_string(),
                enabled: true,
                match_type: DynamicRuleMatchType::Domain,
                pattern: "t.me".to_string(),
                port: Some(443),
                outbound: "proxy".to_string(),
                priority: 100,
                comment: String::new(),
                created_at: 0,
                updated_at: 0,
            },
            DynamicRule {
                id: "2".to_string(),
                enabled: true,
                match_type: DynamicRuleMatchType::Cidr,
                pattern: "149.154.160.0/20".to_string(),
                port: None,
                outbound: "proxy".to_string(),
                priority: 100,
                comment: String::new(),
                created_at: 0,
                updated_at: 0,
            },
            DynamicRule {
                id: "3".to_string(),
                enabled: true,
                match_type: DynamicRuleMatchType::Cidr,
                pattern: "91.108.56.0/22".to_string(),
                port: None,
                outbound: "proxy".to_string(),
                priority: 100,
                comment: String::new(),
                created_at: 0,
                updated_at: 0,
            },
        ]);

        // IP requests on port 80 must match CIDR rules
        let test_cases: &[(&str, u16, bool)] = &[
            ("91.108.56.166", 80, true),
            ("149.154.175.55", 80, true),
            ("149.154.167.41", 80, true),
            ("149.154.167.91", 80, true),
            // Also works on port 443
            ("149.154.167.91", 443, true),
            // Outside CIDR range
            ("8.8.8.8", 80, false),
        ];

        for &(ip_str, port, expect_match) in test_cases {
            let ip: IpAddr = ip_str.parse().unwrap();
            let addr = Address::Socket(SocketAddr::new(ip, port));
            let result = mgr.match_outbound(&Metadata::new(addr));
            assert_eq!(
                result.is_some(),
                expect_match,
                "{}:{} expected match={}, got {:?}",
                ip_str,
                port,
                expect_match,
                result
            );
        }

        // Domain rule with port=443 still works
        assert_eq!(
            mgr.match_outbound(&Metadata::new(Address::domain("t.me", 443))),
            Some("proxy".to_string())
        );
        // Domain rule does NOT match port 80
        assert_eq!(
            mgr.match_outbound(&Metadata::new(Address::domain("t.me", 80))),
            None
        );
    }

    fn unseeded_manager(rules: Vec<DynamicRule>) -> DynamicRuleManager {
        DynamicRuleManager {
            path: PathBuf::from("/nonexistent"),
            items: RwLock::new(sort_rules(rules.clone())),
            compiled: RwLock::new(CompiledDynamic::from_items(&rules)),
        }
    }
}
