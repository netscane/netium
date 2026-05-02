//! Rule types (config-level).

use crate::common::Network;

// ============================================================================
// Rule type enum
// ============================================================================

#[derive(Debug, Clone, Default, PartialEq)]
pub enum RuleType {
    #[default]
    Field,
    ChinaSites,
    ChinaIp,
    PrivateIp,
    All,
}

impl RuleType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "field" => Self::Field,
            "chinasites" | "china_sites" | "china-sites" => Self::ChinaSites,
            "chinaip" | "china_ip" | "china-ip" => Self::ChinaIp,
            "privateip" | "private_ip" | "private-ip" | "private" => Self::PrivateIp,
            "all" | "any" | "*" => Self::All,
            _ => Self::Field,
        }
    }
}

// ============================================================================
// Rule definition (config input)
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct Rule {
    pub rule_type: RuleType,
    pub label: Option<String>,
    pub record_destination: bool,
    pub inbound_tag: Vec<String>,
    pub protocol: Vec<String>,
    pub network: Vec<Network>,
    pub domain: Vec<String>,
    pub ip: Vec<String>,
    pub port: Option<String>,
    pub outbound_tag: String,
}

