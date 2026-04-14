//! Router Layer
//!
//! Responsibilities:
//! - Route selection based on Metadata
//! - NO IO operations
//! - NO async operations
//!
//! Router is a pure function: Metadata -> outbound_tag

pub mod domain_trie;
pub mod matchers;
pub mod rule_router;
pub mod stats;

pub use rule_router::{Rule, RuleRouterBuilder, RuleType};
pub use stats::RuleStatsSnapshot;

use std::any::Any;

use crate::common::Metadata;

/// Router trait - pure function for routing decisions
///
/// IMPORTANT: Router must NOT perform any IO or async operations.
/// It only reads Metadata and returns an outbound tag.
pub trait Router: Send + Sync {
    fn select(&self, metadata: &Metadata) -> &str;
    fn as_any(&self) -> &dyn Any;
}

/// Simple router that always returns the same outbound
pub struct StaticRouter {
    outbound: String,
}

impl StaticRouter {
    pub fn new(outbound: impl Into<String>) -> Self {
        Self { outbound: outbound.into() }
    }
}

impl Router for StaticRouter {
    fn select(&self, _metadata: &Metadata) -> &str {
        &self.outbound
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Default for StaticRouter {
    fn default() -> Self {
        Self::new("direct")
    }
}
