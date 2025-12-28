//! Router Layer
//!
//! Responsibilities:
//! - Route selection based on Metadata
//! - NO IO operations
//! - NO async operations
//!
//! Router is a pure function: Metadata -> outbound_tag

pub mod rule_router;

pub use rule_router::RuleRouter;

use crate::common::Metadata;

/// Router trait - pure function for routing decisions
///
/// IMPORTANT: Router must NOT perform any IO or async operations.
/// It only reads Metadata and returns an outbound tag.
pub trait Router: Send + Sync {
    /// Select an outbound based on metadata
    ///
    /// This is a pure function - no IO, no side effects.
    fn select(&self, metadata: &Metadata) -> &str;
}

/// Simple router that always returns the same outbound
pub struct StaticRouter {
    outbound: String,
}

impl StaticRouter {
    pub fn new(outbound: impl Into<String>) -> Self {
        Self {
            outbound: outbound.into(),
        }
    }
}

impl Router for StaticRouter {
    fn select(&self, _metadata: &Metadata) -> &str {
        &self.outbound
    }
}

impl Default for StaticRouter {
    fn default() -> Self {
        Self::new("direct")
    }
}
