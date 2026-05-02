//! Router Layer
//!
//! Middleware chain:
//! ```text
//! FallbackRouter(
//!     LoggingRouter(
//!         CompositeRouter([StaticRouter, DynamicRouter?])
//!     )
//! ).select(metadata)
//! ```

pub mod composite;
pub mod domain_trie;
pub mod dynamic;
pub mod fallback;
pub mod log;
pub mod logging;
pub mod matchers;
pub mod rule;
pub mod static_route;
pub mod stats;

pub use dynamic::{
    DynamicRule, DynamicRuleInput, DynamicRuleManager, DynamicRuleMatchType, DynamicRuleUpdate,
    DynamicRouter,
};
pub use fallback::FallbackRouter;
pub use static_route::{StaticRouterBuilder, StaticRule};
pub use rule::{Rule, RuleType};
pub use stats::RuleStatsSnapshot;

use crate::common::Metadata;

pub(crate) trait Router: Send + Sync {
    fn try_select(&self, metadata: &Metadata) -> Option<String>;
}

impl<T: Router> Router for std::sync::Arc<T> {
    fn try_select(&self, metadata: &Metadata) -> Option<String> {
        self.as_ref().try_select(metadata)
    }
}
