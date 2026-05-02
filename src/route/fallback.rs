//! FallbackRouter — decorator that provides a default outbound when the inner
//! router returns None, and records fallback destinations.

use std::sync::Arc;

use crate::common::Metadata;

use super::log::FallbackDestinationLog;
use super::Router;

pub struct FallbackRouter {
    inner: Arc<dyn Router>,
    default_outbound: String,
    fallback_log: Arc<FallbackDestinationLog>,
}

impl FallbackRouter {
    pub(crate) fn new(inner: Arc<dyn Router>, default_outbound: impl Into<String>) -> Self {
        Self {
            inner,
            default_outbound: default_outbound.into(),
            fallback_log: Arc::new(FallbackDestinationLog::new()),
        }
    }

    pub fn fallback_log(&self) -> &Arc<FallbackDestinationLog> {
        &self.fallback_log
    }

    /// Convenience: resolves the final outbound, always returning a value.
    pub fn select(&self, metadata: &Metadata) -> String {
        match self.try_select(metadata) {
            Some(outbound) => outbound,
            None => self.default_outbound.clone(), // unreachable: try_select always returns Some
        }
    }
}

impl Router for FallbackRouter {
    fn try_select(&self, metadata: &Metadata) -> Option<String> {
        match self.inner.try_select(metadata) {
            Some(outbound) => Some(outbound),
            None => {
                self.fallback_log
                    .record(metadata.destination.to_string());
                Some(self.default_outbound.clone())
            }
        }
    }
}
