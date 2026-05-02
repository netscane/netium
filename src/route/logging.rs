//! LoggingRouter — decorator that records slow routing decisions.

use std::sync::Arc;
use std::time::Instant;

use crate::common::Metadata;

use super::log::{self, SlowQueryLog};
use super::Router;

pub struct LoggingRouter {
    inner: Arc<dyn Router>,
    slow_queries: Arc<SlowQueryLog>,
}

impl LoggingRouter {
    pub(crate) fn new(inner: Arc<dyn Router>) -> Self {
        Self {
            inner,
            slow_queries: Arc::new(SlowQueryLog::new()),
        }
    }

    pub fn slow_query_log(&self) -> &Arc<SlowQueryLog> {
        &self.slow_queries
    }
}

impl Router for LoggingRouter {
    fn try_select(&self, metadata: &Metadata) -> Option<String> {
        let start = Instant::now();
        let result = self.inner.try_select(metadata);
        let elapsed_ns = start.elapsed().as_nanos() as u64;

        if let Some(ref outbound) = result {
            if elapsed_ns > log::SLOW_QUERY_THRESHOLD_NS {
                self.slow_queries.push(log::SlowQuery {
                    destination: metadata.destination.to_string(),
                    outbound: outbound.clone(),
                    elapsed_us: elapsed_ns as f64 / 1000.0,
                    timestamp: log::fmt_timestamp(),
                });
            }
        }

        result
    }
}
