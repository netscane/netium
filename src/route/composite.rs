//! CompositeRouter — iterates a list of routers, returning the first match.

use std::sync::Arc;

use crate::common::Metadata;

use super::Router;

pub struct CompositeRouter {
    routers: Vec<Arc<dyn Router>>,
}

impl CompositeRouter {
    pub(crate) fn new(routers: Vec<Arc<dyn Router>>) -> Self {
        Self { routers }
    }
}

impl Router for CompositeRouter {
    fn try_select(&self, metadata: &Metadata) -> Option<String> {
        for router in &self.routers {
            if let Some(outbound) = router.try_select(metadata) {
                return Some(outbound);
            }
        }
        None
    }
}
