//! Router statistics types and snapshots

use std::sync::atomic::{AtomicU64, Ordering};

/// Statistics for a single rule
#[derive(Debug)]
pub struct RuleStat {
    pub hits: AtomicU64,
    pub match_time_ns: AtomicU64,
    pub eval_count: AtomicU64,
}

impl Default for RuleStat {
    fn default() -> Self {
        Self {
            hits: AtomicU64::new(0),
            match_time_ns: AtomicU64::new(0),
            eval_count: AtomicU64::new(0),
        }
    }
}

impl Clone for RuleStat {
    fn clone(&self) -> Self {
        Self {
            hits: AtomicU64::new(self.hits.load(Ordering::Relaxed)),
            match_time_ns: AtomicU64::new(self.match_time_ns.load(Ordering::Relaxed)),
            eval_count: AtomicU64::new(self.eval_count.load(Ordering::Relaxed)),
        }
    }
}

/// Snapshot of rule statistics for reporting
#[derive(Debug, Clone)]
pub struct RuleStatsSnapshot {
    pub rule_desc: String,
    pub hits: u64,
    pub percent: f64,
    pub avg_match_time_us: f64,
    pub total_match_time_us: f64,
}
