//! Observability: slow-query log and fallback-destination tracking.

use std::collections::{HashMap, VecDeque};

use parking_lot::Mutex;

// ============================================================================
// Slow query log
// ============================================================================

pub(crate) const SLOW_QUERY_THRESHOLD_NS: u64 = 500_000;

const SLOW_QUERY_MAX_ENTRIES: usize = 256;
const FALLBACK_DESTINATION_MAX_ENTRIES: usize = 4096;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SlowQuery {
    pub destination: String,
    pub outbound: String,
    pub elapsed_us: f64,
    pub timestamp: String,
}

pub struct SlowQueryLog {
    entries: Mutex<VecDeque<SlowQuery>>,
}

impl SlowQueryLog {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(SLOW_QUERY_MAX_ENTRIES)),
        }
    }

    pub fn push(&self, query: SlowQuery) {
        let mut entries = self.entries.lock();
        if entries.len() >= SLOW_QUERY_MAX_ENTRIES {
            entries.pop_front();
        }
        entries.push_back(query);
    }

    pub fn snapshot(&self) -> Vec<SlowQuery> {
        self.entries.lock().iter().cloned().collect()
    }

    pub fn clear(&self) {
        self.entries.lock().clear();
    }
}

// ============================================================================
// Fallback destination log — records destinations that hit the default outbound
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct FallbackDestination {
    pub destination: String,
    pub hits: u64,
    pub first_seen: String,
    pub last_seen: String,
}

pub struct FallbackDestinationLog {
    entries: Mutex<HashMap<String, FallbackDestination>>,
}

impl FallbackDestinationLog {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::with_capacity(FALLBACK_DESTINATION_MAX_ENTRIES)),
        }
    }

    pub fn record(&self, destination: String) {
        let now = fmt_timestamp();
        let mut entries = self.entries.lock();

        if let Some(entry) = entries.get_mut(&destination) {
            entry.hits += 1;
            entry.last_seen = now;
            return;
        }

        if entries.len() >= FALLBACK_DESTINATION_MAX_ENTRIES {
            if let Some(evict_key) = entries
                .iter()
                .min_by_key(|(_, entry)| (entry.hits, entry.last_seen.clone()))
                .map(|(key, _)| key.clone())
            {
                entries.remove(&evict_key);
            }
        }

        entries.insert(
            destination.clone(),
            FallbackDestination {
                destination,
                hits: 1,
                first_seen: now.clone(),
                last_seen: now,
            },
        );
    }

    pub fn snapshot(&self) -> Vec<FallbackDestination> {
        let mut entries: Vec<_> = self.entries.lock().values().cloned().collect();
        entries.sort_by(|a, b| {
            b.hits
                .cmp(&a.hits)
                .then_with(|| b.last_seen.cmp(&a.last_seen))
                .then_with(|| a.destination.cmp(&b.destination))
        });
        entries
    }

    pub fn remove(&self, destination: &str) {
        self.entries.lock().remove(destination);
    }

    pub fn clear(&self) {
        self.entries.lock().clear();
    }
}

// ============================================================================
// Helpers
// ============================================================================

pub(crate) fn fmt_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();

    let days = (secs / 86400) as i64;
    let sod = secs % 86400;
    let (h, min, s) = (sod / 3600, sod / 60 % 60, sod % 60);

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, m, d, h, min, s, millis
    )
}
