//! Response cache for the DNS client: TTL-bounded LRU with optional
//! optimistic serving (return stale + background refresh).
//!
//! LRU, not first-in-first-out: eviction used to scan the whole map for the
//! smallest `inserted` (4096 iterations plus a key clone on every insert at
//! capacity) and, worse, a hot entry that was only *read* aged towards the
//! exit while unknown names churned past it. A hit now bumps the entry, and
//! eviction is the LRU crate's own O(1) pop.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;

/// The transaction ID is replaced for each caller. Every other query byte
/// can affect the upstream response, including EDNS options and question case.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    tag: Arc<str>,
    query: [u8; 32],
    rewrite_ttl: Option<u32>,
}

impl CacheKey {
    pub fn new(tag: &str, query_without_id: &[u8], rewrite_ttl: Option<u32>) -> Self {
        use sha2::{Digest, Sha256};
        Self {
            tag: tag.into(),
            query: Sha256::digest(query_without_id).into(),
            rewrite_ttl,
        }
    }
}

pub struct CacheEntry {
    pub raw: Arc<[u8]>,
    pub inserted: Instant,
    /// Seconds the entry stays fresh (derived from the smallest TTL).
    pub ttl: Duration,
    /// Optimistic window bound (only when optimistic serving is enabled).
    pub optimistic_until: Option<Instant>,
}

pub enum CacheHit {
    /// The answer and the whole seconds of TTL it has left.
    Fresh(Arc<[u8]>, u32),
    /// Stale-but-servable: caller must trigger a background refresh.
    Stale(Arc<[u8]>),
}

pub struct Cache {
    entries: LruCache<CacheKey, CacheEntry>,
}

/// Keep the eviction limit without reserving all hash buckets at startup.
pub(super) fn growing_lru<K: std::hash::Hash + Eq, V>(capacity: NonZeroUsize) -> LruCache<K, V> {
    let mut entries = LruCache::unbounded();
    entries.resize(capacity);
    entries
}

impl Cache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: growing_lru(NonZeroUsize::new(capacity.max(16)).expect("max(16)")),
        }
    }

    /// The read that keeps a hot name alive: it bumps the entry to the front
    /// of the eviction order, so unknown names churning through the cache
    /// cannot push out a name that is being asked for.
    pub fn get(&mut self, key: &CacheKey, now: Instant) -> Option<CacheHit> {
        let entry = self.entries.get(key)?;
        let age = now.duration_since(entry.inserted);
        if age < entry.ttl {
            let remaining = (entry.ttl - age).as_secs().min(u32::MAX as u64) as u32;
            return Some(CacheHit::Fresh(Arc::clone(&entry.raw), remaining));
        }
        if entry.optimistic_until.is_some_and(|until| now < until) {
            return Some(CacheHit::Stale(Arc::clone(&entry.raw)));
        }
        None
    }

    pub fn insert(
        &mut self,
        key: CacheKey,
        raw: impl Into<Arc<[u8]>>,
        ttl_secs: u32,
        optimistic_timeout: Option<Duration>,
    ) {
        let inserted = Instant::now();
        let optimistic_until = optimistic_timeout.map(|window| inserted + window);
        self.entries.put(
            key,
            CacheEntry {
                raw: raw.into(),
                inserted,
                ttl: Duration::from_secs(ttl_secs as u64),
                optimistic_until,
            },
        );
    }

    /// Copy non-expired (or optimistically servable) entries into `target`.
    pub fn copy_valid_into(&self, target: &mut Cache, now: Instant) {
        for (k, v) in self.entries.iter() {
            let is_fresh = now.duration_since(v.inserted) < v.ttl;
            let is_optimistic = v.optimistic_until.is_some_and(|until| now < until);
            if is_fresh || is_optimistic {
                target.entries.put(
                    k.clone(),
                    CacheEntry {
                        raw: Arc::clone(&v.raw),
                        inserted: v.inserted,
                        ttl: v.ttl,
                        optimistic_until: v.optimistic_until,
                    },
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> CacheKey {
        CacheKey::new("t", b"a.test", None)
    }

    #[test]
    fn fresh_then_miss() {
        let mut cache = Cache::new(16);
        let before = Instant::now();
        assert!(cache.get(&key(), before).is_none());
        cache.insert(key(), b"resp".to_vec(), 60, None);
        // `insert` reads the clock itself, so the instant this test measures
        // from has to be taken after it: sampling before leaves the entry's own
        // timestamp a hair later, and the 61-second probe then lands just under
        // the 61 seconds it meant to be, which is a test that fails at random.
        let now = Instant::now();
        assert!(matches!(cache.get(&key(), now), Some(CacheHit::Fresh(..))));
        assert!(cache.get(&key(), now + Duration::from_secs(61)).is_none());
    }

    #[test]
    fn optimistic_window() {
        let mut cache = Cache::new(16);
        cache.insert(key(), b"resp".to_vec(), 1, Some(Duration::from_secs(300)));
        let now = Instant::now();
        assert!(matches!(cache.get(&key(), now), Some(CacheHit::Fresh(..))));
        assert!(matches!(
            cache.get(&key(), now + Duration::from_secs(2)),
            Some(CacheHit::Stale(_))
        ));
        assert!(cache.get(&key(), now + Duration::from_secs(400)).is_none());
    }

    #[test]
    fn evicts_oldest_over_capacity() {
        let mut cache = Cache::new(16);
        for i in 0..17 {
            let k = CacheKey::new("t", format!("h{i}.test").as_bytes(), None);
            std::thread::sleep(Duration::from_millis(2));
            cache.insert(k, vec![i as u8], 60, None);
        }
        assert_eq!(cache.entries.len(), 16);
        let oldest = CacheKey::new("t", b"h0.test", None);
        assert!(cache.get(&oldest, Instant::now()).is_none());
    }

    /// The behaviour the scan did not have: reading an entry keeps it, and
    /// the eviction takes the least recently *used* one, not the least
    /// recently inserted.
    #[test]
    fn a_read_keeps_an_entry_alive_across_eviction() {
        let mut cache = Cache::new(16);
        for i in 0..16 {
            let k = CacheKey::new("t", format!("h{i}.test").as_bytes(), None);
            cache.insert(k, vec![i as u8], 60, None);
        }
        let probe = |name: &str| CacheKey::new("t", name.as_bytes(), None);
        // touch the oldest insert
        assert!(matches!(
            cache.get(&probe("h0.test"), Instant::now()),
            Some(CacheHit::Fresh(..))
        ));
        let newest = probe("h16.test");
        cache.insert(newest, vec![16], 60, None);
        assert!(
            cache.get(&probe("h0.test"), Instant::now()).is_some(),
            "the touched entry survives"
        );
        assert!(
            cache.get(&probe("h1.test"), Instant::now()).is_none(),
            "the untouched one took the eviction"
        );
    }
}
