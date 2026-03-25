use std::collections::HashMap;
use std::sync::Mutex;

/// Default capacity for the tx-seen dedup filter (matches Go `defaultTxSeenCapacity`).
pub const DEFAULT_TX_SEEN_CAPACITY: usize = 50_000;

/// Default capacity for the block-seen dedup filter (matches Go `defaultBlockSeenCapacity`).
pub const DEFAULT_BLOCK_SEEN_CAPACITY: usize = 10_000;

/// Thread-safe bounded FIFO set of `[u8; 32]` hashes.
///
/// Prevents unbounded memory growth by evicting the oldest entry when at capacity.
/// Used for relay dedup: once a txid is in the set, INV/GETDATA churn is suppressed.
///
/// Matches Go `boundedHashSet` in `seen.go`:
/// - `add` → `Add`: returns true if newly inserted
/// - `has` → `Has`: O(1) membership test
/// - FIFO eviction via ring buffer + HashMap
pub struct BoundedHashSet {
    inner: Mutex<BoundedHashSetInner>,
}

struct BoundedHashSetInner {
    cap: usize,
    ring: Vec<[u8; 32]>,
    next: usize,
    items: HashMap<[u8; 32], ()>,
}

impl BoundedHashSet {
    pub fn new(capacity: usize) -> Self {
        let cap = if capacity == 0 {
            DEFAULT_TX_SEEN_CAPACITY
        } else {
            capacity
        };
        Self {
            inner: Mutex::new(BoundedHashSetInner {
                cap,
                ring: vec![[0u8; 32]; cap],
                next: 0,
                items: HashMap::with_capacity(cap),
            }),
        }
    }

    /// Insert hash into the set. Returns `true` if the hash was newly added,
    /// `false` if it was already present. Evicts the oldest entry (FIFO) when
    /// the set is at capacity.
    pub fn add(&self, hash: [u8; 32]) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        if inner.items.contains_key(&hash) {
            return false;
        }
        // Evict the oldest entry when full (matches Go's scan-forward eviction).
        if inner.items.len() >= inner.cap {
            for i in 0..inner.cap {
                let idx = (inner.next + i) % inner.cap;
                let old_hash = inner.ring[idx];
                if inner.items.remove(&old_hash).is_some() {
                    inner.next = idx;
                    break;
                }
            }
        }
        let next = inner.next;
        inner.ring[next] = hash;
        inner.items.insert(hash, ());
        inner.next = (next + 1) % inner.cap;
        true
    }

    /// Returns `true` if hash is in the set.
    pub fn has(&self, hash: &[u8; 32]) -> bool {
        let Ok(inner) = self.inner.lock() else {
            return false;
        };
        inner.items.contains_key(hash)
    }

    /// Returns the current number of entries in the set.
    pub fn len(&self) -> usize {
        let Ok(inner) = self.inner.lock() else {
            return 0;
        };
        inner.items.len()
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_returns_true_for_new_false_for_duplicate() {
        let set = BoundedHashSet::new(100);
        let hash = [1u8; 32];
        assert!(set.add(hash));
        assert!(!set.add(hash));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn has_returns_correct_membership() {
        let set = BoundedHashSet::new(100);
        let hash = [2u8; 32];
        assert!(!set.has(&hash));
        set.add(hash);
        assert!(set.has(&hash));
    }

    #[test]
    fn eviction_at_capacity_removes_oldest() {
        let set = BoundedHashSet::new(3);
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let h3 = [3u8; 32];
        let h4 = [4u8; 32];

        assert!(set.add(h1));
        assert!(set.add(h2));
        assert!(set.add(h3));
        assert_eq!(set.len(), 3);

        // Adding h4 should evict h1 (oldest).
        assert!(set.add(h4));
        assert_eq!(set.len(), 3);
        assert!(!set.has(&h1));
        assert!(set.has(&h2));
        assert!(set.has(&h3));
        assert!(set.has(&h4));
    }

    #[test]
    fn eviction_wraps_ring_buffer() {
        let set = BoundedHashSet::new(2);
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let h3 = [3u8; 32];
        let h4 = [4u8; 32];

        set.add(h1);
        set.add(h2);
        // Ring: [h1, h2], next=0.  Adding h3 evicts h1.
        set.add(h3);
        assert!(!set.has(&h1));
        assert!(set.has(&h2));
        assert!(set.has(&h3));

        // Ring: [h3, h2], next=1.  Adding h4 evicts h2.
        set.add(h4);
        assert!(!set.has(&h2));
        assert!(set.has(&h3));
        assert!(set.has(&h4));
    }

    #[test]
    fn default_capacity_when_zero() {
        let set = BoundedHashSet::new(0);
        // Should use DEFAULT_TX_SEEN_CAPACITY.
        // Just verify it doesn't panic and works.
        let hash = [42u8; 32];
        assert!(set.add(hash));
        assert!(set.has(&hash));
    }

    #[test]
    fn is_empty_works() {
        let set = BoundedHashSet::new(10);
        assert!(set.is_empty());
        set.add([1u8; 32]);
        assert!(!set.is_empty());
    }

    #[test]
    fn concurrent_add_has() {
        use std::sync::Arc;
        use std::thread;

        let set = Arc::new(BoundedHashSet::new(1000));
        let mut handles = Vec::new();
        for t in 0..4u8 {
            let set = Arc::clone(&set);
            handles.push(thread::spawn(move || {
                for i in 0..250u8 {
                    let mut hash = [0u8; 32];
                    hash[0] = t;
                    hash[1] = i;
                    set.add(hash);
                    set.has(&hash);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(set.len(), 1000);
    }
}
