use crate::hash::sha3_256;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
struct SigCacheInner {
    entries: RwLock<HashSet<[u8; 32]>>,
    capacity: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct SigCache {
    inner: Arc<SigCacheInner>,
}

impl SigCache {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Arc::new(SigCacheInner {
                entries: RwLock::new(HashSet::with_capacity(capacity)),
                capacity,
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
            }),
        }
    }

    pub fn lookup(&self, suite_id: u8, pubkey: &[u8], sig: &[u8], digest: [u8; 32]) -> bool {
        let key = sig_cache_key(suite_id, pubkey, sig, digest);
        let ok = self
            .inner
            .entries
            .read()
            .expect("sig cache poisoned")
            .contains(&key);
        if ok {
            self.inner.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.misses.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    pub fn insert(&self, suite_id: u8, pubkey: &[u8], sig: &[u8], digest: [u8; 32]) {
        let key = sig_cache_key(suite_id, pubkey, sig, digest);
        let mut entries = self.inner.entries.write().expect("sig cache poisoned");
        if entries.len() < self.inner.capacity {
            entries.insert(key);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.entries.read().expect("sig cache poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn hits(&self) -> u64 {
        self.inner.hits.load(Ordering::Relaxed)
    }

    pub fn misses(&self) -> u64 {
        self.inner.misses.load(Ordering::Relaxed)
    }

    pub fn reset(&self) {
        let mut entries = self.inner.entries.write().expect("sig cache poisoned");
        *entries = HashSet::with_capacity(self.inner.capacity);
        self.inner.hits.store(0, Ordering::Relaxed);
        self.inner.misses.store(0, Ordering::Relaxed);
    }
}

pub(crate) fn sig_cache_key(suite_id: u8, pubkey: &[u8], sig: &[u8], digest: [u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 4 + pubkey.len() + 4 + sig.len() + 32);
    buf.push(suite_id);
    buf.extend_from_slice(
        &u32::try_from(pubkey.len())
            .expect("pubkey length must fit into u32")
            .to_le_bytes(),
    );
    buf.extend_from_slice(pubkey);
    buf.extend_from_slice(
        &u32::try_from(sig.len())
            .expect("signature length must fit into u32")
            .to_le_bytes(),
    );
    buf.extend_from_slice(sig);
    buf.extend_from_slice(&digest);
    sha3_256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::SUITE_ID_ML_DSA_87;
    use crate::verify_sig_openssl::Mldsa87Keypair;

    #[test]
    fn basic_insert_lookup() {
        let cache = SigCache::new(100);
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let mut digest = [0u8; 32];
        digest[0] = 0x42;
        let sig = keypair.sign_digest32(digest).expect("sign");
        let pubkey = keypair.pubkey_bytes();

        assert!(!cache.lookup(SUITE_ID_ML_DSA_87, &pubkey, &sig, digest));
        assert_eq!(cache.hits(), 0);
        assert_eq!(cache.misses(), 1);

        cache.insert(SUITE_ID_ML_DSA_87, &pubkey, &sig, digest);
        assert!(cache.lookup(SUITE_ID_ML_DSA_87, &pubkey, &sig, digest));
        assert_eq!(cache.hits(), 1);
        assert_eq!(cache.misses(), 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn bounded_capacity() {
        let cache = SigCache::new(2);
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let pubkey = keypair.pubkey_bytes();
        let mut entries = Vec::new();
        for i in 0..3 {
            let mut digest = [0u8; 32];
            digest[0] = i;
            let sig = keypair.sign_digest32(digest).expect("sign");
            cache.insert(SUITE_ID_ML_DSA_87, &pubkey, &sig, digest);
            entries.push((sig, digest));
        }

        assert_eq!(cache.len(), 2);
        assert!(cache.lookup(SUITE_ID_ML_DSA_87, &pubkey, &entries[0].0, entries[0].1));
        assert!(cache.lookup(SUITE_ID_ML_DSA_87, &pubkey, &entries[1].0, entries[1].1));
        assert!(!cache.lookup(SUITE_ID_ML_DSA_87, &pubkey, &entries[2].0, entries[2].1));
    }

    #[test]
    fn reset_clears_entries_and_counters() {
        let cache = SigCache::new(10);
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let digest = [0u8; 32];
        let sig = keypair.sign_digest32(digest).expect("sign");
        let pubkey = keypair.pubkey_bytes();

        cache.insert(SUITE_ID_ML_DSA_87, &pubkey, &sig, digest);
        assert!(cache.lookup(SUITE_ID_ML_DSA_87, &pubkey, &sig, digest));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.hits(), 1);

        cache.reset();
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.hits(), 0);
        assert_eq!(cache.misses(), 0);
        assert!(!cache.lookup(SUITE_ID_ML_DSA_87, &pubkey, &sig, digest));
    }

    #[test]
    fn canonical_key_determinism() {
        let pubkey = [1u8, 2, 3];
        let sig = [4u8, 5, 6];
        let mut digest = [0u8; 32];
        digest[0] = 0xff;

        let first = sig_cache_key(0x01, &pubkey, &sig, digest);
        let second = sig_cache_key(0x01, &pubkey, &sig, digest);
        let different_suite = sig_cache_key(0x02, &pubkey, &sig, digest);

        assert_eq!(first, second);
        assert_ne!(first, different_suite);
    }

    #[test]
    fn zero_capacity_clamps_to_one() {
        let cache = SigCache::new(0);
        assert_eq!(cache.inner.capacity, 1);
    }

    #[test]
    fn different_pubkey_same_sig_yields_different_keys() {
        let sig = [0xABu8; 100];
        let digest = [0u8; 32];
        let k1 = sig_cache_key(0x01, &[1, 2, 3], &sig, digest);
        let k2 = sig_cache_key(0x01, &[4, 5, 6], &sig, digest);
        assert_ne!(k1, k2);
    }

    #[test]
    fn empty_pubkey_and_sig_accepted() {
        let cache = SigCache::new(10);
        let digest = [0x42u8; 32];
        // Insert with empty pubkey and sig — must not panic.
        cache.insert(0x01, &[], &[], digest);
        assert!(cache.lookup(0x01, &[], &[], digest));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn capacity_exactly_reached_then_dropped() {
        let cache = SigCache::new(2);
        let digest = [0u8; 32];
        // Fill to capacity.
        cache.insert(0x01, &[1], &[1], digest);
        cache.insert(0x01, &[2], &[2], digest);
        assert_eq!(cache.len(), 2);
        // Third entry is silently dropped.
        cache.insert(0x01, &[3], &[3], digest);
        assert_eq!(cache.len(), 2);
        // First two still present.
        assert!(cache.lookup(0x01, &[1], &[1], digest));
        assert!(cache.lookup(0x01, &[2], &[2], digest));
        // Third was dropped.
        assert!(!cache.lookup(0x01, &[3], &[3], digest));
    }

    #[test]
    fn concurrent_insert_lookup_no_panic() {
        use std::thread;
        let cache = SigCache::new(64);
        let mut handles = vec![];
        for i in 0..8u8 {
            let c = cache.clone();
            handles.push(thread::spawn(move || {
                let mut digest = [0u8; 32];
                digest[0] = i;
                for j in 0..10u8 {
                    c.insert(i, &[j], &[j], digest);
                    c.lookup(i, &[j], &[j], digest);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert!(cache.len() <= 64);
    }

    #[test]
    fn is_empty_reflects_state() {
        let cache = SigCache::new(10);
        assert!(cache.is_empty());
        cache.insert(0x01, &[1], &[1], [0u8; 32]);
        assert!(!cache.is_empty());
        cache.reset();
        assert!(cache.is_empty());
    }

    #[test]
    fn length_prefix_prevents_ambiguity() {
        // Ensure that (pubkey=[1,2], sig=[3]) differs from (pubkey=[1], sig=[2,3])
        // even though concatenated bytes are the same.
        let digest = [0u8; 32];
        let k1 = sig_cache_key(0x01, &[1, 2], &[3], digest);
        let k2 = sig_cache_key(0x01, &[1], &[2, 3], digest);
        assert_ne!(k1, k2, "length prefix must disambiguate pubkey/sig splits");
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    /// Proves that sig_cache_key is deterministic: same inputs always produce
    /// the same output.
    #[kani::proof]
    fn sig_cache_key_deterministic() {
        let suite_id: u8 = kani::any();
        let pubkey = [kani::any::<u8>(); 4];
        let sig = [kani::any::<u8>(); 4];
        let digest: [u8; 32] = kani::any();

        let k1 = sig_cache_key(suite_id, &pubkey, &sig, digest);
        let k2 = sig_cache_key(suite_id, &pubkey, &sig, digest);
        assert_eq!(k1, k2);
    }

    // NOTE: sig_cache_key_suite_sensitivity removed — asserts collision-freedom
    // on SHA3-256 which is SAT-intractable for Kani (see kani.yml header).
    // Collision resistance is tested empirically in unit tests instead.

    /// Proves that capacity clamping always produces capacity >= 1.
    #[kani::proof]
    fn new_cache_capacity_always_at_least_one() {
        let cap: usize = kani::any();
        // Restrict to avoid OOM in proof.
        kani::assume(cap <= 16);
        let cache = SigCache::new(cap);
        assert!(cache.inner.capacity >= 1);
    }
}
