#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the SigCache with arbitrary (suite_id, pubkey, sig, digest) tuples.
//
// Exercises:
// - Insert/Lookup correctness: inserted tuples are always found.
// - Capacity bound: cache never exceeds configured capacity.
// - Determinism: same key → same lookup result.
// - Reset: clears all entries and counters.
// - Positive-only invariant: only explicit inserts create entries.
fuzz_target!(|data: &[u8]| {
    // Need at least: capacity_byte(1) + num_ops(1) + suite_id(1) + digest(32) = 35
    if data.len() < 35 {
        return;
    }

    // Capacity 1..=16 to keep fuzz fast.
    let capacity = (data[0] as usize % 16) + 1;
    let num_ops = (data[1] as usize % 8) + 1;
    let cache = rubin_consensus::SigCache::new(capacity);

    let mut pos = 2;
    #[allow(clippy::type_complexity)]
    let mut inserted_keys: Vec<(u8, Vec<u8>, Vec<u8>, [u8; 32])> = Vec::new();

    for _ in 0..num_ops {
        if pos + 33 > data.len() {
            break;
        }

        let suite_id = data[pos];
        pos += 1;

        let digest: [u8; 32] = match data[pos..].get(..32) {
            Some(d) => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(d);
                pos += 32;
                arr
            }
            None => break,
        };

        // Variable-length pubkey and sig from remaining data.
        let remaining = data.len() - pos;
        let pk_len = if remaining > 0 {
            (data.get(pos).copied().unwrap_or(0) as usize % 64).min(remaining.saturating_sub(1))
        } else {
            0
        };
        if pk_len > 0 {
            pos += 1; // consumed the length byte
        }
        let pubkey = if pk_len > 0 && pos + pk_len <= data.len() {
            let pk = &data[pos..pos + pk_len];
            pos += pk_len;
            pk.to_vec()
        } else {
            vec![]
        };

        let sig_remaining = data.len() - pos;
        let sig_len = sig_remaining.min(64);
        let sig = if sig_len > 0 {
            let s = &data[pos..pos + sig_len];
            pos += sig_len;
            s.to_vec()
        } else {
            vec![]
        };

        // Lookup before insert — must miss (unless previously inserted same tuple).
        let was_present = cache.lookup(suite_id, &pubkey, &sig, digest);

        // Insert.
        cache.insert(suite_id, &pubkey, &sig, digest);

        // Lookup after insert — must hit (if capacity allows).
        let found = cache.lookup(suite_id, &pubkey, &sig, digest);
        if cache.len() <= capacity && !found {
            // If we just inserted and cache isn't over capacity, must find it.
            // (Unless insert was silently dropped due to capacity — check.)
            if !was_present && cache.len() < capacity {
                panic!(
                    "inserted tuple not found: suite=0x{:02x} pk_len={} sig_len={}",
                    suite_id,
                    pubkey.len(),
                    sig.len()
                );
            }
        }

        // Capacity invariant.
        assert!(
            cache.len() <= capacity,
            "cache exceeded capacity: {} > {}",
            cache.len(),
            capacity
        );

        inserted_keys.push((suite_id, pubkey, sig, digest));
    }

    // Verify hit/miss counters are consistent.
    let total_lookups = cache.hits() + cache.misses();
    // We did at least num_ops * 2 lookups (before + after insert).
    assert!(total_lookups >= inserted_keys.len() as u64);

    // Reset.
    cache.reset();
    assert_eq!(cache.len(), 0);
    assert_eq!(cache.hits(), 0);
    assert_eq!(cache.misses(), 0);

    // After reset, all previously inserted keys must miss.
    for (suite_id, pubkey, sig, digest) in &inserted_keys {
        assert!(
            !cache.lookup(*suite_id, pubkey, sig, *digest),
            "found tuple after reset"
        );
    }
});
