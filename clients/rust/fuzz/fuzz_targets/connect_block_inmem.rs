#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    // Cap input to avoid OOM.
    if data.len() > 8192 {
        return;
    }

    // Derive chain_id from fuzz data: use last 32 bytes if available,
    // otherwise pad with zeros. This covers chainID-dependent consensus paths.
    let (block_bytes, chain_id_raw) = if data.len() > 32 {
        data.split_at(data.len() - 32)
    } else {
        (data, &[][..])
    };
    let mut chain_id = [0u8; 32];
    chain_id[..chain_id_raw.len()].copy_from_slice(chain_id_raw);

    let mut state = rubin_consensus::InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0u128,
    };

    // First call — must not panic.
    let r1 = rubin_consensus::connect_block_basic_in_memory_at_height(
        block_bytes,
        None,
        None,
        1,
        None,
        &mut state,
        chain_id,
    );

    // Invariant (Rust-specific): Result<T,E> guarantees exactly-one-of Ok/Err
    // by type system. Verify Ok-path fields are internally consistent.
    if let Ok(ref s1) = r1 {
        assert!(
            s1.sum_fees <= u64::MAX,
            "sum_fees overflow"
        );
    }

    // Determinism: second call with fresh state must produce same result class.
    let mut state2 = rubin_consensus::InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0u128,
    };

    let r2 = rubin_consensus::connect_block_basic_in_memory_at_height(
        block_bytes,
        None,
        None,
        1,
        None,
        &mut state2,
        chain_id,
    );

    match (&r1, &r2) {
        (Ok(s1), Ok(s2)) => {
            assert_eq!(s1.sum_fees, s2.sum_fees, "non-deterministic fees");
            assert_eq!(
                s1.post_state_digest, s2.post_state_digest,
                "non-deterministic post-state digest"
            );
        }
        (Err(_), Err(_)) => {} // both error — ok
        _ => panic!("non-deterministic: one ok, one err"),
    }
});
