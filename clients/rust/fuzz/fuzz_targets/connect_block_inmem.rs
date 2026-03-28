#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    // Cap input to avoid OOM.
    if data.len() > 8192 {
        return;
    }

    let mut state = rubin_consensus::InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0u128,
    };

    let chain_id = [0u8; 32];

    // First call — must not panic.
    let r1 = rubin_consensus::connect_block_basic_in_memory_at_height(
        data,
        None,
        None,
        1,
        None,
        &mut state,
        chain_id,
    );

    // Determinism: second call with fresh state must produce same result class.
    let mut state2 = rubin_consensus::InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0u128,
    };

    let r2 = rubin_consensus::connect_block_basic_in_memory_at_height(
        data,
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
