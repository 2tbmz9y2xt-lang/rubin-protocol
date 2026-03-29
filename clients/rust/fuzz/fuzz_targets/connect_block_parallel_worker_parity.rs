#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

const CTX_LEN: usize = 32 + 32 + 8 + 8 + 2;

fn empty_state(already_generated: u128) -> rubin_consensus::InMemoryChainState {
    rubin_consensus::InMemoryChainState {
        utxos: HashMap::new(),
        already_generated,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < rubin_consensus::BLOCK_HEADER_BYTES + 1 + CTX_LEN || data.len() > (2 << 20) {
        return;
    }

    let block_end = data.len() - CTX_LEN;
    let block_bytes = &data[..block_end];
    let ctx = &data[block_end..];

    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(&ctx[0..32]);
    let mut target = [0u8; 32];
    target.copy_from_slice(&ctx[32..64]);
    let height = u64::from_be_bytes(ctx[64..72].try_into().expect("height bytes"));
    let already_generated = u64::from_be_bytes(ctx[72..80].try_into().expect("ag bytes"));
    let workers_a = usize::from(ctx[80] % 33);
    let workers_b = usize::from(ctx[81] % 33);

    if height > (1 << 20) || already_generated > (1 << 60) {
        return;
    }

    let prev = if prev_hash == [0u8; 32] {
        None
    } else {
        Some(prev_hash)
    };
    let expected_target = if target == [0u8; 32] {
        None
    } else {
        Some(target)
    };

    let mut state_a = empty_state(u128::from(already_generated));
    let result_a = rubin_consensus::connect_block_parallel_sig_verify(
        block_bytes,
        prev,
        expected_target,
        height,
        None,
        &mut state_a,
        [0u8; 32],
        workers_a,
    );

    let mut state_b = empty_state(u128::from(already_generated));
    let result_b = rubin_consensus::connect_block_parallel_sig_verify(
        block_bytes,
        prev,
        expected_target,
        height,
        None,
        &mut state_b,
        [0u8; 32],
        workers_b,
    );

    match (&result_a, &result_b) {
        (Ok(summary_a), Ok(summary_b)) => {
            assert_eq!(summary_a.sum_fees, summary_b.sum_fees, "sum_fees mismatch");
            assert_eq!(
                summary_a.already_generated,
                summary_b.already_generated,
                "already_generated mismatch"
            );
            assert_eq!(
                summary_a.already_generated_n1,
                summary_b.already_generated_n1,
                "already_generated_n1 mismatch"
            );
            assert_eq!(summary_a.utxo_count, summary_b.utxo_count, "utxo_count mismatch");
            assert_eq!(
                summary_a.post_state_digest,
                summary_b.post_state_digest,
                "post_state_digest mismatch"
            );
            assert_eq!(state_a.utxos, state_b.utxos, "utxo set mismatch");
            assert_eq!(
                state_a.already_generated,
                state_b.already_generated,
                "state already_generated mismatch"
            );
        }
        (Err(err_a), Err(err_b)) => {
            assert_eq!(err_a.code, err_b.code, "error-code mismatch");
            assert_eq!(state_a.utxos, state_b.utxos, "error-path utxo mismatch");
            assert_eq!(
                state_a.already_generated,
                state_b.already_generated,
                "error-path already_generated mismatch"
            );
        }
        _ => panic!("parallel worker result class mismatch"),
    }
});
