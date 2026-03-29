#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

const CTX_LEN: usize = 32 + 32 + 8 + 8 + 1;

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
    let workers = usize::from(ctx[80] % 33);

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

    let mut seq_state = empty_state(u128::from(already_generated));
    let seq = rubin_consensus::connect_block_basic_in_memory_at_height(
        block_bytes,
        prev,
        expected_target,
        height,
        None,
        &mut seq_state,
        [0u8; 32],
    );

    let mut par_state = empty_state(u128::from(already_generated));
    let par = rubin_consensus::connect_block_parallel_sig_verify(
        block_bytes,
        prev,
        expected_target,
        height,
        None,
        &mut par_state,
        [0u8; 32],
        workers,
    );

    match (&seq, &par) {
        (Ok(seq_summary), Ok(par_summary)) => {
            assert_eq!(seq_summary.sum_fees, par_summary.sum_fees, "sum_fees mismatch");
            assert_eq!(
                seq_summary.already_generated,
                par_summary.already_generated,
                "already_generated mismatch"
            );
            assert_eq!(
                seq_summary.already_generated_n1,
                par_summary.already_generated_n1,
                "already_generated_n1 mismatch"
            );
            assert_eq!(seq_summary.utxo_count, par_summary.utxo_count, "utxo_count mismatch");
            assert_eq!(
                seq_summary.post_state_digest,
                par_summary.post_state_digest,
                "post_state_digest mismatch"
            );
            assert_eq!(seq_state.utxos, par_state.utxos, "utxo set mismatch");
            assert_eq!(
                seq_state.already_generated,
                par_state.already_generated,
                "state already_generated mismatch"
            );
        }
        (Err(seq_err), Err(par_err)) => {
            assert_eq!(seq_err.code, par_err.code, "error-code mismatch");
            assert_eq!(seq_state.utxos, par_state.utxos, "error-path utxo mismatch");
            assert_eq!(
                seq_state.already_generated,
                par_state.already_generated,
                "error-path already_generated mismatch"
            );
        }
        _ => panic!("sequential/parallel result class mismatch"),
    }
});
