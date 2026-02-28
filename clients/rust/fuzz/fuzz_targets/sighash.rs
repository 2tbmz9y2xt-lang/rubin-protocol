#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz sighash_v1_digest: parse arbitrary bytes into a Tx, then compute
// sighash for each input.  Verifies determinism (same tx → same digest)
// and no-panic for any parseable transaction.
fuzz_target!(|data: &[u8]| {
    // Need at least some bytes for tx + input_index(4) + input_value(8) + chain_id(32).
    if data.len() < 44 {
        return;
    }

    // Split: last 44 bytes are sighash params, rest is tx wire bytes.
    let tx_end = data.len() - 44;
    let tx_bytes = &data[..tx_end];
    let params = &data[tx_end..];

    let tx = match rubin_consensus::parse_tx(tx_bytes) {
        Ok(t) => t,
        Err(_) => return,
    };

    if tx.inputs.is_empty() {
        return;
    }

    let input_index = u32::from_le_bytes(params[..4].try_into().unwrap()) % tx.inputs.len() as u32;
    let input_value = u64::from_le_bytes(params[4..12].try_into().unwrap());
    let mut chain_id = [0u8; 32];
    chain_id.copy_from_slice(&params[12..44]);

    let r1 = rubin_consensus::sighash_v1_digest(&tx, input_index, input_value, chain_id);
    let r2 = rubin_consensus::sighash_v1_digest(&tx, input_index, input_value, chain_id);

    match (&r1, &r2) {
        (Ok(a), Ok(b)) => {
            if a != b {
                panic!("sighash_v1_digest non-deterministic");
            }
        }
        (Err(_), Err(_)) => {}
        _ => panic!("sighash_v1_digest non-deterministic error/ok mismatch"),
    }
});
