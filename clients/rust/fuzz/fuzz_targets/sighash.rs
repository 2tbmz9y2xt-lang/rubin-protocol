#![no_main]

use libfuzzer_sys::fuzz_target;
use rubin_consensus::constants::{
    SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE,
};

fn select_sighash_type(raw: u8) -> u8 {
    match raw % 8 {
        0 => SIGHASH_ALL,
        1 => SIGHASH_NONE,
        2 => SIGHASH_SINGLE,
        3 => SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        4 => SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        5 => SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        6 => 0x00,
        _ => raw,
    }
}

// Fuzz sighash_v1_digest_with_type: parse arbitrary bytes into a Tx, then
// compute sighash across valid and invalid sighash_type values.
//
// Verifies:
// - wrapper determinism (same tx/type -> same result)
// - cache determinism (same cache path -> same result)
// - wrapper/cache parity for the same sighash_type
// - default wrapper parity for SIGHASH_ALL
fuzz_target!(|data: &[u8]| {
    // Need at least some bytes for tx + input_index(4) + input_value(8) + chain_id(32) + type(1).
    if data.len() < 45 {
        return;
    }

    // Split: last 45 bytes are sighash params, rest is tx wire bytes.
    let tx_end = data.len() - 45;
    let tx_bytes = &data[..tx_end];
    let params = &data[tx_end..];

    let tx = match rubin_consensus::parse_tx(tx_bytes) {
        Ok((tx, _, _, _)) => tx,
        Err(_) => return,
    };

    if tx.inputs.is_empty() {
        return;
    }

    let input_index = u32::from_le_bytes(params[..4].try_into().unwrap()) % tx.inputs.len() as u32;
    let input_value = u64::from_le_bytes(params[4..12].try_into().unwrap());
    let mut chain_id = [0u8; 32];
    chain_id.copy_from_slice(&params[12..44]);
    let sighash_type = select_sighash_type(params[44]);

    let direct1 =
        rubin_consensus::sighash_v1_digest_with_type(&tx, input_index, input_value, chain_id, sighash_type);
    let direct2 =
        rubin_consensus::sighash_v1_digest_with_type(&tx, input_index, input_value, chain_id, sighash_type);
    let mut cache = match rubin_consensus::SighashV1PrehashCache::new(&tx) {
        Ok(cache) => cache,
        Err(_) => return,
    };
    let cached1 = rubin_consensus::sighash_v1_digest_with_cache(
        &mut cache,
        input_index,
        input_value,
        chain_id,
        sighash_type,
    );
    let cached2 = rubin_consensus::sighash_v1_digest_with_cache(
        &mut cache,
        input_index,
        input_value,
        chain_id,
        sighash_type,
    );

    match (&direct1, &direct2, &cached1, &cached2) {
        (Ok(a), Ok(b), Ok(c1), Ok(c2)) => {
            if a != b {
                panic!("sighash_v1_digest_with_type wrapper non-deterministic");
            }
            if c1 != c2 {
                panic!("sighash_v1_digest_with_cache non-deterministic");
            }
            if a != c1 {
                panic!("wrapper/cache sighash mismatch");
            }
            if sighash_type == SIGHASH_ALL {
                let default_digest =
                    rubin_consensus::sighash_v1_digest(&tx, input_index, input_value, chain_id)
                        .expect("default wrapper");
                if a != &default_digest {
                    panic!("SIGHASH_ALL default wrapper diverged");
                }
            }
        }
        (Err(_), Err(_), Err(_), Err(_)) => {}
        _ => panic!("sighash wrapper/cache error/ok mismatch"),
    }
});
