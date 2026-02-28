#![no_main]

use libfuzzer_sys::fuzz_target;

// Replaces Kani verify_merkle_root_deterministic_single
// (SHA3-256 Keccak permutation is SAT-intractable for CBMC).
fuzz_target!(|data: &[u8]| {
    // Interpret raw bytes as consecutive 32-byte txids.
    let n_txids = data.len() / 32;
    if n_txids == 0 {
        let empty: &[[u8; 32]] = &[];
        let _ = rubin_consensus::merkle_root_txids(empty);
        return;
    }

    let mut txids = Vec::with_capacity(n_txids);
    for i in 0..n_txids {
        let mut id = [0u8; 32];
        id.copy_from_slice(&data[i * 32..(i + 1) * 32]);
        txids.push(id);
    }

    let r1 = rubin_consensus::merkle_root_txids(&txids);
    let r2 = rubin_consensus::merkle_root_txids(&txids);

    match (r1, r2) {
        (Ok(a), Ok(b)) => {
            if a != b {
                panic!("merkle_root_txids non-deterministic: {a:02x?} != {b:02x?}");
            }
        }
        (Err(_), Err(_)) => {}
        _ => panic!("merkle_root_txids non-deterministic error/ok mismatch"),
    }
});
