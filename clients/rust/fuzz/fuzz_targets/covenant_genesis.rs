#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz validate_tx_covenants_genesis: covenant type validation per output.
// Uses parse_tx as structure-aware input generation, then validates all
// covenant types (P2PK, ANCHOR, VAULT, MULTISIG, HTLC, DA_COMMIT).
fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Last 8 bytes = block_height, rest = tx wire bytes.
    let tx_end = data.len() - 8;
    let tx_bytes = &data[..tx_end];
    let height = u64::from_le_bytes(data[tx_end..].try_into().unwrap());

    let tx = match rubin_consensus::parse_tx(tx_bytes) {
        Ok(t) => t,
        Err(_) => return,
    };

    let _ = rubin_consensus::validate_tx_covenants_genesis(&tx, height);
});
