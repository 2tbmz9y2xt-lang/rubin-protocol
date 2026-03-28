#![no_main]

use libfuzzer_sys::fuzz_target;

// Structural fuzz of the spend-dispatch path via `validate_tx_local`.
//
// Constructs a minimal Tx with fuzzed covenant type, covenant data, and
// witness items. Derives witness slot count from covenant_type to ensure
// HTLC (2 slots), VAULT/MULTISIG (threshold-dependent) branches are
// reachable, not just P2PK/EXT/STEALTH (1 slot).
//
// Invariants checked:
// - Determinism: two calls with same input produce identical result.
// - Valid↔Err consistency: valid==true iff err==None.
// - TxIndex and Fee preservation from PrecomputedTxContext.
fuzz_target!(|data: &[u8]| {
    // Layout: covenant_type(2) + suite_id(1) + cov_data_len(1) + cov_data(N)
    //       + pubkey_len(2) + pubkey(M) + sig_len(2) + sig(K)
    //       + block_height(8) + chain_id(32)
    if data.len() < 48 {
        return;
    }

    let mut pos = 0;

    // Map raw fuzz bytes to valid covenant IDs so spend-dispatch branches
    // are reliably reached instead of failing at witness_slots() for ~99.99%
    // of random u16 values.
    let cov_selector = data[pos] % 6;
    let covenant_type: u16 = match cov_selector {
        0 => 0x0000, // COV_TYPE_P2PK
        1 => 0x0100, // COV_TYPE_HTLC
        2 => 0x0101, // COV_TYPE_VAULT
        3 => 0x0104, // COV_TYPE_MULTISIG
        4 => 0x0102, // COV_TYPE_EXT
        5 => 0x0105, // COV_TYPE_STEALTH
        _ => unreachable!(),
    };
    pos += 2; // consume both bytes for layout stability

    let suite_id = data[pos];
    pos += 1;

    // For STEALTH (0x0105), covenant_data must be exactly 1600 bytes.
    // For other types, read length from a single byte (max 255).
    let (cov_data_len, cov_data_fixed) = if covenant_type == 0x0105 {
        // Skip the length byte but use remaining fuzz bytes to fill 1600-byte buffer.
        let _ = data[pos]; // consume the byte for layout consistency
        (0usize, true)
    } else {
        (data[pos] as usize, false)
    };
    pos += 1;

    let covenant_data = if cov_data_fixed {
        // STEALTH: build 1600-byte covenant_data from available fuzz bytes.
        let available = if pos + 44 < data.len() {
            data.len() - pos - 44
        } else {
            0
        };
        let take = available.min(1600);
        let mut cd = vec![0u8; 1600];
        cd[..take].copy_from_slice(&data[pos..pos + take]);
        pos += take;
        cd
    } else {
        if pos + cov_data_len > data.len() - 44 {
            return;
        }
        let cd = data[pos..pos + cov_data_len].to_vec();
        pos += cov_data_len;
        cd
    };

    if pos + 4 > data.len() - 40 {
        return;
    }
    let pubkey_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    // Cap to avoid OOM.
    if pubkey_len > 8192 || pos + pubkey_len > data.len() - 42 {
        return;
    }
    let pubkey = data[pos..pos + pubkey_len].to_vec();
    pos += pubkey_len;

    let sig_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if sig_len > 131072 || pos + sig_len > data.len() - 40 {
        return;
    }
    let signature = data[pos..pos + sig_len].to_vec();
    pos += sig_len;

    if pos + 40 > data.len() {
        return;
    }
    let block_height = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let mut chain_id = [0u8; 32];
    chain_id.copy_from_slice(&data[pos..pos + 32]);

    // Compute witness slot count from covenant_type to match consensus logic
    // (vault.rs witness_slots). This ensures multi-slot covenants like HTLC
    // (2 slots), VAULT/MULTISIG (threshold-dependent) are reachable.
    let witness_slot_count: usize = match covenant_type {
        0x0000 => 1, // COV_TYPE_P2PK
        0x0102 => 1, // COV_TYPE_EXT
        0x0105 => 1, // COV_TYPE_STEALTH
        0x0100 => 2, // COV_TYPE_HTLC
        0x0104 => {   // COV_TYPE_MULTISIG: threshold from covenant_data[1]
            covenant_data.get(1).copied().unwrap_or(1).max(1) as usize
        }
        0x0101 => {   // COV_TYPE_VAULT: threshold from covenant_data[33]
            covenant_data.get(33).copied().unwrap_or(1).max(1) as usize
        }
        _ => 1, // Unknown: will fail at witness_slots, but 1 slot is fine
    };

    // Cap to prevent combinatorial explosion.
    if witness_slot_count > 12 {
        return;
    }

    // Build witness items: replicate the fuzzed item for each required slot.
    let witness_items: Vec<rubin_consensus::WitnessItem> = (0..witness_slot_count)
        .map(|_| rubin_consensus::WitnessItem {
            suite_id,
            pubkey: pubkey.clone(),
            signature: signature.clone(),
        })
        .collect();
    let witness_end = witness_items.len();

    let tx = rubin_consensus::Tx {
        version: 1,
        tx_kind: 0,
        tx_nonce: 0,
        inputs: vec![rubin_consensus::TxInput {
            prev_txid: [0x42u8; 32],
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0xFFFF_FFFF,
        }],
        outputs: vec![rubin_consensus::TxOutput {
            value: 1,
            covenant_type: 0x0000,
            covenant_data: vec![0x01; 33],
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: witness_items,
        da_payload: vec![],
    };

    let entry = rubin_consensus::UtxoEntry {
        value: 2,
        covenant_type,
        covenant_data,
        creation_height: 0,
        created_by_coinbase: false,
    };

    let ptc = rubin_consensus::PrecomputedTxContext {
        tx_index: 1,
        tx_block_idx: 0,
        txid: [0u8; 32],
        resolved_inputs: vec![entry],
        witness_start: 0,
        witness_end,
        input_outpoints: vec![rubin_consensus::Outpoint {
            txid: [0x42u8; 32],
            vout: 0,
        }],
        fee: 1,
    };

    let pb = rubin_consensus::ParsedBlock {
        header: rubin_consensus::BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 0,
            target: [0u8; 32],
            nonce: 0,
        },
        header_bytes: [0u8; rubin_consensus::BLOCK_HEADER_BYTES],
        tx_count: 1,
        txs: vec![tx],
        txids: vec![[0u8; 32]],
        wtxids: vec![[0u8; 32]],
    };

    let profiles = rubin_consensus::CoreExtProfiles { active: vec![] };

    // --- First call ---
    let r1 = rubin_consensus::validate_tx_local(
        &ptc, &pb, chain_id, block_height, 0, &profiles, None,
    );

    // --- Invariant: Valid ↔ Err consistency ---
    if r1.valid && r1.err.is_some() {
        panic!("valid==true but err is Some");
    }
    if !r1.valid && r1.err.is_none() {
        panic!("valid==false but err is None");
    }

    // --- Invariant: TxIndex and Fee preserved from PTC ---
    if r1.tx_index != 1 {
        panic!("tx_index not preserved: got {}", r1.tx_index);
    }
    if r1.fee != 1 {
        panic!("fee not preserved: got {}", r1.fee);
    }

    // --- Invariant: Determinism ---
    let r2 = rubin_consensus::validate_tx_local(
        &ptc, &pb, chain_id, block_height, 0, &profiles, None,
    );
    if r1 != r2 {
        panic!("validate_tx_local non-deterministic");
    }
});
