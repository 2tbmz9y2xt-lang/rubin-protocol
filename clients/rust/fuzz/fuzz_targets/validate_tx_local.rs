#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz `validate_tx_local`: the per-transaction worker dispatcher.
//
// Parses arbitrary bytes into a Tx, builds a synthetic `PrecomputedTxContext`
// and minimal `ParsedBlock`, then calls `validate_tx_local` which dispatches
// to per-covenant-type spend validators (P2PK, HTLC, VAULT, MULTISIG,
// CORE_EXT, STEALTH).
//
// Goal: exercise the dispatch switch across all covenant types, witness slot
// accounting, sighash cache, sig queue flush, and error paths — without panic.
//
// Invariants checked:
// - Determinism: two calls with same input produce identical result.
// - Valid↔Err consistency: valid==true iff err==None.
// - TxIndex and Fee preservation from PrecomputedTxContext.
fuzz_target!(|data: &[u8]| {
    // Minimum: tx bytes + chain_id(32) + block_height(8) + block_mtp(8) + cov_selector(1) = 49 tail bytes
    if data.len() < 50 {
        return;
    }

    let tail_len = 49;
    let tx_end = data.len() - tail_len;
    let tx_bytes = &data[..tx_end];
    let params = &data[tx_end..];

    let (tx, _, _, _) = match rubin_consensus::parse_tx(tx_bytes) {
        Ok(v) => v,
        Err(_) => return,
    };

    if tx.inputs.is_empty() {
        return;
    }

    let mut chain_id = [0u8; 32];
    chain_id.copy_from_slice(&params[..32]);
    let block_height = u64::from_le_bytes(params[32..40].try_into().unwrap());
    let block_mtp = u64::from_le_bytes(params[40..48].try_into().unwrap());

    // Select covenant type from fuzz data to exercise all dispatch branches,
    // not just P2PK. This ensures HTLC/VAULT/MULTISIG/EXT/STEALTH paths
    // are reachable.
    let cov_selector = params[48] % 6;
    let covenant_type: u16 = match cov_selector {
        0 => 0x0000, // COV_TYPE_P2PK
        1 => 0x0100, // COV_TYPE_HTLC
        2 => 0x0101, // COV_TYPE_VAULT
        3 => 0x0104, // COV_TYPE_MULTISIG
        4 => 0x0102, // COV_TYPE_EXT
        5 => 0x0105, // COV_TYPE_STEALTH
        _ => unreachable!(),
    };

    // Build covenant_data matching the selected covenant type.
    // Each type requires specific layout for witness_slots() to succeed.
    let build_covenant_data = |suite_id: u8, pk: &[u8]| -> Vec<u8> {
        match covenant_type {
            0x0000 | 0x0102 => {
                // P2PK / EXT: suite_id(1) + key_id(32)
                let mut cd = vec![suite_id];
                let mut key_id = [0u8; 32];
                for (j, b) in pk.iter().take(32).enumerate() {
                    key_id[j] = *b;
                }
                cd.extend_from_slice(&key_id);
                cd
            }
            0x0105 => {
                // STEALTH: ciphertext(1568) + one_time_key_id(32) = 1600 bytes
                // (MAX_STEALTH_COVENANT_DATA). Fill from fuzz data for variety.
                let mut cd = vec![0u8; 1600];
                for (j, b) in pk.iter().enumerate() {
                    if j >= 1600 {
                        break;
                    }
                    cd[j] = *b;
                }
                cd
            }
            0x0100 => {
                // HTLC: hash[32] + lock_mode[1] + lock_value[8] + claim_key_id[32] + refund_key_id[32] = 105 bytes
                // (MAX_HTLC_COVENANT_DATA). Matches parse_htlc_covenant_data layout.
                let mut cd = Vec::with_capacity(105);
                // hash (32 bytes) — fill from fuzz pk data
                let mut hash = [0u8; 32];
                for (j, b) in pk.iter().take(32).enumerate() {
                    hash[j] = *b;
                }
                cd.extend_from_slice(&hash);
                // lock_mode: 0x00 = LOCK_MODE_HEIGHT
                cd.push(0x00);
                // lock_value: non-zero height
                cd.extend_from_slice(&256u64.to_le_bytes());
                // claim_key_id (32 bytes)
                let mut claim = [0u8; 32];
                claim[0] = suite_id;
                cd.extend_from_slice(&claim);
                // refund_key_id (32 bytes)
                cd.extend_from_slice(&[0x02u8; 32]);
                cd
            }
            0x0104 => {
                // MULTISIG: threshold(1) + key_count(1) + keys(N*32)
                // Matches parse_multisig_covenant_data: NO suite_id prefix.
                // threshold=1, key_count=1 → total = 2 + 32 = 34 bytes, 1 witness slot
                let mut cd = vec![1u8, 1u8]; // threshold, key_count
                let mut key = [0u8; 32];
                for (j, b) in pk.iter().take(32).enumerate() {
                    key[j] = *b;
                }
                cd.extend_from_slice(&key);
                cd
            }
            0x0101 => {
                // VAULT: owner_lock_id(32) + threshold(1) + key_count(1) + keys(N*32)
                //      + whitelist_count(2) + whitelist(N*32)
                // Matches parse_vault_covenant_data_for_spend. threshold=1, key_count=1,
                // whitelist_count=1. Total = 32+1+1+32+2+32 = 100 bytes.
                let mut cd = vec![0u8; 32]; // owner_lock_id
                cd.push(1u8); // threshold
                cd.push(1u8); // key_count
                let mut key = [0u8; 32];
                for (j, b) in pk.iter().take(32).enumerate() {
                    key[j] = *b;
                }
                cd.extend_from_slice(&key);
                // whitelist_count = 1 (little-endian u16)
                cd.extend_from_slice(&1u16.to_le_bytes());
                // whitelist entry: 32 bytes
                cd.extend_from_slice(&[0x01u8; 32]);
                cd
            }
            _ => {
                let mut cd = vec![suite_id];
                cd.extend_from_slice(&[0u8; 32]);
                cd
            }
        }
    };

    // Compute witness slots per input for this covenant type.
    // Mirrors consensus witness_slots() logic.
    let slots_per_input: usize = match covenant_type {
        0x0000 | 0x0102 | 0x0105 => 1, // P2PK / EXT / STEALTH
        0x0100 => 2,                     // HTLC
        0x0104 => 1,                     // MULTISIG (threshold=1)
        0x0101 => 1,                     // VAULT (threshold=1)
        _ => 1,
    };

    // Build resolved inputs with the selected covenant type.
    let resolved_inputs: Vec<rubin_consensus::UtxoEntry> = tx
        .inputs
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let (suite_id, pk) = if i * slots_per_input < tx.witness.len()
                && !tx.witness[i * slots_per_input].pubkey.is_empty()
            {
                (
                    tx.witness[i * slots_per_input].suite_id,
                    tx.witness[i * slots_per_input].pubkey.as_slice(),
                )
            } else {
                (0x01u8, [0u8; 32].as_slice())
            };
            let cov_data = build_covenant_data(suite_id, pk);
            rubin_consensus::UtxoEntry {
                value: if i < tx.outputs.len() {
                    tx.outputs[i].value.saturating_add(1)
                } else {
                    1
                },
                covenant_type,
                covenant_data: cov_data,
                creation_height: 0,
                created_by_coinbase: false,
            }
        })
        .collect();

    // witness_end accounts for slots_per_input * num_inputs, capped by actual witness len.
    let expected_witness = tx.inputs.len() * slots_per_input;
    let witness_end = expected_witness.min(tx.witness.len());

    // Sum input values for fee calculation.
    let sum_in: u64 = resolved_inputs.iter().map(|e| e.value).fold(0u64, |a, b| a.saturating_add(b));
    let sum_out: u64 = tx.outputs.iter().map(|o| o.value).fold(0u64, |a, b| a.saturating_add(b));
    let fee = sum_in.saturating_sub(sum_out);

    let ptc = rubin_consensus::PrecomputedTxContext {
        tx_index: 1,
        tx_block_idx: 0,
        txid: [0u8; 32],
        resolved_inputs,
        witness_start: 0,
        witness_end,
        input_outpoints: tx
            .inputs
            .iter()
            .map(|inp| rubin_consensus::Outpoint {
                txid: inp.prev_txid,
                vout: inp.prev_vout,
            })
            .collect(),
        fee,
    };

    // Minimal ParsedBlock with just this one transaction.
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
        &ptc,
        &pb,
        chain_id,
        block_height,
        block_mtp,
        &profiles,
        None,
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
    if r1.fee != fee {
        panic!("fee not preserved: expected {}, got {}", fee, r1.fee);
    }

    // --- Invariant: Determinism ---
    let r2 = rubin_consensus::validate_tx_local(
        &ptc,
        &pb,
        chain_id,
        block_height,
        block_mtp,
        &profiles,
        None,
    );
    if r1 != r2 {
        panic!("validate_tx_local non-deterministic");
    }
});
