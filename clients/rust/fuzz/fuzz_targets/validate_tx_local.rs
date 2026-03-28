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
    // Minimum: tx bytes + chain_id(32) + block_height(8) + block_mtp(8) = 48 tail bytes
    if data.len() < 49 {
        return;
    }

    let tail_len = 48;
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

    // Build resolved inputs — use P2PK covenant with first byte as suite_id.
    // This exercises the most common spend path.
    let resolved_inputs: Vec<rubin_consensus::UtxoEntry> = tx
        .inputs
        .iter()
        .enumerate()
        .map(|(i, _)| {
            // Cycle covenant data from witness if available, else default.
            let cov_data = if i < tx.witness.len() && !tx.witness[i].pubkey.is_empty() {
                let suite_id = tx.witness[i].suite_id;
                let mut cd = vec![suite_id];
                // key_id = 32 bytes from pubkey hash (or zero-padded)
                let pk = &tx.witness[i].pubkey;
                let mut key_id = [0u8; 32];
                for (j, b) in pk.iter().take(32).enumerate() {
                    key_id[j] = *b;
                }
                cd.extend_from_slice(&key_id);
                cd
            } else {
                // Default: suite_id=0x01 + 32 zero bytes
                let mut cd = vec![0x01u8];
                cd.extend_from_slice(&[0u8; 32]);
                cd
            };
            rubin_consensus::UtxoEntry {
                value: if i < tx.outputs.len() {
                    tx.outputs[i].value.saturating_add(1)
                } else {
                    1
                },
                covenant_type: 0x0000, // COV_TYPE_P2PK
                covenant_data: cov_data,
                creation_height: 0,
                created_by_coinbase: false,
            }
        })
        .collect();

    // witness_start=0, witness_end=witness.len() — let the validator do slot accounting.
    let witness_end = tx.witness.len();

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
