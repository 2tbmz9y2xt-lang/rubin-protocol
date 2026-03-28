#![no_main]

use libfuzzer_sys::fuzz_target;

// Structural fuzz of the spend-dispatch path via `validate_tx_local`.
//
// Instead of parsing tx from wire bytes, constructs a minimal valid Tx
// structure with fuzzed covenant type, covenant data, witness items,
// and suite IDs. This targets the covenant-type dispatch switch and
// structural validation paths that wire-format fuzzing rarely reaches
// (because most random bytes fail parse_tx early).
fuzz_target!(|data: &[u8]| {
    // Layout: covenant_type(2) + suite_id(1) + cov_data_len(1) + cov_data(N)
    //       + pubkey_len(2) + pubkey(M) + sig_len(2) + sig(K)
    //       + block_height(8) + chain_id(32)
    if data.len() < 48 {
        return;
    }

    let mut pos = 0;

    let covenant_type = u16::from_le_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    let suite_id = data[pos];
    pos += 1;

    let cov_data_len = data[pos] as usize;
    pos += 1;
    if pos + cov_data_len > data.len() - 44 {
        return;
    }
    let covenant_data = data[pos..pos + cov_data_len].to_vec();
    pos += cov_data_len;

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

    // Build a minimal Tx with one input, one output, one witness item.
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
            covenant_type: 0x0000, // P2PK output
            covenant_data: vec![0x01; 33],
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![rubin_consensus::WitnessItem {
            suite_id,
            pubkey,
            signature,
        }],
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
        witness_end: 1,
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

    let _ = rubin_consensus::validate_tx_local(
        &ptc,
        &pb,
        chain_id,
        block_height,
        0, // block_mtp
        &profiles,
        None,
    );
});
