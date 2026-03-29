use super::*;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

const PARALLEL_TEST_WORKERS: usize = 4;
const MAX_FIXTURE_HEX_BYTES: usize = 100 * 1024;

fn clone_chain_state(
    utxos: &HashMap<Outpoint, UtxoEntry>,
    already_generated: u128,
) -> crate::InMemoryChainState {
    crate::InMemoryChainState {
        utxos: utxos.clone(),
        already_generated,
    }
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../conformance/fixtures")
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    if value.len() % 2 != 0 {
        return Err(format!("hex string must have even length: {}", value.len()));
    }
    let decoded_len = value.len() / 2;
    if decoded_len > MAX_FIXTURE_HEX_BYTES {
        return Err(format!(
            "hex string exceeds fixture limit: {} bytes > {} bytes",
            decoded_len, MAX_FIXTURE_HEX_BYTES
        ));
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for idx in (0..value.len()).step_by(2) {
        out.push(
            u8::from_str_radix(&value[idx..idx + 2], 16)
                .map_err(|err| format!("invalid hex at {idx}: {err}"))?,
        );
    }
    Ok(out)
}

fn decode_hex32_field(name: &str, value: &str) -> Result<[u8; 32], String> {
    let raw = decode_hex(value)?;
    if raw.len() != 32 {
        return Err(format!("{name}: expected 32 bytes, got {}", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[derive(Clone, Debug, Deserialize)]
struct ProbeVector {
    #[serde(default)]
    op: String,
    #[serde(default)]
    expect_ok: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct ConnectBlockVector {
    id: String,
    block_hex: String,
    #[serde(default)]
    chain_id: String,
    height: u64,
    #[serde(default)]
    already_generated: u64,
    utxos: Vec<VectorUtxo>,
    #[serde(default)]
    prev_timestamps: Vec<u64>,
    #[serde(default)]
    expected_prev_hash: String,
    #[serde(default)]
    expected_target: String,
}

#[derive(Clone, Debug, Deserialize)]
struct VectorUtxo {
    txid: String,
    covenant_data: String,
    value: u64,
    creation_height: u64,
    vout: u32,
    covenant_type: u16,
    created_by_coinbase: bool,
}

fn build_utxo_map_from_vector(utxos: &[VectorUtxo]) -> HashMap<Outpoint, UtxoEntry> {
    utxos
        .iter()
        .map(|u| {
            let txid = decode_hex32_field("utxo.txid", &u.txid).expect("decode utxo txid");
            let covenant_data = decode_hex(&u.covenant_data).expect("decode covenant data");
            (
                Outpoint { txid, vout: u.vout },
                UtxoEntry {
                    value: u.value,
                    covenant_type: u.covenant_type,
                    covenant_data,
                    creation_height: u.creation_height,
                    created_by_coinbase: u.created_by_coinbase,
                },
            )
        })
        .collect()
}

fn test_parallel_parity_from_vector(v: &ConnectBlockVector) {
    let block_bytes = decode_hex(&v.block_hex).expect("decode block_hex");
    let chain_id = if v.chain_id.is_empty() {
        ZERO_CHAIN_ID
    } else {
        decode_hex32_field("chain_id", &v.chain_id).expect("decode chain_id")
    };
    let expected_prev_hash = if v.expected_prev_hash.is_empty() {
        None
    } else {
        Some(
            decode_hex32_field("expected_prev_hash", &v.expected_prev_hash)
                .expect("decode expected_prev_hash"),
        )
    };
    let expected_target = if v.expected_target.is_empty() {
        None
    } else {
        Some(
            decode_hex32_field("expected_target", &v.expected_target)
                .expect("decode expected_target"),
        )
    };
    let utxos = build_utxo_map_from_vector(&v.utxos);

    let mut seq_state = clone_chain_state(&utxos, u128::from(v.already_generated));
    let seq_result = crate::connect_block_basic_in_memory_at_height(
        &block_bytes,
        expected_prev_hash,
        expected_target,
        v.height,
        Some(v.prev_timestamps.as_slice()),
        &mut seq_state,
        chain_id,
    )
    .expect("sequential connect");

    let mut par_state = clone_chain_state(&utxos, u128::from(v.already_generated));
    let par_result = crate::connect_block_parallel_sig_verify(
        &block_bytes,
        expected_prev_hash,
        expected_target,
        v.height,
        Some(v.prev_timestamps.as_slice()),
        &mut par_state,
        chain_id,
        PARALLEL_TEST_WORKERS,
    )
    .expect("parallel connect");

    assert_eq!(seq_result.sum_fees, par_result.sum_fees, "{}", v.id);
    assert_eq!(
        seq_result.already_generated, par_result.already_generated,
        "{}",
        v.id
    );
    assert_eq!(
        seq_result.already_generated_n1, par_result.already_generated_n1,
        "{}",
        v.id
    );
    assert_eq!(seq_result.utxo_count, par_result.utxo_count, "{}", v.id);
    assert_eq!(
        seq_result.post_state_digest, par_result.post_state_digest,
        "{}",
        v.id
    );
    assert_eq!(seq_state.utxos, par_state.utxos, "{}", v.id);
}

fn build_test_block(
    coinbase_value: u64,
) -> Option<(Vec<u8>, [u8; 32], [u8; 32], HashMap<Outpoint, UtxoEntry>)> {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0x99;
    let target = [0xffu8; 32];

    let kp = test_mldsa87_keypair()?;
    let cov_data = p2pk_covenant_data_for_pubkey(&kp.pubkey);
    let prev_out = Outpoint {
        txid: prev,
        vout: 0,
    };
    let mut spend_tx = crate::tx::Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![crate::tx::TxInput {
            prev_txid: prev,
            prev_vout: 0,
            script_sig: vec![],
            sequence: 0,
        }],
        outputs: vec![crate::tx::TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data.clone(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    };
    spend_tx.witness = vec![sign_input_witness(&spend_tx, 0, 100, ZERO_CHAIN_ID, &kp)];
    let spend_bytes = crate::tx_helpers::marshal_tx(&spend_tx).expect("marshal spend tx");
    let (_tx, spend_txid, _wtxid, _n) = parse_tx(&spend_bytes).expect("parse spend tx");

    let coinbase = coinbase_with_witness_commitment_and_p2pk_value(
        height as u32,
        coinbase_value,
        std::slice::from_ref(&spend_bytes),
    );
    let (_cb, coinbase_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
    let root = merkle_root_txids(&[coinbase_txid, spend_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 1, &[coinbase, spend_bytes]);

    let utxos = HashMap::from([(
        prev_out,
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov_data,
            creation_height: 0,
            created_by_coinbase: false,
        },
    )]);
    Some((block, prev, target, utxos))
}

#[test]
fn connect_block_parallel_sig_verify_conformance_parity() {
    let fixtures = fixture_dir();
    if !fixtures.exists() {
        return;
    }
    let mut files: Vec<_> = fs::read_dir(fixtures)
        .expect("read fixtures dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.starts_with("CV-") && name.ends_with(".json"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();

    let mut tested = 0usize;
    for path in files {
        let raw = fs::read(&path).expect("read fixture doc");
        let doc: serde_json::Value = serde_json::from_slice(&raw).expect("parse fixture doc");
        let vectors = doc["vectors"].as_array().expect("vectors array");
        for raw_vector in vectors {
            let probe = match serde_json::from_value::<ProbeVector>(raw_vector.clone()) {
                Ok(probe) => probe,
                Err(_) => continue,
            };
            if probe.op != "connect_block_basic" || !probe.expect_ok {
                continue;
            }
            let vector: ConnectBlockVector =
                serde_json::from_value(raw_vector.clone()).expect("parse connect block vector");
            test_parallel_parity_from_vector(&vector);
            tested += 1;
        }
    }

    assert!(tested > 0, "no connect_block_basic expect_ok vectors found");
}

#[test]
fn connect_block_parallel_sig_verify_guard_paths() {
    let mut state = crate::InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };
    let err = crate::connect_block_parallel_sig_verify(
        &[0x00],
        None,
        None,
        0,
        None,
        &mut state,
        ZERO_CHAIN_ID,
        0,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrParse);
    assert!(state.utxos.is_empty());
}

#[test]
fn connect_block_parallel_sig_verify_tx_validation_error_missing_utxo() {
    let height = 1u64;
    let Some((block, prev, target, _utxos)) = build_test_block(100) else {
        return;
    };
    let mut state = crate::InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };
    let err = crate::connect_block_parallel_sig_verify(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut state,
        ZERO_CHAIN_ID,
        4,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrMissingUtxo);
}

#[test]
fn connect_block_parallel_sig_verify_coinbase_value_bound() {
    let height = 1u64;
    let coinbase_value = (crate::constants::TAIL_EMISSION_PER_BLOCK as u64) + 11;
    let Some((block, prev, target, utxos)) = build_test_block(coinbase_value) else {
        return;
    };
    let mut state = clone_chain_state(&utxos, u128::from(crate::constants::MINEABLE_CAP));
    let err = crate::connect_block_parallel_sig_verify(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut state,
        ZERO_CHAIN_ID,
        4,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrSubsidyExceeded);
}

#[test]
fn connect_block_parallel_sig_verify_already_generated_overflow() {
    let height = 1u64;
    let coinbase_value = (crate::constants::TAIL_EMISSION_PER_BLOCK as u64) + 10;
    let Some((block, prev, target, utxos)) = build_test_block(coinbase_value) else {
        return;
    };
    let mut state = clone_chain_state(&utxos, u128::MAX);
    let err = crate::connect_block_parallel_sig_verify(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut state,
        ZERO_CHAIN_ID,
        4,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrParse);
}

#[test]
fn connect_block_parallel_sig_verify_already_generated_n1_overflow() {
    let height = 1u64;
    let subsidy = crate::subsidy::block_subsidy(height, u128::MAX);
    let coinbase_value = (crate::constants::TAIL_EMISSION_PER_BLOCK as u64) + 10;
    let Some((block, prev, target, utxos)) = build_test_block(coinbase_value) else {
        return;
    };
    let mut state = clone_chain_state(&utxos, u128::MAX - u128::from(subsidy) + 1);
    let err = crate::connect_block_parallel_sig_verify(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut state,
        ZERO_CHAIN_ID,
        4,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrParse);
}

#[test]
fn connect_block_parallel_sig_verify_coinbase_vault_forbidden() {
    let height = 1u64;
    let mut prev = [0u8; 32];
    prev[0] = 0xbb;
    let target = [0xffu8; 32];

    let wroot = crate::merkle::witness_merkle_root_wtxids(&[[0u8; 32]]).expect("witness root");
    let commit = crate::merkle::witness_commitment_hash(wroot);
    let coinbase = coinbase_tx_with_outputs(
        height as u32,
        &[
            TestOutput {
                value: 100,
                covenant_type: COV_TYPE_VAULT,
                covenant_data: valid_vault_covenant_data_for_p2pk_output(),
            },
            TestOutput {
                value: 0,
                covenant_type: COV_TYPE_ANCHOR,
                covenant_data: commit.to_vec(),
            },
        ],
    );
    let (_cb, coinbase_txid, _cbw, _cbn) = parse_tx(&coinbase).expect("parse coinbase");
    let root = merkle_root_txids(&[coinbase_txid]).expect("merkle root");
    let block = build_block_bytes(prev, root, target, 1, &[coinbase]);

    let mut state = crate::InMemoryChainState {
        utxos: HashMap::new(),
        already_generated: 0,
    };
    let err = crate::connect_block_parallel_sig_verify(
        &block,
        Some(prev),
        Some(target),
        height,
        Some(&[0]),
        &mut state,
        ZERO_CHAIN_ID,
        4,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::BlockErrCoinbaseInvalid);
}
