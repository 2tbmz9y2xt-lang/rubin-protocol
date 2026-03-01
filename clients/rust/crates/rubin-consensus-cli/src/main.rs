use num_bigint::BigUint;
use num_traits::Zero;
use rubin_consensus::merkle::witness_merkle_root_wtxids;
use rubin_consensus::{
    apply_non_coinbase_tx_basic_with_mtp, block_hash, compact_shortid,
    connect_block_basic_in_memory_at_height, featurebit_state_at_height_from_window_counts,
    fork_work_from_target, merkle_root_txids, parse_tx, pow_check, retarget_v1,
    retarget_v1_clamped, sighash_v1_digest, tx_weight_and_stats_public,
    validate_block_basic_with_context_and_fees_at_height,
    validate_block_basic_with_context_at_height, validate_tx_covenants_genesis, ErrorCode,
    FeatureBitDeployment, FeatureBitState, InMemoryChainState, Outpoint, UtxoEntry,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Sha3_256};
use std::cmp::Ordering;
use std::collections::HashMap;

#[derive(Deserialize, Default)]
struct Request {
    op: String,

    #[serde(default)]
    tx_hex: String,

    #[serde(default)]
    block_hex: String,

    #[serde(default)]
    txids: Vec<String>,

    #[serde(default)]
    wtxids: Vec<String>,

    #[serde(default)]
    wtxid: String,

    #[serde(default)]
    covenant_type: u16,

    #[serde(default)]
    covenant_data_hex: String,

    #[serde(default)]
    nonce1: u64,

    #[serde(default)]
    nonce2: u64,

    #[serde(default)]
    input_index: u32,

    #[serde(default)]
    input_value: u64,

    #[serde(default)]
    chain_id: String,

    #[serde(default)]
    header_hex: String,

    #[serde(default)]
    target_hex: String,

    #[serde(default)]
    target: String,

    #[serde(default)]
    target_old: String,

    #[serde(default)]
    timestamp_first: u64,

    #[serde(default)]
    timestamp_last: u64,

    #[serde(default)]
    window_timestamps: Vec<u64>,

    #[serde(default)]
    expected_prev_hash: String,

    #[serde(default)]
    expected_target: String,

    #[serde(default)]
    utxos: Vec<UtxoJson>,

    #[serde(default)]
    height: u64,

    #[serde(default)]
    name: String,

    #[serde(default)]
    bit: u8,

    #[serde(default)]
    start_height: u64,

    #[serde(default)]
    timeout_height: u64,

    #[serde(default)]
    window_signal_counts: Vec<u32>,

    #[serde(default)]
    prev_timestamps: Vec<u64>,

    #[serde(default)]
    block_timestamp: u64,

    #[serde(default)]
    block_mtp: Option<u64>,

    #[serde(default)]
    already_generated: u64,

    #[serde(default)]
    sum_fees: u64,

    #[serde(default)]
    chains: Vec<ForkChoiceChainJson>,

    #[serde(default)]
    nonces: Vec<u64>,

    #[serde(default)]
    mtp: u64,

    #[serde(default)]
    timestamp: u64,

    #[serde(default)]
    max_future_drift: Option<u64>,

    #[serde(default)]
    keys: Vec<Value>,

    #[serde(default)]
    checks: Vec<CheckJson>,

    #[serde(default)]
    path: String,

    #[serde(default)]
    structural_ok: Option<bool>,

    #[serde(default)]
    locktime_ok: Option<bool>,

    #[serde(default)]
    suite_id: Option<u8>,

    #[serde(default)]
    slh_activation_height: Option<u64>,

    #[serde(default)]
    key_binding_ok: Option<bool>,

    #[serde(default)]
    preimage_ok: Option<bool>,

    #[serde(default)]
    verify_ok: Option<bool>,

    #[serde(default)]
    owner_lock_id: String,

    #[serde(default)]
    vault_input_count: usize,

    #[serde(default)]
    non_vault_lock_ids: Vec<String>,

    #[serde(default)]
    has_owner_auth: Option<bool>,

    #[serde(default)]
    sum_out: u64,

    #[serde(default)]
    sum_in_vault: u64,

    #[serde(default)]
    slots: usize,

    #[serde(default)]
    key_count: usize,

    #[serde(default)]
    sig_threshold_ok: Option<bool>,

    #[serde(default)]
    sentinel_suite_id: u8,

    #[serde(default)]
    sentinel_pubkey_len: usize,

    #[serde(default)]
    sentinel_sig_len: usize,

    #[serde(default)]
    sentinel_verify_called: Option<bool>,

    #[serde(default)]
    whitelist: Vec<String>,

    #[serde(default)]
    validation_order: Vec<String>,

    #[serde(default)]
    missing_indices: Vec<i64>,

    #[serde(default)]
    getblocktxn_ok: Option<bool>,

    #[serde(default)]
    pubkey_length: usize,

    #[serde(default)]
    sig_length: usize,

    #[serde(default)]
    batch_size: usize,

    #[serde(default)]
    invalid_indices: Vec<i64>,

    #[serde(default)]
    tx_count: usize,

    #[serde(default)]
    prefilled_indices: Vec<i64>,

    #[serde(default)]
    mempool_indices: Vec<i64>,

    #[serde(default)]
    blocktxn_indices: Vec<i64>,

    #[serde(default)]
    chunk_count: i64,

    #[serde(default)]
    ttl_blocks: i64,

    #[serde(default)]
    initial_chunks: Vec<i64>,

    #[serde(default)]
    initial_commit_seen: Option<bool>,

    #[serde(default)]
    commit_arrives: Option<bool>,

    #[serde(default)]
    events: Vec<Value>,

    #[serde(default)]
    per_peer_limit: i64,

    #[serde(default)]
    per_da_id_limit: i64,

    #[serde(default)]
    global_limit: i64,

    #[serde(default)]
    current_peer_bytes: i64,

    #[serde(default)]
    current_da_id_bytes: i64,

    #[serde(default)]
    current_global_bytes: i64,

    #[serde(default)]
    incoming_chunk_bytes: i64,

    #[serde(default)]
    incoming_has_commit: Option<bool>,

    #[serde(default)]
    storm_trigger_pct: f64,

    #[serde(default)]
    recovery_success_rate: f64,

    #[serde(default)]
    observation_minutes: i64,

    #[serde(default)]
    max_da_chunk_count: i64,

    #[serde(default)]
    phases: Vec<Value>,

    #[serde(default)]
    in_ibd: Option<bool>,

    #[serde(default)]
    warmup_done: Option<bool>,

    #[serde(default)]
    miss_rate_pct: f64,

    #[serde(default)]
    miss_rate_blocks: i64,

    #[serde(default)]
    start_score: i64,

    #[serde(default)]
    grace_period_active: Option<bool>,

    #[serde(default)]
    elapsed_blocks: i64,

    #[serde(default)]
    per_peer_bps: i64,

    #[serde(default)]
    global_bps: i64,

    #[serde(default)]
    peer_streams_bps: Vec<i64>,

    #[serde(default)]
    peer_stream_bps: i64,

    #[serde(default)]
    active_sets: i64,

    #[serde(default)]
    completed_sets: i64,

    #[serde(default)]
    total_sets: i64,

    #[serde(default)]
    telemetry: serde_json::Map<String, Value>,

    #[serde(default)]
    grace_period_blocks: i64,

    #[serde(default)]
    entries: Vec<Value>,

    #[serde(default)]
    da_id: String,

    #[serde(default)]
    commits: Vec<Value>,

    #[serde(default)]
    commit_fee: i64,

    #[serde(default)]
    chunk_fees: Vec<i64>,

    #[serde(default)]
    current_pinned_payload_bytes: i64,

    #[serde(default)]
    incoming_payload_bytes: i64,

    #[serde(default)]
    incoming_commit_overhead_bytes: i64,

    #[serde(default)]
    cap_bytes: i64,

    #[serde(default)]
    contains_commit: Option<bool>,

    #[serde(default)]
    contains_chunk_for_known_commit: Option<bool>,

    #[serde(default)]
    contains_block_with_commit: Option<bool>,

    #[serde(default)]
    orphan_pool_fill_pct: f64,
}

#[derive(Deserialize)]
struct UtxoJson {
    txid: String,
    vout: u32,
    value: u64,
    covenant_type: u16,
    covenant_data: String,
    creation_height: u64,
    created_by_coinbase: bool,
}

#[derive(Deserialize)]
struct ForkChoiceChainJson {
    id: String,
    targets: Vec<String>,
    tip_hash: String,
}

#[derive(Deserialize, Default)]
struct CheckJson {
    #[serde(default)]
    name: String,
    #[serde(default)]
    fails: bool,
    #[serde(default)]
    err: String,
}

#[derive(Serialize, Default)]
struct Response {
    ok: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    err: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    wtxid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    merkle_root: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    witness_merkle_root: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    consumed: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    block_hash: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    target_new: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    fee: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    utxo_count: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    sum_fees: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    already_generated: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    already_generated_n1: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    work: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    winner: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    chainwork: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    da_bytes: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    anchor_bytes: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    duplicates: Option<Vec<u64>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    sorted_keys: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    first_err: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    evaluated: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    verify_called: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    request_getblocktxn: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    request_full_block: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    penalize_peer: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    roundtrip_ok: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    wire_bytes: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    batch_ok: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    fallback: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    invalid_indices: Option<Vec<i64>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    missing_indices: Option<Vec<i64>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    reconstructed: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    boundary_height: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    prev_window_signal_count: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    signal_window: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    signal_threshold: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    estimated_activation_height: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    evicted: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pinned: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_reset_count: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    checkblock_results: Option<Vec<bool>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    admit: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    fill_pct: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    storm_mode: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    rollback: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    peer_exceeded: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    global_exceeded: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    quality_penalty: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    disconnect: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    rate: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    missing_fields: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    evict_order: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    retained_chunks: Option<Vec<i64>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    prefetch_targets: Option<Vec<i64>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    discarded_chunks: Option<Vec<i64>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    retained_peer: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    duplicates_dropped: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    penalized_peers: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    replaced: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    total_fee: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    counted_bytes: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    ignored_overhead_bytes: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    commit_bearing: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    prioritize: Option<bool>,
}

fn err_code(code: ErrorCode) -> String {
    code.as_str().to_string()
}

fn parse_hex_u256_to_32(s: &str) -> Result<[u8; 32], ()> {
    let mut out = [0u8; 32];
    let mut stripped = s.trim().to_lowercase();
    if let Some(rest) = stripped.strip_prefix("0x") {
        stripped = rest.to_string();
    }
    if stripped.is_empty() {
        return Err(());
    }
    if stripped.len() % 2 == 1 {
        stripped = format!("0{stripped}");
    }
    let b = hex::decode(stripped).map_err(|_| ())?;
    if b.len() > 32 {
        return Err(());
    }
    out[32 - b.len()..].copy_from_slice(&b);
    Ok(out)
}

fn key_bytes(value: &Value) -> Result<Vec<u8>, ()> {
    if let Some(s) = value.as_str() {
        let stripped = s.trim().to_lowercase();
        if let Some(hex_part) = stripped.strip_prefix("0x") {
            let normalized = if hex_part.len() % 2 == 1 {
                format!("0{hex_part}")
            } else {
                hex_part.to_string()
            };
            return hex::decode(normalized).map_err(|_| ());
        }
        return Ok(s.as_bytes().to_vec());
    }
    serde_json::to_string(value)
        .map(|s| s.into_bytes())
        .map_err(|_| ())
}

fn sorted_unique_i64(values: &[i64]) -> Vec<i64> {
    let mut out = values.to_vec();
    out.sort_unstable();
    out.dedup();
    out
}

fn value_as_i64(v: &Value, def: i64) -> i64 {
    v.as_i64().unwrap_or_else(|| {
        if let Some(u) = v.as_u64() {
            u as i64
        } else if let Some(f) = v.as_f64() {
            f as i64
        } else {
            def
        }
    })
}

fn value_as_string(v: &Value, def: &str) -> String {
    v.as_str()
        .map(|s| s.to_string())
        .unwrap_or_else(|| def.to_string())
}

fn op_featurebits_state(req: &Request) -> Response {
    let d = FeatureBitDeployment {
        name: req.name.clone(),
        bit: req.bit,
        start_height: req.start_height,
        timeout_height: req.timeout_height,
    };

    match featurebit_state_at_height_from_window_counts(&d, req.height, &req.window_signal_counts) {
        Ok(ev) => {
            let est = if ev.state == FeatureBitState::LockedIn {
                Some(ev.boundary_height + ev.signal_window)
            } else {
                None
            };
            Response {
                ok: true,
                state: Some(ev.state.as_str().to_string()),
                boundary_height: Some(ev.boundary_height),
                prev_window_signal_count: Some(ev.prev_window_signal_count),
                signal_window: Some(ev.signal_window),
                signal_threshold: Some(ev.signal_threshold),
                estimated_activation_height: est,
                ..Default::default()
            }
        }
        Err(e) => Response {
            ok: false,
            err: Some(e),
            ..Default::default()
        },
    }
}

fn main() {
    let req: Request = match serde_json::from_reader(std::io::stdin()) {
        Ok(v) => v,
        Err(e) => {
            let resp = Response {
                ok: false,
                err: Some(format!("bad request: {e}")),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
            return;
        }
    };

    match req.op.as_str() {
        "parse_tx" => {
            let tx_bytes = match hex::decode(req.tx_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad hex".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            match parse_tx(&tx_bytes) {
                Ok((_tx, txid, wtxid, n)) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: Some(hex::encode(txid)),
                        wtxid: Some(hex::encode(wtxid)),
                        merkle_root: None,
                        digest: None,
                        consumed: Some(n),
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "fork_work" => {
            let target = match parse_hex_u256_to_32(&req.target) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad target".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            match fork_work_from_target(target) {
                Ok(w) => {
                    let resp = Response {
                        ok: true,
                        work: Some(format!("0x{}", w.to_str_radix(16))),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "fork_choice_select" => {
            if req.chains.is_empty() {
                let resp = Response {
                    ok: false,
                    err: Some("bad chains".to_string()),
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }

            let mut best_id: Option<String> = None;
            let mut best_work: BigUint = BigUint::zero();
            let mut best_tip: Option<[u8; 32]> = None;

            for c in &req.chains {
                if c.id.is_empty() || c.targets.is_empty() {
                    let resp = Response {
                        ok: false,
                        err: Some("bad chain".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let tip = match parse_hex_u256_to_32(&c.tip_hash) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad tip_hash".to_string()),
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };

                let mut total = BigUint::zero();
                for ts in &c.targets {
                    let t = match parse_hex_u256_to_32(ts) {
                        Ok(v) => v,
                        Err(_) => {
                            let resp = Response {
                                ok: false,
                                err: Some("bad target".to_string()),
                                ..Default::default()
                            };
                            let _ = serde_json::to_writer(std::io::stdout(), &resp);
                            return;
                        }
                    };
                    match fork_work_from_target(t) {
                        Ok(w) => total += w,
                        Err(e) => {
                            let resp = Response {
                                ok: false,
                                err: Some(err_code(e.code)),
                                ..Default::default()
                            };
                            let _ = serde_json::to_writer(std::io::stdout(), &resp);
                            return;
                        }
                    }
                }

                let better = if best_id.is_none() || total > best_work {
                    true
                } else if total == best_work {
                    match best_tip {
                        Some(bt) => tip < bt,
                        None => true,
                    }
                } else {
                    false
                };

                if better {
                    best_id = Some(c.id.clone());
                    best_work = total;
                    best_tip = Some(tip);
                }
            }

            let resp = Response {
                ok: true,
                winner: best_id,
                chainwork: Some(format!("0x{}", best_work.to_str_radix(16))),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "featurebits_state" => {
            let resp = op_featurebits_state(&req);
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "merkle_root" => {
            let mut txids: Vec<[u8; 32]> = Vec::with_capacity(req.txids.len());
            for h in &req.txids {
                let b = match hex::decode(h) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad txid".to_string()),
                            txid: None,
                            wtxid: None,
                            merkle_root: None,
                            digest: None,
                            consumed: None,
                            block_hash: None,
                            target_new: None,
                            fee: None,
                            utxo_count: None,
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if b.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad txid".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                txids.push(a);
            }
            match merkle_root_txids(&txids) {
                Ok(root) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: Some(hex::encode(root)),
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "witness_merkle_root" => {
            let mut wtxids: Vec<[u8; 32]> = Vec::with_capacity(req.wtxids.len());
            for h in &req.wtxids {
                let b = match hex::decode(h) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad wtxid".to_string()),
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if b.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad wtxid".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                wtxids.push(a);
            }
            match witness_merkle_root_wtxids(&wtxids) {
                Ok(root) => {
                    let resp = Response {
                        ok: true,
                        witness_merkle_root: Some(hex::encode(root)),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "sighash_v1" => {
            let tx_bytes = match hex::decode(req.tx_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad hex".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let tx = match parse_tx(&tx_bytes) {
                Ok((tx, _txid, _wtxid, _n)) => tx,
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            let chain_id_bytes = match hex::decode(req.chain_id) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad chain_id".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            if chain_id_bytes.len() != 32 {
                let resp = Response {
                    ok: false,
                    err: Some("bad chain_id".to_string()),
                    txid: None,
                    wtxid: None,
                    merkle_root: None,
                    digest: None,
                    consumed: None,
                    block_hash: None,
                    target_new: None,
                    fee: None,
                    utxo_count: None,
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let mut chain_id = [0u8; 32];
            chain_id.copy_from_slice(&chain_id_bytes);

            match sighash_v1_digest(&tx, req.input_index, req.input_value, chain_id) {
                Ok(d) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: Some(hex::encode(d)),
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "tx_weight_and_stats" => {
            let tx_bytes = match hex::decode(req.tx_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad hex".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let (tx, _txid, _wtxid, _n) = match parse_tx(&tx_bytes) {
                Ok(v) => v,
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            match tx_weight_and_stats_public(&tx) {
                Ok((w, da, anchor)) => {
                    let resp = Response {
                        ok: true,
                        weight: Some(w),
                        da_bytes: Some(da),
                        anchor_bytes: Some(anchor),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "block_hash" => {
            let header_bytes = match hex::decode(req.header_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad header".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            match block_hash(&header_bytes) {
                Ok(h) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: Some(hex::encode(h)),
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "pow_check" => {
            let header_bytes = match hex::decode(req.header_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad header".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let target_bytes = match hex::decode(req.target_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad target".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            if target_bytes.len() != 32 {
                let resp = Response {
                    ok: false,
                    err: Some("bad target".to_string()),
                    txid: None,
                    wtxid: None,
                    merkle_root: None,
                    digest: None,
                    consumed: None,
                    block_hash: None,
                    target_new: None,
                    fee: None,
                    utxo_count: None,
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let mut target = [0u8; 32];
            target.copy_from_slice(&target_bytes);

            match pow_check(&header_bytes, target) {
                Ok(()) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "retarget_v1" => {
            let old_bytes = match hex::decode(req.target_old) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad target_old".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            if old_bytes.len() != 32 {
                let resp = Response {
                    ok: false,
                    err: Some("bad target_old".to_string()),
                    txid: None,
                    wtxid: None,
                    merkle_root: None,
                    digest: None,
                    consumed: None,
                    block_hash: None,
                    target_new: None,
                    fee: None,
                    utxo_count: None,
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let mut old = [0u8; 32];
            old.copy_from_slice(&old_bytes);

            let retarget_res = if !req.window_timestamps.is_empty() {
                retarget_v1_clamped(old, &req.window_timestamps)
            } else {
                retarget_v1(old, req.timestamp_first, req.timestamp_last)
            };
            match retarget_res {
                Ok(new_t) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: Some(hex::encode(new_t)),
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "block_basic_check" => {
            let block_bytes = match hex::decode(req.block_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad block".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            let expected_prev = if req.expected_prev_hash.is_empty() {
                None
            } else {
                let b = match hex::decode(req.expected_prev_hash) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad expected_prev_hash".to_string()),
                            txid: None,
                            wtxid: None,
                            merkle_root: None,
                            digest: None,
                            consumed: None,
                            block_hash: None,
                            target_new: None,
                            fee: None,
                            utxo_count: None,
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if b.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad expected_prev_hash".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&b);
                Some(h)
            };

            let expected_target = if req.expected_target.is_empty() {
                None
            } else {
                let b = match hex::decode(req.expected_target) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad expected_target".to_string()),
                            txid: None,
                            wtxid: None,
                            merkle_root: None,
                            digest: None,
                            consumed: None,
                            block_hash: None,
                            target_new: None,
                            fee: None,
                            utxo_count: None,
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if b.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad expected_target".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&b);
                Some(h)
            };

            let prev_timestamps = if req.prev_timestamps.is_empty() {
                None
            } else {
                Some(req.prev_timestamps.as_slice())
            };

            match validate_block_basic_with_context_at_height(
                &block_bytes,
                expected_prev,
                expected_target,
                req.height,
                prev_timestamps,
            ) {
                Ok(summary) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: Some(hex::encode(summary.block_hash)),
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "block_basic_check_with_fees" => {
            let block_bytes = match hex::decode(req.block_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad block".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            let expected_prev = if req.expected_prev_hash.is_empty() {
                None
            } else {
                let b = match hex::decode(req.expected_prev_hash) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad expected_prev_hash".to_string()),
                            txid: None,
                            wtxid: None,
                            merkle_root: None,
                            digest: None,
                            consumed: None,
                            block_hash: None,
                            target_new: None,
                            fee: None,
                            utxo_count: None,
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if b.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad expected_prev_hash".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&b);
                Some(h)
            };

            let expected_target = if req.expected_target.is_empty() {
                None
            } else {
                let b = match hex::decode(req.expected_target) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad expected_target".to_string()),
                            txid: None,
                            wtxid: None,
                            merkle_root: None,
                            digest: None,
                            consumed: None,
                            block_hash: None,
                            target_new: None,
                            fee: None,
                            utxo_count: None,
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if b.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad expected_target".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&b);
                Some(h)
            };

            let prev_timestamps = if req.prev_timestamps.is_empty() {
                None
            } else {
                Some(req.prev_timestamps.as_slice())
            };

            match validate_block_basic_with_context_and_fees_at_height(
                &block_bytes,
                expected_prev,
                expected_target,
                req.height,
                prev_timestamps,
                req.already_generated,
                req.sum_fees,
            ) {
                Ok(summary) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: Some(hex::encode(summary.block_hash)),
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "connect_block_basic" => {
            let block_bytes = match hex::decode(req.block_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad block".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            let expected_prev = if req.expected_prev_hash.is_empty() {
                None
            } else {
                let b = match hex::decode(req.expected_prev_hash) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad expected_prev_hash".to_string()),
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if b.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad expected_prev_hash".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&b);
                Some(h)
            };

            let expected_target = if req.expected_target.is_empty() {
                None
            } else {
                let b = match hex::decode(req.expected_target) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad expected_target".to_string()),
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if b.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad expected_target".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&b);
                Some(h)
            };

            let prev_timestamps = if req.prev_timestamps.is_empty() {
                None
            } else {
                Some(req.prev_timestamps.as_slice())
            };

            let mut utxo_set: HashMap<Outpoint, UtxoEntry> =
                HashMap::with_capacity(req.utxos.len());
            for u in &req.utxos {
                let txid_raw = match hex::decode(&u.txid) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad utxo txid".to_string()),
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if txid_raw.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad utxo txid".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let cov_data = match hex::decode(&u.covenant_data) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad utxo covenant_data".to_string()),
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };

                let mut op_txid = [0u8; 32];
                op_txid.copy_from_slice(&txid_raw);
                utxo_set.insert(
                    Outpoint {
                        txid: op_txid,
                        vout: u.vout,
                    },
                    UtxoEntry {
                        value: u.value,
                        covenant_type: u.covenant_type,
                        covenant_data: cov_data,
                        creation_height: u.creation_height,
                        created_by_coinbase: u.created_by_coinbase,
                    },
                );
            }

            let mut state = InMemoryChainState {
                utxos: utxo_set,
                already_generated: req.already_generated,
            };

            let mut chain_id = [0u8; 32];
            if !req.chain_id.trim().is_empty() {
                let b = match hex::decode(req.chain_id.trim()) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad chain_id".to_string()),
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if b.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad chain_id".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                chain_id.copy_from_slice(&b);
            }

            match connect_block_basic_in_memory_at_height(
                &block_bytes,
                expected_prev,
                expected_target,
                req.height,
                prev_timestamps,
                &mut state,
                chain_id,
            ) {
                Ok(summary) => {
                    let resp = Response {
                        ok: true,
                        sum_fees: Some(summary.sum_fees),
                        utxo_count: Some(summary.utxo_count),
                        already_generated: Some(summary.already_generated),
                        already_generated_n1: Some(summary.already_generated_n1),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "covenant_genesis_check" => {
            let tx_bytes = match hex::decode(req.tx_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad hex".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            let tx = match parse_tx(&tx_bytes) {
                Ok((tx, _txid, _wtxid, _n)) => tx,
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            match validate_tx_covenants_genesis(&tx, req.height) {
                Ok(()) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "utxo_apply_basic" => {
            let tx_bytes = match hex::decode(req.tx_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad hex".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            let (tx, txid, _wtxid, _n) = match parse_tx(&tx_bytes) {
                Ok(v) => v,
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            let mut utxo_set: HashMap<Outpoint, UtxoEntry> =
                HashMap::with_capacity(req.utxos.len());
            for u in &req.utxos {
                let txid_raw = match hex::decode(&u.txid) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad utxo txid".to_string()),
                            txid: None,
                            wtxid: None,
                            merkle_root: None,
                            digest: None,
                            consumed: None,
                            block_hash: None,
                            target_new: None,
                            fee: None,
                            utxo_count: None,
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if txid_raw.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad utxo txid".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let cov_data = match hex::decode(&u.covenant_data) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad utxo covenant_data".to_string()),
                            txid: None,
                            wtxid: None,
                            merkle_root: None,
                            digest: None,
                            consumed: None,
                            block_hash: None,
                            target_new: None,
                            fee: None,
                            utxo_count: None,
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };

                let mut op_txid = [0u8; 32];
                op_txid.copy_from_slice(&txid_raw);
                utxo_set.insert(
                    Outpoint {
                        txid: op_txid,
                        vout: u.vout,
                    },
                    UtxoEntry {
                        value: u.value,
                        covenant_type: u.covenant_type,
                        covenant_data: cov_data,
                        creation_height: u.creation_height,
                        created_by_coinbase: u.created_by_coinbase,
                    },
                );
            }

            let block_mtp = req.block_mtp.unwrap_or(req.block_timestamp);

            let mut chain_id = [0u8; 32];
            if !req.chain_id.trim().is_empty() {
                let b = match hex::decode(req.chain_id.trim()) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad chain_id".to_string()),
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if b.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad chain_id".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                chain_id.copy_from_slice(&b);
            }
            match apply_non_coinbase_tx_basic_with_mtp(
                &tx,
                txid,
                &utxo_set,
                req.height,
                req.block_timestamp,
                block_mtp,
                chain_id,
            ) {
                Ok(summary) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: Some(summary.fee),
                        utxo_count: Some(summary.utxo_count),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "compact_shortid" => {
            let wtxid_bytes = match hex::decode(req.wtxid) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad wtxid".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            if wtxid_bytes.len() != 32 {
                let resp = Response {
                    ok: false,
                    err: Some("bad wtxid".to_string()),
                    txid: None,
                    wtxid: None,
                    merkle_root: None,
                    digest: None,
                    consumed: None,
                    block_hash: None,
                    target_new: None,
                    fee: None,
                    utxo_count: None,
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let mut wtxid = [0u8; 32];
            wtxid.copy_from_slice(&wtxid_bytes);
            let sid = compact_shortid(wtxid, req.nonce1, req.nonce2);
            let resp = Response {
                ok: true,
                err: None,
                txid: None,
                wtxid: None,
                merkle_root: None,
                digest: Some(hex::encode(sid)),
                consumed: None,
                block_hash: None,
                target_new: None,
                fee: None,
                utxo_count: None,
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_collision_fallback" => {
            let mut missing = req.missing_indices.clone();
            missing.sort_unstable();
            let getblocktxn_ok = req.getblocktxn_ok.unwrap_or(true);
            let request_getblocktxn = !missing.is_empty();
            let request_full_block = request_getblocktxn && !getblocktxn_ok;
            let resp = Response {
                ok: true,
                request_getblocktxn: Some(request_getblocktxn),
                request_full_block: Some(request_full_block),
                penalize_peer: Some(false),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_witness_roundtrip" => {
            let suite_id = req.suite_id.unwrap_or(0x01);
            let pub_len = req.pubkey_length;
            let sig_len = req.sig_length;

            let mut wire: Vec<u8> = Vec::new();
            wire.push(suite_id);
            wire.extend_from_slice(&encode_compact_size(pub_len as u64));
            wire.extend(vec![0x11u8; pub_len]);
            wire.extend_from_slice(&encode_compact_size(sig_len as u64));
            wire.extend(vec![0x22u8; sig_len]);

            let mut off = 0usize;
            if wire.is_empty() {
                let _ = serde_json::to_writer(
                    std::io::stdout(),
                    &Response {
                        ok: false,
                        err: Some("wire underflow".to_string()),
                        ..Default::default()
                    },
                );
                return;
            }
            let suite2 = wire[off];
            off += 1;

            let dec_compact = |buf: &[u8]| -> Option<(u64, usize)> {
                if buf.is_empty() {
                    return None;
                }
                let pfx = buf[0];
                if pfx < 0xfd {
                    return Some((pfx as u64, 1));
                }
                if pfx == 0xfd {
                    if buf.len() < 3 {
                        return None;
                    }
                    return Some((u16::from_le_bytes([buf[1], buf[2]]) as u64, 3));
                }
                if pfx == 0xfe {
                    if buf.len() < 5 {
                        return None;
                    }
                    return Some((
                        u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as u64,
                        5,
                    ));
                }
                if buf.len() < 9 {
                    return None;
                }
                Some((
                    u64::from_le_bytes([
                        buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
                    ]),
                    9,
                ))
            };

            let (pub2, n) = match dec_compact(&wire[off..]) {
                Some(v) => v,
                None => {
                    let _ = serde_json::to_writer(
                        std::io::stdout(),
                        &Response {
                            ok: false,
                            err: Some("wire decode failed".to_string()),
                            ..Default::default()
                        },
                    );
                    return;
                }
            };
            off += n;
            if off + pub2 as usize > wire.len() {
                let _ = serde_json::to_writer(
                    std::io::stdout(),
                    &Response {
                        ok: false,
                        err: Some("wire bounds".to_string()),
                        ..Default::default()
                    },
                );
                return;
            }
            off += pub2 as usize;
            let (sig2, n) = match dec_compact(&wire[off..]) {
                Some(v) => v,
                None => {
                    let _ = serde_json::to_writer(
                        std::io::stdout(),
                        &Response {
                            ok: false,
                            err: Some("wire decode failed".to_string()),
                            ..Default::default()
                        },
                    );
                    return;
                }
            };
            off += n;
            if off + sig2 as usize > wire.len() {
                let _ = serde_json::to_writer(
                    std::io::stdout(),
                    &Response {
                        ok: false,
                        err: Some("wire bounds".to_string()),
                        ..Default::default()
                    },
                );
                return;
            }
            off += sig2 as usize;
            let roundtrip_ok = suite2 == suite_id
                && pub2 as usize == pub_len
                && sig2 as usize == sig_len
                && off == wire.len();
            let resp = Response {
                ok: true,
                roundtrip_ok: Some(roundtrip_ok),
                wire_bytes: Some(wire.len()),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_batch_verify" => {
            let batch_size = if req.batch_size == 0 {
                64
            } else {
                req.batch_size
            };
            let mut invalid = req.invalid_indices.clone();
            invalid.sort_unstable();
            for idx in &invalid {
                if *idx < 0 || *idx as usize >= batch_size {
                    let _ = serde_json::to_writer(
                        std::io::stdout(),
                        &Response {
                            ok: false,
                            err: Some("invalid index out of range".to_string()),
                            ..Default::default()
                        },
                    );
                    return;
                }
            }
            let batch_ok = invalid.is_empty();
            let resp = Response {
                ok: true,
                batch_ok: Some(batch_ok),
                fallback: Some(!batch_ok),
                invalid_indices: Some(invalid),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_prefill_roundtrip" => {
            let tx_count = req.tx_count as i64;
            let prefilled = sorted_unique_i64(&req.prefilled_indices);
            let mempool = sorted_unique_i64(&req.mempool_indices);
            let mut prefilled_set: HashMap<i64, ()> = HashMap::new();
            for i in &prefilled {
                prefilled_set.insert(*i, ());
            }
            let mut mempool_set: HashMap<i64, ()> = HashMap::new();
            for i in &mempool {
                mempool_set.insert(*i, ());
            }
            let mut short_ids = Vec::new();
            for i in 0..tx_count {
                if !prefilled_set.contains_key(&i) {
                    short_ids.push(i);
                }
            }
            let mut missing = Vec::new();
            for i in short_ids {
                if !mempool_set.contains_key(&i) {
                    missing.push(i);
                }
            }
            let request_getblocktxn = !missing.is_empty();
            let mut blocktxn = req.blocktxn_indices.clone();
            blocktxn.sort_unstable();
            let reconstructed = !request_getblocktxn || blocktxn == missing;
            let request_full_block = request_getblocktxn && !reconstructed;
            let resp = Response {
                ok: true,
                missing_indices: Some(missing),
                reconstructed: Some(reconstructed),
                request_full_block: Some(request_full_block),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_state_machine" => {
            let chunk_count = req.chunk_count;
            let ttl_cfg = if req.ttl_blocks == 0 {
                3
            } else {
                req.ttl_blocks
            };
            let mut chunks: HashMap<i64, ()> = HashMap::new();
            for idx in sorted_unique_i64(&req.initial_chunks) {
                chunks.insert(idx, ());
            }
            let mut commit_seen = req.initial_commit_seen.unwrap_or(false);
            let mut state = if commit_seen && chunks.len() as i64 == chunk_count {
                "C".to_string()
            } else if commit_seen {
                "B".to_string()
            } else {
                "A".to_string()
            };
            let mut pinned = state == "C";
            let mut ttl = if state == "C" { 0 } else { ttl_cfg };
            let mut ttl_reset_count = 0i64;
            let mut evicted = false;
            let mut checkblock_results: Vec<bool> = Vec::new();

            for raw in &req.events {
                let event = match raw.as_object() {
                    Some(v) => v,
                    None => {
                        let _ = serde_json::to_writer(
                            std::io::stdout(),
                            &Response {
                                ok: false,
                                err: Some("state-machine event must be object".to_string()),
                                ..Default::default()
                            },
                        );
                        return;
                    }
                };
                let typ = event
                    .get("type")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string();
                match typ.as_str() {
                    "chunk" => {
                        let idx = event
                            .get("index")
                            .map(|x| value_as_i64(x, -1))
                            .unwrap_or(-1);
                        if idx >= 0 && idx < chunk_count && state != "EVICTED" {
                            chunks.insert(idx, ());
                        }
                        if commit_seen && chunks.len() as i64 == chunk_count {
                            state = "C".to_string();
                            pinned = true;
                        }
                    }
                    "commit" => {
                        if state != "EVICTED" {
                            if state == "A" {
                                ttl = ttl_cfg;
                                ttl_reset_count += 1;
                            }
                            commit_seen = true;
                            if chunks.len() as i64 == chunk_count {
                                state = "C".to_string();
                                pinned = true;
                            } else {
                                state = "B".to_string();
                                pinned = false;
                            }
                        }
                    }
                    "tick" => {
                        if state == "A" || state == "B" {
                            let blocks =
                                event.get("blocks").map(|x| value_as_i64(x, 1)).unwrap_or(1);
                            ttl -= blocks;
                            if ttl <= 0 {
                                state = "EVICTED".to_string();
                                evicted = true;
                                commit_seen = false;
                                chunks.clear();
                                pinned = false;
                                ttl = 0;
                            }
                        }
                    }
                    "checkblock" => {
                        checkblock_results.push(commit_seen && chunks.len() as i64 == chunk_count);
                    }
                    _ => {
                        let _ = serde_json::to_writer(
                            std::io::stdout(),
                            &Response {
                                ok: false,
                                err: Some("unknown state-machine event type".to_string()),
                                ..Default::default()
                            },
                        );
                        return;
                    }
                }
            }
            let resp = Response {
                ok: true,
                state: Some(state),
                evicted: Some(evicted),
                pinned: Some(pinned),
                ttl: Some(ttl),
                ttl_reset_count: Some(ttl_reset_count),
                checkblock_results: Some(checkblock_results),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_orphan_limits" => {
            let per_peer_limit = if req.per_peer_limit == 0 {
                4 * 1024 * 1024
            } else {
                req.per_peer_limit
            };
            let per_da_id_limit = if req.per_da_id_limit == 0 {
                8 * 1024 * 1024
            } else {
                req.per_da_id_limit
            };
            let global_limit = if req.global_limit == 0 {
                64 * 1024 * 1024
            } else {
                req.global_limit
            };
            let admit = req.current_peer_bytes + req.incoming_chunk_bytes <= per_peer_limit
                && req.current_da_id_bytes + req.incoming_chunk_bytes <= per_da_id_limit
                && req.current_global_bytes + req.incoming_chunk_bytes <= global_limit;
            let resp = Response {
                ok: true,
                admit: Some(admit),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_orphan_storm" => {
            let global_limit = if req.global_limit == 0 {
                64 * 1024 * 1024
            } else {
                req.global_limit
            };
            let incoming_has_commit = req.incoming_has_commit.unwrap_or(false);
            let trigger_pct = if req.storm_trigger_pct == 0.0 {
                90.0
            } else {
                req.storm_trigger_pct
            };
            let fill_pct = if global_limit <= 0 {
                0.0
            } else {
                100.0 * (req.current_global_bytes as f64) / (global_limit as f64)
            };
            let storm_mode = fill_pct > trigger_pct;
            let rollback = req.recovery_success_rate < 95.0 && req.observation_minutes >= 10;
            let mut admit = req.current_global_bytes + req.incoming_chunk_bytes <= global_limit;
            if storm_mode && !incoming_has_commit {
                admit = false;
            }
            let resp = Response {
                ok: true,
                fill_pct: Some(fill_pct),
                storm_mode: Some(storm_mode),
                admit: Some(admit),
                rollback: Some(rollback),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_chunk_count_cap" => {
            let max_count = if req.max_da_chunk_count == 0 {
                32_000_000 / 524_288
            } else {
                req.max_da_chunk_count
            };
            let ok = req.chunk_count >= 0 && req.chunk_count <= max_count;
            if !ok {
                let _ = serde_json::to_writer(
                    std::io::stdout(),
                    &Response {
                        ok: false,
                        err: Some(err_code(ErrorCode::TxErrParse)),
                        ..Default::default()
                    },
                );
                return;
            }
            let _ = serde_json::to_writer(
                std::io::stdout(),
                &Response {
                    ok: true,
                    ..Default::default()
                },
            );
        }
        "compact_sendcmpct_modes" => {
            let compute_mode = |payload: &Value| -> i64 {
                let in_ibd = payload
                    .get("in_ibd")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false);
                let warmup_done = payload
                    .get("warmup_done")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false);
                let miss_rate_pct = payload
                    .get("miss_rate_pct")
                    .and_then(|x| x.as_f64())
                    .unwrap_or(0.0);
                let miss_rate_blocks = payload
                    .get("miss_rate_blocks")
                    .and_then(|x| x.as_i64())
                    .unwrap_or(0);
                if in_ibd {
                    return 0;
                }
                if miss_rate_pct > 10.0 && miss_rate_blocks >= 5 {
                    return 0;
                }
                if warmup_done && miss_rate_pct <= 0.5 {
                    return 2;
                }
                if warmup_done {
                    return 1;
                }
                0
            };
            if !req.phases.is_empty() {
                let mut modes: Vec<i64> = Vec::with_capacity(req.phases.len());
                for p in &req.phases {
                    modes.push(compute_mode(p));
                }
                let resp = Response {
                    ok: true,
                    invalid_indices: Some(modes),
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let mut payload = serde_json::Map::new();
            payload.insert(
                "in_ibd".to_string(),
                Value::Bool(req.in_ibd.unwrap_or(false)),
            );
            payload.insert(
                "warmup_done".to_string(),
                Value::Bool(req.warmup_done.unwrap_or(false)),
            );
            payload.insert("miss_rate_pct".to_string(), Value::from(req.miss_rate_pct));
            payload.insert(
                "miss_rate_blocks".to_string(),
                Value::from(req.miss_rate_blocks),
            );
            let mode = compute_mode(&Value::Object(payload));
            let resp = Response {
                ok: true,
                mode: Some(mode),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_peer_quality" => {
            let mut score = if req.start_score == 0 {
                50
            } else {
                req.start_score
            };
            let grace = req.grace_period_active.unwrap_or(false);
            let deltas: HashMap<&str, i64> = HashMap::from([
                ("reconstruct_no_getblocktxn", 2),
                ("getblocktxn_first_try", 1),
                ("prefetch_completed", 1),
                ("incomplete_set", -5),
                ("getblocktxn_required", -3),
                ("full_block_required", -10),
                ("prefetch_cap_exceeded", -2),
            ]);
            for e in &req.events {
                let ev = value_as_string(e, "");
                let mut delta = match deltas.get(ev.as_str()) {
                    Some(v) => *v,
                    None => {
                        let _ = serde_json::to_writer(
                            std::io::stdout(),
                            &Response {
                                ok: false,
                                err: Some("unknown peer-quality event".to_string()),
                                ..Default::default()
                            },
                        );
                        return;
                    }
                };
                if grace && delta < 0 {
                    delta /= 2;
                }
                score = (score + delta).clamp(0, 100);
            }
            for _ in 0..(req.elapsed_blocks / 144) {
                if score > 50 {
                    score -= 1;
                } else if score < 50 {
                    score += 1;
                }
            }
            let mode = if score >= 75 {
                2
            } else if score >= 40 {
                1
            } else {
                0
            };
            let resp = Response {
                ok: true,
                score: Some(score),
                mode: Some(mode),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_prefetch_caps" => {
            let per_peer_bps = if req.per_peer_bps == 0 {
                4_000_000
            } else {
                req.per_peer_bps
            };
            let global_bps = if req.global_bps == 0 {
                32_000_000
            } else {
                req.global_bps
            };
            let streams = if !req.peer_streams_bps.is_empty() {
                req.peer_streams_bps.clone()
            } else {
                let active = if req.active_sets <= 0 {
                    1
                } else {
                    req.active_sets
                };
                vec![req.peer_stream_bps; active as usize]
            };
            let peer_exceeded = streams.iter().any(|s| *s > per_peer_bps);
            let global_exceeded = streams.iter().sum::<i64>() > global_bps;
            let quality_penalty = peer_exceeded || global_exceeded;
            let resp = Response {
                ok: true,
                peer_exceeded: Some(peer_exceeded),
                global_exceeded: Some(global_exceeded),
                quality_penalty: Some(quality_penalty),
                disconnect: Some(false),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_telemetry_rate" => {
            if req.total_sets < 0 || req.completed_sets < 0 || req.completed_sets > req.total_sets {
                let _ = serde_json::to_writer(
                    std::io::stdout(),
                    &Response {
                        ok: false,
                        err: Some("invalid completed/total values".to_string()),
                        ..Default::default()
                    },
                );
                return;
            }
            let rate = if req.total_sets == 0 {
                1.0
            } else {
                req.completed_sets as f64 / req.total_sets as f64
            };
            let resp = Response {
                ok: true,
                rate: Some(rate),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_telemetry_fields" => {
            let required = [
                "shortid_collision_count",
                "shortid_collision_blocks",
                "shortid_collision_peers",
                "da_mempool_fill_pct",
                "orphan_pool_fill_pct",
                "miss_rate_bytes_L1",
                "miss_rate_bytes_DA",
                "partial_set_count",
                "partial_set_age_p95",
                "recovery_success_rate",
                "prefetch_latency_ms",
                "peer_quality_score",
            ];
            let mut missing: Vec<String> = Vec::new();
            for field in required {
                if !req.telemetry.contains_key(field) {
                    missing.push(field.to_string());
                }
            }
            missing.sort();
            if !missing.is_empty() {
                let _ = serde_json::to_writer(
                    std::io::stdout(),
                    &Response {
                        ok: false,
                        err: Some("missing telemetry fields".to_string()),
                        missing_fields: Some(missing),
                        ..Default::default()
                    },
                );
                return;
            }
            let _ = serde_json::to_writer(
                std::io::stdout(),
                &Response {
                    ok: true,
                    missing_fields: Some(missing),
                    ..Default::default()
                },
            );
        }
        "compact_grace_period" => {
            let grace_period_blocks = if req.grace_period_blocks == 0 {
                1440
            } else {
                req.grace_period_blocks
            };
            let grace_active = req.elapsed_blocks < grace_period_blocks;
            let mut score = if req.start_score == 0 {
                50
            } else {
                req.start_score
            };
            let deltas: HashMap<&str, i64> = HashMap::from([
                ("reconstruct_no_getblocktxn", 2),
                ("getblocktxn_first_try", 1),
                ("prefetch_completed", 1),
                ("incomplete_set", -5),
                ("getblocktxn_required", -3),
                ("full_block_required", -10),
                ("prefetch_cap_exceeded", -2),
            ]);
            for e in &req.events {
                let ev = value_as_string(e, "");
                let mut delta = match deltas.get(ev.as_str()) {
                    Some(v) => *v,
                    None => {
                        let _ = serde_json::to_writer(
                            std::io::stdout(),
                            &Response {
                                ok: false,
                                err: Some("unknown grace event".to_string()),
                                ..Default::default()
                            },
                        );
                        return;
                    }
                };
                if grace_active && delta < 0 {
                    delta /= 2;
                }
                score = (score + delta).clamp(0, 100);
            }
            let disconnect = score < 5 && !grace_active;
            let resp = Response {
                ok: true,
                storm_mode: Some(grace_active),
                score: Some(score),
                disconnect: Some(disconnect),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_eviction_tiebreak" => {
            let mut normalized: Vec<(String, f64, i64)> = Vec::new();
            for e in &req.entries {
                let obj = match e.as_object() {
                    Some(v) => v,
                    None => {
                        let _ = serde_json::to_writer(
                            std::io::stdout(),
                            &Response {
                                ok: false,
                                err: Some("entry must be object".to_string()),
                                ..Default::default()
                            },
                        );
                        return;
                    }
                };
                let da_id = obj
                    .get("da_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string();
                let fee = obj.get("fee").map(|x| value_as_i64(x, 0)).unwrap_or(0);
                let wire_bytes = obj
                    .get("wire_bytes")
                    .map(|x| value_as_i64(x, 0))
                    .unwrap_or(0);
                let received_time = obj
                    .get("received_time")
                    .map(|x| value_as_i64(x, 0))
                    .unwrap_or(0);
                if da_id.is_empty() || wire_bytes <= 0 {
                    let _ = serde_json::to_writer(
                        std::io::stdout(),
                        &Response {
                            ok: false,
                            err: Some("invalid da_id/wire_bytes".to_string()),
                            ..Default::default()
                        },
                    );
                    return;
                }
                normalized.push((da_id, fee as f64 / wire_bytes as f64, received_time));
            }
            normalized.sort_by(|a, b| {
                if a.1 != b.1 {
                    a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal)
                } else if a.2 != b.2 {
                    a.2.cmp(&b.2)
                } else {
                    a.0.cmp(&b.0)
                }
            });
            let order: Vec<String> = normalized.into_iter().map(|x| x.0).collect();
            let resp = Response {
                ok: true,
                evict_order: Some(order),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_a_to_b_retention" => {
            if req.chunk_count <= 0 {
                let _ = serde_json::to_writer(
                    std::io::stdout(),
                    &Response {
                        ok: false,
                        err: Some("chunk_count must be > 0".to_string()),
                        ..Default::default()
                    },
                );
                return;
            }
            let retained_chunks = sorted_unique_i64(&req.initial_chunks);
            let retained_set: HashMap<i64, ()> = retained_chunks.iter().map(|x| (*x, ())).collect();
            let mut missing_chunks: Vec<i64> = Vec::new();
            for i in 0..req.chunk_count {
                if !retained_set.contains_key(&i) {
                    missing_chunks.push(i);
                }
            }
            let commit_arrives = req.commit_arrives.unwrap_or(true);
            let state = if commit_arrives {
                if missing_chunks.is_empty() {
                    "C".to_string()
                } else {
                    "B".to_string()
                }
            } else {
                "A".to_string()
            };
            let prefetch_targets = if state == "B" {
                missing_chunks.clone()
            } else {
                Vec::new()
            };
            let resp = Response {
                ok: true,
                state: Some(state),
                retained_chunks: Some(retained_chunks),
                missing_indices: Some(missing_chunks),
                prefetch_targets: Some(prefetch_targets),
                discarded_chunks: Some(Vec::new()),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_duplicate_commit" => {
            let mut target_da_id = req.da_id.clone();
            let mut first_seen_peer: Option<String> = None;
            let mut duplicates_dropped = 0i64;
            let mut penalized_peers: Vec<String> = Vec::new();
            for c in &req.commits {
                let obj = match c.as_object() {
                    Some(v) => v,
                    None => {
                        let _ = serde_json::to_writer(
                            std::io::stdout(),
                            &Response {
                                ok: false,
                                err: Some("commit entry must be object".to_string()),
                                ..Default::default()
                            },
                        );
                        return;
                    }
                };
                let da_id = obj
                    .get("da_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string();
                let peer = obj
                    .get("peer")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string();
                if da_id.is_empty() || peer.is_empty() {
                    let _ = serde_json::to_writer(
                        std::io::stdout(),
                        &Response {
                            ok: false,
                            err: Some("invalid duplicate-commit entry".to_string()),
                            ..Default::default()
                        },
                    );
                    return;
                }
                if target_da_id.is_empty() {
                    target_da_id = da_id.clone();
                }
                if da_id != target_da_id {
                    continue;
                }
                if first_seen_peer.is_none() {
                    first_seen_peer = Some(peer);
                } else {
                    duplicates_dropped += 1;
                    penalized_peers.push(peer);
                }
            }
            penalized_peers.sort();
            let resp = Response {
                ok: true,
                retained_peer: first_seen_peer,
                duplicates_dropped: Some(duplicates_dropped),
                penalized_peers: Some(penalized_peers),
                replaced: Some(false),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_total_fee" => {
            let total_fee = req.commit_fee + req.chunk_fees.iter().sum::<i64>();
            let resp = Response {
                ok: true,
                total_fee: Some(total_fee),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_pinned_accounting" => {
            let cap = if req.cap_bytes == 0 {
                96_000_000
            } else {
                req.cap_bytes
            };
            let counted = req.current_pinned_payload_bytes + req.incoming_payload_bytes;
            let admit = counted <= cap;
            let resp = Response {
                ok: true,
                counted_bytes: Some(counted),
                admit: Some(admit),
                ignored_overhead_bytes: Some(req.incoming_commit_overhead_bytes),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "compact_storm_commit_bearing" => {
            let contains_commit = req.contains_commit.unwrap_or(false);
            let contains_chunk = req.contains_chunk_for_known_commit.unwrap_or(false);
            let contains_block = req.contains_block_with_commit.unwrap_or(false);
            let trigger_pct = if req.storm_trigger_pct == 0.0 {
                90.0
            } else {
                req.storm_trigger_pct
            };
            let commit_bearing = contains_commit || contains_chunk || contains_block;
            let storm_mode = req.orphan_pool_fill_pct > trigger_pct;
            let prioritize = !storm_mode || commit_bearing;
            let admit = !storm_mode || commit_bearing;
            let resp = Response {
                ok: true,
                storm_mode: Some(storm_mode),
                commit_bearing: Some(commit_bearing),
                prioritize: Some(prioritize),
                admit: Some(admit),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "output_descriptor_bytes" => {
            let cov_data = match hex::decode(req.covenant_data_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad covenant_data_hex".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let desc = output_descriptor_bytes(req.covenant_type, &cov_data);
            let resp = Response {
                ok: true,
                err: None,
                txid: None,
                wtxid: None,
                merkle_root: None,
                digest: Some(hex::encode(desc)),
                consumed: None,
                block_hash: None,
                target_new: None,
                fee: None,
                utxo_count: None,
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "output_descriptor_hash" => {
            let cov_data = match hex::decode(req.covenant_data_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad covenant_data_hex".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                        fee: None,
                        utxo_count: None,
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let desc = output_descriptor_bytes(req.covenant_type, &cov_data);
            let mut hasher = Sha3_256::new();
            hasher.update(desc);
            let h = hasher.finalize();
            let resp = Response {
                ok: true,
                err: None,
                txid: None,
                wtxid: None,
                merkle_root: None,
                digest: Some(hex::encode(h)),
                consumed: None,
                block_hash: None,
                target_new: None,
                fee: None,
                utxo_count: None,
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "nonce_replay_intrablock" => {
            let mut seen: HashMap<u64, ()> = HashMap::new();
            let mut duplicates: Vec<u64> = Vec::new();
            for nonce in &req.nonces {
                if seen.contains_key(nonce) {
                    duplicates.push(*nonce);
                } else {
                    seen.insert(*nonce, ());
                }
            }
            if duplicates.is_empty() {
                let resp = Response {
                    ok: true,
                    duplicates: Some(duplicates),
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let resp = Response {
                ok: false,
                err: Some(err_code(ErrorCode::TxErrNonceReplay)),
                duplicates: Some(duplicates),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "timestamp_bounds" => {
            let max_future_drift = req.max_future_drift.unwrap_or(7_200);
            if req.timestamp <= req.mtp {
                let resp = Response {
                    ok: false,
                    err: Some(err_code(ErrorCode::BlockErrTimestampOld)),
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            if req.timestamp > req.mtp.saturating_add(max_future_drift) {
                let resp = Response {
                    ok: false,
                    err: Some(err_code(ErrorCode::BlockErrTimestampFuture)),
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let resp = Response {
                ok: true,
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "determinism_order" => {
            let mut items: Vec<(String, Vec<u8>)> = Vec::with_capacity(req.keys.len());
            for key in &req.keys {
                let bytes = match key_bytes(key) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad key".to_string()),
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                let value = key
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| key.to_string());
                items.push((value, bytes));
            }
            items.sort_by(|a, b| {
                let cmp = a.1.cmp(&b.1);
                if cmp == Ordering::Equal {
                    a.0.cmp(&b.0)
                } else {
                    cmp
                }
            });
            let sorted_keys: Vec<String> = items.into_iter().map(|(v, _)| v).collect();
            let resp = Response {
                ok: true,
                sorted_keys: Some(sorted_keys),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "validation_order" => {
            if req.checks.is_empty() {
                let resp = Response {
                    ok: false,
                    err: Some("bad checks".to_string()),
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let mut evaluated: Vec<String> = Vec::with_capacity(req.checks.len());
            let mut first_err: Option<String> = None;
            for check in &req.checks {
                evaluated.push(check.name.clone());
                if check.fails {
                    first_err = Some(check.err.clone());
                    break;
                }
            }
            if let Some(err) = first_err.clone() {
                let resp = Response {
                    ok: false,
                    err: Some(err),
                    first_err,
                    evaluated: Some(evaluated),
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let resp = Response {
                ok: true,
                evaluated: Some(evaluated),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "htlc_ordering_policy" => {
            let path = if req.path.trim().is_empty() {
                "claim".to_string()
            } else {
                req.path.trim().to_lowercase()
            };
            let structural_ok = req.structural_ok.unwrap_or(true);
            let locktime_ok = req.locktime_ok.unwrap_or(true);
            let suite_id = req.suite_id.unwrap_or(0x01);
            let activation_height = req.slh_activation_height.unwrap_or(1_000_000);
            let key_binding_ok = req.key_binding_ok.unwrap_or(true);
            let preimage_ok = req.preimage_ok.unwrap_or(true);
            let verify_ok = req.verify_ok.unwrap_or(true);

            let mut verify_called = false;
            let mut err: Option<String> = None;

            if !structural_ok {
                err = Some(err_code(ErrorCode::TxErrParse));
            } else if path == "refund" && !locktime_ok {
                err = Some(err_code(ErrorCode::TxErrTimelockNotMet));
            } else if (suite_id != 0x01 && suite_id != 0x02)
                || (suite_id == 0x02 && req.height < activation_height)
            {
                err = Some(err_code(ErrorCode::TxErrSigAlgInvalid));
            } else if !key_binding_ok || (path == "claim" && !preimage_ok) {
                err = Some(err_code(ErrorCode::TxErrSigInvalid));
            } else {
                verify_called = true;
                if !verify_ok {
                    err = Some(err_code(ErrorCode::TxErrSigInvalid));
                }
            }

            if let Some(err_code_value) = err {
                let resp = Response {
                    ok: false,
                    err: Some(err_code_value),
                    verify_called: Some(verify_called),
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let resp = Response {
                ok: true,
                verify_called: Some(verify_called),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "vault_policy_rules" => {
            let owner_lock_id = if req.owner_lock_id.trim().is_empty() {
                "owner".to_string()
            } else {
                req.owner_lock_id.clone()
            };

            let mut has_owner_auth = req.has_owner_auth.unwrap_or(false);
            if req.has_owner_auth.is_none() {
                has_owner_auth = req.non_vault_lock_ids.iter().any(|x| x == &owner_lock_id);
            }
            let sig_threshold_ok = req.sig_threshold_ok.unwrap_or(true);
            let sentinel_verify_called = req.sentinel_verify_called.unwrap_or(false);
            let sentinel_ok = req.sentinel_suite_id == 0
                && req.sentinel_pubkey_len == 0
                && req.sentinel_sig_len == 0
                && !sentinel_verify_called;

            let mut whitelist_sorted = req.whitelist.clone();
            whitelist_sorted.sort();
            let whitelist_unique = whitelist_sorted.windows(2).all(|w| w[0] != w[1]);
            let whitelist_ok = req.whitelist == whitelist_sorted && whitelist_unique;

            let validation_order = if req.validation_order.is_empty() {
                vec![
                    "multi_vault".to_string(),
                    "owner_auth".to_string(),
                    "fee_sponsor".to_string(),
                    "witness_slots".to_string(),
                    "sentinel".to_string(),
                    "sig_threshold".to_string(),
                    "whitelist".to_string(),
                    "value".to_string(),
                ]
            } else {
                req.validation_order.clone()
            };

            for rule in &validation_order {
                let check = match rule.as_str() {
                    "multi_vault" => (
                        req.vault_input_count <= 1,
                        err_code(ErrorCode::TxErrVaultMultiInputForbidden),
                    ),
                    "owner_auth" => (
                        has_owner_auth,
                        err_code(ErrorCode::TxErrVaultOwnerAuthRequired),
                    ),
                    "fee_sponsor" => (
                        req.non_vault_lock_ids.iter().all(|x| x == &owner_lock_id),
                        err_code(ErrorCode::TxErrVaultFeeSponsorForbidden),
                    ),
                    "witness_slots" => {
                        (req.slots == req.key_count, err_code(ErrorCode::TxErrParse))
                    }
                    "sentinel" => (sentinel_ok, err_code(ErrorCode::TxErrParse)),
                    "sig_threshold" => (sig_threshold_ok, err_code(ErrorCode::TxErrSigInvalid)),
                    "whitelist" => (
                        whitelist_ok,
                        err_code(ErrorCode::TxErrVaultWhitelistNotCanonical),
                    ),
                    "value" => (
                        req.sum_out >= req.sum_in_vault,
                        err_code(ErrorCode::TxErrValueConservation),
                    ),
                    _ => {
                        let resp = Response {
                            ok: false,
                            err: Some("unknown validation rule".to_string()),
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if !check.0 {
                    let resp = Response {
                        ok: false,
                        err: Some(check.1),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            }

            let resp = Response {
                ok: true,
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        _ => {
            let resp = Response {
                ok: false,
                err: Some("unknown op".to_string()),
                txid: None,
                wtxid: None,
                merkle_root: None,
                digest: None,
                consumed: None,
                block_hash: None,
                target_new: None,
                fee: None,
                utxo_count: None,
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
    }
}

fn output_descriptor_bytes(covenant_type: u16, covenant_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 9 + covenant_data.len());
    out.extend_from_slice(&covenant_type.to_le_bytes());
    out.extend_from_slice(&encode_compact_size(covenant_data.len() as u64));
    out.extend_from_slice(covenant_data);
    out
}

fn encode_compact_size(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut out = vec![0xfd, 0, 0];
        out[1..3].copy_from_slice(&(n as u16).to_le_bytes());
        out
    } else if n <= 0xffff_ffff {
        let mut out = vec![0xfe, 0, 0, 0, 0];
        out[1..5].copy_from_slice(&(n as u32).to_le_bytes());
        out
    } else {
        let mut out = vec![0xff, 0, 0, 0, 0, 0, 0, 0, 0];
        out[1..9].copy_from_slice(&n.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn featurebits_state_ok_locked_in() {
        let req = Request {
            op: "featurebits_state".to_string(),
            name: "X".to_string(),
            bit: 0,
            start_height: 0,
            timeout_height: rubin_consensus::constants::SIGNAL_WINDOW * 10,
            height: rubin_consensus::constants::SIGNAL_WINDOW,
            window_signal_counts: vec![rubin_consensus::constants::SIGNAL_THRESHOLD],
            ..Default::default()
        };

        let resp = op_featurebits_state(&req);
        assert!(resp.ok);
        assert_eq!(resp.state.as_deref(), Some("LOCKED_IN"));
        assert_eq!(
            resp.boundary_height,
            Some(rubin_consensus::constants::SIGNAL_WINDOW)
        );
        assert_eq!(
            resp.prev_window_signal_count,
            Some(rubin_consensus::constants::SIGNAL_THRESHOLD)
        );
        assert_eq!(
            resp.signal_window,
            Some(rubin_consensus::constants::SIGNAL_WINDOW)
        );
        assert_eq!(
            resp.signal_threshold,
            Some(rubin_consensus::constants::SIGNAL_THRESHOLD)
        );
        assert_eq!(
            resp.estimated_activation_height,
            Some(rubin_consensus::constants::SIGNAL_WINDOW * 2)
        );
    }

    #[test]
    fn featurebits_state_err_bit_out_of_range() {
        let req = Request {
            op: "featurebits_state".to_string(),
            name: "X".to_string(),
            bit: 32,
            start_height: 0,
            timeout_height: 1,
            height: 0,
            window_signal_counts: vec![],
            ..Default::default()
        };

        let resp = op_featurebits_state(&req);
        assert!(!resp.ok);
        assert_eq!(
            resp.err.as_deref(),
            Some("featurebits: bit out of range: 32")
        );
    }
}
