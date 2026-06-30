use num_bigint::BigUint;
use num_traits::Zero;
use rubin_consensus::constants::{
    COV_TYPE_HTLC, COV_TYPE_P2PK, LOCK_MODE_HEIGHT, MAX_HTLC_COVENANT_DATA,
    MAX_WITNESS_BYTES_PER_TX, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_SENTINEL,
};
use rubin_consensus::merkle::witness_merkle_root_wtxids;
use rubin_consensus::{
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context,
    block_hash, compact_shortid,
    connect_block_basic_in_memory_at_height_and_core_ext_deployments_with_suite_context,
    featurebit_state_at_height_from_window_counts, flagday_active_at_height, merkle_root_txids,
    parse_tx, pow_check, retarget_v1, retarget_v1_clamped, sighash_v1_digest, simplicity,
    tx_weight_and_stats_at_height, tx_weight_and_stats_public,
    validate_block_basic_with_context_and_fees_at_height,
    validate_block_basic_with_context_at_height, validate_htlc_spend,
    validate_rotation_descriptor_for_network, validate_rotation_set_for_network,
    validate_tx_covenants_genesis, work_from_target, CryptoRotationDescriptor,
    DescriptorRotationProvider, ErrorCode, FeatureBitDeployment, FeatureBitState,
    FlagDayDeployment, HtlcSpendContext, InMemoryChainState, Outpoint, RotationProvider,
    SuiteParams, SuiteRegistry, Tx, TxInput, TxOutput, UtxoEntry, WitnessItem,
    ROTATION_V1_PRODUCTION_AT_MOST_ONE_DESCRIPTOR_ERR_STEM,
    ROTATION_V1_PRODUCTION_FINITE_H4_REQUIRED_ERR_STEM,
};
use rubin_node::{devnet_genesis_chain_id, ChainState, TxPool, TxPoolAdmitErrorKind, TxPoolConfig};
use serde::de::{IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha3::{Digest, Sha3_256};
use std::cmp::Ordering;
use std::collections::HashMap;

const ROTATION_DESCRIPTOR_NOT_ACTIVATED_ERR: &str = "descriptor-not-activated";
const ROTATION_TOO_MANY_DESCRIPTORS_ERR: &str = "rotation-too-many-descriptors";
const ROTATION_FINITE_H4_REQUIRED_ERR: &str = "rotation-finite-h4-required";
const ROTATION_OVERLAPPING_DESCRIPTORS_ERR: &str = "rotation-overlapping-descriptors";
const ROTATION_UNREGISTERED_SUITE_ERR: &str = "rotation-unregistered-suite";
const ROTATION_EQUAL_SUITE_IDS_ERR: &str = "rotation-equal-suite-ids";
const ROTATION_INVALID_HEIGHT_ORDER_ERR: &str = "rotation-invalid-height-order";
const ROTATION_INVALID_DESCRIPTOR_ERR: &str = "rotation-invalid-descriptor";
const ROTATION_OVERLAPPING_DESCRIPTORS_MSG: &str = "rotation: overlapping rotations";
const ROTATION_NAME_REQUIRED_MSG: &str = "rotation: name required";
const ROTATION_OLD_SUITE_NOT_REGISTERED_MSG: &str = "rotation: old suite ";
const ROTATION_NEW_SUITE_NOT_REGISTERED_MSG: &str = "rotation: new suite ";
const ROTATION_EQUAL_SUITE_IDS_MSG: &str = "must differ from new suite";
const ROTATION_CREATE_HEIGHT_ORDER_MSG: &str = "rotation: create_height (";
const ROTATION_SUNSET_HEIGHT_ORDER_MSG: &str = "rotation: sunset_height (";

#[derive(Default)]
struct RetiredCoreExtProfiles {
    has_items: bool,
}

fn deserialize_retired_core_ext_profiles<'de, D>(
    deserializer: D,
) -> Result<RetiredCoreExtProfiles, D::Error>
where
    D: Deserializer<'de>,
{
    struct RetiredCoreExtProfilesVisitor;

    impl<'de> Visitor<'de> for RetiredCoreExtProfilesVisitor {
        type Value = RetiredCoreExtProfiles;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an array")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut has_items = false;
            while seq.next_element::<IgnoredAny>()?.is_some() {
                has_items = true;
            }
            Ok(RetiredCoreExtProfiles { has_items })
        }
    }

    deserializer.deserialize_seq(RetiredCoreExtProfilesVisitor)
}

fn matches_wrapped_prefix_validation_err(err: &str, expected: &str) -> bool {
    err.starts_with(expected) || err.contains(&format!(": {expected}"))
}

fn matches_wrapped_suffix_validation_err(err: &str, expected: &str) -> bool {
    err == expected || err.ends_with(expected)
}

fn sanitize_rotation_validation_err(err: &str) -> &'static str {
    if matches_wrapped_prefix_validation_err(
        err,
        ROTATION_V1_PRODUCTION_AT_MOST_ONE_DESCRIPTOR_ERR_STEM,
    ) {
        ROTATION_TOO_MANY_DESCRIPTORS_ERR
    } else if matches_wrapped_prefix_validation_err(
        err,
        ROTATION_V1_PRODUCTION_FINITE_H4_REQUIRED_ERR_STEM,
    ) {
        ROTATION_FINITE_H4_REQUIRED_ERR
    } else if matches_wrapped_prefix_validation_err(err, ROTATION_OVERLAPPING_DESCRIPTORS_MSG) {
        ROTATION_OVERLAPPING_DESCRIPTORS_ERR
    } else if matches_wrapped_prefix_validation_err(err, ROTATION_NAME_REQUIRED_MSG) {
        ROTATION_INVALID_DESCRIPTOR_ERR
    } else if matches_wrapped_suffix_validation_err(err, ROTATION_EQUAL_SUITE_IDS_MSG) {
        ROTATION_EQUAL_SUITE_IDS_ERR
    } else if matches_wrapped_prefix_validation_err(err, ROTATION_OLD_SUITE_NOT_REGISTERED_MSG)
        || matches_wrapped_prefix_validation_err(err, ROTATION_NEW_SUITE_NOT_REGISTERED_MSG)
    {
        ROTATION_UNREGISTERED_SUITE_ERR
    } else if matches_wrapped_prefix_validation_err(err, ROTATION_CREATE_HEIGHT_ORDER_MSG)
        || matches_wrapped_prefix_validation_err(err, ROTATION_SUNSET_HEIGHT_ORDER_MSG)
    {
        ROTATION_INVALID_HEIGHT_ORDER_ERR
    } else {
        ROTATION_INVALID_DESCRIPTOR_ERR
    }
}

fn rotation_descriptor_validation_response(err: String) -> Response {
    Response {
        ok: false,
        err: Some(ROTATION_DESCRIPTOR_NOT_ACTIVATED_ERR.to_string()),
        diagnostics: Some(serde_json::json!({
            "rotation_validation_err": sanitize_rotation_validation_err(&err),
        })),
        ..Default::default()
    }
}

#[derive(Deserialize, Default)]
struct Request {
    op: String,

    /// When set to mainnet/testnet, applies v1 production rotation rules
    /// (strict single descriptor + finite H4).
    #[serde(default)]
    network: String,

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

    #[serde(default, deserialize_with = "deserialize_retired_core_ext_profiles")]
    core_ext_profiles: RetiredCoreExtProfiles,

    #[serde(default)]
    core_ext_profile_set_anchor_hex: String,

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
    activation_height: Option<u64>,

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
    selector_payload_len_ok: Option<bool>,

    #[serde(default)]
    suite_id: Option<u8>,

    #[serde(default)]
    rotation_descriptor: Option<RotationDescriptorJson>,

    #[serde(default)]
    suite_registry: Vec<SuiteParamsJson>,

    #[serde(default)]
    rotation_descriptors: Vec<RotationDescriptorJson>,

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
    current_mempool_min_fee_rate: Option<u64>,

    #[serde(default)]
    min_da_fee_rate: Option<u64>,

    #[serde(default)]
    da_surcharge_per_byte: u64,

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

    #[serde(default)]
    program_hex: String,

    #[serde(default)]
    witness_hex: String,

    #[serde(default)]
    semantics_version: Option<u32>,

    #[serde(default)]
    covenant_cmr_hex: String,

    #[serde(default)]
    jet_accepted: Option<bool>,

    #[serde(default)]
    jet_cost: Option<u64>,

    #[serde(default)]
    eval_steps: Option<u64>,

    #[serde(default)]
    frame_bit_widths: Vec<u64>,
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

#[derive(Deserialize, Default)]
struct RotationDescriptorJson {
    #[serde(default)]
    name: String,
    #[serde(default)]
    old_suite_id: u8,
    #[serde(default)]
    new_suite_id: u8,
    #[serde(default)]
    create_height: u64,
    #[serde(default)]
    spend_height: u64,
    #[serde(default)]
    sunset_height: u64,
}

#[derive(Default)]
struct SuiteParamsJson {
    suite_id: u8,
    pubkey_len: u64,
    sig_len: u64,
    verify_cost: u64,
    alg_name: String,
}

#[derive(Deserialize, Default)]
struct SuiteParamsJsonWire {
    #[serde(default)]
    suite_id: Option<u8>,
    #[serde(default)]
    pubkey_len: Option<u64>,
    #[serde(default)]
    sig_len: Option<u64>,
    #[serde(default)]
    verify_cost: Option<u64>,
    #[serde(default)]
    alg_name: Option<String>,
    #[serde(default)]
    openssl_alg: Option<String>,
}

impl<'de> Deserialize<'de> for SuiteParamsJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SuiteParamsJsonWire::deserialize(deserializer)?;
        let suite_id = wire
            .suite_id
            .ok_or_else(|| serde::de::Error::custom("bad suite_registry"))?;
        let pubkey_len = wire
            .pubkey_len
            .ok_or_else(|| serde::de::Error::custom("bad suite_registry"))?;
        let sig_len = wire
            .sig_len
            .ok_or_else(|| serde::de::Error::custom("bad suite_registry"))?;
        let verify_cost = wire
            .verify_cost
            .ok_or_else(|| serde::de::Error::custom("bad suite_registry"))?;
        let alg_name = if let Some(value) = wire.alg_name {
            value
        } else {
            wire.openssl_alg.unwrap_or_default()
        };
        Ok(Self {
            suite_id,
            pubkey_len,
            sig_len,
            verify_cost,
            alg_name,
        })
    }
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
    diagnostics: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    err: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    accepted: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    final_counter: Option<u64>,

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
    ext_id: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    suite_ids: Option<Vec<u8>>,

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
    activation_height: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    consensus_active: Option<bool>,

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
    relay_fee_floor: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    da_fee_floor: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    da_surcharge: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    da_required_fee: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    required_fee: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    admit_class: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    dominant_floor: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    reject_reason: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    policy_entrypoint: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    mutation_checked: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    mutated: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pool_len_before: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pool_len_after: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    duplicate_conflict_capacity_checked: Option<bool>,

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

fn htlc_refund_ordering_policy_response(
    req: &Request,
    suite_id: u8,
    key_binding_ok: bool,
    selector_payload_len_ok: bool,
) -> Response {
    let mut claim_key_id = [0u8; 32];
    let mut refund_key_id = [0u8; 32];
    claim_key_id[0] = 0x11;
    refund_key_id[0] = 0x22;

    let mut covenant_data = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
    covenant_data.extend_from_slice(&[0u8; 32]);
    covenant_data.push(LOCK_MODE_HEIGHT);
    covenant_data.extend_from_slice(&1u64.to_le_bytes());
    covenant_data.extend_from_slice(&claim_key_id);
    covenant_data.extend_from_slice(&refund_key_id);

    let entry = UtxoEntry {
        value: 100,
        covenant_type: COV_TYPE_HTLC,
        covenant_data,
        creation_height: 0,
        created_by_coinbase: false,
    };
    let selector_key_id = if key_binding_ok {
        refund_key_id
    } else {
        claim_key_id
    };
    let selector_payload = if selector_payload_len_ok {
        vec![0x01]
    } else {
        vec![0x01, 0x02]
    };
    let path_item = WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: selector_key_id.to_vec(),
        signature: selector_payload,
    };
    let sig_item = WitnessItem {
        suite_id,
        pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
        signature: vec![0u8; (ML_DSA_87_SIG_BYTES + 1) as usize],
    };
    let tx = Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 90,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: Vec::new(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: Vec::new(),
    };
    let ctx = HtlcSpendContext {
        input_index: 0,
        input_value: 100,
        chain_id: [0u8; 32],
        block_height: req.height,
        block_mtp: req.block_mtp.unwrap_or(0),
    };

    match validate_htlc_spend(&entry, &path_item, &sig_item, &tx, ctx) {
        Ok(()) => Response {
            ok: true,
            verify_called: Some(true),
            ..Default::default()
        },
        Err(err) => Response {
            ok: false,
            err: Some(err_code(err.code)),
            verify_called: Some(false),
            ..Default::default()
        },
    }
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

fn parse_exact_hex32(s: &str) -> Result<[u8; 32], ()> {
    let stripped = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))
        .unwrap_or_else(|| s.trim());
    let b = hex::decode(stripped).map_err(|_| ())?;
    if b.len() != 32 {
        return Err(());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
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

fn normalize_suite_alg_name(value: &str) -> Result<&'static str, String> {
    const CANONICAL_SUITE_ALG_NAME: &str = "ML-DSA-87";
    let trimmed = value.trim();
    if !trimmed.eq_ignore_ascii_case(CANONICAL_SUITE_ALG_NAME) {
        return Err("bad suite_registry".to_string());
    }
    Ok(CANONICAL_SUITE_ALG_NAME)
}

const MAX_EXPLICIT_SUITE_REGISTRY_ITEMS: usize = 16;

fn validate_suite_registry_param_len(value: u64) -> Result<u64, String> {
    if value > MAX_WITNESS_BYTES_PER_TX as u64 {
        return Err("bad suite_registry".to_string());
    }
    Ok(value)
}

fn build_suite_registry_from_json(
    items: &[SuiteParamsJson],
) -> Result<Option<SuiteRegistry>, String> {
    if items.is_empty() {
        return Ok(None);
    }
    if items.len() > MAX_EXPLICIT_SUITE_REGISTRY_ITEMS {
        return Err("bad suite_registry".to_string());
    }

    let mut suites = std::collections::BTreeMap::new();
    for s in items {
        if s.suite_id == rubin_consensus::constants::SUITE_ID_SENTINEL || s.verify_cost == 0 {
            return Err("bad suite_registry".to_string());
        }
        let pubkey_len = validate_suite_registry_param_len(s.pubkey_len)?;
        let sig_len = validate_suite_registry_param_len(s.sig_len)?;
        let alg = normalize_suite_alg_name(&s.alg_name)?;
        // Missing required JSON fields are rejected during Deserialize above.
        // Reaching this path means zero-valued lengths were explicit, which the
        // CLI harness still permits for synthetic conformance vectors.
        if suites
            .insert(
                s.suite_id,
                SuiteParams {
                    suite_id: s.suite_id,
                    pubkey_len,
                    sig_len,
                    verify_cost: s.verify_cost,
                    alg_name: alg,
                },
            )
            .is_some()
        {
            return Err("bad suite_registry".to_string());
        }
    }

    Ok(Some(SuiteRegistry::with_suites(suites)))
}

fn decode_optional_simplicity_hex(
    name: &str,
    value: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if stripped.is_empty() {
        return Ok(Vec::new());
    }
    if stripped.len() > max_bytes.saturating_mul(2) {
        return Err(format!("bad {name}"));
    }
    hex::decode(stripped).map_err(|_| format!("bad {name}"))
}

fn decode_simplicity_program_hex(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if stripped.is_empty() {
        return Err("bad program_hex".to_string());
    }
    if stripped.len() > simplicity::MAX_PROGRAM_BYTES.saturating_mul(2) {
        return Err(simplicity::ErrorCode::ProgramTooLarge.as_str().to_string());
    }
    hex::decode(stripped).map_err(|_| "bad program_hex".to_string())
}

fn parse_optional_hex32_named(value: &str, bad_err: &str) -> Result<Option<[u8; 32]>, String> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    parse_exact_hex32(value)
        .map(Some)
        .map_err(|_| bad_err.to_string())
}

fn cli_error(err: impl Into<String>) -> Response {
    Response {
        ok: false,
        err: Some(err.into()),
        ..Default::default()
    }
}

fn simplicity_eval_error_response(err: simplicity::EvalError) -> Response {
    Response {
        ok: false,
        err: Some(err.code.as_str().to_string()),
        accepted: Some(err.result.accepted),
        final_counter: Some(err.result.cost),
        ..Default::default()
    }
}

fn run_simplicity_synthetic_exec_vector(req: &Request) -> Response {
    let Some(eval_steps) = req.eval_steps else {
        return cli_error(if req.frame_bit_widths.is_empty() {
            "bad program_hex"
        } else {
            "bad eval_steps"
        });
    };
    match evaluate_simplicity_synthetic(eval_steps, &req.frame_bit_widths) {
        Ok(result) => Response {
            ok: true,
            accepted: Some(result.accepted),
            final_counter: Some(result.cost),
            ..Default::default()
        },
        Err(err) => simplicity_eval_error_response(err),
    }
}

fn evaluate_simplicity_synthetic(
    eval_steps: u64,
    frame_bit_widths: &[u64],
) -> Result<simplicity::EvalResult, simplicity::EvalError> {
    if eval_steps == 0 {
        return Err(simplicity::EvalError {
            code: simplicity::ErrorCode::Decode,
            result: simplicity::EvalResult::default(),
        });
    }
    check_simplicity_synthetic_memory(frame_bit_widths)?;
    let max_steps = simplicity::MAX_EXEC_COST
        .checked_div(simplicity::STEP_COST)
        .unwrap_or(u64::MAX);
    if eval_steps > max_steps {
        return Err(simplicity::EvalError {
            code: simplicity::ErrorCode::BudgetExceeded,
            result: simplicity::EvalResult {
                accepted: true,
                cost: simplicity::MAX_EXEC_COST,
            },
        });
    }
    Ok(simplicity::EvalResult {
        accepted: true,
        cost: eval_steps * simplicity::STEP_COST,
    })
}

fn check_simplicity_synthetic_memory(
    frame_bit_widths: &[u64],
) -> Result<(), simplicity::EvalError> {
    let mut live = 0u64;
    for frame_bits in frame_bit_widths {
        let Some(rounded) = frame_bits.checked_add(7) else {
            return Err(simplicity_budget_exceeded());
        };
        let frame_bytes = rounded / 8;
        if frame_bytes > simplicity::MAX_FRAME_BYTES {
            return Err(simplicity_budget_exceeded());
        }
        live = live
            .checked_add(frame_bytes)
            .ok_or_else(simplicity_budget_exceeded)?;
        if live > simplicity::MAX_LIVE_MEMORY_BYTES {
            return Err(simplicity_budget_exceeded());
        }
    }
    Ok(())
}

fn simplicity_budget_exceeded() -> simplicity::EvalError {
    simplicity::EvalError {
        code: simplicity::ErrorCode::BudgetExceeded,
        result: simplicity::EvalResult::default(),
    }
}

fn run_simplicity_exec_vector(req: &Request) -> Response {
    if req.program_hex.trim().is_empty() {
        return run_simplicity_synthetic_exec_vector(req);
    }
    let program_bytes = match decode_simplicity_program_hex(&req.program_hex) {
        Ok(bytes) => bytes,
        Err(err) => return cli_error(err),
    };
    let witness_bytes = match decode_optional_simplicity_hex(
        "witness_hex",
        &req.witness_hex,
        simplicity::MAX_PROGRAM_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(err) => return cli_error(err),
    };
    let covenant_program_cmr =
        match parse_optional_hex32_named(&req.covenant_cmr_hex, "bad covenant_cmr_hex") {
            Ok(cmr) => cmr,
            Err(err) => return cli_error(err),
        };

    let program = match simplicity::decode(
        &program_bytes,
        &witness_bytes,
        simplicity::DecodeOptions {
            semantics_version: req
                .semantics_version
                .unwrap_or(simplicity::SEMANTICS_VERSION),
            covenant_program_cmr,
        },
    ) {
        Ok(program) => program,
        Err(err) => return cli_error(err.code.as_str()),
    };

    let jet_hook;
    let opts = if program.jet.is_some() {
        let Some(jet_cost) = req.jet_cost else {
            return cli_error("bad jet_cost");
        };
        let jet_accepted = req.jet_accepted.unwrap_or(false);
        jet_hook = move |_: simplicity::Jet| {
            Ok(simplicity::EvalResult {
                accepted: jet_accepted,
                cost: jet_cost,
            })
        };
        simplicity::EvalOptions {
            jet_evaluator: Some(&jet_hook),
        }
    } else {
        simplicity::EvalOptions::default()
    };

    match program.evaluate(opts) {
        Ok(result) => Response {
            ok: true,
            accepted: Some(result.accepted),
            final_counter: Some(result.cost),
            ..Default::default()
        },
        Err(err) => simplicity_eval_error_response(err),
    }
}

// Conformance replay mirrors the current standard mempool default without importing node runtime.
const CONFORMANCE_DEFAULT_MEMPOOL_MIN_FEE_RATE: u64 = 1;
const CONFORMANCE_DEFAULT_MIN_DA_FEE_RATE: u64 = 1;

fn checked_add_policy(a: u64, b: u64) -> Option<u64> {
    a.checked_add(b)
}

fn checked_mul_policy(a: u64, b: u64) -> Option<u64> {
    a.checked_mul(b)
}

fn max_u64(a: u64, b: u64) -> u64 {
    if a > b {
        a
    } else {
        b
    }
}

fn dominant_fee_floor(relay_fee_floor: u64, da_required_fee: u64) -> &'static str {
    if da_required_fee > relay_fee_floor {
        "da"
    } else if relay_fee_floor > da_required_fee {
        "relay"
    } else if relay_fee_floor == 0 {
        "none"
    } else {
        "tie"
    }
}

fn policy_utxo_map(items: &[UtxoJson]) -> Result<HashMap<Outpoint, UtxoEntry>, String> {
    let mut utxos: HashMap<Outpoint, UtxoEntry> = HashMap::with_capacity(items.len());
    for u in items {
        let op_txid = parse_exact_hex32(&u.txid).map_err(|_| "bad utxo txid".to_string())?;
        let cov_data =
            hex::decode(&u.covenant_data).map_err(|_| "bad utxo covenant_data".to_string())?;
        utxos.insert(
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
    Ok(utxos)
}

fn fee_from_policy_utxos(
    tx: &rubin_consensus::tx::Tx,
    utxos: &HashMap<Outpoint, UtxoEntry>,
) -> Result<u64, String> {
    let mut total_in = 0u64;
    if tx.inputs.is_empty() {
        return Err("missing inputs".to_string());
    }
    for input in &tx.inputs {
        let entry = utxos
            .get(&Outpoint {
                txid: input.prev_txid,
                vout: input.prev_vout,
            })
            .ok_or_else(|| "missing utxo".to_string())?;
        total_in = checked_add_policy(total_in, entry.value)
            .ok_or_else(|| "sum_in overflow".to_string())?;
    }

    let mut total_out = 0u64;
    for output in &tx.outputs {
        total_out = checked_add_policy(total_out, output.value)
            .ok_or_else(|| "sum_out overflow".to_string())?;
    }
    if total_out > total_in {
        return Err("overspend".to_string());
    }
    Ok(total_in - total_out)
}

fn fee_below_rolling_floor_policy(fee: u64, weight: u64, floor: u64) -> bool {
    if weight == 0 {
        return true;
    }
    let floor = floor.max(CONFORMANCE_DEFAULT_MEMPOOL_MIN_FEE_RATE);
    (fee as u128) < (weight as u128) * (floor as u128)
}

fn da_fee_floor_policy_response(req: &Request) -> Response {
    let tx_bytes = match hex::decode(&req.tx_hex) {
        Ok(v) => v,
        Err(_) => {
            return Response {
                ok: false,
                err: Some("bad hex".to_string()),
                ..Default::default()
            }
        }
    };
    let (tx, _txid, _wtxid, consumed) = match parse_tx(&tx_bytes) {
        Ok(v) => v,
        Err(e) => {
            return Response {
                ok: false,
                err: Some(err_code(e.code)),
                ..Default::default()
            }
        }
    };
    if consumed != tx_bytes.len() {
        return Response {
            ok: false,
            err: Some(ErrorCode::TxErrParse.as_str().to_string()),
            ..Default::default()
        };
    }
    let (weight, da_bytes, _anchor_bytes) = match tx_weight_and_stats_public(&tx) {
        Ok(v) => v,
        Err(e) => {
            return Response {
                ok: false,
                err: Some(err_code(e.code)),
                ..Default::default()
            }
        }
    };

    let min_fee_rate = req
        .current_mempool_min_fee_rate
        .unwrap_or(CONFORMANCE_DEFAULT_MEMPOOL_MIN_FEE_RATE);
    let min_da_fee_rate = req
        .min_da_fee_rate
        .unwrap_or(CONFORMANCE_DEFAULT_MIN_DA_FEE_RATE);
    let relay_fee_floor = checked_mul_policy(weight, min_fee_rate);

    let mut resp = Response {
        ok: true,
        weight: Some(weight),
        da_bytes: Some(da_bytes),
        relay_fee_floor,
        da_fee_floor: Some(0),
        da_surcharge: Some(0),
        da_required_fee: Some(0),
        required_fee: relay_fee_floor,
        admit_class: Some("accepted".to_string()),
        dominant_floor: Some(
            match relay_fee_floor {
                Some(floor) => dominant_fee_floor(floor, 0),
                None => "relay",
            }
            .to_string(),
        ),
        ..Default::default()
    };

    if da_bytes > 0 {
        let da_fee_floor = match checked_mul_policy(da_bytes, min_da_fee_rate) {
            Some(v) => v,
            None => {
                resp.reject_reason = Some("DA_FEE_FLOOR_OVERFLOW".to_string());
                resp.admit_class = Some("rejected".to_string());
                resp.dominant_floor = Some("da".to_string());
                return resp;
            }
        };
        let da_surcharge = match checked_mul_policy(da_bytes, req.da_surcharge_per_byte) {
            Some(v) => v,
            None => {
                resp.reject_reason = Some("DA_SURCHARGE_OVERFLOW".to_string());
                resp.admit_class = Some("rejected".to_string());
                resp.dominant_floor = Some("da".to_string());
                resp.da_fee_floor = Some(da_fee_floor);
                return resp;
            }
        };
        let da_required_fee = match checked_add_policy(da_fee_floor, da_surcharge) {
            Some(v) => v,
            None => {
                resp.reject_reason = Some("DA_REQUIRED_FEE_OVERFLOW".to_string());
                resp.admit_class = Some("rejected".to_string());
                resp.dominant_floor = Some("da".to_string());
                resp.da_fee_floor = Some(da_fee_floor);
                resp.da_surcharge = Some(da_surcharge);
                return resp;
            }
        };
        resp.da_fee_floor = Some(da_fee_floor);
        resp.da_surcharge = Some(da_surcharge);
        resp.da_required_fee = Some(da_required_fee);
        if let Some(relay_fee_floor) = relay_fee_floor {
            resp.required_fee = Some(max_u64(relay_fee_floor, da_required_fee));
            resp.dominant_floor =
                Some(dominant_fee_floor(relay_fee_floor, da_required_fee).to_string());
        } else {
            resp.required_fee = Some(da_required_fee);
            resp.dominant_floor = Some("relay".to_string());
        }
    }

    if (da_bytes == 0 || resp.da_required_fee == Some(0)) && relay_fee_floor == Some(0) {
        resp.admit = Some(true);
        return resp;
    }

    let utxos = match policy_utxo_map(&req.utxos) {
        Ok(v) => v,
        Err(e) => {
            return Response {
                ok: false,
                err: Some(e),
                ..Default::default()
            }
        }
    };
    let fee = match fee_from_policy_utxos(&tx, &utxos) {
        Ok(v) => v,
        Err(e) => {
            return Response {
                ok: false,
                err: Some(e),
                ..Default::default()
            }
        }
    };
    resp.fee = Some(fee);

    if da_bytes > 0 {
        if let Some(da_required_fee) = resp.da_required_fee {
            if da_required_fee > 0 && fee < da_required_fee {
                resp.reject_reason = Some("DA_FEE_BELOW_STAGE_C_FLOOR".to_string());
                resp.admit_class = Some("rejected".to_string());
                resp.required_fee = Some(da_required_fee);
                resp.dominant_floor = Some("da".to_string());
                return resp;
            }
        }
    }

    if fee_below_rolling_floor_policy(fee, weight, min_fee_rate) {
        resp.admit_class = Some("unavailable".to_string());
        resp.dominant_floor = Some("relay".to_string());
        resp.reject_reason = Some("MEMPOOL_FEE_BELOW_ROLLING_MINIMUM".to_string());
        if let Some(relay_fee_floor) = relay_fee_floor {
            resp.required_fee = Some(relay_fee_floor);
        }
        return resp;
    }

    resp.admit = Some(true);
    resp
}

fn mempool_relay_metadata_policy_response(req: &Request) -> Response {
    let tx_bytes = match hex::decode(&req.tx_hex) {
        Ok(v) => v,
        Err(_) => {
            return Response {
                ok: false,
                err: Some("bad hex".to_string()),
                ..Default::default()
            }
        }
    };
    let chain_id = if req.chain_id.trim().is_empty() {
        devnet_genesis_chain_id()
    } else {
        match parse_exact_hex32(&req.chain_id) {
            Ok(v) => v,
            Err(_) => {
                return Response {
                    ok: false,
                    err: Some("bad chain_id".to_string()),
                    ..Default::default()
                }
            }
        }
    };

    let utxos = match policy_utxo_map(&req.utxos) {
        Ok(v) => v,
        Err(e) => {
            return Response {
                ok: false,
                err: Some(e),
                ..Default::default()
            }
        }
    };
    let mut state = ChainState::new();
    state.utxos = utxos;
    if req.height > 0 {
        state.has_tip = true;
        state.height = req.height - 1;
        state.tip_hash[0] = 0x11;
    }

    let default_cfg = TxPoolConfig::default();
    let cfg = TxPoolConfig {
        policy_da_surcharge_per_byte: req.da_surcharge_per_byte,
        policy_current_mempool_min_fee_rate: req
            .current_mempool_min_fee_rate
            .unwrap_or(default_cfg.policy_current_mempool_min_fee_rate),
        policy_min_da_fee_rate: req
            .min_da_fee_rate
            .unwrap_or(default_cfg.policy_min_da_fee_rate),
        ..default_cfg
    };
    let pool = TxPool::new_with_config(cfg);
    let before_len = pool.len();
    let parsed = parse_tx(&tx_bytes);
    let canonical_txid = match &parsed {
        Ok((_tx, txid, _wtxid, consumed)) if *consumed == tx_bytes.len() => Some(*txid),
        _ => None,
    };
    let before_contains = canonical_txid
        .as_ref()
        .map(|txid| pool.contains(txid))
        .unwrap_or(false);
    let relay_result = pool.relay_metadata_for_bytes(&tx_bytes, &state, None, chain_id);
    let after_len = pool.len();
    let after_contains = canonical_txid
        .as_ref()
        .map(|txid| pool.contains(txid))
        .unwrap_or(false);
    let mutated = before_len != after_len || before_contains != after_contains;

    let mut resp = da_fee_floor_policy_response(req);
    resp.policy_entrypoint = Some("mempool_relay_metadata".to_string());
    resp.mutation_checked = Some(true);
    resp.mutated = Some(mutated);
    resp.pool_len_before = Some(before_len);
    resp.pool_len_after = Some(after_len);
    resp.duplicate_conflict_capacity_checked = Some(false);
    let (tx, _txid, _wtxid, consumed) = match parsed {
        Ok(v) => v,
        Err(_) => {
            resp.ok = false;
            resp.admit = None;
            resp.admit_class = None;
            resp.dominant_floor = None;
            resp.reject_reason = None;
            resp.err = Some(match relay_result {
                Ok(_) => "relay metadata accepted malformed tx".to_string(),
                Err(err)
                    if matches!(err.kind, TxPoolAdmitErrorKind::Rejected)
                        && relay_metadata_parse_reject(&err.message) =>
                {
                    ErrorCode::TxErrParse.as_str().to_string()
                }
                Err(err) => format!(
                    "relay metadata parse mismatch: kind={:?} message={}",
                    err.kind, err.message
                ),
            });
            return resp;
        }
    };
    if consumed != tx_bytes.len() {
        resp.ok = false;
        resp.admit = None;
        resp.admit_class = None;
        resp.dominant_floor = None;
        resp.reject_reason = None;
        resp.err = Some(match relay_result {
            Ok(_) => "relay metadata accepted non-canonical tx".to_string(),
            Err(err)
                if matches!(err.kind, TxPoolAdmitErrorKind::Rejected)
                    && relay_metadata_parse_reject(&err.message) =>
            {
                ErrorCode::TxErrParse.as_str().to_string()
            }
            Err(err) => format!(
                "relay metadata parse mismatch: kind={:?} message={}",
                err.kind, err.message
            ),
        });
        return resp;
    }
    if let Ok((weight, da_bytes, _anchor_bytes)) = tx_weight_and_stats_public(&tx) {
        resp.weight = Some(weight);
        resp.da_bytes = Some(da_bytes);
    }
    resp.wire_bytes = Some(tx_bytes.len());

    match relay_result {
        Ok(meta) => {
            resp.ok = true;
            resp.admit = Some(true);
            resp.admit_class = Some("accepted".to_string());
            resp.reject_reason = None;
            resp.fee = Some(meta.fee);
            resp.wire_bytes = Some(meta.size);
        }
        Err(err) => {
            resp.ok = true;
            resp.admit = Some(false);
            match err.kind {
                TxPoolAdmitErrorKind::Unavailable => {
                    resp.admit_class = Some("unavailable".to_string());
                    if err.message.contains("mempool fee below rolling minimum") {
                        resp.reject_reason = Some("MEMPOOL_FEE_BELOW_ROLLING_MINIMUM".to_string());
                        resp.dominant_floor = Some("relay".to_string());
                    }
                }
                TxPoolAdmitErrorKind::Rejected => {
                    resp.admit_class = Some("rejected".to_string());
                    if err.message.contains("DA fee below Stage C floor") {
                        resp.reject_reason = Some("DA_FEE_BELOW_STAGE_C_FLOOR".to_string());
                        resp.dominant_floor = Some("da".to_string());
                    } else if err.message.contains(ErrorCode::TxErrParse.as_str())
                        || err.message.contains("non-canonical tx bytes")
                    {
                        resp.ok = false;
                        resp.err = Some(ErrorCode::TxErrParse.as_str().to_string());
                        resp.admit = None;
                        resp.admit_class = None;
                        resp.dominant_floor = None;
                        resp.reject_reason = None;
                    } else {
                        resp.err = Some(err.message);
                    }
                }
                TxPoolAdmitErrorKind::Conflict => {
                    resp.admit_class = Some("conflict".to_string());
                    resp.err = Some(err.message);
                }
            }
        }
    }
    resp
}

fn relay_metadata_parse_reject(message: &str) -> bool {
    message.contains(ErrorCode::TxErrParse.as_str())
        || message.contains("non-canonical tx bytes")
        || message.contains("trailing bytes after canonical tx")
}

fn reject_core_ext_profiles_from_json(
    profiles: &RetiredCoreExtProfiles,
    expected_set_anchor_hex: &str,
) -> Result<(), String> {
    if !expected_set_anchor_hex.trim().is_empty() {
        return Err("core_ext_profile_set_anchor_hex unsupported by Rust runtime".to_string());
    }
    if profiles.has_items {
        return Err("core_ext_profiles unsupported by Rust runtime".to_string());
    }
    Ok(())
}

fn build_core_ext_suite_context(
    req: &Request,
) -> Result<(Option<DescriptorRotationProvider>, Option<SuiteRegistry>), String> {
    let registry = build_suite_registry_from_json(&req.suite_registry)?;

    let rotation = match &req.rotation_descriptor {
        Some(rd) => {
            let registry_ref = registry
                .as_ref()
                .ok_or_else(|| "bad suite_registry".to_string())?;
            let desc = CryptoRotationDescriptor {
                name: rd.name.clone(),
                old_suite_id: rd.old_suite_id,
                new_suite_id: rd.new_suite_id,
                create_height: rd.create_height,
                spend_height: rd.spend_height,
                sunset_height: rd.sunset_height,
            };
            validate_rotation_descriptor_for_network(&req.network, &desc, registry_ref)
                .map_err(|_| ROTATION_DESCRIPTOR_NOT_ACTIVATED_ERR.to_string())?;
            Some(DescriptorRotationProvider { descriptor: desc })
        }
        None => None,
    };

    Ok((rotation, registry))
}

fn op_featurebits_state(req: &Request) -> Response {
    let d = FeatureBitDeployment {
        name: req.name.clone(),
        bit: req.bit,
        start_height: req.start_height,
        timeout_height: req.timeout_height,
    };

    fn normalize_featurebits_error(err: String) -> String {
        if err.starts_with("featurebits: bit out of range:") {
            return "BLOCK_ERR_PARSE".to_string();
        }
        err
    }

    match featurebit_state_at_height_from_window_counts(&d, req.height, &req.window_signal_counts) {
        Ok(ev) => {
            let est = if ev.state == FeatureBitState::LockedIn {
                Some(ev.boundary_height + ev.signal_window)
            } else {
                None
            };

            let (activation_height, consensus_active) =
                if let Some(activation_height) = req.activation_height {
                    let fd = FlagDayDeployment {
                        name: req.name.clone(),
                        activation_height,
                        bit: Some(req.bit),
                    };
                    match flagday_active_at_height(&fd, req.height) {
                        Ok(active) => (Some(activation_height), Some(active)),
                        Err(e) => {
                            return Response {
                                ok: false,
                                err: Some(e),
                                ..Default::default()
                            }
                        }
                    }
                } else {
                    (None, None)
                };

            Response {
                ok: true,
                state: Some(ev.state.as_str().to_string()),
                boundary_height: Some(ev.boundary_height),
                prev_window_signal_count: Some(ev.prev_window_signal_count),
                signal_window: Some(ev.signal_window),
                signal_threshold: Some(ev.signal_threshold),
                estimated_activation_height: est,
                activation_height,
                consensus_active,
                ..Default::default()
            }
        }
        Err(e) => Response {
            ok: false,
            err: Some(normalize_featurebits_error(e)),
            ..Default::default()
        },
    }
}

fn op_rotation_descriptor_check(req: &Request) -> Response {
    let registry = match build_suite_registry_from_json(&req.suite_registry) {
        Ok(Some(registry)) => registry,
        _ => {
            return Response {
                ok: false,
                err: Some("bad suite_registry".to_string()),
                ..Default::default()
            };
        }
    };
    if !req.rotation_descriptors.is_empty() {
        let ds: Vec<CryptoRotationDescriptor> = req
            .rotation_descriptors
            .iter()
            .map(|rd| CryptoRotationDescriptor {
                name: rd.name.clone(),
                old_suite_id: rd.old_suite_id,
                new_suite_id: rd.new_suite_id,
                create_height: rd.create_height,
                spend_height: rd.spend_height,
                sunset_height: rd.sunset_height,
            })
            .collect();
        if let Err(err) = validate_rotation_set_for_network(&req.network, &ds, &registry) {
            return rotation_descriptor_validation_response(err);
        }
        return Response {
            ok: true,
            ..Default::default()
        };
    }
    let rd = match &req.rotation_descriptor {
        Some(v) => v,
        None => {
            return Response {
                ok: false,
                err: Some("bad rotation_descriptor".to_string()),
                ..Default::default()
            };
        }
    };
    let desc = CryptoRotationDescriptor {
        name: rd.name.clone(),
        old_suite_id: rd.old_suite_id,
        new_suite_id: rd.new_suite_id,
        create_height: rd.create_height,
        spend_height: rd.spend_height,
        sunset_height: rd.sunset_height,
    };
    if let Err(err) = validate_rotation_descriptor_for_network(&req.network, &desc, &registry) {
        return rotation_descriptor_validation_response(err);
    }
    Response {
        ok: true,
        ..Default::default()
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
        "simplicity_exec_vector" => {
            let resp = run_simplicity_exec_vector(&req);
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "parse_tx" => {
            let tx_bytes = match hex::decode(&req.tx_hex) {
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

            match work_from_target(target) {
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
                    match work_from_target(t) {
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
            let tx_bytes = match hex::decode(&req.tx_hex) {
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

            let chain_id_bytes = match hex::decode(&req.chain_id) {
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
            let tx_bytes = match hex::decode(&req.tx_hex) {
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
            if req.rotation_descriptor.is_some() && req.suite_registry.is_empty() {
                let resp = Response {
                    ok: false,
                    err: Some("bad suite_registry".to_string()),
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let use_registry = req.rotation_descriptor.is_some() && !req.suite_registry.is_empty();
            let r = if use_registry {
                let rd = req.rotation_descriptor.as_ref().expect("checked");
                let registry = match build_suite_registry_from_json(&req.suite_registry) {
                    Ok(Some(registry)) => registry,
                    _ => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad suite_registry".to_string()),
                            ..Default::default()
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                let desc = CryptoRotationDescriptor {
                    name: rd.name.clone(),
                    old_suite_id: rd.old_suite_id,
                    new_suite_id: rd.new_suite_id,
                    create_height: rd.create_height,
                    spend_height: rd.spend_height,
                    sunset_height: rd.sunset_height,
                };
                if validate_rotation_descriptor_for_network(&req.network, &desc, &registry).is_err()
                {
                    let resp = Response {
                        ok: false,
                        err: Some(ROTATION_DESCRIPTOR_NOT_ACTIVATED_ERR.to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let rp = DescriptorRotationProvider { descriptor: desc };
                tx_weight_and_stats_at_height(&tx, req.height, Some(&rp), Some(&registry))
            } else {
                tx_weight_and_stats_public(&tx)
            };
            match r {
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
        "da_fee_floor_policy" => {
            let resp = da_fee_floor_policy_response(&req);
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "mempool_relay_metadata_policy" => {
            let resp = mempool_relay_metadata_policy_response(&req);
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "rotation_create_suite_check" => {
            let rd = match &req.rotation_descriptor {
                Some(v) => v,
                None => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad rotation_descriptor".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let registry = match build_suite_registry_from_json(&req.suite_registry) {
                Ok(Some(registry)) => registry,
                _ => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad suite_registry".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let desc = CryptoRotationDescriptor {
                name: rd.name.clone(),
                old_suite_id: rd.old_suite_id,
                new_suite_id: rd.new_suite_id,
                create_height: rd.create_height,
                spend_height: rd.spend_height,
                sunset_height: rd.sunset_height,
            };
            if validate_rotation_descriptor_for_network(&req.network, &desc, &registry).is_err() {
                let resp = Response {
                    ok: false,
                    err: Some(ROTATION_DESCRIPTOR_NOT_ACTIVATED_ERR.to_string()),
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let rp = DescriptorRotationProvider { descriptor: desc };
            let suite_id = req.suite_id.unwrap_or(0);
            if !rp.native_create_suites(req.height).contains(suite_id) {
                let resp = Response {
                    ok: false,
                    err: Some("TX_ERR_SIG_ALG_INVALID".to_string()),
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
        "rotation_native_create_suites" => {
            let rd = match &req.rotation_descriptor {
                Some(v) => v,
                None => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad rotation_descriptor".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let registry = match build_suite_registry_from_json(&req.suite_registry) {
                Ok(Some(registry)) => registry,
                _ => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad suite_registry".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let desc = CryptoRotationDescriptor {
                name: rd.name.clone(),
                old_suite_id: rd.old_suite_id,
                new_suite_id: rd.new_suite_id,
                create_height: rd.create_height,
                spend_height: rd.spend_height,
                sunset_height: rd.sunset_height,
            };
            if validate_rotation_descriptor_for_network(&req.network, &desc, &registry).is_err() {
                let resp = Response {
                    ok: false,
                    err: Some(ROTATION_DESCRIPTOR_NOT_ACTIVATED_ERR.to_string()),
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let rp = DescriptorRotationProvider { descriptor: desc };
            let ids = rp.native_create_suites(req.height).suite_ids();
            let resp = Response {
                ok: true,
                suite_ids: Some(ids),
                ..Default::default()
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "rotation_spend_suite_check" => {
            let rd = match &req.rotation_descriptor {
                Some(v) => v,
                None => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad rotation_descriptor".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let registry = match build_suite_registry_from_json(&req.suite_registry) {
                Ok(Some(registry)) => registry,
                _ => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad suite_registry".to_string()),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let desc = CryptoRotationDescriptor {
                name: rd.name.clone(),
                old_suite_id: rd.old_suite_id,
                new_suite_id: rd.new_suite_id,
                create_height: rd.create_height,
                spend_height: rd.spend_height,
                sunset_height: rd.sunset_height,
            };
            if validate_rotation_descriptor_for_network(&req.network, &desc, &registry).is_err() {
                let resp = Response {
                    ok: false,
                    err: Some(ROTATION_DESCRIPTOR_NOT_ACTIVATED_ERR.to_string()),
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let rp = DescriptorRotationProvider { descriptor: desc };
            let suite_id = req.suite_id.unwrap_or(0);
            if !rp.native_spend_suites(req.height).contains(suite_id) {
                let resp = Response {
                    ok: false,
                    err: Some("TX_ERR_SIG_ALG_INVALID".to_string()),
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
        "rotation_descriptor_check" => {
            let resp = op_rotation_descriptor_check(&req);
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "block_hash" => {
            let header_bytes = match hex::decode(&req.header_hex) {
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
            let header_bytes = match hex::decode(&req.header_hex) {
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
            let target_bytes = match hex::decode(&req.target_hex) {
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
            let old_bytes = match hex::decode(&req.target_old) {
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
            let block_bytes = match hex::decode(&req.block_hex) {
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
                let b = match hex::decode(&req.expected_prev_hash) {
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
                let b = match hex::decode(&req.expected_target) {
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
            let block_bytes = match hex::decode(&req.block_hex) {
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
                let b = match hex::decode(&req.expected_prev_hash) {
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
                let b = match hex::decode(&req.expected_target) {
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
                u128::from(req.already_generated),
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
            let block_bytes = match hex::decode(&req.block_hex) {
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
                let b = match hex::decode(&req.expected_prev_hash) {
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
                let b = match hex::decode(&req.expected_target) {
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
                already_generated: u128::from(req.already_generated),
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

            if let Err(e) = reject_core_ext_profiles_from_json(
                &req.core_ext_profiles,
                &req.core_ext_profile_set_anchor_hex,
            ) {
                let resp = Response {
                    ok: false,
                    err: Some(e),
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let (rotation, registry) = match build_core_ext_suite_context(&req) {
                Ok(v) => v,
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(e),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            match connect_block_basic_in_memory_at_height_and_core_ext_deployments_with_suite_context(
                &block_bytes,
                expected_prev,
                expected_target,
                req.height,
                prev_timestamps,
                &mut state,
                chain_id,
                rotation.as_ref().map(|rp| rp as &dyn RotationProvider),
                registry.as_ref(),
            ) {
                Ok(summary) => {
                    let already_generated = match u64::try_from(summary.already_generated) {
                        Ok(v) => v,
                        Err(_) => {
                            let resp = Response {
                                ok: false,
                                err: Some("already_generated_overflow".to_string()),
                                ..Default::default()
                            };
                            let _ = serde_json::to_writer(std::io::stdout(), &resp);
                            return;
                        }
                    };
                    let already_generated_n1 = match u64::try_from(summary.already_generated_n1) {
                        Ok(v) => v,
                        Err(_) => {
                            let resp = Response {
                                ok: false,
                                err: Some("already_generated_overflow".to_string()),
                                ..Default::default()
                            };
                            let _ = serde_json::to_writer(std::io::stdout(), &resp);
                            return;
                        }
                    };
                    let resp = Response {
                        ok: true,
                        sum_fees: Some(summary.sum_fees),
                        utxo_count: Some(summary.utxo_count),
                        already_generated: Some(already_generated),
                        already_generated_n1: Some(already_generated_n1),
                        digest: Some(hex::encode(summary.post_state_digest)),
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
            let tx_bytes = match hex::decode(&req.tx_hex) {
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

            match validate_tx_covenants_genesis(&tx, req.height, None) {
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
            let tx_bytes = match hex::decode(&req.tx_hex) {
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
            if let Err(e) = reject_core_ext_profiles_from_json(
                &req.core_ext_profiles,
                &req.core_ext_profile_set_anchor_hex,
            ) {
                let resp = Response {
                    ok: false,
                    err: Some(e),
                    ..Default::default()
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let (rotation, registry) = match build_core_ext_suite_context(&req) {
                Ok(v) => v,
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(e),
                        ..Default::default()
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let apply_result =
                apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
                    &tx,
                    txid,
                    &utxo_set,
                    req.height,
                    req.block_timestamp,
                    block_mtp,
                    chain_id,
                    rotation.as_ref().map(|rp| rp as &dyn RotationProvider),
                    registry.as_ref(),
                );

            match apply_result {
                Ok((_next_utxos, summary)) => {
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
            let wtxid_bytes = match hex::decode(&req.wtxid) {
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
            let cov_data = match hex::decode(&req.covenant_data_hex) {
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
            let cov_data = match hex::decode(&req.covenant_data_hex) {
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
            let selector_payload_len_ok = req.selector_payload_len_ok.unwrap_or(true);
            let key_binding_ok = req.key_binding_ok.unwrap_or(true);
            let preimage_ok = req.preimage_ok.unwrap_or(true);
            let verify_ok = req.verify_ok.unwrap_or(true);

            let mut verify_called = false;
            let mut err: Option<String> = None;

            if !structural_ok {
                err = Some(err_code(ErrorCode::TxErrParse));
            } else if path == "refund" && !selector_payload_len_ok {
                let resp = htlc_refund_ordering_policy_response(
                    &req,
                    suite_id,
                    key_binding_ok,
                    selector_payload_len_ok,
                );
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            } else if path == "refund" && !locktime_ok {
                err = Some(err_code(ErrorCode::TxErrTimelockNotMet));
            } else if suite_id != 0x01 {
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
                    "owner_destination".to_string(),
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
                    "owner_destination" => (
                        !req.whitelist.contains(&owner_lock_id),
                        err_code(ErrorCode::TxErrVaultOwnerDestinationForbidden),
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
    use std::fs;

    fn cli_test_rotation_suites() -> Vec<SuiteParamsJson> {
        vec![
            SuiteParamsJson {
                suite_id: 1,
                pubkey_len: rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
                sig_len: rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
                verify_cost: rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87".to_string(),
            },
            SuiteParamsJson {
                suite_id: 2,
                pubkey_len: rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
                sig_len: rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
                verify_cost: rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87".to_string(),
            },
            SuiteParamsJson {
                suite_id: 3,
                pubkey_len: rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
                sig_len: rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
                verify_cost: rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87".to_string(),
            },
        ]
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CliSharedExecCorpus {
        contract_version: u64,
        fixture_kind: String,
        description: String,
        cases: Vec<CliSharedExecCase>,
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CliSharedExecCase {
        id: String,
        #[serde(default)]
        program_hex: String,
        #[serde(default)]
        witness_hex: String,
        #[serde(default)]
        eval_steps: Option<u64>,
        #[serde(default)]
        frame_bit_widths: Vec<u64>,
        #[serde(default)]
        jet_accepted: Option<bool>,
        #[serde(default)]
        jet_cost: Option<u64>,
        expected_accepted: bool,
        #[serde(default)]
        expected_error: String,
        expected_final_counter: u64,
    }

    fn simplicity_exec_request(case: &CliSharedExecCase) -> Request {
        Request {
            program_hex: case.program_hex.clone(),
            witness_hex: case.witness_hex.clone(),
            eval_steps: case.eval_steps,
            frame_bit_widths: case.frame_bit_widths.clone(),
            jet_accepted: case.jet_accepted,
            jet_cost: case.jet_cost,
            ..Default::default()
        }
    }

    #[test]
    fn simplicity_exec_vector_covers_error_surface() {
        let missing_program = run_simplicity_exec_vector(&Request {
            ..Default::default()
        });
        assert_eq!(missing_program.err.as_deref(), Some("bad program_hex"));

        let missing_eval_steps = run_simplicity_exec_vector(&Request {
            frame_bit_widths: vec![1],
            ..Default::default()
        });
        assert!(!missing_eval_steps.ok);
        assert_eq!(missing_eval_steps.err.as_deref(), Some("bad eval_steps"));

        let missing_jet_cost = run_simplicity_exec_vector(&Request {
            program_hex: "60".to_string(),
            ..Default::default()
        });
        assert!(!missing_jet_cost.ok);
        assert_eq!(missing_jet_cost.err.as_deref(), Some("bad jet_cost"));

        let oversized = run_simplicity_exec_vector(&Request {
            program_hex: "00".repeat(simplicity::MAX_PROGRAM_BYTES + 1),
            ..Default::default()
        });
        assert!(!oversized.ok);
        assert_eq!(
            oversized.err.as_deref(),
            Some(simplicity::ErrorCode::ProgramTooLarge.as_str())
        );
    }

    #[test]
    fn simplicity_exec_vector_replays_shared_exec_corpus() {
        let corpus_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../conformance/fixtures/protocol/simplicity_exec_corpus_v1.json");
        let raw = fs::read_to_string(corpus_path).expect("read shared exec corpus");
        let corpus: CliSharedExecCorpus =
            serde_json::from_str(&raw).expect("parse shared exec corpus");
        assert_eq!(corpus.contract_version, 1);
        assert_eq!(corpus.fixture_kind, "simplicity_exec_corpus_v1");
        assert!(!corpus.description.is_empty());

        for case in &corpus.cases {
            let id = case.id.as_str();
            let resp = run_simplicity_exec_vector(&simplicity_exec_request(case));
            if case.expected_error.is_empty() {
                assert!(resp.ok, "{id}: err={:?}", resp.err);
                assert_eq!(resp.err, None, "{id}");
            } else {
                assert!(!resp.ok, "{id}");
                assert_eq!(
                    resp.err.as_deref(),
                    Some(case.expected_error.as_str()),
                    "{id}"
                );
            }
            assert_eq!(resp.accepted, Some(case.expected_accepted), "{id}");
            assert_eq!(
                resp.final_counter,
                Some(case.expected_final_counter),
                "{id}"
            );
        }
    }

    #[test]
    fn rotation_descriptor_check_mainnet_rejects_multi_descriptor_batch() {
        let resp = op_rotation_descriptor_check(&Request {
            op: "rotation_descriptor_check".to_string(),
            network: "mainnet".to_string(),
            suite_registry: cli_test_rotation_suites(),
            rotation_descriptors: vec![
                RotationDescriptorJson {
                    name: "a".to_string(),
                    old_suite_id: 1,
                    new_suite_id: 2,
                    create_height: 10,
                    spend_height: 20,
                    sunset_height: 100,
                },
                RotationDescriptorJson {
                    name: "b".to_string(),
                    old_suite_id: 2,
                    new_suite_id: 3,
                    create_height: 100,
                    spend_height: 110,
                    sunset_height: 200,
                },
            ],
            ..Default::default()
        });
        assert!(!resp.ok);
        assert_eq!(
            resp.err.as_deref(),
            Some(ROTATION_DESCRIPTOR_NOT_ACTIVATED_ERR)
        );
        assert_eq!(
            resp.diagnostics
                .as_ref()
                .and_then(|value| value.get("rotation_validation_err"))
                .and_then(|value| value.as_str()),
            Some("rotation-too-many-descriptors")
        );
    }

    #[test]
    fn rotation_descriptor_check_devnet_preserves_multi_descriptor_batch() {
        let resp = op_rotation_descriptor_check(&Request {
            op: "rotation_descriptor_check".to_string(),
            network: "devnet".to_string(),
            suite_registry: cli_test_rotation_suites(),
            rotation_descriptors: vec![
                RotationDescriptorJson {
                    name: "a".to_string(),
                    old_suite_id: 1,
                    new_suite_id: 2,
                    create_height: 10,
                    spend_height: 20,
                    sunset_height: 100,
                },
                RotationDescriptorJson {
                    name: "b".to_string(),
                    old_suite_id: 2,
                    new_suite_id: 3,
                    create_height: 100,
                    spend_height: 110,
                    sunset_height: 200,
                },
            ],
            ..Default::default()
        });
        assert!(resp.ok);
    }

    #[test]
    fn sanitize_rotation_validation_err_uses_shared_stems() {
        assert_eq!(
            sanitize_rotation_validation_err(&format!(
                "{ROTATION_V1_PRODUCTION_AT_MOST_ONE_DESCRIPTOR_ERR_STEM}, got 2"
            )),
            ROTATION_TOO_MANY_DESCRIPTORS_ERR
        );
        assert_eq!(
            sanitize_rotation_validation_err(
                r#"rotation[0] "bad": rotation: old suite (0x01) must differ from new suite"#,
            ),
            ROTATION_EQUAL_SUITE_IDS_ERR
        );
        assert_eq!(
            sanitize_rotation_validation_err(
                r#"rotation[0] "bad": rotation: new suite 0x03 not registered"#,
            ),
            ROTATION_UNREGISTERED_SUITE_ERR
        );
        assert_eq!(
            sanitize_rotation_validation_err(r#"rotation[0] "bad": rotation: name required"#),
            ROTATION_INVALID_DESCRIPTOR_ERR
        );
        assert_eq!(
            sanitize_rotation_validation_err(ROTATION_V1_PRODUCTION_FINITE_H4_REQUIRED_ERR_STEM),
            ROTATION_FINITE_H4_REQUIRED_ERR
        );
        assert_eq!(
            sanitize_rotation_validation_err(
                r#"rotation[0] "bad": rotation: create_height (20) must be < spend_height (10)"#,
            ),
            ROTATION_INVALID_HEIGHT_ORDER_ERR
        );
        assert_eq!(
            sanitize_rotation_validation_err(
                r#"rotation[0] "bad": rotation: sunset_height (20) must be > spend_height (20)"#,
            ),
            ROTATION_INVALID_HEIGHT_ORDER_ERR
        );
    }

    #[test]
    fn featurebits_state_ok_locked_in() {
        let req = Request {
            op: "featurebits_state".to_string(),
            name: "X".to_string(),
            bit: 0,
            start_height: 0,
            timeout_height: rubin_consensus::constants::SIGNAL_WINDOW * 10,
            height: rubin_consensus::constants::SIGNAL_WINDOW,
            activation_height: Some(rubin_consensus::constants::SIGNAL_WINDOW * 2),
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
        assert_eq!(
            resp.activation_height,
            Some(rubin_consensus::constants::SIGNAL_WINDOW * 2)
        );
        assert_eq!(resp.consensus_active, Some(false));
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
        assert_eq!(resp.err.as_deref(), Some("BLOCK_ERR_PARSE"));
    }

    #[test]
    fn core_ext_profiles_empty_input_is_retired_noop() {
        reject_core_ext_profiles_from_json(&RetiredCoreExtProfiles::default(), "")
            .expect("empty retired profile input");
    }

    #[test]
    fn core_ext_profiles_non_empty_input_is_unsupported() {
        let err =
            reject_core_ext_profiles_from_json(&RetiredCoreExtProfiles { has_items: true }, "")
                .unwrap_err();
        assert_eq!(err, "core_ext_profiles unsupported by Rust runtime");
    }

    #[test]
    fn core_ext_profiles_legacy_json_deserializes_to_unsupported_error() {
        let req: Request = serde_json::from_str(
            r#"{"op":"utxo_apply_basic","core_ext_profiles":[{"ext_id":9,"tx_context_enabled":2}]}"#,
        )
        .expect("legacy profile envelope should deserialize before fail-closed rejection");
        let err = reject_core_ext_profiles_from_json(&req.core_ext_profiles, "").unwrap_err();
        assert_eq!(err, "core_ext_profiles unsupported by Rust runtime");
    }

    #[test]
    fn core_ext_profile_set_anchor_input_is_unsupported() {
        let err = reject_core_ext_profiles_from_json(&RetiredCoreExtProfiles::default(), "00")
            .unwrap_err();
        assert_eq!(
            err,
            "core_ext_profile_set_anchor_hex unsupported by Rust runtime"
        );
    }

    #[test]
    fn suite_registry_rejects_unknown_alg_name() {
        let err = build_suite_registry_from_json(&[SuiteParamsJson {
            suite_id: 3,
            pubkey_len: rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
            sig_len: rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            verify_cost: rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
            alg_name: "SLH-DSA".to_string(),
        }])
        .unwrap_err();
        assert_eq!(err, "bad suite_registry");
    }

    #[test]
    fn suite_registry_rejects_empty_alg_name() {
        let err = build_suite_registry_from_json(&[SuiteParamsJson {
            suite_id: 3,
            pubkey_len: rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
            sig_len: rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            verify_cost: rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
            alg_name: "".to_string(),
        }])
        .unwrap_err();
        assert_eq!(err, "bad suite_registry");
    }

    #[test]
    fn suite_registry_rejects_duplicate_suite_ids() {
        let err = build_suite_registry_from_json(&[
            SuiteParamsJson {
                suite_id: 3,
                pubkey_len: rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
                sig_len: rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
                verify_cost: rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87".to_string(),
            },
            SuiteParamsJson {
                suite_id: 3,
                pubkey_len: rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
                sig_len: rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
                verify_cost: rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87".to_string(),
            },
        ])
        .unwrap_err();
        assert_eq!(err, "bad suite_registry");
    }

    #[test]
    fn suite_registry_rejects_oversized_registry() {
        let items = (0..(MAX_EXPLICIT_SUITE_REGISTRY_ITEMS + 1))
            .map(|idx| SuiteParamsJson {
                suite_id: (idx + 1) as u8,
                pubkey_len: rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
                sig_len: rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
                verify_cost: rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87".to_string(),
            })
            .collect::<Vec<_>>();
        let err = build_suite_registry_from_json(&items).unwrap_err();
        assert_eq!(err, "bad suite_registry");
    }

    #[test]
    fn suite_registry_rejects_oversized_pubkey_len() {
        let err = build_suite_registry_from_json(&[SuiteParamsJson {
            suite_id: 3,
            pubkey_len: MAX_WITNESS_BYTES_PER_TX as u64 + 1,
            sig_len: rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            verify_cost: rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
            alg_name: "ML-DSA-87".to_string(),
        }])
        .unwrap_err();
        assert_eq!(err, "bad suite_registry");
    }

    #[test]
    fn suite_registry_rejects_zero_verify_cost() {
        let err = build_suite_registry_from_json(&[SuiteParamsJson {
            suite_id: 3,
            pubkey_len: rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
            sig_len: rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            verify_cost: 0,
            alg_name: "ML-DSA-87".to_string(),
        }])
        .unwrap_err();
        assert_eq!(err, "bad suite_registry");
    }

    #[test]
    fn suite_registry_accepts_synthetic_params_for_harness_vectors() {
        let registry = build_suite_registry_from_json(&[SuiteParamsJson {
            suite_id: 3,
            pubkey_len: 64,
            sig_len: 0,
            verify_cost: 9,
            alg_name: "ML-DSA-87".to_string(),
        }])
        .expect("registry");
        let registry = registry.expect("suite registry");
        let params = registry.lookup(3).expect("suite 3 present");
        assert_eq!(params.pubkey_len, 64);
        assert_eq!(params.sig_len, 0);
        assert_eq!(params.verify_cost, 9);
    }

    #[test]
    fn suite_registry_accepts_case_insensitive_alg_name() {
        let registry = build_suite_registry_from_json(&[SuiteParamsJson {
            suite_id: 3,
            pubkey_len: rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
            sig_len: rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            verify_cost: rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
            alg_name: "mL-dSa-87".to_string(),
        }])
        .expect("registry")
        .expect("suite registry");
        let params = registry.lookup(3).expect("suite 3 present");
        assert_eq!(params.alg_name, "ML-DSA-87");
    }

    #[test]
    fn rotation_descriptor_check_accepts_legacy_openssl_alg_alias() {
        let payload = format!(
            r#"{{
                "op":"rotation_descriptor_check",
                "network":"devnet",
                "suite_registry":[
                    {{"suite_id":1,"pubkey_len":{},"sig_len":{},"verify_cost":{},"openssl_alg":"ML-DSA-87"}},
                    {{"suite_id":2,"pubkey_len":{},"sig_len":{},"verify_cost":{},"openssl_alg":"ML-DSA-87"}}
                ],
                "rotation_descriptor":{{"name":"r1","old_suite_id":1,"new_suite_id":2,"create_height":10,"spend_height":20,"sunset_height":100}}
            }}"#,
            rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
            rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
            rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
            rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
        );
        let req: Request = serde_json::from_str(&payload).expect("request");
        assert_eq!(req.suite_registry[0].alg_name, "ML-DSA-87");
        assert_eq!(req.suite_registry[1].alg_name, "ML-DSA-87");
        let resp = op_rotation_descriptor_check(&req);
        assert!(resp.ok, "unexpected err: {:?}", resp.err);
    }

    #[test]
    fn rotation_descriptor_check_accepts_dual_alg_name_and_openssl_alg_keys() {
        let payload = format!(
            r#"{{
                "op":"rotation_descriptor_check",
                "network":"devnet",
                "suite_registry":[
                    {{"suite_id":1,"pubkey_len":{},"sig_len":{},"verify_cost":{},"alg_name":"ML-DSA-87","openssl_alg":"ML-DSA-87"}},
                    {{"suite_id":2,"pubkey_len":{},"sig_len":{},"verify_cost":{},"alg_name":"ML-DSA-87","openssl_alg":"ML-DSA-87"}}
                ],
                "rotation_descriptor":{{"name":"r1","old_suite_id":1,"new_suite_id":2,"create_height":10,"spend_height":20,"sunset_height":100}}
            }}"#,
            rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
            rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
            rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
            rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
        );
        let req: Request = serde_json::from_str(&payload).expect("request");
        assert_eq!(req.suite_registry[0].alg_name, "ML-DSA-87");
        assert_eq!(req.suite_registry[1].alg_name, "ML-DSA-87");
        let resp = op_rotation_descriptor_check(&req);
        assert!(resp.ok, "unexpected err: {:?}", resp.err);
    }

    #[test]
    fn rotation_descriptor_check_rejects_empty_alg_name_even_with_legacy_alias() {
        let payload = format!(
            r#"{{
                "op":"rotation_descriptor_check",
                "network":"devnet",
                "suite_registry":[
                    {{"suite_id":1,"pubkey_len":{},"sig_len":{},"verify_cost":{},"alg_name":"","openssl_alg":"ML-DSA-87"}},
                    {{"suite_id":2,"pubkey_len":{},"sig_len":{},"verify_cost":{},"alg_name":"ML-DSA-87","openssl_alg":"ML-DSA-87"}}
                ],
                "rotation_descriptor":{{"name":"r1","old_suite_id":1,"new_suite_id":2,"create_height":10,"spend_height":20,"sunset_height":100}}
            }}"#,
            rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
            rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
            rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
            rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
        );
        let req: Request = serde_json::from_str(&payload).expect("request");
        let resp = op_rotation_descriptor_check(&req);
        assert!(!resp.ok);
        assert_eq!(resp.err.as_deref(), Some("bad suite_registry"));
    }

    #[test]
    fn rotation_descriptor_check_rejects_missing_suite_registry_pubkey_len() {
        let payload = format!(
            r#"{{
                "op":"rotation_descriptor_check",
                "network":"devnet",
                "suite_registry":[
                    {{"suite_id":1,"sig_len":{},"verify_cost":{},"alg_name":"ML-DSA-87"}},
                    {{"suite_id":2,"pubkey_len":{},"sig_len":{},"verify_cost":{},"alg_name":"ML-DSA-87"}}
                ],
                "rotation_descriptor":{{"name":"r1","old_suite_id":1,"new_suite_id":2,"create_height":10,"spend_height":20,"sunset_height":100}}
            }}"#,
            rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
            rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
            rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
        );
        let err = match serde_json::from_str::<Request>(&payload) {
            Ok(_) => panic!("expected missing pubkey_len to fail closed during deserialize"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("bad suite_registry"));
    }

    #[test]
    fn rotation_descriptor_check_rejects_missing_suite_registry_sig_len() {
        let payload = format!(
            r#"{{
                "op":"rotation_descriptor_check",
                "network":"devnet",
                "suite_registry":[
                    {{"suite_id":1,"pubkey_len":{},"verify_cost":{},"alg_name":"ML-DSA-87"}},
                    {{"suite_id":2,"pubkey_len":{},"sig_len":{},"verify_cost":{},"alg_name":"ML-DSA-87"}}
                ],
                "rotation_descriptor":{{"name":"r1","old_suite_id":1,"new_suite_id":2,"create_height":10,"spend_height":20,"sunset_height":100}}
            }}"#,
            rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
            rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
            rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
            rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            rubin_consensus::constants::VERIFY_COST_ML_DSA_87,
        );
        let err = match serde_json::from_str::<Request>(&payload) {
            Ok(_) => panic!("expected missing sig_len to fail closed during deserialize"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("bad suite_registry"));
    }
}
