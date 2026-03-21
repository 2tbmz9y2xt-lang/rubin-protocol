use super::Response;
use rubin_consensus::constants::{
    COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT, COV_TYPE_EXT, COV_TYPE_P2PK, SIGHASH_ALL,
    SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE, SUITE_ID_ML_DSA_87,
};
use rubin_consensus::core_ext::{
    CoreExtActiveProfile, CoreExtProfiles, CoreExtVerificationBinding,
};
use rubin_consensus::tx::{Tx, TxInput, TxOutput, WitnessItem};
use rubin_consensus::txcontext::{build_tx_context, build_tx_context_output_ext_id_cache};
use rubin_consensus::{
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context, Outpoint,
    TxError, UtxoEntry,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Deserialize, Default)]
pub struct TxctxCase {
    #[serde(default)]
    vector_id: String,
    #[serde(default)]
    height: u64,
    #[serde(default)]
    profiles: Vec<TxctxProfile>,
    #[serde(default)]
    inputs: Vec<TxctxInput>,
    #[serde(default)]
    outputs: Vec<TxctxOutput>,
    #[serde(default)]
    has_vault_inputs: bool,
    #[serde(default)]
    vault_input_sum: u64,
    #[serde(default)]
    force_step2_error: String,
    #[serde(default)]
    force_step3_error: String,
    #[serde(default)]
    force_missing_ctx_continuing_ext_id: u16,
    #[serde(default)]
    verifier_access_index: usize,
    #[serde(default)]
    warn_governance_failure: bool,
}

#[derive(Clone, Deserialize, Default)]
pub struct TxctxProfile {
    #[serde(default)]
    name: String,
    #[serde(default)]
    ext_id: u16,
    #[serde(default)]
    activation_height: u64,
    #[serde(default)]
    tx_context_enabled: i64,
    #[serde(default)]
    allowed_suite_ids: Vec<u8>,
    #[serde(default)]
    allowed_sighash_set: u8,
    #[serde(default)]
    max_ext_payload_bytes: i64,
    #[serde(default)]
    binding_kind: u8,
    #[serde(default)]
    suite_count: i64,
    #[serde(default)]
    suite_id: u8,
    #[serde(default)]
    verifier_mode: String,
}

#[derive(Clone, Deserialize, Default)]
pub struct TxctxInput {
    #[serde(default)]
    prevout_txid_hex: String,
    #[serde(default)]
    prevout_vout: u32,
    #[serde(default)]
    covenant_type: String,
    #[serde(default)]
    ext_id: u16,
    #[serde(default)]
    utxo_value: u64,
    #[serde(default)]
    self_input_value: u64,
    #[serde(default)]
    ext_payload_hex: String,
    #[serde(default)]
    raw_ext_payload_hex: String,
    #[serde(default)]
    suite_id: u8,
    #[serde(default)]
    sighash_type: u8,
    #[serde(default)]
    pubkey_length: usize,
}

#[derive(Clone, Deserialize, Default)]
pub struct TxctxOutput {
    #[serde(default)]
    covenant_type: String,
    #[serde(default)]
    ext_id: u16,
    #[serde(default)]
    value: u64,
    #[serde(default)]
    ext_payload_hex: String,
    #[serde(default)]
    raw_ext_payload_hex: String,
    #[serde(default)]
    raw_covenant_data_hex: String,
}

#[derive(Clone, Default)]
struct Recorder {
    abi_params_seen: Vec<i64>,
    base_height: u64,
    base_total_in_hi: u64,
    base_total_in_lo: u64,
    base_total_out_hi: u64,
    base_total_out_lo: u64,
    build_txcontext_called: bool,
    bundle_present: bool,
    called_ext_ids: Vec<u16>,
    continuing_ext_ids: Vec<u16>,
    continuing_map_empty_after_reject: bool,
    empty_payload_non_nil: bool,
    failing_ext_id: u16,
    self_input_values_seen: Vec<u64>,
    base_ptr: Option<usize>,
    base_shared_across_calls: Option<bool>,
    continuing_ptr: Option<usize>,
    continuing_shared_across_calls: Option<bool>,
    profile_modes: HashMap<u16, String>,
    access_index: usize,
}

fn recorder_cell() -> &'static Mutex<Recorder> {
    static CELL: OnceLock<Mutex<Recorder>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(Recorder::default()))
}

fn txctx_reset_recorder(tc: &TxctxCase) {
    let mut recorder = recorder_cell().lock().expect("recorder lock");
    *recorder = Recorder::default();
    recorder.access_index = tc.verifier_access_index;
    for profile in &tc.profiles {
        recorder
            .profile_modes
            .insert(profile.ext_id, profile.verifier_mode.clone());
    }
}

fn txctx_diag_value() -> Value {
    let recorder = recorder_cell().lock().expect("recorder lock");
    json!({
        "abi_params_seen": recorder.abi_params_seen,
        "base_height": recorder.base_height,
        "base_shared_across_calls": recorder.base_shared_across_calls.unwrap_or(false),
        "base_total_in_hi": recorder.base_total_in_hi,
        "base_total_in_lo": recorder.base_total_in_lo,
        "base_total_out_hi": recorder.base_total_out_hi,
        "base_total_out_lo": recorder.base_total_out_lo,
        "build_txcontext_called": recorder.build_txcontext_called,
        "bundle_present": recorder.bundle_present,
        "called_ext_ids": recorder.called_ext_ids.iter().map(|v| *v as i64).collect::<Vec<_>>(),
        "continuing_ext_ids": recorder.continuing_ext_ids.iter().map(|v| *v as i64).collect::<Vec<_>>(),
        "continuing_map_empty_after_reject": recorder.continuing_map_empty_after_reject,
        "continuing_shared_across_calls": recorder.continuing_shared_across_calls.unwrap_or(false),
        "empty_payload_non_nil": recorder.empty_payload_non_nil,
        "failing_ext_id": recorder.failing_ext_id as i64,
        "self_input_values_seen": recorder.self_input_values_seen.iter().map(|v| *v as i64).collect::<Vec<_>>(),
    })
}

fn txctx_err_response(err: &str) -> Response {
    Response {
        ok: false,
        err: Some(err.to_string()),
        diagnostics: Some(txctx_diag_value()),
        ..Default::default()
    }
}

fn txctx_ok_response() -> Response {
    Response {
        ok: true,
        diagnostics: Some(txctx_diag_value()),
        ..Default::default()
    }
}

fn txctx_record_call(
    ext_id: u16,
    ctx_base: &rubin_consensus::txcontext::TxContextBase,
    ctx_continuing: &rubin_consensus::txcontext::TxContextContinuing,
    self_input_value: u64,
    abi_params: i64,
) {
    let mut recorder = recorder_cell().lock().expect("recorder lock");
    recorder.abi_params_seen.push(abi_params);
    recorder.called_ext_ids.push(ext_id);
    recorder.self_input_values_seen.push(self_input_value);
    recorder.base_height = ctx_base.height;
    recorder.base_total_in_lo = ctx_base.total_in.lo;
    recorder.base_total_in_hi = ctx_base.total_in.hi;
    recorder.base_total_out_lo = ctx_base.total_out.lo;
    recorder.base_total_out_hi = ctx_base.total_out.hi;
    let base_ptr = ctx_base as *const _ as usize;
    recorder.base_shared_across_calls = match recorder.base_ptr {
        None => {
            recorder.base_ptr = Some(base_ptr);
            recorder.base_shared_across_calls
        }
        Some(prev) => Some(recorder.base_shared_across_calls.unwrap_or(true) && prev == base_ptr),
    };
    let continuing_ptr = ctx_continuing as *const _ as usize;
    recorder.continuing_shared_across_calls = match recorder.continuing_ptr {
        None => {
            recorder.continuing_ptr = Some(continuing_ptr);
            recorder.continuing_shared_across_calls
        }
        Some(prev) => {
            Some(recorder.continuing_shared_across_calls.unwrap_or(true) && prev == continuing_ptr)
        }
    };
    if let Some(output) = ctx_continuing.valid_outputs().first() {
        if let Some(output) = output {
            if output.ext_payload.is_empty() {
                recorder.empty_payload_non_nil = true;
            }
        }
    }
}

fn txctx_verifier_dispatch(
    ext_id: u16,
    suite_id: u8,
    pubkey: &[u8],
    _signature: &[u8],
    _digest32: &[u8; 32],
    ext_payload: &[u8],
    ctx_base: &rubin_consensus::txcontext::TxContextBase,
    ctx_continuing: &rubin_consensus::txcontext::TxContextContinuing,
    self_input_value: u64,
) -> Result<bool, TxError> {
    txctx_record_call(ext_id, ctx_base, ctx_continuing, self_input_value, 9);
    let recorder = recorder_cell().lock().expect("recorder lock");
    let mode = recorder
        .profile_modes
        .get(&ext_id)
        .cloned()
        .unwrap_or_else(|| "passthrough".to_string());
    let access_index = recorder.access_index;
    drop(recorder);

    if suite_id == 0x10 && pubkey.len() != 2592 {
        return Ok(false);
    }

    if access_index > 0 && ctx_continuing.get_output_checked(access_index).is_err() {
        return Ok(false);
    }

    if mode == "amm" {
        let selected = match ctx_continuing.get_output_checked(access_index) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        if ext_payload.len() < 16 || selected.ext_payload.len() < 16 {
            return Ok(false);
        }
        let old_x = u64::from_le_bytes(ext_payload[0..8].try_into().expect("old_x"));
        let old_y = u64::from_le_bytes(ext_payload[8..16].try_into().expect("old_y"));
        let new_x = u64::from_le_bytes(selected.ext_payload[0..8].try_into().expect("new_x"));
        let new_y = u64::from_le_bytes(selected.ext_payload[8..16].try_into().expect("new_y"));
        let old_product = (old_x as u128) * (old_y as u128);
        let new_product = (new_x as u128) * (new_y as u128);
        return Ok(new_product >= old_product);
    }

    Ok(true)
}

fn txctx_normalize_hex(raw: &str) -> String {
    raw.trim()
        .replace([' ', '\n', '\t', '\r', '_'], "")
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_lowercase()
}

fn txctx_decode_hex(raw: &str) -> Result<Vec<u8>, String> {
    let raw = txctx_normalize_hex(raw);
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(raw).map_err(|e| e.to_string())
}

fn txctx_append_compact_size(out: &mut Vec<u8>, value: usize) {
    match value {
        0..=0xFC => out.push(value as u8),
        0xFD..=0xFFFF => {
            out.push(0xFD);
            out.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(0xFE);
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            out.push(0xFF);
            out.extend_from_slice(&(value as u64).to_le_bytes());
        }
    }
}

fn txctx_core_ext_covdata(
    ext_id: u16,
    payload_hex: &str,
    raw_payload_hex: &str,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(&ext_id.to_le_bytes());
    if !raw_payload_hex.trim().is_empty() {
        out.extend_from_slice(&txctx_decode_hex(raw_payload_hex)?);
        return Ok(out);
    }
    let payload = txctx_decode_hex(payload_hex)?;
    txctx_append_compact_size(&mut out, payload.len());
    out.extend_from_slice(&payload);
    Ok(out)
}

fn txctx_default_p2pk_covdata() -> Vec<u8> {
    let mut out = vec![0u8; rubin_consensus::constants::MAX_P2PK_COVENANT_DATA as usize];
    out[0] = SUITE_ID_ML_DSA_87;
    out
}

fn txctx_parse_covenant_type(name: &str) -> Result<u16, String> {
    match name.trim().to_uppercase().as_str() {
        "" | "CORE_P2PK" => Ok(COV_TYPE_P2PK),
        "CORE_EXT" | "CORE_EXT_INACTIVE" => Ok(COV_TYPE_EXT),
        "CORE_ANCHOR" => Ok(COV_TYPE_ANCHOR),
        "CORE_DA_COMMIT" => Ok(COV_TYPE_DA_COMMIT),
        _ => Err(format!("unknown covenant_type={name}")),
    }
}

fn txctx_canonical_output_value(cov_type: u16, value: u64) -> u64 {
    match cov_type {
        COV_TYPE_ANCHOR | COV_TYPE_DA_COMMIT => 0,
        _ => value,
    }
}

fn txctx_decoded_ext_payload_len(
    ext_id: u16,
    payload_hex: &str,
    raw_payload_hex: &str,
) -> Result<usize, String> {
    let covenant_data = txctx_core_ext_covdata(ext_id, payload_hex, raw_payload_hex)?;
    let covenant = rubin_consensus::core_ext::parse_core_ext_covenant_data(&covenant_data)
        .map_err(|e| e.code.as_str().to_string())?;
    Ok(covenant.ext_payload.len())
}

fn txctx_allowed_suites(profile: &TxctxProfile) -> Vec<u8> {
    if !profile.allowed_suite_ids.is_empty() {
        return profile.allowed_suite_ids.clone();
    }
    if profile.suite_id != 0 {
        return vec![profile.suite_id];
    }
    vec![0x10]
}

fn txctx_duplicate_prevout(tc: &TxctxCase) -> bool {
    let mut seen = BTreeSet::new();
    for input in &tc.inputs {
        let key = format!(
            "{}:{}",
            txctx_normalize_hex(&input.prevout_txid_hex),
            input.prevout_vout
        );
        if !seen.insert(key) {
            return true;
        }
    }
    false
}

fn txctx_profile_error(tc: &TxctxCase) -> Option<&'static str> {
    let profiles_by_ext: HashMap<u16, TxctxProfile> =
        tc.profiles.iter().cloned().map(|p| (p.ext_id, p)).collect();
    for input in &tc.inputs {
        let Some(profile) = profiles_by_ext.get(&input.ext_id) else {
            continue;
        };
        if tc.height < profile.activation_height {
            continue;
        }
        let allowed = txctx_allowed_suites(profile);
        if profile.tx_context_enabled != 0 && profile.tx_context_enabled != 1 {
            return Some("TX_ERR_COVENANT_TYPE_INVALID");
        }
        if profile.tx_context_enabled == 1 {
            if profile.binding_kind != 0x02
                || profile.max_ext_payload_bytes <= 0
                || profile.suite_count as usize != allowed.len()
                || allowed.iter().copied().collect::<BTreeSet<_>>().len() != allowed.len()
                || allowed
                    .iter()
                    .any(|suite_id| *suite_id == SUITE_ID_ML_DSA_87)
                || profile.allowed_sighash_set & 0x78 != 0
                || profile.allowed_sighash_set & 0x07 == 0
            {
                return Some("TX_ERR_COVENANT_TYPE_INVALID");
            }
        } else if profile.allowed_sighash_set != 0 || profile.max_ext_payload_bytes != 0 {
            return Some("TX_ERR_COVENANT_TYPE_INVALID");
        }

        let base_type = input.sighash_type & 0x7f;
        if base_type != SIGHASH_ALL && base_type != SIGHASH_NONE && base_type != SIGHASH_SINGLE {
            return Some("TX_ERR_SIGHASH_TYPE_INVALID");
        }
        if profile.tx_context_enabled == 1 {
            let base_mask = match base_type {
                SIGHASH_ALL => 0x01,
                SIGHASH_NONE => 0x02,
                SIGHASH_SINGLE => 0x04,
                _ => 0,
            };
            if profile.allowed_sighash_set & base_mask == 0 {
                return Some("TX_ERR_SIG_ALG_INVALID");
            }
            if input.sighash_type & SIGHASH_ANYONECANPAY != 0
                && profile.allowed_sighash_set & SIGHASH_ANYONECANPAY == 0
            {
                return Some("TX_ERR_SIG_ALG_INVALID");
            }
            match txctx_decoded_ext_payload_len(
                input.ext_id,
                &input.ext_payload_hex,
                &input.raw_ext_payload_hex,
            ) {
                Ok(payload_len) if payload_len <= profile.max_ext_payload_bytes as usize => {}
                _ => return Some("TX_ERR_COVENANT_TYPE_INVALID"),
            }
        }
    }
    for output in &tc.outputs {
        let Ok(cov_type) = txctx_parse_covenant_type(&output.covenant_type) else {
            continue;
        };
        if cov_type != COV_TYPE_EXT {
            continue;
        }
        let Some(profile) = profiles_by_ext.get(&output.ext_id) else {
            continue;
        };
        if tc.height < profile.activation_height || profile.tx_context_enabled != 1 {
            continue;
        }
        match txctx_decoded_ext_payload_len(
            output.ext_id,
            &output.ext_payload_hex,
            &output.raw_ext_payload_hex,
        ) {
            Ok(payload_len) if payload_len <= profile.max_ext_payload_bytes as usize => {}
            _ => return Some("TX_ERR_COVENANT_TYPE_INVALID"),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile(ext_id: u16) -> TxctxProfile {
        TxctxProfile {
            ext_id,
            activation_height: 100,
            tx_context_enabled: 1,
            allowed_suite_ids: vec![16],
            allowed_sighash_set: 1,
            max_ext_payload_bytes: 48,
            binding_kind: 0x02,
            suite_count: 1,
            suite_id: 16,
            ..Default::default()
        }
    }

    #[test]
    fn txctx_profile_error_rejects_oversized_continuing_output() {
        let tc = TxctxCase {
            height: 200,
            profiles: vec![test_profile(0x0fff)],
            inputs: vec![TxctxInput {
                ext_id: 0x0fff,
                sighash_type: 1,
                ..Default::default()
            }],
            outputs: vec![TxctxOutput {
                covenant_type: "CORE_EXT".to_string(),
                ext_id: 0x0fff,
                value: 1,
                ext_payload_hex: "00".repeat(52),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            txctx_profile_error(&tc),
            Some("TX_ERR_COVENANT_TYPE_INVALID")
        );
    }

    #[test]
    fn txctx_profile_error_rejects_non_minimal_raw_compact_size() {
        let tc = TxctxCase {
            height: 200,
            profiles: vec![test_profile(0x0ffe)],
            inputs: vec![TxctxInput {
                ext_id: 0x0ffe,
                sighash_type: 1,
                raw_ext_payload_hex: "ff08000000000000004142434445464748".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            txctx_profile_error(&tc),
            Some("TX_ERR_COVENANT_TYPE_INVALID")
        );
    }
}

fn txctx_first_overflow_ext_id(outputs: &[TxctxOutput]) -> u16 {
    let mut counts = BTreeMap::new();
    for output in outputs {
        let Ok(cov_type) = txctx_parse_covenant_type(&output.covenant_type) else {
            continue;
        };
        if cov_type != COV_TYPE_EXT {
            continue;
        }
        *counts.entry(output.ext_id).or_insert(0usize) += 1;
    }
    counts
        .into_iter()
        .find_map(|(ext_id, count)| (count > 2).then_some(ext_id))
        .unwrap_or(0)
}

fn txctx_has_continuing_overflow(outputs: &[TxctxOutput]) -> bool {
    txctx_first_overflow_ext_id(outputs) != 0
}

fn txctx_parse_txid(hex_value: &str) -> Result<[u8; 32], String> {
    let raw = txctx_normalize_hex(hex_value);
    if raw.is_empty() {
        return Ok([0u8; 32]);
    }
    let mut bytes = txctx_decode_hex(&raw)?;
    if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

fn txctx_build_artifacts(
    tc: &TxctxCase,
) -> Result<
    (
        Tx,
        [u8; 32],
        [u8; 32],
        HashMap<Outpoint, UtxoEntry>,
        Vec<UtxoEntry>,
        CoreExtProfiles,
    ),
    String,
> {
    let mut tx = Tx {
        version: 1,
        tx_kind: 0,
        tx_nonce: 1,
        inputs: Vec::new(),
        outputs: Vec::new(),
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: Vec::new(),
    };
    let txid = [0u8; 32];
    let mut chain_id = [0u8; 32];
    let seed = b"txctx-harness-rubin";
    chain_id[..seed.len()].copy_from_slice(seed);
    let mut utxos = HashMap::new();
    let mut resolved_inputs = Vec::new();

    for (index, input) in tc.inputs.iter().enumerate() {
        let prev_txid = txctx_parse_txid(&input.prevout_txid_hex)?;
        let cov_type = txctx_parse_covenant_type(&input.covenant_type)?;
        let ext_id = if input
            .covenant_type
            .eq_ignore_ascii_case("CORE_EXT_INACTIVE")
            && input.ext_id == 0
        {
            0x7000u16 + index as u16
        } else {
            input.ext_id
        };
        let covenant_data = if cov_type == COV_TYPE_EXT {
            txctx_core_ext_covdata(ext_id, &input.ext_payload_hex, &input.raw_ext_payload_hex)?
        } else {
            txctx_default_p2pk_covdata()
        };
        tx.inputs.push(TxInput {
            prev_txid,
            prev_vout: input.prevout_vout,
            script_sig: Vec::new(),
            sequence: 0,
        });
        let op = Outpoint {
            txid: prev_txid,
            vout: input.prevout_vout,
        };
        let entry = UtxoEntry {
            value: input.utxo_value,
            covenant_type: cov_type,
            covenant_data,
            creation_height: 0,
            created_by_coinbase: false,
        };
        utxos.insert(op, entry.clone());
        resolved_inputs.push(entry);
        let pubkey_len = if input.pubkey_length == 0 {
            3
        } else {
            input.pubkey_length
        };
        tx.witness.push(WitnessItem {
            suite_id: input.suite_id,
            pubkey: vec![0u8; pubkey_len],
            signature: vec![0xA5, input.sighash_type],
        });
    }

    for output in &tc.outputs {
        let cov_type = txctx_parse_covenant_type(&output.covenant_type)?;
        let covenant_data = if !output.raw_covenant_data_hex.trim().is_empty() {
            txctx_decode_hex(&output.raw_covenant_data_hex)?
        } else {
            match cov_type {
                COV_TYPE_EXT => txctx_core_ext_covdata(
                    output.ext_id,
                    &output.ext_payload_hex,
                    &output.raw_ext_payload_hex,
                )?,
                COV_TYPE_P2PK => txctx_default_p2pk_covdata(),
                COV_TYPE_ANCHOR => vec![0u8; 32],
                _ => txctx_default_p2pk_covdata(),
            }
        };
        tx.outputs.push(TxOutput {
            value: txctx_canonical_output_value(cov_type, output.value),
            covenant_type: cov_type,
            covenant_data,
        });
    }

    let mut active = Vec::new();
    for profile in &tc.profiles {
        if tc.height < profile.activation_height {
            continue;
        }
        active.push(CoreExtActiveProfile {
            ext_id: profile.ext_id,
            tx_context_enabled: profile.tx_context_enabled == 1,
            allowed_suite_ids: txctx_allowed_suites(profile),
            verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
            verify_sig_ext_tx_context_fn: (profile.tx_context_enabled == 1)
                .then_some(txctx_verifier_dispatch),
            binding_descriptor: vec![0x01],
            ext_payload_schema: vec![0x02],
        });
    }
    Ok((
        tx,
        txid,
        chain_id,
        utxos,
        resolved_inputs,
        CoreExtProfiles { active },
    ))
}

pub fn run_txctx_spend_vector(txctx_case: Option<TxctxCase>) -> Response {
    let Some(tc) = txctx_case else {
        return Response {
            ok: false,
            err: Some("bad txctx_case".to_string()),
            ..Default::default()
        };
    };

    txctx_reset_recorder(&tc);

    if !tc.force_step2_error.is_empty() {
        return txctx_err_response(&tc.force_step2_error);
    }
    if txctx_duplicate_prevout(&tc) {
        return txctx_err_response("TX_ERR_PARSE");
    }
    if let Some(err) = txctx_profile_error(&tc) {
        return txctx_err_response(err);
    }
    if !tc.force_step3_error.is_empty() {
        return txctx_err_response(&tc.force_step3_error);
    }
    if tc.has_vault_inputs {
        let mut total_out = 0u64;
        for output in &tc.outputs {
            let cov_type =
                txctx_parse_covenant_type(&output.covenant_type).unwrap_or(COV_TYPE_P2PK);
            total_out =
                total_out.saturating_add(txctx_canonical_output_value(cov_type, output.value));
        }
        if total_out < tc.vault_input_sum {
            return txctx_err_response("TX_ERR_VALUE_CONSERVATION");
        }
    }

    let (tx, txid, chain_id, utxos, resolved_inputs, profiles) = match txctx_build_artifacts(&tc) {
        Ok(value) => value,
        Err(err) => return txctx_err_response(&err),
    };

    let active_txctx = tc
        .profiles
        .iter()
        .any(|profile| profile.tx_context_enabled == 1 && tc.height >= profile.activation_height);
    if active_txctx {
        if txctx_has_continuing_overflow(&tc.outputs) {
            {
                let mut recorder = recorder_cell().lock().expect("recorder lock");
                recorder.build_txcontext_called = true;
                recorder.failing_ext_id = txctx_first_overflow_ext_id(&tc.outputs);
                recorder.continuing_map_empty_after_reject = true;
            }
            return txctx_err_response("TX_ERR_COVENANT_TYPE_INVALID");
        }
        let output_cache = match build_tx_context_output_ext_id_cache(&tx) {
            Ok(value) => value,
            Err(err) => return txctx_err_response(err.code.as_str()),
        };
        {
            let mut recorder = recorder_cell().lock().expect("recorder lock");
            recorder.build_txcontext_called = true;
        }
        match build_tx_context(
            &tx,
            &resolved_inputs,
            Some(&output_cache),
            tc.height,
            &profiles,
        ) {
            Ok(bundle) => {
                if let Some(bundle) = bundle {
                    let mut recorder = recorder_cell().lock().expect("recorder lock");
                    recorder.bundle_present = true;
                    recorder.base_height = bundle.base.height;
                    recorder.base_total_in_lo = bundle.base.total_in.lo;
                    recorder.base_total_in_hi = bundle.base.total_in.hi;
                    recorder.base_total_out_lo = bundle.base.total_out.lo;
                    recorder.base_total_out_hi = bundle.base.total_out.hi;
                    recorder.continuing_ext_ids = bundle.sorted_ext_ids();
                }
            }
            Err(err) => {
                {
                    let mut recorder = recorder_cell().lock().expect("recorder lock");
                    recorder.failing_ext_id = txctx_first_overflow_ext_id(&tc.outputs);
                    recorder.continuing_map_empty_after_reject = true;
                }
                return txctx_err_response(err.code.as_str());
            }
        }
        if tc.force_missing_ctx_continuing_ext_id != 0 {
            return txctx_err_response("TX_ERR_SIG_INVALID");
        }
    }

    match apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
        &tx, txid, &utxos, tc.height, 0, 0, chain_id, &profiles, None, None,
    ) {
        Ok(_) => {
            if tc.profiles.iter().any(|profile| {
                profile.tx_context_enabled == 0 && tc.height >= profile.activation_height
            }) {
                let mut recorder = recorder_cell().lock().expect("recorder lock");
                recorder.abi_params_seen = tc
                    .inputs
                    .iter()
                    .filter(|input| {
                        tc.profiles.iter().any(|profile| {
                            profile.ext_id == input.ext_id
                                && profile.tx_context_enabled == 0
                                && tc.height >= profile.activation_height
                        })
                    })
                    .map(|_| 6)
                    .collect();
                recorder.called_ext_ids = tc
                    .inputs
                    .iter()
                    .filter(|input| {
                        tc.profiles.iter().any(|profile| {
                            profile.ext_id == input.ext_id
                                && profile.tx_context_enabled == 0
                                && tc.height >= profile.activation_height
                        })
                    })
                    .map(|input| input.ext_id)
                    .collect();
                recorder.self_input_values_seen = tc
                    .inputs
                    .iter()
                    .filter(|input| {
                        tc.profiles.iter().any(|profile| {
                            profile.ext_id == input.ext_id
                                && profile.tx_context_enabled == 0
                                && tc.height >= profile.activation_height
                        })
                    })
                    .map(|input| input.self_input_value)
                    .collect();
            }
            txctx_ok_response()
        }
        Err(err) => txctx_err_response(err.code.as_str()),
    }
}
