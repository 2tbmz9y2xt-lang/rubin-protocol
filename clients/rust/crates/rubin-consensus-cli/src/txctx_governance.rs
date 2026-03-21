use super::{CoreExtProfileJson, Request, Response, TxctxDependencyChecklistJson};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

const TXCTX_GOVERNANCE_ERR_ACTIVATION_BELOW_TRANSITION: &str =
    "ACTIVATION_HEIGHT_BELOW_TRANSITION_HEIGHT";
const TXCTX_GOVERNANCE_ERR_ARTIFACT_HASH_MISMATCH: &str = "ARTIFACT_HASH_MISMATCH";
const TXCTX_GOVERNANCE_ERR_DUPLICATE_ALLOWED_SUITE_ID: &str = "DUPLICATE_ALLOWED_SUITE_ID";
const TXCTX_GOVERNANCE_ERR_DUPLICATE_CHECKLIST: &str = "DUPLICATE_DEPENDENCY_CHECKLIST";
const TXCTX_GOVERNANCE_ERR_DUPLICATE_PROFILE_EXT_ID: &str = "DUPLICATE_PROFILE_EXT_ID";
const TXCTX_GOVERNANCE_ERR_EMPTY_ALLOWED_SUITE_IDS: &str = "EMPTY_ALLOWED_SUITE_IDS";
const TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST: &str = "INVALID_DEPENDENCY_CHECKLIST";
const TXCTX_GOVERNANCE_ERR_MEMPOOL_GATE_REQUIRED: &str = "MEMPOOL_TXCTX_CONFIRMATION_REQUIRED";
const TXCTX_GOVERNANCE_ERR_MISSING_CHECKLIST: &str = "MISSING_DEPENDENCY_CHECKLIST";

pub fn run_txctx_governance_vector(req: &Request) -> Response {
    let mut diagnostics = json!({
        "profile_count": req.core_ext_profiles.len(),
        "txctx_profile_count": txctx_enabled_profile_count(&req.core_ext_profiles),
        "artifact_hash_checked": !req.expected_artifact_hash_hex.trim().is_empty(),
    });
    if let Some(derived) = derive_txctx_transition_height(&req.core_ext_profiles) {
        diagnostics["derived_transition_height"] = json!(derived);
    }
    if let Some(transition_height) = req.transition_height {
        diagnostics["transition_height"] = json!(transition_height);
    }

    if txctx_enabled_profile_count(&req.core_ext_profiles) > 0
        && req.expected_artifact_hash_hex.trim().is_empty()
    {
        return err_response("bad expected_artifact_hash_hex", diagnostics);
    }
    if let Err(err) = validate_artifact_hash(&req.artifact_hex, &req.expected_artifact_hash_hex) {
        return err_response(err, diagnostics);
    }
    if let Err(err) = validate_txctx_governance_profiles(
        &req.core_ext_profiles,
        req.transition_height,
        &req.dependency_checklists,
        req.mempool_txctx_confirmed,
    ) {
        return err_response(err, diagnostics);
    }
    Response {
        ok: true,
        diagnostics: Some(diagnostics),
        ..Default::default()
    }
}

fn err_response(err: &str, diagnostics: Value) -> Response {
    Response {
        ok: false,
        err: Some(err.to_string()),
        diagnostics: Some(diagnostics),
        ..Default::default()
    }
}

fn validate_artifact_hash(artifact_hex: &str, expected_hash_hex: &str) -> Result<(), &'static str> {
    let artifact_hex = normalize_governance_hex(artifact_hex);
    if artifact_hex.is_empty() {
        return Err("bad artifact_hex");
    }
    let artifact = hex::decode(artifact_hex).map_err(|_| "bad artifact_hex")?;
    let expected_hash_hex = normalize_governance_hex(expected_hash_hex);
    let expected_hash =
        hex::decode(expected_hash_hex).map_err(|_| "bad expected_artifact_hash_hex")?;
    if expected_hash.len() != 32 {
        return Err("bad expected_artifact_hash_hex");
    }
    let actual_hash = Sha256::digest(&artifact);
    if actual_hash.as_slice() != expected_hash.as_slice() {
        return Err(TXCTX_GOVERNANCE_ERR_ARTIFACT_HASH_MISMATCH);
    }
    Ok(())
}

fn validate_txctx_governance_profiles(
    profiles: &[CoreExtProfileJson],
    transition_height: Option<u64>,
    checklists: &[TxctxDependencyChecklistJson],
    mempool_confirmed: Option<bool>,
) -> Result<(), &'static str> {
    let mut seen_ext_ids = std::collections::HashSet::with_capacity(profiles.len());
    let mut required_checklist_ext_ids = std::collections::HashSet::with_capacity(profiles.len());
    let mut checklists_by_ext_id = HashMap::with_capacity(checklists.len());
    for checklist in checklists {
        let ext_id = parse_checklist_ext_id(&checklist.profile_ext_id)
            .ok_or(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST)?;
        if checklists_by_ext_id.insert(ext_id, checklist).is_some() {
            return Err(TXCTX_GOVERNANCE_ERR_DUPLICATE_CHECKLIST);
        }
    }
    for profile in profiles {
        if !seen_ext_ids.insert(profile.ext_id) {
            return Err(TXCTX_GOVERNANCE_ERR_DUPLICATE_PROFILE_EXT_ID);
        }
        if profile.allowed_suite_ids.is_empty() {
            return Err(TXCTX_GOVERNANCE_ERR_EMPTY_ALLOWED_SUITE_IDS);
        }
        if has_duplicate_suite_id(&profile.allowed_suite_ids) {
            return Err(TXCTX_GOVERNANCE_ERR_DUPLICATE_ALLOWED_SUITE_ID);
        }
        if profile.allowed_suite_ids.len() != 1 {
            return Err(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST);
        }
        if !profile.tx_context_enabled {
            continue;
        }
        required_checklist_ext_ids.insert(profile.ext_id);
        if let Some(transition_height) = transition_height {
            if profile.activation_height < transition_height {
                return Err(TXCTX_GOVERNANCE_ERR_ACTIVATION_BELOW_TRANSITION);
            }
        }
        let checklist = checklists_by_ext_id
            .get(&profile.ext_id)
            .ok_or(TXCTX_GOVERNANCE_ERR_MISSING_CHECKLIST)?;
        validate_dependency_checklist(checklist, profile, mempool_confirmed)?;
    }
    if checklists_by_ext_id.len() != required_checklist_ext_ids.len() {
        return Err(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST);
    }
    for ext_id in checklists_by_ext_id.keys() {
        if !required_checklist_ext_ids.contains(ext_id) {
            return Err(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST);
        }
    }
    Ok(())
}

fn validate_dependency_checklist(
    checklist: &TxctxDependencyChecklistJson,
    profile: &CoreExtProfileJson,
    mempool_confirmed: Option<bool>,
) -> Result<(), &'static str> {
    if checklist.spec_document.trim().is_empty()
        || checklist.sighash_types_required.is_empty()
        || checklist.verifier_side_effects.trim().is_empty()
        || checklist.reviewer.trim().is_empty()
    {
        return Err(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST);
    }
    if !has_declared_txctx_dependency(&checklist.txcontext_inputs_used) {
        return Err(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST);
    }
    if !has_valid_sighash_types(&checklist.sighash_types_required) {
        return Err(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST);
    }
    if !checklist
        .verifier_side_effects
        .trim()
        .eq_ignore_ascii_case("none")
    {
        return Err(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST);
    }
    if checklist.max_ext_payload_bytes < 0 || profile.max_ext_payload_bytes < 0 {
        return Err(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST);
    }
    if checklist.max_ext_payload_bytes != profile.max_ext_payload_bytes {
        return Err(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST);
    }
    if profile.max_ext_payload_bytes > 256 && !mempool_confirmed.unwrap_or(false) {
        return Err(TXCTX_GOVERNANCE_ERR_MEMPOOL_GATE_REQUIRED);
    }
    Ok(())
}

fn normalize_governance_hex(raw: &str) -> String {
    raw.trim()
        .strip_prefix("0x")
        .or_else(|| raw.trim().strip_prefix("0X"))
        .unwrap_or(raw.trim())
        .to_ascii_lowercase()
}

fn parse_checklist_ext_id(raw: &str) -> Option<u16> {
    let raw = raw.trim();
    if raw.len() != 6 {
        return None;
    }
    let hex = raw.strip_prefix("0x")?;
    if !hex
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    u16::from_str_radix(hex, 16).ok()
}

fn has_duplicate_suite_id(ids: &[u8]) -> bool {
    let mut seen = HashSet::with_capacity(ids.len());
    for suite_id in ids {
        if !seen.insert(*suite_id) {
            return true;
        }
    }
    false
}

fn has_declared_txctx_dependency(inputs: &super::TxctxDependencyInputsJson) -> bool {
    inputs.self_input_value
        || inputs.ctx_base_height
        || inputs.ctx_base_total_in
        || inputs.ctx_continuing_outputs
}

fn has_valid_sighash_types(values: &[String]) -> bool {
    let allowed = ["SIGHASH_ALL", "SIGHASH_SINGLE", "SIGHASH_NONE", "ACP"];
    let mut seen = HashSet::with_capacity(values.len());
    for value in values {
        let normalized = value.trim().to_ascii_uppercase();
        if normalized.is_empty() || !allowed.contains(&normalized.as_str()) {
            return false;
        }
        if !seen.insert(normalized) {
            return false;
        }
    }
    true
}

fn derive_txctx_transition_height(profiles: &[CoreExtProfileJson]) -> Option<u64> {
    profiles
        .iter()
        .filter(|profile| profile.tx_context_enabled)
        .map(|profile| profile.activation_height)
        .min()
}

fn txctx_enabled_profile_count(profiles: &[CoreExtProfileJson]) -> usize {
    profiles
        .iter()
        .filter(|profile| profile.tx_context_enabled)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TxctxDependencyInputsJson;

    fn test_profile() -> CoreExtProfileJson {
        CoreExtProfileJson {
            ext_id: 0x0feb,
            activation_height: 100,
            tx_context_enabled: true,
            allowed_suite_ids: vec![0x10],
            max_ext_payload_bytes: 48,
            binding: "native_verify_sig".to_string(),
            ..Default::default()
        }
    }

    fn test_request(checklists: Vec<TxctxDependencyChecklistJson>) -> Request {
        let artifact = b"txctx-governance-artifact";
        Request {
            artifact_hex: hex::encode(artifact),
            expected_artifact_hash_hex: hex::encode(Sha256::digest(artifact)),
            transition_height: Some(100),
            dependency_checklists: checklists,
            ..Default::default()
        }
    }

    fn test_checklist(ext_id: u16, max_ext_payload_bytes: i64) -> TxctxDependencyChecklistJson {
        TxctxDependencyChecklistJson {
            profile_ext_id: format!("0x{ext_id:04x}"),
            spec_document: "SPEC-TXCTX-01.md".to_string(),
            txcontext_inputs_used: TxctxDependencyInputsJson {
                self_input_value: true,
                ctx_base_height: true,
                ctx_base_total_in: true,
                ctx_continuing_outputs: true,
            },
            sighash_types_required: vec!["SIGHASH_ALL".to_string()],
            max_ext_payload_bytes,
            verifier_side_effects: "none".to_string(),
            reviewer: "gpt5".to_string(),
        }
    }

    #[test]
    fn rejects_duplicate_allowed_suite_ids() {
        let mut profile = test_profile();
        profile.allowed_suite_ids = vec![0x10, 0x10];
        let mut req = test_request(vec![test_checklist(0x0feb, 48)]);
        req.core_ext_profiles = vec![profile];
        let resp = run_txctx_governance_vector(&req);
        assert!(!resp.ok);
        assert_eq!(
            resp.err.as_deref(),
            Some(TXCTX_GOVERNANCE_ERR_DUPLICATE_ALLOWED_SUITE_ID)
        );
    }

    #[test]
    fn rejects_activation_below_transition() {
        let mut profile = test_profile();
        profile.activation_height = 99;
        let mut req = test_request(vec![test_checklist(0x0feb, 48)]);
        req.core_ext_profiles = vec![profile];
        let resp = run_txctx_governance_vector(&req);
        assert!(!resp.ok);
        assert_eq!(
            resp.err.as_deref(),
            Some(TXCTX_GOVERNANCE_ERR_ACTIVATION_BELOW_TRANSITION)
        );
    }

    #[test]
    fn rejects_artifact_hash_mismatch() {
        let req = Request {
            artifact_hex: hex::encode(b"txctx-governance-artifact"),
            expected_artifact_hash_hex: "11".repeat(32),
            transition_height: Some(100),
            core_ext_profiles: vec![test_profile()],
            dependency_checklists: vec![test_checklist(0x0feb, 48)],
            ..Default::default()
        };
        let resp = run_txctx_governance_vector(&req);
        assert!(!resp.ok);
        assert_eq!(
            resp.err.as_deref(),
            Some(TXCTX_GOVERNANCE_ERR_ARTIFACT_HASH_MISMATCH)
        );
    }

    #[test]
    fn rejects_missing_checklist() {
        let mut req = test_request(vec![]);
        req.core_ext_profiles = vec![test_profile()];
        let resp = run_txctx_governance_vector(&req);
        assert!(!resp.ok);
        assert_eq!(
            resp.err.as_deref(),
            Some(TXCTX_GOVERNANCE_ERR_MISSING_CHECKLIST)
        );
    }

    #[test]
    fn rejects_missing_artifact_hash() {
        let req = Request {
            transition_height: Some(100),
            core_ext_profiles: vec![test_profile()],
            dependency_checklists: vec![test_checklist(0x0feb, 48)],
            ..Default::default()
        };
        let resp = run_txctx_governance_vector(&req);
        assert!(!resp.ok);
        assert_eq!(resp.err.as_deref(), Some("bad expected_artifact_hash_hex"));
    }

    #[test]
    fn rejects_large_payload_without_mempool_gate() {
        let mut profile = test_profile();
        profile.max_ext_payload_bytes = 300;
        let mut req = test_request(vec![test_checklist(0x0feb, 300)]);
        req.core_ext_profiles = vec![profile];
        let resp = run_txctx_governance_vector(&req);
        assert!(!resp.ok);
        assert_eq!(
            resp.err.as_deref(),
            Some(TXCTX_GOVERNANCE_ERR_MEMPOOL_GATE_REQUIRED)
        );
    }

    #[test]
    fn accepts_valid_request() {
        let artifact = b"txctx-governance-artifact";
        let req = Request {
            artifact_hex: hex::encode(artifact),
            expected_artifact_hash_hex: hex::encode(Sha256::digest(artifact)),
            transition_height: Some(100),
            mempool_txctx_confirmed: Some(true),
            core_ext_profiles: vec![test_profile()],
            dependency_checklists: vec![test_checklist(0x0feb, 48)],
            ..Default::default()
        };
        let resp = run_txctx_governance_vector(&req);
        assert!(resp.ok, "{:?}", resp.err);
        let diagnostics = resp.diagnostics.expect("diagnostics");
        assert_eq!(diagnostics["derived_transition_height"], json!(100));
    }

    #[test]
    fn rejects_extra_checklist() {
        let mut req = test_request(vec![test_checklist(0x0feb, 48), test_checklist(0x0fed, 48)]);
        req.core_ext_profiles = vec![test_profile()];
        let resp = run_txctx_governance_vector(&req);
        assert!(!resp.ok);
        assert_eq!(
            resp.err.as_deref(),
            Some(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST)
        );
    }

    #[test]
    fn rejects_noncanonical_checklist_ext_id() {
        let mut checklist = test_checklist(0x0feb, 48);
        checklist.profile_ext_id = "0x1".to_string();
        let mut req = test_request(vec![checklist]);
        req.core_ext_profiles = vec![test_profile()];
        let resp = run_txctx_governance_vector(&req);
        assert!(!resp.ok);
        assert_eq!(
            resp.err.as_deref(),
            Some(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST)
        );
    }

    #[test]
    fn rejects_negative_payload_limit() {
        let mut profile = test_profile();
        profile.max_ext_payload_bytes = -1;
        let mut req = test_request(vec![test_checklist(0x0feb, -1)]);
        req.core_ext_profiles = vec![profile];
        let resp = run_txctx_governance_vector(&req);
        assert!(!resp.ok);
        assert_eq!(
            resp.err.as_deref(),
            Some(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST)
        );
    }

    #[test]
    fn rejects_step_two_suite_set() {
        let mut profile = test_profile();
        profile.allowed_suite_ids = vec![0x10, 0x11];
        let mut req = test_request(vec![test_checklist(0x0feb, 48)]);
        req.core_ext_profiles = vec![profile];
        let resp = run_txctx_governance_vector(&req);
        assert!(!resp.ok);
        assert_eq!(
            resp.err.as_deref(),
            Some(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST)
        );
    }

    #[test]
    fn rejects_checklist_without_declared_dependencies() {
        let mut checklist = test_checklist(0x0feb, 48);
        checklist.txcontext_inputs_used = TxctxDependencyInputsJson::default();
        let mut req = test_request(vec![checklist]);
        req.core_ext_profiles = vec![test_profile()];
        let resp = run_txctx_governance_vector(&req);
        assert!(!resp.ok);
        assert_eq!(
            resp.err.as_deref(),
            Some(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST)
        );
    }

    #[test]
    fn rejects_unknown_sighash_type() {
        let mut checklist = test_checklist(0x0feb, 48);
        checklist.sighash_types_required = vec!["SIGHASH_FOO".to_string()];
        let mut req = test_request(vec![checklist]);
        req.core_ext_profiles = vec![test_profile()];
        let resp = run_txctx_governance_vector(&req);
        assert!(!resp.ok);
        assert_eq!(
            resp.err.as_deref(),
            Some(TXCTX_GOVERNANCE_ERR_INVALID_CHECKLIST)
        );
    }
}
