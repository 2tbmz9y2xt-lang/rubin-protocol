use crate::compactsize::{encode_compact_size, read_compact_size_bytes};
use crate::constants::{MAX_COVENANT_DATA_PER_OUTPUT, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::live_binding_policy::{
    live_binding_policy_core_ext_entry, LiveBindingPolicyEntry, LiveBindingPolicyLookupError,
    LIVE_BINDING_POLICY_RUNTIME_OPENSSL_DIGEST32_V1,
};
use crate::txcontext::{TxContextBase, TxContextContinuing};

pub const CORE_EXT_BINDING_KIND_NATIVE_ONLY: u8 = 0x01;
pub const CORE_EXT_BINDING_KIND_VERIFY_SIG_EXT: u8 = 0x02;
pub const CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1: &str =
    "verify_sig_ext_openssl_digest32_v1";
const CORE_EXT_OPENSSL_DIGEST32_BINDING_DESCRIPTOR_PREFIX: &[u8] =
    b"RUBIN-CORE-EXT-VERIFY-SIG-OPENSSL-DIGEST32-v1";

pub type CoreExtVerifySigExtTxContextFn = fn(
    ext_id: u16,
    suite_id: u8,
    pubkey: &[u8],
    signature: &[u8],
    digest32: &[u8; 32],
    ext_payload: &[u8],
    ctx_base: &TxContextBase,
    ctx_continuing: &TxContextContinuing,
    self_input_value: u64,
) -> Result<bool, TxError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreExtCovenant<'a> {
    pub ext_id: u16,
    pub ext_payload: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreExtVerificationBinding {
    /// Verify via native `verify_sig` dispatch.
    NativeVerifySig,
    /// Deterministic test binding: `verify_sig_ext` accepts.
    VerifySigExtAccept,
    /// Deterministic test binding: `verify_sig_ext` returns false.
    VerifySigExtReject,
    /// Deterministic test binding: `verify_sig_ext` errors.
    VerifySigExtError,
    /// Activation-ready binding: verify digest32 with an OpenSSL-backed verifier.
    VerifySigExtOpenSslDigest32V1(CoreExtOpenSslDigest32BindingDescriptor),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreExtOpenSslDigest32BindingDescriptor {
    pub openssl_alg: String,
    pub pubkey_len: u64,
    pub sig_len: u64,
}

#[allow(unpredictable_function_pointer_comparisons)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreExtActiveProfile {
    pub ext_id: u16,
    pub tx_context_enabled: bool,
    pub allowed_suite_ids: Vec<u8>,
    pub verification_binding: CoreExtVerificationBinding,
    pub verify_sig_ext_tx_context_fn: Option<CoreExtVerifySigExtTxContextFn>,
    pub binding_descriptor: Vec<u8>,
    pub ext_payload_schema: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoreExtProfiles {
    pub active: Vec<CoreExtActiveProfile>,
}

#[allow(unpredictable_function_pointer_comparisons)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreExtDeploymentProfile {
    pub ext_id: u16,
    pub activation_height: u64,
    pub tx_context_enabled: bool,
    pub allowed_suite_ids: Vec<u8>,
    pub verification_binding: CoreExtVerificationBinding,
    pub verify_sig_ext_tx_context_fn: Option<CoreExtVerifySigExtTxContextFn>,
    pub binding_descriptor: Vec<u8>,
    pub ext_payload_schema: Vec<u8>,
    /// Governance nonce for replay protection. Incremented on each
    /// governance action (activate/deactivate/parameter change).
    /// Tokens issued with a previous nonce are rejected.
    ///
    /// `0` remains the only safe v1 default: `core_ext_profile_bytes_v1()`
    /// fail-closes on any non-zero nonce until the coordinated Go+Rust
    /// profile-bytes-v2 path exists.
    pub governance_nonce: u64,
}

/// GovernanceReplayToken binds a profile authorization to a specific
/// height window, preventing replay of governance actions across
/// activation/deactivation cycles.
///
/// A token is valid only when `current_height` falls within
/// `[issued_at_height, issued_at_height + validity_window)` AND
/// `nonce` matches the deployment's governance nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceReplayToken {
    pub ext_id: u16,
    pub nonce: u64,
    pub issued_at_height: u64,
    pub validity_window: u64,
}

const GOVERNANCE_REPLAY_TOKEN_BYTES: usize = 26;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GovernanceReplayTokenValidation {
    Valid,
    ExtIdMismatch,
    NonceMismatch,
    NotYetValid,
    Expired,
}

impl GovernanceReplayToken {
    /// Create a new replay token for the given profile deployment.
    pub fn issue(ext_id: u16, nonce: u64, current_height: u64, validity_window: u64) -> Self {
        Self {
            ext_id,
            nonce,
            issued_at_height: current_height,
            validity_window,
        }
    }

    /// Check whether this token is valid for the given ext_id at the given height and nonce.
    /// Returns Ok(()) if valid, Err with reason if not.
    pub fn validate(
        &self,
        expected_ext_id: u16,
        current_height: u64,
        expected_nonce: u64,
    ) -> Result<(), String> {
        match self.validation_outcome(expected_ext_id, current_height, expected_nonce) {
            GovernanceReplayTokenValidation::Valid => Ok(()),
            GovernanceReplayTokenValidation::ExtIdMismatch => Err(format!(
                "governance replay token ext_id mismatch: token={} expected={}",
                self.ext_id, expected_ext_id
            )),
            GovernanceReplayTokenValidation::NonceMismatch => Err(format!(
                "governance replay token nonce mismatch: token={} expected={}",
                self.nonce, expected_nonce
            )),
            GovernanceReplayTokenValidation::NotYetValid => Err(format!(
                "governance replay token not yet valid: issued_at={} current={}",
                self.issued_at_height, current_height
            )),
            GovernanceReplayTokenValidation::Expired => Err(format!(
                "governance replay token expired: expiry={} current={}",
                self.expiry_height(),
                current_height
            )),
        }
    }

    fn expiry_height(&self) -> u64 {
        // Tokens intentionally saturate to u64::MAX rather than wrapping so an
        // oversized validity window cannot become valid again after overflow.
        self.issued_at_height.saturating_add(self.validity_window)
    }

    fn validation_outcome(
        &self,
        expected_ext_id: u16,
        current_height: u64,
        expected_nonce: u64,
    ) -> GovernanceReplayTokenValidation {
        // Keep this check order canonical for any future multi-impl parity:
        // ext_id -> nonce -> issued_at -> expiry.
        if self.ext_id != expected_ext_id {
            return GovernanceReplayTokenValidation::ExtIdMismatch;
        }
        if self.nonce != expected_nonce {
            return GovernanceReplayTokenValidation::NonceMismatch;
        }
        if current_height < self.issued_at_height {
            return GovernanceReplayTokenValidation::NotYetValid;
        }
        if current_height >= self.expiry_height() {
            return GovernanceReplayTokenValidation::Expired;
        }
        GovernanceReplayTokenValidation::Valid
    }

    /// Serialize the token to a deterministic byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(26);
        out.extend_from_slice(&self.ext_id.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.issued_at_height.to_le_bytes());
        out.extend_from_slice(&self.validity_window.to_le_bytes());
        out
    }

    /// Deserialize a token from its byte representation.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() != GOVERNANCE_REPLAY_TOKEN_BYTES {
            return Err(format!(
                "governance replay token: expected 26 bytes, got {}",
                data.len()
            ));
        }
        let ext_id = u16::from_le_bytes([data[0], data[1]]);
        let nonce = read_replay_token_u64(data, 2)?;
        let issued_at_height = read_replay_token_u64(data, 10)?;
        let validity_window = read_replay_token_u64(data, 18)?;
        Ok(Self {
            ext_id,
            nonce,
            issued_at_height,
            validity_window,
        })
    }
}

fn read_replay_token_u64(data: &[u8], offset: usize) -> Result<u64, String> {
    let end = offset + 8;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| format!("governance replay token: truncated field at offset {offset}"))?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(raw))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoreExtDeploymentProfiles {
    pub deployments: Vec<CoreExtDeploymentProfile>,
}

impl CoreExtProfiles {
    pub fn empty() -> Self {
        Self { active: Vec::new() }
    }
}

impl CoreExtDeploymentProfiles {
    pub fn empty() -> Self {
        Self {
            deployments: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        for deployment in &self.deployments {
            if deployment.allowed_suite_ids.is_empty() {
                return Err(format!(
                    "core_ext deployment for ext_id={} must have non-empty allowed_suite_ids",
                    deployment.ext_id
                ));
            }
        }
        Ok(())
    }

    pub fn active_profiles_at_height(&self, height: u64) -> Result<CoreExtProfiles, TxError> {
        self.validate().map_err(|_| {
            TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "CORE_EXT active profile must have non-empty allowed_suite_ids",
            )
        })?;
        let mut active = Vec::new();
        for deployment in &self.deployments {
            if height < deployment.activation_height {
                continue;
            }
            if active
                .iter()
                .any(|profile: &CoreExtActiveProfile| profile.ext_id == deployment.ext_id)
            {
                return Err(TxError::new(
                    ErrorCode::TxErrCovenantTypeInvalid,
                    "CORE_EXT multiple ACTIVE profiles for ext_id",
                ));
            }
            active.push(CoreExtActiveProfile {
                ext_id: deployment.ext_id,
                tx_context_enabled: deployment.tx_context_enabled,
                allowed_suite_ids: deployment.allowed_suite_ids.clone(),
                verification_binding: deployment.verification_binding.clone(),
                verify_sig_ext_tx_context_fn: deployment.verify_sig_ext_tx_context_fn,
                binding_descriptor: deployment.binding_descriptor.clone(),
                ext_payload_schema: deployment.ext_payload_schema.clone(),
            });
        }
        Ok(CoreExtProfiles { active })
    }
}

fn normalized_allowed_suite_ids(ids: &[u8]) -> Vec<u8> {
    let mut out = ids.to_vec();
    out.sort_unstable();
    out.dedup();
    out
}

fn core_ext_binding_kind(profile: &CoreExtDeploymentProfile) -> Result<u8, String> {
    match profile.verification_binding {
        CoreExtVerificationBinding::NativeVerifySig => {
            if !profile.binding_descriptor.is_empty() {
                return Err(format!(
                    "core_ext profile ext_id={} native-only profile must not carry binding_descriptor",
                    profile.ext_id
                ));
            }
            Ok(CORE_EXT_BINDING_KIND_NATIVE_ONLY)
        }
        _ => {
            if profile.binding_descriptor.is_empty() {
                return Err(format!(
                    "core_ext profile ext_id={} verify_sig_ext profile must carry binding_descriptor",
                    profile.ext_id
                ));
            }
            Ok(CORE_EXT_BINDING_KIND_VERIFY_SIG_EXT)
        }
    }
}

pub fn core_ext_profile_bytes_v1(profile: &CoreExtDeploymentProfile) -> Result<Vec<u8>, String> {
    if profile.governance_nonce != 0 {
        return Err(format!(
            "core_ext profile ext_id={} governance_nonce={} requires v2 profile bytes (Go+Rust coordinated)",
            profile.ext_id, profile.governance_nonce
        ));
    }
    if profile.tx_context_enabled {
        return Err(format!(
            "core_ext profile ext_id={} txcontext-enabled profile requires v2 anchor pipeline",
            profile.ext_id
        ));
    }
    let allowed_suite_ids = normalized_allowed_suite_ids(&profile.allowed_suite_ids);
    if allowed_suite_ids.is_empty() {
        return Err(format!(
            "core_ext profile ext_id={} must have non-empty allowed_suite_ids",
            profile.ext_id
        ));
    }
    if profile.ext_payload_schema.is_empty() {
        return Err(format!(
            "core_ext profile ext_id={} must carry ext_payload_schema",
            profile.ext_id
        ));
    }
    let binding_kind = core_ext_binding_kind(profile)?;

    let mut out = b"RUBIN-CORE-EXT-PROFILE-v1".to_vec();
    out.extend_from_slice(&profile.ext_id.to_le_bytes());
    out.extend_from_slice(&profile.activation_height.to_le_bytes());
    encode_compact_size(allowed_suite_ids.len() as u64, &mut out);
    out.extend_from_slice(&allowed_suite_ids);
    out.push(binding_kind);
    encode_compact_size(profile.binding_descriptor.len() as u64, &mut out);
    out.extend_from_slice(&profile.binding_descriptor);
    encode_compact_size(profile.ext_payload_schema.len() as u64, &mut out);
    out.extend_from_slice(&profile.ext_payload_schema);
    // NOTE: governance_nonce is intentionally NOT included in v1 profile bytes.
    // Adding it here would break Go/Rust parity (Go CoreExtProfileBytesV1 does
    // not include it yet). Must be added to BOTH clients simultaneously in a
    // coordinated profile-bytes-v2 PR.
    Ok(out)
}

pub fn core_ext_profile_anchor_v1(profile: &CoreExtDeploymentProfile) -> Result<[u8; 32], String> {
    let mut preimage = b"RUBIN-CORE-EXT-PROFILE-ANCHOR-v1".to_vec();
    preimage.extend_from_slice(&core_ext_profile_bytes_v1(profile)?);
    Ok(sha3_256(&preimage))
}

pub fn core_ext_profile_set_anchor_v1(
    chain_id: [u8; 32],
    deployments: &[CoreExtDeploymentProfile],
) -> Result<[u8; 32], String> {
    let mut anchors = Vec::with_capacity(deployments.len());
    for deployment in deployments {
        anchors.push(core_ext_profile_anchor_v1(deployment)?);
    }
    anchors.sort_unstable();

    let mut preimage = b"RUBIN-CORE-EXT-PROFILE-SET-v1".to_vec();
    preimage.extend_from_slice(&chain_id);
    encode_compact_size(anchors.len() as u64, &mut preimage);
    for anchor in anchors {
        preimage.extend_from_slice(&anchor);
    }
    Ok(sha3_256(&preimage))
}

pub fn core_ext_verification_binding_from_name(
    binding_name: &str,
) -> Result<CoreExtVerificationBinding, String> {
    core_ext_verification_binding_from_name_and_descriptor(binding_name, &[], &[])
}

fn unsupported_core_ext_binding_error(binding_name: &str) -> String {
    format!("unsupported core_ext binding: {binding_name:?}")
}

fn supported_live_core_ext_policy_entry(
    binding_name: &str,
) -> Result<&'static LiveBindingPolicyEntry, String> {
    let entry = match live_binding_policy_core_ext_entry(binding_name) {
        Ok(entry) => entry,
        Err(LiveBindingPolicyLookupError::NotFound(_)) => {
            return Err(unsupported_core_ext_binding_error(binding_name));
        }
        Err(LiveBindingPolicyLookupError::Invalid(err)) => return Err(err),
    };
    match entry.runtime_binding.as_str() {
        LIVE_BINDING_POLICY_RUNTIME_OPENSSL_DIGEST32_V1 => Ok(entry),
        _ => Err(unsupported_core_ext_binding_error(binding_name)),
    }
}

pub fn normalize_core_ext_binding_name(binding_name: &str) -> Result<&'static str, String> {
    let binding_name = binding_name.trim();
    match binding_name {
        "" => Ok(""),
        "native_verify_sig" => Ok("native_verify_sig"),
        CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1 => {
            Ok(CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1)
        }
        _ => Err(unsupported_core_ext_binding_error(binding_name)),
    }
}

pub fn core_ext_verification_binding_from_name_and_descriptor(
    binding_name: &str,
    binding_descriptor: &[u8],
    ext_payload_schema: &[u8],
) -> Result<CoreExtVerificationBinding, String> {
    let binding_name = normalize_core_ext_binding_name(binding_name)?;
    core_ext_verification_binding_from_normalized_name_and_descriptor(
        binding_name,
        binding_descriptor,
        ext_payload_schema,
    )
}

pub fn core_ext_verification_binding_from_normalized_name_and_descriptor(
    binding_name: &str,
    binding_descriptor: &[u8],
    ext_payload_schema: &[u8],
) -> Result<CoreExtVerificationBinding, String> {
    match binding_name {
        "" | "native_verify_sig" => Ok(CoreExtVerificationBinding::NativeVerifySig),
        CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1 => {
            if ext_payload_schema.is_empty() {
                return Err(format!(
                    "core_ext binding {} requires ext_payload_schema_hex",
                    CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1
                ));
            }
            Ok(CoreExtVerificationBinding::VerifySigExtOpenSslDigest32V1(
                parse_core_ext_openssl_digest32_binding_descriptor(binding_descriptor)?,
            ))
        }
        _ => Err(unsupported_core_ext_binding_error(binding_name)),
    }
}

/// Live/runtime helper for callers that already normalized the binding through
/// `normalize_live_core_ext_binding_name` and still need fail-closed
/// ext_payload_schema enforcement on the active chain path.
pub fn live_core_ext_verification_binding_from_normalized_name_and_descriptor(
    binding_name: &str,
    binding_descriptor: &[u8],
    ext_payload_schema: &[u8],
) -> Result<CoreExtVerificationBinding, String> {
    let entry = supported_live_core_ext_policy_entry(binding_name)?;
    match entry.runtime_binding.as_str() {
        LIVE_BINDING_POLICY_RUNTIME_OPENSSL_DIGEST32_V1 => {
            core_ext_verification_binding_from_normalized_name_and_descriptor(
                entry.core_ext_live_binding_name.as_str(),
                binding_descriptor,
                ext_payload_schema,
            )
        }
        _ => Err(unsupported_core_ext_binding_error(binding_name)),
    }
}

pub fn normalize_live_core_ext_binding_name(binding_name: &str) -> Result<&'static str, String> {
    let binding_name = binding_name.trim();
    let entry = supported_live_core_ext_policy_entry(binding_name)?;
    Ok(entry.core_ext_live_binding_name.as_str())
}

pub fn live_core_ext_verification_binding_from_name_and_descriptor(
    binding_name: &str,
    binding_descriptor: &[u8],
    ext_payload_schema: &[u8],
) -> Result<CoreExtVerificationBinding, String> {
    let binding_name = normalize_live_core_ext_binding_name(binding_name)?;
    live_core_ext_verification_binding_from_normalized_name_and_descriptor(
        binding_name,
        binding_descriptor,
        ext_payload_schema,
    )
}

fn core_ext_supported_openssl_alg(openssl_alg: &str) -> Option<(u64, u64)> {
    match openssl_alg {
        "ML-DSA-87" => Some((ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)),
        _ => None,
    }
}

// OpenSSL digest32 binding descriptors remain valid for non-txcontext
// verify_sig_ext profiles. Once tx_context_enabled is active, both Go and Rust
// require a runtime txcontext verifier and fail closed if it is unavailable.
fn validate_core_ext_openssl_binding_descriptor(
    openssl_alg: &str,
    pubkey_len: u64,
    sig_len: u64,
) -> Result<(), String> {
    let Some((expected_pubkey_len, expected_sig_len)) = core_ext_supported_openssl_alg(openssl_alg)
    else {
        return Err(format!("unsupported core_ext OpenSSL alg: {openssl_alg}"));
    };
    if pubkey_len != expected_pubkey_len {
        return Err(format!(
            "core_ext OpenSSL binding pubkey length mismatch for {}: got {} want {}",
            openssl_alg, pubkey_len, expected_pubkey_len
        ));
    }
    if sig_len != expected_sig_len {
        return Err(format!(
            "core_ext OpenSSL binding sig length mismatch for {}: got {} want {}",
            openssl_alg, sig_len, expected_sig_len
        ));
    }
    Ok(())
}

pub fn core_ext_openssl_digest32_binding_descriptor_bytes(
    openssl_alg: &str,
    pubkey_len: u64,
    sig_len: u64,
) -> Result<Vec<u8>, String> {
    validate_core_ext_openssl_binding_descriptor(openssl_alg, pubkey_len, sig_len)?;
    let mut out = CORE_EXT_OPENSSL_DIGEST32_BINDING_DESCRIPTOR_PREFIX.to_vec();
    encode_compact_size(openssl_alg.len() as u64, &mut out);
    out.extend_from_slice(openssl_alg.as_bytes());
    encode_compact_size(pubkey_len, &mut out);
    encode_compact_size(sig_len, &mut out);
    Ok(out)
}

pub fn parse_core_ext_openssl_digest32_binding_descriptor(
    raw: &[u8],
) -> Result<CoreExtOpenSslDigest32BindingDescriptor, String> {
    if !raw.starts_with(CORE_EXT_OPENSSL_DIGEST32_BINDING_DESCRIPTOR_PREFIX) {
        return Err("bad core_ext binding_descriptor".to_string());
    }
    let mut off = CORE_EXT_OPENSSL_DIGEST32_BINDING_DESCRIPTOR_PREFIX.len();
    let (alg_len, alg_len_bytes) = read_compact_size_bytes(&raw[off..])
        .map_err(|_| "bad core_ext binding_descriptor".to_string())?;
    off += alg_len_bytes;
    let alg_len_usize =
        usize::try_from(alg_len).map_err(|_| "bad core_ext binding_descriptor".to_string())?;
    let end = off
        .checked_add(alg_len_usize)
        .ok_or_else(|| "bad core_ext binding_descriptor".to_string())?;
    if end > raw.len() {
        return Err("bad core_ext binding_descriptor".to_string());
    }
    let openssl_alg = std::str::from_utf8(&raw[off..end])
        .map_err(|_| "bad core_ext binding_descriptor".to_string())?
        .to_string();
    off = end;
    let (pubkey_len, pubkey_len_bytes) = read_compact_size_bytes(&raw[off..])
        .map_err(|_| "bad core_ext binding_descriptor".to_string())?;
    off += pubkey_len_bytes;
    let (sig_len, sig_len_bytes) = read_compact_size_bytes(&raw[off..])
        .map_err(|_| "bad core_ext binding_descriptor".to_string())?;
    off += sig_len_bytes;
    if off != raw.len() {
        return Err("bad core_ext binding_descriptor".to_string());
    }
    validate_core_ext_openssl_binding_descriptor(&openssl_alg, pubkey_len, sig_len)?;
    Ok(CoreExtOpenSslDigest32BindingDescriptor {
        openssl_alg,
        pubkey_len,
        sig_len,
    })
}

#[cfg(test)]
pub(crate) fn encode_core_ext_covenant_data(
    ext_id: u16,
    payload: &[u8],
) -> Result<Vec<u8>, TxError> {
    let mut out = Vec::with_capacity(2 + payload.len() + 10);
    out.extend_from_slice(&ext_id.to_le_bytes());
    encode_compact_size(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    if out.len() as u64 > MAX_COVENANT_DATA_PER_OUTPUT {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_EXT covenant_data length exceeds MAX_COVENANT_DATA_PER_OUTPUT",
        ));
    }
    Ok(out)
}

pub fn parse_core_ext_covenant_data(cov_data: &[u8]) -> Result<CoreExtCovenant<'_>, TxError> {
    let (ext_id, payload_start, expected_len) = parse_core_ext_covenant_header(cov_data)?;
    Ok(CoreExtCovenant {
        ext_id,
        ext_payload: &cov_data[payload_start..expected_len],
    })
}

fn core_ext_covenant_parse_error(msg: &'static str) -> TxError {
    TxError::new(ErrorCode::TxErrCovenantTypeInvalid, msg)
}

fn parse_core_ext_covenant_header(cov_data: &[u8]) -> Result<(u16, usize, usize), TxError> {
    if cov_data.len() as u64 > MAX_COVENANT_DATA_PER_OUTPUT {
        return Err(core_ext_covenant_parse_error(
            "CORE_EXT covenant_data length exceeds MAX_COVENANT_DATA_PER_OUTPUT",
        ));
    }
    if cov_data.len() < 2 {
        return Err(core_ext_covenant_parse_error(
            "CORE_EXT covenant_data too short",
        ));
    }
    let ext_id = u16::from_le_bytes([cov_data[0], cov_data[1]]);
    let (ext_payload_len, varint_bytes) = parse_core_ext_payload_len(cov_data)?;
    let expected_len = core_ext_expected_covenant_len(varint_bytes, ext_payload_len)?;
    if cov_data.len() != expected_len {
        let msg = if cov_data.len() < expected_len {
            "CORE_EXT covenant_data ext_payload parse failure"
        } else {
            "CORE_EXT covenant_data length mismatch"
        };
        return Err(core_ext_covenant_parse_error(msg));
    }

    Ok((ext_id, 2 + varint_bytes, expected_len))
}

fn parse_core_ext_payload_len(cov_data: &[u8]) -> Result<(usize, usize), TxError> {
    let (payload_len_u64, varint_bytes) =
        read_compact_size_bytes(&cov_data[2..]).map_err(|_| {
            core_ext_covenant_parse_error("CORE_EXT ext_payload_len CompactSize invalid")
        })?;
    #[cfg(target_pointer_width = "32")]
    if payload_len_u64 > usize::MAX as u64 {
        return Err(core_ext_covenant_parse_error(
            "CORE_EXT covenant_data ext_payload parse failure",
        ));
    }
    Ok((payload_len_u64 as usize, varint_bytes))
}

fn core_ext_expected_covenant_len(
    varint_bytes: usize,
    payload_len: usize,
) -> Result<usize, TxError> {
    2usize
        .checked_add(varint_bytes)
        .and_then(|v| v.checked_add(payload_len))
        .ok_or_else(|| {
            core_ext_covenant_parse_error("CORE_EXT covenant_data ext_payload parse failure")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compactsize::encode_compact_size;
    use crate::constants::{ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES};

    fn core_ext_covdata(ext_id: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ext_id.to_le_bytes());
        encode_compact_size(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }

    fn deployment_profile(
        allowed_suite_ids: Vec<u8>,
        verification_binding: CoreExtVerificationBinding,
        binding_descriptor: Vec<u8>,
        tx_context_enabled: bool,
    ) -> CoreExtDeploymentProfile {
        CoreExtDeploymentProfile {
            ext_id: 7,
            activation_height: 1,
            tx_context_enabled,
            allowed_suite_ids,
            verification_binding,
            verify_sig_ext_tx_context_fn: None,
            binding_descriptor,
            ext_payload_schema: b"schema-a".to_vec(),
            governance_nonce: 0,
        }
    }

    fn openssl_digest32_descriptor() -> (Vec<u8>, CoreExtOpenSslDigest32BindingDescriptor) {
        let bytes = core_ext_openssl_digest32_binding_descriptor_bytes(
            "ML-DSA-87",
            ML_DSA_87_PUBKEY_BYTES,
            ML_DSA_87_SIG_BYTES,
        )
        .expect("descriptor");
        let descriptor = parse_core_ext_openssl_digest32_binding_descriptor(&bytes).expect("parse");
        (bytes, descriptor)
    }

    #[test]
    fn core_ext_openssl_digest32_binding_descriptor_round_trip() {
        let raw = core_ext_openssl_digest32_binding_descriptor_bytes(
            "ML-DSA-87",
            ML_DSA_87_PUBKEY_BYTES,
            ML_DSA_87_SIG_BYTES,
        )
        .expect("descriptor");
        let desc = parse_core_ext_openssl_digest32_binding_descriptor(&raw).expect("parse");
        assert_eq!(desc.openssl_alg, "ML-DSA-87");
        assert_eq!(desc.pubkey_len, ML_DSA_87_PUBKEY_BYTES);
        assert_eq!(desc.sig_len, ML_DSA_87_SIG_BYTES);
    }

    #[test]
    fn core_ext_deployments_activate_at_height() {
        let deployments = CoreExtDeploymentProfiles {
            deployments: vec![CoreExtDeploymentProfile {
                ext_id: 7,
                activation_height: 10,
                tx_context_enabled: true,
                allowed_suite_ids: vec![0x03],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
                governance_nonce: 0,
            }],
        };

        let before = deployments.active_profiles_at_height(9).unwrap();
        assert!(before.active.is_empty());

        let active = deployments.active_profiles_at_height(10).unwrap();
        assert_eq!(active.active.len(), 1);
        assert_eq!(active.active[0].ext_id, 7);
        assert!(active.active[0].tx_context_enabled);
    }

    #[test]
    fn core_ext_deployments_empty_allowed_suite_ids_rejected_at_activation_lookup() {
        let deployments = CoreExtDeploymentProfiles {
            deployments: vec![CoreExtDeploymentProfile {
                ext_id: 7,
                activation_height: 10,
                tx_context_enabled: false,
                allowed_suite_ids: Vec::new(),
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: Vec::new(),
                ext_payload_schema: b"schema".to_vec(),
                governance_nonce: 0,
            }],
        };

        let err = deployments.active_profiles_at_height(10).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    #[test]
    fn core_ext_deployments_duplicate_active_rejected() {
        let deployments = CoreExtDeploymentProfiles {
            deployments: vec![
                CoreExtDeploymentProfile {
                    ext_id: 7,
                    activation_height: 0,
                    tx_context_enabled: false,
                    allowed_suite_ids: vec![0x03],
                    verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                    verify_sig_ext_tx_context_fn: None,
                    binding_descriptor: b"accept".to_vec(),
                    ext_payload_schema: b"schema-a".to_vec(),
                    governance_nonce: 0,
                },
                CoreExtDeploymentProfile {
                    ext_id: 7,
                    activation_height: 0,
                    tx_context_enabled: false,
                    allowed_suite_ids: vec![0x04],
                    verification_binding: CoreExtVerificationBinding::VerifySigExtReject,
                    verify_sig_ext_tx_context_fn: None,
                    binding_descriptor: b"reject".to_vec(),
                    ext_payload_schema: b"schema-b".to_vec(),
                    governance_nonce: 0,
                },
            ],
        };

        let err = deployments.active_profiles_at_height(0).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    #[test]
    fn core_ext_profile_set_anchor_changes_with_payload_schema() {
        let chain_id = [0x42; 32];
        let mut base = CoreExtDeploymentProfile {
            ext_id: 7,
            activation_height: 1,
            tx_context_enabled: false,
            allowed_suite_ids: vec![3],
            verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
            verify_sig_ext_tx_context_fn: None,
            binding_descriptor: b"accept".to_vec(),
            ext_payload_schema: b"schema-a".to_vec(),
            governance_nonce: 0,
        };
        let base_anchor =
            core_ext_profile_set_anchor_v1(chain_id, &[base.clone()]).expect("base anchor");
        base.ext_payload_schema = b"schema-b".to_vec();
        let changed_anchor =
            core_ext_profile_set_anchor_v1(chain_id, &[base]).expect("changed anchor");
        assert_ne!(base_anchor, changed_anchor);
    }

    #[test]
    fn core_ext_profile_set_anchor_changes_with_activation_height() {
        let chain_id = [0x42; 32];
        let mut base = CoreExtDeploymentProfile {
            ext_id: 7,
            activation_height: 1,
            tx_context_enabled: false,
            allowed_suite_ids: vec![3],
            verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
            verify_sig_ext_tx_context_fn: None,
            binding_descriptor: b"accept".to_vec(),
            ext_payload_schema: b"schema-a".to_vec(),
            governance_nonce: 0,
        };
        let base_anchor =
            core_ext_profile_set_anchor_v1(chain_id, &[base.clone()]).expect("base anchor");
        base.activation_height = 2;
        let changed_anchor =
            core_ext_profile_set_anchor_v1(chain_id, &[base]).expect("changed anchor");
        assert_ne!(base_anchor, changed_anchor);
    }

    #[test]
    fn core_ext_profile_bytes_v1_native_binding_succeeds_without_descriptor() {
        let profile = CoreExtDeploymentProfile {
            ext_id: 7,
            activation_height: 1,
            tx_context_enabled: false,
            allowed_suite_ids: vec![3],
            verification_binding: CoreExtVerificationBinding::NativeVerifySig,
            verify_sig_ext_tx_context_fn: None,
            binding_descriptor: Vec::new(),
            ext_payload_schema: b"schema-a".to_vec(),
            governance_nonce: 0,
        };

        let bytes = core_ext_profile_bytes_v1(&profile).expect("native profile bytes");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn core_ext_profile_bytes_v1_rejects_invalid_profiles() {
        macro_rules! assert_profile_err {
            ($allowed:expr, $binding:expr, $descriptor:expr, $txctx:expr, $expected:expr) => {{
                let profile = deployment_profile($allowed, $binding, $descriptor, $txctx);
                let err = core_ext_profile_bytes_v1(&profile).unwrap_err();
                assert!(err.contains($expected), "{err}");
            }};
        }
        assert_profile_err!(
            Vec::new(),
            CoreExtVerificationBinding::NativeVerifySig,
            Vec::new(),
            false,
            "must have non-empty allowed_suite_ids"
        );
        assert_profile_err!(
            vec![3],
            CoreExtVerificationBinding::NativeVerifySig,
            vec![0xa1],
            false,
            "native-only profile must not carry binding_descriptor"
        );
        assert_profile_err!(
            vec![3],
            CoreExtVerificationBinding::VerifySigExtAccept,
            Vec::new(),
            false,
            "verify_sig_ext profile must carry binding_descriptor"
        );
        assert_profile_err!(
            vec![3],
            CoreExtVerificationBinding::NativeVerifySig,
            Vec::new(),
            true,
            "txcontext-enabled profile requires v2 anchor pipeline"
        );
    }

    #[test]
    fn core_ext_verification_binding_name_helper_covers_native_and_unsupported() {
        for binding in [
            core_ext_verification_binding_from_name("").expect("native empty"),
            core_ext_verification_binding_from_name(" native_verify_sig \n").expect("native named"),
            core_ext_verification_binding_from_normalized_name_and_descriptor("", &[], &[])
                .expect("normalized empty native"),
            core_ext_verification_binding_from_normalized_name_and_descriptor(
                "native_verify_sig",
                &[],
                &[],
            )
            .expect("normalized native alias"),
        ] {
            assert!(matches!(
                binding,
                CoreExtVerificationBinding::NativeVerifySig
            ));
        }

        let (descriptor, _) = openssl_digest32_descriptor();
        let openssl = core_ext_verification_binding_from_name_and_descriptor(
            &format!("  {CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1}\n"),
            &descriptor,
            &[0xb2],
        )
        .expect("openssl binding");
        assert!(matches!(
            openssl,
            CoreExtVerificationBinding::VerifySigExtOpenSslDigest32V1(_)
        ));

        let err = core_ext_verification_binding_from_name_and_descriptor(
            CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1,
            &descriptor,
            &[],
        )
        .expect_err("missing schema must fail");
        assert_eq!(
            err,
            format!(
                "core_ext binding {} requires ext_payload_schema_hex",
                CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1
            )
        );
        let err =
            core_ext_verification_binding_from_name("unsupported").expect_err("unsupported bind");
        assert!(err.contains("unsupported core_ext binding"));
    }

    #[test]
    fn live_core_ext_binding_helper_rejects_non_manifest_bindings() {
        let padded = format!("  {CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1}\n");
        let normalized = normalize_live_core_ext_binding_name(&padded).expect("valid live binding");
        assert_eq!(
            normalized,
            CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1
        );

        macro_rules! assert_normalize_rejects {
            ($name:expr) => {{
                let err =
                    normalize_live_core_ext_binding_name($name).expect_err("non-live must fail");
                assert!(err.contains("unsupported core_ext binding"), "{err}");
            }};
        }
        assert_normalize_rejects!("");
        assert_normalize_rejects!(" native_verify_sig ");
    }

    #[test]
    fn live_core_ext_binding_helper_accepts_openssl_and_rejects_non_live_names() {
        let padded = format!("  {CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1}\n");
        let (descriptor, _) = openssl_digest32_descriptor();
        macro_rules! assert_openssl {
            ($binding:expr) => {{
                assert!(matches!(
                    $binding,
                    CoreExtVerificationBinding::VerifySigExtOpenSslDigest32V1(_)
                ));
            }};
        }
        assert_openssl!(live_core_ext_verification_binding_from_name_and_descriptor(
            &padded,
            &descriptor,
            &[0xb2]
        )
        .expect("live binding"));
        assert_openssl!(
            live_core_ext_verification_binding_from_normalized_name_and_descriptor(
                CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1,
                &descriptor,
                &[0xb2],
            )
            .expect("normalized live binding")
        );
        for name in ["", "native_verify_sig"] {
            let err = live_core_ext_verification_binding_from_normalized_name_and_descriptor(
                name,
                &descriptor,
                &[0xb2],
            )
            .expect_err("normalized non-live binding must fail");
            assert_eq!(err, unsupported_core_ext_binding_error(name));
        }
    }

    #[test]
    fn live_core_ext_binding_helper_rejects_missing_schema() {
        let (descriptor, _) = openssl_digest32_descriptor();
        let err = live_core_ext_verification_binding_from_name_and_descriptor(
            CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1,
            &descriptor,
            &[],
        )
        .expect_err("missing schema must fail on live path");
        assert_eq!(
            err,
            format!(
                "core_ext binding {} requires ext_payload_schema_hex",
                CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1
            )
        );
    }

    #[test]
    fn core_ext_binding_descriptor_validation_errors() {
        let err = core_ext_openssl_digest32_binding_descriptor_bytes(
            "bad",
            ML_DSA_87_PUBKEY_BYTES,
            ML_DSA_87_SIG_BYTES,
        )
        .expect_err("unsupported alg");
        assert!(err.contains("unsupported core_ext OpenSSL alg"));

        let err = core_ext_openssl_digest32_binding_descriptor_bytes(
            "ML-DSA-87",
            ML_DSA_87_PUBKEY_BYTES - 1,
            ML_DSA_87_SIG_BYTES,
        )
        .expect_err("pubkey mismatch");
        assert!(err.contains("pubkey length mismatch"));

        let err = core_ext_openssl_digest32_binding_descriptor_bytes(
            "ML-DSA-87",
            ML_DSA_87_PUBKEY_BYTES,
            ML_DSA_87_SIG_BYTES - 1,
        )
        .expect_err("sig mismatch");
        assert!(err.contains("sig length mismatch"));
    }

    #[test]
    fn parse_core_ext_binding_descriptor_rejects_malformed_inputs() {
        let err = parse_core_ext_openssl_digest32_binding_descriptor(b"bad")
            .expect_err("bad prefix must fail");
        assert_eq!(err, "bad core_ext binding_descriptor");

        let truncated = CORE_EXT_OPENSSL_DIGEST32_BINDING_DESCRIPTOR_PREFIX.to_vec();
        let err = parse_core_ext_openssl_digest32_binding_descriptor(&truncated)
            .expect_err("missing alg len must fail");
        assert_eq!(err, "bad core_ext binding_descriptor");

        let mut bad_alg = CORE_EXT_OPENSSL_DIGEST32_BINDING_DESCRIPTOR_PREFIX.to_vec();
        encode_compact_size(5, &mut bad_alg);
        bad_alg.extend_from_slice(b"x");
        let err = parse_core_ext_openssl_digest32_binding_descriptor(&bad_alg)
            .expect_err("truncated alg must fail");
        assert_eq!(err, "bad core_ext binding_descriptor");

        let mut trailing = core_ext_openssl_digest32_binding_descriptor_bytes(
            "ML-DSA-87",
            ML_DSA_87_PUBKEY_BYTES,
            ML_DSA_87_SIG_BYTES,
        )
        .expect("descriptor");
        trailing.push(0);
        let err = parse_core_ext_openssl_digest32_binding_descriptor(&trailing)
            .expect_err("trailing bytes must fail");
        assert_eq!(err, "bad core_ext binding_descriptor");
    }

    // --- GovernanceReplayToken tests ---

    #[test]
    fn governance_replay_token_issue_and_validate() {
        let token = GovernanceReplayToken::issue(7, 1, 100, 50);
        assert!(token.validate(7, 100, 1).is_ok());
        assert!(token.validate(7, 149, 1).is_ok());
    }

    #[test]
    fn governance_replay_token_rejects_wrong_nonce() {
        let token = GovernanceReplayToken::issue(7, 1, 100, 50);
        let err = token.validate(7, 120, 2).unwrap_err();
        assert!(err.contains("nonce mismatch"));
    }

    #[test]
    fn governance_replay_token_rejects_wrong_ext_id() {
        let token = GovernanceReplayToken::issue(7, 1, 100, 50);
        let err = token.validate(9, 120, 1).unwrap_err();
        assert!(err.contains("ext_id mismatch"));
    }

    #[test]
    fn governance_replay_token_rejects_before_issued() {
        let token = GovernanceReplayToken::issue(7, 1, 100, 50);
        let err = token.validate(7, 99, 1).unwrap_err();
        assert!(err.contains("not yet valid"));
    }

    #[test]
    fn governance_replay_token_rejects_expired() {
        let token = GovernanceReplayToken::issue(7, 1, 100, 50);
        let err = token.validate(7, 150, 1).unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn governance_replay_token_boundary_at_expiry() {
        let token = GovernanceReplayToken::issue(7, 1, 100, 1);
        // height=100 is valid (issued_at)
        assert!(token.validate(7, 100, 1).is_ok());
        // height=101 is expired (100 + 1 = 101)
        let err = token.validate(7, 101, 1).unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn governance_replay_token_roundtrip_bytes() {
        let token = GovernanceReplayToken::issue(42, 7, 1000, 500);
        let bytes = token.to_bytes();
        assert_eq!(bytes.len(), 26);
        let recovered = GovernanceReplayToken::from_bytes(&bytes).unwrap();
        assert_eq!(token, recovered);
    }

    #[test]
    fn governance_replay_token_from_bytes_rejects_wrong_len() {
        let err = GovernanceReplayToken::from_bytes(&[0u8; 10]).unwrap_err();
        assert!(err.contains("expected 26 bytes"));
    }

    #[test]
    fn governance_replay_token_overflow_safe() {
        // validity_window = u64::MAX should not panic and should saturate.
        let token = GovernanceReplayToken::issue(1, 1, u64::MAX - 10, u64::MAX);
        assert!(token.validate(1, u64::MAX - 5, 1).is_ok());
        let err = token.validate(1, u64::MAX, 1).unwrap_err();
        assert!(err.contains("expired: expiry=18446744073709551615"));
    }

    #[test]
    fn governance_replay_token_expiry_saturates_instead_of_wrapping() {
        let token = GovernanceReplayToken::issue(9, 2, u64::MAX - 1, 50);
        assert!(token.validate(9, u64::MAX - 1, 2).is_ok());
        let err = token.validate(9, u64::MAX, 2).unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn governance_replay_token_from_bytes_accepts_exact_26_byte_payload() {
        let token = GovernanceReplayToken::issue(5, 8, 13, 21);
        let recovered = GovernanceReplayToken::from_bytes(&token.to_bytes()).unwrap();
        assert_eq!(recovered, token);
    }

    #[test]
    fn governance_replay_token_nonce_zero_is_allowed_for_v1_fail_closed_paths() {
        let token = GovernanceReplayToken::issue(7, 0, 100, 25);
        assert!(token.validate(7, 110, 0).is_ok());
    }

    #[test]
    fn governance_replay_token_zero_window_is_immediately_expired() {
        let token = GovernanceReplayToken::issue(7, 1, 100, 0);
        let err = token.validate(7, 100, 1).unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn governance_replay_token_validation_order_is_ext_nonce_issued_expiry() {
        let token = GovernanceReplayToken::issue(7, 1, 100, 0);

        let err = token.validate(9, 50, 2).unwrap_err();
        assert!(err.contains("ext_id mismatch"));

        let err = token.validate(7, 50, 2).unwrap_err();
        assert!(err.contains("nonce mismatch"));

        let err = token.validate(7, 99, 1).unwrap_err();
        assert!(err.contains("not yet valid"));

        let err = token.validate(7, 100, 1).unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn parse_core_ext_covenant_data_rejects_huge_payload_len_without_panicking() {
        let cov_data = [
            0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00,
        ];

        let err = parse_core_ext_covenant_data(&cov_data).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
        assert_eq!(err.msg, "CORE_EXT covenant_data ext_payload parse failure");
    }

    #[test]
    fn parse_core_ext_covenant_data_rejects_trailing_bytes() {
        let cov_data = [0x34, 0x12, 0x01, 0xaa, 0xbb];

        let err = parse_core_ext_covenant_data(&cov_data).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
        assert_eq!(err.msg, "CORE_EXT covenant_data length mismatch");
    }

    #[test]
    fn parse_core_ext_covenant_data_rejects_oversized_buffer() {
        let mut cov_data = vec![0x34, 0x12, 0x00];
        cov_data.resize(MAX_COVENANT_DATA_PER_OUTPUT as usize + 1, 0x00);

        let err = parse_core_ext_covenant_data(&cov_data).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
        assert_eq!(
            err.msg,
            "CORE_EXT covenant_data length exceeds MAX_COVENANT_DATA_PER_OUTPUT"
        );
    }

    #[test]
    fn parse_core_ext_covenant_data_pins_success_and_error_order() {
        macro_rules! assert_parse_ok {
            ($data:expr, $expected_ext_id:expr, $expected_payload:expr) => {{
                let data = $data;
                let expected_payload: &[u8] = $expected_payload;
                let parsed = parse_core_ext_covenant_data(&data).expect("valid covenant_data");
                assert_eq!(parsed.ext_id, $expected_ext_id);
                assert_eq!(parsed.ext_payload, expected_payload);
            }};
        }
        macro_rules! assert_parse_err {
            ($data:expr, $expected:expr) => {{
                let data = $data;
                let err = parse_core_ext_covenant_data(&data).unwrap_err();
                assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
                assert_eq!(err.msg, $expected);
            }};
        }
        assert_parse_ok!(core_ext_covdata(7, &[]), 7, &[]);
        assert_parse_ok!(core_ext_covdata(8, &[0xab]), 8, &[0xab]);
        assert_parse_err!(vec![0x07], "CORE_EXT covenant_data too short");
        assert_parse_err!(
            vec![0x07, 0x00, 0xfd],
            "CORE_EXT ext_payload_len CompactSize invalid"
        );
        assert_parse_err!(
            vec![0x07, 0x00, 0x02, 0xaa],
            "CORE_EXT covenant_data ext_payload parse failure"
        );
        assert_parse_err!(
            vec![0x07, 0x00, 0x00, 0xaa],
            "CORE_EXT covenant_data length mismatch"
        );
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn verify_parse_core_ext_covenant_data_accepts_empty_payload() {
        let ext_id: u16 = kani::any();
        let mut cov_data = Vec::with_capacity(3);
        cov_data.extend_from_slice(&ext_id.to_le_bytes());
        cov_data.push(0); // CompactSize(0)

        let parsed = parse_core_ext_covenant_data(&cov_data);
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else {
            return;
        };
        assert_eq!(parsed.ext_id, ext_id);
        assert!(parsed.ext_payload.is_empty());
    }

    #[kani::proof]
    fn verify_parse_core_ext_covenant_data_accepts_single_byte_payload() {
        let ext_id: u16 = kani::any();
        let payload_byte: u8 = kani::any();
        let mut cov_data = Vec::with_capacity(4);
        cov_data.extend_from_slice(&ext_id.to_le_bytes());
        cov_data.push(1); // CompactSize(1)
        cov_data.push(payload_byte);

        let parsed = parse_core_ext_covenant_data(&cov_data);
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else {
            return;
        };
        assert_eq!(parsed.ext_id, ext_id);
        assert_eq!(parsed.ext_payload, &[payload_byte]);
    }

    #[kani::proof]
    fn verify_parse_core_ext_covenant_data_rejects_truncated_payload() {
        let ext_id: u16 = kani::any();
        let mut cov_data = Vec::with_capacity(4);
        cov_data.extend_from_slice(&ext_id.to_le_bytes());
        cov_data.push(2); // CompactSize(2)
        cov_data.push(0xaa); // only one payload byte present

        let parsed = parse_core_ext_covenant_data(&cov_data);
        assert!(parsed.is_err());
        let Err(err) = parsed else {
            return;
        };
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    #[kani::proof]
    fn verify_governance_replay_token_roundtrip_bytes() {
        let ext_id: u16 = kani::any();
        let nonce: u64 = kani::any();
        let issued_at_height: u64 = kani::any();
        let validity_window: u64 = kani::any();

        let token = GovernanceReplayToken::issue(ext_id, nonce, issued_at_height, validity_window);
        let bytes = token.to_bytes();
        assert_eq!(bytes.len(), GOVERNANCE_REPLAY_TOKEN_BYTES);

        let parsed = GovernanceReplayToken::from_bytes(&bytes);
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else {
            return;
        };
        assert_eq!(parsed, token);
    }

    #[kani::proof]
    fn verify_governance_replay_token_validate_rejects_wrong_nonce() {
        let token = GovernanceReplayToken::issue(7, 1, 100, 50);
        assert_eq!(
            token.validation_outcome(7, 100, 2),
            GovernanceReplayTokenValidation::NonceMismatch
        );
    }

    #[kani::proof]
    fn verify_governance_replay_token_validate_rejects_expired_boundary() {
        let token = GovernanceReplayToken::issue(7, 1, 100, 1);
        assert_eq!(
            token.validation_outcome(7, 101, 1),
            GovernanceReplayTokenValidation::Expired
        );
    }
}
