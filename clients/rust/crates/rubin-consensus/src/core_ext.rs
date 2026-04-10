use crate::compactsize::{encode_compact_size, read_compact_size_bytes};
use crate::constants::{
    MAX_COVENANT_DATA_PER_OUTPUT, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_SENTINEL,
};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::sig_queue::{queue_or_verify_signature, SigCheckQueue};
use crate::sighash::{is_valid_sighash_type, sighash_v1_digest_with_cache, SighashV1PrehashCache};
use crate::spend_verify::extract_crypto_sig_and_sighash;
use crate::suite_registry::{DefaultRotationProvider, RotationProvider, SuiteRegistry};
use crate::tx::Tx;
use crate::tx::WitnessItem;
use crate::txcontext::{TxContextBase, TxContextBundle, TxContextContinuing};
use crate::utxo_basic::UtxoEntry;
use crate::verify_sig_openssl::openssl_verify_sig_digest_oneshot;
use core::ffi::CStr;
use std::sync::OnceLock;

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

fn default_suite_registry() -> &'static SuiteRegistry {
    static DEFAULT_SUITE_REGISTRY: OnceLock<SuiteRegistry> = OnceLock::new();
    DEFAULT_SUITE_REGISTRY.get_or_init(SuiteRegistry::default_registry)
}

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

    pub(crate) fn lookup_active_profile(
        &self,
        ext_id: u16,
    ) -> Result<Option<&CoreExtActiveProfile>, TxError> {
        let mut found: Option<&CoreExtActiveProfile> = None;
        for p in &self.active {
            if p.ext_id != ext_id {
                continue;
            }
            if found.is_some() {
                return Err(TxError::new(
                    ErrorCode::TxErrCovenantTypeInvalid,
                    "CORE_EXT multiple ACTIVE profiles for ext_id",
                ));
            }
            found = Some(p);
        }
        Ok(found)
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
    core_ext_verification_binding_from_name_and_descriptor(binding_name, &[])
}

pub fn normalize_core_ext_binding_name(binding_name: &str) -> Result<&'static str, String> {
    let binding_name = binding_name.trim();
    match binding_name {
        "" => Ok(""),
        "native_verify_sig" => Ok("native_verify_sig"),
        CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1 => {
            Ok(CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1)
        }
        _ => Err(format!("unsupported core_ext binding: {binding_name:?}")),
    }
}

pub fn core_ext_verification_binding_from_name_and_descriptor(
    binding_name: &str,
    binding_descriptor: &[u8],
) -> Result<CoreExtVerificationBinding, String> {
    let binding_name = normalize_core_ext_binding_name(binding_name)?;
    match binding_name {
        "" | "native_verify_sig" => Ok(CoreExtVerificationBinding::NativeVerifySig),
        CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1 => {
            Ok(CoreExtVerificationBinding::VerifySigExtOpenSslDigest32V1(
                parse_core_ext_openssl_digest32_binding_descriptor(binding_descriptor)?,
            ))
        }
        _ => Err(format!("unsupported core_ext binding: {binding_name:?}")),
    }
}

pub fn normalize_live_core_ext_binding_name(binding_name: &str) -> Result<&'static str, String> {
    let binding_name = normalize_core_ext_binding_name(binding_name)?;
    match binding_name {
        CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1 => {
            Ok(CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1)
        }
        _ => Err(format!("unsupported core_ext binding: {binding_name:?}")),
    }
}

pub fn live_core_ext_verification_binding_from_name_and_descriptor(
    binding_name: &str,
    binding_descriptor: &[u8],
    ext_payload_schema: &[u8],
) -> Result<CoreExtVerificationBinding, String> {
    let binding_name = normalize_live_core_ext_binding_name(binding_name)?;
    if ext_payload_schema.is_empty() {
        return Err(format!(
            "core_ext binding {} requires ext_payload_schema_hex",
            CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1
        ));
    }
    core_ext_verification_binding_from_name_and_descriptor(binding_name, binding_descriptor)
}

fn core_ext_supported_openssl_alg(openssl_alg: &str) -> Option<(u64, u64)> {
    match openssl_alg {
        "ML-DSA-87" => Some((ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)),
        _ => None,
    }
}

fn run_core_ext_verify_sig_ext_binding(
    binding: &CoreExtVerificationBinding,
    pubkey: &[u8],
    crypto_sig: &[u8],
    digest32: &[u8; 32],
) -> Result<(), TxError> {
    match binding {
        CoreExtVerificationBinding::NativeVerifySig => Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_EXT native verifier binding unsupported on verify_sig_ext path",
        )),
        CoreExtVerificationBinding::VerifySigExtAccept => Ok(()),
        CoreExtVerificationBinding::VerifySigExtReject => Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "CORE_EXT signature invalid",
        )),
        CoreExtVerificationBinding::VerifySigExtError => Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_EXT verify_sig_ext error",
        )),
        CoreExtVerificationBinding::VerifySigExtOpenSslDigest32V1(descriptor) => {
            match verify_core_ext_openssl_digest32_binding(descriptor, pubkey, crypto_sig, digest32)
            {
                Ok(true) => Ok(()),
                Ok(false) => Err(TxError::new(
                    ErrorCode::TxErrSigInvalid,
                    "CORE_EXT signature invalid",
                )),
                Err(_) => Err(TxError::new(
                    ErrorCode::TxErrSigAlgInvalid,
                    "CORE_EXT verify_sig_ext error",
                )),
            }
        }
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

fn core_ext_openssl_alg_cstr(openssl_alg: &str) -> Result<&'static CStr, TxError> {
    match openssl_alg {
        "ML-DSA-87" => Ok(c"ML-DSA-87"),
        _ => Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_EXT verify_sig_ext unsupported OpenSSL alg",
        )),
    }
}

fn verify_core_ext_openssl_digest32_binding(
    descriptor: &CoreExtOpenSslDigest32BindingDescriptor,
    pubkey: &[u8],
    signature: &[u8],
    digest32: &[u8; 32],
) -> Result<bool, TxError> {
    #[cfg(target_pointer_width = "32")]
    if descriptor.pubkey_len > usize::MAX as u64 || descriptor.sig_len > usize::MAX as u64 {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_EXT verify_sig_ext unsupported OpenSSL binding",
        ));
    }
    if pubkey.len() as u64 != descriptor.pubkey_len || signature.len() as u64 != descriptor.sig_len
    {
        return Ok(false);
    }
    crate::verify_sig_openssl::ensure_openssl_consensus_init()?;
    let alg = core_ext_openssl_alg_cstr(&descriptor.openssl_alg)?;
    openssl_verify_sig_digest_oneshot(alg, pubkey, signature, digest32)
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
    if cov_data.len() as u64 > MAX_COVENANT_DATA_PER_OUTPUT {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_EXT covenant_data length exceeds MAX_COVENANT_DATA_PER_OUTPUT",
        ));
    }
    if cov_data.len() < 2 {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_EXT covenant_data too short",
        ));
    }
    let ext_id = u16::from_le_bytes(
        cov_data[0..2]
            .try_into()
            .expect("cov_data[0..2] is 2 bytes"),
    );

    let (ext_payload_len_u64, varint_bytes) =
        read_compact_size_bytes(&cov_data[2..]).map_err(|_| {
            TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "CORE_EXT ext_payload_len CompactSize invalid",
            )
        })?;
    #[cfg(target_pointer_width = "32")]
    if ext_payload_len_u64 > usize::MAX as u64 {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_EXT covenant_data ext_payload parse failure",
        ));
    }
    let ext_payload_len = ext_payload_len_u64 as usize;
    let expected_len = 2usize
        .checked_add(varint_bytes)
        .and_then(|v| v.checked_add(ext_payload_len))
        .ok_or_else(|| {
            TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "CORE_EXT covenant_data ext_payload parse failure",
            )
        })?;
    if cov_data.len() != expected_len {
        let msg = if cov_data.len() < expected_len {
            "CORE_EXT covenant_data ext_payload parse failure"
        } else {
            "CORE_EXT covenant_data length mismatch"
        };
        return Err(TxError::new(ErrorCode::TxErrCovenantTypeInvalid, msg));
    }
    let payload_start = 2 + varint_bytes;
    let ext_payload = &cov_data[payload_start..expected_len];

    Ok(CoreExtCovenant {
        ext_id,
        ext_payload,
    })
}

pub fn validate_core_ext_spend(
    entry: &UtxoEntry,
    w: &WitnessItem,
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    profiles_at_height: &CoreExtProfiles,
) -> Result<(), TxError> {
    let mut cache = SighashV1PrehashCache::new(tx)?;
    validate_core_ext_spend_with_cache_and_suite_context(
        entry,
        w,
        tx,
        input_index,
        input_value,
        chain_id,
        0,
        profiles_at_height,
        None,
        None,
        None,
        &mut cache,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn validate_core_ext_spend_at_height(
    entry: &UtxoEntry,
    w: &WitnessItem,
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    profiles_at_height: &CoreExtProfiles,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
) -> Result<(), TxError> {
    let mut cache = SighashV1PrehashCache::new(tx)?;
    validate_core_ext_spend_with_cache_and_suite_context(
        entry,
        w,
        tx,
        input_index,
        input_value,
        chain_id,
        block_height,
        profiles_at_height,
        rotation,
        registry,
        None,
        &mut cache,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_core_ext_spend_with_cache_and_suite_context(
    entry: &UtxoEntry,
    w: &WitnessItem,
    _tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    profiles_at_height: &CoreExtProfiles,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
    tx_context: Option<&TxContextBundle>,
    cache: &mut SighashV1PrehashCache<'_>,
) -> Result<(), TxError> {
    validate_core_ext_spend_with_cache_and_suite_context_q(
        entry,
        w,
        input_index,
        input_value,
        chain_id,
        block_height,
        profiles_at_height,
        rotation,
        registry,
        tx_context,
        None,
        cache,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_core_ext_spend_with_cache_and_suite_context_q(
    entry: &UtxoEntry,
    w: &WitnessItem,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    profiles_at_height: &CoreExtProfiles,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
    tx_context: Option<&TxContextBundle>,
    sig_queue: Option<&mut SigCheckQueue>,
    cache: &mut SighashV1PrehashCache<'_>,
) -> Result<(), TxError> {
    let default_rotation = DefaultRotationProvider;
    let rotation = rotation.unwrap_or(&default_rotation);
    let registry = match registry {
        Some(registry) => registry,
        None => default_suite_registry(),
    };

    validate_core_ext_spend_with_cache_impl(
        entry,
        w,
        input_index,
        input_value,
        chain_id,
        block_height,
        profiles_at_height,
        rotation,
        registry,
        tx_context,
        sig_queue,
        cache,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_core_ext_spend_with_cache_impl(
    entry: &UtxoEntry,
    w: &WitnessItem,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    profiles_at_height: &CoreExtProfiles,
    rotation: &dyn RotationProvider,
    registry: &SuiteRegistry,
    tx_context: Option<&TxContextBundle>,
    sig_queue: Option<&mut SigCheckQueue>,
    cache: &mut SighashV1PrehashCache<'_>,
) -> Result<(), TxError> {
    let cov = parse_core_ext_covenant_data(&entry.covenant_data)?;

    let active_profile = profiles_at_height.lookup_active_profile(cov.ext_id)?;
    if active_profile.is_none() {
        return Ok(());
    }
    let p = active_profile.expect("active_profile is Some");

    if !p.allowed_suite_ids.contains(&w.suite_id) {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_EXT suite disallowed under ACTIVE profile",
        ));
    }
    if w.suite_id == SUITE_ID_SENTINEL {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_EXT sentinel suite forbidden under ACTIVE profile",
        ));
    }

    let native_spend_suites = rotation.native_spend_suites(block_height);
    let native_params = registry.lookup(w.suite_id);

    // Per CANONICAL §12.5 / §23.2.2, registry-known native suites stay on the
    // native path only while currently spend-permitted at this height; suites
    // outside the current native spend set reject here and never fall through
    // to verify_sig_ext.
    if let Some(params) = native_params {
        if !native_spend_suites.contains(w.suite_id) {
            return Err(TxError::new(
                ErrorCode::TxErrSigAlgInvalid,
                "CORE_EXT registered native suite not spend-permitted at this height",
            ));
        }
        if w.pubkey.len() as u64 != params.pubkey_len
            || w.signature.len() as u64 != params.sig_len + 1
        {
            return Err(TxError::new(
                ErrorCode::TxErrSigNoncanonical,
                "non-canonical CORE_EXT native witness item lengths",
            ));
        }
        let mut sig_queue = sig_queue;
        let (crypto_sig, sighash_type) = extract_crypto_sig_and_sighash(w)?;
        let digest32 =
            sighash_v1_digest_with_cache(cache, input_index, input_value, chain_id, sighash_type)?;
        return queue_or_verify_signature(
            w.suite_id,
            &w.pubkey,
            crypto_sig,
            digest32,
            registry,
            &mut sig_queue,
            TxError::new(ErrorCode::TxErrSigInvalid, "CORE_EXT signature invalid"),
        );
    }
    if native_spend_suites.contains(w.suite_id) {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_EXT registered native suite missing from registry",
        ));
    }

    let Some((&sighash_type, crypto_sig)) = w.signature.split_last() else {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "missing sighash_type byte",
        ));
    };
    if !is_valid_sighash_type(sighash_type) {
        return Err(TxError::new(
            ErrorCode::TxErrSighashTypeInvalid,
            "invalid sighash_type",
        ));
    }
    let digest32 =
        sighash_v1_digest_with_cache(cache, input_index, input_value, chain_id, sighash_type)?;

    if p.tx_context_enabled {
        let Some(verify_tx_context_fn) = p.verify_sig_ext_tx_context_fn else {
            return Err(TxError::new(
                ErrorCode::TxErrSigAlgInvalid,
                "CORE_EXT verify_sig_ext unsupported",
            ));
        };
        let tx_context = tx_context.ok_or_else(|| {
            TxError::new(
                ErrorCode::TxErrSigInvalid,
                "CORE_EXT txcontext bundle missing",
            )
        })?;
        let ctx_continuing = tx_context.get_continuing(cov.ext_id).ok_or_else(|| {
            TxError::new(
                ErrorCode::TxErrSigInvalid,
                "CORE_EXT txcontext continuing bundle missing",
            )
        })?;
        let ok = verify_tx_context_fn(
            cov.ext_id,
            w.suite_id,
            &w.pubkey,
            crypto_sig,
            &digest32,
            cov.ext_payload,
            tx_context.base.as_ref(),
            ctx_continuing.as_ref(),
            input_value,
        )
        .map_err(|_| {
            TxError::new(
                ErrorCode::TxErrSigAlgInvalid,
                "CORE_EXT verify_sig_ext error",
            )
        })?;
        return if ok {
            Ok(())
        } else {
            Err(TxError::new(
                ErrorCode::TxErrSigInvalid,
                "CORE_EXT signature invalid",
            ))
        };
    }
    run_core_ext_verify_sig_ext_binding(&p.verification_binding, &w.pubkey, crypto_sig, &digest32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compactsize::encode_compact_size;
    use crate::constants::{
        COV_TYPE_EXT, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87,
        VERIFY_COST_ML_DSA_87,
    };
    use crate::tx::{Tx, TxInput, TxOutput};
    use crate::txcontext::{build_tx_context, build_tx_context_output_ext_id_cache};

    fn core_ext_covdata(ext_id: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ext_id.to_le_bytes());
        encode_compact_size(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }

    fn dummy_entry(ext_id: u16) -> UtxoEntry {
        UtxoEntry {
            value: 1,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(ext_id, b""),
            creation_height: 0,
            created_by_coinbase: false,
        }
    }

    fn dummy_tx() -> (Tx, u32, u64, [u8; 32]) {
        let mut prev = [0u8; 32];
        prev[0] = 0x11;
        let mut chain_id = [0u8; 32];
        chain_id[0] = 0x22;
        (
            Tx {
                version: 1,
                tx_kind: 0x00,
                tx_nonce: 1,
                inputs: vec![TxInput {
                    prev_txid: prev,
                    prev_vout: 0,
                    script_sig: vec![],
                    sequence: 0,
                }],
                outputs: vec![TxOutput {
                    value: 1,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: vec![],
                }],
                locktime: 0,
                witness: vec![],
                da_payload: vec![],
                da_commit_core: None,
                da_chunk_core: None,
            },
            0,
            1,
            chain_id,
        )
    }

    #[test]
    fn core_ext_pre_active_keyless_sentinel_ok() {
        let entry = dummy_entry(7);
        let w = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![],
            signature: vec![],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &CoreExtProfiles::empty(),
        )
        .unwrap();
    }

    #[test]
    fn core_ext_pre_active_non_keyless_sentinel_ok() {
        let entry = dummy_entry(7);
        let w = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![0u8; 32],
            signature: vec![0x01],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &CoreExtProfiles::empty(),
        )
        .unwrap();
    }

    #[test]
    fn core_ext_pre_active_non_sentinel_ok() {
        let entry = dummy_entry(7);
        let w = WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0u8; (ML_DSA_87_SIG_BYTES as usize) + 1],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &CoreExtProfiles::empty(),
        )
        .unwrap();
    }

    #[test]
    fn core_ext_active_disallowed_suite_rejected_sig_alg_invalid() {
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: false,
                allowed_suite_ids: vec![SUITE_ID_ML_DSA_87],
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: Vec::new(),
                ext_payload_schema: Vec::new(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x02,
            pubkey: vec![0u8; 1],
            signature: vec![0u8; 1],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let err = validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn core_ext_active_unknown_suite_allowed_but_unsupported_binding_rejected_sig_alg_invalid() {
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: false,
                allowed_suite_ids: vec![0x03],
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: Vec::new(),
                ext_payload_schema: Vec::new(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x03,
            pubkey: vec![0x01],
            signature: vec![0x02],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let err = validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn core_ext_active_verify_sig_ext_accept_allows_non_native_suite() {
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: false,
                allowed_suite_ids: vec![0x03],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x03,
            pubkey: vec![0x11],
            signature: vec![0x01],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap();
    }

    #[test]
    fn core_ext_active_verify_sig_ext_reject_maps_to_sig_invalid() {
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: false,
                allowed_suite_ids: vec![0x03],
                verification_binding: CoreExtVerificationBinding::VerifySigExtReject,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: b"reject".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x03,
            pubkey: vec![0x11],
            signature: vec![0x01],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let err = validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn core_ext_active_verify_sig_ext_error_maps_to_sig_alg_invalid() {
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: false,
                allowed_suite_ids: vec![0x03],
                verification_binding: CoreExtVerificationBinding::VerifySigExtError,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: b"error".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x03,
            pubkey: vec![0x11],
            signature: vec![0x01],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let err = validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[allow(clippy::too_many_arguments)]
    fn txcontext_accept_verifier(
        _ext_id: u16,
        _suite_id: u8,
        _pubkey: &[u8],
        _signature: &[u8],
        _digest32: &[u8; 32],
        _ext_payload: &[u8],
        _ctx_base: &TxContextBase,
        _ctx_continuing: &TxContextContinuing,
        _self_input_value: u64,
    ) -> Result<bool, TxError> {
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    fn txcontext_reject_verifier(
        _ext_id: u16,
        _suite_id: u8,
        _pubkey: &[u8],
        _signature: &[u8],
        _digest32: &[u8; 32],
        _ext_payload: &[u8],
        _ctx_base: &TxContextBase,
        _ctx_continuing: &TxContextContinuing,
        _self_input_value: u64,
    ) -> Result<bool, TxError> {
        Ok(false)
    }

    #[allow(clippy::too_many_arguments)]
    fn txcontext_error_verifier(
        _ext_id: u16,
        _suite_id: u8,
        _pubkey: &[u8],
        _signature: &[u8],
        _digest32: &[u8; 32],
        _ext_payload: &[u8],
        _ctx_base: &TxContextBase,
        _ctx_continuing: &TxContextContinuing,
        _self_input_value: u64,
    ) -> Result<bool, TxError> {
        Err(TxError::new(
            ErrorCode::TxErrParse,
            "test txcontext verifier error",
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn txcontext_openssl_digest32_verifier(
        _ext_id: u16,
        _suite_id: u8,
        pubkey: &[u8],
        signature: &[u8],
        digest32: &[u8; 32],
        _ext_payload: &[u8],
        _ctx_base: &TxContextBase,
        _ctx_continuing: &TxContextContinuing,
        _self_input_value: u64,
    ) -> Result<bool, TxError> {
        let descriptor = CoreExtOpenSslDigest32BindingDescriptor {
            openssl_alg: "ML-DSA-87".to_string(),
            pubkey_len: ML_DSA_87_PUBKEY_BYTES,
            sig_len: ML_DSA_87_SIG_BYTES,
        };
        verify_core_ext_openssl_digest32_binding(&descriptor, pubkey, signature, digest32)
    }

    fn build_test_txcontext_bundle(
        ext_id: u16,
        height: u64,
    ) -> (Tx, TxContextBundle, u32, u64, [u8; 32]) {
        let mut prev = [0u8; 32];
        prev[0] = 0x44;
        let mut chain_id = [0u8; 32];
        chain_id[0] = 0x55;
        let tx = Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid: prev,
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 90,
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covdata(ext_id, &[]),
            }],
            locktime: 0,
            witness: vec![WitnessItem {
                suite_id: 0x42,
                pubkey: vec![0x01, 0x02, 0x03],
                signature: vec![0x04, 0x01],
            }],
            da_commit_core: None,
            da_chunk_core: None,
            da_payload: vec![],
        };
        let resolved_inputs = vec![UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(ext_id, &[0x99]),
            creation_height: 0,
            created_by_coinbase: false,
        }];
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id,
                tx_context_enabled: true,
                allowed_suite_ids: vec![0x42],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                verify_sig_ext_tx_context_fn: Some(txcontext_accept_verifier),
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let cache = build_tx_context_output_ext_id_cache(&tx).expect("txcontext cache");
        let bundle = build_tx_context(&tx, &resolved_inputs, Some(&cache), height, &profiles)
            .expect("txcontext build")
            .expect("txcontext bundle");
        (tx, bundle, 0, 100, chain_id)
    }

    #[test]
    fn core_ext_active_txcontext_missing_bundle_fails_closed() {
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(7, &[0x99]),
            creation_height: 0,
            created_by_coinbase: false,
        };
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: true,
                allowed_suite_ids: vec![0x42],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                verify_sig_ext_tx_context_fn: Some(txcontext_accept_verifier),
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x42,
            pubkey: vec![0x01, 0x02, 0x03],
            signature: vec![0x04, 0x01],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let err = validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
        assert_eq!(err.msg, "CORE_EXT txcontext bundle missing");
    }

    #[test]
    fn core_ext_active_txcontext_missing_runtime_verifier_wins_before_bundle_checks() {
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(7, &[0x99]),
            creation_height: 0,
            created_by_coinbase: false,
        };
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: true,
                allowed_suite_ids: vec![0x42],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x42,
            pubkey: vec![0x01, 0x02, 0x03],
            signature: vec![0x04, 0x01],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let err = validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
        assert_eq!(err.msg, "CORE_EXT verify_sig_ext unsupported");
    }

    #[test]
    fn core_ext_active_txcontext_openssl_binding_without_runtime_verifier_fails_closed() {
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(7, &[0x99]),
            creation_height: 0,
            created_by_coinbase: false,
        };
        let binding_descriptor = core_ext_openssl_digest32_binding_descriptor_bytes(
            "ML-DSA-87",
            ML_DSA_87_PUBKEY_BYTES,
            ML_DSA_87_SIG_BYTES,
        )
        .expect("descriptor");
        let descriptor =
            parse_core_ext_openssl_digest32_binding_descriptor(&binding_descriptor).expect("parse");
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: true,
                allowed_suite_ids: vec![0x42],
                verification_binding: CoreExtVerificationBinding::VerifySigExtOpenSslDigest32V1(
                    descriptor,
                ),
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor,
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let (mut tx, tx_context, input_index, input_value, chain_id) =
            build_test_txcontext_bundle(7, 55);
        let keypair = crate::verify_sig_openssl::Mldsa87Keypair::generate().expect("keypair");
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let digest =
            sighash_v1_digest_with_cache(&mut cache, input_index, input_value, chain_id, 0x01)
                .expect("digest");
        let mut signature = keypair.sign_digest32(digest).expect("sign");
        signature.push(0x01);
        let witness = WitnessItem {
            suite_id: 0x42,
            pubkey: keypair.pubkey_bytes(),
            signature,
        };
        tx.witness[0] = witness.clone();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_core_ext_spend_with_cache_and_suite_context(
            &entry,
            &witness,
            &tx,
            input_index,
            input_value,
            chain_id,
            55,
            &profiles,
            None,
            None,
            Some(&tx_context),
            &mut cache,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
        assert_eq!(err.msg, "CORE_EXT verify_sig_ext unsupported");
    }

    #[test]
    fn core_ext_active_txcontext_legacy_binding_without_runtime_verifier_fails_closed() {
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(7, &[0x99]),
            creation_height: 0,
            created_by_coinbase: false,
        };
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: true,
                allowed_suite_ids: vec![0x42],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x42,
            pubkey: vec![0x01, 0x02, 0x03],
            signature: vec![0x04, 0x01],
        };
        let (tx, tx_context, input_index, input_value, chain_id) =
            build_test_txcontext_bundle(7, 55);
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_core_ext_spend_with_cache_and_suite_context(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            55,
            &profiles,
            None,
            None,
            Some(&tx_context),
            &mut cache,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
        assert_eq!(err.msg, "CORE_EXT verify_sig_ext unsupported");
    }

    #[test]
    fn core_ext_active_txcontext_native_binding_without_runtime_verifier_fails_closed() {
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(7, &[0x99]),
            creation_height: 0,
            created_by_coinbase: false,
        };
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: true,
                allowed_suite_ids: vec![0x42],
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: Vec::new(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x42,
            pubkey: vec![0x01, 0x02, 0x03],
            signature: vec![0x04, 0x01],
        };
        let (tx, tx_context, input_index, input_value, chain_id) =
            build_test_txcontext_bundle(7, 55);
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_core_ext_spend_with_cache_and_suite_context(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            55,
            &profiles,
            None,
            None,
            Some(&tx_context),
            &mut cache,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
        assert_eq!(err.msg, "CORE_EXT verify_sig_ext unsupported");
    }

    #[test]
    fn core_ext_active_txcontext_missing_continuing_bundle_fails_closed() {
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(7, &[0x99]),
            creation_height: 0,
            created_by_coinbase: false,
        };
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: true,
                allowed_suite_ids: vec![0x42],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                verify_sig_ext_tx_context_fn: Some(txcontext_accept_verifier),
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x42,
            pubkey: vec![0x01, 0x02, 0x03],
            signature: vec![0x04, 0x01],
        };
        let (tx, tx_context, input_index, input_value, chain_id) =
            build_test_txcontext_bundle(9, 55);
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_core_ext_spend_with_cache_and_suite_context(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            55,
            &profiles,
            None,
            None,
            Some(&tx_context),
            &mut cache,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
        assert_eq!(err.msg, "CORE_EXT txcontext continuing bundle missing");
    }

    #[test]
    fn core_ext_active_txcontext_reject_maps_to_sig_invalid() {
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(7, &[0x99]),
            creation_height: 0,
            created_by_coinbase: false,
        };
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: true,
                allowed_suite_ids: vec![0x42],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                verify_sig_ext_tx_context_fn: Some(txcontext_reject_verifier),
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x42,
            pubkey: vec![0x01, 0x02, 0x03],
            signature: vec![0x04, 0x01],
        };
        let (tx, tx_context, input_index, input_value, chain_id) =
            build_test_txcontext_bundle(7, 55);
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_core_ext_spend_with_cache_and_suite_context(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            55,
            &profiles,
            None,
            None,
            Some(&tx_context),
            &mut cache,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
        assert_eq!(err.msg, "CORE_EXT signature invalid");
    }

    #[test]
    fn core_ext_active_txcontext_error_maps_to_sig_alg_invalid() {
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(7, &[0x99]),
            creation_height: 0,
            created_by_coinbase: false,
        };
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: true,
                allowed_suite_ids: vec![0x42],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                verify_sig_ext_tx_context_fn: Some(txcontext_error_verifier),
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x42,
            pubkey: vec![0x01, 0x02, 0x03],
            signature: vec![0x04, 0x01],
        };
        let (tx, tx_context, input_index, input_value, chain_id) =
            build_test_txcontext_bundle(7, 55);
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_core_ext_spend_with_cache_and_suite_context(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            55,
            &profiles,
            None,
            None,
            Some(&tx_context),
            &mut cache,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
        assert_eq!(err.msg, "CORE_EXT verify_sig_ext error");
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
    fn core_ext_active_txcontext_openssl_digest32_binding_verifies_mldsa87_parity() {
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(7, &[0x99]),
            creation_height: 0,
            created_by_coinbase: false,
        };
        let binding_descriptor = core_ext_openssl_digest32_binding_descriptor_bytes(
            "ML-DSA-87",
            ML_DSA_87_PUBKEY_BYTES,
            ML_DSA_87_SIG_BYTES,
        )
        .expect("descriptor");
        let descriptor =
            parse_core_ext_openssl_digest32_binding_descriptor(&binding_descriptor).expect("parse");
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: true,
                allowed_suite_ids: vec![SUITE_ID_ML_DSA_87],
                verification_binding: CoreExtVerificationBinding::VerifySigExtOpenSslDigest32V1(
                    descriptor,
                ),
                verify_sig_ext_tx_context_fn: Some(txcontext_openssl_digest32_verifier),
                binding_descriptor,
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let (mut tx, tx_context, input_index, input_value, chain_id) =
            build_test_txcontext_bundle(7, 55);
        let keypair = crate::verify_sig_openssl::Mldsa87Keypair::generate().expect("keypair");
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let digest =
            sighash_v1_digest_with_cache(&mut cache, input_index, input_value, chain_id, 0x01)
                .expect("digest");
        let mut signature = keypair.sign_digest32(digest).expect("sign");
        signature.push(0x01);
        let witness = WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: keypair.pubkey_bytes(),
            signature,
        };
        tx.witness[0] = witness.clone();

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        validate_core_ext_spend_with_cache_and_suite_context(
            &entry,
            &witness,
            &tx,
            input_index,
            input_value,
            chain_id,
            55,
            &profiles,
            None,
            None,
            Some(&tx_context),
            &mut cache,
        )
        .unwrap();

        let mut bad = witness.clone();
        bad.signature[0] ^= 0x01;
        tx.witness[0] = bad.clone();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_core_ext_spend_with_cache_and_suite_context(
            &entry,
            &bad,
            &tx,
            input_index,
            input_value,
            chain_id,
            55,
            &profiles,
            None,
            None,
            Some(&tx_context),
            &mut cache,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
        assert_eq!(err.msg, "CORE_EXT signature invalid");
    }

    #[test]
    fn core_ext_active_verify_sig_ext_openssl_digest32_allows_non_native_suite() {
        let kp = crate::verify_sig_openssl::Mldsa87Keypair::generate().expect("keypair");
        let binding_descriptor = core_ext_openssl_digest32_binding_descriptor_bytes(
            "ML-DSA-87",
            ML_DSA_87_PUBKEY_BYTES,
            ML_DSA_87_SIG_BYTES,
        )
        .expect("descriptor");
        let descriptor =
            parse_core_ext_openssl_digest32_binding_descriptor(&binding_descriptor).expect("parse");
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: false,
                allowed_suite_ids: vec![0x09],
                verification_binding: CoreExtVerificationBinding::VerifySigExtOpenSslDigest32V1(
                    descriptor,
                ),
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor,
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let digest =
            sighash_v1_digest_with_cache(&mut cache, input_index, input_value, chain_id, 0x01)
                .expect("digest");
        let mut signature = kp.sign_digest32(digest).expect("sign");
        signature.push(0x01);
        let w = WitnessItem {
            suite_id: 0x09,
            pubkey: kp.pubkey_bytes(),
            signature,
        };
        validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap();
    }

    #[test]
    fn core_ext_active_verify_sig_ext_accept_invalid_sighash_rejected() {
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: false,
                allowed_suite_ids: vec![0x03],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x03,
            pubkey: vec![0x11],
            signature: vec![0x00],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let err = validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSighashTypeInvalid);
    }

    #[test]
    fn core_ext_active_native_suite_invalid_signature_maps_to_sig_invalid() {
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: false,
                allowed_suite_ids: vec![SUITE_ID_ML_DSA_87],
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: Vec::new(),
                ext_payload_schema: Vec::new(),
            }],
        };
        let mut sig = vec![0u8; (ML_DSA_87_SIG_BYTES as usize) + 1];
        sig[ML_DSA_87_SIG_BYTES as usize] = 0x01; // SIGHASH_ALL
        let w = WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: sig,
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let err = validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
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
        let err = core_ext_profile_bytes_v1(&CoreExtDeploymentProfile {
            ext_id: 7,
            activation_height: 1,
            tx_context_enabled: false,
            allowed_suite_ids: Vec::new(),
            verification_binding: CoreExtVerificationBinding::NativeVerifySig,
            verify_sig_ext_tx_context_fn: None,
            binding_descriptor: Vec::new(),
            ext_payload_schema: b"schema-a".to_vec(),
            governance_nonce: 0,
        })
        .unwrap_err();
        assert!(err.contains("must have non-empty allowed_suite_ids"));

        let err = core_ext_profile_bytes_v1(&CoreExtDeploymentProfile {
            ext_id: 7,
            activation_height: 1,
            tx_context_enabled: false,
            allowed_suite_ids: vec![3],
            verification_binding: CoreExtVerificationBinding::NativeVerifySig,
            verify_sig_ext_tx_context_fn: None,
            binding_descriptor: vec![0xa1],
            ext_payload_schema: b"schema-a".to_vec(),
            governance_nonce: 0,
        })
        .unwrap_err();
        assert!(err.contains("native-only profile must not carry binding_descriptor"));

        let err = core_ext_profile_bytes_v1(&CoreExtDeploymentProfile {
            ext_id: 7,
            activation_height: 1,
            tx_context_enabled: false,
            allowed_suite_ids: vec![3],
            verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
            verify_sig_ext_tx_context_fn: None,
            binding_descriptor: Vec::new(),
            ext_payload_schema: b"schema-a".to_vec(),
            governance_nonce: 0,
        })
        .unwrap_err();
        assert!(err.contains("verify_sig_ext profile must carry binding_descriptor"));

        let err = core_ext_profile_bytes_v1(&CoreExtDeploymentProfile {
            ext_id: 7,
            activation_height: 1,
            tx_context_enabled: true,
            allowed_suite_ids: vec![3],
            verification_binding: CoreExtVerificationBinding::NativeVerifySig,
            verify_sig_ext_tx_context_fn: None,
            binding_descriptor: Vec::new(),
            ext_payload_schema: b"schema-a".to_vec(),
            governance_nonce: 0,
        })
        .unwrap_err();
        assert!(err.contains("txcontext-enabled profile requires v2 anchor pipeline"));
    }

    #[test]
    fn core_ext_rotated_native_suite_uses_registry_path() {
        use crate::suite_registry::{NativeSuiteSet, RotationProvider, SuiteParams, SuiteRegistry};
        use std::collections::BTreeMap;

        struct RotatedSpend;
        impl RotationProvider for RotatedSpend {
            fn native_create_suites(&self, _height: u64) -> NativeSuiteSet {
                NativeSuiteSet::new(&[SUITE_ID_ML_DSA_87, 0x02])
            }

            fn native_spend_suites(&self, _height: u64) -> NativeSuiteSet {
                NativeSuiteSet::new(&[SUITE_ID_ML_DSA_87, 0x02])
            }
        }

        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: false,
                allowed_suite_ids: vec![0x02],
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: Vec::new(),
                ext_payload_schema: Vec::new(),
            }],
        };
        let mut sig = vec![0u8; (ML_DSA_87_SIG_BYTES as usize) + 1];
        sig[ML_DSA_87_SIG_BYTES as usize] = 0x01;
        let w = WitnessItem {
            suite_id: 0x02,
            pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: sig,
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let mut suites = BTreeMap::new();
        suites.insert(
            0x02,
            SuiteParams {
                suite_id: 0x02,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87",
            },
        );
        let reg = SuiteRegistry::with_suites(suites);
        let err = validate_core_ext_spend_at_height(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            &profiles,
            Some(&RotatedSpend),
            Some(&reg),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn core_ext_registered_native_suite_outside_spend_set_rejected() {
        use crate::suite_registry::{NativeSuiteSet, RotationProvider, SuiteParams, SuiteRegistry};
        use std::collections::BTreeMap;

        struct SunsetSpend;
        impl RotationProvider for SunsetSpend {
            fn native_create_suites(&self, _height: u64) -> NativeSuiteSet {
                NativeSuiteSet::new(&[SUITE_ID_ML_DSA_87, 0x02])
            }

            fn native_spend_suites(&self, _height: u64) -> NativeSuiteSet {
                NativeSuiteSet::new(&[SUITE_ID_ML_DSA_87])
            }
        }

        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                tx_context_enabled: false,
                allowed_suite_ids: vec![0x02],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x02,
            pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0u8; (ML_DSA_87_SIG_BYTES as usize) + 1],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let mut suites = BTreeMap::new();
        suites.insert(
            0x02,
            SuiteParams {
                suite_id: 0x02,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87",
            },
        );
        let reg = SuiteRegistry::with_suites(suites);
        let err = validate_core_ext_spend_at_height(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            &profiles,
            Some(&SunsetSpend),
            Some(&reg),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
        assert_eq!(
            err.msg,
            "CORE_EXT registered native suite not spend-permitted at this height"
        );
    }

    #[test]
    fn core_ext_verification_binding_name_helper_covers_native_and_unsupported() {
        let native = core_ext_verification_binding_from_name("").expect("native empty");
        assert!(matches!(
            native,
            CoreExtVerificationBinding::NativeVerifySig
        ));
        let native_named =
            core_ext_verification_binding_from_name(" native_verify_sig \n").expect("native named");
        assert!(matches!(
            native_named,
            CoreExtVerificationBinding::NativeVerifySig
        ));
        let descriptor = core_ext_openssl_digest32_binding_descriptor_bytes(
            "ML-DSA-87",
            ML_DSA_87_PUBKEY_BYTES,
            ML_DSA_87_SIG_BYTES,
        )
        .expect("descriptor");
        let openssl = core_ext_verification_binding_from_name_and_descriptor(
            &format!("  {CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1}\n"),
            &descriptor,
        )
        .expect("openssl binding");
        assert!(matches!(
            openssl,
            CoreExtVerificationBinding::VerifySigExtOpenSslDigest32V1(_)
        ));
        let err =
            core_ext_verification_binding_from_name("unsupported").expect_err("unsupported bind");
        assert!(err.contains("unsupported core_ext binding"));
    }

    #[test]
    fn live_core_ext_binding_helper_rejects_non_manifest_bindings() {
        let err = normalize_live_core_ext_binding_name("").expect_err("empty must fail");
        assert!(err.contains("unsupported core_ext binding"));

        let err = normalize_live_core_ext_binding_name(" native_verify_sig ")
            .expect_err("native alias must fail");
        assert!(err.contains("unsupported core_ext binding"));

        let descriptor = core_ext_openssl_digest32_binding_descriptor_bytes(
            "ML-DSA-87",
            ML_DSA_87_PUBKEY_BYTES,
            ML_DSA_87_SIG_BYTES,
        )
        .expect("descriptor");
        let binding = live_core_ext_verification_binding_from_name_and_descriptor(
            &format!("  {CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1}\n"),
            &descriptor,
            &[0xb2],
        )
        .expect("live binding");
        assert!(matches!(
            binding,
            CoreExtVerificationBinding::VerifySigExtOpenSslDigest32V1(_)
        ));
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
