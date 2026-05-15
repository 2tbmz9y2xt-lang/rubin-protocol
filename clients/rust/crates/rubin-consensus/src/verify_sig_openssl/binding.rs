use super::alg::openssl_alg_name_cstr;
use super::bootstrap::ensure_openssl_consensus_init;
use super::digest::openssl_verify_sig_digest_oneshot;
use crate::constants::{ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87};
use crate::error::{ErrorCode, TxError};
use crate::live_binding_policy::{
    live_binding_policy_runtime_entry, LiveBindingPolicyLookupError,
    LIVE_BINDING_POLICY_RUNTIME_OPENSSL_DIGEST32_V1,
};
use std::sync::OnceLock;

static DEFAULT_RUNTIME_SUITE_REGISTRY: OnceLock<crate::suite_registry::SuiteRegistry> =
    OnceLock::new();

pub fn verify_sig(
    suite_id: u8,
    pubkey: &[u8],
    signature: &[u8],
    digest32: &[u8; 32],
) -> Result<bool, TxError> {
    if suite_id != SUITE_ID_ML_DSA_87 {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "verify_sig: unsupported suite_id",
        ));
    }
    ensure_openssl_consensus_init()?;
    let binding =
        resolve_suite_verifier_binding("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)?;
    verify_sig_with_binding(&binding, pubkey, signature, digest32)
}

pub(super) enum SuiteVerifierBinding {
    OpenSslDigest32V1 {
        alg: &'static core::ffi::CStr,
        pubkey_len: u64,
        sig_len: u64,
    },
}

// v1 keeps the current live verifier contract pinned to the canonical
// ML-DSA-87/OpenSSL-digest32 tuple from the shared live binding artifact.
// Runtime dispatch must resolve a concrete binding instead of treating
// registry.alg_name as an implicit backend switch.
pub(super) fn resolve_suite_verifier_binding(
    alg_name: &str,
    pubkey_len: u64,
    sig_len: u64,
) -> Result<SuiteVerifierBinding, TxError> {
    let entry = live_binding_policy_runtime_entry(alg_name, pubkey_len, sig_len).map_err(
        |err| match err {
            LiveBindingPolicyLookupError::NotFound(_) => TxError::new(
                ErrorCode::TxErrSigAlgInvalid,
                "resolve_suite_verifier_binding: unsupported suite verifier binding",
            ),
            LiveBindingPolicyLookupError::Invalid(_) => TxError::new(
                ErrorCode::TxErrSigAlgInvalid,
                "resolve_suite_verifier_binding: live binding policy invalid",
            ),
        },
    )?;
    if entry.runtime_binding.as_str() == LIVE_BINDING_POLICY_RUNTIME_OPENSSL_DIGEST32_V1 {
        return canonical_v1_binding_from_entry(entry);
    }
    Err(TxError::new(
        ErrorCode::TxErrSigAlgInvalid,
        "resolve_suite_verifier_binding: unsupported suite verifier binding",
    ))
}

fn canonical_v1_binding_from_entry(
    entry: &crate::live_binding_policy::LiveBindingPolicyEntry,
) -> Result<SuiteVerifierBinding, TxError> {
    if entry.alg_name != "ML-DSA-87"
        || entry.openssl_alg != "ML-DSA-87"
        || entry.pubkey_len != ML_DSA_87_PUBKEY_BYTES
        || entry.sig_len != ML_DSA_87_SIG_BYTES
    {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "resolve_suite_verifier_binding: unsupported suite verifier binding",
        ));
    }
    let alg = openssl_alg_name_cstr(entry.openssl_alg.as_str()).ok_or_else(|| {
        TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "resolve_suite_verifier_binding: unsupported OpenSSL alg",
        )
    })?;
    Ok(SuiteVerifierBinding::OpenSslDigest32V1 {
        alg,
        pubkey_len: ML_DSA_87_PUBKEY_BYTES,
        sig_len: ML_DSA_87_SIG_BYTES,
    })
}

fn verify_sig_with_binding(
    binding: &SuiteVerifierBinding,
    pubkey: &[u8],
    signature: &[u8],
    digest32: &[u8; 32],
) -> Result<bool, TxError> {
    match binding {
        SuiteVerifierBinding::OpenSslDigest32V1 {
            alg,
            pubkey_len,
            sig_len,
        } => {
            #[cfg(target_pointer_width = "32")]
            if *pubkey_len > usize::MAX as u64 || *sig_len > usize::MAX as u64 {
                return Err(TxError::new(
                    ErrorCode::TxErrSigAlgInvalid,
                    "unsupported suite verifier binding",
                ));
            }
            if pubkey.len() as u64 != *pubkey_len || signature.len() as u64 != *sig_len {
                return Ok(false);
            }
            openssl_verify_sig_digest_oneshot(alg, pubkey, signature, digest32)
        }
    }
}

pub(super) fn default_runtime_suite_registry() -> &'static crate::suite_registry::SuiteRegistry {
    DEFAULT_RUNTIME_SUITE_REGISTRY
        .get_or_init(crate::suite_registry::SuiteRegistry::default_registry)
}

pub(super) fn runtime_verification_registry_with_default<'a>(
    registry: Option<&'a crate::suite_registry::SuiteRegistry>,
    default_registry: &'a crate::suite_registry::SuiteRegistry,
) -> Result<&'a crate::suite_registry::SuiteRegistry, TxError> {
    match registry {
        Some(registry) => Ok(registry),
        None => {
            if !default_registry.is_canonical_default_live_manifest() {
                return Err(TxError::new(
                    ErrorCode::TxErrSigAlgInvalid,
                    "verify_sig: default runtime registry drift",
                ));
            }
            Ok(default_registry)
        }
    }
}

pub(super) fn runtime_suite_params_for_verification(
    suite_id: u8,
    registry: Option<&crate::suite_registry::SuiteRegistry>,
) -> Result<crate::suite_registry::SuiteParams, TxError> {
    runtime_suite_params_for_verification_with_default(
        suite_id,
        registry,
        default_runtime_suite_registry(),
    )
}

pub(super) fn runtime_suite_params_for_verification_with_default(
    suite_id: u8,
    registry: Option<&crate::suite_registry::SuiteRegistry>,
    default_registry: &crate::suite_registry::SuiteRegistry,
) -> Result<crate::suite_registry::SuiteParams, TxError> {
    let registry = runtime_verification_registry_with_default(registry, default_registry)?;
    let params = registry.lookup(suite_id).cloned();
    params.ok_or_else(|| {
        TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "verify_sig: unsupported suite_id",
        )
    })
}

/// Registry-aware signature verification. When registry is Some, looks up
/// the suite's parameters from the registry. When registry is None, the
/// canonical default live registry is used instead of a separate legacy
/// verifier path. The nil path also fail-closes if that cached default
/// registry stops matching the canonical single-suite ML-DSA-87 live manifest.
/// The registry no longer selects a backend implicitly through `alg_name`;
/// runtime verification resolves an explicit v1 binding from the suite
/// parameters instead. Parity with Go `verifySigWithRegistry`.
pub fn verify_sig_with_registry(
    suite_id: u8,
    pubkey: &[u8],
    signature: &[u8],
    digest32: &[u8; 32],
    registry: Option<&crate::suite_registry::SuiteRegistry>,
) -> Result<bool, TxError> {
    let params = runtime_suite_params_for_verification(suite_id, registry)?;
    ensure_openssl_consensus_init()?;
    let binding =
        resolve_suite_verifier_binding(params.alg_name, params.pubkey_len, params.sig_len)?;
    verify_sig_with_binding(&binding, pubkey, signature, digest32)
}
