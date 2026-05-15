mod alg;
mod binding;
mod bootstrap;
mod digest;
mod ffi;
mod keypair;

use crate::constants::{ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87};
use crate::error::{ErrorCode, TxError};
use std::sync::OnceLock;

pub(crate) use digest::openssl_verify_sig_digest_oneshot;
pub use keypair::Mldsa87Keypair;

const OPENSSL_INIT_NO_LOAD_CONFIG: u64 = 0x0000_0080;

static OPENSSL_CONSENSUS_INIT: OnceLock<Result<(), TxError>> = OnceLock::new();

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
    let binding = binding::resolve_suite_verifier_binding(
        "ML-DSA-87",
        ML_DSA_87_PUBKEY_BYTES,
        ML_DSA_87_SIG_BYTES,
    )?;
    binding::verify_sig_with_binding(&binding, pubkey, signature, digest32)
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
    let params = binding::runtime_suite_params_for_verification(suite_id, registry)?;
    ensure_openssl_consensus_init()?;
    let binding = binding::resolve_suite_verifier_binding(
        params.alg_name,
        params.pubkey_len,
        params.sig_len,
    )?;
    binding::verify_sig_with_binding(&binding, pubkey, signature, digest32)
}

/// Deterministic OpenSSL initialization for the consensus verification path.
///
/// Does NOT read any `RUBIN_OPENSSL_*` environment variables, does NOT load the
/// FIPS provider, and does NOT set `fips=yes` default properties. This ensures
/// that consensus signature verification produces identical results across all
/// nodes regardless of host environment configuration.
///
/// Non-consensus callers (key generation, signing, CLI tools) should continue
/// to use the operator-configured bootstrap in the `bootstrap` module.
fn openssl_consensus_bootstrap() -> Result<(), TxError> {
    // SAFETY: OpenSSL consensus initialization uses a null settings pointer and
    // a fixed no-load-config flag, so no Rust-owned memory is transferred and no
    // operator OpenSSL environment is consulted.
    unsafe {
        openssl_sys::ERR_clear_error();
        bootstrap::map_openssl_init_rc(
            ffi::OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, core::ptr::null()),
            "openssl consensus init: OPENSSL_init_crypto failed",
        )?;
    }
    bootstrap::openssl_check_sigalg(c"ML-DSA-87", c"")?;
    Ok(())
}

pub(crate) fn ensure_openssl_consensus_init() -> Result<(), TxError> {
    OPENSSL_CONSENSUS_INIT
        .get_or_init(openssl_consensus_bootstrap)
        .clone()
}

#[cfg(test)]
pub(crate) use alg::test_suite_alg_name;
#[cfg(test)]
pub(crate) use bootstrap::{
    test_ensure_openssl_bootstrap_for_mode, test_openssl_check_sigalg_bad_alg,
    test_set_env_if_empty,
};
#[cfg(test)]
pub(crate) use digest::{
    test_openssl_verify_sig_digest_oneshot_bad_alg,
    test_openssl_verify_sig_digest_oneshot_empty_input,
};
#[cfg(test)]
mod tests;
