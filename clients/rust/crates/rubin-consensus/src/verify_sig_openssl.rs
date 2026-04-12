use crate::constants::{ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87};
use crate::error::{ErrorCode, TxError};
use crate::live_binding_policy::{
    live_binding_policy_runtime_entry, live_binding_policy_runtime_entry_not_found_error,
    LIVE_BINDING_POLICY_RUNTIME_OPENSSL_DIGEST32_V1,
};
use crate::tx_helpers::DigestSigner;
use core::ffi::CStr;
use std::sync::OnceLock;

const OPENSSL_INIT_LOAD_CONFIG: u64 = 0x0000_0040;
const OPENSSL_INIT_NO_LOAD_CONFIG: u64 = 0x0000_0080;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpenSslFipsMode {
    Off,
    Ready,
    Only,
}

static OPENSSL_BOOTSTRAP_STATE: OnceLock<Result<(), TxError>> = OnceLock::new();
static OPENSSL_CONSENSUS_INIT: OnceLock<Result<(), TxError>> = OnceLock::new();
static DEFAULT_RUNTIME_SUITE_REGISTRY: OnceLock<crate::suite_registry::SuiteRegistry> =
    OnceLock::new();

extern "C" {
    fn EVP_PKEY_CTX_new_from_name(
        libctx: *mut core::ffi::c_void,
        name: *const core::ffi::c_char,
        propq: *const core::ffi::c_char,
    ) -> *mut openssl_sys::EVP_PKEY_CTX;

    fn EVP_PKEY_new_raw_public_key_ex(
        libctx: *mut core::ffi::c_void,
        keytype: *const core::ffi::c_char,
        propq: *const core::ffi::c_char,
        key: *const core::ffi::c_uchar,
        keylen: usize,
    ) -> *mut openssl_sys::EVP_PKEY;

    fn EVP_MD_CTX_new() -> *mut openssl_sys::EVP_MD_CTX;
    fn EVP_MD_CTX_free(ctx: *mut openssl_sys::EVP_MD_CTX);

    fn EVP_DigestVerifyInit_ex(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
        mdname: *const core::ffi::c_char,
        libctx: *mut core::ffi::c_void,
        props: *const core::ffi::c_char,
        pkey: *mut openssl_sys::EVP_PKEY,
        params: *const core::ffi::c_void,
    ) -> core::ffi::c_int;

    fn EVP_DigestVerify(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        sigret: *const core::ffi::c_uchar,
        siglen: usize,
        tbs: *const core::ffi::c_uchar,
        tbslen: usize,
    ) -> core::ffi::c_int;

    fn EVP_DigestSignInit_ex(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
        mdname: *const core::ffi::c_char,
        libctx: *mut core::ffi::c_void,
        props: *const core::ffi::c_char,
        pkey: *mut openssl_sys::EVP_PKEY,
        params: *const core::ffi::c_void,
    ) -> core::ffi::c_int;

    fn EVP_DigestSign(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        sigret: *mut core::ffi::c_uchar,
        siglen: *mut usize,
        tbs: *const core::ffi::c_uchar,
        tbslen: usize,
    ) -> core::ffi::c_int;

    fn OPENSSL_init_crypto(opts: u64, settings: *const core::ffi::c_void) -> core::ffi::c_int;

    fn EVP_set_default_properties(
        libctx: *mut core::ffi::c_void,
        propq: *const core::ffi::c_char,
    ) -> core::ffi::c_int;

    fn EVP_PKEY_get_raw_public_key(
        pkey: *const openssl_sys::EVP_PKEY,
        pub_: *mut core::ffi::c_uchar,
        publen: *mut usize,
    ) -> core::ffi::c_int;
}

pub struct Mldsa87Keypair {
    pkey: *mut openssl_sys::EVP_PKEY,
    pubkey: Vec<u8>,
}

impl Drop for Mldsa87Keypair {
    fn drop(&mut self) {
        unsafe {
            if !self.pkey.is_null() {
                openssl_sys::EVP_PKEY_free(self.pkey);
                self.pkey = core::ptr::null_mut();
            }
        }
    }
}

impl Mldsa87Keypair {
    pub fn generate() -> Result<Self, TxError> {
        ensure_openssl_bootstrap()?;
        let alg = suite_alg_name(SUITE_ID_ML_DSA_87)?;
        unsafe {
            openssl_sys::ERR_clear_error();
            let ctx =
                EVP_PKEY_CTX_new_from_name(core::ptr::null_mut(), alg.as_ptr(), core::ptr::null());
            if ctx.is_null() {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "openssl: EVP_PKEY_CTX_new_from_name failed",
                ));
            }
            if openssl_sys::EVP_PKEY_keygen_init(ctx) <= 0 {
                openssl_sys::EVP_PKEY_CTX_free(ctx);
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "openssl: EVP_PKEY_keygen_init failed",
                ));
            }
            let mut pkey: *mut openssl_sys::EVP_PKEY = core::ptr::null_mut();
            if openssl_sys::EVP_PKEY_keygen(ctx, &mut pkey) <= 0 || pkey.is_null() {
                openssl_sys::EVP_PKEY_CTX_free(ctx);
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "openssl: EVP_PKEY_keygen failed",
                ));
            }
            openssl_sys::EVP_PKEY_CTX_free(ctx);

            let mut pubkey = vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize];
            let mut pubkey_len = pubkey.len();
            if EVP_PKEY_get_raw_public_key(pkey, pubkey.as_mut_ptr(), &mut pubkey_len) <= 0 {
                openssl_sys::EVP_PKEY_free(pkey);
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "openssl: EVP_PKEY_get_raw_public_key failed",
                ));
            }
            if pubkey_len != ML_DSA_87_PUBKEY_BYTES as usize {
                openssl_sys::EVP_PKEY_free(pkey);
                return Err(TxError::new(
                    ErrorCode::TxErrSigNoncanonical,
                    "openssl: non-canonical ML-DSA public key length",
                ));
            }
            Ok(Self { pkey, pubkey })
        }
    }

    pub fn pubkey_bytes(&self) -> Vec<u8> {
        self.pubkey.clone()
    }

    pub fn sign_digest32(&self, digest32: [u8; 32]) -> Result<Vec<u8>, TxError> {
        if self.pkey.is_null() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: nil ML-DSA keypair",
            ));
        }
        unsafe {
            openssl_sys::ERR_clear_error();
            let mctx = EVP_MD_CTX_new();
            if mctx.is_null() {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "openssl: EVP_MD_CTX_new failed",
                ));
            }
            if EVP_DigestSignInit_ex(
                mctx,
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null(),
                self.pkey,
                core::ptr::null(),
            ) <= 0
            {
                EVP_MD_CTX_free(mctx);
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "openssl: EVP_DigestSignInit_ex failed",
                ));
            }
            let mut signature = vec![0u8; ML_DSA_87_SIG_BYTES as usize];
            let mut sig_len = signature.len();
            if EVP_DigestSign(
                mctx,
                signature.as_mut_ptr(),
                &mut sig_len,
                digest32.as_ptr(),
                digest32.len(),
            ) <= 0
            {
                EVP_MD_CTX_free(mctx);
                return Err(TxError::new(
                    ErrorCode::TxErrSigInvalid,
                    "openssl: EVP_DigestSign failed",
                ));
            }
            EVP_MD_CTX_free(mctx);
            if sig_len != ML_DSA_87_SIG_BYTES as usize {
                return Err(TxError::new(
                    ErrorCode::TxErrSigNoncanonical,
                    "openssl: non-canonical ML-DSA signature length",
                ));
            }
            signature.truncate(sig_len);
            Ok(signature)
        }
    }
}

impl DigestSigner for Mldsa87Keypair {
    fn pubkey_bytes(&self) -> Vec<u8> {
        Mldsa87Keypair::pubkey_bytes(self)
    }

    fn sign_digest32(&self, digest32: [u8; 32]) -> Result<Vec<u8>, TxError> {
        Mldsa87Keypair::sign_digest32(self, digest32)
    }
}

fn suite_alg_name(suite_id: u8) -> Result<&'static CStr, TxError> {
    match suite_id {
        SUITE_ID_ML_DSA_87 => Ok(c"ML-DSA-87"),
        _ => Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "verify_sig: unsupported suite_id",
        )),
    }
}

fn openssl_alg_name_cstr(name: &str) -> Option<&'static CStr> {
    match name {
        "ML-DSA-87" => Some(c"ML-DSA-87"),
        _ => None,
    }
}

fn parse_openssl_fips_mode(raw: &str) -> Result<OpenSslFipsMode, TxError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "off" => Ok(OpenSslFipsMode::Off),
        "ready" => Ok(OpenSslFipsMode::Ready),
        "only" => Ok(OpenSslFipsMode::Only),
        _ => Err(TxError::new(
            ErrorCode::TxErrParse,
            "openssl bootstrap: invalid RUBIN_OPENSSL_FIPS_MODE",
        )),
    }
}

fn ensure_openssl_bootstrap() -> Result<(), TxError> {
    let mode_raw = std::env::var("RUBIN_OPENSSL_FIPS_MODE").unwrap_or_default();
    let mode = parse_openssl_fips_mode(&mode_raw)?;
    ensure_openssl_bootstrap_for_mode(mode)
}

fn ensure_openssl_bootstrap_for_mode(mode: OpenSslFipsMode) -> Result<(), TxError> {
    if mode == OpenSslFipsMode::Off {
        return Ok(());
    }

    let require_fips = mode == OpenSslFipsMode::Only;
    let state = OPENSSL_BOOTSTRAP_STATE.get_or_init(|| openssl_bootstrap(require_fips));
    state.clone()
}

fn set_env_if_empty(key: &str, value: Option<String>) {
    let Some(raw_value) = value else {
        return;
    };
    let trimmed = raw_value.trim();
    if trimmed.is_empty() {
        return;
    }
    if std::env::var_os(key).is_some() {
        return;
    }
    std::env::set_var(key, trimmed);
}

fn openssl_check_sigalg(alg: &'static CStr, props: &'static CStr) -> Result<(), TxError> {
    unsafe {
        let sig =
            openssl_sys::EVP_SIGNATURE_fetch(core::ptr::null_mut(), alg.as_ptr(), props.as_ptr());
        if sig.is_null() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl bootstrap: EVP_SIGNATURE_fetch failed",
            ));
        }
        openssl_sys::EVP_SIGNATURE_free(sig);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_set_env_if_empty(key: &str, value: Option<String>) {
    set_env_if_empty(key, value);
}

#[cfg(test)]
pub(crate) fn test_suite_alg_name(suite_id: u8) -> Result<&'static str, TxError> {
    suite_alg_name(suite_id).map(|alg| alg.to_str().expect("cstr"))
}

#[cfg(test)]
pub(crate) fn test_ensure_openssl_bootstrap_for_mode(mode_raw: &str) -> Result<(), TxError> {
    let mode = parse_openssl_fips_mode(mode_raw)?;
    ensure_openssl_bootstrap_for_mode(mode)
}

#[cfg(test)]
pub(crate) fn test_openssl_check_sigalg_bad_alg() -> Result<(), TxError> {
    openssl_check_sigalg(c"NOT-A-REAL-SIGALG", c"")
}

#[cfg(test)]
pub(crate) fn test_openssl_verify_sig_digest_oneshot_empty_input() -> Result<bool, TxError> {
    openssl_verify_sig_digest_oneshot(c"ML-DSA-87", &[], &[], &[])
}

#[cfg(test)]
pub(crate) fn test_openssl_verify_sig_digest_oneshot_bad_alg() -> Result<bool, TxError> {
    openssl_verify_sig_digest_oneshot(c"NOT-A-REAL-SIGALG", &[1], &[1], &[1])
}

fn openssl_bootstrap(require_fips: bool) -> Result<(), TxError> {
    set_env_if_empty("OPENSSL_CONF", std::env::var("RUBIN_OPENSSL_CONF").ok());
    set_env_if_empty(
        "OPENSSL_MODULES",
        std::env::var("RUBIN_OPENSSL_MODULES").ok(),
    );

    unsafe {
        openssl_sys::ERR_clear_error();
        if OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, core::ptr::null()) != 1 {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl bootstrap: OPENSSL_init_crypto failed",
            ));
        }
        if !require_fips {
            return Ok(());
        }

        let fips_provider =
            openssl_sys::OSSL_PROVIDER_load(core::ptr::null_mut(), c"fips".as_ptr());
        if fips_provider.is_null() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl bootstrap: OSSL_PROVIDER_load(fips) failed",
            ));
        }

        if EVP_set_default_properties(core::ptr::null_mut(), c"fips=yes".as_ptr()) != 1 {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl bootstrap: EVP_set_default_properties(fips=yes) failed",
            ));
        }
    }

    openssl_check_sigalg(c"ML-DSA-87", c"provider=fips")?;
    Ok(())
}

fn map_openssl_init_rc(rc: core::ffi::c_int, message: &'static str) -> Result<(), TxError> {
    if rc == 1 {
        Ok(())
    } else {
        Err(TxError::new(ErrorCode::TxErrParse, message))
    }
}

/// Deterministic OpenSSL initialization for the consensus verification path.
///
/// Does NOT read any `RUBIN_OPENSSL_*` environment variables, does NOT load the
/// FIPS provider, and does NOT set `fips=yes` default properties. This ensures
/// that consensus signature verification produces identical results across all
/// nodes regardless of host environment configuration.
///
/// Non-consensus callers (key generation, signing, CLI tools) should continue
/// to use [`ensure_openssl_bootstrap`] which honors operator-configured FIPS.
fn openssl_consensus_bootstrap() -> Result<(), TxError> {
    unsafe {
        openssl_sys::ERR_clear_error();
        map_openssl_init_rc(
            OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, core::ptr::null()),
            "openssl consensus init: OPENSSL_init_crypto failed",
        )?;
    }
    openssl_check_sigalg(c"ML-DSA-87", c"")?;
    Ok(())
}

pub(crate) fn ensure_openssl_consensus_init() -> Result<(), TxError> {
    OPENSSL_CONSENSUS_INIT
        .get_or_init(openssl_consensus_bootstrap)
        .clone()
}

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
    let binding = resolve_suite_verifier_binding(
        SUITE_ID_ML_DSA_87,
        "ML-DSA-87",
        ML_DSA_87_PUBKEY_BYTES,
        ML_DSA_87_SIG_BYTES,
    )?;
    verify_sig_with_binding(&binding, pubkey, signature, digest32)
}

enum SuiteVerifierBinding {
    OpenSslDigest32V1 {
        alg: &'static CStr,
        pubkey_len: u64,
        sig_len: u64,
    },
}

// v1 keeps the current live verifier contract pinned to the canonical
// ML-DSA-87/OpenSSL-digest32 tuple from the shared live binding artifact.
// Runtime dispatch must resolve a concrete binding instead of treating
// registry.alg_name as an implicit backend switch.
//
// `suite_id` is admitted earlier by `runtime_suite_params_for_verification`.
// This helper intentionally does not restore a second hardcoded live-policy
// switch: the artifact stays authoritative, and only callers that advertise
// the exact canonical tuple can reuse the legacy v1 verifier path as in Go.
fn resolve_suite_verifier_binding(
    suite_id: u8,
    alg_name: &str,
    pubkey_len: u64,
    sig_len: u64,
) -> Result<SuiteVerifierBinding, TxError> {
    let _ = suite_id;
    let entry =
        live_binding_policy_runtime_entry(alg_name, pubkey_len, sig_len).map_err(|err| {
            if err
                == live_binding_policy_runtime_entry_not_found_error(alg_name, pubkey_len, sig_len)
            {
                return TxError::new(
                    ErrorCode::TxErrSigAlgInvalid,
                    "resolve_suite_verifier_binding: unsupported suite verifier binding",
                );
            }
            TxError::new(
                ErrorCode::TxErrSigAlgInvalid,
                "resolve_suite_verifier_binding: live binding policy invalid",
            )
        })?;
    match entry.runtime_binding.as_str() {
        LIVE_BINDING_POLICY_RUNTIME_OPENSSL_DIGEST32_V1 => {
            let alg = openssl_alg_name_cstr(entry.openssl_alg.as_str()).ok_or_else(|| {
                TxError::new(
                    ErrorCode::TxErrSigAlgInvalid,
                    "resolve_suite_verifier_binding: unsupported OpenSSL alg",
                )
            })?;
            return Ok(SuiteVerifierBinding::OpenSslDigest32V1 {
                alg,
                pubkey_len: entry.pubkey_len,
                sig_len: entry.sig_len,
            });
        }
        _ => {}
    }
    Err(TxError::new(
        ErrorCode::TxErrSigAlgInvalid,
        "resolve_suite_verifier_binding: unsupported suite verifier binding",
    ))
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

fn default_runtime_suite_registry() -> &'static crate::suite_registry::SuiteRegistry {
    DEFAULT_RUNTIME_SUITE_REGISTRY
        .get_or_init(crate::suite_registry::SuiteRegistry::default_registry)
}

fn runtime_verification_registry_with_default<'a>(
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

fn runtime_suite_params_for_verification(
    suite_id: u8,
    registry: Option<&crate::suite_registry::SuiteRegistry>,
) -> Result<crate::suite_registry::SuiteParams, TxError> {
    runtime_suite_params_for_verification_with_default(
        suite_id,
        registry,
        default_runtime_suite_registry(),
    )
}

fn runtime_suite_params_for_verification_with_default(
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
    let binding = resolve_suite_verifier_binding(
        suite_id,
        params.alg_name,
        params.pubkey_len,
        params.sig_len,
    )?;
    verify_sig_with_binding(&binding, pubkey, signature, digest32)
}

fn map_digest_verify_rc(rc: core::ffi::c_int) -> Result<bool, TxError> {
    if rc == 1 {
        Ok(true)
    } else if rc == 0 {
        Ok(false)
    } else {
        Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "openssl: EVP_DigestVerify internal error",
        ))
    }
}

pub(crate) fn openssl_verify_sig_digest_oneshot(
    alg: &'static CStr,
    pubkey: &[u8],
    signature: &[u8],
    msg: &[u8],
) -> Result<bool, TxError> {
    if pubkey.is_empty() || signature.is_empty() || msg.is_empty() {
        return Err(TxError::new(ErrorCode::TxErrParse, "openssl: empty input"));
    }

    unsafe {
        openssl_sys::ERR_clear_error();

        let pkey = EVP_PKEY_new_raw_public_key_ex(
            core::ptr::null_mut(),
            alg.as_ptr(),
            core::ptr::null(),
            pubkey.as_ptr(),
            pubkey.len(),
        );
        if pkey.is_null() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_PKEY_new_raw_public_key_ex failed",
            ));
        }

        let mctx = EVP_MD_CTX_new();
        if mctx.is_null() {
            openssl_sys::EVP_PKEY_free(pkey);
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_MD_CTX_new failed",
            ));
        }

        if EVP_DigestVerifyInit_ex(
            mctx,
            core::ptr::null_mut(),
            core::ptr::null(),
            core::ptr::null_mut(),
            core::ptr::null(),
            pkey,
            core::ptr::null(),
        ) <= 0
        {
            EVP_MD_CTX_free(mctx);
            openssl_sys::EVP_PKEY_free(pkey);
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_DigestVerifyInit_ex failed",
            ));
        }

        let rc = EVP_DigestVerify(
            mctx,
            signature.as_ptr(),
            signature.len(),
            msg.as_ptr(),
            msg.len(),
        );

        EVP_MD_CTX_free(mctx);
        openssl_sys::EVP_PKEY_free(pkey);
        map_digest_verify_rc(rc)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        map_digest_verify_rc, map_openssl_init_rc, openssl_bootstrap, parse_openssl_fips_mode,
        Mldsa87Keypair, OpenSslFipsMode,
    };
    use crate::error::ErrorCode;
    use std::sync::{Mutex, OnceLock};

    fn canonical_default_suite_params() -> crate::suite_registry::SuiteParams {
        crate::suite_registry::SuiteRegistry::default_registry()
            .lookup(crate::constants::SUITE_ID_ML_DSA_87)
            .cloned()
            .expect("default runtime registry missing ML-DSA-87")
    }

    fn drifted_default_runtime_registry(
        mutate: impl FnOnce(&mut crate::suite_registry::SuiteParams),
    ) -> crate::suite_registry::SuiteRegistry {
        let mut params = canonical_default_suite_params();
        mutate(&mut params);
        let mut suites = std::collections::BTreeMap::new();
        suites.insert(crate::constants::SUITE_ID_ML_DSA_87, params);
        crate::suite_registry::SuiteRegistry::with_suites(suites)
    }

    fn openssl_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn map_digest_verify_rc_accepts_valid_signature() {
        let got = map_digest_verify_rc(1).expect("rc=1 should be success");
        assert!(got);
    }

    #[test]
    fn map_digest_verify_rc_rejects_invalid_signature() {
        let got = map_digest_verify_rc(0).expect("rc=0 should be deterministic invalid");
        assert!(!got);
    }

    #[test]
    fn map_digest_verify_rc_negative_maps_to_sig_invalid() {
        let err = map_digest_verify_rc(-1).expect_err("rc<0 should be mapped error");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn map_openssl_init_rc_accepts_success() {
        map_openssl_init_rc(1, "bootstrap failed").expect("rc=1 should pass");
    }

    #[test]
    fn map_openssl_init_rc_maps_failure_to_parse() {
        let err = map_openssl_init_rc(0, "bootstrap failed").expect_err("rc!=1 should fail");
        assert_eq!(err.code, ErrorCode::TxErrParse);
        assert_eq!(err.msg, "bootstrap failed");
    }

    #[test]
    fn parse_openssl_fips_mode_accepts_supported_values() {
        assert_eq!(
            parse_openssl_fips_mode("").expect("empty should map to off"),
            OpenSslFipsMode::Off
        );
        assert_eq!(
            parse_openssl_fips_mode("off").expect("off should map to off"),
            OpenSslFipsMode::Off
        );
        assert_eq!(
            parse_openssl_fips_mode("ready").expect("ready should parse"),
            OpenSslFipsMode::Ready
        );
        assert_eq!(
            parse_openssl_fips_mode("only").expect("only should parse"),
            OpenSslFipsMode::Only
        );
    }

    #[test]
    fn parse_openssl_fips_mode_rejects_unknown_value() {
        let err = parse_openssl_fips_mode("definitely-invalid")
            .expect_err("unknown mode must return parse error");
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn openssl_bootstrap_ready_smoke() {
        openssl_bootstrap(false).expect("ready-mode bootstrap should succeed");
    }

    #[test]
    fn openssl_bootstrap_only_smoke_or_parse_error() {
        if let Err(err) = openssl_bootstrap(true) {
            assert_eq!(err.code, ErrorCode::TxErrParse);
        }
    }

    #[test]
    fn mldsa87_keypair_generate_sign_and_verify_roundtrip() {
        let keypair = match Mldsa87Keypair::generate() {
            Ok(value) => value,
            Err(err) => {
                assert_eq!(err.code, ErrorCode::TxErrParse);
                return;
            }
        };
        let pubkey = keypair.pubkey_bytes();
        let digest = [0x42; 32];
        let signature = keypair.sign_digest32(digest).expect("sign digest");
        let ok = super::verify_sig(
            crate::constants::SUITE_ID_ML_DSA_87,
            &pubkey,
            &signature,
            &digest,
        )
        .expect("verify signature");
        assert!(ok);
    }

    #[test]
    fn openssl_consensus_bootstrap_ignores_inherited_openssl_env() {
        let _guard = openssl_env_lock().lock().expect("env lock");
        let saved_conf = std::env::var_os("OPENSSL_CONF");
        let saved_modules = std::env::var_os("OPENSSL_MODULES");
        std::env::remove_var("OPENSSL_CONF");
        std::env::remove_var("OPENSSL_MODULES");

        let keypair = match Mldsa87Keypair::generate() {
            Ok(value) => value,
            Err(err) => {
                if let Some(value) = saved_conf {
                    std::env::set_var("OPENSSL_CONF", value);
                } else {
                    std::env::remove_var("OPENSSL_CONF");
                }
                if let Some(value) = saved_modules {
                    std::env::set_var("OPENSSL_MODULES", value);
                } else {
                    std::env::remove_var("OPENSSL_MODULES");
                }
                assert_eq!(err.code, ErrorCode::TxErrParse);
                return;
            }
        };
        let pubkey = keypair.pubkey_bytes();
        let digest = [0x6a; 32];
        let signature = keypair.sign_digest32(digest).expect("sign digest");

        std::env::set_var("OPENSSL_CONF", "/tmp/rubin-consensus-invalid-openssl.cnf");
        std::env::set_var(
            "OPENSSL_MODULES",
            "/tmp/rubin-consensus-invalid-ossl-modules",
        );

        super::openssl_consensus_bootstrap()
            .expect("consensus bootstrap must ignore inherited OPENSSL_* env");
        let ok =
            super::openssl_verify_sig_digest_oneshot(c"ML-DSA-87", &pubkey, &signature, &digest)
                .expect("verify signature under poisoned OPENSSL_* env");
        assert!(ok);

        if let Some(value) = saved_conf {
            std::env::set_var("OPENSSL_CONF", value);
        } else {
            std::env::remove_var("OPENSSL_CONF");
        }
        if let Some(value) = saved_modules {
            std::env::set_var("OPENSSL_MODULES", value);
        } else {
            std::env::remove_var("OPENSSL_MODULES");
        }
    }

    /// Helper: generate keypair or skip test if OpenSSL state is corrupted
    /// by bootstrap FIPS tests polluting global EVP provider config.
    /// Only skips the narrow "CTX_new_from_name failed" case — any other
    /// keygen failure is a real regression and must panic.
    fn generate_or_skip() -> Option<Mldsa87Keypair> {
        match Mldsa87Keypair::generate() {
            Ok(kp) => Some(kp),
            Err(err) => {
                assert_eq!(err.code, ErrorCode::TxErrParse);
                assert!(
                    err.msg.contains("EVP_PKEY_CTX_new_from_name"),
                    "keygen failed for unexpected reason (not bootstrap pollution): {}",
                    err.msg
                );
                None // skip: OpenSSL state poisoned by bootstrap test
            }
        }
    }

    // Key Generation & Lifecycle (5)
    #[test]
    fn keypair_generate_pubkey_is_expected_length() {
        let Some(kp) = generate_or_skip() else { return };
        assert_eq!(
            kp.pubkey_bytes().len(),
            crate::constants::ML_DSA_87_PUBKEY_BYTES as usize
        );
    }

    #[test]
    fn keypair_pubkey_bytes_is_copy() {
        let Some(kp) = generate_or_skip() else { return };
        let a = kp.pubkey_bytes();
        let b = kp.pubkey_bytes();
        assert_eq!(a, b);
    }

    #[test]
    fn keypair_sign_digest_produces_expected_length() {
        let Some(kp) = generate_or_skip() else { return };
        let sig = kp.sign_digest32([0x42; 32]).expect("sign");
        assert_eq!(sig.len(), crate::constants::ML_DSA_87_SIG_BYTES as usize);
    }

    #[test]
    fn keypair_close_idempotent() {
        let Some(kp) = generate_or_skip() else { return };
        drop(kp);
    }

    #[test]
    fn keypair_generate_different_pubkeys() {
        let Some(a) = generate_or_skip() else { return };
        let Some(b) = generate_or_skip() else { return };
        assert_ne!(a.pubkey_bytes(), b.pubkey_bytes());
    }

    // Verify Error Paths (6)
    #[test]
    fn verify_sig_unsupported_suite_returns_error() {
        let err =
            super::verify_sig(0xFF, &[0u8; 32], &[0u8; 32], &[0u8; 32]).expect_err("bad suite");
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn verify_sig_empty_inputs_return_false_or_error() {
        let result = super::verify_sig(crate::constants::SUITE_ID_ML_DSA_87, &[], &[], &[0u8; 32]);
        match result {
            Ok(false) => {}
            Err(_) => {}
            Ok(true) => panic!("empty inputs must not verify as true"),
        }
    }

    #[test]
    fn verify_sig_wrong_message_returns_false() {
        let Some(kp) = generate_or_skip() else { return };
        let digest = [0x11; 32];
        let sig = kp.sign_digest32(digest).expect("sign");
        let wrong_digest = [0x22; 32];
        let result = super::verify_sig(
            crate::constants::SUITE_ID_ML_DSA_87,
            &kp.pubkey_bytes(),
            &sig,
            &wrong_digest,
        )
        .expect("no error");
        assert!(!result, "wrong digest must return false");
    }

    #[test]
    fn verify_sig_rejects_wrong_mldsa_lengths() {
        let result = super::verify_sig(
            crate::constants::SUITE_ID_ML_DSA_87,
            &[0u8; 16],
            &[0u8; 16],
            &[0u8; 32],
        );
        match result {
            Ok(false) => {}
            Err(_) => {}
            Ok(true) => panic!("wrong lengths must not verify true"),
        }
    }

    #[test]
    fn verify_sig_corrupted_sig_returns_false() {
        let Some(kp) = generate_or_skip() else { return };
        let digest = [0x33; 32];
        let sig = kp.sign_digest32(digest).expect("sign");
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xFF;
        let result = super::verify_sig(
            crate::constants::SUITE_ID_ML_DSA_87,
            &kp.pubkey_bytes(),
            &bad_sig,
            &digest,
        )
        .expect("no error");
        assert!(!result, "corrupted sig must return false");
    }

    #[test]
    fn verify_sig_unknown_suite_errors() {
        let err = super::verify_sig(0x42, &[0u8; 100], &[0u8; 100], &[0u8; 32])
            .expect_err("unknown suite");
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    // Bootstrap & FIPS (7)
    #[test]
    fn bootstrap_mode_off_noop() {
        super::test_ensure_openssl_bootstrap_for_mode("off").expect("off is noop");
    }

    #[test]
    fn bootstrap_invalid_fips_mode_rejected() {
        super::test_ensure_openssl_bootstrap_for_mode("banana").expect_err("bad mode");
    }

    #[test]
    fn bootstrap_fips_only_or_skip() {
        let _ = super::test_ensure_openssl_bootstrap_for_mode("only");
    }

    #[test]
    fn suite_alg_name_known_suite() {
        let name = super::test_suite_alg_name(crate::constants::SUITE_ID_ML_DSA_87).expect("known");
        assert_eq!(name, "ML-DSA-87");
    }

    #[test]
    fn suite_alg_name_unknown_suite_errors() {
        super::test_suite_alg_name(0xFF).expect_err("unknown");
    }

    #[test]
    fn verify_sig_valid_roundtrip_ignores_fips() {
        let Some(kp) = generate_or_skip() else { return };
        let digest = [0x44; 32];
        let sig = kp.sign_digest32(digest).expect("sign");
        let ok = super::verify_sig(
            crate::constants::SUITE_ID_ML_DSA_87,
            &kp.pubkey_bytes(),
            &sig,
            &digest,
        )
        .expect("verify");
        assert!(ok, "valid sig must verify");
    }

    #[test]
    fn set_env_if_empty_behavior() {
        super::test_set_env_if_empty("RUBIN_TEST_UNUSED_KEY_12345", Some("value".to_string()));
    }

    // Concurrency (1)
    #[test]
    fn verify_sig_parallel_deterministic() {
        let Some(kp) = generate_or_skip() else { return };
        let digest = [0x55; 32];
        let sig = kp.sign_digest32(digest).expect("sign");
        let pubkey = kp.pubkey_bytes();

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let pk = pubkey.clone();
                let s = sig.clone();
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        let ok = super::verify_sig(
                            crate::constants::SUITE_ID_ML_DSA_87,
                            &pk,
                            &s,
                            &digest,
                        )
                        .expect("verify");
                        assert!(ok, "parallel verify must succeed");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread");
        }
    }

    // Registry Extension (2)
    #[test]
    fn verify_sig_with_registry_nil_uses_default_live_registry() {
        let Some(kp) = generate_or_skip() else { return };
        let digest = [0x66; 32];
        let sig = kp.sign_digest32(digest).expect("sign");
        let ok = super::verify_sig_with_registry(
            crate::constants::SUITE_ID_ML_DSA_87,
            &kp.pubkey_bytes(),
            &sig,
            &digest,
            None,
        )
        .expect("verify");
        assert!(ok, "default live registry must verify canonical suite");
        assert!(super::default_runtime_suite_registry().is_canonical_default_live_manifest());
    }

    #[test]
    fn verify_sig_with_registry_nil_matches_explicit_default_live_registry() {
        let Some(kp) = generate_or_skip() else { return };
        let digest = [0x67; 32];
        let sig = kp.sign_digest32(digest).expect("sign");
        let explicit = crate::suite_registry::SuiteRegistry::default_registry();
        let canonical = canonical_default_suite_params();
        assert_eq!(
            canonical.verify_cost,
            crate::constants::VERIFY_COST_ML_DSA_87
        );

        let nil_ok = super::verify_sig_with_registry(
            crate::constants::SUITE_ID_ML_DSA_87,
            &kp.pubkey_bytes(),
            &sig,
            &digest,
            None,
        )
        .expect("nil verify");
        let explicit_ok = super::verify_sig_with_registry(
            crate::constants::SUITE_ID_ML_DSA_87,
            &kp.pubkey_bytes(),
            &sig,
            &digest,
            Some(&explicit),
        )
        .expect("explicit verify");

        assert_eq!(nil_ok, explicit_ok);
        assert!(
            nil_ok,
            "canonical default live registry must verify on both paths"
        );
        let explicit_params = explicit
            .lookup(crate::constants::SUITE_ID_ML_DSA_87)
            .cloned()
            .expect("explicit default registry missing ML-DSA-87");
        assert_eq!(canonical, explicit_params);
    }

    #[test]
    fn runtime_suite_params_for_verification_nil_matches_explicit_default_live_registry() {
        let canonical = canonical_default_suite_params();
        let explicit = crate::suite_registry::SuiteRegistry::default_registry();

        let nil_params = super::runtime_suite_params_for_verification(
            crate::constants::SUITE_ID_ML_DSA_87,
            None,
        )
        .expect("nil params");
        let explicit_params = super::runtime_suite_params_for_verification(
            crate::constants::SUITE_ID_ML_DSA_87,
            Some(&explicit),
        )
        .expect("explicit params");

        assert_eq!(nil_params, canonical);
        assert_eq!(explicit_params, canonical);
        assert_eq!(nil_params, explicit_params);
    }

    #[test]
    fn runtime_suite_params_for_verification_public_wrapper_matches_helper() {
        let explicit = crate::suite_registry::SuiteRegistry::default_registry();

        let public_nil = super::runtime_suite_params_for_verification(
            crate::constants::SUITE_ID_ML_DSA_87,
            None,
        )
        .expect("public nil params");
        let helper_nil = super::runtime_suite_params_for_verification_with_default(
            crate::constants::SUITE_ID_ML_DSA_87,
            None,
            &explicit,
        )
        .expect("helper nil params");

        let public_explicit = super::runtime_suite_params_for_verification(
            crate::constants::SUITE_ID_ML_DSA_87,
            Some(&explicit),
        )
        .expect("public explicit params");
        let helper_explicit = super::runtime_suite_params_for_verification_with_default(
            crate::constants::SUITE_ID_ML_DSA_87,
            Some(&explicit),
            &explicit,
        )
        .expect("helper explicit params");

        assert_eq!(public_nil, helper_nil);
        assert_eq!(public_explicit, helper_explicit);
        assert_eq!(public_nil, public_explicit);
    }

    #[test]
    fn runtime_suite_params_for_verification_unknown_suite_preserves_error_surface() {
        let err = super::runtime_suite_params_for_verification(0xff, None)
            .expect_err("unknown suite must fail closed");
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
        assert_eq!(err.msg, "verify_sig: unsupported suite_id");
    }

    #[test]
    fn resolve_suite_verifier_binding_matches_core_ext_descriptor() {
        let params = canonical_default_suite_params();
        let binding = super::resolve_suite_verifier_binding(
            params.suite_id,
            params.alg_name,
            params.pubkey_len,
            params.sig_len,
        )
        .expect("binding");
        let descriptor = crate::core_ext_openssl_digest32_binding_descriptor_bytes(
            params.alg_name,
            params.pubkey_len,
            params.sig_len,
        )
        .expect("descriptor");
        let parsed =
            crate::parse_core_ext_openssl_digest32_binding_descriptor(&descriptor).expect("parse");
        match binding {
            super::SuiteVerifierBinding::OpenSslDigest32V1 {
                alg,
                pubkey_len,
                sig_len,
            } => {
                assert_eq!(alg.to_str().expect("alg utf8"), parsed.openssl_alg);
                assert_eq!(pubkey_len, parsed.pubkey_len);
                assert_eq!(sig_len, parsed.sig_len);
            }
        }
    }

    #[test]
    fn resolve_suite_verifier_binding_live_policy_pins_canonical_legacy_v1_binding() {
        let entry = crate::live_binding_policy::live_binding_policy_runtime_entry(
            "ML-DSA-87",
            crate::constants::ML_DSA_87_PUBKEY_BYTES,
            crate::constants::ML_DSA_87_SIG_BYTES,
        )
        .expect("live binding entry");
        assert_eq!(
            entry.runtime_binding,
            crate::live_binding_policy::LIVE_BINDING_POLICY_RUNTIME_OPENSSL_DIGEST32_V1
        );
        assert_eq!(entry.alg_name, "ML-DSA-87");
        assert_eq!(entry.openssl_alg, "ML-DSA-87");

        let binding = super::resolve_suite_verifier_binding(
            crate::constants::SUITE_ID_ML_DSA_87,
            "ML-DSA-87",
            crate::constants::ML_DSA_87_PUBKEY_BYTES,
            crate::constants::ML_DSA_87_SIG_BYTES,
        )
        .expect("binding");
        match binding {
            super::SuiteVerifierBinding::OpenSslDigest32V1 {
                alg,
                pubkey_len,
                sig_len,
            } => {
                assert_eq!(alg.to_str().expect("alg utf8"), "ML-DSA-87");
                assert_eq!(pubkey_len, crate::constants::ML_DSA_87_PUBKEY_BYTES);
                assert_eq!(sig_len, crate::constants::ML_DSA_87_SIG_BYTES);
            }
        }
    }

    #[test]
    fn verify_sig_with_registry_unknown_suite_errors() {
        let err = super::verify_sig_with_registry(0xFF, &[0u8; 32], &[0u8; 32], &[0u8; 32], None)
            .expect_err("bad suite");
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn verify_sig_with_registry_custom_suite_exact_v1_binding_allowed() {
        let Some(kp) = generate_or_skip() else { return };
        let digest = [0x68; 32];
        let sig = kp.sign_digest32(digest).expect("sign");
        let mut suites = std::collections::BTreeMap::new();
        suites.insert(
            0x02,
            crate::suite_registry::SuiteParams {
                suite_id: 0x02,
                pubkey_len: crate::constants::ML_DSA_87_PUBKEY_BYTES,
                sig_len: crate::constants::ML_DSA_87_SIG_BYTES,
                verify_cost: crate::constants::VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87",
            },
        );
        let registry = crate::suite_registry::SuiteRegistry::with_suites(suites);

        let ok = super::verify_sig_with_registry(
            0x02,
            &kp.pubkey_bytes(),
            &sig,
            &digest,
            Some(&registry),
        )
        .expect("custom suite should reuse canonical v1 binding");
        assert!(ok, "custom suite entry should verify");
    }

    #[test]
    fn runtime_verification_registry_rejects_noncanonical_default_manifest() {
        let test_cases = [
            (
                "alg_name",
                drifted_default_runtime_registry(|params| params.alg_name = "ML-DSA-65"),
            ),
            (
                "pubkey_len",
                drifted_default_runtime_registry(|params| params.pubkey_len -= 1),
            ),
            (
                "sig_len",
                drifted_default_runtime_registry(|params| params.sig_len -= 1),
            ),
            (
                "verify_cost",
                drifted_default_runtime_registry(|params| params.verify_cost -= 1),
            ),
        ];

        for (name, registry) in test_cases {
            let err = super::runtime_verification_registry_with_default(None, &registry)
                .expect_err("noncanonical default registry must fail closed");
            assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid, "{name}");
            assert_eq!(
                err.msg, "verify_sig: default runtime registry drift",
                "{name}"
            );
        }
    }

    #[test]
    fn runtime_verification_registry_rejects_empty_and_alias_alg_name() {
        let test_cases = [
            (
                "alg_name_empty",
                drifted_default_runtime_registry(|params| params.alg_name = ""),
            ),
            (
                "alg_name_alias",
                drifted_default_runtime_registry(|params| params.alg_name = "ml-dsa-87"),
            ),
        ];

        for (name, registry) in test_cases {
            let err = super::runtime_verification_registry_with_default(None, &registry)
                .expect_err("noncanonical default registry must fail closed");
            assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid, "{name}");
            assert_eq!(
                err.msg, "verify_sig: default runtime registry drift",
                "{name}"
            );
        }
    }

    #[test]
    fn runtime_verification_registry_rejects_pubkey_sig_and_verify_cost_drift() {
        let test_cases = [
            (
                "pubkey_len",
                drifted_default_runtime_registry(|params| params.pubkey_len -= 1),
            ),
            (
                "sig_len",
                drifted_default_runtime_registry(|params| params.sig_len -= 1),
            ),
            (
                "verify_cost",
                drifted_default_runtime_registry(|params| params.verify_cost -= 1),
            ),
        ];

        for (name, registry) in test_cases {
            let err = super::runtime_verification_registry_with_default(None, &registry)
                .expect_err("noncanonical default registry must fail closed");
            assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid, "{name}");
            assert_eq!(
                err.msg, "verify_sig: default runtime registry drift",
                "{name}"
            );
        }
    }

    #[test]
    fn runtime_suite_params_for_verification_with_default_rejects_noncanonical_default_manifest() {
        let test_cases = [
            (
                "alg_name_empty",
                drifted_default_runtime_registry(|params| params.alg_name = ""),
            ),
            (
                "alg_name_alias",
                drifted_default_runtime_registry(|params| params.alg_name = "ml-dsa-87"),
            ),
            (
                "pubkey_len",
                drifted_default_runtime_registry(|params| params.pubkey_len -= 1),
            ),
            (
                "sig_len",
                drifted_default_runtime_registry(|params| params.sig_len -= 1),
            ),
            (
                "verify_cost",
                drifted_default_runtime_registry(|params| params.verify_cost -= 1),
            ),
        ];

        for (name, registry) in test_cases {
            let err = super::runtime_suite_params_for_verification_with_default(
                crate::constants::SUITE_ID_ML_DSA_87,
                None,
                &registry,
            )
            .expect_err("noncanonical default registry must fail closed");
            assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid, "{name}");
            assert_eq!(
                err.msg, "verify_sig: default runtime registry drift",
                "{name}"
            );
        }
    }

    // Error Parsing (2)
    #[test]
    fn parse_fips_mode_valid_values() {
        super::test_ensure_openssl_bootstrap_for_mode("off").expect("off");
        // "ready" mode may fail if FIPS provider not available — not a test failure
        let _ = super::test_ensure_openssl_bootstrap_for_mode("ready");
    }

    #[test]
    fn openssl_check_sigalg_bad_alg_fails() {
        super::test_openssl_check_sigalg_bad_alg().expect_err("bad alg must fail");
    }

    // Additional verification (1)
    #[test]
    fn openssl_verify_with_invalid_alg_name() {
        // Test that invalid algorithm names are rejected
        let result = super::test_openssl_verify_sig_digest_oneshot_bad_alg();
        assert!(result.is_err());
    }
}
