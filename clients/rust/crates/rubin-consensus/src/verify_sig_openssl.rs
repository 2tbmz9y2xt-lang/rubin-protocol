mod alg;
mod binding;
mod digest;

use crate::constants::{ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87};
use crate::error::{ErrorCode, TxError};
use crate::tx_helpers::DigestSigner;
use core::ffi::CStr;
use std::sync::OnceLock;

use alg::suite_alg_name;
use digest::map_digest_verify_rc;

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
pub(crate) fn test_ensure_openssl_bootstrap_for_mode(mode_raw: &str) -> Result<(), TxError> {
    let mode = parse_openssl_fips_mode(mode_raw)?;
    ensure_openssl_bootstrap_for_mode(mode)
}

#[cfg(test)]
pub(crate) fn test_openssl_check_sigalg_bad_alg() -> Result<(), TxError> {
    openssl_check_sigalg(c"NOT-A-REAL-SIGALG", c"")
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
    let binding = binding::resolve_suite_verifier_binding(
        "ML-DSA-87",
        ML_DSA_87_PUBKEY_BYTES,
        ML_DSA_87_SIG_BYTES,
    )?;
    binding::verify_sig_with_binding(&binding, pubkey, signature, digest32)
}

// v1 keeps the current live verifier contract pinned to the canonical
// ML-DSA-87/OpenSSL-digest32 tuple from the shared live binding artifact.
// Runtime dispatch must resolve a concrete binding instead of treating
// registry.alg_name as an implicit backend switch.
//
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
pub(crate) use alg::test_suite_alg_name;
#[cfg(test)]
pub(crate) use digest::{
    test_openssl_verify_sig_digest_oneshot_bad_alg,
    test_openssl_verify_sig_digest_oneshot_empty_input,
};
#[cfg(test)]
mod tests;
