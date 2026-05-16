mod alg;
mod binding;
mod bootstrap;
mod digest;
mod ffi;
mod keypair;

use crate::constants::{ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87};
use crate::error::ErrorCode::{TxErrSigInvalid, TxErrSigNoncanonical};
use crate::error::{ErrorCode, TxError};
use crate::tx_helpers::DigestSigner;
use core::ffi::CStr;
use std::sync::OnceLock;

use alg::suite_alg_name;
use bootstrap::ensure_openssl_bootstrap;
use digest::map_digest_verify_rc;
pub use keypair::Mldsa87Keypair;

const OPENSSL_INIT_LOAD_CONFIG: u64 = 0x0000_0040;
const OPENSSL_INIT_NO_LOAD_CONFIG: u64 = 0x0000_0080;
const ERR_KEY_CTX: &str = "openssl: EVP_PKEY_CTX_new_from_name failed";
const ERR_RAW_PUBKEY: &str = "openssl: EVP_PKEY_get_raw_public_key failed";
const ERR_BAD_PUBKEY_LEN: &str = "openssl: non-canonical ML-DSA public key length";
const ERR_DIGEST_SIGN: &str = "openssl: EVP_DigestSign failed";
const ERR_BAD_SIG_LEN: &str = "openssl: non-canonical ML-DSA signature length";

static OPENSSL_CONSENSUS_INIT: OnceLock<Result<(), TxError>> = OnceLock::new();

fn openssl_parse_error(message: &'static str) -> TxError {
    TxError::new(ErrorCode::TxErrParse, message)
}

fn read_mldsa87_pubkey(pkey: *mut openssl_sys::EVP_PKEY) -> Result<Vec<u8>, TxError> {
    unsafe {
        // SAFETY: pkey is a live EVP_PKEY owned by the caller. The output
        // buffer is ML_DSA_87_PUBKEY_BYTES long, and OpenSSL writes at most the
        // provided length through pubkey_len. On failure or non-canonical length
        // this helper consumes and frees pkey so no partially initialized keypair
        // can leak ownership.
        let mut pubkey = vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize];
        let mut pubkey_len = pubkey.len();
        if ffi::EVP_PKEY_get_raw_public_key(pkey, pubkey.as_mut_ptr(), &mut pubkey_len) <= 0 {
            openssl_sys::EVP_PKEY_free(pkey);
            return Err(openssl_parse_error(ERR_RAW_PUBKEY));
        }
        if pubkey_len != ML_DSA_87_PUBKEY_BYTES as usize {
            openssl_sys::EVP_PKEY_free(pkey);
            return Err(TxError::new(TxErrSigNoncanonical, ERR_BAD_PUBKEY_LEN));
        }
        Ok(pubkey)
    }
}

fn new_digest_sign_ctx(keypair: &Mldsa87Keypair) -> Result<*mut openssl_sys::EVP_MD_CTX, TxError> {
    let pkey = keypair.pkey;
    if pkey.is_null() {
        return Err(openssl_parse_error("openssl: nil ML-DSA keypair"));
    }
    unsafe {
        // SAFETY: Mldsa87Keypair owns pkey and keeps it live for this call.
        // ERR_clear_error only resets OpenSSL's thread-local error queue.
        // OpenSSL allocates mctx here; every failure after allocation frees it
        // before returning, while success transfers it to sign_mldsa87_digest.
        openssl_sys::ERR_clear_error();
        let mctx = ffi::EVP_MD_CTX_new();
        if mctx.is_null() {
            return Err(openssl_parse_error("openssl: EVP_MD_CTX_new failed"));
        }
        if ffi::EVP_DigestSignInit_ex(
            mctx,
            core::ptr::null_mut(),
            core::ptr::null(),
            core::ptr::null_mut(),
            core::ptr::null(),
            pkey,
            core::ptr::null(),
        ) <= 0
        {
            ffi::EVP_MD_CTX_free(mctx);
            return Err(openssl_parse_error("openssl: EVP_DigestSignInit_ex failed"));
        }
        Ok(mctx)
    }
}

fn sign_mldsa87_digest(
    mctx: *mut openssl_sys::EVP_MD_CTX,
    digest32: [u8; 32],
) -> Result<Vec<u8>, TxError> {
    unsafe {
        // SAFETY: mctx is returned by new_digest_sign_ctx and is valid until this
        // function frees it on every path. signature is allocated to the maximum
        // ML-DSA-87 signature size, sig_len points to its current capacity, and
        // digest32 is an owned 32-byte digest with a stable pointer for the call.
        let mut signature = vec![0u8; ML_DSA_87_SIG_BYTES as usize];
        let mut sig_len = signature.len();
        if ffi::EVP_DigestSign(
            mctx,
            signature.as_mut_ptr(),
            &mut sig_len,
            digest32.as_ptr(),
            digest32.len(),
        ) <= 0
        {
            ffi::EVP_MD_CTX_free(mctx);
            return Err(TxError::new(TxErrSigInvalid, ERR_DIGEST_SIGN));
        }
        ffi::EVP_MD_CTX_free(mctx);
        if sig_len != ML_DSA_87_SIG_BYTES as usize {
            return Err(TxError::new(TxErrSigNoncanonical, ERR_BAD_SIG_LEN));
        }
        signature.truncate(sig_len);
        Ok(signature)
    }
}

impl Drop for Mldsa87Keypair {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: pkey ownership is unique to this keypair. The null check
            // makes Drop idempotent against earlier explicit cleanup paths.
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
            // SAFETY: alg is a static NUL-terminated CStr selected from the
            // canonical suite registry. ctx is freed on every error path after
            // allocation. On successful keygen, pkey ownership is either consumed
            // by read_mldsa87_pubkey on failure or stored in Mldsa87Keypair.
            // If keygen fails after writing pkey, this path frees it below.
            openssl_sys::ERR_clear_error();
            let ctx = ffi::EVP_PKEY_CTX_new_from_name(
                core::ptr::null_mut(),
                alg.as_ptr(),
                core::ptr::null(),
            );
            if ctx.is_null() {
                return Err(openssl_parse_error(ERR_KEY_CTX));
            }
            if openssl_sys::EVP_PKEY_keygen_init(ctx) <= 0 {
                openssl_sys::EVP_PKEY_CTX_free(ctx);
                return Err(openssl_parse_error("openssl: EVP_PKEY_keygen_init failed"));
            }
            let mut pkey: *mut openssl_sys::EVP_PKEY = core::ptr::null_mut();
            if openssl_sys::EVP_PKEY_keygen(ctx, &mut pkey) <= 0 || pkey.is_null() {
                openssl_sys::EVP_PKEY_CTX_free(ctx);
                if !pkey.is_null() {
                    openssl_sys::EVP_PKEY_free(pkey);
                }
                return Err(openssl_parse_error("openssl: EVP_PKEY_keygen failed"));
            }
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            let pubkey = read_mldsa87_pubkey(pkey)?;
            Ok(Self { pkey, pubkey })
        }
    }

    pub fn pubkey_bytes(&self) -> Vec<u8> {
        self.pubkey.clone()
    }

    pub fn sign_digest32(&self, digest32: [u8; 32]) -> Result<Vec<u8>, TxError> {
        let mctx = new_digest_sign_ctx(self)?;
        sign_mldsa87_digest(mctx, digest32)
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

fn openssl_bootstrap(require_fips: bool) -> Result<(), TxError> {
    set_env_if_empty("OPENSSL_CONF", std::env::var("RUBIN_OPENSSL_CONF").ok());
    set_env_if_empty(
        "OPENSSL_MODULES",
        std::env::var("RUBIN_OPENSSL_MODULES").ok(),
    );

    unsafe {
        openssl_sys::ERR_clear_error();
        if ffi::OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, core::ptr::null()) != 1 {
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

        if ffi::EVP_set_default_properties(core::ptr::null_mut(), c"fips=yes".as_ptr()) != 1 {
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
            ffi::OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, core::ptr::null()),
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

    // SAFETY: alg is a static OpenSSL algorithm name, and pubkey, signature,
    // and msg are immutable slices whose pointers remain valid for each FFI
    // call. This block owns pkey and mctx after allocation and frees both on
    // every error and success path before returning.
    unsafe {
        openssl_sys::ERR_clear_error();

        let pkey = ffi::EVP_PKEY_new_raw_public_key_ex(
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

        let mctx = ffi::EVP_MD_CTX_new();
        if mctx.is_null() {
            openssl_sys::EVP_PKEY_free(pkey);
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_MD_CTX_new failed",
            ));
        }

        if ffi::EVP_DigestVerifyInit_ex(
            mctx,
            core::ptr::null_mut(),
            core::ptr::null(),
            core::ptr::null_mut(),
            core::ptr::null(),
            pkey,
            core::ptr::null(),
        ) <= 0
        {
            ffi::EVP_MD_CTX_free(mctx);
            openssl_sys::EVP_PKEY_free(pkey);
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_DigestVerifyInit_ex failed",
            ));
        }

        let rc = ffi::EVP_DigestVerify(
            mctx,
            signature.as_ptr(),
            signature.len(),
            msg.as_ptr(),
            msg.len(),
        );

        ffi::EVP_MD_CTX_free(mctx);
        openssl_sys::EVP_PKEY_free(pkey);
        map_digest_verify_rc(rc)
    }
}

#[cfg(test)]
pub(crate) use alg::test_suite_alg_name;
#[cfg(test)]
pub(crate) use bootstrap::{
    parse_openssl_fips_mode, test_ensure_openssl_bootstrap_for_mode,
    test_openssl_check_sigalg_bad_alg, test_set_env_if_empty, OpenSslFipsMode,
};
#[cfg(test)]
pub(crate) use digest::{
    test_openssl_verify_sig_digest_oneshot_bad_alg,
    test_openssl_verify_sig_digest_oneshot_empty_input,
};
#[cfg(test)]
mod tests;
