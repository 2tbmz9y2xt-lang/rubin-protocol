mod alg;
mod binding;
mod digest;

mod ffi {
    use crate::error::{ErrorCode, TxError};
    use core::ffi::{c_char, c_int, c_uchar, c_void, CStr};

    extern "C" {
        pub(super) fn EVP_PKEY_CTX_new_from_name(
            libctx: *mut c_void,
            name: *const c_char,
            propq: *const c_char,
        ) -> *mut openssl_sys::EVP_PKEY_CTX;

        pub(super) fn EVP_PKEY_new_raw_public_key_ex(
            libctx: *mut c_void,
            keytype: *const c_char,
            propq: *const c_char,
            key: *const c_uchar,
            keylen: usize,
        ) -> *mut openssl_sys::EVP_PKEY;

        pub(super) fn EVP_PKEY_get_raw_public_key(
            pkey: *const openssl_sys::EVP_PKEY,
            pub_: *mut c_uchar,
            publen: *mut usize,
        ) -> c_int;
    }

    extern "C" {
        pub(super) fn EVP_MD_CTX_new() -> *mut openssl_sys::EVP_MD_CTX;
        pub(super) fn EVP_MD_CTX_free(ctx: *mut openssl_sys::EVP_MD_CTX);

        pub(super) fn EVP_DigestVerifyInit_ex(
            ctx: *mut openssl_sys::EVP_MD_CTX,
            pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
            mdname: *const c_char,
            libctx: *mut c_void,
            props: *const c_char,
            pkey: *mut openssl_sys::EVP_PKEY,
            params: *const c_void,
        ) -> c_int;

        pub(super) fn EVP_DigestVerify(
            ctx: *mut openssl_sys::EVP_MD_CTX,
            sigret: *const c_uchar,
            siglen: usize,
            tbs: *const c_uchar,
            tbslen: usize,
        ) -> c_int;
    }

    extern "C" {
        pub(super) fn EVP_DigestSignInit_ex(
            ctx: *mut openssl_sys::EVP_MD_CTX,
            pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
            mdname: *const c_char,
            libctx: *mut c_void,
            props: *const c_char,
            pkey: *mut openssl_sys::EVP_PKEY,
            params: *const c_void,
        ) -> c_int;

        pub(super) fn EVP_DigestSign(
            ctx: *mut openssl_sys::EVP_MD_CTX,
            sigret: *mut c_uchar,
            siglen: *mut usize,
            tbs: *const c_uchar,
            tbslen: usize,
        ) -> c_int;
    }

    extern "C" {
        pub(super) fn OPENSSL_init_crypto(opts: u64, settings: *const c_void) -> c_int;

        pub(super) fn EVP_set_default_properties(
            libctx: *mut c_void,
            propq: *const c_char,
        ) -> c_int;
    }

    pub(super) struct PkeyCtx {
        ptr: *mut openssl_sys::EVP_PKEY_CTX,
    }

    impl PkeyCtx {
        /// SAFETY: `alg` must be a valid OpenSSL algorithm name with static storage.
        /// The returned context is uniquely owned by `PkeyCtx` and freed in `Drop`.
        pub(super) unsafe fn new_from_name(alg: &'static CStr) -> Result<Self, TxError> {
            let ptr =
                EVP_PKEY_CTX_new_from_name(core::ptr::null_mut(), alg.as_ptr(), core::ptr::null());
            if ptr.is_null() {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "openssl: EVP_PKEY_CTX_new_from_name failed",
                ));
            }
            Ok(Self { ptr })
        }

        pub(super) fn as_mut_ptr(&self) -> *mut openssl_sys::EVP_PKEY_CTX {
            self.ptr
        }
    }

    impl Drop for PkeyCtx {
        fn drop(&mut self) {
            // SAFETY: `PkeyCtx` uniquely owns `ptr`; OpenSSL accepts null checks here
            // and the field is nulled after free to prevent double-free on re-entry.
            unsafe {
                if !self.ptr.is_null() {
                    openssl_sys::EVP_PKEY_CTX_free(self.ptr);
                    self.ptr = core::ptr::null_mut();
                }
            }
        }
    }

    pub(super) struct MdCtx {
        ptr: *mut openssl_sys::EVP_MD_CTX,
    }

    impl MdCtx {
        /// SAFETY: this creates a new OpenSSL digest context and transfers unique
        /// ownership to `MdCtx`, which releases it exactly once in `Drop`.
        pub(super) unsafe fn new(error_msg: &'static str) -> Result<Self, TxError> {
            let ptr = EVP_MD_CTX_new();
            if ptr.is_null() {
                return Err(TxError::new(ErrorCode::TxErrParse, error_msg));
            }
            Ok(Self { ptr })
        }

        pub(super) fn as_mut_ptr(&self) -> *mut openssl_sys::EVP_MD_CTX {
            self.ptr
        }
    }

    impl Drop for MdCtx {
        fn drop(&mut self) {
            // SAFETY: `MdCtx` uniquely owns `ptr`; the null check mirrors OpenSSL
            // ownership rules and the field is nulled after free.
            unsafe {
                if !self.ptr.is_null() {
                    EVP_MD_CTX_free(self.ptr);
                    self.ptr = core::ptr::null_mut();
                }
            }
        }
    }

    pub(super) struct VerificationPkey {
        ptr: *mut openssl_sys::EVP_PKEY,
    }

    impl VerificationPkey {
        /// SAFETY: `alg` is a static OpenSSL algorithm name and `pubkey` is passed
        /// as an immutable byte slice for the duration of the FFI call. Ownership of
        /// the returned key is transferred into `VerificationPkey`.
        pub(super) unsafe fn new_raw_public_key(
            alg: &'static CStr,
            pubkey: &[u8],
        ) -> Result<Self, TxError> {
            let ptr = EVP_PKEY_new_raw_public_key_ex(
                core::ptr::null_mut(),
                alg.as_ptr(),
                core::ptr::null(),
                pubkey.as_ptr(),
                pubkey.len(),
            );
            if ptr.is_null() {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "openssl: EVP_PKEY_new_raw_public_key_ex failed",
                ));
            }
            Ok(Self { ptr })
        }

        pub(super) fn as_mut_ptr(&self) -> *mut openssl_sys::EVP_PKEY {
            self.ptr
        }
    }

    impl Drop for VerificationPkey {
        fn drop(&mut self) {
            // SAFETY: `VerificationPkey` uniquely owns `ptr`; OpenSSL permits the
            // checked free path and the field is nulled after release.
            unsafe {
                if !self.ptr.is_null() {
                    openssl_sys::EVP_PKEY_free(self.ptr);
                    self.ptr = core::ptr::null_mut();
                }
            }
        }
    }
}

mod bootstrap {
    use super::ffi;
    use crate::error::{ErrorCode, TxError};
    use std::sync::OnceLock;

    const OPENSSL_INIT_LOAD_CONFIG: u64 = 0x0000_0040;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum OpenSslFipsMode {
        Off,
        Ready,
        Only,
    }

    static OPENSSL_BOOTSTRAP_STATE: OnceLock<Result<(), TxError>> = OnceLock::new();

    pub(super) fn parse_openssl_fips_mode(raw: &str) -> Result<OpenSslFipsMode, TxError> {
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

    pub(super) fn ensure_openssl_bootstrap() -> Result<(), TxError> {
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

    pub(super) fn openssl_check_sigalg(
        alg: &'static core::ffi::CStr,
        props: &'static core::ffi::CStr,
    ) -> Result<(), TxError> {
        // SAFETY: `alg` and `props` are static C strings, and the fetched OpenSSL
        // signature handle is freed exactly once before returning.
        unsafe {
            let sig = openssl_sys::EVP_SIGNATURE_fetch(
                core::ptr::null_mut(),
                alg.as_ptr(),
                props.as_ptr(),
            );
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

    pub(super) fn openssl_bootstrap(require_fips: bool) -> Result<(), TxError> {
        set_env_if_empty("OPENSSL_CONF", std::env::var("RUBIN_OPENSSL_CONF").ok());
        set_env_if_empty(
            "OPENSSL_MODULES",
            std::env::var("RUBIN_OPENSSL_MODULES").ok(),
        );

        // SAFETY: OpenSSL global initialization/provider calls use static C string
        // arguments and do not transfer Rust-owned memory to OpenSSL.
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

    pub(super) fn map_openssl_init_rc(
        rc: core::ffi::c_int,
        message: &'static str,
    ) -> Result<(), TxError> {
        if rc == 1 {
            Ok(())
        } else {
            Err(TxError::new(ErrorCode::TxErrParse, message))
        }
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
}

mod keypair {
    use super::alg::suite_alg_name;
    use super::ffi::{self, MdCtx, PkeyCtx};
    use crate::constants::{ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87};
    use crate::error::{ErrorCode, TxError};
    use crate::tx_helpers::DigestSigner;
    use core::ffi::CStr;

    pub struct Mldsa87Keypair {
        pkey: *mut openssl_sys::EVP_PKEY,
        pubkey: Vec<u8>,
    }

    impl Drop for Mldsa87Keypair {
        fn drop(&mut self) {
            // SAFETY: `Mldsa87Keypair` uniquely owns `pkey`; the null check and
            // post-free null assignment preserve the existing single-free invariant.
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
            super::bootstrap::ensure_openssl_bootstrap()?;
            let alg = suite_alg_name(SUITE_ID_ML_DSA_87)?;
            // SAFETY: the helper calls below validate each OpenSSL allocation and
            // either transfer ownership into `Mldsa87Keypair` or free `pkey` on the
            // public-key extraction error path.
            unsafe {
                openssl_sys::ERR_clear_error();
                let pkey = generate_raw_pkey(alg)?;
                let pubkey = match read_public_key(pkey) {
                    Ok(value) => value,
                    Err(err) => {
                        openssl_sys::EVP_PKEY_free(pkey);
                        return Err(err);
                    }
                };
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
            // SAFETY: `self.pkey` was created by OpenSSL, is owned by this keypair,
            // and the null check above guarantees a valid pointer for signing.
            unsafe { sign_digest32_with_pkey(self.pkey, digest32) }
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

    // SAFETY: caller must provide a valid OpenSSL signature algorithm name. The
    // returned raw key is owned by the caller on success.
    unsafe fn generate_raw_pkey(alg: &'static CStr) -> Result<*mut openssl_sys::EVP_PKEY, TxError> {
        let ctx = PkeyCtx::new_from_name(alg)?;
        if openssl_sys::EVP_PKEY_keygen_init(ctx.as_mut_ptr()) <= 0 {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_PKEY_keygen_init failed",
            ));
        }
        let mut pkey: *mut openssl_sys::EVP_PKEY = core::ptr::null_mut();
        if openssl_sys::EVP_PKEY_keygen(ctx.as_mut_ptr(), &mut pkey) <= 0 || pkey.is_null() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_PKEY_keygen failed",
            ));
        }
        Ok(pkey)
    }

    // SAFETY: caller must pass a valid OpenSSL key pointer that remains alive for
    // the duration of this raw public-key extraction call.
    unsafe fn read_public_key(pkey: *mut openssl_sys::EVP_PKEY) -> Result<Vec<u8>, TxError> {
        let mut pubkey = vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize];
        let mut pubkey_len = pubkey.len();
        if ffi::EVP_PKEY_get_raw_public_key(pkey, pubkey.as_mut_ptr(), &mut pubkey_len) <= 0 {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_PKEY_get_raw_public_key failed",
            ));
        }
        if pubkey_len != ML_DSA_87_PUBKEY_BYTES as usize {
            return Err(TxError::new(
                ErrorCode::TxErrSigNoncanonical,
                "openssl: non-canonical ML-DSA public key length",
            ));
        }
        Ok(pubkey)
    }

    // SAFETY: caller must pass a non-null OpenSSL key pointer that remains valid
    // and uniquely owned by its keypair for the full signing call.
    unsafe fn sign_digest32_with_pkey(
        pkey: *mut openssl_sys::EVP_PKEY,
        digest32: [u8; 32],
    ) -> Result<Vec<u8>, TxError> {
        openssl_sys::ERR_clear_error();
        let mctx = MdCtx::new("openssl: EVP_MD_CTX_new failed")?;
        if ffi::EVP_DigestSignInit_ex(
            mctx.as_mut_ptr(),
            core::ptr::null_mut(),
            core::ptr::null(),
            core::ptr::null_mut(),
            core::ptr::null(),
            pkey,
            core::ptr::null(),
        ) <= 0
        {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_DigestSignInit_ex failed",
            ));
        }
        let mut signature = vec![0u8; ML_DSA_87_SIG_BYTES as usize];
        let mut sig_len = signature.len();
        if ffi::EVP_DigestSign(
            mctx.as_mut_ptr(),
            signature.as_mut_ptr(),
            &mut sig_len,
            digest32.as_ptr(),
            digest32.len(),
        ) <= 0
        {
            return Err(TxError::new(
                ErrorCode::TxErrSigInvalid,
                "openssl: EVP_DigestSign failed",
            ));
        }
        canonical_signature(signature, sig_len)
    }

    fn canonical_signature(mut signature: Vec<u8>, sig_len: usize) -> Result<Vec<u8>, TxError> {
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

use crate::constants::{ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87};
use crate::error::{ErrorCode, TxError};
use core::ffi::CStr;
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

fn openssl_verify_sig_digest_oneshot_raw(
    alg: &'static CStr,
    pubkey: &[u8],
    signature: &[u8],
    msg: &[u8],
) -> Result<bool, TxError> {
    // SAFETY: all pointers passed to OpenSSL are derived from live Rust slices
    // for the duration of the call; RAII wrappers own and free the created
    // OpenSSL key/context exactly once.
    unsafe {
        openssl_sys::ERR_clear_error();
        let pkey = ffi::VerificationPkey::new_raw_public_key(alg, pubkey)?;
        let mctx = ffi::MdCtx::new("openssl: EVP_MD_CTX_new failed")?;
        if ffi::EVP_DigestVerifyInit_ex(
            mctx.as_mut_ptr(),
            core::ptr::null_mut(),
            core::ptr::null(),
            core::ptr::null_mut(),
            core::ptr::null(),
            pkey.as_mut_ptr(),
            core::ptr::null(),
        ) <= 0
        {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_DigestVerifyInit_ex failed",
            ));
        }
        let rc = ffi::EVP_DigestVerify(
            mctx.as_mut_ptr(),
            signature.as_ptr(),
            signature.len(),
            msg.as_ptr(),
            msg.len(),
        );
        digest::map_digest_verify_rc(rc)
    }
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
