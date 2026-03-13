use crate::constants::{ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87};
use crate::error::{ErrorCode, TxError};
use crate::tx_helpers::DigestSigner;
use core::ffi::CStr;
use std::sync::OnceLock;

const OPENSSL_INIT_LOAD_CONFIG: u64 = 0x0000_0040;

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

fn suite_alg_name(suite_id: u8) -> Result<&'static CStr, TxError> {
    match suite_id {
        SUITE_ID_ML_DSA_87 => Ok(c"ML-DSA-87"),
        _ => Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "verify_sig: unsupported suite_id",
        )),
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
        if OPENSSL_init_crypto(0, core::ptr::null()) != 1 {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl consensus init: OPENSSL_init_crypto failed",
            ));
        }
    }
    openssl_check_sigalg(c"ML-DSA-87", c"")?;
    Ok(())
}

fn ensure_openssl_consensus_init() -> Result<(), TxError> {
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

    let alg = suite_alg_name(suite_id)?;
    ensure_openssl_consensus_init()?;

    if pubkey.len() != ML_DSA_87_PUBKEY_BYTES as usize
        || signature.len() != ML_DSA_87_SIG_BYTES as usize
    {
        return Ok(false);
    }

    openssl_verify_sig_digest_oneshot(alg, pubkey, signature, digest32)
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

fn openssl_verify_sig_digest_oneshot(
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
        map_digest_verify_rc, openssl_bootstrap, parse_openssl_fips_mode, Mldsa87Keypair,
        OpenSslFipsMode,
    };
    use crate::error::ErrorCode;
    use std::sync::{Mutex, OnceLock};

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
}
