use crate::constants::{
    MAX_SLH_DSA_SIG_BYTES, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES,
    SLH_DSA_SHAKE_256F_PUBKEY_BYTES, SUITE_ID_ML_DSA_87, SUITE_ID_SLH_DSA_SHAKE_256F,
};
use crate::error::{ErrorCode, TxError};
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

extern "C" {
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

    fn OPENSSL_init_crypto(opts: u64, settings: *const core::ffi::c_void) -> core::ffi::c_int;

    fn EVP_set_default_properties(
        libctx: *mut core::ffi::c_void,
        propq: *const core::ffi::c_char,
    ) -> core::ffi::c_int;
}

fn suite_alg_name(suite_id: u8) -> Result<&'static CStr, TxError> {
    match suite_id {
        SUITE_ID_ML_DSA_87 => Ok(c"ML-DSA-87"),
        SUITE_ID_SLH_DSA_SHAKE_256F => Ok(c"SLH-DSA-SHAKE-256f"),
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
    openssl_check_sigalg(c"SLH-DSA-SHAKE-256f", c"provider=fips")?;
    Ok(())
}

pub fn verify_sig(
    suite_id: u8,
    pubkey: &[u8],
    signature: &[u8],
    digest32: &[u8; 32],
) -> Result<bool, TxError> {
    let alg = suite_alg_name(suite_id)?;
    ensure_openssl_bootstrap()?;
    match suite_id {
        SUITE_ID_ML_DSA_87 => {
            if pubkey.len() != ML_DSA_87_PUBKEY_BYTES as usize
                || signature.len() != ML_DSA_87_SIG_BYTES as usize
            {
                return Ok(false);
            }
        }
        SUITE_ID_SLH_DSA_SHAKE_256F => {
            if pubkey.len() != SLH_DSA_SHAKE_256F_PUBKEY_BYTES as usize
                || signature.len() != MAX_SLH_DSA_SIG_BYTES as usize
            {
                return Ok(false);
            }
        }
        _ => {}
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
        map_digest_verify_rc, openssl_bootstrap, parse_openssl_fips_mode, OpenSslFipsMode,
    };
    use crate::error::ErrorCode;

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
}
