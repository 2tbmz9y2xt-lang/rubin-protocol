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

pub(super) fn openssl_bootstrap(require_fips: bool) -> Result<(), TxError> {
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
