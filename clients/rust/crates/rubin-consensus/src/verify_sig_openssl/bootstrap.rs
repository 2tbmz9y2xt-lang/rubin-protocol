use crate::error::{ErrorCode, TxError};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenSslFipsMode {
    Off,
    Ready,
    Only,
}

static OPENSSL_BOOTSTRAP_STATE: OnceLock<Result<(), TxError>> = OnceLock::new();

pub(crate) fn parse_openssl_fips_mode(raw: &str) -> Result<OpenSslFipsMode, TxError> {
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
    let state = OPENSSL_BOOTSTRAP_STATE.get_or_init(|| super::openssl_bootstrap(require_fips));
    state.clone()
}

#[cfg(test)]
pub(crate) fn test_set_env_if_empty(key: &str, value: Option<String>) {
    super::set_env_if_empty(key, value);
}

#[cfg(test)]
pub(crate) fn test_ensure_openssl_bootstrap_for_mode(mode_raw: &str) -> Result<(), TxError> {
    let mode = parse_openssl_fips_mode(mode_raw)?;
    ensure_openssl_bootstrap_for_mode(mode)
}

#[cfg(test)]
pub(crate) fn test_openssl_check_sigalg_bad_alg() -> Result<(), TxError> {
    super::openssl_check_sigalg(c"NOT-A-REAL-SIGALG", c"")
}
