use crate::error::{ErrorCode, TxError};
use core::ffi::CStr;

pub(super) fn map_digest_verify_rc(rc: core::ffi::c_int) -> Result<bool, TxError> {
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
    super::openssl_verify_sig_digest_oneshot_raw(alg, pubkey, signature, msg)
}

#[cfg(test)]
pub(crate) fn test_openssl_verify_sig_digest_oneshot_empty_input() -> Result<bool, TxError> {
    openssl_verify_sig_digest_oneshot(c"ML-DSA-87", &[], &[], &[])
}

#[cfg(test)]
pub(crate) fn test_openssl_verify_sig_digest_oneshot_bad_alg() -> Result<bool, TxError> {
    openssl_verify_sig_digest_oneshot(c"NOT-A-REAL-SIGALG", &[1], &[1], &[1])
}
