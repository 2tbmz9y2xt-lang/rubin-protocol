use super::ffi::{self, MdCtx, VerificationPkey};
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

    // SAFETY: all pointers passed to OpenSSL are derived from live Rust slices
    // for the duration of the call; RAII wrappers own and free the created
    // OpenSSL key/context exactly once.
    unsafe {
        openssl_sys::ERR_clear_error();
        let pkey = VerificationPkey::new_raw_public_key(alg, pubkey)?;
        let mctx = MdCtx::new("openssl: EVP_MD_CTX_new failed")?;
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
        map_digest_verify_rc(rc)
    }
}

#[cfg(test)]
pub(crate) fn test_openssl_verify_sig_digest_oneshot_empty_input() -> Result<bool, TxError> {
    openssl_verify_sig_digest_oneshot(c"ML-DSA-87", &[], &[], &[])
}

#[cfg(test)]
pub(crate) fn test_openssl_verify_sig_digest_oneshot_bad_alg() -> Result<bool, TxError> {
    openssl_verify_sig_digest_oneshot(c"NOT-A-REAL-SIGALG", &[1], &[1], &[1])
}
