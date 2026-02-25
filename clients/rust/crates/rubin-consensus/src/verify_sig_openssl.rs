use crate::constants::{SUITE_ID_ML_DSA_87, SUITE_ID_SLH_DSA_SHAKE_256F};
use crate::error::{ErrorCode, TxError};
use core::ffi::CStr;

extern "C" {
    fn EVP_PKEY_new_raw_public_key_ex(
        libctx: *mut core::ffi::c_void,
        keytype: *const core::ffi::c_char,
        propq: *const core::ffi::c_char,
        key: *const core::ffi::c_uchar,
        keylen: usize,
    ) -> *mut openssl_sys::EVP_PKEY;

    fn EVP_PKEY_verify_message_init(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        algo: *mut core::ffi::c_void,
        params: *const core::ffi::c_void,
    ) -> core::ffi::c_int;
    fn EVP_PKEY_verify_message_update(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        in_: *const core::ffi::c_uchar,
        inlen: usize,
    ) -> core::ffi::c_int;
    fn EVP_PKEY_verify_message_final(ctx: *mut openssl_sys::EVP_PKEY_CTX) -> core::ffi::c_int;
    fn EVP_PKEY_CTX_set_signature(
        pctx: *mut openssl_sys::EVP_PKEY_CTX,
        sig: *const core::ffi::c_uchar,
        siglen: usize,
    ) -> core::ffi::c_int;
}

fn suite_alg_name(suite_id: u8) -> Result<&'static CStr, TxError> {
    match suite_id {
        SUITE_ID_ML_DSA_87 => Ok(unsafe { CStr::from_bytes_with_nul_unchecked(b"ML-DSA-87\0") }),
        SUITE_ID_SLH_DSA_SHAKE_256F => Ok(unsafe {
            CStr::from_bytes_with_nul_unchecked(b"SLH-DSA-SHAKE-256f\0")
        }),
        _ => Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "verify_sig: unsupported suite_id",
        )),
    }
}

pub fn verify_sig(suite_id: u8, pubkey: &[u8], signature: &[u8], digest32: &[u8; 32]) -> Result<bool, TxError> {
    let alg = suite_alg_name(suite_id)?;
    openssl_verify_sig(alg, pubkey, signature, digest32)
}

fn openssl_verify_sig(alg: &'static CStr, pubkey: &[u8], signature: &[u8], msg: &[u8]) -> Result<bool, TxError> {
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

        let ctx = openssl_sys::EVP_PKEY_CTX_new(pkey, core::ptr::null_mut());
        if ctx.is_null() {
            openssl_sys::EVP_PKEY_free(pkey);
            return Err(TxError::new(ErrorCode::TxErrParse, "openssl: EVP_PKEY_CTX_new failed"));
        }

        if EVP_PKEY_verify_message_init(ctx, core::ptr::null_mut(), core::ptr::null()) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            openssl_sys::EVP_PKEY_free(pkey);
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_PKEY_verify_message_init failed",
            ));
        }

        if EVP_PKEY_CTX_set_signature(ctx, signature.as_ptr(), signature.len()) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            openssl_sys::EVP_PKEY_free(pkey);
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_PKEY_CTX_set_signature failed",
            ));
        }
        if EVP_PKEY_verify_message_update(ctx, msg.as_ptr(), msg.len()) <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            openssl_sys::EVP_PKEY_free(pkey);
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_PKEY_verify_message_update failed",
            ));
        }

        let rc = EVP_PKEY_verify_message_final(ctx);

        openssl_sys::EVP_PKEY_CTX_free(ctx);
        openssl_sys::EVP_PKEY_free(pkey);

        if rc == 1 {
            Ok(true)
        } else if rc == 0 {
            Ok(false)
        } else {
            Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_PKEY_verify_message_final failed",
            ))
        }
    }
}
