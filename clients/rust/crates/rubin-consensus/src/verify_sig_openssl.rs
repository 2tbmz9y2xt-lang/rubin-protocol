use crate::constants::{
    MAX_SLH_DSA_SIG_BYTES, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES,
    SLH_DSA_SHAKE_256F_PUBKEY_BYTES, SUITE_ID_ML_DSA_87, SUITE_ID_SLH_DSA_SHAKE_256F,
};
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

pub fn verify_sig(
    suite_id: u8,
    pubkey: &[u8],
    signature: &[u8],
    digest32: &[u8; 32],
) -> Result<bool, TxError> {
    let alg = suite_alg_name(suite_id)?;
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
                || signature.is_empty()
                || signature.len() > MAX_SLH_DSA_SIG_BYTES as usize
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
    use super::map_digest_verify_rc;
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
}
