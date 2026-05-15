use crate::constants::SUITE_ID_ML_DSA_87;
use crate::error::{ErrorCode, TxError};
use core::ffi::CStr;

pub(super) fn suite_alg_name(suite_id: u8) -> Result<&'static CStr, TxError> {
    match suite_id {
        SUITE_ID_ML_DSA_87 => Ok(c"ML-DSA-87"),
        _ => Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "verify_sig: unsupported suite_id",
        )),
    }
}

pub(super) fn openssl_alg_name_cstr(name: &str) -> Option<&'static CStr> {
    match name {
        "ML-DSA-87" => Some(c"ML-DSA-87"),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) fn test_suite_alg_name(suite_id: u8) -> Result<&'static str, TxError> {
    suite_alg_name(suite_id).map(|alg| alg.to_str().expect("cstr"))
}
