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
