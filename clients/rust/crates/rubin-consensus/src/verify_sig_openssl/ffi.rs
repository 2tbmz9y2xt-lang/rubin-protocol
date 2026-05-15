use crate::error::{ErrorCode, TxError};
use core::ffi::{c_char, c_int, c_uchar, c_void, CStr};

extern "C" {
    pub(super) fn EVP_PKEY_CTX_new_from_name(
        libctx: *mut c_void,
        name: *const c_char,
        propq: *const c_char,
    ) -> *mut openssl_sys::EVP_PKEY_CTX;

    pub(super) fn EVP_PKEY_new_raw_public_key_ex(
        libctx: *mut c_void,
        keytype: *const c_char,
        propq: *const c_char,
        key: *const c_uchar,
        keylen: usize,
    ) -> *mut openssl_sys::EVP_PKEY;

    pub(super) fn EVP_PKEY_get_raw_public_key(
        pkey: *const openssl_sys::EVP_PKEY,
        pub_: *mut c_uchar,
        publen: *mut usize,
    ) -> c_int;
}

extern "C" {
    pub(super) fn EVP_MD_CTX_new() -> *mut openssl_sys::EVP_MD_CTX;
    pub(super) fn EVP_MD_CTX_free(ctx: *mut openssl_sys::EVP_MD_CTX);

    pub(super) fn EVP_DigestVerifyInit_ex(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
        mdname: *const c_char,
        libctx: *mut c_void,
        props: *const c_char,
        pkey: *mut openssl_sys::EVP_PKEY,
        params: *const c_void,
    ) -> c_int;

    pub(super) fn EVP_DigestVerify(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        sigret: *const c_uchar,
        siglen: usize,
        tbs: *const c_uchar,
        tbslen: usize,
    ) -> c_int;
}

extern "C" {
    pub(super) fn EVP_DigestSignInit_ex(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
        mdname: *const c_char,
        libctx: *mut c_void,
        props: *const c_char,
        pkey: *mut openssl_sys::EVP_PKEY,
        params: *const c_void,
    ) -> c_int;

    pub(super) fn EVP_DigestSign(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        sigret: *mut c_uchar,
        siglen: *mut usize,
        tbs: *const c_uchar,
        tbslen: usize,
    ) -> c_int;
}

extern "C" {
    pub(super) fn OPENSSL_init_crypto(opts: u64, settings: *const c_void) -> c_int;

    pub(super) fn EVP_set_default_properties(libctx: *mut c_void, propq: *const c_char) -> c_int;
}

pub(super) struct PkeyCtx {
    ptr: *mut openssl_sys::EVP_PKEY_CTX,
}

impl PkeyCtx {
    /// SAFETY: `alg` must be a valid OpenSSL algorithm name with static storage.
    /// The returned context is uniquely owned by `PkeyCtx` and freed in `Drop`.
    pub(super) unsafe fn new_from_name(alg: &'static CStr) -> Result<Self, TxError> {
        let ptr =
            EVP_PKEY_CTX_new_from_name(core::ptr::null_mut(), alg.as_ptr(), core::ptr::null());
        if ptr.is_null() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_PKEY_CTX_new_from_name failed",
            ));
        }
        Ok(Self { ptr })
    }

    pub(super) fn as_mut_ptr(&self) -> *mut openssl_sys::EVP_PKEY_CTX {
        self.ptr
    }
}

impl Drop for PkeyCtx {
    fn drop(&mut self) {
        // SAFETY: `PkeyCtx` uniquely owns `ptr`; OpenSSL accepts null checks here
        // and the field is nulled after free to prevent double-free on re-entry.
        unsafe {
            if !self.ptr.is_null() {
                openssl_sys::EVP_PKEY_CTX_free(self.ptr);
                self.ptr = core::ptr::null_mut();
            }
        }
    }
}

pub(super) struct MdCtx {
    ptr: *mut openssl_sys::EVP_MD_CTX,
}

impl MdCtx {
    /// SAFETY: this creates a new OpenSSL digest context and transfers unique
    /// ownership to `MdCtx`, which releases it exactly once in `Drop`.
    pub(super) unsafe fn new(error_msg: &'static str) -> Result<Self, TxError> {
        let ptr = EVP_MD_CTX_new();
        if ptr.is_null() {
            return Err(TxError::new(ErrorCode::TxErrParse, error_msg));
        }
        Ok(Self { ptr })
    }

    pub(super) fn as_mut_ptr(&self) -> *mut openssl_sys::EVP_MD_CTX {
        self.ptr
    }
}

impl Drop for MdCtx {
    fn drop(&mut self) {
        // SAFETY: `MdCtx` uniquely owns `ptr`; the null check mirrors OpenSSL
        // ownership rules and the field is nulled after free.
        unsafe {
            if !self.ptr.is_null() {
                EVP_MD_CTX_free(self.ptr);
                self.ptr = core::ptr::null_mut();
            }
        }
    }
}

pub(super) struct VerificationPkey {
    ptr: *mut openssl_sys::EVP_PKEY,
}

impl VerificationPkey {
    /// SAFETY: `alg` is a static OpenSSL algorithm name and `pubkey` is passed
    /// as an immutable byte slice for the duration of the FFI call. Ownership of
    /// the returned key is transferred into `VerificationPkey`.
    pub(super) unsafe fn new_raw_public_key(
        alg: &'static CStr,
        pubkey: &[u8],
    ) -> Result<Self, TxError> {
        let ptr = EVP_PKEY_new_raw_public_key_ex(
            core::ptr::null_mut(),
            alg.as_ptr(),
            core::ptr::null(),
            pubkey.as_ptr(),
            pubkey.len(),
        );
        if ptr.is_null() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "openssl: EVP_PKEY_new_raw_public_key_ex failed",
            ));
        }
        Ok(Self { ptr })
    }

    pub(super) fn as_mut_ptr(&self) -> *mut openssl_sys::EVP_PKEY {
        self.ptr
    }
}

impl Drop for VerificationPkey {
    fn drop(&mut self) {
        // SAFETY: `VerificationPkey` uniquely owns `ptr`; OpenSSL permits the
        // checked free path and the field is nulled after release.
        unsafe {
            if !self.ptr.is_null() {
                openssl_sys::EVP_PKEY_free(self.ptr);
                self.ptr = core::ptr::null_mut();
            }
        }
    }
}
