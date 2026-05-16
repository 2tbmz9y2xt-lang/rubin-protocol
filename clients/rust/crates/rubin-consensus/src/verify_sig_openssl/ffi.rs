extern "C" {
    pub(super) fn EVP_PKEY_CTX_new_from_name(
        libctx: *mut core::ffi::c_void,
        name: *const core::ffi::c_char,
        propq: *const core::ffi::c_char,
    ) -> *mut openssl_sys::EVP_PKEY_CTX;
    pub(super) fn EVP_PKEY_new_raw_public_key_ex(
        libctx: *mut core::ffi::c_void,
        keytype: *const core::ffi::c_char,
        propq: *const core::ffi::c_char,
        key: *const core::ffi::c_uchar,
        keylen: usize,
    ) -> *mut openssl_sys::EVP_PKEY;
    pub(super) fn EVP_MD_CTX_new() -> *mut openssl_sys::EVP_MD_CTX;
    pub(super) fn EVP_MD_CTX_free(ctx: *mut openssl_sys::EVP_MD_CTX);
    pub(super) fn EVP_DigestVerifyInit_ex(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
        mdname: *const core::ffi::c_char,
        libctx: *mut core::ffi::c_void,
        props: *const core::ffi::c_char,
        pkey: *mut openssl_sys::EVP_PKEY,
        params: *const core::ffi::c_void,
    ) -> core::ffi::c_int;
    pub(super) fn EVP_DigestVerify(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        sigret: *const core::ffi::c_uchar,
        siglen: usize,
        tbs: *const core::ffi::c_uchar,
        tbslen: usize,
    ) -> core::ffi::c_int;
    pub(super) fn EVP_DigestSignInit_ex(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
        mdname: *const core::ffi::c_char,
        libctx: *mut core::ffi::c_void,
        props: *const core::ffi::c_char,
        pkey: *mut openssl_sys::EVP_PKEY,
        params: *const core::ffi::c_void,
    ) -> core::ffi::c_int;
    pub(super) fn EVP_DigestSign(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        sigret: *mut core::ffi::c_uchar,
        siglen: *mut usize,
        tbs: *const core::ffi::c_uchar,
        tbslen: usize,
    ) -> core::ffi::c_int;
    pub(super) fn OPENSSL_init_crypto(
        opts: u64,
        settings: *const core::ffi::c_void,
    ) -> core::ffi::c_int;
    pub(super) fn EVP_set_default_properties(
        libctx: *mut core::ffi::c_void,
        propq: *const core::ffi::c_char,
    ) -> core::ffi::c_int;
    pub(super) fn EVP_PKEY_get_raw_public_key(
        pkey: *const openssl_sys::EVP_PKEY,
        pub_: *mut core::ffi::c_uchar,
        publen: *mut usize,
    ) -> core::ffi::c_int;
}
