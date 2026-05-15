pub struct Mldsa87Keypair {
    pub(super) pkey: *mut openssl_sys::EVP_PKEY,
    pub(super) pubkey: Vec<u8>,
}
