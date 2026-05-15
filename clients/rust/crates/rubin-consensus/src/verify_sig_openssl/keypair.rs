use crate::error::TxError;

pub struct Mldsa87Keypair {
    pub(super) pkey: *mut openssl_sys::EVP_PKEY,
    pub(super) pubkey: Vec<u8>,
}

impl Drop for Mldsa87Keypair {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: pkey ownership is unique to this keypair and is released at most once.
            if !self.pkey.is_null() {
                openssl_sys::EVP_PKEY_free(self.pkey);
                self.pkey = core::ptr::null_mut();
            }
        }
    }
}

impl Mldsa87Keypair {
    pub fn generate() -> Result<Self, TxError> {
        let (pkey, pubkey) = super::generate_mldsa87_keypair()?;
        Ok(Self { pkey, pubkey })
    }

    pub fn pubkey_bytes(&self) -> Vec<u8> {
        self.pubkey.clone()
    }

    pub fn sign_digest32(&self, digest32: [u8; 32]) -> Result<Vec<u8>, TxError> {
        super::sign_mldsa87_digest32(self.pkey, digest32)
    }
}
