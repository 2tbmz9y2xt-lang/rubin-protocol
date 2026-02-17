//! Cryptography provider interface for RUBIN implementations.
//!
//! Consensus code must depend only on this narrow interface.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuiteId {
    Sentinel = 0x00,
    MlDsa87 = 0x01,
    SlhDsaShake256f = 0x02,
}

pub trait CryptoProvider {
    fn sha3_256(&self, input: &[u8]) -> Result<[u8; 32], String>;
    fn verify_mldsa87(
        &self,
        pubkey: &[u8],
        sig: &[u8],
        digest32: &[u8; 32],
    ) -> Result<bool, String>;
    fn verify_slhdsa_shake_256f(
        &self,
        pubkey: &[u8],
        sig: &[u8],
        digest32: &[u8; 32],
    ) -> Result<bool, String>;
}

#[cfg(feature = "wolfcrypt-dylib")]
mod wolfcrypt_dylib;
#[cfg(feature = "wolfcrypt-dylib")]
pub use wolfcrypt_dylib::WolfcryptDylibProvider;

/// Development-only provider using a software SHA3 implementation.
/// This is NOT a FIPS claim. It exists to unblock early devnet tooling.
#[cfg(feature = "dev-std")]
pub struct DevStdCryptoProvider;

#[cfg(feature = "dev-std")]
impl CryptoProvider for DevStdCryptoProvider {
    fn sha3_256(&self, input: &[u8]) -> Result<[u8; 32], String> {
        use sha3::Digest;
        let mut h = sha3::Sha3_256::new();
        h.update(input);
        let out = h.finalize();
        let mut r = [0u8; 32];
        r.copy_from_slice(&out);
        Ok(r)
    }

    fn verify_mldsa87(
        &self,
        _pubkey: &[u8],
        _sig: &[u8],
        _digest32: &[u8; 32],
    ) -> Result<bool, String> {
        Ok(false)
    }

    fn verify_slhdsa_shake_256f(
        &self,
        _pubkey: &[u8],
        _sig: &[u8],
        _digest32: &[u8; 32],
    ) -> Result<bool, String> {
        Ok(false)
    }
}
