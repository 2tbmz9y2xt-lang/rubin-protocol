//! wolfCrypt backend via a stable shim dylib ABI.
//!
//! This module intentionally does not include wolfSSL headers. Instead, it loads a
//! local dynamic library that exposes a narrow, stable C ABI for:
//!
//! - SHA3-256
//! - ML-DSA-87 verify
//! - SLH-DSA-SHAKE-256f verify
//!
//! The shim library is expected to be provided by the operator/compliance build
//! pipeline and linked to wolfCrypt (FIPS-path / FIPS-PQC as applicable).

use crate::CryptoProvider;

use libloading::Library;
use sha3::{Digest, Sha3_256};
use std::fs;

type RubSha3_256 =
    unsafe extern "C" fn(input_ptr: *const u8, input_len: usize, out32: *mut u8) -> i32;
type RubVerify = unsafe extern "C" fn(
    pubkey_ptr: *const u8,
    pubkey_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
    digest32_ptr: *const u8,
) -> i32;
type RubKeyWrap = unsafe extern "C" fn(
    kek: *const u8,
    kek_len: usize,
    key_in: *const u8,
    key_in_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32;

pub struct WolfcryptDylibProvider {
    _lib: Library,
    sha3_256: RubSha3_256,
    verify_mldsa87: RubVerify,
    verify_slhdsa_shake_256f: RubVerify,
    /// Optional: present only in shims that export keywrap symbols (v1.1+)
    aes_keywrap: Option<RubKeyWrap>,
    aes_keyunwrap: Option<RubKeyWrap>,
}

impl WolfcryptDylibProvider {
    /// Load a wolfCrypt shim dylib from a filesystem path (e.g. `librubin_wc_shim.so`).
    ///
    /// Expected exported symbols:
    /// - `rubin_wc_sha3_256`
    /// - `rubin_wc_verify_mldsa87`
    /// - `rubin_wc_verify_slhdsa_shake_256f`
    pub fn load(path: &str) -> Result<Self, String> {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let lib = unsafe { Library::new(path).map_err(|e| e.to_string())? };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let sha3_256: RubSha3_256 =
                *lib.get(b"rubin_wc_sha3_256\0").map_err(|e| e.to_string())?;
            let verify_mldsa87: RubVerify = *lib
                .get(b"rubin_wc_verify_mldsa87\0")
                .map_err(|e| e.to_string())?;
            let verify_slhdsa_shake_256f: RubVerify = *lib
                .get(b"rubin_wc_verify_slhdsa_shake_256f\0")
                .map_err(|e| e.to_string())?;

            /* keywrap symbols are optional — older shims still load */
            let aes_keywrap: Option<RubKeyWrap> =
                lib.get(b"rubin_wc_aes_keywrap\0").ok().map(|s| *s);
            let aes_keyunwrap: Option<RubKeyWrap> =
                lib.get(b"rubin_wc_aes_keyunwrap\0").ok().map(|s| *s);

            Ok(Self {
                _lib: lib,
                sha3_256,
                verify_mldsa87,
                verify_slhdsa_shake_256f,
                aes_keywrap,
                aes_keyunwrap,
            })
        }
    }

    /// Load a wolfCrypt shim dylib from RUBIN_WOLFCRYPT_SHIM_PATH.
    pub fn load_from_env() -> Result<Self, String> {
        let path = std::env::var("RUBIN_WOLFCRYPT_SHIM_PATH")
            .map_err(|_| String::from("RUBIN_WOLFCRYPT_SHIM_PATH is not set"))?;

        let strict = std::env::var("RUBIN_WOLFCRYPT_STRICT")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if let Ok(expected_hex) = std::env::var("RUBIN_WOLFCRYPT_SHIM_SHA3_256") {
            let bytes = fs::read(&path).map_err(|e| format!("read shim: {e}"))?;
            let mut hasher = Sha3_256::new();
            hasher.update(&bytes);
            let digest = hasher.finalize();
            let actual_hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
            if actual_hex != expected_hex.to_ascii_lowercase() {
                return Err("wolfcrypt shim hash mismatch (RUBIN_WOLFCRYPT_SHIM_SHA3_256)".into());
            }
        } else if strict {
            return Err(
                "RUBIN_WOLFCRYPT_SHIM_SHA3_256 required when RUBIN_WOLFCRYPT_STRICT=1".into(),
            );
        }

        Self::load(&path)
    }
}

impl CryptoProvider for WolfcryptDylibProvider {
    fn sha3_256(&self, input: &[u8]) -> Result<[u8; 32], String> {
        let mut out = [0u8; 32];
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let rc = unsafe { (self.sha3_256)(input.as_ptr(), input.len(), out.as_mut_ptr()) };
        if rc != 1 {
            return Err(format!("wolfcrypt shim error: rubin_wc_sha3_256 rc={rc}"));
        }
        Ok(out)
    }

    fn verify_mldsa87(
        &self,
        pubkey: &[u8],
        sig: &[u8],
        digest32: &[u8; 32],
    ) -> Result<bool, String> {
        let rc =
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { (self.verify_mldsa87)(pubkey.as_ptr(), pubkey.len(), sig.as_ptr(), sig.len(), digest32.as_ptr()) };
        match rc {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(format!(
                "wolfcrypt shim error: rubin_wc_verify_mldsa87 rc={rc}"
            )),
        }
    }

    fn verify_slhdsa_shake_256f(
        &self,
        pubkey: &[u8],
        sig: &[u8],
        digest32: &[u8; 32],
    ) -> Result<bool, String> {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let rc = unsafe {
            (self.verify_slhdsa_shake_256f)(
                pubkey.as_ptr(),
                pubkey.len(),
                sig.as_ptr(),
                sig.len(),
                digest32.as_ptr(),
            )
        };
        match rc {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(format!(
                "wolfcrypt shim error: rubin_wc_verify_slhdsa_shake_256f rc={rc}"
            )),
        }
    }
}

/// Sentinel error for AES-KW integrity failure (wrong KEK or corrupted blob).
#[derive(Debug)]
pub struct KeyWrapIntegrityError;
impl std::fmt::Display for KeyWrapIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "keyunwrap: integrity check failed (wrong KEK or corrupted blob)")
    }
}
impl std::error::Error for KeyWrapIntegrityError {}

impl WolfcryptDylibProvider {
    /// Returns true if the loaded shim exports AES keywrap symbols (shim v1.1+).
    pub fn has_key_management(&self) -> bool {
        self.aes_keywrap.is_some() && self.aes_keyunwrap.is_some()
    }

    /// Wrap key material using AES-256-KW (RFC 3394).
    /// `kek` must be exactly 32 bytes. `key_in` must be a non-zero multiple of 8 bytes.
    /// Returns wrapped blob (`key_in.len() + 8` bytes).
    pub fn key_wrap(&self, kek: &[u8], key_in: &[u8]) -> Result<Vec<u8>, String> {
        let f = self.aes_keywrap
            .ok_or_else(|| "keywrap symbol absent in shim (upgrade shim to v1.1+)".to_string())?;
        if kek.len() != 32 {
            return Err("keywrap: kek must be 32 bytes (AES-256)".into());
        }
        if key_in.is_empty() || key_in.len() % 8 != 0 {
            return Err("keywrap: key_in must be non-zero multiple of 8 bytes (RFC 3394)".into());
        }
        let mut out = vec![0u8; key_in.len() + 8];
        let mut out_len = out.len();
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let rc = unsafe {
            f(kek.as_ptr(), kek.len(), key_in.as_ptr(), key_in.len(), out.as_mut_ptr(), &mut out_len)
        };
        if rc <= 0 {
            return Err(format!("keywrap: shim error rc={rc}"));
        }
        out.truncate(out_len);
        Ok(out)
    }

    /// Unwrap a blob produced by `key_wrap` using AES-256-KW (RFC 3394).
    /// Returns `Err(KeyWrapIntegrityError)` if the KEK is wrong or blob is corrupted.
    pub fn key_unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let f = self.aes_keyunwrap
            .ok_or_else(|| "keyunwrap symbol absent in shim (upgrade shim to v1.1+)".to_string())?;
        if kek.len() != 32 {
            return Err("keyunwrap: kek must be 32 bytes (AES-256)".into());
        }
        if wrapped.len() < 16 {
            return Err("keyunwrap: wrapped blob too short".into());
        }
        let mut out = vec![0u8; wrapped.len()];
        let mut out_len = out.len();
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let rc = unsafe {
            f(kek.as_ptr(), kek.len(), wrapped.as_ptr(), wrapped.len(), out.as_mut_ptr(), &mut out_len)
        };
        if rc == -36 {
            return Err(Box::new(KeyWrapIntegrityError));
        }
        if rc <= 0 {
            return Err(format!("keyunwrap: shim error rc={rc}").into());
        }
        out.truncate(out_len);
        Ok(out)
    }
}
