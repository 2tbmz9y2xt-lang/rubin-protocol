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

type RubSha3_256 = unsafe extern "C" fn(input_ptr: *const u8, input_len: usize, out32: *mut u8) -> i32;
type RubVerify = unsafe extern "C" fn(
    pubkey_ptr: *const u8,
    pubkey_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
    digest32_ptr: *const u8,
) -> i32;

pub struct WolfcryptDylibProvider {
    _lib: Library,
    sha3_256: RubSha3_256,
    verify_mldsa87: RubVerify,
    verify_slhdsa_shake_256f: RubVerify,
}

impl WolfcryptDylibProvider {
    /// Load a wolfCrypt shim dylib from a filesystem path (e.g. `librubin_wc_shim.so`).
    ///
    /// Expected exported symbols:
    /// - `rubin_wc_sha3_256`
    /// - `rubin_wc_verify_mldsa87`
    /// - `rubin_wc_verify_slhdsa_shake_256f`
    pub fn load(path: &str) -> Result<Self, String> {
        let lib = unsafe { Library::new(path).map_err(|e| e.to_string())? };
        unsafe {
            let sha3_256: RubSha3_256 = *lib.get(b"rubin_wc_sha3_256\0").map_err(|e| e.to_string())?;
            let verify_mldsa87: RubVerify =
                *lib.get(b"rubin_wc_verify_mldsa87\0").map_err(|e| e.to_string())?;
            let verify_slhdsa_shake_256f: RubVerify =
                *lib.get(b"rubin_wc_verify_slhdsa_shake_256f\0").map_err(|e| e.to_string())?;

            Ok(Self {
                _lib: lib,
                sha3_256,
                verify_mldsa87,
                verify_slhdsa_shake_256f,
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
            return Err("RUBIN_WOLFCRYPT_SHIM_SHA3_256 required when RUBIN_WOLFCRYPT_STRICT=1".into());
        }

        Self::load(&path)
    }
}

impl CryptoProvider for WolfcryptDylibProvider {
    fn sha3_256(&self, input: &[u8]) -> Result<[u8; 32], String> {
        let mut out = [0u8; 32];
        let rc = unsafe { (self.sha3_256)(input.as_ptr(), input.len(), out.as_mut_ptr()) };
        if rc != 1 {
            return Err(format!("wolfcrypt shim error: rubin_wc_sha3_256 rc={rc}"));
        }
        Ok(out)
    }

    fn verify_mldsa87(&self, pubkey: &[u8], sig: &[u8], digest32: &[u8; 32]) -> Result<bool, String> {
        let rc =
            unsafe { (self.verify_mldsa87)(pubkey.as_ptr(), pubkey.len(), sig.as_ptr(), sig.len(), digest32.as_ptr()) };
        match rc {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(format!("wolfcrypt shim error: rubin_wc_verify_mldsa87 rc={rc}")),
        }
    }

    fn verify_slhdsa_shake_256f(&self, pubkey: &[u8], sig: &[u8], digest32: &[u8; 32]) -> Result<bool, String> {
        let rc = unsafe {
            (self.verify_slhdsa_shake_256f)(pubkey.as_ptr(), pubkey.len(), sig.as_ptr(), sig.len(), digest32.as_ptr())
        };
        match rc {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(format!("wolfcrypt shim error: rubin_wc_verify_slhdsa_shake_256f rc={rc}")),
        }
    }
}
