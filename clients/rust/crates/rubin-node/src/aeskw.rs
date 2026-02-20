// AES-256 Key Wrap (RFC 3394 / NIST SP 800-38F).
//
// This is a dev-only fallback for environments without a wolfcrypt shim keywrap
// implementation. Strict/FIPS deployments must use the shim/HSM path.

use aes::Aes256;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

const DEFAULT_IV: [u8; 8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

fn xor_u64_be(a: &mut [u8; 8], t: u64) {
    for (k, v) in a.iter_mut().enumerate().take(8) {
        *v ^= ((t >> (56 - 8 * k)) & 0xff) as u8;
    }
}

pub fn aes_key_wrap_rfc3394(kek: &[u8], key_in: &[u8]) -> Result<Vec<u8>, String> {
    if kek.len() != 32 {
        return Err("aeskw: kek must be 32 bytes (AES-256)".into());
    }
    if key_in.len() < 16 || key_in.len() > 4096 || !key_in.len().is_multiple_of(8) {
        return Err("aeskw: keyIn must be 16..4096 bytes and multiple of 8".into());
    }

    let cipher = Aes256::new_from_slice(kek).map_err(|_| "aeskw: invalid kek".to_string())?;
    let n = key_in.len() / 8;

    let mut r = vec![[0u8; 8]; n];
    for i in 0..n {
        r[i].copy_from_slice(&key_in[i * 8..(i + 1) * 8]);
    }
    let mut a = DEFAULT_IV;

    for j in 0..6u64 {
        for (i, ri) in r.iter_mut().enumerate().take(n) {
            let mut b = [0u8; 16];
            b[0..8].copy_from_slice(&a);
            b[8..16].copy_from_slice(ri);

            let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(&b);
            cipher.encrypt_block(&mut block);
            b.copy_from_slice(&block);

            a.copy_from_slice(&b[0..8]);
            let t = (n as u64) * j + (i as u64) + 1;
            xor_u64_be(&mut a, t);
            ri.copy_from_slice(&b[8..16]);
        }
    }

    let mut out = Vec::with_capacity(8 + key_in.len());
    out.extend_from_slice(&a);
    for ri in r.iter().take(n) {
        out.extend_from_slice(ri);
    }
    Ok(out)
}

pub fn aes_key_unwrap_rfc3394(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, String> {
    if kek.len() != 32 {
        return Err("aeskw: kek must be 32 bytes (AES-256)".into());
    }
    if wrapped.len() < 24 || wrapped.len() > 4104 || !wrapped.len().is_multiple_of(8) {
        return Err("aeskw: wrapped must be 24..4104 bytes and multiple of 8".into());
    }

    let cipher = Aes256::new_from_slice(kek).map_err(|_| "aeskw: invalid kek".to_string())?;
    let n = (wrapped.len() / 8) - 1;

    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped[0..8]);
    let mut r = vec![[0u8; 8]; n];
    for i in 0..n {
        r[i].copy_from_slice(&wrapped[(i + 1) * 8..(i + 2) * 8]);
    }

    for j in (0..6u64).rev() {
        for i in (0..n).rev() {
            let t = (n as u64) * j + (i as u64) + 1;
            let mut a_xor = a;
            xor_u64_be(&mut a_xor, t);

            let mut b = [0u8; 16];
            b[0..8].copy_from_slice(&a_xor);
            b[8..16].copy_from_slice(&r[i]);

            let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(&b);
            cipher.decrypt_block(&mut block);
            b.copy_from_slice(&block);

            a.copy_from_slice(&b[0..8]);
            r[i].copy_from_slice(&b[8..16]);
        }
    }

    if a != DEFAULT_IV {
        return Err("aeskw: integrity check failed".into());
    }

    let mut out = Vec::with_capacity(n * 8);
    for ri in r.iter().take(n) {
        out.extend_from_slice(ri);
    }
    if out.len() % 8 != 0 {
        return Err("aeskw: unwrap produced non-multiple-of-8 length".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aeskw_roundtrip() {
        let kek = [0x11u8; 32];
        let key_in = [0x22u8; 16];
        let wrapped = aes_key_wrap_rfc3394(&kek, &key_in).unwrap();
        let unwrapped = aes_key_unwrap_rfc3394(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, key_in);
    }

    #[test]
    fn test_aeskw_wrong_kek_fails_integrity() {
        let kek = [0x11u8; 32];
        let kek2 = [0x12u8; 32];
        let key_in = [0x22u8; 16];
        let wrapped = aes_key_wrap_rfc3394(&kek, &key_in).unwrap();
        let err = aes_key_unwrap_rfc3394(&kek2, &wrapped).unwrap_err();
        assert!(err.contains("integrity"));
    }
}
