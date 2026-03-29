use sha3::{Digest, Sha3_256};

pub fn sha3_256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_256_empty_input() {
        let got = sha3_256(b"");
        // NIST FIPS 202: SHA3-256("") = a7ffc6f8...
        let want: [u8; 32] = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
            0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
            0x80, 0xf8, 0x43, 0x4a,
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn sha3_256_known_vector_abc() {
        // SHA3-256("abc") = 3a985da7...
        let got = sha3_256(b"abc");
        let want: [u8; 32] = [
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3,
            0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45,
            0x11, 0x43, 0x15, 0x32,
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn sha3_256_output_is_32_bytes() {
        assert_eq!(sha3_256(b"test").len(), 32);
    }

    #[test]
    fn sha3_256_deterministic() {
        let a = sha3_256(b"deterministic");
        let b = sha3_256(b"deterministic");
        assert_eq!(a, b);
    }

    #[test]
    fn sha3_256_different_inputs_differ() {
        assert_ne!(sha3_256(b"input1"), sha3_256(b"input2"));
    }

    #[test]
    fn sha3_256_single_zero_byte_differs_from_empty() {
        assert_ne!(sha3_256(&[0x00]), sha3_256(b""));
    }

    #[test]
    fn sha3_256_large_input() {
        let input: Vec<u8> = (0..=255).cycle().take(1 << 16).collect();
        let a = sha3_256(&input);
        let b = sha3_256(&input);
        assert_eq!(a.len(), 32);
        assert_eq!(a, b);
    }

    #[test]
    fn sha3_256_go_rust_parity_empty() {
        // Cross-check: Go crypto/sha3.Sum256(nil) must produce same result
        // as Rust sha3::Sha3_256. Both use NIST FIPS 202.
        let got = sha3_256(b"");
        assert_eq!(got[0], 0xa7, "first byte mismatch with NIST vector");
        assert_eq!(got[31], 0x4a, "last byte mismatch with NIST vector");
    }
}
