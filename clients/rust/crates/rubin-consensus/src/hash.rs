use sha3::{Digest, Sha3_256};

pub fn sha3_256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}
