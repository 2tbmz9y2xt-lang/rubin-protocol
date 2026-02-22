fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

pub(crate) fn siphash24(msg: &[u8], k0: u64, k1: u64) -> u64 {
    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;

    let mut i = 0usize;
    while i + 8 <= msg.len() {
        let m = u64::from_le_bytes(msg[i..i + 8].try_into().expect("8-byte chunk"));
        v3 ^= m;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
        i += 8;
    }

    let rem = &msg[i..];
    let mut b = (msg.len() as u64) << 56;
    if !rem.is_empty() {
        b |= rem[0] as u64;
    }
    if rem.len() > 1 {
        b |= (rem[1] as u64) << 8;
    }
    if rem.len() > 2 {
        b |= (rem[2] as u64) << 16;
    }
    if rem.len() > 3 {
        b |= (rem[3] as u64) << 24;
    }
    if rem.len() > 4 {
        b |= (rem[4] as u64) << 32;
    }
    if rem.len() > 5 {
        b |= (rem[5] as u64) << 40;
    }
    if rem.len() > 6 {
        b |= (rem[6] as u64) << 48;
    }

    v3 ^= b;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;

    v2 ^= 0xff;
    for _ in 0..4 {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }

    v0 ^ v1 ^ v2 ^ v3
}

/// Computes a 6-byte compact short ID from WTXID using SipHash-2-4.
/// The 64-bit SipHash result is truncated to lower 48 bits (little-endian bytes).
pub fn compact_shortid(wtxid: [u8; 32], nonce1: u64, nonce2: u64) -> [u8; 6] {
    let h = siphash24(&wtxid, nonce1, nonce2) & 0x0000ffff_ffff_ffff;
    let b = h.to_le_bytes();
    let mut out = [0u8; 6];
    out.copy_from_slice(&b[..6]);
    out
}
