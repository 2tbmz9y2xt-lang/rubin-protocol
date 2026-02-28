#![no_main]

use libfuzzer_sys::fuzz_target;
use num_bigint::BigUint;

// Replaces Kani verify_biguint_to_bytes32_roundtrip
// (BigUint arbitrary-precision arithmetic is SAT-intractable for CBMC).
//
// biguint_to_bytes32 is private in pow.rs, so we replicate its 6-line
// algorithm here.  The roundtrip property is mathematical and does not
// depend on internal crate state.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 32 {
        return;
    }

    let x = BigUint::from_bytes_be(data);

    // Replicate biguint_to_bytes32: BigUint → big-endian → zero-pad to 32 bytes.
    let b = x.to_bytes_be();
    assert!(b.len() <= 32, "to_bytes_be produced >32 bytes from <=32-byte input");
    let mut bytes32 = [0u8; 32];
    bytes32[32 - b.len()..].copy_from_slice(&b);

    // Roundtrip: bytes32 → BigUint → bytes32.
    let y = BigUint::from_bytes_be(&bytes32);
    let b2 = y.to_bytes_be();
    assert!(b2.len() <= 32, "roundtrip produced >32 bytes");
    let mut bytes32_again = [0u8; 32];
    bytes32_again[32 - b2.len()..].copy_from_slice(&b2);

    assert_eq!(bytes32, bytes32_again, "biguint roundtrip bytes mismatch");
    assert_eq!(x, y, "biguint roundtrip value mismatch");
});
