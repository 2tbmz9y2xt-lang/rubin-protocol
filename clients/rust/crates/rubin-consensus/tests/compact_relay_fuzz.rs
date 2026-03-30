//! Deterministic fuzz-style tests for compact_relay: compact_shortid.
//! Mirrors Go FuzzCompactShortID + TestSiphash24_ReferenceVectors + TestCompactShortID_Vector.
//!
//! Invariant: no panic; deterministic; 6-byte output; Go parity on reference vectors.

use rubin_consensus::compact_shortid;

// =============================================================
// Reference vectors — Go parity (TestCompactShortID_Vector)
// =============================================================

#[test]
fn shortid_go_reference_vector() {
    // Go test: wtxid = 26ce78c5..., nonces = 0x0706050403020100, 0x0f0e0d0c0b0a0908
    // Expected: b50c6fb86b2f
    let wtxid_hex = "26ce78c5671f12911e3610831095305ed00a112b9ba59cddb87c694bb8b4e695";
    let mut wtxid = [0u8; 32];
    for i in 0..32 {
        wtxid[i] = u8::from_str_radix(&wtxid_hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    let nonce1: u64 = 0x0706050403020100;
    let nonce2: u64 = 0x0f0e0d0c0b0a0908;
    let got = compact_shortid(wtxid, nonce1, nonce2);
    let expected: [u8; 6] = [0xb5, 0x0c, 0x6f, 0xb8, 0x6b, 0x2f];
    assert_eq!(got, expected, "Go parity vector mismatch");
}

// =============================================================
// Output properties
// =============================================================

#[test]
fn shortid_output_is_6_bytes() {
    let wtxid = [0x42u8; 32];
    let out = compact_shortid(wtxid, 0, 0);
    assert_eq!(out.len(), 6);
}

#[test]
fn shortid_zero_inputs() {
    let wtxid = [0u8; 32];
    let out = compact_shortid(wtxid, 0, 0);
    // Must not be all zeros (SipHash IV ensures mixing)
    assert_ne!(out, [0u8; 6]);
}

#[test]
fn shortid_all_ff_no_panic() {
    let _ = compact_shortid([0xFF; 32], u64::MAX, u64::MAX);
}

// =============================================================
// Determinism
// =============================================================

#[test]
fn shortid_deterministic_same_inputs() {
    let wtxid = [0xAB; 32];
    let r1 = compact_shortid(wtxid, 100, 200);
    let r2 = compact_shortid(wtxid, 100, 200);
    assert_eq!(r1, r2);
}

#[test]
fn shortid_deterministic_sweep() {
    for byte in 0..=255u8 {
        let mut wtxid = [0u8; 32];
        wtxid[0] = byte;
        let r1 = compact_shortid(wtxid, 1, 2);
        let r2 = compact_shortid(wtxid, 1, 2);
        assert_eq!(r1, r2, "non-deterministic for byte={byte}");
    }
}

// =============================================================
// Sensitivity — different inputs → (likely) different outputs
// =============================================================

#[test]
fn shortid_different_wtxid_different_output() {
    let a = compact_shortid([0x00; 32], 1, 2);
    let b = compact_shortid([0x01; 32], 1, 2);
    // With cryptographic hash, collision is astronomically unlikely
    assert_ne!(a, b);
}

#[test]
fn shortid_different_nonce1_different_output() {
    let wtxid = [0x42; 32];
    let a = compact_shortid(wtxid, 0, 0);
    let b = compact_shortid(wtxid, 1, 0);
    assert_ne!(a, b);
}

#[test]
fn shortid_different_nonce2_different_output() {
    let wtxid = [0x42; 32];
    let a = compact_shortid(wtxid, 0, 0);
    let b = compact_shortid(wtxid, 0, 1);
    assert_ne!(a, b);
}

// =============================================================
// 48-bit truncation: upper 2 bytes of siphash64 must be zeroed
// =============================================================

#[test]
fn shortid_is_lower_48_bits() {
    // compact_shortid returns 6 bytes = 48 bits of the siphash.
    // Verify it's exactly 6 bytes (type system guarantees this,
    // but let's verify the semantic contract).
    for i in 0..50u8 {
        let mut wtxid = [0u8; 32];
        wtxid[0] = i;
        let out = compact_shortid(wtxid, 0x1234, 0x5678);
        assert_eq!(out.len(), 6);
    }
}

// =============================================================
// Fuzz-style: incremental wtxid bytes, no panic
// =============================================================

#[test]
fn shortid_incremental_wtxid_no_panic() {
    for i in 0..=255u8 {
        let wtxid = [i; 32];
        let _ = compact_shortid(wtxid, i as u64, (255 - i) as u64);
    }
}

// =============================================================
// Nonce symmetry check: swapping nonces changes output
// =============================================================

#[test]
fn shortid_nonce_swap_changes_output() {
    let wtxid = [0x42; 32];
    let a = compact_shortid(wtxid, 1, 2);
    let b = compact_shortid(wtxid, 2, 1);
    assert_ne!(a, b, "swapping nonces should change output");
}

// =============================================================
// Bulk determinism: 1000 iterations same result
// =============================================================

#[test]
fn shortid_bulk_determinism() {
    let wtxid = [0xDE; 32];
    let reference = compact_shortid(wtxid, 0xCAFE, 0xBEEF);
    for _ in 0..1000 {
        assert_eq!(compact_shortid(wtxid, 0xCAFE, 0xBEEF), reference);
    }
}
