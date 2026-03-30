//! Deterministic fuzz-style tests for parse_stealth_covenant_data.
//! Mirrors Go FuzzParseStealthCovenantData.
//!
//! Invariant: no panic on any byte input; canonical length check;
//! deterministic results; no aliasing.

use rubin_consensus::{
    constants::{MAX_STEALTH_COVENANT_DATA, ML_KEM_1024_CT_BYTES},
    parse_stealth_covenant_data,
};

fn stealth_covenant_data_for_key_id(key_id: [u8; 32]) -> Vec<u8> {
    let mut cov = vec![0u8; MAX_STEALTH_COVENANT_DATA as usize];
    cov[ML_KEM_1024_CT_BYTES as usize..MAX_STEALTH_COVENANT_DATA as usize].copy_from_slice(&key_id);
    cov
}

// =============================================================
// Length rejection — no panic
// =============================================================

#[test]
fn stealth_parse_empty() {
    assert!(parse_stealth_covenant_data(&[]).is_err());
}

#[test]
fn stealth_parse_too_short() {
    assert!(parse_stealth_covenant_data(&[0u8; (MAX_STEALTH_COVENANT_DATA - 1) as usize]).is_err());
}

#[test]
fn stealth_parse_too_long() {
    assert!(parse_stealth_covenant_data(&[0u8; (MAX_STEALTH_COVENANT_DATA + 1) as usize]).is_err());
}

#[test]
fn stealth_parse_one_byte() {
    assert!(parse_stealth_covenant_data(&[0x42]).is_err());
}

// =============================================================
// Valid canonical length — succeeds
// =============================================================

#[test]
fn stealth_parse_exact_zeros() {
    let cov = vec![0u8; MAX_STEALTH_COVENANT_DATA as usize];
    let result = parse_stealth_covenant_data(&cov);
    assert!(result.is_ok());
    let sc = result.unwrap();
    assert_eq!(sc.ciphertext.len(), ML_KEM_1024_CT_BYTES as usize);
    assert_eq!(sc.one_time_key_id, [0u8; 32]);
}

#[test]
fn stealth_parse_exact_ff() {
    let cov = vec![0xFF; MAX_STEALTH_COVENANT_DATA as usize];
    let result = parse_stealth_covenant_data(&cov);
    assert!(result.is_ok());
    let sc = result.unwrap();
    assert_eq!(sc.one_time_key_id, [0xFF; 32]);
}

#[test]
fn stealth_parse_with_key_id() {
    let mut key_id = [0u8; 32];
    key_id[0] = 0xAA;
    key_id[31] = 0x55;
    let cov = stealth_covenant_data_for_key_id(key_id);
    let sc = parse_stealth_covenant_data(&cov).unwrap();
    assert_eq!(sc.one_time_key_id, key_id);
}

// =============================================================
// Ciphertext extraction correctness
// =============================================================

#[test]
fn stealth_ciphertext_len() {
    let cov = vec![0x42u8; MAX_STEALTH_COVENANT_DATA as usize];
    let sc = parse_stealth_covenant_data(&cov).unwrap();
    assert_eq!(sc.ciphertext.len(), ML_KEM_1024_CT_BYTES as usize);
    // Ciphertext should be the first ML_KEM_1024_CT_BYTES bytes
    assert!(sc.ciphertext.iter().all(|&b| b == 0x42));
}

#[test]
fn stealth_key_id_from_tail() {
    let mut cov = vec![0u8; MAX_STEALTH_COVENANT_DATA as usize];
    // Set last 32 bytes to specific pattern
    for (i, b) in cov[ML_KEM_1024_CT_BYTES as usize..].iter_mut().enumerate() {
        *b = i as u8;
    }
    let sc = parse_stealth_covenant_data(&cov).unwrap();
    let mut expected = [0u8; 32];
    for (i, b) in expected.iter_mut().enumerate() {
        *b = i as u8;
    }
    assert_eq!(sc.one_time_key_id, expected);
}

// =============================================================
// No aliasing — ciphertext is owned copy
// =============================================================

#[test]
fn stealth_no_aliasing() {
    let mut cov = vec![0x42u8; MAX_STEALTH_COVENANT_DATA as usize];
    let sc = parse_stealth_covenant_data(&cov).unwrap();
    let first_byte = sc.ciphertext[0];
    // Mutate original — should NOT affect parsed result
    cov[0] = 0xFF;
    assert_eq!(sc.ciphertext[0], first_byte);
}

// =============================================================
// Determinism
// =============================================================

#[test]
fn stealth_deterministic() {
    let cov = vec![0x42u8; MAX_STEALTH_COVENANT_DATA as usize];
    let r1 = parse_stealth_covenant_data(&cov);
    let r2 = parse_stealth_covenant_data(&cov);
    assert_eq!(r1.is_ok(), r2.is_ok());
    if let (Ok(s1), Ok(s2)) = (r1, r2) {
        assert_eq!(s1.ciphertext, s2.ciphertext);
        assert_eq!(s1.one_time_key_id, s2.one_time_key_id);
    }
}

#[test]
fn stealth_deterministic_error() {
    let r1 = parse_stealth_covenant_data(&[0x00; 10]);
    let r2 = parse_stealth_covenant_data(&[0x00; 10]);
    assert!(r1.is_err());
    assert!(r2.is_err());
}

// =============================================================
// Incremental lengths — no panic
// =============================================================

#[test]
fn stealth_incremental_lengths_no_panic() {
    // Test lengths around the canonical boundary
    let max = MAX_STEALTH_COVENANT_DATA as usize;
    for len in [0, 1, 31, 32, 33, max - 1, max, max + 1, max + 100] {
        let buf = vec![0x55u8; len];
        let _ = parse_stealth_covenant_data(&buf);
    }
}

// =============================================================
// Constants consistency
// =============================================================

#[test]
fn stealth_constants_consistency() {
    // MAX_STEALTH_COVENANT_DATA = ML_KEM_1024_CT_BYTES + 32
    assert_eq!(
        MAX_STEALTH_COVENANT_DATA,
        ML_KEM_1024_CT_BYTES + 32,
        "MAX_STEALTH_COVENANT_DATA must equal ML_KEM_1024_CT_BYTES + 32"
    );
}
