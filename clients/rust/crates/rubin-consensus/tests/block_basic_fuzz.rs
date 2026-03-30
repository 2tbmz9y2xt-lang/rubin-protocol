//! Deterministic fuzz-style tests for block_basic: parse_block_bytes,
//! parse_block_header_bytes, validate_block_basic. Mirrors Go FuzzValidateBlockBasic,
//! FuzzParseBlockBytes, FuzzParseBlockHeaderBytes.
//!
//! Invariant: no panic on any byte input; deterministic error/ok.

use rubin_consensus::{
    parse_block_bytes, parse_block_header_bytes, validate_block_basic,
    validate_block_basic_at_height, BLOCK_HEADER_BYTES,
};

// =============================================================
// parse_block_header_bytes — no panic on arbitrary inputs
// =============================================================

#[test]
fn header_parse_empty() {
    assert!(parse_block_header_bytes(&[]).is_err());
}

#[test]
fn header_parse_too_short() {
    assert!(parse_block_header_bytes(&[0u8; BLOCK_HEADER_BYTES - 1]).is_err());
}

#[test]
fn header_parse_too_long() {
    assert!(parse_block_header_bytes(&[0u8; BLOCK_HEADER_BYTES + 1]).is_err());
}

#[test]
fn header_parse_exact_zeros() {
    // 116 zero bytes: valid header structurally (version=0, all fields 0).
    let result = parse_block_header_bytes(&[0u8; BLOCK_HEADER_BYTES]);
    assert!(result.is_ok());
    let h = result.unwrap();
    assert_eq!(h.version, 0);
    assert_eq!(h.prev_block_hash, [0u8; 32]);
    assert_eq!(h.merkle_root, [0u8; 32]);
    assert_eq!(h.timestamp, 0);
}

#[test]
fn header_parse_all_ff() {
    let result = parse_block_header_bytes(&[0xFF; BLOCK_HEADER_BYTES]);
    assert!(result.is_ok());
}

#[test]
fn header_parse_deterministic() {
    let buf = [0x42u8; BLOCK_HEADER_BYTES];
    let r1 = parse_block_header_bytes(&buf);
    let r2 = parse_block_header_bytes(&buf);
    assert_eq!(r1.is_ok(), r2.is_ok());
    if let (Ok(h1), Ok(h2)) = (r1, r2) {
        assert_eq!(h1.version, h2.version);
        assert_eq!(h1.prev_block_hash, h2.prev_block_hash);
        assert_eq!(h1.merkle_root, h2.merkle_root);
        assert_eq!(h1.timestamp, h2.timestamp);
    }
}

// =============================================================
// parse_block_bytes — no panic on arbitrary inputs
// =============================================================

#[test]
fn block_parse_empty() {
    assert!(parse_block_bytes(&[]).is_err());
}

#[test]
fn block_parse_header_only() {
    // Just a header, no tx_count byte → too short
    assert!(parse_block_bytes(&[0u8; BLOCK_HEADER_BYTES]).is_err());
}

#[test]
fn block_parse_zero_tx_count() {
    // Header + tx_count=0 → rejected (empty block tx list)
    let mut buf = vec![0u8; BLOCK_HEADER_BYTES + 1];
    buf[BLOCK_HEADER_BYTES] = 0x00; // tx_count = 0
    let err = parse_block_bytes(&buf).unwrap_err();
    assert!(err.msg.contains("empty block tx list") || err.msg.contains("tx"));
}

#[test]
fn block_parse_tx_count_but_no_tx_data() {
    // Header + tx_count=1 but no actual tx data
    let mut buf = vec![0u8; BLOCK_HEADER_BYTES + 1];
    buf[BLOCK_HEADER_BYTES] = 0x01; // tx_count = 1
    assert!(parse_block_bytes(&buf).is_err());
}

#[test]
fn block_parse_large_tx_count_truncated() {
    // Header + tx_count=252 (max single byte) but only a few bytes after
    let mut buf = vec![0u8; BLOCK_HEADER_BYTES + 5];
    buf[BLOCK_HEADER_BYTES] = 0xFC; // tx_count = 252
    assert!(parse_block_bytes(&buf).is_err());
}

#[test]
fn block_parse_3byte_tx_count_truncated() {
    // Header + 0xFD prefix for tx_count but truncated
    let mut buf = vec![0u8; BLOCK_HEADER_BYTES + 2];
    buf[BLOCK_HEADER_BYTES] = 0xFD;
    buf[BLOCK_HEADER_BYTES + 1] = 0x01;
    assert!(parse_block_bytes(&buf).is_err());
}

#[test]
fn block_parse_all_ff_no_panic() {
    let _ = parse_block_bytes(&[0xFF; 256]);
}

#[test]
fn block_parse_all_zeros_no_panic() {
    let _ = parse_block_bytes(&[0x00; 256]);
}

#[test]
fn block_parse_deterministic() {
    let buf = vec![0x42u8; 512];
    let r1 = parse_block_bytes(&buf);
    let r2 = parse_block_bytes(&buf);
    assert_eq!(r1.is_ok(), r2.is_ok());
}

// =============================================================
// Malformed byte patterns — no panic
// =============================================================

#[test]
fn block_parse_one_byte() {
    let _ = parse_block_bytes(&[0x01]);
}

#[test]
fn block_parse_header_plus_one_ff() {
    let mut buf = vec![0u8; BLOCK_HEADER_BYTES + 1];
    buf[BLOCK_HEADER_BYTES] = 0xFF; // 0xFF tag = 9-byte compact_size, but only 1 byte after header
    assert!(parse_block_bytes(&buf).is_err());
}

#[test]
fn block_parse_incremental_lengths_no_panic() {
    // Test various lengths from 0 to 300 — none should panic
    for len in 0..=300 {
        let buf = vec![0x00u8; len];
        let _ = parse_block_bytes(&buf);
    }
}

// =============================================================
// validate_block_basic — no panic on arbitrary inputs
// =============================================================

#[test]
fn validate_basic_empty() {
    assert!(validate_block_basic(&[], None, None).is_err());
}

#[test]
fn validate_basic_zeros() {
    let buf = vec![0u8; BLOCK_HEADER_BYTES + 1];
    assert!(validate_block_basic(&buf, None, None).is_err());
}

#[test]
fn validate_basic_with_constraints_no_panic() {
    let buf = vec![0u8; 256];
    let prev_hash = [0x01u8; 32];
    let target = [0xFFu8; 32];
    let _ = validate_block_basic(&buf, Some(prev_hash), Some(target));
}

#[test]
fn validate_basic_at_height_no_panic() {
    let buf = vec![0u8; 256];
    let _ = validate_block_basic_at_height(&buf, None, None, 0);
    let _ = validate_block_basic_at_height(&buf, None, None, u64::MAX);
}

#[test]
fn validate_basic_deterministic() {
    let buf = vec![0xAB; 256];
    let r1 = validate_block_basic(&buf, None, None);
    let r2 = validate_block_basic(&buf, None, None);
    assert_eq!(r1.is_ok(), r2.is_ok());
}

#[test]
fn validate_basic_all_ff_no_panic() {
    let _ = validate_block_basic(&[0xFF; 1024], None, None);
}

#[test]
fn validate_basic_incremental_lengths_no_panic() {
    for len in 0..=300 {
        let buf = vec![0x55u8; len];
        let _ = validate_block_basic(&buf, None, None);
    }
}
