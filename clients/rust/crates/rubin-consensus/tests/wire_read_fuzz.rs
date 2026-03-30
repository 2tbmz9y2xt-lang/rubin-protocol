//! Deterministic direct tests for wire_read::Reader.
//! Covers: read_u8, read_u16_le, read_u32_le, read_u64_le, read_bytes, offset tracking, EOF errors.
//!
//! wire_read::Reader is pub(crate), so we test it through parse_tx which uses it internally.
//! For direct Reader coverage, we use the re-exported parse functions that exercise each read path.
//!
//! Invariant: no panic on any input; deterministic; correct error on truncated data.

use rubin_consensus::parse_tx;

// =============================================================
// Empty / minimal inputs — EOF handling
// =============================================================

#[test]
fn wire_read_empty_input() {
    assert!(parse_tx(&[]).is_err());
}

#[test]
fn wire_read_one_byte() {
    assert!(parse_tx(&[0x00]).is_err());
}

#[test]
fn wire_read_two_bytes() {
    assert!(parse_tx(&[0x01, 0x00]).is_err());
}

#[test]
fn wire_read_three_bytes() {
    assert!(parse_tx(&[0x01, 0x00, 0x00]).is_err());
}

#[test]
fn wire_read_four_bytes_version_only() {
    // version=1 (u32 LE) but nothing after → EOF on tx_kind
    assert!(parse_tx(&[0x01, 0x00, 0x00, 0x00]).is_err());
}

#[test]
fn wire_read_version_plus_kind() {
    // version=1 + tx_kind=0 → EOF on tx_nonce (u64)
    let mut buf = vec![0x01, 0x00, 0x00, 0x00, 0x00];
    assert!(parse_tx(&buf).is_err());

    // Add partial tx_nonce (only 4 bytes of 8)
    buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    assert!(parse_tx(&buf).is_err());
}

// =============================================================
// Truncation at each wire field boundary — exercises each read_*
// =============================================================

#[test]
fn wire_read_truncated_at_nonce() {
    // version(4) + kind(1) + nonce(8, but only 7 provided)
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_le_bytes()); // version
    buf.push(0x00); // kind
    buf.extend_from_slice(&[0x01; 7]); // 7 of 8 nonce bytes
    assert!(parse_tx(&buf).is_err());
}

#[test]
fn wire_read_truncated_at_input_count() {
    // version(4) + kind(1) + nonce(8) → EOF on input_count
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&1u64.to_le_bytes());
    assert!(parse_tx(&buf).is_err());
}

#[test]
fn wire_read_truncated_at_prev_txid() {
    // version + kind + nonce + input_count=1 + only 16 of 32 txid bytes
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&1u64.to_le_bytes());
    buf.push(0x01); // 1 input
    buf.extend_from_slice(&[0x55; 16]); // only 16 of 32 txid bytes
    assert!(parse_tx(&buf).is_err());
}

#[test]
fn wire_read_truncated_at_prev_vout() {
    // version + kind + nonce + input_count=1 + prev_txid(32) + only 2 of 4 vout bytes
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&1u64.to_le_bytes());
    buf.push(0x01);
    buf.extend_from_slice(&[0x55; 32]); // prev_txid
    buf.extend_from_slice(&[0x00, 0x00]); // 2 of 4 vout bytes
    assert!(parse_tx(&buf).is_err());
}

#[test]
fn wire_read_truncated_at_script_sig_len() {
    // Full input header but no script_sig_len
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&1u64.to_le_bytes());
    buf.push(0x01);
    buf.extend_from_slice(&[0x55; 32]); // prev_txid
    buf.extend_from_slice(&0u32.to_le_bytes()); // prev_vout
                                                // EOF — no script_sig_len
    assert!(parse_tx(&buf).is_err());
}

#[test]
fn wire_read_truncated_at_sequence() {
    // Input with script_sig_len=0 but no sequence
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&1u64.to_le_bytes());
    buf.push(0x01);
    buf.extend_from_slice(&[0x55; 32]);
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.push(0x00); // script_sig_len = 0
                    // EOF — no sequence
    assert!(parse_tx(&buf).is_err());
}

// =============================================================
// Version rejection
// =============================================================

#[test]
fn wire_read_wrong_version_zero() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0u32.to_le_bytes()); // version 0
    buf.push(0x00);
    buf.extend_from_slice(&1u64.to_le_bytes());
    buf.push(0x00); // 0 inputs
    buf.push(0x00); // 0 outputs
    buf.extend_from_slice(&0u32.to_le_bytes()); // locktime
    buf.push(0x00); // witness_count
    buf.push(0x00); // da_payload_len
    assert!(parse_tx(&buf).is_err());
}

#[test]
fn wire_read_wrong_version_two() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&2u32.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&1u64.to_le_bytes());
    buf.push(0x00);
    buf.push(0x00);
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.push(0x00);
    buf.push(0x00);
    assert!(parse_tx(&buf).is_err());
}

#[test]
fn wire_read_wrong_version_max() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&u32::MAX.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&1u64.to_le_bytes());
    buf.push(0x00);
    buf.push(0x00);
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.push(0x00);
    buf.push(0x00);
    assert!(parse_tx(&buf).is_err());
}

// =============================================================
// Incremental lengths — no panic at any truncation point
// =============================================================

#[test]
fn wire_read_incremental_lengths_no_panic() {
    for len in 0..=256 {
        let buf = vec![0x01; len]; // version byte 0x01 at offset 0 → version=0x01010101 ≠ 1
        assert!(parse_tx(&buf).is_err());
    }
}

#[test]
fn wire_read_incremental_valid_prefix_no_panic() {
    // Build valid prefix byte by byte, expect graceful EOF at each cutoff
    let mut full = Vec::new();
    full.extend_from_slice(&1u32.to_le_bytes()); // version=1
    full.push(0x00); // kind=0
    full.extend_from_slice(&1u64.to_le_bytes()); // nonce=1
    full.push(0x00); // 0 inputs
    full.push(0x00); // 0 outputs
    full.extend_from_slice(&0u32.to_le_bytes()); // locktime
    full.push(0x00); // witness_count=0
    full.push(0x00); // da_payload_len=0

    for cutoff in 0..full.len() {
        assert!(
            parse_tx(&full[..cutoff]).is_err(),
            "cutoff={cutoff} should fail"
        );
    }
    // Full buffer should parse successfully (0 inputs, 0 outputs)
    assert!(parse_tx(&full).is_ok());
}

// =============================================================
// Determinism
// =============================================================

#[test]
fn wire_read_deterministic_error() {
    let bad = vec![0x00; 50];
    let r1 = parse_tx(&bad);
    let r2 = parse_tx(&bad);
    assert_eq!(r1.is_err(), r2.is_err());
}

#[test]
fn wire_read_deterministic_success() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&1u64.to_le_bytes());
    buf.push(0x00); // 0 inputs
    buf.push(0x00); // 0 outputs
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.push(0x00); // witness
    buf.push(0x00); // da_payload

    let (tx1, txid1, _, _) = parse_tx(&buf).unwrap();
    let (tx2, txid2, _, _) = parse_tx(&buf).unwrap();
    assert_eq!(txid1, txid2);
    assert_eq!(tx1.version, tx2.version);
    assert_eq!(tx1.tx_kind, tx2.tx_kind);
    assert_eq!(tx1.tx_nonce, tx2.tx_nonce);
}

// =============================================================
// All-zeros / all-ff: no panic
// =============================================================

#[test]
fn wire_read_all_zeros_256() {
    assert!(parse_tx(&[0x00; 256]).is_err());
}

#[test]
fn wire_read_all_ff_256() {
    assert!(parse_tx(&[0xFF; 256]).is_err());
}

// =============================================================
// Compact size edge cases via parse_tx
// =============================================================

#[test]
fn wire_read_compact_size_fd_prefix_truncated() {
    // version=1, kind=0, nonce=1, then 0xFD for input_count but only 1 byte follows (need 2)
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&1u64.to_le_bytes());
    buf.push(0xFD); // compact size prefix for 2-byte value
    buf.push(0x01); // only 1 of 2 bytes
    assert!(parse_tx(&buf).is_err());
}

#[test]
fn wire_read_compact_size_fe_prefix_truncated() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&1u64.to_le_bytes());
    buf.push(0xFE); // 4-byte value
    buf.extend_from_slice(&[0x01, 0x00]); // only 2 of 4 bytes
    assert!(parse_tx(&buf).is_err());
}

#[test]
fn wire_read_compact_size_ff_prefix_truncated() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&1u64.to_le_bytes());
    buf.push(0xFF); // 8-byte value
    buf.extend_from_slice(&[0x01; 4]); // only 4 of 8 bytes
    assert!(parse_tx(&buf).is_err());
}
