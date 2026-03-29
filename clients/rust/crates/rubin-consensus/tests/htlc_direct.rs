use rubin_consensus::{parse_htlc_covenant_data, ErrorCode};

// --- helpers ---

const LOCK_MODE_HEIGHT: u8 = 0x00;
const LOCK_MODE_TIMESTAMP: u8 = 0x01;

fn build_htlc_data(
    hash: [u8; 32],
    lock_mode: u8,
    lock_value: u64,
    claim_key_id: [u8; 32],
    refund_key_id: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(105);
    out.extend_from_slice(&hash);
    out.push(lock_mode);
    out.extend_from_slice(&lock_value.to_le_bytes());
    out.extend_from_slice(&claim_key_id);
    out.extend_from_slice(&refund_key_id);
    assert_eq!(out.len(), 105); // MAX_HTLC_COVENANT_DATA
    out
}

fn default_claim_key() -> [u8; 32] {
    [0xAA; 32]
}

fn default_refund_key() -> [u8; 32] {
    [0xBB; 32]
}

// =============================================================
// parse_htlc_covenant_data — valid inputs
// =============================================================

#[test]
fn htlc_parse_valid_height_lock() {
    let hash = [0x11; 32];
    let data = build_htlc_data(
        hash,
        LOCK_MODE_HEIGHT,
        100,
        default_claim_key(),
        default_refund_key(),
    );
    let h = parse_htlc_covenant_data(&data).expect("valid height lock");
    assert_eq!(h.hash, hash);
    assert_eq!(h.lock_mode, LOCK_MODE_HEIGHT);
    assert_eq!(h.lock_value, 100);
    assert_eq!(h.claim_key_id, default_claim_key());
    assert_eq!(h.refund_key_id, default_refund_key());
}

#[test]
fn htlc_parse_valid_timestamp_lock() {
    let hash = [0x22; 32];
    let data = build_htlc_data(
        hash,
        LOCK_MODE_TIMESTAMP,
        1700000000,
        default_claim_key(),
        default_refund_key(),
    );
    let h = parse_htlc_covenant_data(&data).expect("valid timestamp lock");
    assert_eq!(h.lock_mode, LOCK_MODE_TIMESTAMP);
    assert_eq!(h.lock_value, 1700000000);
}

#[test]
fn htlc_parse_max_lock_value() {
    let data = build_htlc_data(
        [0; 32],
        LOCK_MODE_HEIGHT,
        u64::MAX,
        default_claim_key(),
        default_refund_key(),
    );
    let h = parse_htlc_covenant_data(&data).expect("max lock_value");
    assert_eq!(h.lock_value, u64::MAX);
}

// =============================================================
// parse_htlc_covenant_data — error paths
// =============================================================

#[test]
fn htlc_parse_wrong_length_short() {
    let data = vec![0u8; 104]; // 105 - 1
    let err = parse_htlc_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err.msg.contains("length mismatch"));
}

#[test]
fn htlc_parse_wrong_length_long() {
    let data = vec![0u8; 106]; // 105 + 1
    let err = parse_htlc_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn htlc_parse_empty() {
    let err = parse_htlc_covenant_data(&[]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn htlc_parse_invalid_lock_mode() {
    let data = build_htlc_data(
        [0; 32],
        0x02, // neither HEIGHT(0x00) nor TIMESTAMP(0x01)
        100,
        default_claim_key(),
        default_refund_key(),
    );
    let err = parse_htlc_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err.msg.contains("lock_mode"));
}

#[test]
fn htlc_parse_invalid_lock_mode_0x03() {
    let data = build_htlc_data(
        [0; 32],
        0x03,
        100,
        default_claim_key(),
        default_refund_key(),
    );
    let err = parse_htlc_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn htlc_parse_invalid_lock_mode_0xff() {
    let data = build_htlc_data(
        [0; 32],
        0xFF,
        100,
        default_claim_key(),
        default_refund_key(),
    );
    let err = parse_htlc_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn htlc_parse_lock_value_zero() {
    let data = build_htlc_data(
        [0; 32],
        LOCK_MODE_HEIGHT,
        0,
        default_claim_key(),
        default_refund_key(),
    );
    let err = parse_htlc_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err.msg.contains("lock_value"));
}

#[test]
fn htlc_parse_lock_value_zero_timestamp() {
    let data = build_htlc_data(
        [0; 32],
        LOCK_MODE_TIMESTAMP,
        0,
        default_claim_key(),
        default_refund_key(),
    );
    let err = parse_htlc_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err.msg.contains("lock_value"));
}

#[test]
fn htlc_parse_claim_equals_refund_key() {
    let same_key = [0xCC; 32];
    let data = build_htlc_data([0; 32], LOCK_MODE_HEIGHT, 100, same_key, same_key);
    let err = parse_htlc_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert!(err.msg.contains("claim/refund key_id must differ"));
}

// =============================================================
// HtlcCovenant struct derives
// =============================================================

#[test]
fn htlc_struct_clone_eq() {
    let data = build_htlc_data(
        [0x11; 32],
        LOCK_MODE_HEIGHT,
        50,
        default_claim_key(),
        default_refund_key(),
    );
    let h = parse_htlc_covenant_data(&data).unwrap();
    let h2 = h.clone();
    assert_eq!(h, h2);
}

#[test]
fn htlc_struct_ne_different_hash() {
    let d1 = build_htlc_data(
        [0x11; 32],
        LOCK_MODE_HEIGHT,
        50,
        default_claim_key(),
        default_refund_key(),
    );
    let d2 = build_htlc_data(
        [0x22; 32],
        LOCK_MODE_HEIGHT,
        50,
        default_claim_key(),
        default_refund_key(),
    );
    let h1 = parse_htlc_covenant_data(&d1).unwrap();
    let h2 = parse_htlc_covenant_data(&d2).unwrap();
    assert_ne!(h1, h2);
}

#[test]
fn htlc_struct_debug() {
    let data = build_htlc_data(
        [0; 32],
        LOCK_MODE_HEIGHT,
        1,
        default_claim_key(),
        default_refund_key(),
    );
    let h = parse_htlc_covenant_data(&data).unwrap();
    let dbg = format!("{:?}", h);
    assert!(dbg.contains("HtlcCovenant"));
}

// =============================================================
// Lock mode boundary: exactly HEIGHT and TIMESTAMP
// =============================================================

#[test]
fn htlc_parse_lock_mode_height_is_0x00() {
    // Ensure LOCK_MODE_HEIGHT == 0x00 (consensus constant)
    let data = build_htlc_data([0; 32], 0x00, 1, default_claim_key(), default_refund_key());
    let h = parse_htlc_covenant_data(&data).unwrap();
    assert_eq!(h.lock_mode, 0x00);
}

#[test]
fn htlc_parse_lock_mode_timestamp_is_0x01() {
    let data = build_htlc_data([0; 32], 0x01, 1, default_claim_key(), default_refund_key());
    let h = parse_htlc_covenant_data(&data).unwrap();
    assert_eq!(h.lock_mode, 0x01);
}

// =============================================================
// LE byte order for lock_value
// =============================================================

#[test]
fn htlc_parse_lock_value_le_byte_order() {
    // 0x0100000000000000 in LE = 1
    let data = build_htlc_data(
        [0; 32],
        LOCK_MODE_HEIGHT,
        0x0102030405060708,
        default_claim_key(),
        default_refund_key(),
    );
    let h = parse_htlc_covenant_data(&data).unwrap();
    assert_eq!(h.lock_value, 0x0102030405060708);
    // Verify raw bytes at offset 33..41 are LE
    assert_eq!(data[33], 0x08); // least significant byte first
    assert_eq!(data[40], 0x01); // most significant byte last
}
