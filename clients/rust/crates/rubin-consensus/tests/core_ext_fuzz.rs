//! Deterministic fuzz-style tests for parse_core_ext_covenant_data.
//! Mirrors Go FuzzParseCoreExtCovenantData.
//!
//! Invariant: no panic on any byte input; roundtrip canonicality;
//! deterministic results.

use rubin_consensus::{encode_compact_size, parse_core_ext_covenant_data};

/// Construct canonical CORE_EXT covenant_data: ext_id(u16 LE) + compact_size(payload_len) + payload.
fn core_ext_covenant_data(ext_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ext_id.to_le_bytes());
    encode_compact_size(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

// =============================================================
// Empty / too short — no panic
// =============================================================

#[test]
fn core_ext_parse_empty() {
    assert!(parse_core_ext_covenant_data(&[]).is_err());
}

#[test]
fn core_ext_parse_one_byte() {
    assert!(parse_core_ext_covenant_data(&[0x01]).is_err());
}

#[test]
fn core_ext_parse_two_bytes_zero_payload() {
    // ext_id(2 bytes) + implicit compact_size needed
    assert!(parse_core_ext_covenant_data(&[0x00, 0x00]).is_err());
}

// =============================================================
// Canonical roundtrip — parse → re-encode = original
// =============================================================

#[test]
fn core_ext_roundtrip_empty_payload() {
    let data = core_ext_covenant_data(0x1234, &[]);
    let parsed = parse_core_ext_covenant_data(&data).unwrap();
    assert_eq!(parsed.ext_id, 0x1234);
    assert!(parsed.ext_payload.is_empty());
    let reencoded = core_ext_covenant_data(parsed.ext_id, parsed.ext_payload);
    assert_eq!(data, reencoded);
}

#[test]
fn core_ext_roundtrip_small_payload() {
    let payload = vec![0xAA, 0xBB, 0xCC];
    let data = core_ext_covenant_data(0x1234, &payload);
    let parsed = parse_core_ext_covenant_data(&data).unwrap();
    assert_eq!(parsed.ext_id, 0x1234);
    assert_eq!(parsed.ext_payload, &payload[..]);
    let reencoded = core_ext_covenant_data(parsed.ext_id, parsed.ext_payload);
    assert_eq!(data, reencoded);
}

#[test]
fn core_ext_roundtrip_ext_id_zero() {
    let data = core_ext_covenant_data(0x0000, &[0x01, 0x02]);
    let parsed = parse_core_ext_covenant_data(&data).unwrap();
    assert_eq!(parsed.ext_id, 0x0000);
    let reencoded = core_ext_covenant_data(parsed.ext_id, parsed.ext_payload);
    assert_eq!(data, reencoded);
}

#[test]
fn core_ext_roundtrip_ext_id_max() {
    let data = core_ext_covenant_data(0xFFFF, &[0xFF]);
    let parsed = parse_core_ext_covenant_data(&data).unwrap();
    assert_eq!(parsed.ext_id, 0xFFFF);
    let reencoded = core_ext_covenant_data(parsed.ext_id, parsed.ext_payload);
    assert_eq!(data, reencoded);
}

// =============================================================
// Non-canonical inputs — rejected
// =============================================================

#[test]
fn core_ext_truncated_compact_size() {
    // ext_id + 0xFD prefix (needs 2 more bytes) but only 1 more
    let data = vec![0x34, 0x12, 0xFD, 0x01];
    assert!(parse_core_ext_covenant_data(&data).is_err());
}

#[test]
fn core_ext_payload_len_exceeds_data() {
    // ext_id=0x1234, compact_size says 2 bytes payload, but only 1 byte present
    let data = vec![0x34, 0x12, 0x02, 0xAA];
    assert!(parse_core_ext_covenant_data(&data).is_err());
}

#[test]
fn core_ext_trailing_bytes() {
    // Valid data + extra trailing byte → non-canonical
    let mut data = core_ext_covenant_data(0x0001, &[0x42]);
    data.push(0xFF); // trailing garbage
    assert!(parse_core_ext_covenant_data(&data).is_err());
}

#[test]
fn core_ext_huge_compact_size_no_panic() {
    // ext_id + 0xFF tag (9-byte compact_size indicating huge payload)
    let data = vec![
        0x00, 0xFF, // ext_id
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, // compact_size = huge
        0x00, // one byte of "payload"
    ];
    assert!(parse_core_ext_covenant_data(&data).is_err());
}

// =============================================================
// Determinism
// =============================================================

#[test]
fn core_ext_deterministic_ok() {
    let data = core_ext_covenant_data(0x0042, &[0x01, 0x02, 0x03]);
    let r1 = parse_core_ext_covenant_data(&data);
    let r2 = parse_core_ext_covenant_data(&data);
    assert!(r1.is_ok());
    assert!(r2.is_ok());
    let (p1, p2) = (r1.unwrap(), r2.unwrap());
    assert_eq!(p1.ext_id, p2.ext_id);
    assert_eq!(p1.ext_payload, p2.ext_payload);
}

#[test]
fn core_ext_deterministic_err() {
    let data = vec![0x00; 1];
    let r1 = parse_core_ext_covenant_data(&data);
    let r2 = parse_core_ext_covenant_data(&data);
    assert!(r1.is_err());
    assert!(r2.is_err());
}

// =============================================================
// Various payload sizes — no panic
// =============================================================

#[test]
fn core_ext_various_payload_sizes() {
    for size in [0, 1, 10, 100, 252, 253, 254, 500, 1000] {
        let payload = vec![0xABu8; size];
        let data = core_ext_covenant_data(0x0001, &payload);
        let parsed = parse_core_ext_covenant_data(&data).unwrap();
        assert_eq!(parsed.ext_payload.len(), size);
    }
}

#[test]
fn core_ext_incremental_raw_lengths_no_panic() {
    for len in 0..=300 {
        let buf = vec![0x55u8; len];
        let _ = parse_core_ext_covenant_data(&buf);
    }
}

// =============================================================
// All-zeros and all-ff — no panic
// =============================================================

#[test]
fn core_ext_all_zeros_no_panic() {
    // [0x00, 0x00, 0x00] = ext_id=0, compact_size=0, payload empty
    let data = vec![0u8; 3];
    let r = parse_core_ext_covenant_data(&data);
    assert!(r.is_ok());
    let p = r.unwrap();
    assert_eq!(p.ext_id, 0);
    assert!(p.ext_payload.is_empty());
}

#[test]
fn core_ext_all_ff_256_no_panic() {
    let _ = parse_core_ext_covenant_data(&[0xFF; 256]);
}
