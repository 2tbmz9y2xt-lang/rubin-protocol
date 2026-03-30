use rubin_consensus::{encode_compact_size, read_compact_size_bytes, ErrorCode};

// =============================================================
// encode_compact_size — encoding correctness
// =============================================================

#[test]
fn encode_zero() {
    let mut buf = Vec::new();
    encode_compact_size(0, &mut buf);
    assert_eq!(buf, vec![0x00]);
}

#[test]
fn encode_one() {
    let mut buf = Vec::new();
    encode_compact_size(1, &mut buf);
    assert_eq!(buf, vec![0x01]);
}

#[test]
fn encode_252_single_byte_max() {
    let mut buf = Vec::new();
    encode_compact_size(252, &mut buf);
    assert_eq!(buf, vec![0xfc]);
}

#[test]
fn encode_253_three_bytes() {
    let mut buf = Vec::new();
    encode_compact_size(253, &mut buf);
    assert_eq!(buf, vec![0xfd, 0xfd, 0x00]); // 0xfd + 253u16 LE
}

#[test]
fn encode_65535_three_bytes_max() {
    let mut buf = Vec::new();
    encode_compact_size(65535, &mut buf);
    assert_eq!(buf, vec![0xfd, 0xff, 0xff]); // 0xfd + 65535u16 LE
}

#[test]
fn encode_65536_five_bytes() {
    let mut buf = Vec::new();
    encode_compact_size(65536, &mut buf);
    assert_eq!(buf, vec![0xfe, 0x00, 0x00, 0x01, 0x00]); // 0xfe + 65536u32 LE
}

#[test]
fn encode_u32_max_five_bytes() {
    let mut buf = Vec::new();
    encode_compact_size(0xffff_ffff, &mut buf);
    assert_eq!(buf, vec![0xfe, 0xff, 0xff, 0xff, 0xff]);
}

#[test]
fn encode_u32_max_plus_one_nine_bytes() {
    let mut buf = Vec::new();
    encode_compact_size(0x1_0000_0000, &mut buf);
    assert_eq!(
        buf,
        vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
    );
}

#[test]
fn encode_u64_max() {
    let mut buf = Vec::new();
    encode_compact_size(u64::MAX, &mut buf);
    assert_eq!(
        buf,
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
}

// =============================================================
// encode_compact_size — output length
// =============================================================

#[test]
fn encode_length_1byte_range() {
    for v in [0u64, 1, 127, 252] {
        let mut buf = Vec::new();
        encode_compact_size(v, &mut buf);
        assert_eq!(buf.len(), 1, "value {v} should encode to 1 byte");
    }
}

#[test]
fn encode_length_3byte_range() {
    for v in [253u64, 1000, 65535] {
        let mut buf = Vec::new();
        encode_compact_size(v, &mut buf);
        assert_eq!(buf.len(), 3, "value {v} should encode to 3 bytes");
    }
}

#[test]
fn encode_length_5byte_range() {
    for v in [65536u64, 1_000_000, 0xffff_ffff] {
        let mut buf = Vec::new();
        encode_compact_size(v, &mut buf);
        assert_eq!(buf.len(), 5, "value {v} should encode to 5 bytes");
    }
}

#[test]
fn encode_length_9byte_range() {
    for v in [0x1_0000_0000u64, u64::MAX / 2, u64::MAX] {
        let mut buf = Vec::new();
        encode_compact_size(v, &mut buf);
        assert_eq!(buf.len(), 9, "value {v} should encode to 9 bytes");
    }
}

// =============================================================
// read_compact_size_bytes — valid decoding
// =============================================================

#[test]
fn decode_zero() {
    let (v, consumed) = read_compact_size_bytes(&[0x00]).unwrap();
    assert_eq!(v, 0);
    assert_eq!(consumed, 1);
}

#[test]
fn decode_252() {
    let (v, consumed) = read_compact_size_bytes(&[0xfc]).unwrap();
    assert_eq!(v, 252);
    assert_eq!(consumed, 1);
}

#[test]
fn decode_253() {
    let (v, consumed) = read_compact_size_bytes(&[0xfd, 0xfd, 0x00]).unwrap();
    assert_eq!(v, 253);
    assert_eq!(consumed, 3);
}

#[test]
fn decode_65535() {
    let (v, consumed) = read_compact_size_bytes(&[0xfd, 0xff, 0xff]).unwrap();
    assert_eq!(v, 65535);
    assert_eq!(consumed, 3);
}

#[test]
fn decode_65536() {
    let (v, consumed) = read_compact_size_bytes(&[0xfe, 0x00, 0x00, 0x01, 0x00]).unwrap();
    assert_eq!(v, 65536);
    assert_eq!(consumed, 5);
}

#[test]
fn decode_u32_max() {
    let (v, consumed) = read_compact_size_bytes(&[0xfe, 0xff, 0xff, 0xff, 0xff]).unwrap();
    assert_eq!(v, 0xffff_ffff);
    assert_eq!(consumed, 5);
}

#[test]
fn decode_u32_max_plus_one() {
    let (v, consumed) =
        read_compact_size_bytes(&[0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(v, 0x1_0000_0000);
    assert_eq!(consumed, 9);
}

#[test]
fn decode_u64_max() {
    let (v, consumed) =
        read_compact_size_bytes(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap();
    assert_eq!(v, u64::MAX);
    assert_eq!(consumed, 9);
}

// =============================================================
// roundtrip: encode → decode for boundary values
// =============================================================

#[test]
fn roundtrip_boundaries() {
    let values = [
        0u64,
        1,
        252,
        253,
        254,
        65534,
        65535,
        65536,
        65537,
        0xffff_fffe,
        0xffff_ffff,
        0x1_0000_0000,
        u64::MAX - 1,
        u64::MAX,
    ];
    for &v in &values {
        let mut buf = Vec::new();
        encode_compact_size(v, &mut buf);
        let (decoded, consumed) = read_compact_size_bytes(&buf)
            .unwrap_or_else(|e| panic!("roundtrip failed for {v}: {e:?}"));
        assert_eq!(decoded, v, "roundtrip mismatch for {v}");
        assert_eq!(consumed, buf.len(), "consumed mismatch for {v}");
    }
}

// =============================================================
// read_compact_size_bytes — non-minimal encoding rejection
// =============================================================

#[test]
fn nonminimal_fd_tag_for_value_0() {
    // 0xfd + 0u16 LE = encoding "0" as 3 bytes (non-minimal)
    let err = read_compact_size_bytes(&[0xfd, 0x00, 0x00]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert!(err.msg.contains("non-minimal"));
}

#[test]
fn nonminimal_fd_tag_for_value_252() {
    // 0xfd + 252u16 LE (should be single byte 0xfc)
    let err = read_compact_size_bytes(&[0xfd, 0xfc, 0x00]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert!(err.msg.contains("non-minimal"));
}

#[test]
fn nonminimal_fe_tag_for_value_253() {
    // 0xfe + 253u32 LE (should be 0xfd + u16)
    let err = read_compact_size_bytes(&[0xfe, 0xfd, 0x00, 0x00, 0x00]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert!(err.msg.contains("non-minimal"));
}

#[test]
fn nonminimal_fe_tag_for_value_65535() {
    // 0xfe + 65535u32 LE (should be 0xfd + u16)
    let err = read_compact_size_bytes(&[0xfe, 0xff, 0xff, 0x00, 0x00]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert!(err.msg.contains("non-minimal"));
}

#[test]
fn nonminimal_ff_tag_for_value_0() {
    // 0xff + 0u64 LE
    let err = read_compact_size_bytes(&[0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert!(err.msg.contains("non-minimal"));
}

#[test]
fn nonminimal_ff_tag_for_value_u32_max() {
    // 0xff + 0xffffffff u64 LE (should be 0xfe + u32)
    let err = read_compact_size_bytes(&[0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00])
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert!(err.msg.contains("non-minimal"));
}

// =============================================================
// read_compact_size_bytes — EOF errors
// =============================================================

#[test]
fn eof_empty_buffer() {
    let err = read_compact_size_bytes(&[]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn eof_fd_tag_missing_u16() {
    // 0xfd tag but only 1 byte after (need 2)
    let err = read_compact_size_bytes(&[0xfd, 0x00]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn eof_fd_tag_no_payload() {
    let err = read_compact_size_bytes(&[0xfd]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn eof_fe_tag_missing_u32() {
    let err = read_compact_size_bytes(&[0xfe, 0x00, 0x00]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn eof_ff_tag_missing_u64() {
    let err = read_compact_size_bytes(&[0xff, 0x00, 0x00, 0x00]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

// =============================================================
// Trailing bytes: decode ignores extra data
// =============================================================

#[test]
fn decode_with_trailing_bytes() {
    let (v, consumed) = read_compact_size_bytes(&[0x42, 0xAA, 0xBB]).unwrap();
    assert_eq!(v, 0x42);
    assert_eq!(consumed, 1); // only consumed 1 byte, trailing ignored
}

#[test]
fn decode_fd_with_trailing() {
    let (v, consumed) = read_compact_size_bytes(&[0xfd, 0xfd, 0x00, 0xff, 0xff]).unwrap();
    assert_eq!(v, 253);
    assert_eq!(consumed, 3);
}
