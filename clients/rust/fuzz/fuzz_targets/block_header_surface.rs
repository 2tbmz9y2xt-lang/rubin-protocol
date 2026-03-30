#![no_main]

use libfuzzer_sys::fuzz_target;
use rubin_consensus::{block_hash, parse_block_header_bytes, ErrorCode, BLOCK_HEADER_BYTES};

fuzz_target!(|data: &[u8]| {
    if data.len() < BLOCK_HEADER_BYTES {
        let err = parse_block_header_bytes(data).expect_err("short block header must fail");
        assert_eq!(err.code, ErrorCode::TxErrParse);
        return;
    }

    let header_bytes = &data[..BLOCK_HEADER_BYTES];
    let parsed_a = parse_block_header_bytes(header_bytes).expect("exact header");
    let parsed_b = parse_block_header_bytes(header_bytes).expect("repeat exact header");
    assert_eq!(parsed_a, parsed_b, "parse_block_header_bytes drift");

    let hash_a = block_hash(header_bytes).expect("hash exact header");
    let hash_b = block_hash(header_bytes).expect("rehash exact header");
    assert_eq!(hash_a, hash_b, "block_hash drift");
});
