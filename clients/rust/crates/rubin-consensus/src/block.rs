use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u64,
    pub target: [u8; 32],
    pub nonce: u64,
}

pub const BLOCK_HEADER_BYTES: usize = 116;

pub fn parse_block_header_bytes(b: &[u8]) -> Result<BlockHeader, TxError> {
    if b.len() != BLOCK_HEADER_BYTES {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "block header length mismatch",
        ));
    }

    let version = u32::from_le_bytes(b[0..4].try_into().unwrap());
    let mut prev_block_hash = [0u8; 32];
    prev_block_hash.copy_from_slice(&b[4..36]);
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&b[36..68]);
    let timestamp = u64::from_le_bytes(b[68..76].try_into().unwrap());
    let mut target = [0u8; 32];
    target.copy_from_slice(&b[76..108]);
    let nonce = u64::from_le_bytes(b[108..116].try_into().unwrap());

    Ok(BlockHeader {
        version,
        prev_block_hash,
        merkle_root,
        timestamp,
        target,
        nonce,
    })
}

pub fn block_hash(header_bytes: &[u8]) -> Result<[u8; 32], TxError> {
    if header_bytes.len() != BLOCK_HEADER_BYTES {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "block hash: invalid header length",
        ));
    }
    Ok(sha3_256(header_bytes))
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn verify_parse_block_header_bytes_accepts_exact_length() {
        let buf: [u8; BLOCK_HEADER_BYTES] = kani::any();
        let header = parse_block_header_bytes(&buf).expect("exact-length header must parse");

        assert_eq!(
            header.version,
            u32::from_le_bytes(buf[0..4].try_into().unwrap())
        );
        assert_eq!(
            header.prev_block_hash,
            <[u8; 32]>::try_from(&buf[4..36]).expect("prev_block_hash slice")
        );
        assert_eq!(
            header.merkle_root,
            <[u8; 32]>::try_from(&buf[36..68]).expect("merkle_root slice")
        );
        assert_eq!(
            header.timestamp,
            u64::from_le_bytes(buf[68..76].try_into().unwrap())
        );
        assert_eq!(
            header.target,
            <[u8; 32]>::try_from(&buf[76..108]).expect("target slice")
        );
        assert_eq!(
            header.nonce,
            u64::from_le_bytes(buf[108..116].try_into().unwrap())
        );
    }

    #[kani::proof]
    fn verify_parse_block_header_bytes_rejects_short_length() {
        let buf: [u8; BLOCK_HEADER_BYTES - 1] = kani::any();
        let err = parse_block_header_bytes(&buf).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }
}
