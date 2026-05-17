use super::ParsedBlock;
use crate::block::{parse_block_header_bytes, BLOCK_HEADER_BYTES};
use crate::compactsize::read_compact_size;
use crate::error::{ErrorCode, TxError};
use crate::tx::{parse_tx, Tx};
use crate::wire_read::Reader;

pub(super) fn parse_block_bytes_impl(block_bytes: &[u8]) -> Result<ParsedBlock, TxError> {
    if block_bytes.len() < BLOCK_HEADER_BYTES + 1 {
        return Err(TxError::new(ErrorCode::BlockErrParse, "block too short"));
    }

    let mut header_bytes = [0u8; BLOCK_HEADER_BYTES];
    header_bytes.copy_from_slice(&block_bytes[..BLOCK_HEADER_BYTES]);
    let header = parse_block_header_bytes(&header_bytes)
        .map_err(|_| TxError::new(ErrorCode::BlockErrParse, "invalid block header"))?;

    let mut r = Reader::new(&block_bytes[BLOCK_HEADER_BYTES..]);
    let (tx_count, _) = read_compact_size(&mut r)
        .map_err(|_| TxError::new(ErrorCode::BlockErrParse, "invalid tx_count"))?;
    if tx_count == 0 {
        return Err(TxError::new(
            ErrorCode::BlockErrCoinbaseInvalid,
            "empty block tx list",
        ));
    }

    let mut txs: Vec<Tx> = Vec::new();
    let mut txids: Vec<[u8; 32]> = Vec::new();
    let mut wtxids: Vec<[u8; 32]> = Vec::new();

    for _ in 0..tx_count {
        let (tx, txid, wtxid) = parse_next_block_tx(block_bytes, &mut r)?;
        txs.push(tx);
        txids.push(txid);
        wtxids.push(wtxid);
    }

    if BLOCK_HEADER_BYTES + r.offset() != block_bytes.len() {
        return Err(TxError::new(
            ErrorCode::BlockErrParse,
            "trailing bytes after tx list",
        ));
    }

    Ok(ParsedBlock {
        header,
        header_bytes,
        tx_count,
        txs,
        txids,
        wtxids,
    })
}

fn parse_next_block_tx(
    block_bytes: &[u8],
    r: &mut Reader<'_>,
) -> Result<(Tx, [u8; 32], [u8; 32]), TxError> {
    let rem = &block_bytes[BLOCK_HEADER_BYTES + r.offset()..];
    if rem.is_empty() {
        return Err(TxError::new(
            ErrorCode::BlockErrParse,
            "unexpected EOF in tx list",
        ));
    }

    let (tx, txid, wtxid, consumed) = parse_tx(rem)?;
    if consumed == 0 {
        return Err(TxError::new(
            ErrorCode::BlockErrParse,
            "zero-length tx parse",
        ));
    }

    r.read_bytes(consumed)
        .map_err(|_| TxError::new(ErrorCode::BlockErrParse, "unexpected EOF in tx list"))?;

    Ok((tx, txid, wtxid))
}
