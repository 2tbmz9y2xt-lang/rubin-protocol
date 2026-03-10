//! Shared test utilities for rubin-node integration tests.

use rubin_consensus::constants::POW_LIMIT;
use rubin_consensus::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
use rubin_consensus::{
    block_hash, encode_compact_size, merkle_root_txids, parse_block_bytes, parse_tx,
    BLOCK_HEADER_BYTES,
};

use crate::coinbase::{build_coinbase_tx, default_mine_address};
use crate::genesis::devnet_genesis_block_bytes;

pub fn build_block_bytes(
    prev_hash: [u8; 32],
    merkle_root: [u8; 32],
    target: [u8; 32],
    timestamp: u64,
    txs: &[Vec<u8>],
) -> Vec<u8> {
    let mut header = Vec::with_capacity(BLOCK_HEADER_BYTES);
    header.extend_from_slice(&1u32.to_le_bytes());
    header.extend_from_slice(&prev_hash);
    header.extend_from_slice(&merkle_root);
    header.extend_from_slice(&timestamp.to_le_bytes());
    header.extend_from_slice(&target);
    header.extend_from_slice(&0u64.to_le_bytes());
    assert_eq!(header.len(), BLOCK_HEADER_BYTES);

    let mut block = header;
    encode_compact_size(txs.len() as u64, &mut block);
    for tx in txs {
        block.extend_from_slice(tx);
    }
    block
}

/// Returns (genesis_bytes, genesis_hash, genesis_timestamp).
pub fn genesis_info() -> (Vec<u8>, [u8; 32], u64) {
    let genesis = devnet_genesis_block_bytes();
    let hash = block_hash(&genesis[..BLOCK_HEADER_BYTES]).expect("genesis hash");
    let parsed = parse_block_bytes(&genesis).expect("parse genesis");
    (genesis, hash, parsed.header.timestamp)
}

/// Build a valid coinbase-only block at a given height with explicit already_generated.
pub fn coinbase_only_block_with_gen(
    height: u64,
    already_generated: u64,
    prev_hash: [u8; 32],
    timestamp: u64,
) -> Vec<u8> {
    let witness_root = witness_merkle_root_wtxids(&[[0u8; 32]]).expect("witness root");
    let witness_commitment = witness_commitment_hash(witness_root);
    let coinbase = build_coinbase_tx(
        height,
        already_generated,
        &default_mine_address(),
        witness_commitment,
    )
    .expect("coinbase");
    let (_, coinbase_txid, _, consumed) = parse_tx(&coinbase).expect("parse coinbase");
    assert_eq!(consumed, coinbase.len());
    let merkle_root = merkle_root_txids(&[coinbase_txid]).expect("merkle root");
    build_block_bytes(prev_hash, merkle_root, POW_LIMIT, timestamp, &[coinbase])
}

/// Build a valid coinbase-only block at a given height (already_generated = 0).
pub fn coinbase_only_block(height: u64, prev_hash: [u8; 32], timestamp: u64) -> Vec<u8> {
    coinbase_only_block_with_gen(height, 0, prev_hash, timestamp)
}

/// Build a valid height-1 coinbase-only block with timestamp > genesis.
pub fn height_one_coinbase_only_block(prev_hash: [u8; 32], timestamp: u64) -> Vec<u8> {
    coinbase_only_block(1, prev_hash, timestamp)
}
