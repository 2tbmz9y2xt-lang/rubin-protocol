//! Shared test utilities for rubin-node integration tests.

use rubin_consensus::constants::POW_LIMIT;
use rubin_consensus::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
use rubin_consensus::{
    block_hash, encode_compact_size, marshal_tx, merkle_root_txids, p2pk_covenant_data_for_pubkey,
    parse_block_bytes, parse_tx, sign_transaction, Mldsa87Keypair, Outpoint, Tx, TxInput, TxOutput,
    UtxoEntry, BLOCK_HEADER_BYTES,
};

use crate::coinbase::{build_coinbase_tx, default_mine_address};
use crate::devnet_genesis_chain_id;
use crate::genesis::devnet_genesis_block_bytes;
use crate::ChainState;

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

pub fn block_with_txs(
    height: u64,
    already_generated: u64,
    prev_hash: [u8; 32],
    timestamp: u64,
    txs: &[Vec<u8>],
) -> Vec<u8> {
    let mut txids = Vec::with_capacity(1 + txs.len());
    let mut wtxids = Vec::with_capacity(1 + txs.len());
    wtxids.push([0u8; 32]);
    for tx_bytes in txs {
        let (_tx, txid, wtxid, consumed) = parse_tx(tx_bytes).expect("parse tx");
        assert_eq!(consumed, tx_bytes.len());
        txids.push(txid);
        wtxids.push(wtxid);
    }

    let witness_root = witness_merkle_root_wtxids(&wtxids).expect("witness root");
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

    let mut all_txids = Vec::with_capacity(1 + txids.len());
    all_txids.push(coinbase_txid);
    all_txids.extend_from_slice(&txids);
    let merkle_root = merkle_root_txids(&all_txids).expect("merkle root");

    let mut block_txs = Vec::with_capacity(1 + txs.len());
    block_txs.push(coinbase);
    block_txs.extend(txs.iter().cloned());
    build_block_bytes(prev_hash, merkle_root, POW_LIMIT, timestamp, &block_txs)
}

pub fn signed_conflicting_p2pk_state_and_txs(
    input_value: u64,
    first_output_value: u64,
    second_output_value: u64,
) -> (ChainState, Vec<u8>, Vec<u8>) {
    let keypair = Mldsa87Keypair::generate().expect("OpenSSL signer unavailable");
    let pubkey = keypair.pubkey_bytes();
    let outpoint = Outpoint {
        txid: [0x11; 32],
        vout: 0,
    };

    let mut state = ChainState::new();
    state.utxos.insert(
        outpoint.clone(),
        UtxoEntry {
            value: input_value,
            covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
            covenant_data: p2pk_covenant_data_for_pubkey(&pubkey),
            creation_height: 0,
            created_by_coinbase: false,
        },
    );

    let build_tx = |tx_nonce: u64, output_value: u64| -> Vec<u8> {
        let mut tx = Tx {
            version: rubin_consensus::constants::TX_WIRE_VERSION,
            tx_kind: 0x00,
            tx_nonce,
            inputs: vec![TxInput {
                prev_txid: outpoint.txid,
                prev_vout: outpoint.vout,
                script_sig: Vec::new(),
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: output_value,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&vec![tx_nonce as u8; 2592]),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        };
        sign_transaction(&mut tx, &state.utxos, devnet_genesis_chain_id(), &keypair)
            .expect("sign tx");
        marshal_tx(&tx).expect("marshal tx")
    };

    let first = build_tx(7, first_output_value);
    let second = build_tx(8, second_output_value);
    (state, first, second)
}

/// Build a valid coinbase-only block at a given height (already_generated = 0).
pub fn coinbase_only_block(height: u64, prev_hash: [u8; 32], timestamp: u64) -> Vec<u8> {
    coinbase_only_block_with_gen(height, 0, prev_hash, timestamp)
}

/// Build a valid height-1 coinbase-only block with timestamp > genesis.
pub fn height_one_coinbase_only_block(prev_hash: [u8; 32], timestamp: u64) -> Vec<u8> {
    coinbase_only_block(1, prev_hash, timestamp)
}
