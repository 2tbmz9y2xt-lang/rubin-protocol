#![allow(dead_code)]

use sha3::{Digest, Sha3_256};

use rubin_consensus::constants::{
    COV_TYPE_ANCHOR, SIGHASH_ALL, SUITE_ID_ML_DSA_87, TX_WIRE_VERSION,
};
use rubin_consensus::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
use rubin_consensus::{
    block_subsidy, encode_compact_size, marshal_tx, merkle_root_txids,
    p2pk_covenant_data_for_pubkey, parse_tx, sighash_v1_digest_with_type, Mldsa87Keypair, Tx,
    TxInput, TxOutput, WitnessItem,
};

pub const ZERO_CHAIN_ID: [u8; 32] = [0u8; 32];

#[derive(Clone)]
pub struct TestOutput {
    pub value: u64,
    pub covenant_type: u16,
    pub covenant_data: Vec<u8>,
}

pub fn sha3_256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn filled32(byte: u8) -> [u8; 32] {
    [byte; 32]
}

pub fn build_block_bytes(
    prev_hash: [u8; 32],
    merkle_root: [u8; 32],
    target: [u8; 32],
    nonce: u64,
    txs: &[Vec<u8>],
) -> Vec<u8> {
    let mut header = Vec::with_capacity(rubin_consensus::BLOCK_HEADER_BYTES);
    header.extend_from_slice(&1u32.to_le_bytes());
    header.extend_from_slice(&prev_hash);
    header.extend_from_slice(&merkle_root);
    header.extend_from_slice(&1u64.to_le_bytes());
    header.extend_from_slice(&target);
    header.extend_from_slice(&nonce.to_le_bytes());

    let mut block = header;
    encode_compact_size(txs.len() as u64, &mut block);
    for tx in txs {
        block.extend_from_slice(tx);
    }
    block
}

pub fn tx_ids(tx_bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
    let (_, txid, wtxid, _) = parse_tx(tx_bytes).expect("parse tx");
    (txid, wtxid)
}

pub fn marshal_tx_expect(tx: &Tx) -> Vec<u8> {
    marshal_tx(tx).expect("marshal tx")
}

pub fn sign_input_witness(
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    kp: &Mldsa87Keypair,
) -> WitnessItem {
    let digest =
        sighash_v1_digest_with_type(tx, input_index, input_value, ZERO_CHAIN_ID, SIGHASH_ALL)
            .expect("sighash");
    let mut signature = kp.sign_digest32(digest).expect("sign");
    signature.push(SIGHASH_ALL);
    WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: kp.pubkey_bytes(),
        signature,
    }
}

pub fn p2pk_covdata_for_keypair(kp: &Mldsa87Keypair) -> Vec<u8> {
    p2pk_covenant_data_for_pubkey(&kp.pubkey_bytes())
}

pub fn coinbase_with_witness_commitment(
    locktime: u32,
    outputs: &[TestOutput],
    non_coinbase_txs: &[Vec<u8>],
) -> Vec<u8> {
    let mut wtxids = Vec::with_capacity(1 + non_coinbase_txs.len());
    wtxids.push([0u8; 32]);
    for tx_bytes in non_coinbase_txs {
        let (_, wtxid) = tx_ids(tx_bytes);
        wtxids.push(wtxid);
    }

    let wroot = witness_merkle_root_wtxids(&wtxids).expect("witness merkle root");
    let commit = witness_commitment_hash(wroot);

    let mut all_outputs = outputs.to_vec();
    all_outputs.push(TestOutput {
        value: 0,
        covenant_type: COV_TYPE_ANCHOR,
        covenant_data: commit.to_vec(),
    });

    coinbase_tx_with_outputs(locktime, &all_outputs)
}

pub fn coinbase_with_witness_commitment_and_p2pk_value(
    locktime: u32,
    value: u64,
    non_coinbase_txs: &[Vec<u8>],
    payout_covdata: Vec<u8>,
) -> Vec<u8> {
    coinbase_with_witness_commitment(
        locktime,
        &[TestOutput {
            value,
            covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
            covenant_data: payout_covdata,
        }],
        non_coinbase_txs,
    )
}

pub fn block_merkle_root(txs: &[Vec<u8>]) -> [u8; 32] {
    let txids = txs
        .iter()
        .map(|tx_bytes| tx_ids(tx_bytes).0)
        .collect::<Vec<_>>();
    merkle_root_txids(&txids).expect("merkle root")
}

pub fn subsidy_with_fees(height: u64, fees: u64) -> u64 {
    block_subsidy(height, 0) + fees
}

fn coinbase_tx_with_outputs(locktime: u32, outputs: &[TestOutput]) -> Vec<u8> {
    let tx = Tx {
        version: TX_WIRE_VERSION,
        tx_kind: 0x00,
        tx_nonce: 0,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_vout: u32::MAX,
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: outputs
            .iter()
            .map(|output| TxOutput {
                value: output.value,
                covenant_type: output.covenant_type,
                covenant_data: output.covenant_data.clone(),
            })
            .collect(),
        locktime,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: Vec::new(),
    };
    marshal_tx_expect(&tx)
}
