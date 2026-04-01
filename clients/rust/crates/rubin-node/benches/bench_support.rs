use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rubin_consensus::constants::POW_LIMIT;
use rubin_consensus::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
use rubin_consensus::{
    encode_compact_size, marshal_tx, merkle_root_txids, p2pk_covenant_data_for_pubkey, parse_tx,
    sign_transaction, Mldsa87Keypair, Outpoint, Tx, TxInput, TxOutput, UtxoEntry,
    BLOCK_HEADER_BYTES,
};
use rubin_node::undo::{build_block_undo, BlockUndo};
use rubin_node::{
    block_store_path, build_coinbase_tx, chain_state_path, default_mine_address,
    default_sync_config, devnet_genesis_block_bytes, devnet_genesis_chain_id, BlockStore,
    ChainState, SyncEngine, TxPool,
};

#[allow(dead_code)]
pub const RUNTIME_BASELINE_BENCH_COMMAND: &str =
    "cargo bench --manifest-path clients/rust/Cargo.toml -p rubin-node --bench runtime_baseline -- --noplot --sample-size 10 --measurement-time 2";
pub const RUNTIME_BASELINE_TXPOOL_GROUP: &str = "rubin_node_txpool";
pub const RUNTIME_BASELINE_TXPOOL_ADMIT: &str = "admit";
pub const RUNTIME_BASELINE_TXPOOL_RELAY_METADATA: &str = "relay_metadata";
pub const RUNTIME_BASELINE_CHAINSTATE_CLONE: &str = "rubin_node_chainstate_clone";
pub const RUNTIME_BASELINE_SYNC_SNAPSHOT: &str = "rubin_node_sync_chain_state_snapshot";
pub const RUNTIME_BASELINE_SYNC_GROUP: &str = "rubin_node_sync";
pub const RUNTIME_BASELINE_SYNC_APPLY_GENESIS: &str = "apply_genesis";
pub const RUNTIME_BASELINE_SYNC_DISCONNECT_TIP: &str = "disconnect_tip_after_genesis";
pub const RUNTIME_BASELINE_UNDO_GROUP: &str = "rubin_node_undo";
pub const RUNTIME_BASELINE_UNDO_BUILD_LARGE_BLOCK: &str = "build_large_block";
pub const RUNTIME_BASELINE_UNDO_DISCONNECT_LARGE_BLOCK: &str = "disconnect_large_block";
pub const RUNTIME_BASELINE_MINER_MINE_ONE: &str = "rubin_node_miner_mine_one";
#[allow(dead_code)]
pub const RUNTIME_BASELINE_EVIDENCE_TARGETS: &[&str] = &[
    "rubin_node_txpool/admit",
    "rubin_node_txpool/relay_metadata",
    "rubin_node_chainstate_clone",
    "rubin_node_sync_chain_state_snapshot",
    "rubin_node_sync/apply_genesis",
    "rubin_node_sync/disconnect_tip_after_genesis",
    "rubin_node_undo/build_large_block",
    "rubin_node_undo/disconnect_large_block",
    "rubin_node_miner_mine_one",
];

const BENCH_BLOCK_TIMESTAMP: u64 = 1_777_000_123;
const BENCH_UTXO_COUNT: usize = 4096;
const BENCH_SPEND_COUNT: usize = 256;
#[allow(dead_code)]
const TEST_UTXO_COUNT: usize = 512;
#[allow(dead_code)]
const TEST_SPEND_COUNT: usize = 32;

pub fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

pub struct SyncFixture {
    pub dir: PathBuf,
    pub store: BlockStore,
    pub engine: SyncEngine,
}

#[derive(Clone)]
pub struct UndoBenchmarkFixture {
    pub prev_state: ChainState,
    pub connected_state: ChainState,
    pub block_bytes: Vec<u8>,
    pub block_height: u64,
    pub undo: BlockUndo,
}

impl SyncFixture {
    pub fn cleanup(self) {
        let SyncFixture { dir, store, engine } = self;
        drop(engine);
        drop(store);
        std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
    }
}

fn build_block_bytes(
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

fn block_with_txs(
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
    let (_tx, coinbase_txid, _wtxid, consumed) = parse_tx(&coinbase).expect("parse coinbase");
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

fn bench_prev_timestamps() -> Vec<u64> {
    vec![BENCH_BLOCK_TIMESTAMP.saturating_sub(60); 11]
}

pub fn chain_state_with_spendable_utxos(
    count: usize,
) -> (ChainState, Vec<Outpoint>, Mldsa87Keypair, Vec<u8>) {
    let keypair = Mldsa87Keypair::generate().expect("OpenSSL signer unavailable");
    let from_address = p2pk_covenant_data_for_pubkey(&keypair.pubkey_bytes());
    let mut state = ChainState::new();
    state.has_tip = true;
    state.height = 100;
    state.tip_hash[0] = 0x11;

    let mut outpoints = Vec::with_capacity(count);
    for i in 0..count {
        let mut txid = [0u8; 32];
        txid[0] = (i as u8).wrapping_add(1);
        txid[31] = (i as u8).wrapping_add(9);
        let outpoint = Outpoint {
            txid,
            vout: i as u32,
        };
        state.utxos.insert(
            outpoint.clone(),
            UtxoEntry {
                value: 100 + i as u64,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: from_address.clone(),
                creation_height: 1,
                created_by_coinbase: true,
            },
        );
        outpoints.push(outpoint);
    }
    (state, outpoints, keypair, from_address)
}

pub struct SignedTransferSpec<'a> {
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    pub change_address: &'a [u8],
    pub to_address: &'a [u8],
}

pub fn signed_transfer_tx(
    state: &ChainState,
    inputs: &[Outpoint],
    signer: &Mldsa87Keypair,
    spec: SignedTransferSpec<'_>,
) -> Vec<u8> {
    let mut tx_inputs = Vec::with_capacity(inputs.len());
    let mut total_in = 0u64;
    for op in inputs {
        let entry = state.utxos.get(op).expect("missing utxo");
        total_in = total_in.saturating_add(entry.value);
        tx_inputs.push(TxInput {
            prev_txid: op.txid,
            prev_vout: op.vout,
            script_sig: Vec::new(),
            sequence: 0,
        });
    }
    let mut outputs = vec![TxOutput {
        value: spec.amount,
        covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
        covenant_data: spec.to_address.to_vec(),
    }];
    let change = total_in
        .checked_sub(spec.amount)
        .and_then(|v| v.checked_sub(spec.fee))
        .expect("valid change");
    if change > 0 {
        outputs.push(TxOutput {
            value: change,
            covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
            covenant_data: spec.change_address.to_vec(),
        });
    }

    let mut tx = Tx {
        version: rubin_consensus::constants::TX_WIRE_VERSION,
        tx_kind: 0x00,
        tx_nonce: spec.nonce,
        inputs: tx_inputs,
        outputs,
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: Vec::new(),
    };
    sign_transaction(&mut tx, &state.utxos, devnet_genesis_chain_id(), signer).expect("sign tx");
    marshal_tx(&tx).expect("marshal tx")
}

pub fn fresh_sync_engine(prefix: &str) -> SyncFixture {
    let dir = unique_temp_dir(prefix);
    let chain_state_file = chain_state_path(&dir);
    let block_store = BlockStore::open(block_store_path(&dir)).expect("open block store");
    let chain_state = ChainState::new();
    chain_state
        .save(&chain_state_file)
        .expect("save chainstate");
    let sync = SyncEngine::new(
        chain_state,
        Some(block_store.clone()),
        default_sync_config(None, devnet_genesis_chain_id(), Some(chain_state_file)),
    )
    .expect("new sync engine");
    SyncFixture {
        dir,
        store: block_store,
        engine: sync,
    }
}

pub fn engine_after_genesis(prefix: &str) -> SyncFixture {
    let mut fixture = fresh_sync_engine(prefix);
    fixture
        .engine
        .apply_block(&devnet_genesis_block_bytes(), None)
        .expect("apply genesis");
    fixture
}

pub fn fresh_txpool_fixture() -> (ChainState, Vec<u8>) {
    let (state, outpoints, signer, from_address) = chain_state_with_spendable_utxos(1);
    let to_signer = Mldsa87Keypair::generate().expect("OpenSSL signer unavailable");
    let to_address = p2pk_covenant_data_for_pubkey(&to_signer.pubkey_bytes());
    let raw = signed_transfer_tx(
        &state,
        &[outpoints[0].clone()],
        &signer,
        SignedTransferSpec {
            amount: 90,
            fee: 1,
            nonce: 1,
            change_address: &from_address,
            to_address: &to_address,
        },
    );
    (state, raw)
}

pub fn fresh_pool() -> TxPool {
    TxPool::new()
}

fn block_undo_fixture(utxo_count: usize, spend_count: usize) -> UndoBenchmarkFixture {
    let (prev_state, outpoints, signer, from_address) =
        chain_state_with_spendable_utxos(utxo_count);
    let to_signer = Mldsa87Keypair::generate().expect("OpenSSL signer unavailable");
    let to_address = p2pk_covenant_data_for_pubkey(&to_signer.pubkey_bytes());
    let spend_txs: Vec<Vec<u8>> = outpoints
        .iter()
        .take(spend_count)
        .enumerate()
        .map(|(nonce, outpoint)| {
            signed_transfer_tx(
                &prev_state,
                std::slice::from_ref(outpoint),
                &signer,
                SignedTransferSpec {
                    amount: 50,
                    fee: 1,
                    nonce: (nonce as u64) + 1,
                    change_address: &from_address,
                    to_address: &to_address,
                },
            )
        })
        .collect();
    let block_height = prev_state.height + 1;
    let block_bytes = block_with_txs(
        block_height,
        prev_state.already_generated,
        prev_state.tip_hash,
        BENCH_BLOCK_TIMESTAMP,
        &spend_txs,
    );
    let undo = build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");
    let mut connected_state = prev_state.clone();
    connected_state
        .connect_block(
            &block_bytes,
            Some(POW_LIMIT),
            Some(&bench_prev_timestamps()),
            devnet_genesis_chain_id(),
        )
        .expect("connect block");

    UndoBenchmarkFixture {
        prev_state,
        connected_state,
        block_bytes,
        block_height,
        undo,
    }
}

pub fn large_block_undo_fixture() -> UndoBenchmarkFixture {
    block_undo_fixture(BENCH_UTXO_COUNT, BENCH_SPEND_COUNT)
}

#[allow(dead_code)]
pub fn test_block_undo_fixture() -> UndoBenchmarkFixture {
    block_undo_fixture(TEST_UTXO_COUNT, TEST_SPEND_COUNT)
}
