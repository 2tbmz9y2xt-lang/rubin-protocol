use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rubin_consensus::{
    marshal_tx, p2pk_covenant_data_for_pubkey, sign_transaction, Mldsa87Keypair, Outpoint, Tx,
    TxInput, TxOutput, UtxoEntry,
};
use rubin_node::{
    block_store_path, chain_state_path, default_sync_config, devnet_genesis_block_bytes,
    devnet_genesis_chain_id, BlockStore, ChainState, SyncEngine, TxPool,
};

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

impl SyncFixture {
    pub fn cleanup(self) {
        let SyncFixture { dir, store, engine } = self;
        drop(engine);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }
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
