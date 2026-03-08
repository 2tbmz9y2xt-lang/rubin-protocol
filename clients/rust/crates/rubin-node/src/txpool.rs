use std::collections::HashMap;

use rubin_consensus::{
    apply_non_coinbase_tx_basic_with_mtp, parse_block_header_bytes, parse_tx, Outpoint,
};

use crate::{BlockStore, ChainState};

const MAX_TX_POOL_TRANSACTIONS: usize = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxPoolEntry {
    pub raw: Vec<u8>,
    pub inputs: Vec<Outpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxPool {
    txs: HashMap<[u8; 32], TxPoolEntry>,
    spenders: HashMap<Outpoint, [u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxPoolAdmitErrorKind {
    Conflict,
    Rejected,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxPoolAdmitError {
    pub kind: TxPoolAdmitErrorKind,
    pub message: String,
}

impl std::fmt::Display for TxPoolAdmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TxPoolAdmitError {}

impl TxPool {
    pub fn new() -> Self {
        Self {
            txs: HashMap::new(),
            spenders: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn admit(
        &mut self,
        tx_bytes: &[u8],
        chain_state: &ChainState,
        block_store: Option<&BlockStore>,
        chain_id: [u8; 32],
    ) -> Result<[u8; 32], TxPoolAdmitError> {
        let (tx, txid, _wtxid, consumed) =
            parse_tx(tx_bytes).map_err(|err| rejected(format!("transaction rejected: {err}")))?;
        if consumed != tx_bytes.len() {
            return Err(rejected("transaction rejected: non-canonical tx bytes"));
        }
        if self.txs.contains_key(&txid) {
            return Err(conflict("tx already in mempool"));
        }
        if self.txs.len() >= MAX_TX_POOL_TRANSACTIONS {
            return Err(unavailable("tx pool full"));
        }

        let inputs: Vec<Outpoint> = tx
            .inputs
            .iter()
            .map(|input| Outpoint {
                txid: input.prev_txid,
                vout: input.prev_vout,
            })
            .collect();
        for input in &inputs {
            if let Some(existing) = self.spenders.get(input) {
                return Err(conflict(format!(
                    "mempool double-spend conflict with {}",
                    hex::encode(existing)
                )));
            }
        }

        let next_height = next_block_height(chain_state)?;
        let block_mtp = next_block_mtp(block_store, next_height)?;
        apply_non_coinbase_tx_basic_with_mtp(
            &tx,
            txid,
            &chain_state.utxos,
            next_height,
            block_mtp,
            block_mtp,
            chain_id,
        )
        .map_err(|err| rejected(format!("transaction rejected: {err}")))?;

        self.txs.insert(
            txid,
            TxPoolEntry {
                raw: tx_bytes.to_vec(),
                inputs: inputs.clone(),
            },
        );
        for input in inputs {
            self.spenders.insert(input, txid);
        }
        Ok(txid)
    }
}

impl Default for TxPool {
    fn default() -> Self {
        Self::new()
    }
}

fn next_block_height(chain_state: &ChainState) -> Result<u64, TxPoolAdmitError> {
    if !chain_state.has_tip {
        return Ok(0);
    }
    if chain_state.height == u64::MAX {
        return Err(unavailable("height overflow"));
    }
    Ok(chain_state.height + 1)
}

fn next_block_mtp(
    block_store: Option<&BlockStore>,
    next_height: u64,
) -> Result<u64, TxPoolAdmitError> {
    let Some(block_store) = block_store else {
        return Ok(0);
    };
    if next_height == 0 {
        return Ok(0);
    }
    let mut window_len = 11u64;
    if next_height < window_len {
        window_len = next_height;
    }
    let mut out = Vec::with_capacity(window_len as usize);
    for idx in 0..window_len {
        let height = next_height - 1 - idx;
        let Some(hash) = block_store
            .canonical_hash(height)
            .map_err(|err| unavailable(err.to_string()))?
        else {
            return Err(unavailable(
                "missing canonical header for timestamp context",
            ));
        };
        let header_bytes = block_store
            .get_header_by_hash(hash)
            .map_err(|err| unavailable(err.to_string()))?;
        let header =
            parse_block_header_bytes(&header_bytes).map_err(|err| unavailable(err.to_string()))?;
        out.push(header.timestamp);
    }
    Ok(mtp_median(next_height, &out))
}

fn mtp_median(next_height: u64, prev_timestamps: &[u64]) -> u64 {
    let mut window_len = 11usize;
    if next_height < window_len as u64 {
        window_len = next_height as usize;
    }
    if prev_timestamps.len() < window_len {
        if prev_timestamps.is_empty() {
            return 0;
        }
        window_len = prev_timestamps.len();
    }
    let mut window = prev_timestamps[..window_len].to_vec();
    window.sort_unstable();
    window[(window.len() - 1) / 2]
}

fn conflict(message: impl Into<String>) -> TxPoolAdmitError {
    TxPoolAdmitError {
        kind: TxPoolAdmitErrorKind::Conflict,
        message: message.into(),
    }
}

fn rejected(message: impl Into<String>) -> TxPoolAdmitError {
    TxPoolAdmitError {
        kind: TxPoolAdmitErrorKind::Rejected,
        message: message.into(),
    }
}

fn unavailable(message: impl Into<String>) -> TxPoolAdmitError {
    TxPoolAdmitError {
        kind: TxPoolAdmitErrorKind::Unavailable,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;

    use rubin_consensus::block::BLOCK_HEADER_BYTES;
    use rubin_consensus::{parse_tx, Outpoint, UtxoEntry};

    use super::{
        conflict, mtp_median, next_block_height, next_block_mtp, rejected, unavailable, TxPool,
        TxPoolAdmitErrorKind, TxPoolEntry, MAX_TX_POOL_TRANSACTIONS,
    };
    use crate::{
        block_store_path, default_sync_config, devnet_genesis_block_bytes, devnet_genesis_chain_id,
        BlockStore, ChainState, SyncEngine,
    };

    #[derive(serde::Deserialize)]
    struct FixtureFile<T> {
        vectors: Vec<T>,
    }

    #[derive(serde::Deserialize)]
    struct MaturityVector {
        tx_hex: String,
    }

    #[derive(Clone, serde::Deserialize)]
    struct FixtureUtxo {
        txid: String,
        vout: u32,
        value: u64,
        covenant_type: u16,
        covenant_data: String,
        creation_height: u64,
        created_by_coinbase: bool,
    }

    #[derive(Clone, serde::Deserialize)]
    struct PositiveTxVector {
        id: String,
        tx_hex: String,
        #[serde(default)]
        chain_id: Option<String>,
        height: u64,
        expect_ok: bool,
        utxos: Vec<FixtureUtxo>,
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    fn open_block_store(prefix: &str) -> (BlockStore, PathBuf) {
        let dir = unique_temp_dir(prefix);
        fs::create_dir_all(&dir).expect("mkdir");
        let store = BlockStore::open(block_store_path(&dir)).expect("blockstore");
        (store, dir)
    }

    fn genesis_coinbase_bytes() -> Vec<u8> {
        let block = devnet_genesis_block_bytes();
        assert_eq!(
            block[BLOCK_HEADER_BYTES], 0x01,
            "expected single-tx genesis fixture"
        );
        let tx_start = BLOCK_HEADER_BYTES + 1;
        let (_tx, _txid, _wtxid, consumed) = parse_tx(&block[tx_start..]).expect("parse tx");
        block[tx_start..tx_start + consumed].to_vec()
    }

    fn maturity_fixture_tx_bytes() -> Vec<u8> {
        const DEVNET_MATURITY_FIXTURE_JSON: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../conformance/fixtures/CV-DEVNET-MATURITY.json"
        ));
        let fixture: FixtureFile<MaturityVector> =
            serde_json::from_str(DEVNET_MATURITY_FIXTURE_JSON).expect("parse fixture");
        let vector = fixture.vectors.into_iter().next().expect("fixture vector");
        hex::decode(vector.tx_hex).expect("tx hex")
    }

    fn parse_hex32_test(name: &str, value: &str) -> [u8; 32] {
        let raw = hex::decode(value).unwrap_or_else(|err| panic!("{name} hex: {err}"));
        assert_eq!(raw.len(), 32, "{name} must be 32 bytes");
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        out
    }

    fn fixture_utxos_to_map(items: &[FixtureUtxo]) -> HashMap<Outpoint, UtxoEntry> {
        let mut out = HashMap::with_capacity(items.len());
        for item in items {
            out.insert(
                Outpoint {
                    txid: parse_hex32_test("fixture utxo txid", &item.txid),
                    vout: item.vout,
                },
                UtxoEntry {
                    value: item.value,
                    covenant_type: item.covenant_type,
                    covenant_data: hex::decode(&item.covenant_data)
                        .expect("fixture covenant_data hex"),
                    creation_height: item.creation_height,
                    created_by_coinbase: item.created_by_coinbase,
                },
            );
        }
        out
    }

    fn positive_fixture_vector() -> PositiveTxVector {
        const UTXO_BASIC_FIXTURE_JSON: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../conformance/fixtures/CV-UTXO-BASIC.json"
        ));
        let fixture: FixtureFile<PositiveTxVector> =
            serde_json::from_str(UTXO_BASIC_FIXTURE_JSON).expect("parse positive fixture");
        fixture
            .vectors
            .into_iter()
            .find(|vector| vector.id == "CV-U-06")
            .expect("positive fixture vector")
    }

    fn fixture_chain_id(chain_id: Option<&str>) -> [u8; 32] {
        chain_id
            .map(|value| parse_hex32_test("chain_id", value))
            .unwrap_or([0u8; 32])
    }

    fn chain_state_from_positive_fixture(vector: &PositiveTxVector) -> ChainState {
        let mut state = ChainState::new();
        state.has_tip = vector.height > 0;
        state.height = vector.height.saturating_sub(1);
        state.utxos = fixture_utxos_to_map(&vector.utxos);
        state
    }

    #[test]
    fn mtp_median_uses_sorted_middle_of_window() {
        let got = mtp_median(5, &[9, 3, 5, 1, 7]);
        assert_eq!(got, 5);
    }

    #[test]
    fn mtp_median_uses_available_history_when_window_is_short() {
        assert_eq!(mtp_median(3, &[9]), 9);
    }

    #[test]
    fn admit_rejects_parse_errors() {
        let mut pool = TxPool::new();
        let err = pool
            .admit(&[], &ChainState::new(), None, [0u8; 32])
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Rejected);
        assert!(err.message.contains("transaction rejected"));
    }

    #[test]
    fn admit_accepts_valid_conformance_tx() {
        let vector = positive_fixture_vector();
        assert!(vector.expect_ok, "{} should be positive fixture", vector.id);
        let raw = hex::decode(&vector.tx_hex).expect("tx hex");
        let (tx, txid, _wtxid, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len(), "{}", vector.id);

        let state = chain_state_from_positive_fixture(&vector);
        let mut pool = TxPool::new();
        let admitted = pool
            .admit(
                &raw,
                &state,
                None,
                fixture_chain_id(vector.chain_id.as_deref()),
            )
            .expect("admit valid tx");

        assert_eq!(admitted, txid);
        assert_eq!(pool.len(), 1);
        let entry = pool.txs.get(&txid).expect("pool entry");
        assert_eq!(entry.raw, raw);
        assert_eq!(entry.inputs.len(), tx.inputs.len());
        for input in &tx.inputs {
            let outpoint = Outpoint {
                txid: input.prev_txid,
                vout: input.prev_vout,
            };
            assert_eq!(pool.spenders.get(&outpoint), Some(&txid));
        }
    }

    #[test]
    fn new_pool_starts_empty() {
        let pool = TxPool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn default_impl_matches_empty_pool() {
        let pool = TxPool::default();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn next_block_height_handles_tip_states() {
        assert_eq!(next_block_height(&ChainState::new()).expect("height"), 0);

        let mut state = ChainState::new();
        state.has_tip = true;
        state.height = 7;
        assert_eq!(next_block_height(&state).expect("height"), 8);

        state.height = u64::MAX;
        let err = next_block_height(&state).unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(err.message.contains("height overflow"));
    }

    #[test]
    fn next_block_mtp_handles_missing_store_context() {
        assert_eq!(next_block_mtp(None, 0).expect("mtp"), 0);

        let (store, dir) = open_block_store("rubin-txpool-mtp");
        assert_eq!(next_block_mtp(Some(&store), 0).expect("mtp"), 0);
        let err = next_block_mtp(Some(&store), 1).unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(err.message.contains("missing canonical header"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn next_block_mtp_reads_timestamp_context_from_store() {
        let (store, dir) = open_block_store("rubin-txpool-mtp-success");
        let mut engine = SyncEngine::new(
            ChainState::new(),
            Some(store.clone()),
            default_sync_config(None, devnet_genesis_chain_id(), None),
        )
        .expect("sync");
        engine
            .apply_block(&devnet_genesis_block_bytes(), None)
            .expect("apply genesis");
        let reopened = BlockStore::open(block_store_path(&dir)).expect("reopen");
        assert!(next_block_mtp(Some(&reopened), 1).expect("mtp") > 0);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn admit_rejects_duplicate_txid() {
        let raw = genesis_coinbase_bytes();
        let (_tx, txid, _wtxid, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len());

        let mut pool = TxPool::new();
        pool.txs.insert(
            txid,
            TxPoolEntry {
                raw: raw.clone(),
                inputs: Vec::new(),
            },
        );
        let err = pool
            .admit(&raw, &ChainState::new(), None, devnet_genesis_chain_id())
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Conflict);
        assert!(err.message.contains("already in mempool"));
    }

    #[test]
    fn admit_rejects_non_canonical_trailing_bytes() {
        let mut raw = genesis_coinbase_bytes();
        raw.push(0x00);
        let err = TxPool::new()
            .admit(&raw, &ChainState::new(), None, devnet_genesis_chain_id())
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Rejected);
        assert!(err.message.contains("non-canonical tx bytes"));
    }

    #[test]
    fn admit_rejects_pool_full() {
        let raw = genesis_coinbase_bytes();
        let (_tx, txid, _wtxid, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len());

        let mut pool = TxPool::new();
        for idx in 0..MAX_TX_POOL_TRANSACTIONS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(idx as u64 + 1).to_le_bytes());
            if key == txid {
                key[8] = 1;
            }
            pool.txs.insert(
                key,
                TxPoolEntry {
                    raw: Vec::new(),
                    inputs: Vec::new(),
                },
            );
        }
        let err = pool
            .admit(&raw, &ChainState::new(), None, devnet_genesis_chain_id())
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(err.message.contains("tx pool full"));
    }

    #[test]
    fn admit_rejects_mempool_input_conflict() {
        let raw = maturity_fixture_tx_bytes();
        let (tx, _txid, _wtxid, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len());
        let first = tx.inputs.first().expect("fixture input");

        let mut pool = TxPool::new();
        pool.spenders.insert(
            rubin_consensus::Outpoint {
                txid: first.prev_txid,
                vout: first.prev_vout,
            },
            [0xabu8; 32],
        );
        let err = pool
            .admit(&raw, &ChainState::new(), None, devnet_genesis_chain_id())
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Conflict);
        assert!(err.message.contains("double-spend conflict"));
    }

    #[test]
    fn admit_reports_unavailable_on_height_overflow() {
        let raw = genesis_coinbase_bytes();
        let mut state = ChainState::new();
        state.has_tip = true;
        state.height = u64::MAX;

        let err = TxPool::new()
            .admit(&raw, &state, None, devnet_genesis_chain_id())
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(err.message.contains("height overflow"));
    }

    #[test]
    fn admit_reports_unavailable_when_timestamp_context_missing() {
        let raw = genesis_coinbase_bytes();
        let mut state = ChainState::new();
        state.has_tip = true;
        state.height = 0;

        let (store, dir) = open_block_store("rubin-txpool-admit-mtp");
        let err = TxPool::new()
            .admit(&raw, &state, Some(&store), devnet_genesis_chain_id())
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(err.message.contains("missing canonical header"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn admit_reports_unavailable_when_header_lookup_fails() {
        let vector = positive_fixture_vector();
        let raw = hex::decode(&vector.tx_hex).expect("tx hex");
        let mut state = chain_state_from_positive_fixture(&vector);
        state.has_tip = true;
        state.height = 0;

        let (mut store, dir) = open_block_store("rubin-txpool-admit-header-read");
        store
            .set_canonical_tip(0, [0x42; 32])
            .expect("set canonical tip");

        let err = TxPool::new()
            .admit(
                &raw,
                &state,
                Some(&store),
                fixture_chain_id(vector.chain_id.as_deref()),
            )
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert!(err.message.contains("read header"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn admit_rejects_coinbase_semantics_as_non_coinbase() {
        let raw = genesis_coinbase_bytes();
        let err = TxPool::new()
            .admit(&raw, &ChainState::new(), None, devnet_genesis_chain_id())
            .unwrap_err();
        assert_eq!(err.kind, TxPoolAdmitErrorKind::Rejected);
        assert!(err.message.contains("transaction rejected"));
    }

    #[test]
    fn helper_errors_preserve_kind_and_message() {
        let conflict_err = conflict("conflict");
        assert_eq!(conflict_err.kind, TxPoolAdmitErrorKind::Conflict);
        assert_eq!(conflict_err.to_string(), "conflict");

        let rejected_err = rejected("rejected");
        assert_eq!(rejected_err.kind, TxPoolAdmitErrorKind::Rejected);
        assert_eq!(rejected_err.to_string(), "rejected");

        let unavailable_err = unavailable("unavailable");
        assert_eq!(unavailable_err.kind, TxPoolAdmitErrorKind::Unavailable);
        assert_eq!(unavailable_err.to_string(), "unavailable");
    }
}
