use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use rubin_consensus::{
    block_hash,
    connect_block_basic_in_memory_at_height_and_core_ext_deployments_with_suite_context,
    encode_compact_size, parse_block_bytes, ConnectBlockBasicSummary, CoreExtDeploymentProfiles,
    InMemoryChainState, Outpoint, RotationProvider, SuiteRegistry, UtxoEntry,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::genesis::validate_incoming_chain_id;
use crate::io_utils::{parse_hex32, write_file_atomic};

pub const CHAIN_STATE_FILE_NAME: &str = "chainstate.json";
const CHAIN_STATE_DISK_VERSION: u32 = 1;
pub const UTXO_SET_HASH_DST: &[u8] = b"RUBINv1-utxo-set-hash/";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainState {
    pub has_tip: bool,
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub already_generated: u64,
    pub utxos: HashMap<Outpoint, UtxoEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainStateConnectSummary {
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub sum_fees: u64,
    pub already_generated: u64,
    pub already_generated_n1: u64,
    pub utxo_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainStateDisk {
    version: u32,
    has_tip: bool,
    height: u64,
    tip_hash: String,
    already_generated: u64,
    utxos: Vec<UtxoDiskEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UtxoDiskEntry {
    txid: String,
    vout: u32,
    value: u64,
    covenant_type: u16,
    covenant_data: String,
    creation_height: u64,
    created_by_coinbase: bool,
}

impl ChainState {
    pub fn new() -> Self {
        Self {
            has_tip: false,
            height: 0,
            tip_hash: [0u8; 32],
            already_generated: 0,
            utxos: HashMap::new(),
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let path = path.as_ref();
        let disk = state_to_disk(self)?;
        let mut raw =
            serde_json::to_vec_pretty(&disk).map_err(|e| format!("encode chainstate: {e}"))?;
        raw.push(b'\n');
        // Parent creation is delegated to `write_file_atomic`, which
        // runs `fs::create_dir_all(effective_parent(path))` on the
        // actual write target. `effective_parent` maps a bare-filename
        // input (`Path::new("chainstate.json").parent() == Some("")`)
        // to `Some(".")` so the `create_dir_all` call always receives
        // a non-empty directory. Running an explicit
        // `fs::create_dir_all(path.parent())` here — as an earlier
        // version did — instead passed `""` to `create_dir_all` on
        // bare-filename callers and failed with an I/O error; this
        // helper's own `effective_parent` is the correct layer.
        //
        // Raw `write_file_atomic`. Paired with `load_chain_state`'s
        // raw `fs::read` — both use the caller-supplied path
        // directly, with no per-helper `lexical_clean` step.
        //
        // For the node binary, `path` originates from
        // `chain_state_path(cfg.data_dir)` after `cfg.data_dir` was
        // cleaned at the CLI parse site, so the startup read and
        // every subsequent save land on one on-disk file even for
        // operator `--data-dir` values that cross a symlink
        // combined with `..`. Other callers of `ChainState::save`
        // are responsible for their own path hygiene — see
        // `load_chain_state` for the mirror note.
        write_file_atomic(path, &raw)
    }

    pub fn connect_block(
        &mut self,
        block_bytes: &[u8],
        expected_target: Option<[u8; 32]>,
        prev_timestamps: Option<&[u64]>,
        chain_id: [u8; 32],
    ) -> Result<ChainStateConnectSummary, String> {
        self.connect_block_with_core_ext_deployments(
            block_bytes,
            expected_target,
            prev_timestamps,
            chain_id,
            &CoreExtDeploymentProfiles::empty(),
        )
    }

    pub fn connect_block_with_core_ext_deployments(
        &mut self,
        block_bytes: &[u8],
        expected_target: Option<[u8; 32]>,
        prev_timestamps: Option<&[u64]>,
        chain_id: [u8; 32],
        core_ext_deployments: &CoreExtDeploymentProfiles,
    ) -> Result<ChainStateConnectSummary, String> {
        self.connect_block_with_core_ext_deployments_and_suite_context(
            block_bytes,
            expected_target,
            prev_timestamps,
            chain_id,
            core_ext_deployments,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn connect_block_with_core_ext_deployments_and_suite_context(
        &mut self,
        block_bytes: &[u8],
        expected_target: Option<[u8; 32]>,
        prev_timestamps: Option<&[u64]>,
        chain_id: [u8; 32],
        core_ext_deployments: &CoreExtDeploymentProfiles,
        rotation: Option<&dyn RotationProvider>,
        registry: Option<&SuiteRegistry>,
    ) -> Result<ChainStateConnectSummary, String> {
        let (block_height, expected_prev_hash) = self.next_block_context()?;
        validate_incoming_chain_id(block_height, chain_id)?;
        let mut work_state = InMemoryChainState {
            utxos: copy_utxo_set(&self.utxos),
            already_generated: u128::from(self.already_generated),
        };

        let connect_summary: ConnectBlockBasicSummary =
            connect_block_basic_in_memory_at_height_and_core_ext_deployments_with_suite_context(
                block_bytes,
                expected_prev_hash,
                expected_target,
                block_height,
                prev_timestamps,
                &mut work_state,
                chain_id,
                core_ext_deployments,
                rotation,
                registry,
            )
            .map_err(|e| e.to_string())?;

        let parsed = parse_block_bytes(block_bytes).map_err(|e| e.to_string())?;
        let tip_hash = block_hash(&parsed.header_bytes).map_err(|e| e.to_string())?;

        self.has_tip = true;
        self.height = block_height;
        self.tip_hash = tip_hash;
        self.already_generated = u64::try_from(work_state.already_generated)
            .map_err(|_| "already_generated overflow".to_string())?;
        self.utxos = work_state.utxos;

        Ok(ChainStateConnectSummary {
            block_height,
            block_hash: tip_hash,
            sum_fees: connect_summary.sum_fees,
            already_generated: u64::try_from(connect_summary.already_generated)
                .map_err(|_| "already_generated overflow".to_string())?,
            already_generated_n1: u64::try_from(connect_summary.already_generated_n1)
                .map_err(|_| "already_generated_n1 overflow".to_string())?,
            utxo_count: connect_summary.utxo_count,
        })
    }

    pub fn utxo_set_hash(&self) -> [u8; 32] {
        utxo_set_hash(&self.utxos)
    }

    pub fn state_digest(&self) -> [u8; 32] {
        self.utxo_set_hash()
    }

    /// Defensive-copy read path for a single UTXO entry. Mirrors the Go twin
    /// `copyUtxoEntry` contract in `clients/go/node/chainstate.go`: callers
    /// receive an owned `UtxoEntry` whose mutation cannot reach the canonical
    /// `self.utxos` map. Returns `None` for missing outpoints.
    ///
    /// Prefer this read path for code that needs to mutate the returned entry
    /// or forward it across trust boundaries. Direct reads from `self.utxos`
    /// also exist (the field is `pub`), including read-only fast paths such as
    /// iteration in `utxo_set_hash` and `indexed_suite_ids`, but those callers
    /// do not get the defensive-copy guarantee provided by this method.
    pub fn lookup_utxo_owned(&self, outpoint: &Outpoint) -> Option<UtxoEntry> {
        self.utxos.get(outpoint).map(copy_utxo_entry)
    }

    /// Returns the sorted suite IDs that are explicitly bound in current UTXO
    /// covenant data. Today this covers explicit suite_id carriers such as
    /// CORE_P2PK outputs.
    pub fn indexed_suite_ids(&self) -> Vec<u8> {
        let mut ids = Vec::new();
        for entry in self.utxos.values() {
            if let Some(suite_id) = explicit_suite_id_for_utxo_entry(entry) {
                ids.push(suite_id);
            }
        }
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Returns deterministically sorted outpoints whose covenant data
    /// explicitly binds to suite_id.
    pub fn utxo_outpoints_by_suite_id(&self, suite_id: u8) -> Vec<Outpoint> {
        let mut outpoints = Vec::new();
        for (outpoint, entry) in &self.utxos {
            if utxo_entry_explicitly_uses_suite(entry, suite_id) {
                outpoints.push(outpoint.clone());
            }
        }
        outpoints.sort_by(|a, b| match a.txid.cmp(&b.txid) {
            Ordering::Equal => a.vout.cmp(&b.vout),
            other => other,
        });
        outpoints
    }

    /// Returns how many current UTXOs explicitly bind to suite_id.
    pub fn utxo_exposure_count_by_suite_id(&self, suite_id: u8) -> u64 {
        self.utxos
            .values()
            .filter(|entry| utxo_entry_explicitly_uses_suite(entry, suite_id))
            .count() as u64
    }

    fn next_block_context(&self) -> Result<(u64, Option<[u8; 32]>), String> {
        if !self.has_tip {
            return Ok((0, None));
        }
        if self.height == u64::MAX {
            return Err("height overflow".to_string());
        }
        Ok((self.height + 1, Some(self.tip_hash)))
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

/// Canonical deep-copy helper for a single UTXO entry. Mirrors the Go twin
/// `copyUtxoEntry` in `clients/go/node/chainstate.go`. Implemented in terms
/// of `entry.clone()` so future fields added to `UtxoEntry` are deep-copied
/// by construction (the derived `Clone` already deep-copies
/// `covenant_data: Vec<u8>`); the named helper preserves the explicit
/// defensive-copy intent at call sites and makes the contract greppable.
pub(crate) fn copy_utxo_entry(entry: &UtxoEntry) -> UtxoEntry {
    entry.clone()
}

/// Defensive deep-copy of a full UTXO set. Mirrors the Go twin `copyUtxoSet`.
/// Used by `connect_block_with_core_ext_deployments_and_suite_context` to
/// build the `work_state` replay map without sharing entries with the
/// canonical `ChainState.utxos` map. Implemented as `src.clone()` to avoid
/// a manual per-entry `insert` loop and preserve the source `HashMap`'s
/// hasher / configuration. The exact rehashing behaviour of `HashMap::clone`
/// is not a documented stdlib guarantee, so this comment makes only the
/// weaker claim — but in practice both `std` and `hashbrown` reuse the
/// existing layout, which is the implementation reason for picking
/// `src.clone()` over a hand-rolled re-insert.
pub(crate) fn copy_utxo_set(src: &HashMap<Outpoint, UtxoEntry>) -> HashMap<Outpoint, UtxoEntry> {
    src.clone()
}

pub fn chain_state_path<P: AsRef<Path>>(data_dir: P) -> PathBuf {
    data_dir.as_ref().join(CHAIN_STATE_FILE_NAME)
}

pub fn load_chain_state<P: AsRef<Path>>(path: P) -> Result<ChainState, String> {
    let path = path.as_ref();
    // Raw `fs::read` on a caller-supplied path. Mirrors the Go
    // `LoadChainState` reader in `clients/go/node/chainstate.go`,
    // which also uses a caller-supplied path directly.
    //
    // For the node binary's own call site, `path` originates from
    // `chain_state_path(cfg.data_dir)` after `cfg.data_dir` was
    // lexically cleaned at the CLI parse site (`normalize_data_dir`
    // in `main.rs`), so the startup read and subsequent
    // `ChainState::save` writes land on exactly one on-disk file
    // regardless of whether the operator `--data-dir` contained
    // symlink+`..` segments. Other callers of this public function
    // are responsible for their own path hygiene — this helper does
    // NOT canonicalise or sandbox its input.
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ChainState::new()),
        Err(e) => return Err(format!("read chainstate {}: {e}", path.display())),
    };
    let disk: ChainStateDisk = serde_json::from_slice(&raw)
        .map_err(|e| format!("parse chainstate {}: {e}", path.display()))?;
    chain_state_from_disk(disk)
}

fn state_to_disk(s: &ChainState) -> Result<ChainStateDisk, String> {
    let mut utxos: Vec<UtxoDiskEntry> = s
        .utxos
        .iter()
        .map(|(op, entry)| UtxoDiskEntry {
            txid: hex::encode(op.txid),
            vout: op.vout,
            value: entry.value,
            covenant_type: entry.covenant_type,
            covenant_data: hex::encode(&entry.covenant_data),
            creation_height: entry.creation_height,
            created_by_coinbase: entry.created_by_coinbase,
        })
        .collect();
    utxos.sort_by(|a, b| match a.txid.cmp(&b.txid) {
        Ordering::Equal => a.vout.cmp(&b.vout),
        other => other,
    });

    Ok(ChainStateDisk {
        version: CHAIN_STATE_DISK_VERSION,
        has_tip: s.has_tip,
        height: s.height,
        tip_hash: hex::encode(s.tip_hash),
        already_generated: s.already_generated,
        utxos,
    })
}

fn utxo_set_hash(utxos: &HashMap<Outpoint, UtxoEntry>) -> [u8; 32] {
    let mut items: Vec<([u8; 36], &UtxoEntry)> = Vec::with_capacity(utxos.len());
    for (outpoint, entry) in utxos {
        let mut key = [0u8; 36];
        key[..32].copy_from_slice(&outpoint.txid);
        key[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
        items.push((key, entry));
    }
    // sort_unstable_by avoids decorate/sort/undecorate copies of the
    // [u8; 36] key that sort_by_key/sort_unstable_by_key would do —
    // important on the consensus digest path with large UTXO sets.
    #[allow(clippy::unnecessary_sort_by)]
    items.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    let mut buf = Vec::with_capacity(UTXO_SET_HASH_DST.len() + 8 + items.len() * 64);
    buf.extend_from_slice(UTXO_SET_HASH_DST);
    buf.extend_from_slice(&(items.len() as u64).to_le_bytes());

    for (key, entry) in items {
        buf.extend_from_slice(&key);
        buf.extend_from_slice(&entry.value.to_le_bytes());
        buf.extend_from_slice(&entry.covenant_type.to_le_bytes());
        encode_compact_size(entry.covenant_data.len() as u64, &mut buf);
        buf.extend_from_slice(&entry.covenant_data);
        buf.extend_from_slice(&entry.creation_height.to_le_bytes());
        buf.push(u8::from(entry.created_by_coinbase));
    }

    Sha3_256::digest(&buf).into()
}

fn explicit_suite_id_for_utxo_entry(entry: &UtxoEntry) -> Option<u8> {
    match entry.covenant_type {
        rubin_consensus::constants::COV_TYPE_P2PK
            if entry.covenant_data.len()
                == rubin_consensus::constants::MAX_P2PK_COVENANT_DATA as usize =>
        {
            Some(entry.covenant_data[0])
        }
        _ => None,
    }
}

fn utxo_entry_explicitly_uses_suite(entry: &UtxoEntry, suite_id: u8) -> bool {
    explicit_suite_id_for_utxo_entry(entry) == Some(suite_id)
}

fn chain_state_from_disk(disk: ChainStateDisk) -> Result<ChainState, String> {
    if disk.version != CHAIN_STATE_DISK_VERSION {
        return Err(format!("unsupported chainstate version: {}", disk.version));
    }

    let tip_hash = parse_hex32("tip_hash", &disk.tip_hash)?;
    let mut utxos = HashMap::with_capacity(disk.utxos.len());
    for item in disk.utxos {
        let txid = parse_hex32("utxo.txid", &item.txid)?;
        let covenant_data = parse_hex("utxo.covenant_data", &item.covenant_data)?;
        let outpoint = Outpoint {
            txid,
            vout: item.vout,
        };
        if utxos.contains_key(&outpoint) {
            return Err(format!(
                "duplicate utxo outpoint: {}:{}",
                item.txid, item.vout
            ));
        }
        utxos.insert(
            outpoint,
            UtxoEntry {
                value: item.value,
                covenant_type: item.covenant_type,
                covenant_data,
                creation_height: item.creation_height,
                created_by_coinbase: item.created_by_coinbase,
            },
        );
    }

    Ok(ChainState {
        has_tip: disk.has_tip,
        height: disk.height,
        tip_hash,
        already_generated: disk.already_generated,
        utxos,
    })
}

fn parse_hex(name: &str, value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err(format!("{name}: odd-length hex"));
    }
    hex::decode(trimmed).map_err(|e| format!("{name}: {e}"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::coinbase::{build_coinbase_tx, default_mine_address};
    use crate::genesis::{devnet_genesis_block_bytes, devnet_genesis_chain_id};
    use crate::io_utils::unique_temp_path;

    use super::{
        chain_state_path, copy_utxo_entry, copy_utxo_set, load_chain_state, ChainState,
        ChainStateDisk, CHAIN_STATE_FILE_NAME,
    };
    use rubin_consensus::constants::POW_LIMIT;
    use rubin_consensus::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
    use rubin_consensus::{
        apply_non_coinbase_tx_basic_with_mtp, block_hash, block_subsidy, encode_compact_size,
        merkle_root_txids, parse_block_bytes, parse_tx, Outpoint, UtxoEntry, BLOCK_HEADER_BYTES,
    };
    use serde::Deserialize;

    const GENESIS_ONLY_STATE_DIGEST_HEX: &str =
        "8b172fb3a5e70b56de9ae78ce750c04eccbc4dd8b3be55751252e5a1b4f2e752";
    const GENESIS_PLUS_HEIGHT_ONE_STATE_DIGEST_HEX: &str =
        "a26ade4263f7659ef250d13c05a05137c61e223d1fdd585d0c70a5165a94bb5e";
    const DEVNET_GENESIS_FIXTURE_JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../conformance/fixtures/CV-DEVNET-GENESIS.json"
    ));
    const DEVNET_SUBSIDY_FIXTURE_JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../conformance/fixtures/CV-DEVNET-SUBSIDY.json"
    ));
    const DEVNET_MATURITY_FIXTURE_JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../conformance/fixtures/CV-DEVNET-MATURITY.json"
    ));

    #[derive(Debug, Deserialize)]
    struct FixtureFile<T> {
        vectors: Vec<T>,
    }

    #[derive(Clone, Debug, Deserialize)]
    struct FixtureUtxo {
        txid: String,
        vout: u32,
        value: u64,
        covenant_type: u16,
        covenant_data: String,
        creation_height: u64,
        created_by_coinbase: bool,
    }

    #[derive(Debug, Deserialize)]
    struct ChainStateAfterFixture {
        tip_hash: String,
        height: u64,
        already_generated: u64,
        has_tip: bool,
        utxos: Vec<FixtureUtxo>,
    }

    #[derive(Debug, Deserialize)]
    struct DevnetConnectBlockVector {
        id: String,
        block_hex: String,
        chain_id: String,
        height: u64,
        already_generated: u64,
        utxos: Vec<FixtureUtxo>,
        prev_timestamps: Vec<u64>,
        expected_prev_hash: Option<String>,
        expected_target: String,
        expect_ok: bool,
        expect_sum_fees: u64,
        expect_utxo_count: u64,
        expect_already_generated: u64,
        expect_already_generated_n1: u64,
        block_hash: String,
        chainstate_after: Option<ChainStateAfterFixture>,
    }

    #[derive(Debug, Deserialize)]
    struct DevnetMaturityVector {
        id: String,
        tx_hex: String,
        chain_id: String,
        height: u64,
        block_timestamp: u64,
        utxos: Vec<FixtureUtxo>,
        expect_ok: bool,
        expect_err: String,
    }

    fn parse_hex32_test(name: &str, value: &str) -> [u8; 32] {
        let raw = hex::decode(value).unwrap_or_else(|e| panic!("{name} hex: {e}"));
        assert_eq!(raw.len(), 32, "{name} must be 32 bytes");
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        out
    }

    fn fixture_utxos_to_map(items: &[FixtureUtxo]) -> HashMap<Outpoint, UtxoEntry> {
        let mut out = HashMap::with_capacity(items.len());
        for item in items {
            let txid = parse_hex32_test("fixture utxo txid", &item.txid);
            let covenant_data =
                hex::decode(&item.covenant_data).expect("fixture covenant_data hex");
            out.insert(
                Outpoint {
                    txid,
                    vout: item.vout,
                },
                UtxoEntry {
                    value: item.value,
                    covenant_type: item.covenant_type,
                    covenant_data,
                    creation_height: item.creation_height,
                    created_by_coinbase: item.created_by_coinbase,
                },
            );
        }
        out
    }

    fn chainstate_from_connect_fixture(v: &DevnetConnectBlockVector) -> ChainState {
        let mut state = ChainState::new();
        state.already_generated = v.already_generated;
        state.utxos = fixture_utxos_to_map(&v.utxos);
        if v.height > 0 {
            state.has_tip = true;
            state.height = v.height - 1;
            state.tip_hash = parse_hex32_test(
                "expected_prev_hash",
                v.expected_prev_hash
                    .as_deref()
                    .expect("non-genesis vector must provide expected_prev_hash"),
            );
        }
        state
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

    fn height_one_coinbase_only_block(prev_hash: [u8; 32]) -> Vec<u8> {
        let witness_root = witness_merkle_root_wtxids(&[[0u8; 32]]).expect("witness root");
        let witness_commitment = witness_commitment_hash(witness_root);
        let coinbase =
            build_coinbase_tx(1, 0, &default_mine_address(), witness_commitment).expect("coinbase");
        let (_, coinbase_txid, _, consumed) = parse_tx(&coinbase).expect("parse coinbase");
        assert_eq!(consumed, coinbase.len());
        let merkle_root = merkle_root_txids(&[coinbase_txid]).expect("merkle root");
        build_block_bytes(prev_hash, merkle_root, POW_LIMIT, 1, &[coinbase])
    }

    #[test]
    fn chainstate_roundtrip_with_utxos() {
        let dir = unique_temp_path("rubin-chainstate-test");
        let path = chain_state_path(&dir);
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some(CHAIN_STATE_FILE_NAME)
        );

        let mut st = ChainState::new();
        st.has_tip = true;
        st.height = 42;
        st.tip_hash = [0x11; 32];
        st.already_generated = 77;
        st.utxos.insert(
            Outpoint {
                txid: [0x22; 32],
                vout: 3,
            },
            UtxoEntry {
                value: 123,
                covenant_type: 0,
                covenant_data: vec![0x01; 33],
                creation_height: 10,
                created_by_coinbase: false,
            },
        );

        st.save(&path).expect("save");
        let got = load_chain_state(&path).expect("load");
        assert_eq!(got, st);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// `ChainState::save` must accept a bare-filename path (e.g.
    /// `"chainstate.json"`) without the pre-write `create_dir_all`
    /// running against `""`. An earlier version of `save` called
    /// `fs::create_dir_all(path.parent())` directly; for a
    /// bare-filename input `path.parent()` is `Some("")` on Unix,
    /// and `create_dir_all("")` fails with an I/O error. Parent
    /// creation is delegated to `write_file_atomic` which uses
    /// `effective_parent` (maps `""` → `.`), so `save("file.json")`
    /// from the current working directory succeeds.
    #[test]
    fn save_accepts_bare_filename_via_effective_parent() {
        use std::path::Path;
        let dir = unique_temp_path("rubin-chainstate-bare-filename");
        std::fs::create_dir_all(&dir).expect("mkdir");
        // cd into the temp dir so "chainstate.json" resolves locally.
        let prev_cwd = std::env::current_dir().expect("get cwd");
        std::env::set_current_dir(&dir).expect("cd");

        let st = ChainState::new();
        let result = st.save(Path::new("chainstate.json"));

        // Always restore cwd before asserting so a failing assert
        // does not leave the process in the temp dir.
        std::env::set_current_dir(&prev_cwd).expect("restore cwd");

        result.expect("save with bare filename must not error on empty parent");

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn chainstate_suite_exposure_queries_by_explicit_suite_id() {
        let mut st = ChainState::new();
        let first = Outpoint {
            txid: [0x03; 32],
            vout: 2,
        };
        let second = Outpoint {
            txid: [0x01; 32],
            vout: 0,
        };
        let third = Outpoint {
            txid: [0x02; 32],
            vout: 1,
        };
        let ignored = Outpoint {
            txid: [0xaa; 32],
            vout: 9,
        };

        let mut first_cov = vec![0x01; 33];
        first_cov[0] = rubin_consensus::constants::SUITE_ID_ML_DSA_87;
        st.utxos.insert(
            first.clone(),
            UtxoEntry {
                value: 10,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: first_cov,
                creation_height: 3,
                created_by_coinbase: false,
            },
        );
        let mut rotated_cov = vec![0x11; 33];
        rotated_cov[0] = 0x42;
        st.utxos.insert(
            second.clone(),
            UtxoEntry {
                value: 11,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: rotated_cov.clone(),
                creation_height: 4,
                created_by_coinbase: false,
            },
        );
        st.utxos.insert(
            third.clone(),
            UtxoEntry {
                value: 12,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: rotated_cov,
                creation_height: 5,
                created_by_coinbase: false,
            },
        );
        st.utxos.insert(
            ignored,
            UtxoEntry {
                value: 7,
                covenant_type: rubin_consensus::constants::COV_TYPE_HTLC,
                covenant_data: vec![
                    0x00;
                    rubin_consensus::constants::MAX_HTLC_COVENANT_DATA as usize
                ],
                creation_height: 6,
                created_by_coinbase: false,
            },
        );

        assert_eq!(
            st.indexed_suite_ids(),
            vec![rubin_consensus::constants::SUITE_ID_ML_DSA_87, 0x42]
        );
        assert_eq!(st.utxo_exposure_count_by_suite_id(0x42), 2);
        assert_eq!(
            st.utxo_outpoints_by_suite_id(0x42),
            vec![second.clone(), third.clone()]
        );
        assert_eq!(st.utxo_exposure_count_by_suite_id(0x99), 0);
    }

    #[test]
    fn load_chainstate_rejects_wrong_version() {
        let dir = unique_temp_path("rubin-chainstate-version-test");
        let path = chain_state_path(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");

        let bad = ChainStateDisk {
            version: 999,
            has_tip: false,
            height: 0,
            tip_hash: "00".repeat(32),
            already_generated: 0,
            utxos: vec![],
        };
        let raw = serde_json::to_vec_pretty(&bad).expect("json");
        std::fs::write(&path, raw).expect("write");

        let err = load_chain_state(&path).unwrap_err();
        assert!(err.contains("unsupported chainstate version"));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn chainstate_connect_block_rejects_wrong_non_zero_genesis_chain_id() {
        let mut st = ChainState::new();
        let err = st
            .connect_block(
                &devnet_genesis_block_bytes(),
                Some(POW_LIMIT),
                None,
                [0x11; 32],
            )
            .unwrap_err();
        assert_eq!(err, "genesis chain_id mismatch");
        assert_eq!(st, ChainState::new());
    }

    #[test]
    fn chainstate_connect_block_accepts_zero_chain_id_at_genesis() {
        let mut st = ChainState::new();
        let summary = st
            .connect_block(
                &devnet_genesis_block_bytes(),
                Some(POW_LIMIT),
                None,
                [0u8; 32],
            )
            .expect("connect genesis");
        assert_eq!(summary.block_height, 0);
        assert_eq!(summary.already_generated, 0);
        assert_eq!(summary.already_generated_n1, 0);
        assert_eq!(
            hex::encode(st.state_digest()),
            GENESIS_ONLY_STATE_DIGEST_HEX
        );
    }

    #[test]
    fn chainstate_connect_block_accepts_expected_non_zero_genesis_chain_id() {
        let mut st = ChainState::new();
        let summary = st
            .connect_block(
                &devnet_genesis_block_bytes(),
                Some(POW_LIMIT),
                None,
                devnet_genesis_chain_id(),
            )
            .expect("connect genesis");
        assert_eq!(summary.block_height, 0);
        assert!(st.has_tip);
    }

    #[test]
    fn chainstate_state_digest_matches_genesis_plus_height_one_parity_vector() {
        let mut st = ChainState::new();
        let genesis_summary = st
            .connect_block(
                &devnet_genesis_block_bytes(),
                Some(POW_LIMIT),
                None,
                [0u8; 32],
            )
            .expect("connect genesis");
        let parsed_genesis =
            parse_block_bytes(&devnet_genesis_block_bytes()).expect("parse genesis block");
        let genesis_hash = block_hash(&parsed_genesis.header_bytes).expect("genesis hash");
        assert_eq!(genesis_summary.block_hash, genesis_hash);
        assert_eq!(
            hex::encode(st.state_digest()),
            GENESIS_ONLY_STATE_DIGEST_HEX
        );

        let block1 = height_one_coinbase_only_block(genesis_hash);
        let summary = st
            .connect_block(&block1, Some(POW_LIMIT), None, [0u8; 32])
            .expect("connect height 1");
        assert_eq!(summary.block_height, 1);
        assert_eq!(summary.already_generated, 0);
        assert_eq!(summary.already_generated_n1, block_subsidy(1, 0));
        assert_eq!(st.already_generated, block_subsidy(1, 0));
        assert_eq!(
            hex::encode(st.state_digest()),
            GENESIS_PLUS_HEIGHT_ONE_STATE_DIGEST_HEX
        );
    }

    #[test]
    fn chainstate_replays_devnet_genesis_fixture() {
        let fixture: FixtureFile<DevnetConnectBlockVector> =
            serde_json::from_str(DEVNET_GENESIS_FIXTURE_JSON).expect("parse genesis fixture");
        let vector = fixture
            .vectors
            .into_iter()
            .next()
            .expect("genesis fixture vector");
        assert!(vector.expect_ok, "{} should be positive fixture", vector.id);

        let mut st = chainstate_from_connect_fixture(&vector);
        let block_bytes = hex::decode(&vector.block_hex).expect("genesis block hex");
        let summary = st
            .connect_block(
                &block_bytes,
                Some(parse_hex32_test("expected_target", &vector.expected_target)),
                None,
                parse_hex32_test("chain_id", &vector.chain_id),
            )
            .expect("connect genesis fixture");

        assert_eq!(summary.block_height, vector.height, "{}", vector.id);
        assert_eq!(summary.sum_fees, vector.expect_sum_fees, "{}", vector.id);
        assert_eq!(
            summary.utxo_count, vector.expect_utxo_count,
            "{}",
            vector.id
        );
        assert_eq!(
            summary.already_generated, vector.expect_already_generated,
            "{}",
            vector.id
        );
        assert_eq!(
            summary.already_generated_n1, vector.expect_already_generated_n1,
            "{}",
            vector.id
        );
        assert_eq!(
            hex::encode(summary.block_hash),
            vector.block_hash,
            "{}",
            vector.id
        );

        let expected_state = vector.chainstate_after.expect("genesis chainstate_after");
        assert_eq!(st.has_tip, expected_state.has_tip, "{}", vector.id);
        assert_eq!(st.height, expected_state.height, "{}", vector.id);
        assert_eq!(
            hex::encode(st.tip_hash),
            expected_state.tip_hash,
            "{}",
            vector.id
        );
        assert_eq!(
            st.already_generated, expected_state.already_generated,
            "{}",
            vector.id
        );
        assert_eq!(
            st.utxos,
            fixture_utxos_to_map(&expected_state.utxos),
            "{}",
            vector.id
        );
    }

    #[test]
    fn chainstate_replays_devnet_subsidy_vectors() {
        let fixture: FixtureFile<DevnetConnectBlockVector> =
            serde_json::from_str(DEVNET_SUBSIDY_FIXTURE_JSON).expect("parse subsidy fixture");

        for vector in fixture.vectors {
            assert!(vector.expect_ok, "{} should be positive fixture", vector.id);
            let mut st = chainstate_from_connect_fixture(&vector);
            let block_bytes = hex::decode(&vector.block_hex).expect("subsidy block hex");
            let summary = st
                .connect_block(
                    &block_bytes,
                    Some(parse_hex32_test("expected_target", &vector.expected_target)),
                    Some(vector.prev_timestamps.as_slice()),
                    parse_hex32_test("chain_id", &vector.chain_id),
                )
                .unwrap_or_else(|e| panic!("{} connect_block failed: {e}", vector.id));

            assert_eq!(summary.block_height, vector.height, "{}", vector.id);
            assert_eq!(summary.sum_fees, vector.expect_sum_fees, "{}", vector.id);
            assert_eq!(
                summary.utxo_count, vector.expect_utxo_count,
                "{}",
                vector.id
            );
            assert_eq!(
                summary.already_generated, vector.expect_already_generated,
                "{}",
                vector.id
            );
            assert_eq!(
                summary.already_generated_n1, vector.expect_already_generated_n1,
                "{}",
                vector.id
            );
            assert_eq!(
                hex::encode(summary.block_hash),
                vector.block_hash,
                "{}",
                vector.id
            );
            assert_eq!(st.height, vector.height, "{}", vector.id);
            assert_eq!(st.tip_hash, summary.block_hash, "{}", vector.id);
            assert_eq!(
                st.already_generated, vector.expect_already_generated_n1,
                "{}",
                vector.id
            );
            assert_eq!(
                st.utxos.len() as u64,
                vector.expect_utxo_count,
                "{}",
                vector.id
            );
        }
    }

    #[test]
    fn chainstate_replays_devnet_maturity_fixture() {
        let fixture: FixtureFile<DevnetMaturityVector> =
            serde_json::from_str(DEVNET_MATURITY_FIXTURE_JSON).expect("parse maturity fixture");
        let vector = fixture
            .vectors
            .into_iter()
            .next()
            .expect("maturity fixture vector");
        assert!(
            !vector.expect_ok,
            "{} should be negative fixture",
            vector.id
        );

        let tx_bytes = hex::decode(&vector.tx_hex).expect("maturity tx hex");
        let (tx, txid, _, consumed) = parse_tx(&tx_bytes).expect("parse maturity tx");
        assert_eq!(consumed, tx_bytes.len(), "{}", vector.id);

        let err = apply_non_coinbase_tx_basic_with_mtp(
            &tx,
            txid,
            &fixture_utxos_to_map(&vector.utxos),
            vector.height,
            vector.block_timestamp,
            vector.block_timestamp,
            parse_hex32_test("chain_id", &vector.chain_id),
        )
        .expect_err("maturity fixture must reject");
        assert_eq!(err.code.as_str(), vector.expect_err, "{}", vector.id);
    }

    // ---------- E.9: Rust UTXO defensive-copy helper twin (Go parity) ----------
    //
    // These tests pin the contract that mirrors `copyUtxoEntry`,
    // `copyUtxoSet`, and the snapshot-isolation invariants in
    // `clients/go/node/chainstate.go`.

    fn sample_entry(value: u64, covenant_byte: u8) -> UtxoEntry {
        UtxoEntry {
            value,
            covenant_type: 0x0001,
            covenant_data: vec![covenant_byte; 4],
            creation_height: 7,
            created_by_coinbase: false,
        }
    }

    fn sample_outpoint(byte: u8) -> Outpoint {
        Outpoint {
            txid: [byte; 32],
            vout: 0,
        }
    }

    #[test]
    fn copy_utxo_entry_deep_copies_covenant_data() {
        // Mutating the copy's covenant_data must not touch the source.
        let src = sample_entry(100, 0xAA);
        let mut dst = copy_utxo_entry(&src);
        dst.covenant_data[0] = 0xFF;
        dst.value = 999;
        assert_eq!(src.covenant_data, vec![0xAA; 4]);
        assert_eq!(src.value, 100);
    }

    #[test]
    fn copy_utxo_set_deep_copies_all_entries() {
        let mut src = HashMap::new();
        src.insert(sample_outpoint(1), sample_entry(10, 0x11));
        src.insert(sample_outpoint(2), sample_entry(20, 0x22));

        let mut dst = copy_utxo_set(&src);
        // Mutate every entry in the copy.
        for entry in dst.values_mut() {
            entry.covenant_data[0] = 0x00;
            entry.value = 0;
        }
        // Insert a new entry into the copy; canonical map must be unaffected.
        dst.insert(sample_outpoint(3), sample_entry(30, 0x33));

        assert_eq!(src.len(), 2);
        assert_eq!(src[&sample_outpoint(1)].covenant_data, vec![0x11; 4]);
        assert_eq!(src[&sample_outpoint(1)].value, 10);
        assert_eq!(src[&sample_outpoint(2)].covenant_data, vec![0x22; 4]);
        assert_eq!(src[&sample_outpoint(2)].value, 20);
        assert!(!src.contains_key(&sample_outpoint(3)));
    }

    #[test]
    fn lookup_utxo_owned_returns_none_for_missing_outpoint() {
        // Mirrors the Go twin's presence-check / skip-missing semantics
        // for absent UTXOs (cf. `copySelectedUtxoSet` in
        // `clients/go/node/chainstate.go`, which uses `value, ok := m[op]`
        // and skips when `!ok` rather than treating zero-value entries as
        // present).
        let st = ChainState::new();
        assert!(st.lookup_utxo_owned(&sample_outpoint(0xEE)).is_none());
    }

    #[test]
    fn lookup_utxo_owned_returns_owned_copy_caller_mutation_isolated() {
        // Caller mutates the returned entry; canonical map must be unaffected.
        let mut st = ChainState::new();
        let op = sample_outpoint(7);
        st.utxos.insert(op.clone(), sample_entry(500, 0xBB));

        let mut owned = st.lookup_utxo_owned(&op).expect("present");
        owned.covenant_data.fill(0x00);
        owned.value = 1;

        let canonical = st.utxos.get(&op).expect("still present");
        assert_eq!(canonical.value, 500);
        assert_eq!(canonical.covenant_data, vec![0xBB; 4]);
    }

    #[test]
    fn lookup_utxo_owned_drop_does_not_leak_or_panic() {
        // Caller drops the copy; canonical map remains intact.
        let mut st = ChainState::new();
        let op = sample_outpoint(9);
        st.utxos.insert(op.clone(), sample_entry(42, 0xCC));
        {
            let owned = st.lookup_utxo_owned(&op).expect("present");
            assert_eq!(owned.value, 42);
        } // owned dropped here
        assert_eq!(st.utxos.get(&op).expect("still present").value, 42);
    }
}
