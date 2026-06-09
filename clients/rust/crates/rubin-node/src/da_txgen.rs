//! Deterministic in-process signed DA tx source for the devnet DA relay
//! process smoke (`scripts/devnet-rust-da-relay.sh`).
//!
//! RUB-442 (`Q-RUST-DA-SIGNED-TX-SOURCE-01`). The Go devnet DA relay smoke
//! (`scripts/devnet-go-da-relay.sh`) generates its signed DA commit/chunk txs
//! with a throwaway `go run` helper that exports the mining keypair as DER and
//! re-imports it to sign coinbase spends across a keygen -> mine -> sign process
//! boundary. The Rust `Mldsa87Keypair` exposes neither a DER export nor a
//! seed/from-bytes constructor (only OpenSSL random `generate()`), so the same
//! key cannot be reconstructed in a second process. This module closes that gap
//! in the only way available without introducing a new crypto path: it does
//! keygen + mine + sign **in one process**, so the single keypair never leaves
//! memory.
//!
//! Scope is the DA tx *source* only: it produces one `DA_COMMIT` tx and two
//! `DA_CHUNK` txs (plus the Go-parity duplicate commit) that pass Rust canonical
//! tx admission. Driving the two-node relay -> complete-set -> mine scenario to
//! a PASS verdict is the follow-up RUB-443.
//!
//! Non-scope (mirrors the Linear issue): no consensus changes, no Go changes,
//! no P2P protocol changes, no DA economics, no DA ticket gate, no production
//! wallet/key generation. The key material is devnet-only and ephemeral.

use std::fs;
use std::path::Path;

use rubin_consensus::constants::{
    COINBASE_MATURITY, COV_TYPE_DA_COMMIT, COV_TYPE_P2PK, TX_WIRE_VERSION,
};
use rubin_consensus::{
    marshal_tx, p2pk_covenant_data_for_pubkey, parse_tx, sign_transaction, DaChunkCore,
    DaCommitCore, Mldsa87Keypair, Outpoint, Tx, TxInput, TxOutput,
};
use sha3::{Digest, Sha3_256};

use crate::blockstore::{block_store_path, BlockStore};
use crate::chainstate::{chain_state_path, load_chain_state, ChainState};
use crate::genesis::load_genesis_config;
use crate::miner::{Miner, MinerConfig};
use crate::sync::{default_sync_config, SyncEngine};
use crate::txpool::{TxPool, TxPoolConfig};

/// Base chain height mined before generating the DA set. Mirrors the Go relay
/// smoke (`BASE_HEIGHT=105`): enough confirmations that the early coinbase
/// outputs spent by the DA txs are mature (`COINBASE_MATURITY = 100`).
pub const DA_RELAY_BASE_HEIGHT: u64 = 105;

/// Number of mature coinbase outputs the DA set spends: chunk0, commit,
/// duplicate commit, chunk1 — each from a distinct coinbase, mirroring the Go
/// helper's four-coin selection.
const DA_SET_COIN_COUNT: usize = 4;

// Deterministic fixture material. The byte labels are identical to the Go relay
// smoke so both clients exercise the same DA identity/payloads; the txids still
// differ per run because the signing key is freshly generated.
const DA_ID_LABEL: &[u8] = b"rubin-da-relay-process-smoke-da-id";
const PAYLOAD_0: &[u8] = b"rubin-da-relay-process-smoke-0";
const PAYLOAD_1: &[u8] = b"rubin-da-relay-process-smoke-1";
const REPLACEMENT_PAYLOAD: &[u8] = b"rubin-da-relay-replacement";
const BATCH_SIG_LABEL: &[u8] = b"rubin-da-relay-process-smoke-batch-sig";

// DA commit manifest body (`da_payload` for tx_kind=0x01). Matches the Go
// helper's single opaque byte; the consensus rules only bound its length.
const DA_COMMIT_MANIFEST: &[u8] = &[0xa1];

// RETL batch header fields carried in `DaCommitCore`. These reuse the canonical
// in-repo Rust DA-commit fixture values (`main.rs` local DA commit builder and
// `da_relay.rs` relay_commit_core): retl_domain_id=0x10.., roots=0x11../0x12../
// 0x13.., batch_number=1. They are opaque to tx admission (DA economics /
// settlement semantics are out of scope) but are populated deterministically as
// the issue's fixture shape requires rather than left zero.
const RETL_DOMAIN_ID: [u8; 32] = [0x10; 32];
const TX_DATA_ROOT: [u8; 32] = [0x11; 32];
const STATE_ROOT: [u8; 32] = [0x12; 32];
const WITHDRAWALS_ROOT: [u8; 32] = [0x13; 32];
const BATCH_NUMBER: u64 = 1;
/// `batch_sig_suite` for the fixture. Suite 0 with an opaque (here, non-empty)
/// `batch_sig` blob matches existing in-repo usage; admission treats the blob as
/// opaque and only bounds its length.
const BATCH_SIG_SUITE: u8 = 0;

// tx_nonce values, identical to the Go helper (chunk0/commit/duplicate/chunk1).
const NONCE_CHUNK_0: u64 = 3201;
const NONCE_COMMIT: u64 = 3202;
const NONCE_DUPLICATE: u64 = 3203;
const NONCE_CHUNK_1: u64 = 3204;

const DA_CHUNK_COUNT: u16 = 2;

fn sha3_256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Deterministic da_id shared by the whole set.
pub fn fixture_da_id() -> [u8; 32] {
    sha3_256(DA_ID_LABEL)
}

/// Deterministic opaque batch signature blob (devnet fixture only).
fn fixture_batch_sig() -> Vec<u8> {
    sha3_256(BATCH_SIG_LABEL).to_vec()
}

/// One signed DA transaction: canonical wire bytes plus its txid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDaTx {
    pub raw: Vec<u8>,
    pub txid: [u8; 32],
}

impl SignedDaTx {
    pub fn hex(&self) -> String {
        hex::encode(&self.raw)
    }

    pub fn txid_hex(&self) -> String {
        hex::encode(self.txid)
    }
}

/// A complete signed DA set for the relay smoke: the commit, both chunks, and
/// the duplicate commit (used by the relay first-seen-no-replacement evidence
/// path). The complete, internally consistent set is `commit` + `chunk0` +
/// `chunk1`; `duplicate_commit` is an alternate commit over the same da_id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDaSet {
    pub da_id: [u8; 32],
    pub commit: SignedDaTx,
    pub chunk0: SignedDaTx,
    pub chunk1: SignedDaTx,
    pub duplicate_commit: SignedDaTx,
}

impl SignedDaSet {
    /// JSON carrying the Go helper's `da-txs.json` keys
    /// (`{chunk0,commit,duplicate_commit,chunk1: {hex, txid}}`) so the shell
    /// harness can consume either client's output with one keyed parser,
    /// plus an additive top-level `da_id` field (not present in the Go
    /// output) for downstream relay wiring.
    pub fn to_json(&self) -> serde_json::Value {
        let entry = |tx: &SignedDaTx| serde_json::json!({"hex": tx.hex(), "txid": tx.txid_hex()});
        serde_json::json!({
            "da_id": hex::encode(self.da_id),
            "chunk0": entry(&self.chunk0),
            "commit": entry(&self.commit),
            "duplicate_commit": entry(&self.duplicate_commit),
            "chunk1": entry(&self.chunk1),
        })
    }
}

/// Select `count` mature coinbase P2PK outputs paying to `mine_covenant_data`,
/// in a deterministic order (by outpoint). Mirrors the Go helper's `selectCoins`
/// maturity + ownership filter. Errors if too few mature coins exist.
pub fn select_mature_p2pk_coinbases(
    state: &ChainState,
    mine_covenant_data: &[u8],
    next_height: u64,
    count: usize,
) -> Result<Vec<Outpoint>, String> {
    let mut coins: Vec<Outpoint> = state
        .utxos
        .iter()
        .filter(|(_, entry)| {
            entry.created_by_coinbase
                && entry.covenant_type == COV_TYPE_P2PK
                && entry.covenant_data.as_slice() == mine_covenant_data
                && entry
                    .creation_height
                    .checked_add(COINBASE_MATURITY)
                    .is_some_and(|mature_at| next_height >= mature_at)
        })
        .map(|(outpoint, _)| outpoint.clone())
        .collect();
    // Deterministic selection given a fixed chain state.
    coins.sort_by(|a, b| a.txid.cmp(&b.txid).then(a.vout.cmp(&b.vout)));
    if coins.len() < count {
        return Err(format!(
            "need {count} mature P2PK coinbase outputs, have {}",
            coins.len()
        ));
    }
    coins.truncate(count);
    Ok(coins)
}

fn da_input(coin: &Outpoint) -> TxInput {
    TxInput {
        prev_txid: coin.txid,
        prev_vout: coin.vout,
        script_sig: Vec::new(),
        sequence: 0,
    }
}

fn da_commit_core(da_id: [u8; 32]) -> DaCommitCore {
    DaCommitCore {
        da_id,
        chunk_count: DA_CHUNK_COUNT,
        retl_domain_id: RETL_DOMAIN_ID,
        batch_number: BATCH_NUMBER,
        tx_data_root: TX_DATA_ROOT,
        state_root: STATE_ROOT,
        withdrawals_root: WITHDRAWALS_ROOT,
        batch_sig_suite: BATCH_SIG_SUITE,
        batch_sig: fixture_batch_sig(),
    }
}

/// Build an unsigned `DA_COMMIT` tx (tx_kind=0x01). The single
/// `COV_TYPE_DA_COMMIT` output carries the 32-byte payload commitment
/// `sha3_256(payload)`; the commit spends `coin` entirely as fee.
fn build_da_commit(coin: &Outpoint, da_id: [u8; 32], nonce: u64, payload: &[u8]) -> Tx {
    let commitment = sha3_256(payload);
    Tx {
        version: TX_WIRE_VERSION,
        tx_kind: 0x01,
        tx_nonce: nonce,
        inputs: vec![da_input(coin)],
        outputs: vec![TxOutput {
            value: 0,
            covenant_type: COV_TYPE_DA_COMMIT,
            covenant_data: commitment.to_vec(),
        }],
        locktime: 0,
        da_commit_core: Some(da_commit_core(da_id)),
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: DA_COMMIT_MANIFEST.to_vec(),
    }
}

/// Build an unsigned `DA_CHUNK` tx (tx_kind=0x02). It carries the chunk payload
/// in `da_payload` with `chunk_hash = sha3_256(payload)`, has no outputs, and
/// spends `coin` entirely as fee (mirrors the Go helper's chunk shape).
fn build_da_chunk(coin: &Outpoint, da_id: [u8; 32], nonce: u64, index: u16, payload: &[u8]) -> Tx {
    Tx {
        version: TX_WIRE_VERSION,
        tx_kind: 0x02,
        tx_nonce: nonce,
        inputs: vec![da_input(coin)],
        outputs: Vec::new(),
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: Some(DaChunkCore {
            da_id,
            chunk_index: index,
            chunk_hash: sha3_256(payload),
        }),
        witness: Vec::new(),
        da_payload: payload.to_vec(),
    }
}

/// Sign `tx`, marshal it, and confirm the result passes Rust canonical tx
/// admission (`TxPool::admit`) — the same gate the relay `/submit_tx` path uses.
/// Returns the canonical bytes + txid only if admission accepts.
fn sign_marshal_admit(
    mut tx: Tx,
    state: &ChainState,
    block_store: Option<&BlockStore>,
    keypair: &Mldsa87Keypair,
    chain_id: [u8; 32],
) -> Result<SignedDaTx, String> {
    sign_transaction(&mut tx, &state.utxos, chain_id, keypair).map_err(|err| err.to_string())?;
    let raw = marshal_tx(&tx).map_err(|err| err.to_string())?;
    let (_, txid, _, consumed) = parse_tx(&raw).map_err(|err| err.to_string())?;
    if consumed != raw.len() {
        return Err("generated non-canonical DA tx bytes".to_string());
    }
    let mut pool = TxPool::new_with_config(TxPoolConfig::default());
    pool.admit(&raw, state, block_store, chain_id)
        .map_err(|err| format!("DA tx failed canonical admission: {}", err.message))?;
    Ok(SignedDaTx { raw, txid })
}

/// Build the complete signed DA set against a chain state that already holds
/// mature coinbase outputs owned by `keypair`. `block_store` (when present) is
/// used by admission for median-time-past; `chain_id` is the signing/admission
/// chain id (devnet).
pub fn build_signed_da_set(
    state: &ChainState,
    block_store: Option<&BlockStore>,
    keypair: &Mldsa87Keypair,
    chain_id: [u8; 32],
) -> Result<SignedDaSet, String> {
    let next_height = state
        .height
        .checked_add(1)
        .ok_or_else(|| "chain height overflow".to_string())?;
    let mine_covenant_data = p2pk_covenant_data_for_pubkey(&keypair.pubkey_bytes());
    let coins =
        select_mature_p2pk_coinbases(state, &mine_covenant_data, next_height, DA_SET_COIN_COUNT)?;

    let da_id = fixture_da_id();
    let mut full_payload = PAYLOAD_0.to_vec();
    full_payload.extend_from_slice(PAYLOAD_1);

    let sign = |tx| sign_marshal_admit(tx, state, block_store, keypair, chain_id);
    let chunk0 = sign(build_da_chunk(
        &coins[0],
        da_id,
        NONCE_CHUNK_0,
        0,
        PAYLOAD_0,
    ))?;
    let commit = sign(build_da_commit(
        &coins[1],
        da_id,
        NONCE_COMMIT,
        &full_payload,
    ))?;
    let duplicate_commit = sign(build_da_commit(
        &coins[2],
        da_id,
        NONCE_DUPLICATE,
        REPLACEMENT_PAYLOAD,
    ))?;
    let chunk1 = sign(build_da_chunk(
        &coins[3],
        da_id,
        NONCE_CHUNK_1,
        1,
        PAYLOAD_1,
    ))?;

    Ok(SignedDaSet {
        da_id,
        commit,
        chunk0,
        chunk1,
        duplicate_commit,
    })
}

/// In-process keygen + mine + sign: mine `mine_blocks` base blocks into
/// `data_dir` paying a fresh ephemeral devnet keypair, then build and return the
/// signed DA set spending the matured coinbases. The keypair never leaves this
/// process. Leaves a persisted devnet datadir (chainstate + blockstore) for
/// downstream relay wiring (RUB-443).
pub fn mine_and_generate(data_dir: &Path, mine_blocks: u64) -> Result<SignedDaSet, String> {
    let genesis = load_genesis_config(None, "devnet")?;
    let chain_id = genesis.chain_id;
    let keypair = Mldsa87Keypair::generate().map_err(|err| err.to_string())?;
    let mine_covenant_data = p2pk_covenant_data_for_pubkey(&keypair.pubkey_bytes());

    fs::create_dir_all(data_dir)
        .map_err(|err| format!("datadir create failed ({}): {err}", data_dir.display()))?;
    let chain_state_file = chain_state_path(data_dir);
    let chain_state = load_chain_state(&chain_state_file)?;
    let block_store = BlockStore::open(block_store_path(data_dir))?;

    let mut sync_cfg = default_sync_config(None, chain_id, Some(chain_state_file.clone()));
    sync_cfg.core_ext_deployments = genesis.core_ext_deployments.clone();
    sync_cfg.suite_context = genesis.suite_context.clone();
    let mut sync_engine = SyncEngine::new(chain_state, Some(block_store), sync_cfg)?;

    let miner_cfg = MinerConfig {
        core_ext_deployments: genesis.core_ext_deployments.clone(),
        mine_address: mine_covenant_data,
        ..MinerConfig::default()
    };
    {
        let mut miner = Miner::new(&mut sync_engine, None, miner_cfg)?;
        let blocks = usize::try_from(mine_blocks)
            .map_err(|_| "mine_blocks exceeds usize range".to_string())?;
        miner.mine_n(blocks, &[])?;
    }

    // Persist the mined state and reopen independent handles so admission reads
    // the same on-disk datadir a node would load.
    sync_engine.chain_state.save(&chain_state_file)?;
    let state = load_chain_state(&chain_state_file)?;
    let block_store = BlockStore::open(block_store_path(data_dir))?;
    build_signed_da_set(&state, Some(&block_store), &keypair, chain_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da_relay::{DaRelayError, DaRelayState};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("rubin-da-txgen-test-{}-{n}", std::process::id()));
            fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn parse(raw: &[u8]) -> Tx {
        let (tx, _txid, _wtxid, consumed) = parse_tx(raw).expect("parse generated DA tx");
        assert_eq!(consumed, raw.len(), "generated DA tx has trailing bytes");
        tx
    }

    #[test]
    fn signed_da_set_is_complete_consistent_and_admissible() {
        let dir = TempDir::new();
        let set = mine_and_generate(&dir.path, DA_RELAY_BASE_HEIGHT)
            .expect("mine + generate signed DA set");

        // Four distinct transactions.
        let txids = [
            set.commit.txid,
            set.chunk0.txid,
            set.chunk1.txid,
            set.duplicate_commit.txid,
        ];
        for i in 0..txids.len() {
            for j in (i + 1)..txids.len() {
                assert_ne!(txids[i], txids[j], "DA set txids must be distinct");
            }
        }

        let da_id = fixture_da_id();
        assert_eq!(set.da_id, da_id);

        // Commit: covenant commitment == sha3(payload0 || payload1), 2 chunks,
        // shared da_id, deterministic RETL header fields.
        let commit = parse(&set.commit.raw);
        assert_eq!(commit.tx_kind, 0x01);
        let mut full_payload = PAYLOAD_0.to_vec();
        full_payload.extend_from_slice(PAYLOAD_1);
        let expected_commitment = sha3_256(&full_payload);
        let commit_output = commit
            .outputs
            .iter()
            .find(|o| o.covenant_type == COV_TYPE_DA_COMMIT)
            .expect("commit output");
        assert_eq!(commit_output.covenant_data.as_slice(), &expected_commitment);
        let core = commit.da_commit_core.as_ref().expect("commit core");
        assert_eq!(core.da_id, da_id);
        assert_eq!(core.chunk_count, DA_CHUNK_COUNT);
        assert_eq!(core.retl_domain_id, RETL_DOMAIN_ID);
        assert_eq!(core.tx_data_root, TX_DATA_ROOT);
        assert_eq!(core.state_root, STATE_ROOT);
        assert_eq!(core.withdrawals_root, WITHDRAWALS_ROOT);
        assert_eq!(core.batch_number, BATCH_NUMBER);
        assert_eq!(core.batch_sig, fixture_batch_sig());

        // Chunks: chunk_hash == sha3(payload), indexes 0 and 1, shared da_id.
        for (raw, index, payload) in [
            (&set.chunk0.raw, 0u16, PAYLOAD_0),
            (&set.chunk1.raw, 1u16, PAYLOAD_1),
        ] {
            let chunk = parse(raw);
            assert_eq!(chunk.tx_kind, 0x02);
            let chunk_core = chunk.da_chunk_core.as_ref().expect("chunk core");
            assert_eq!(chunk_core.da_id, da_id);
            assert_eq!(chunk_core.chunk_index, index);
            assert_eq!(chunk_core.chunk_hash, sha3_256(payload));
            assert_eq!(chunk.da_payload.as_slice(), payload);
        }

        // Independent canonical re-admission against the persisted datadir.
        let state = load_chain_state(chain_state_path(&dir.path)).expect("reload state");
        let block_store = BlockStore::open(block_store_path(&dir.path)).expect("reopen blockstore");
        for tx in [&set.commit, &set.chunk0, &set.chunk1, &set.duplicate_commit] {
            let mut pool = TxPool::new_with_config(TxPoolConfig::default());
            pool.admit(&tx.raw, &state, Some(&block_store), genesis_chain_id())
                .expect("DA tx must pass canonical admission");
        }

        // Relay DA admission accepts the well-formed chunks.
        DaRelayState::validate_relay_da_tx_for_admission(&set.chunk0.raw)
            .expect("well-formed chunk passes relay admission");
        DaRelayState::validate_relay_da_tx_for_admission(&set.chunk1.raw)
            .expect("well-formed chunk passes relay admission");
    }

    #[test]
    fn corrupted_chunk_hash_is_rejected_by_relay_admission() {
        let dir = TempDir::new();
        let set = mine_and_generate(&dir.path, DA_RELAY_BASE_HEIGHT)
            .expect("mine + generate signed DA set");

        // Flip the chunk_hash so it no longer matches sha3(payload), re-marshal,
        // and confirm relay DA admission rejects it.
        let mut chunk = parse(&set.chunk0.raw);
        let core = chunk.da_chunk_core.as_mut().expect("chunk core");
        core.chunk_hash[0] ^= 0xff;
        let corrupted = marshal_tx(&chunk).expect("marshal corrupted chunk");

        let err = DaRelayState::validate_relay_da_tx_for_admission(&corrupted)
            .expect_err("corrupted chunk_hash must be rejected");
        assert_eq!(err, DaRelayError::ChunkHashMismatch);
    }

    fn genesis_chain_id() -> [u8; 32] {
        crate::genesis::devnet_genesis_chain_id()
    }
}
