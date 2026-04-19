//! Startup-time reconcile / repair between the persisted ChainState
//! snapshot and the on-disk BlockStore (`E.2` of the 2026-04-14 audit).
//!
//! Rust mirror of `clients/go/node/chainstate_recovery.go`.
//!
//! # What this closes
//!
//! Before this module, the Rust node entrypoint (`main.rs`) opened the
//! chainstate snapshot and the blockstore independently and immediately
//! constructed a `SyncEngine` from them. If the two diverged — most
//! commonly after a crash that landed the chainstate snapshot but lost
//! the matching block / undo file, or vice versa — the sync engine
//! would happily run with a chainstate tip that no longer points at any
//! canonical block on disk. Go has had this since the storage
//! cluster landed: function defined in
//! `clients/go/node/chainstate_recovery.go::ReconcileChainStateWithBlockStore`,
//! invoked from `clients/go/cmd/rubin-node/main.go` between
//! `OpenBlockStore` and the sync engine constructor. Rust did not.
//!
//! # Repair contract
//!
//! `reconcile_chain_state_with_block_store(state, store, cfg)` performs
//! two repair steps:
//!
//! 1. `truncate_incomplete_canonical_suffix(store)` — walks the
//!    canonical index from height 0 forward and stops at the first
//!    height whose header / block-bytes / undo file is missing on
//!    disk. Truncates the canonical index to that prefix. This is the
//!    "blockstore lost its tail" repair. A present-but-unparseable
//!    artifact (e.g. corrupt JSON undo) is propagated as an error and
//!    no truncate happens — operator must investigate.
//! 2. Snapshot reconciliation — compares the loaded chainstate snapshot
//!    against the (possibly truncated) blockstore canonical chain:
//!      * empty store + dirty snapshot → reset snapshot to empty;
//!      * empty store + empty snapshot → no-op;
//!      * snapshot at height H, canonical(H) == snapshot.tip → replay
//!        canonical blocks from H+1 to tip;
//!      * canonical(H) ≠ snapshot.tip OR snapshot.height > tip → reset
//!        snapshot and replay from genesis.
//!
//! Replay reuses `ChainState::connect_block_with_core_ext_deployments_
//! and_suite_context`, the same entry point the live sync engine uses,
//! so consensus rules during reconcile match consensus rules during
//! steady-state sync.
//!
//! # Out of scope
//!
//! - fsync durability (closed by `E.1`, PR #1218)
//! - atomic canonical commit semantics (closed by `E.4`, already
//!   merged via PR #1211)
//! - WAL / snapshot-cadence redesign
//! - Any non-startup runtime reconciliation (the live sync engine
//!   handles steady-state mismatch through reorg / disconnect paths).

use crate::blockstore::BlockStore;
use crate::chainstate::{ChainState, ChainStateConnectSummary};
use crate::sync::SyncConfig;
use rubin_consensus::parse_block_header_bytes;

/// Snapshot cadence: persist `ChainState` to disk on every block until
/// the UTxO set crosses [`CHAIN_STATE_SNAPSHOT_SMALL_UTXO_CUTOFF`], then
/// throttle to once every [`CHAIN_STATE_SNAPSHOT_INTERVAL_BLOCKS`]
/// blocks. Mirrors Go `chainStateSnapshotIntervalBlocks` in
/// `clients/go/node/chainstate_recovery.go`.
pub const CHAIN_STATE_SNAPSHOT_INTERVAL_BLOCKS: u64 = 32;

/// At or below this UTxO-set size the snapshot is small enough that
/// per-block save cost is negligible; persist on every block to
/// minimise the post-crash replay window. The gate is inclusive
/// (`<= CHAIN_STATE_SNAPSHOT_SMALL_UTXO_CUTOFF`) — matching Go's
/// `chainStateSnapshotSmallUtxoCutoff` comparison shape.
pub const CHAIN_STATE_SNAPSHOT_SMALL_UTXO_CUTOFF: u64 = 4096;

/// Decide whether the apply-block hot path should persist the
/// `ChainState` snapshot to disk after the current block. Mirrors Go
/// `shouldPersistChainStateSnapshot` (`clients/go/node/chainstate_recovery.go`):
///
/// * `state == None` or `summary == None` → fail-closed, persist.
/// * tipless state OR `block_height == 0` → seed first snapshot.
/// * UTxO count `<= CHAIN_STATE_SNAPSHOT_SMALL_UTXO_CUTOFF` → persist
///   every block (cheap snapshot, small replay window).
/// * Otherwise persist only when `block_height` is a multiple of
///   `CHAIN_STATE_SNAPSHOT_INTERVAL_BLOCKS`.
///
/// Boundary saves outside the apply-block hot path
/// (`SyncEngine::disconnect_tip`, reorg rollback, miner publish, and
/// the startup E.2 reconcile in `main.rs`) call `ChainState::save`
/// directly and are NOT gated by this policy: shutdown / reorg /
/// explicit-flush durability is preserved.
pub(crate) fn should_persist_chainstate_snapshot(
    state: Option<&ChainState>,
    summary: Option<&ChainStateConnectSummary>,
) -> bool {
    let (Some(state), Some(summary)) = (state, summary) else {
        return true;
    };
    if !state.has_tip || summary.block_height == 0 {
        return true;
    }
    if (state.utxos.len() as u64) <= CHAIN_STATE_SNAPSHOT_SMALL_UTXO_CUTOFF {
        return true;
    }
    summary.block_height % CHAIN_STATE_SNAPSHOT_INTERVAL_BLOCKS == 0
}

/// Walk the canonical index forward; for every canonical hash, verify
/// the matching header file, block-bytes file, and undo file all exist
/// on disk and (for undo) parse cleanly. On the first missing
/// artifact, truncate the canonical index to the prefix that was
/// fully present. Returns `Ok(true)` if a truncate happened,
/// `Ok(false)` if the index was already complete.
///
/// Errors propagate from (one bullet per `?`-site in the body so the
/// doc enumeration matches the actual exit set):
///   * `BlockStore::canonical_hash(height)` propagation, plus the
///     internal "canonical index hole at height N during truncate
///     scan" error if the index has a gap below `canonical_len`
///     (a corrupt `blockstore-index.json`);
///   * `try_has_block` / `try_has_block_data` / `try_has_undo`
///     metadata failures — i.e. EACCES / EIO / ENOTDIR on the parent
///     directory or on the artifact itself, surfaced as
///     `stat <path>: <err>`. NotFound is intentionally NOT propagated
///     here: it converts to `Ok(false)` and triggers truncate;
///   * `get_header_by_hash` / `get_block_by_hash` read failures on
///     present-but-unreadable artifact files (the follow-up `get_*`
///     call after `try_has_*` confirms presence — corruption /
///     EACCES on the file itself surfaces here). The threat-model
///     assumption (no concurrent reconcile, no external process
///     mutating BlockStore files mid-call) means a NotFound at this
///     point is a hard error: it implies an external delete between
///     `try_has_*` and `get_*_by_hash`, which violates the contract;
///   * `get_undo` parse failure on a present-and-readable but
///     unparseable undo JSON (operator must investigate);
///   * `BlockStore::truncate_canonical` failure when the prefix
///     write back to the index file fails.
///
/// Mirrors the Go `truncateIncompleteCanonicalSuffix` helper.
pub(crate) fn truncate_incomplete_canonical_suffix(store: &mut BlockStore) -> Result<bool, String> {
    // Iterate by height instead of cloning the entire canonical
    // index via `canonical_suffix_from(0)` — that allocation is
    // O(chain_height) bytes for a one-shot scan that only needs
    // height-by-height access. `canonical_hash` reads each entry
    // in place; `canonical_len` gives the bound.
    let canonical_len = store.canonical_len();
    let mut valid_count: usize = 0;
    for height in 0..canonical_len {
        let block_hash = store.canonical_hash(height as u64)?.ok_or_else(|| {
            format!("canonical index hole at height {height} during truncate scan")
        })?;
        // Use the fallible `try_has_*` probes so a metadata-level
        // failure (EACCES, EIO, ENOTDIR on parent) propagates as a
        // HARD startup error instead of silently looking like
        // "missing file → truncate". The boolean `Path::exists()`
        // siblings cannot distinguish those classes from NotFound
        // and would lose canonical suffix on transient I/O —
        // mismatching Go's `errors.Is(err, os.ErrNotExist)` semantics
        // and the operator contract documented at the module level.
        // After existence is confirmed, the follow-up `get_*_by_hash`
        // read propagates corruption / EACCES on the artifact file
        // itself.
        if !store.try_has_block(block_hash)? {
            break;
        }
        store.get_header_by_hash(block_hash)?;
        if !store.try_has_block_data(block_hash)? {
            break;
        }
        store.get_block_by_hash(block_hash)?;
        if !store.try_has_undo(block_hash)? {
            break;
        }
        store.get_undo(block_hash)?;
        valid_count += 1;
    }
    if valid_count == canonical_len {
        return Ok(false);
    }
    store.truncate_canonical(valid_count)?;
    Ok(true)
}

/// Reconcile the persisted chainstate snapshot against the on-disk
/// canonical chain in `store`. Returns `Ok(true)` if any repair was
/// applied (truncate, reset, or replay), `Ok(false)` if both inputs
/// already agreed.
///
/// Repair sequence (mirrors Go `ReconcileChainStateWithBlockStore`):
///
/// 1. `truncate_incomplete_canonical_suffix(store)` — drop any tail
///    of the canonical index that lost its block / undo files.
/// 2. If the (possibly truncated) blockstore has no tip:
///       * if `state` is also empty → no-op (`Ok(false)`),
///       * else reset `state` to empty and return `Ok(true)`.
/// 3. If `state` has a tip and `state.height <= tip_height`:
///       * if `canonical(state.height) == state.tip_hash`:
///           - if `state.height == tip_height` → no-op (caller may
///             still see `Ok(true)` if step 1 truncated),
///           - else replay forward from `state.height + 1`.
///       * else (mismatch) reset `state` and replay from height 0.
/// 4. If `state.height > tip_height` (snapshot is ahead of blockstore)
///    → reset `state` and replay from height 0.
/// 5. If `state` has no tip → reset to empty (idempotent) and replay
///    from height 0.
///
/// Replay reuses
/// `ChainState::connect_block_with_core_ext_deployments_and_suite_context`
/// so consensus checks during recovery match steady-state sync.
///
/// # Threat model
///
/// **Concurrent actors**: This is a startup-only function. Caller
/// (`main.rs`) holds an exclusive `&mut ChainState` and `&mut
/// BlockStore` before any sync engine, P2P, RPC, or miner thread
/// starts. No concurrent reconcile.
///
/// **Process crash**: The reconcile makes the disk state self-
/// consistent before the live engine runs. If the process crashes
/// mid-reconcile (e.g. between `truncate_canonical` and the replay
/// loop), the next startup re-runs reconcile from scratch — the truncate
/// is itself atomic via `write_file_atomic` on the canonical index
/// file (`E.1`), and the chainstate snapshot is re-saved by the caller
/// after reconcile returns. Re-entry is idempotent.
///
/// **Cross-platform**: All I/O goes through helpers that already abide
/// by the storage cluster's OS contracts (`O_EXCL` for temp creates,
/// `drop(fd)` before unlink on Windows in `write_and_sync_temp`,
/// best-effort `sync_dir` on permission-hardened parents).
///
/// **Retry / exhaustion**: No bounded retry inside reconcile — the
/// caller (`main.rs`) treats a reconcile error as a fatal startup
/// failure and exits with non-zero, mirroring Go's `chainstate
/// reconcile failed: %v` exit path.
///
/// **Inode / fs-layer**: Reconcile reads only — does not create new
/// files. `truncate_canonical` rewrites the canonical index via the
/// existing atomic-write helper (no shared-inode hazards).
///
/// **Durability**: After reconcile returns `Ok(true)`, the caller
/// MUST persist `chain_state.save(...)` BEFORE starting any sync
/// engine / P2P / RPC / miner thread, so a crash between
/// `truncate_canonical` (already atomic via `write_file_atomic`) and
/// the chainstate snapshot rewrite cannot expose a chainstate whose
/// claimed tip exceeds the truncated canonical index. If the caller
/// honours this ordering and crashes before save, the next startup
/// re-runs reconcile from scratch — correct, just wasteful. Mirror
/// of Go `ReconcileChainStateWithBlockStore` caller-side contract
/// in `clients/go/cmd/rubin-node/main.go`.
///
/// Mirrors the Go `ReconcileChainStateWithBlockStore` for cross-client
/// storage parity.
pub fn reconcile_chain_state_with_block_store(
    state: &mut ChainState,
    store: &mut BlockStore,
    cfg: &SyncConfig,
) -> Result<bool, String> {
    let truncated = truncate_incomplete_canonical_suffix(store)?;
    let tip = store.tip()?;
    let mut changed = truncated;

    let Some((tip_height, _tip_hash)) = tip else {
        // Empty store. Reset chainstate if it carries any state.
        if truncated
            || state.has_tip
            || state.height != 0
            || state.tip_hash != [0u8; 32]
            || state.already_generated != 0
            || !state.utxos.is_empty()
        {
            *state = ChainState::new();
            return Ok(true);
        }
        return Ok(false);
    };

    let mut replay_from: u64 = 0;
    if state.has_tip {
        if state.height <= tip_height {
            let canonical = store.canonical_hash(state.height)?;
            match canonical {
                Some(canonical_hash) if canonical_hash == state.tip_hash => {
                    if state.height == tip_height {
                        return Ok(changed);
                    }
                    replay_from = state.height + 1;
                }
                _ => {
                    *state = ChainState::new();
                    changed = true;
                }
            }
        } else {
            *state = ChainState::new();
            changed = true;
        }
    } else {
        *state = ChainState::new();
        changed = true;
    }

    // Hoist rotation / registry resolution out of the replay loop —
    // `cfg.suite_context` is immutable for the lifetime of reconcile,
    // so the per-height re-borrow is wasted work on long replays.
    // The trait-erasure re-borrow has to stay even at the hoist
    // point: `SuiteContext.rotation` is stored as
    // `Arc<dyn RotationProvider + Send + Sync>` while
    // `connect_block_with_core_ext_deployments_and_suite_context`
    // takes the bare `Option<&dyn RotationProvider>` (no `+ Send +
    // Sync` bound). Without the explicit `let r: &(dyn ... + Send +
    // Sync) = ctx.rotation.as_ref();` step the compiler refuses to
    // weaken the bound through a single coercion. Same idiom
    // `SyncEngine` uses internally for the per-call re-borrow.
    let rotation: Option<&dyn rubin_consensus::RotationProvider> =
        cfg.suite_context.as_ref().map(|ctx| {
            let r: &(dyn rubin_consensus::RotationProvider + Send + Sync) = ctx.rotation.as_ref();
            r as &dyn rubin_consensus::RotationProvider
        });
    let registry = cfg.suite_context.as_ref().map(|ctx| ctx.registry.as_ref());

    for height in replay_from..=tip_height {
        // Error literal stays prefixed `missing canonical block hash
        // during chainstate replay` for log-scrape parity with Go;
        // height + tip_height suffix added in BOTH clients in the
        // same commit so operators can locate the corrupt canonical
        // entry. See Go `clients/go/node/chainstate_recovery.go`
        // ReconcileChainStateWithBlockStore for the mirror.
        let block_hash = store.canonical_hash(height)?.ok_or_else(|| {
            format!(
                "missing canonical block hash during chainstate replay at height {height} (tip_height={tip_height})"
            )
        })?;
        let block_bytes = store.get_block_by_hash(block_hash)?;
        // Defence-in-depth: re-hash the loaded block's header and
        // confirm it matches the canonical-index entry BEFORE
        // delegating to `connect_block_*`. A parseable-but-swapped
        // `<hash>.bin` (bit-rot, manual disk repair gone wrong,
        // adversarial replacement that happens to point at the
        // current tip's prev_hash) would otherwise be accepted by
        // connect_block, leaving ChainState with a tip that no
        // longer corresponds to its canonical-index entry. The
        // prev_hash chain-integrity check inside connect_block
        // catches some of this class but NOT the same-prev-hash
        // adversarial case. One hash per replay block is recovery-
        // path-only cost (N rows, not steady state). Cross-client
        // symmetric: Go `clients/go/node/chainstate_recovery.go`
        // ReconcileChainStateWithBlockStore replay loop performs
        // the bit-identical check with the same error literal.
        let parsed = rubin_consensus::parse_block_bytes(&block_bytes).map_err(|e| {
            format!("parse block bytes during chainstate replay at height {height}: {e}")
        })?;
        let observed_hash = rubin_consensus::block_hash(&parsed.header_bytes)
            .map_err(|e| format!("hash header during chainstate replay at height {height}: {e}"))?;
        if observed_hash != block_hash {
            return Err(format!(
                "canonical artifact corruption during chainstate replay at height {height}: \
                 expected {expected}, on-disk header hashes to {observed}",
                expected = hex::encode(block_hash),
                observed = hex::encode(observed_hash),
            ));
        }
        let prev_timestamps = prev_timestamps_from_store(store, height)?;
        state.connect_block_with_core_ext_deployments_and_suite_context(
            &block_bytes,
            cfg.expected_target,
            prev_timestamps.as_deref(),
            cfg.chain_id,
            &cfg.core_ext_deployments,
            rotation,
            registry,
        )?;
        changed = true;
    }
    Ok(changed)
}

/// Build the prev-timestamps window used by `connect_block` consensus
/// validation during replay. Returns up to 11 timestamps (the BIP-113
/// MTP window) for the canonical chain ending at `height - 1`. A
/// `None` return means `height == 0` (genesis), which has no prev
/// window.
///
/// Standalone helper instead of going through `SyncEngine.
/// prev_timestamps_for_height` because reconcile runs before the
/// sync engine exists; both implementations are functionally
/// identical and both will diverge into a shared helper if a third
/// caller appears.
fn prev_timestamps_from_store(store: &BlockStore, height: u64) -> Result<Option<Vec<u64>>, String> {
    if height == 0 {
        return Ok(None);
    }
    let window_len = height.min(11);
    let mut out = Vec::with_capacity(window_len as usize);
    for offset in 0..window_len {
        let h = height - 1 - offset;
        let hash = store.canonical_hash(h)?.ok_or_else(|| {
            format!(
                "missing canonical hash at height {h} for timestamp context (next_height={height})"
            )
        })?;
        let header_bytes = store.get_header_by_hash(hash)?;
        let header = parse_block_header_bytes(&header_bytes).map_err(|e| e.to_string())?;
        out.push(header.timestamp);
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::block_store_path;
    use crate::genesis::{devnet_genesis_block_bytes, devnet_genesis_chain_id};
    use crate::io_utils::unique_temp_path;
    use crate::sync::{default_sync_config, SyncEngine};
    use rubin_consensus::constants::POW_LIMIT;
    use rubin_consensus::{block_hash, parse_block_bytes};
    use std::fs;

    fn fresh_dir(prefix: &str) -> std::path::PathBuf {
        let dir = unique_temp_path(prefix);
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    fn open_store_in(dir: &std::path::Path) -> BlockStore {
        BlockStore::open(block_store_path(dir)).expect("open blockstore")
    }

    fn devnet_cfg() -> SyncConfig {
        default_sync_config(Some(POW_LIMIT), devnet_genesis_chain_id(), None)
    }

    fn apply_genesis(store: BlockStore) -> ([u8; 32], BlockStore, ChainState) {
        let cfg = devnet_cfg();
        let mut engine = SyncEngine::new(ChainState::new(), Some(store), cfg).expect("sync engine");
        engine
            .apply_block(&devnet_genesis_block_bytes(), None)
            .expect("apply_block(genesis)");
        let parsed = parse_block_bytes(&devnet_genesis_block_bytes()).expect("parse genesis bytes");
        let genesis_hash = block_hash(&parsed.header_bytes).expect("hash genesis");
        let final_state = engine.chain_state_snapshot();
        let final_store = engine.block_store_snapshot().expect("blockstore");
        (genesis_hash, final_store, final_state)
    }

    /// Input validation: nil-equivalent inputs return errors (Go
    /// `TestReconcileChainStateWithBlockStore_InputValidation*`).
    /// Rust enforces non-null via `&mut` references — compile-time
    /// check, but we still verify the empty-state noop branch and the
    /// dirty-empty-store reset branch.
    #[test]
    fn reconcile_empty_store_empty_state_is_noop() {
        let dir = fresh_dir("rubin-recover-empty");
        let mut store = open_store_in(&dir);
        let mut state = ChainState::new();
        let cfg = devnet_cfg();
        let changed =
            reconcile_chain_state_with_block_store(&mut state, &mut store, &cfg).expect("ok");
        assert!(!changed, "empty store + empty state must be a noop");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconcile_empty_store_dirty_state_resets_to_empty() {
        let dir = fresh_dir("rubin-recover-dirty");
        let mut store = open_store_in(&dir);
        let mut state = ChainState::new();
        state.has_tip = true;
        state.height = 7;
        state.tip_hash[0] = 0xaa;
        state.already_generated = 99;
        let cfg = devnet_cfg();
        let changed = reconcile_chain_state_with_block_store(&mut state, &mut store, &cfg)
            .expect("reconcile");
        assert!(changed, "dirty state with empty store must be reset");
        assert!(!state.has_tip);
        assert_eq!(state.height, 0);
        assert_eq!(state.tip_hash, [0u8; 32]);
        assert_eq!(state.already_generated, 0);
        assert!(state.utxos.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconcile_noop_when_state_matches_canonical_tip() {
        let dir = fresh_dir("rubin-recover-noop");
        let store = open_store_in(&dir);
        let (_genesis_hash, mut store, mut state) = apply_genesis(store);
        let cfg = devnet_cfg();
        let changed = reconcile_chain_state_with_block_store(&mut state, &mut store, &cfg)
            .expect("reconcile");
        assert!(!changed, "matching canonical tip must be a noop");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconcile_resets_mismatched_snapshot_at_genesis() {
        let dir = fresh_dir("rubin-recover-mismatch");
        let store = open_store_in(&dir);
        let (genesis_hash, mut store, mut state) = apply_genesis(store);
        // Corrupt the snapshot's tip hash so canonical(height) != tip.
        state.tip_hash[0] ^= 0xff;
        let cfg = devnet_cfg();
        let changed = reconcile_chain_state_with_block_store(&mut state, &mut store, &cfg)
            .expect("reconcile");
        assert!(changed, "mismatched snapshot must be reset and replayed");
        assert!(state.has_tip);
        assert_eq!(state.height, 0);
        assert_eq!(state.tip_hash, genesis_hash);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconcile_resets_ahead_snapshot() {
        let dir = fresh_dir("rubin-recover-ahead");
        let store = open_store_in(&dir);
        let (genesis_hash, mut store, mut state) = apply_genesis(store);
        // Snapshot claims a height the blockstore does not have.
        state.height = 5;
        let cfg = devnet_cfg();
        let changed = reconcile_chain_state_with_block_store(&mut state, &mut store, &cfg)
            .expect("reconcile");
        assert!(changed, "ahead snapshot must be reset and replayed");
        assert_eq!(state.height, 0);
        assert_eq!(state.tip_hash, genesis_hash);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Set up a canonical entry at height 1 whose chosen artifact is
    /// missing while the other two are present on disk. Verifies the
    /// per-artifact `break` branches inside
    /// `truncate_incomplete_canonical_suffix` (lines 96-107). `kind`
    /// selects which file to OMIT: "header" / "block_data" / "undo".
    fn synth_partial_artifact_at_height_1(
        dir: &std::path::Path,
        store: &mut BlockStore,
        omit: &str,
    ) -> [u8; 32] {
        let fake_hash: [u8; 32] = [0xee; 32];
        let bs_root = block_store_path(dir);
        let header_path = bs_root
            .join("headers")
            .join(format!("{}.bin", hex::encode(fake_hash)));
        let block_path = bs_root
            .join("blocks")
            .join(format!("{}.bin", hex::encode(fake_hash)));
        let undo_path = bs_root
            .join("undo")
            .join(format!("{}.json", hex::encode(fake_hash)));
        if omit != "header" {
            fs::write(&header_path, b"fake header bytes").expect("write header");
        }
        if omit != "block_data" {
            fs::write(&block_path, b"fake block bytes").expect("write block");
        }
        if omit != "undo" {
            // Build a real `BlockUndo` and serialise via the
            // production marshal helper so the on-disk JSON shape
            // tracks the current `BlockUndoDisk` schema; using a
            // hand-written JSON literal would silently drift on any
            // future schema change and pass for the wrong reason.
            let raw = crate::undo::marshal_block_undo(&crate::undo::BlockUndo {
                block_height: 1,
                previous_already_generated: 0,
                txs: Vec::new(),
            })
            .expect("marshal undo");
            fs::write(&undo_path, &raw).expect("write undo");
        }
        store
            .set_canonical_tip(1, fake_hash)
            .expect("set_canonical_tip");
        fake_hash
    }

    /// Multi-block forward replay: snapshot is at height 1 with the
    /// matching canonical hash, blockstore has tip at height 2 →
    /// reconcile replays just block #2 (covers L213
    /// `replay_from = state.height + 1` and L276-286 prev_timestamps
    /// body for height >= 2).
    #[test]
    fn reconcile_replays_forward_from_matching_lower_height() {
        use crate::test_helpers::{coinbase_only_block_with_gen, height_one_coinbase_only_block};
        let dir = fresh_dir("rubin-recover-fwd-replay");
        let store = open_store_in(&dir);
        let cfg = devnet_cfg();
        let mut engine =
            SyncEngine::new(ChainState::new(), Some(store), cfg.clone()).expect("sync engine");
        // Apply genesis.
        engine
            .apply_block(&devnet_genesis_block_bytes(), None)
            .expect("apply_block(genesis)");
        let g_parsed = parse_block_bytes(&devnet_genesis_block_bytes()).expect("parse genesis");
        let g_hash = block_hash(&g_parsed.header_bytes).expect("hash genesis");
        let g_ts = g_parsed.header.timestamp;
        // Apply block 1.
        let block1 = height_one_coinbase_only_block(g_hash, g_ts + 1);
        engine.apply_block(&block1, None).expect("apply_block(1)");
        let b1_parsed = parse_block_bytes(&block1).expect("parse block1");
        let b1_hash = block_hash(&b1_parsed.header_bytes).expect("hash block1");
        let b1_ts = b1_parsed.header.timestamp;
        // Apply block 2 — provide the post-block-1 already_generated
        // so the coinbase subsidy stays within consensus bounds.
        let post_b1_already_gen = engine.chain_state_snapshot().already_generated;
        let block2 = coinbase_only_block_with_gen(2, post_b1_already_gen, b1_hash, b1_ts + 1);
        engine.apply_block(&block2, None).expect("apply_block(2)");
        let b2_parsed = parse_block_bytes(&block2).expect("parse block2");
        let b2_hash = block_hash(&b2_parsed.header_bytes).expect("hash block2");

        let mut store = engine.block_store_snapshot().expect("blockstore");
        // Build a stale snapshot at height 1 with matching canonical
        // hash by replaying genesis + block1 onto a fresh ChainState —
        // mirrors the intermediate state apply_block produced before
        // block2. Reconcile must keep this state intact and replay
        // only block 2.
        let mut state = ChainState::new();
        state
            .connect_block_with_core_ext_deployments_and_suite_context(
                &devnet_genesis_block_bytes(),
                cfg.expected_target,
                None,
                cfg.chain_id,
                &cfg.core_ext_deployments,
                None,
                None,
            )
            .expect("seed genesis");
        state
            .connect_block_with_core_ext_deployments_and_suite_context(
                &block1,
                cfg.expected_target,
                Some(&[g_ts]),
                cfg.chain_id,
                &cfg.core_ext_deployments,
                None,
                None,
            )
            .expect("seed block1");
        // Sanity-check the seeded snapshot matches the canonical hash
        // at height 1 so reconcile takes the forward-replay path
        // instead of resetting.
        assert_eq!(state.height, 1);
        assert_eq!(state.tip_hash, b1_hash);

        let changed = reconcile_chain_state_with_block_store(&mut state, &mut store, &cfg)
            .expect("reconcile");
        assert!(changed, "stale-at-1 snapshot must replay block 2");
        assert_eq!(state.height, 2);
        assert_eq!(state.tip_hash, b2_hash);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Bit-rot / file-swap defence: a parseable-but-wrong
    /// `<hash>.bin` MUST be rejected by reconcile's re-hash check
    /// before delegating to `connect_block_*`. Replace block 1's
    /// payload with block 2's bytes (parseable, links to b1_hash as
    /// prev_hash so chain-integrity passes — only re-hash catches
    /// the swap), and assert reconcile returns
    /// `canonical artifact corruption ... at height 1`. Mirror of
    /// Go `TestReconcileChainStateWithBlockStore_PropagatesCorruptBlockBytesSwap`.
    #[test]
    fn reconcile_propagates_corrupt_canonical_block_artifact() {
        use crate::test_helpers::{coinbase_only_block_with_gen, height_one_coinbase_only_block};
        let dir = fresh_dir("rubin-recover-corrupt-block");
        let store = open_store_in(&dir);
        let cfg = devnet_cfg();
        let mut engine =
            SyncEngine::new(ChainState::new(), Some(store), cfg.clone()).expect("sync engine");
        engine
            .apply_block(&devnet_genesis_block_bytes(), None)
            .expect("apply_block(genesis)");
        let g_parsed = parse_block_bytes(&devnet_genesis_block_bytes()).expect("parse genesis");
        let g_hash = block_hash(&g_parsed.header_bytes).expect("hash genesis");
        let g_ts = g_parsed.header.timestamp;
        let block1 = height_one_coinbase_only_block(g_hash, g_ts + 1);
        engine.apply_block(&block1, None).expect("apply_block(1)");
        let b1_parsed = parse_block_bytes(&block1).expect("parse b1");
        let b1_hash = block_hash(&b1_parsed.header_bytes).expect("hash b1");
        let post_b1_already_gen = engine.chain_state_snapshot().already_generated;
        let block2 = coinbase_only_block_with_gen(
            2,
            post_b1_already_gen,
            b1_hash,
            b1_parsed.header.timestamp + 1,
        );
        // Overwrite `<b1_hash>.bin` block-bytes with block2 bytes —
        // parseable, but header hashes to b2_hash, NOT b1_hash.
        let bs_root = block_store_path(&dir);
        let b1_block_path = bs_root
            .join("blocks")
            .join(format!("{}.bin", hex::encode(b1_hash)));
        fs::write(&b1_block_path, &block2).expect("overwrite b1 block bytes");

        let mut store = engine.block_store_snapshot().expect("blockstore");
        let mut state = ChainState::new();
        state
            .connect_block_with_core_ext_deployments_and_suite_context(
                &devnet_genesis_block_bytes(),
                cfg.expected_target,
                None,
                cfg.chain_id,
                &cfg.core_ext_deployments,
                None,
                None,
            )
            .expect("seed genesis");
        let result = reconcile_chain_state_with_block_store(&mut state, &mut store, &cfg);
        match result {
            Err(msg) => assert!(
                msg.contains("canonical artifact corruption") && msg.contains("at height 1"),
                "expected corruption error mentioning height 1, got {msg}"
            ),
            Ok(_) => panic!("expected reconcile to reject corrupt block-bytes file"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// Pin `prev_timestamps_from_store` against `SyncEngine::
    /// prev_timestamps_for_height` so the two implementations stay
    /// in lockstep. Builds 4 blocks (genesis + 3) so window_len
    /// reaches 3 (still below the 11-cap, but exercises the loop
    /// body more than once) and asserts both functions produce
    /// byte-identical `Vec<u64>` for the same `(store, height)`.
    #[test]
    fn prev_timestamps_from_store_matches_sync_engine() {
        use crate::test_helpers::{coinbase_only_block_with_gen, height_one_coinbase_only_block};
        let dir = fresh_dir("rubin-recover-prev-ts-parity");
        let store = open_store_in(&dir);
        let cfg = devnet_cfg();
        let mut engine =
            SyncEngine::new(ChainState::new(), Some(store), cfg.clone()).expect("sync engine");
        engine
            .apply_block(&devnet_genesis_block_bytes(), None)
            .expect("apply_block(genesis)");
        let g_parsed = parse_block_bytes(&devnet_genesis_block_bytes()).expect("parse genesis");
        let g_hash = block_hash(&g_parsed.header_bytes).expect("hash genesis");
        let g_ts = g_parsed.header.timestamp;
        let block1 = height_one_coinbase_only_block(g_hash, g_ts + 1);
        engine.apply_block(&block1, None).expect("apply_block(1)");
        let b1_parsed = parse_block_bytes(&block1).expect("parse b1");
        let b1_hash = block_hash(&b1_parsed.header_bytes).expect("hash b1");
        let post_b1_gen = engine.chain_state_snapshot().already_generated;
        let block2 =
            coinbase_only_block_with_gen(2, post_b1_gen, b1_hash, b1_parsed.header.timestamp + 1);
        engine.apply_block(&block2, None).expect("apply_block(2)");
        let b2_parsed = parse_block_bytes(&block2).expect("parse b2");
        let b2_hash = block_hash(&b2_parsed.header_bytes).expect("hash b2");
        let post_b2_gen = engine.chain_state_snapshot().already_generated;
        let block3 =
            coinbase_only_block_with_gen(3, post_b2_gen, b2_hash, b2_parsed.header.timestamp + 1);
        engine.apply_block(&block3, None).expect("apply_block(3)");

        let store = engine.block_store_snapshot().expect("blockstore");
        // Compare both helpers at every reachable height.
        for h in 0..=3u64 {
            let ours = prev_timestamps_from_store(&store, h).expect("ours");
            let theirs = engine.prev_timestamps_for_height(h).expect("theirs");
            assert_eq!(ours, theirs, "prev_timestamps mismatch at height {h}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconcile_truncates_when_block_data_missing() {
        let dir = fresh_dir("rubin-recover-trunc-block");
        let store = open_store_in(&dir);
        let (genesis_hash, mut store, mut state) = apply_genesis(store);
        // Header + undo present, block_data missing → truncate at L101.
        let _fake = synth_partial_artifact_at_height_1(&dir, &mut store, "block_data");
        state.height = 0;
        state.tip_hash = genesis_hash;
        let cfg = devnet_cfg();
        let changed = reconcile_chain_state_with_block_store(&mut state, &mut store, &cfg)
            .expect("reconcile");
        assert!(changed);
        let tip = store.tip().expect("tip").expect("has tip");
        assert_eq!(tip.0, 0);
        assert_eq!(tip.1, genesis_hash);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconcile_truncates_when_undo_missing() {
        let dir = fresh_dir("rubin-recover-trunc-undo");
        let store = open_store_in(&dir);
        let (genesis_hash, mut store, mut state) = apply_genesis(store);
        // Header + block_data present, undo missing → truncate at L105.
        let _fake = synth_partial_artifact_at_height_1(&dir, &mut store, "undo");
        state.height = 0;
        state.tip_hash = genesis_hash;
        let cfg = devnet_cfg();
        let changed = reconcile_chain_state_with_block_store(&mut state, &mut store, &cfg)
            .expect("reconcile");
        assert!(changed);
        let tip = store.tip().expect("tip").expect("has tip");
        assert_eq!(tip.0, 0);
        assert_eq!(tip.1, genesis_hash);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconcile_resets_tipless_dirty_state_with_canonical_chain() {
        let dir = fresh_dir("rubin-recover-tipless");
        let store = open_store_in(&dir);
        let (genesis_hash, mut store, _) = apply_genesis(store);
        // Build a fresh dirty-but-tipless state: has_tip=false but
        // utxos non-empty (the "stale dirty snapshot" residue path).
        // This forces the `else` branch at lines 224-226 (reset to
        // empty + replay from 0).
        let mut state = ChainState::new();
        state.utxos.insert(
            rubin_consensus::Outpoint {
                txid: [0x33; 32],
                vout: 0,
            },
            rubin_consensus::UtxoEntry {
                value: 1,
                covenant_type: 0,
                covenant_data: Vec::new(),
                creation_height: 0,
                created_by_coinbase: false,
            },
        );
        let cfg = devnet_cfg();
        let changed = reconcile_chain_state_with_block_store(&mut state, &mut store, &cfg)
            .expect("reconcile");
        assert!(changed, "tipless dirty state must be reset and replayed");
        assert!(state.has_tip);
        assert_eq!(state.tip_hash, genesis_hash);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Regression for the Codex P1 + Copilot P0 wave on PR #1221:
    /// a metadata-level error on the canonical artifact (EACCES on
    /// parent dir) MUST propagate as `Err(...)` from
    /// `truncate_incomplete_canonical_suffix`, NOT silently be
    /// interpreted as "missing → truncate". Unix-only because the
    /// repro uses chmod 0; skipped under root.
    #[cfg(unix)]
    #[test]
    fn truncate_propagates_metadata_eacces_instead_of_silent_truncate() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_dir("rubin-recover-eacces");
        let store = open_store_in(&dir);
        let (_genesis_hash, mut store, _state) = apply_genesis(store);
        // Promote canonical to a fake height-1 entry whose artifact
        // dir we will chmod 0o000 to force EACCES on metadata().
        let fake_hash: [u8; 32] = [0x77; 32];
        let bs_root = block_store_path(&dir);
        let header_path = bs_root
            .join("headers")
            .join(format!("{}.bin", hex::encode(fake_hash)));
        fs::write(&header_path, b"fake header").expect("write header");
        store
            .set_canonical_tip(1, fake_hash)
            .expect("set_canonical_tip");
        let headers_dir = bs_root.join("headers");
        let original_perm = fs::metadata(&headers_dir).expect("stat dir").permissions();
        fs::set_permissions(&headers_dir, fs::Permissions::from_mode(0o000)).expect("chmod 0");
        // Detect root (or any environment that bypasses chmod) by
        // checking whether metadata still succeeds — if it does, the
        // test cannot reproduce EACCES, so skip the assertion to
        // avoid a false negative under sudo / CI containers.
        if fs::metadata(&header_path).is_ok() {
            let _ = fs::set_permissions(&headers_dir, original_perm);
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        let result = truncate_incomplete_canonical_suffix(&mut store);
        // Restore perms before any panic so cleanup works.
        let _ = fs::set_permissions(&headers_dir, original_perm);
        match result {
            Err(msg) => {
                assert!(
                    msg.contains("stat ") || msg.contains("Permission") || msg.contains("denied"),
                    "expected propagated metadata error, got {msg}"
                );
            }
            Ok(truncated) => panic!(
                "EACCES on metadata MUST propagate, not silent truncate (got Ok({truncated}))"
            ),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconcile_truncates_incomplete_canonical_suffix() {
        let dir = fresh_dir("rubin-recover-truncate");
        let store = open_store_in(&dir);
        let (genesis_hash, mut store, mut state) = apply_genesis(store);
        // Synthesise a canonical entry at height 1 whose artifacts are
        // missing. We use `BlockStore::set_canonical_tip` with a hash
        // that has no header / block / undo files on disk — exactly
        // the residue a crash between artifact write and tip advance
        // would leave.
        let fake_hash: [u8; 32] = [0x99; 32];
        store
            .set_canonical_tip(1, fake_hash)
            .expect("set_canonical_tip");
        // Reset the snapshot so reconcile must repair the truncation.
        let stale_state = state.clone();
        state.height = 0;
        state.tip_hash = genesis_hash;
        let cfg = devnet_cfg();
        let changed = reconcile_chain_state_with_block_store(&mut state, &mut store, &cfg)
            .expect("reconcile");
        assert!(
            changed,
            "incomplete canonical suffix must trigger truncate + change report"
        );
        // After truncate, blockstore tip falls back to genesis.
        let tip = store.tip().expect("tip").expect("has tip");
        assert_eq!(tip.0, 0);
        assert_eq!(tip.1, genesis_hash);
        // Snapshot ends at genesis, identical to pre-set-canonical.
        assert_eq!(state.height, 0);
        assert_eq!(state.tip_hash, genesis_hash);
        // Stale snapshot is unused after the test — silence dead-code.
        drop(stale_state);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Cross-client cadence parity: cell-by-cell mirror of Go
    /// `TestShouldPersistChainStateSnapshotCadence` in
    /// `clients/go/node/chainstate_recovery_test.go`. Any divergence
    /// here means Rust apply_block hot-path saves drift away from Go.
    #[test]
    fn should_persist_chainstate_snapshot_cadence() {
        // Nil-equivalent inputs → fail-closed persist.
        assert!(
            should_persist_chainstate_snapshot(None, None),
            "missing state+summary must persist (fail-closed)"
        );

        // Tipless state seeds the first snapshot regardless of height.
        let empty = ChainState::new();
        assert!(
            should_persist_chainstate_snapshot(
                Some(&empty),
                Some(&ChainStateConnectSummary {
                    block_height: 1,
                    block_hash: [0u8; 32],
                    sum_fees: 0,
                    already_generated: 0,
                    already_generated_n1: 0,
                    utxo_count: 0,
                }),
            ),
            "tipless state must persist to seed first snapshot"
        );

        // Small UTxO set persists every block, even off the interval.
        let mut small = ChainState::new();
        small.has_tip = true;
        for i in 0..CHAIN_STATE_SNAPSHOT_SMALL_UTXO_CUTOFF {
            let mut txid = [0u8; 32];
            txid[0] = i as u8;
            small.utxos.insert(
                rubin_consensus::Outpoint {
                    txid,
                    vout: i as u32,
                },
                rubin_consensus::UtxoEntry {
                    value: i + 1,
                    covenant_type: 0,
                    covenant_data: Vec::new(),
                    creation_height: 0,
                    created_by_coinbase: false,
                },
            );
        }
        assert!(
            should_persist_chainstate_snapshot(
                Some(&small),
                Some(&ChainStateConnectSummary {
                    block_height: 17,
                    block_hash: [0u8; 32],
                    sum_fees: 0,
                    already_generated: 0,
                    already_generated_n1: 0,
                    utxo_count: small.utxos.len() as u64,
                }),
            ),
            "small utxo set must persist every block"
        );

        // Crossing the cutoff switches to interval-only persistence.
        let mut large = ChainState::new();
        large.has_tip = true;
        for i in 0..=CHAIN_STATE_SNAPSHOT_SMALL_UTXO_CUTOFF {
            let mut txid = [0u8; 32];
            txid[0] = i as u8;
            txid[1] = (i >> 8) as u8;
            large.utxos.insert(
                rubin_consensus::Outpoint {
                    txid,
                    vout: i as u32,
                },
                rubin_consensus::UtxoEntry {
                    value: i + 1,
                    covenant_type: 0,
                    covenant_data: Vec::new(),
                    creation_height: 0,
                    created_by_coinbase: false,
                },
            );
        }
        // Off-interval block at (interval - 1) MUST be skipped.
        assert!(
            !should_persist_chainstate_snapshot(
                Some(&large),
                Some(&ChainStateConnectSummary {
                    block_height: CHAIN_STATE_SNAPSHOT_INTERVAL_BLOCKS - 1,
                    block_hash: [0u8; 32],
                    sum_fees: 0,
                    already_generated: 0,
                    already_generated_n1: 0,
                    utxo_count: large.utxos.len() as u64,
                }),
            ),
            "large utxo set must skip non-interval snapshots"
        );
        // Interval boundary triggers the throttled persist.
        assert!(
            should_persist_chainstate_snapshot(
                Some(&large),
                Some(&ChainStateConnectSummary {
                    block_height: CHAIN_STATE_SNAPSHOT_INTERVAL_BLOCKS,
                    block_hash: [0u8; 32],
                    sum_fees: 0,
                    already_generated: 0,
                    already_generated_n1: 0,
                    utxo_count: large.utxos.len() as u64,
                }),
            ),
            "large utxo set must persist on interval boundary"
        );
        // height == 0 always seeds (genesis snapshot).
        assert!(
            should_persist_chainstate_snapshot(
                Some(&large),
                Some(&ChainStateConnectSummary {
                    block_height: 0,
                    block_hash: [0u8; 32],
                    sum_fees: 0,
                    already_generated: 0,
                    already_generated_n1: 0,
                    utxo_count: large.utxos.len() as u64,
                }),
            ),
            "height zero summary must persist"
        );
    }

    /// Boundary contract: even with the apply-block save gated, the
    /// pre-existing E.2 startup reconcile path (`main.rs` calling
    /// `chain_state.save` after `reconcile_chain_state_with_block_store`)
    /// continues to land a snapshot on disk. This test pins the
    /// reconcile + explicit-save sequence end-to-end so a future change
    /// to the apply-block gate cannot silently break the explicit-flush
    /// boundary contract documented on `should_persist_chainstate_snapshot`.
    #[test]
    fn reconcile_then_explicit_save_persists_snapshot_independent_of_gate() {
        let dir = fresh_dir("rubin-recover-explicit-save");
        let chain_state_file = crate::chainstate::chain_state_path(&dir);
        let store = open_store_in(&dir);
        let (_genesis_hash, mut store, mut state) = apply_genesis(store);
        // Force the gate to its "skip" branch by faking a large UTxO
        // set + off-interval height; reconcile + explicit save must
        // STILL land the snapshot.
        for i in 0..=CHAIN_STATE_SNAPSHOT_SMALL_UTXO_CUTOFF {
            let mut txid = [0u8; 32];
            txid[0] = i as u8;
            txid[1] = (i >> 8) as u8;
            state.utxos.insert(
                rubin_consensus::Outpoint {
                    txid,
                    vout: i as u32,
                },
                rubin_consensus::UtxoEntry {
                    value: i + 1,
                    covenant_type: 0,
                    covenant_data: Vec::new(),
                    creation_height: 0,
                    created_by_coinbase: false,
                },
            );
        }
        let cfg = devnet_cfg();
        // Reconcile is a noop here (genesis tip already matches), but
        // the explicit save AFTER it is the durability point.
        let _ = reconcile_chain_state_with_block_store(&mut state, &mut store, &cfg)
            .expect("reconcile");
        state.save(&chain_state_file).expect("explicit save");
        assert!(
            chain_state_file.exists(),
            "explicit save outside the apply-block gate must always land"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
