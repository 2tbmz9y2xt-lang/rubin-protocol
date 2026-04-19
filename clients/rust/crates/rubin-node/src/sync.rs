use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rubin_consensus::constants::POW_LIMIT;
use rubin_consensus::{
    block_hash, parse_block_bytes, parse_block_header_bytes, CoreExtDeploymentProfiles,
};
use rubin_consensus::{RotationProvider, SuiteRegistry};

use crate::blockstore::BlockStore;
use crate::chainstate::{ChainState, ChainStateConnectSummary};
use crate::chainstate_recovery::should_persist_chainstate_snapshot;
use crate::undo::build_block_undo;

pub const DEFAULT_IBD_LAG_SECONDS: u64 = 24 * 60 * 60;
const DEFAULT_HEADER_BATCH_LIMIT: u64 = 512;
const DEFAULT_PV_SHADOW_MAX_SAMPLES: u64 = 3;
const MAX_PV_SHADOW_MAX_SAMPLES: u64 = 10_000;

#[derive(Clone, Debug)]
pub struct SyncConfig {
    pub header_batch_limit: u64,
    pub ibd_lag_seconds: u64,
    pub expected_target: Option<[u8; 32]>,
    pub chain_id: [u8; 32],
    pub chain_state_path: Option<PathBuf>,
    pub network: String,
    pub core_ext_deployments: CoreExtDeploymentProfiles,
    pub suite_context: Option<SuiteContext>,
    pub parallel_validation_mode: String,
    pub pv_shadow_max_samples: u64,
}

#[derive(Clone)]
pub struct SuiteContext {
    pub rotation: Arc<dyn RotationProvider + Send + Sync>,
    pub registry: Arc<SuiteRegistry>,
}

impl std::fmt::Debug for SuiteContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuiteContext")
            .field("rotation", &"<dyn RotationProvider>")
            .field("registry", &self.registry)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParallelValidationMode {
    Off,
    Shadow,
    On,
}

impl ParallelValidationMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
            Self::On => "on",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PVTelemetrySnapshot {
    pub mode: String,
    pub blocks_validated: u64,
    pub blocks_skipped: u64,
    pub mismatch_verdict: u64,
    pub mismatch_error: u64,
    pub mismatch_state: u64,
    pub mismatch_witness: u64,
    pub sig_total: u64,
    pub sig_cache_hits: u64,
    pub worker_tasks_total: u64,
    pub worker_panics: u64,
    pub validate_count: u64,
    pub validate_avg_ns: u64,
    pub commit_count: u64,
    pub commit_avg_ns: u64,
}

impl PVTelemetrySnapshot {
    pub fn prometheus_lines(&self) -> Vec<String> {
        vec![
            "# HELP rubin_pv_mode Current parallel validation mode (0=off, 1=shadow, 2=on)."
                .to_string(),
            "# TYPE rubin_pv_mode gauge".to_string(),
            format!("rubin_pv_mode{{mode=\"{}\"}} 1", self.mode),
            "# HELP rubin_pv_blocks_validated_total Blocks processed through PV path.".to_string(),
            "# TYPE rubin_pv_blocks_validated_total counter".to_string(),
            format!("rubin_pv_blocks_validated_total {}", self.blocks_validated),
            "# HELP rubin_pv_blocks_skipped_total Blocks skipped (mode=off or not in IBD)."
                .to_string(),
            "# TYPE rubin_pv_blocks_skipped_total counter".to_string(),
            format!("rubin_pv_blocks_skipped_total {}", self.blocks_skipped),
            "# HELP rubin_pv_shadow_mismatches_total Shadow mismatch count by type.".to_string(),
            "# TYPE rubin_pv_shadow_mismatches_total counter".to_string(),
            format!(
                "rubin_pv_shadow_mismatches_total{{type=\"verdict\"}} {}",
                self.mismatch_verdict
            ),
            format!(
                "rubin_pv_shadow_mismatches_total{{type=\"error\"}} {}",
                self.mismatch_error
            ),
            format!(
                "rubin_pv_shadow_mismatches_total{{type=\"state\"}} {}",
                self.mismatch_state
            ),
            format!(
                "rubin_pv_shadow_mismatches_total{{type=\"witness\"}} {}",
                self.mismatch_witness
            ),
            "# HELP rubin_pv_sig_total Total PV signature checks attempted.".to_string(),
            "# TYPE rubin_pv_sig_total counter".to_string(),
            format!("rubin_pv_sig_total {}", self.sig_total),
            "# HELP rubin_pv_sig_cache_hits_total Total PV signature cache hits.".to_string(),
            "# TYPE rubin_pv_sig_cache_hits_total counter".to_string(),
            format!("rubin_pv_sig_cache_hits_total {}", self.sig_cache_hits),
            "# HELP rubin_pv_worker_tasks_total Total PV worker tasks dispatched.".to_string(),
            "# TYPE rubin_pv_worker_tasks_total counter".to_string(),
            format!("rubin_pv_worker_tasks_total {}", self.worker_tasks_total),
            "# HELP rubin_pv_worker_panics_total Total recovered PV worker panics.".to_string(),
            "# TYPE rubin_pv_worker_panics_total counter".to_string(),
            format!("rubin_pv_worker_panics_total {}", self.worker_panics),
            "# HELP rubin_pv_validate_runs_total Total PV validation runs.".to_string(),
            "# TYPE rubin_pv_validate_runs_total counter".to_string(),
            format!("rubin_pv_validate_runs_total {}", self.validate_count),
            "# HELP rubin_pv_validate_avg_ns Average PV validation latency in nanoseconds."
                .to_string(),
            "# TYPE rubin_pv_validate_avg_ns gauge".to_string(),
            format!("rubin_pv_validate_avg_ns {}", self.validate_avg_ns),
            "# HELP rubin_pv_commit_runs_total Total PV commit runs.".to_string(),
            "# TYPE rubin_pv_commit_runs_total counter".to_string(),
            format!("rubin_pv_commit_runs_total {}", self.commit_count),
            "# HELP rubin_pv_commit_avg_ns Average PV commit latency in nanoseconds.".to_string(),
            "# TYPE rubin_pv_commit_avg_ns gauge".to_string(),
            format!("rubin_pv_commit_avg_ns {}", self.commit_avg_ns),
        ]
    }
}

#[derive(Clone, Debug)]
struct PVTelemetry {
    mode: ParallelValidationMode,
    blocks_validated: u64,
    blocks_skipped: u64,
    mismatch_verdict: u64,
    mismatch_error: u64,
    mismatch_state: u64,
    worker_panics: u64,
    validate_count: u64,
    validate_total_ns: u128,
    commit_count: u64,
    commit_total_ns: u128,
}

impl PVTelemetry {
    fn new(mode: ParallelValidationMode) -> Self {
        Self {
            mode,
            blocks_validated: 0,
            blocks_skipped: 0,
            mismatch_verdict: 0,
            mismatch_error: 0,
            mismatch_state: 0,
            worker_panics: 0,
            validate_count: 0,
            validate_total_ns: 0,
            commit_count: 0,
            commit_total_ns: 0,
        }
    }

    fn record_block_validated(&mut self) {
        self.blocks_validated = self.blocks_validated.saturating_add(1);
    }

    fn record_block_skipped(&mut self) {
        self.blocks_skipped = self.blocks_skipped.saturating_add(1);
    }

    fn record_mismatch_verdict(&mut self) {
        self.mismatch_verdict = self.mismatch_verdict.saturating_add(1);
    }

    fn record_mismatch_error(&mut self) {
        self.mismatch_error = self.mismatch_error.saturating_add(1);
    }

    fn record_mismatch_state(&mut self) {
        self.mismatch_state = self.mismatch_state.saturating_add(1);
    }

    fn record_worker_panic(&mut self) {
        self.worker_panics = self.worker_panics.saturating_add(1);
    }

    fn record_validate_latency(&mut self, latency: Duration) {
        self.validate_count = self.validate_count.saturating_add(1);
        self.validate_total_ns = self.validate_total_ns.saturating_add(latency.as_nanos());
    }

    fn record_commit_latency(&mut self, latency: Duration) {
        self.commit_count = self.commit_count.saturating_add(1);
        self.commit_total_ns = self.commit_total_ns.saturating_add(latency.as_nanos());
    }

    fn snapshot(&self) -> PVTelemetrySnapshot {
        let validate_avg_ns = averaged_latency_ns(self.validate_total_ns, self.validate_count);
        let commit_avg_ns = averaged_latency_ns(self.commit_total_ns, self.commit_count);
        PVTelemetrySnapshot {
            mode: self.mode.as_str().to_string(),
            blocks_validated: self.blocks_validated,
            blocks_skipped: self.blocks_skipped,
            mismatch_verdict: self.mismatch_verdict,
            mismatch_error: self.mismatch_error,
            mismatch_state: self.mismatch_state,
            mismatch_witness: 0,
            sig_total: 0,
            sig_cache_hits: 0,
            worker_tasks_total: 0,
            worker_panics: self.worker_panics,
            validate_count: self.validate_count,
            validate_avg_ns,
            commit_count: self.commit_count,
            commit_avg_ns,
        }
    }
}

fn averaged_latency_ns(total_ns: u128, count: u64) -> u64 {
    if count == 0 {
        return 0;
    }
    let avg = (total_ns / u128::from(count))
        .try_into()
        .unwrap_or(u64::MAX);
    avg.max(1)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRequest {
    pub from_hash: [u8; 32],
    pub has_from: bool,
    pub limit: u64,
}

#[derive(Debug)]
pub struct SyncEngine {
    pub(crate) chain_state: ChainState,
    pub(crate) block_store: Option<BlockStore>,
    pub(crate) cfg: SyncConfig,
    pub(crate) tip_timestamp: u64,
    pub(crate) best_known_height: u64,
    pv_mode: ParallelValidationMode,
    pv_shadow_max_samples: u64,
    pv_shadow_mismatches: u64,
    pv_shadow_samples: Vec<String>,
    pv_telemetry: PVTelemetry,
    /// Test-only: drop block_store after canonical truncate (between
    /// truncate and save) to exercise the otherwise-unreachable
    /// blockstore-missing branch in disconnect_tip's save-failure
    /// recovery.
    #[cfg(test)]
    pub(crate) drop_block_store_after_truncate: bool,
}

/// Captured state for rollback on failure during reorg.
#[derive(Clone, Debug)]
pub(crate) struct SyncRollbackState {
    pub chain_state: ChainState,
    pub canonical_len: usize,
    /// Suffix of canonical entries removed during disconnect (reorg path).
    /// For rollback: truncate canonical to `canonical_len`, then re-append
    /// this suffix.  `None` for light rollback (disconnect_tip).
    /// O(reorg_depth) instead of O(chain_height).
    pub canonical_removed_suffix: Option<Vec<String>>,
    pub tip_timestamp: u64,
    pub best_known_height: u64,
}

pub fn default_sync_config(
    expected_target: Option<[u8; 32]>,
    chain_id: [u8; 32],
    chain_state_path: Option<PathBuf>,
) -> SyncConfig {
    SyncConfig {
        header_batch_limit: DEFAULT_HEADER_BATCH_LIMIT,
        ibd_lag_seconds: DEFAULT_IBD_LAG_SECONDS,
        expected_target,
        chain_id,
        chain_state_path,
        network: "devnet".to_string(),
        core_ext_deployments: CoreExtDeploymentProfiles::empty(),
        suite_context: None,
        parallel_validation_mode: "off".to_string(),
        pv_shadow_max_samples: DEFAULT_PV_SHADOW_MAX_SAMPLES,
    }
}

impl SyncEngine {
    pub(crate) fn suite_context(&self) -> (Option<&dyn RotationProvider>, Option<&SuiteRegistry>) {
        match self.cfg.suite_context.as_ref() {
            Some(ctx) => (Some(ctx.rotation.as_ref()), Some(ctx.registry.as_ref())),
            None => (None, None),
        }
    }

    pub fn new(
        chain_state: ChainState,
        block_store: Option<BlockStore>,
        mut cfg: SyncConfig,
    ) -> Result<Self, String> {
        // Defence-in-depth re-check on the final `SyncConfig` actually
        // used to construct the engine — catches any mutation of cfg
        // between the authoritative early guard in `main.rs` (run BEFORE
        // reconcile) and engine construction. For callers that construct
        // `SyncEngine` directly (tests, embedded uses) this is the ONLY
        // guard. Devnet / test networks no-op; guard itself is idempotent.
        validate_mainnet_genesis_guard(&cfg)?;
        if cfg.header_batch_limit == 0 {
            cfg.header_batch_limit = DEFAULT_HEADER_BATCH_LIMIT;
        }
        if cfg.ibd_lag_seconds == 0 {
            cfg.ibd_lag_seconds = DEFAULT_IBD_LAG_SECONDS;
        }
        cfg.parallel_validation_mode =
            normalize_parallel_validation_mode(&cfg.parallel_validation_mode);
        if cfg.pv_shadow_max_samples == 0 {
            cfg.pv_shadow_max_samples = DEFAULT_PV_SHADOW_MAX_SAMPLES;
        }
        cfg.pv_shadow_max_samples = cfg.pv_shadow_max_samples.min(MAX_PV_SHADOW_MAX_SAMPLES);
        let pv_mode = parse_parallel_validation_mode(&cfg.parallel_validation_mode)?;
        let pv_shadow_max_samples = cfg.pv_shadow_max_samples;
        let tip_timestamp = load_persisted_tip_timestamp(&chain_state, block_store.as_ref())?;
        let best_known_height = if chain_state.has_tip {
            chain_state.height
        } else {
            0
        };
        Ok(Self {
            chain_state,
            block_store,
            cfg,
            tip_timestamp,
            best_known_height,
            pv_mode,
            pv_shadow_max_samples,
            pv_shadow_mismatches: 0,
            pv_shadow_samples: Vec::new(),
            pv_telemetry: PVTelemetry::new(pv_mode),
            #[cfg(test)]
            drop_block_store_after_truncate: false,
        })
    }

    pub fn header_sync_request(&self) -> HeaderRequest {
        if !self.chain_state.has_tip {
            return HeaderRequest {
                from_hash: [0u8; 32],
                has_from: false,
                limit: self.cfg.header_batch_limit,
            };
        }
        HeaderRequest {
            from_hash: self.chain_state.tip_hash,
            has_from: true,
            limit: self.cfg.header_batch_limit,
        }
    }

    pub fn record_best_known_height(&mut self, height: u64) {
        if height > self.best_known_height {
            self.best_known_height = height;
        }
    }

    pub fn best_known_height(&self) -> u64 {
        self.best_known_height
    }

    pub fn chain_state_snapshot(&self) -> ChainState {
        self.chain_state.clone()
    }

    pub fn chain_id(&self) -> [u8; 32] {
        self.cfg.chain_id
    }

    pub fn block_store_snapshot(&self) -> Option<BlockStore> {
        self.block_store.clone()
    }

    pub fn core_ext_deployments(&self) -> CoreExtDeploymentProfiles {
        self.cfg.core_ext_deployments.clone()
    }

    pub fn tip(&self) -> Result<Option<(u64, [u8; 32])>, String> {
        if let Some(block_store) = self.block_store.as_ref() {
            return block_store.tip();
        }
        if !self.chain_state.has_tip {
            return Ok(None);
        }
        Ok(Some((self.chain_state.height, self.chain_state.tip_hash)))
    }

    pub fn locator_hashes(&self, limit: usize) -> Result<Vec<[u8; 32]>, String> {
        match self.block_store.as_ref() {
            Some(block_store) => block_store.locator_hashes(limit),
            None => Ok(Vec::new()),
        }
    }

    pub fn hashes_after_locators(
        &self,
        locator_hashes: &[[u8; 32]],
        stop_hash: [u8; 32],
        limit: u64,
    ) -> Result<Vec<[u8; 32]>, String> {
        match self.block_store.as_ref() {
            Some(block_store) => {
                block_store.hashes_after_locators(locator_hashes, stop_hash, limit)
            }
            None => Ok(Vec::new()),
        }
    }

    pub fn get_block_by_hash(&self, block_hash_bytes: [u8; 32]) -> Result<Vec<u8>, String> {
        let Some(block_store) = self.block_store.as_ref() else {
            return Err("sync engine missing blockstore".to_string());
        };
        block_store.get_block_by_hash(block_hash_bytes)
    }

    pub fn has_block(&self, block_hash_bytes: [u8; 32]) -> Result<bool, String> {
        let Some(block_store) = self.block_store.as_ref() else {
            return Ok(false);
        };
        Ok(block_store.has_block(block_hash_bytes))
    }

    pub fn is_in_ibd(&self, now_unix: u64) -> bool {
        if !self.chain_state.has_tip {
            return true;
        }
        if now_unix < self.tip_timestamp {
            return true;
        }
        now_unix - self.tip_timestamp > self.cfg.ibd_lag_seconds
    }

    pub fn pv_shadow_stats(&self) -> (u64, Vec<String>) {
        (self.pv_shadow_mismatches, self.pv_shadow_samples.clone())
    }

    pub fn pv_telemetry_snapshot(&self) -> PVTelemetrySnapshot {
        self.pv_telemetry.snapshot()
    }

    fn pv_shadow_active(&self) -> bool {
        matches!(
            self.pv_mode,
            ParallelValidationMode::Shadow | ParallelValidationMode::On
        ) && self.is_in_ibd_unchecked()
    }

    fn is_in_ibd_unchecked(&self) -> bool {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return true;
        };
        self.is_in_ibd(now.as_secs())
    }

    fn record_pv_shadow_mismatch(&mut self, line: String) {
        self.pv_shadow_mismatches = self.pv_shadow_mismatches.saturating_add(1);
        if self.pv_shadow_samples.len() < self.pv_shadow_max_samples as usize {
            self.pv_shadow_samples.push(line);
        }
    }

    pub fn apply_block(
        &mut self,
        block_bytes: &[u8],
        prev_timestamps: Option<&[u64]>,
    ) -> Result<ChainStateConnectSummary, String> {
        let parsed = parse_block_bytes(block_bytes).map_err(|e| e.to_string())?;
        let block_hash_bytes = block_hash(&parsed.header_bytes).map_err(|e| e.to_string())?;
        let derived_prev_timestamps = if prev_timestamps.is_none() {
            self.prev_timestamps_for_next_block()?
        } else {
            None
        };
        let prev_timestamps = prev_timestamps.or(derived_prev_timestamps.as_deref());
        let pv_active = self.pv_shadow_active();

        let snapshot = self.chain_state.clone();
        let old_tip_timestamp = self.tip_timestamp;
        let old_best_known_height = self.best_known_height;

        // Build undo record from the pre-mutation state.
        let next_height = if self.chain_state.has_tip {
            self.chain_state.height + 1
        } else {
            0
        };
        let undo = build_block_undo(&self.chain_state, block_bytes, next_height)?;

        let suite_context = self.cfg.suite_context.clone();
        let (rotation, registry): (Option<&dyn RotationProvider>, Option<&SuiteRegistry>) =
            match suite_context.as_ref() {
                Some(ctx) => (Some(ctx.rotation.as_ref()), Some(ctx.registry.as_ref())),
                None => (None, None),
            };
        let summary = match self
            .chain_state
            .connect_block_with_core_ext_deployments_and_suite_context(
                block_bytes,
                self.cfg.expected_target,
                prev_timestamps,
                self.cfg.chain_id,
                &self.cfg.core_ext_deployments,
                rotation,
                registry,
            ) {
            Ok(summary) => summary,
            Err(err) => {
                if pv_active {
                    self.pv_telemetry.record_block_validated();
                    let validate_start = Instant::now();
                    match run_pv_shadow_validation_guarded(|| {
                        run_pv_shadow_validation(&snapshot, block_bytes, prev_timestamps, &self.cfg)
                    }) {
                        Ok(Ok(_)) => {
                            self.record_pv_shadow_mismatch(format!(
                                "pv_shadow mismatch(height={}): seq_err={} shadow_ok",
                                next_height,
                                pv_error_code(&err)
                            ));
                            self.pv_telemetry.record_mismatch_verdict();
                        }
                        Ok(Err(shadow_err)) => {
                            let seq_code = pv_error_code(&err);
                            let shadow_code = pv_error_code(&shadow_err);
                            if seq_code != shadow_code {
                                self.record_pv_shadow_mismatch(format!(
                                    "pv_shadow mismatch(height={}): seq_err={} shadow_err={}",
                                    next_height, seq_code, shadow_code
                                ));
                                self.pv_telemetry.record_mismatch_error();
                            }
                        }
                        Err(shadow_panic) => {
                            self.record_pv_shadow_mismatch(format!(
                                "pv_shadow mismatch(height={}): seq_err={} shadow_panic={}",
                                next_height,
                                pv_error_code(&err),
                                shadow_panic
                            ));
                            self.pv_telemetry.record_mismatch_verdict();
                            self.pv_telemetry.record_worker_panic();
                        }
                    }
                    self.pv_telemetry
                        .record_validate_latency(validate_start.elapsed());
                } else {
                    self.pv_telemetry.record_block_skipped();
                }
                return Err(err);
            }
        };

        if pv_active {
            self.pv_telemetry.record_block_validated();
            let validate_start = Instant::now();
            match run_pv_shadow_validation_guarded(|| {
                run_pv_shadow_validation(&snapshot, block_bytes, prev_timestamps, &self.cfg)
            }) {
                Ok(Ok(shadow_digest)) => {
                    let current_digest = self.chain_state.utxo_set_hash();
                    if shadow_digest != current_digest {
                        self.record_pv_shadow_mismatch(format!(
                            "pv_shadow mismatch(height={}): post_state_digest",
                            summary.block_height
                        ));
                        self.pv_telemetry.record_mismatch_state();
                    }
                }
                Ok(Err(shadow_err)) => {
                    self.record_pv_shadow_mismatch(format!(
                        "pv_shadow mismatch(height={}): seq_ok shadow_err={}",
                        summary.block_height,
                        pv_error_code(&shadow_err)
                    ));
                    self.pv_telemetry.record_mismatch_verdict();
                }
                Err(shadow_panic) => {
                    self.record_pv_shadow_mismatch(format!(
                        "pv_shadow mismatch(height={}): seq_ok shadow_panic={}",
                        summary.block_height, shadow_panic
                    ));
                    self.pv_telemetry.record_mismatch_verdict();
                    self.pv_telemetry.record_worker_panic();
                }
            }
            self.pv_telemetry
                .record_validate_latency(validate_start.elapsed());
        } else {
            self.pv_telemetry.record_block_skipped();
        }

        let commit_start = Instant::now();
        // `canonical_len_before` is the rewind target for the ONLY remaining
        // post-commit failure point: `chain_state.save` below. If
        // `commit_canonical_block` itself returns `Err`, the persisted
        // canonical tip has not advanced: the tip write is the last step
        // inside the atomic API, so an earlier failure leaves the prior
        // on-disk tip in place. Note that a save failure inside
        // `set_canonical_tip` mutates in-memory state before a best-effort
        // reload of the on-disk length; if that reload also fails, the
        // in-memory length may still be ahead of disk and the blockstore
        // would require repair. No rewind is needed here for the normal
        // `commit_canonical_block` error path.
        let canonical_len_before = self.block_store.as_ref().map_or(0, |bs| bs.canonical_len());
        if let Some(block_store) = self.block_store.as_mut() {
            // Atomic canonical commit — Go parity
            // (`clients/go/node/blockstore.go`, `CommitCanonicalBlock`).
            // Order inside the call: block bytes -> header bytes -> undo
            // -> canonical tip (last). A failure before the tip advance
            // leaves the canonical tip at its prior height, so no rewind
            // is required on block/header/undo write failure.
            if let Err(err) = block_store.commit_canonical_block(
                summary.block_height,
                block_hash_bytes,
                &parsed.header_bytes,
                block_bytes,
                &undo,
            ) {
                self.chain_state = snapshot;
                self.tip_timestamp = old_tip_timestamp;
                self.best_known_height = old_best_known_height;
                return Err(err);
            }
        }

        // Snapshot cadence gate (B.1, sub-issue #1246) — Go parity with
        // `clients/go/node/sync.go::persistAppliedBlock` save guard:
        // when a blockstore is wired, throttle per-block snapshot writes
        // through `should_persist_chainstate_snapshot`. The blockstore
        // already durably persists block bytes / header / undo on every
        // commit, so a missing snapshot at crash time is recoverable by
        // the E.2 startup reconcile path. Without a blockstore (test /
        // embedded mode), we do not throttle per-block snapshot attempts
        // through this cadence gate; an on-disk save still only occurs
        // when `cfg.chain_state_path` is configured. Boundary saves
        // (disconnect_tip, reorg rollback, miner publish, startup
        // reconcile in main.rs) call `chain_state.save` directly and are
        // unaffected by this gate.
        //
        // Early-return when chainstate persistence is fully disabled
        // (`chain_state_path == None`): no save would happen anyway, so
        // skip the cadence computation entirely on the hot path.
        if let Some(chain_state_path) = self.cfg.chain_state_path.as_ref() {
            let persist_snapshot = self.block_store.is_none()
                || should_persist_chainstate_snapshot(Some(&self.chain_state), Some(&summary));
            if persist_snapshot {
                if let Err(err) = self.chain_state.save(chain_state_path) {
                    // Canonical commit MAY have advanced the tip. The
                    // same-hash replay path returns Ok(()) without advancing
                    // the canonical index/tip (canonical_len unchanged),
                    // though it may still back-fill missing undo data on
                    // disk, so only rewind when the canonical length
                    // actually grew past the pre-commit snapshot.
                    let rewind_err = self.block_store.as_mut().and_then(|bs| {
                        if bs.canonical_len() > canonical_len_before {
                            bs.truncate_canonical(canonical_len_before).err()
                        } else {
                            None
                        }
                    });
                    self.chain_state = snapshot;
                    self.tip_timestamp = old_tip_timestamp;
                    self.best_known_height = old_best_known_height;
                    if let Some(rewind_err) = rewind_err {
                        return Err(format!(
                            "{err}; failed to rewind canonical index after chain_state save failure: {rewind_err}; blockstore may require repair"
                        ));
                    }
                    return Err(err);
                }
            }
        }

        self.tip_timestamp = parsed.header.timestamp;
        if summary.block_height > self.best_known_height {
            self.best_known_height = summary.block_height;
        }
        if pv_active {
            self.pv_telemetry
                .record_commit_latency(commit_start.elapsed());
        }

        Ok(summary)
    }

    // ----- Rollback helpers (used by sync_disconnect / sync_reorg) -----

    /// Light rollback state — no canonical suffix (used by disconnect_tip).
    pub(crate) fn capture_rollback_state(&self) -> SyncRollbackState {
        SyncRollbackState {
            chain_state: self.chain_state.clone(),
            canonical_len: self.block_store.as_ref().map_or(0, |bs| bs.canonical_len()),
            canonical_removed_suffix: None,
            tip_timestamp: self.tip_timestamp,
            best_known_height: self.best_known_height,
        }
    }

    /// Reorg rollback state — captures only the canonical suffix that
    /// will be removed during disconnect (O(reorg_depth), not O(height)).
    pub(crate) fn capture_reorg_rollback_state(
        &self,
        common_ancestor_height: u64,
    ) -> SyncRollbackState {
        let reorg_base = (common_ancestor_height as usize).saturating_add(1);
        SyncRollbackState {
            chain_state: self.chain_state.clone(),
            canonical_len: reorg_base,
            canonical_removed_suffix: self
                .block_store
                .as_ref()
                .map(|bs| bs.canonical_suffix_from(reorg_base)),
            tip_timestamp: self.tip_timestamp,
            best_known_height: self.best_known_height,
        }
    }

    /// Rollback in-memory and persisted state to the captured snapshot.
    ///
    /// Canonical index is rolled back FIRST (IO operation).  Only after
    /// that succeeds are in-memory fields updated and chain_state saved.
    /// This ordering prevents partial mutations on IO failure.
    ///
    /// Returns an error description if persistence failed — callers
    /// should surface this as a repair hint.
    pub(crate) fn rollback_apply_block(&mut self, rb: SyncRollbackState) -> Option<String> {
        // Phase 1: canonical index rollback (IO) — fail-fast before
        // mutating any in-memory state.
        if let Some(bs) = self.block_store.as_mut() {
            let res = if let Some(suffix) = rb.canonical_removed_suffix {
                // Reorg path: truncate to base, re-append removed suffix.
                bs.rollback_canonical(rb.canonical_len, suffix)
            } else {
                // Light rollback: truncate to saved length (disconnect_tip).
                bs.truncate_canonical(rb.canonical_len)
            };
            if let Err(e) = res {
                return Some(format!("canonical rollback failed: {e}"));
            }
        }

        // Phase 2: update in-memory state and persist chain_state.
        self.chain_state = rb.chain_state;
        self.tip_timestamp = rb.tip_timestamp;
        self.best_known_height = rb.best_known_height;

        if let Some(path) = self.cfg.chain_state_path.as_ref() {
            if let Err(e) = self.chain_state.save(path) {
                return Some(format!(
                    "chain_state save on rollback failed \
                     (canonical already rolled back, may require repair): {e}"
                ));
            }
        }

        None
    }

    /// Format an error message, optionally appending rollback failure details.
    pub(crate) fn err_with_rollback(err: String, rb: Option<String>) -> String {
        match rb {
            Some(rb_err) => {
                format!("{err}; rollback failed: {rb_err}; blockstore may require repair")
            }
            None => err,
        }
    }

    pub fn prev_timestamps_for_next_block(&self) -> Result<Option<Vec<u64>>, String> {
        if !self.chain_state.has_tip {
            return Ok(None);
        }
        if self.chain_state.height == u64::MAX {
            return Err("height overflow".to_string());
        }

        let Some(block_store) = self.block_store.as_ref() else {
            return Err("sync engine missing blockstore for timestamp context".to_string());
        };

        let next_height = self.chain_state.height + 1;
        let window_len = next_height.min(11);
        let mut out = Vec::with_capacity(window_len as usize);
        for offset in 0..window_len {
            let height = next_height - 1 - offset;
            let Some(hash) = block_store.canonical_hash(height)? else {
                return Err(format!(
                    "missing canonical hash at height {height} for timestamp context (next_height={next_height})"
                ));
            };
            let header_bytes = block_store.get_header_by_hash(hash)?;
            let header = parse_block_header_bytes(&header_bytes).map_err(|e| e.to_string())?;
            out.push(header.timestamp);
        }
        Ok(Some(out))
    }

    /// Derive prev_timestamps for a given `next_height` from the blockstore.
    /// Used by the reorg preview loop which needs timestamps at arbitrary
    /// heights (not just `self.chain_state.height + 1`).
    pub(crate) fn prev_timestamps_for_height(
        &self,
        next_height: u64,
    ) -> Result<Option<Vec<u64>>, String> {
        if next_height == 0 {
            return Ok(None);
        }
        let Some(block_store) = self.block_store.as_ref() else {
            return Err("sync engine missing blockstore for timestamp context".to_string());
        };
        let window_len = next_height.min(11);
        let mut out = Vec::with_capacity(window_len as usize);
        for offset in 0..window_len {
            let height = next_height - 1 - offset;
            let Some(hash) = block_store.canonical_hash(height)? else {
                return Err(format!(
                    "missing canonical hash at height {height} for timestamp context (next_height={next_height})"
                ));
            };
            let header_bytes = block_store.get_header_by_hash(hash)?;
            let header = parse_block_header_bytes(&header_bytes).map_err(|e| e.to_string())?;
            out.push(header.timestamp);
        }
        Ok(Some(out))
    }
}

pub fn validate_mainnet_genesis_guard(cfg: &SyncConfig) -> Result<(), String> {
    let network = cfg.network.trim().to_ascii_lowercase();
    let network = if network.is_empty() {
        "devnet".to_string()
    } else {
        network
    };
    if network != "mainnet" {
        return Ok(());
    }
    let expected_target = cfg
        .expected_target
        .ok_or_else(|| "mainnet requires explicit expected_target".to_string())?;
    if expected_target == POW_LIMIT {
        return Err("mainnet expected_target must not equal devnet POW_LIMIT (all-ff)".to_string());
    }
    Ok(())
}

fn normalize_parallel_validation_mode(mode: &str) -> String {
    let mode = mode.trim().to_ascii_lowercase();
    if mode.is_empty() {
        "off".to_string()
    } else {
        mode
    }
}

fn parse_parallel_validation_mode(mode: &str) -> Result<ParallelValidationMode, String> {
    match normalize_parallel_validation_mode(mode).as_str() {
        "off" => Ok(ParallelValidationMode::Off),
        "shadow" => Ok(ParallelValidationMode::Shadow),
        "on" => Ok(ParallelValidationMode::On),
        other => Err(format!(
            "invalid parallel_validation_mode: {other:?} (want off|shadow|on)"
        )),
    }
}

fn pv_error_code(err: &str) -> String {
    err.split_once(':').map_or_else(
        || err.trim().to_string(),
        |(code, _)| code.trim().to_string(),
    )
}

fn load_persisted_tip_timestamp(
    chain_state: &ChainState,
    block_store: Option<&BlockStore>,
) -> Result<u64, String> {
    if !chain_state.has_tip {
        return Ok(0);
    }
    let Some(block_store) = block_store else {
        return Ok(0);
    };
    let header_bytes = block_store.get_header_by_hash(chain_state.tip_hash)?;
    let header = parse_block_header_bytes(&header_bytes).map_err(|e| e.to_string())?;
    Ok(header.timestamp)
}

fn run_pv_shadow_validation(
    snapshot: &ChainState,
    block_bytes: &[u8],
    prev_timestamps: Option<&[u64]>,
    cfg: &SyncConfig,
) -> Result<[u8; 32], String> {
    let mut shadow_state = snapshot.clone();
    let (rotation, registry): (Option<&dyn RotationProvider>, Option<&SuiteRegistry>) =
        match cfg.suite_context.as_ref() {
            Some(ctx) => (Some(ctx.rotation.as_ref()), Some(ctx.registry.as_ref())),
            None => (None, None),
        };
    shadow_state.connect_block_with_core_ext_deployments_and_suite_context(
        block_bytes,
        cfg.expected_target,
        prev_timestamps,
        cfg.chain_id,
        &cfg.core_ext_deployments,
        rotation,
        registry,
    )?;
    Ok(shadow_state.utxo_set_hash())
}

fn run_pv_shadow_validation_guarded<F>(run: F) -> Result<Result<[u8; 32], String>, String>
where
    F: FnOnce() -> Result<[u8; 32], String>,
{
    catch_unwind(AssertUnwindSafe(run)).map_err(|_| "pv_shadow panic".to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rubin_consensus::constants::{COV_TYPE_EXT, COV_TYPE_P2PK, POW_LIMIT, SUITE_ID_ML_DSA_87};
    use rubin_consensus::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
    use rubin_consensus::{
        block_hash, encode_compact_size, merkle_root_txids, parse_block_bytes, parse_tx,
        CoreExtDeploymentProfile, CoreExtDeploymentProfiles, CoreExtVerificationBinding,
        NativeSuiteSet, Outpoint, RotationProvider, UtxoEntry, BLOCK_HEADER_BYTES,
    };
    use rubin_consensus::{DefaultRotationProvider, SuiteRegistry};

    use crate::blockstore::{block_store_path, BlockStore};
    use crate::chainstate::{chain_state_path, load_chain_state, ChainState};
    use crate::coinbase::{build_coinbase_tx, default_mine_address};
    use crate::genesis::{devnet_genesis_block_bytes, devnet_genesis_chain_id};
    use crate::io_utils::unique_temp_path;
    use crate::sync::{
        default_sync_config, run_pv_shadow_validation_guarded, SuiteContext, SyncEngine,
        MAX_PV_SHADOW_MAX_SAMPLES,
    };

    const VALID_BLOCK_HEX: &str = "01000000111111111111111111111111111111111111111111111111111111111111111102e66000bf8ce870908df4a8689554852ccef681ee0b5df32246162a53e36e290100000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff07000000000000000101000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff010000000000000000020020b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34cf37071a8000000000000";
    const CORE_EXT_NATIVE_BINDING_SPEND_TX_HEX: &str = "0100000000010000000000000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee000000000000000000015a0000000000000000002101111111111111111111111111111111111111111111111111111111111111111100000000010300010100";

    struct CountingRotationProvider {
        spend_calls: AtomicUsize,
    }

    impl RotationProvider for CountingRotationProvider {
        fn native_create_suites(&self, _height: u64) -> NativeSuiteSet {
            NativeSuiteSet::try_new(&[SUITE_ID_ML_DSA_87])
                .expect("counting rotation provider suite set must stay <= 2")
        }

        fn native_spend_suites(&self, _height: u64) -> NativeSuiteSet {
            self.spend_calls.fetch_add(1, Ordering::SeqCst);
            NativeSuiteSet::try_new(&[SUITE_ID_ML_DSA_87])
                .expect("counting rotation provider suite set must stay <= 2")
        }
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(hex.len() / 2);
        let bytes = hex.as_bytes();
        let mut idx = 0;
        while idx + 1 < bytes.len() {
            let nibble = |b: u8| -> u8 {
                match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    b'A'..=b'F' => b - b'A' + 10,
                    _ => panic!("invalid hex"),
                }
            };
            out.push((nibble(bytes[idx]) << 4) | nibble(bytes[idx + 1]));
            idx += 2;
        }
        out
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

    #[test]
    fn sync_engine_ibd_logic_and_header_request() {
        let st = ChainState::new();
        let cfg = default_sync_config(None, [0u8; 32], None);
        let mut engine = SyncEngine::new(st, None, cfg).expect("new sync engine");

        let req = engine.header_sync_request();
        assert!(!req.has_from);
        assert_eq!(req.limit, 512);
        assert!(engine.is_in_ibd(1_000));

        engine.chain_state.has_tip = true;
        engine.chain_state.height = 10;
        engine.chain_state.tip_hash = [0x11; 32];
        engine.tip_timestamp = 1_000;
        engine.cfg.ibd_lag_seconds = 100;

        let req2 = engine.header_sync_request();
        assert!(req2.has_from);
        assert_eq!(req2.from_hash, [0x11; 32]);

        assert!(engine.is_in_ibd(1_200));
        assert!(!engine.is_in_ibd(1_050));
    }

    #[test]
    fn sync_engine_apply_block_persists_chainstate_and_store() {
        let dir = unique_temp_path("rubin-node-sync-persist");
        let chain_state_file = chain_state_path(&dir);
        let block_store_root = block_store_path(&dir);
        let store = BlockStore::open(block_store_root).expect("open blockstore");

        let st = ChainState::new();
        let cfg = default_sync_config(Some(POW_LIMIT), [0u8; 32], Some(chain_state_file.clone()));
        let mut engine = SyncEngine::new(st, Some(store), cfg).expect("new sync");

        let block = hex_to_bytes(VALID_BLOCK_HEX);
        let summary = engine.apply_block(&block, None).expect("apply block");
        assert_eq!(summary.block_height, 0);

        assert!(chain_state_file.exists());
        let loaded = load_chain_state(&chain_state_file).expect("load chainstate");
        assert!(loaded.has_tip);
        assert_eq!(loaded.height, 0);

        let tip = engine
            .block_store
            .as_ref()
            .expect("store")
            .tip()
            .expect("tip")
            .expect("some tip");
        assert_eq!(tip.0, 0);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// B.1 sub-issue #1246: when `cfg.chain_state_path == None`, the
    /// snapshot cadence gate must early-return BEFORE calling
    /// `should_persist_chainstate_snapshot`, so apply_block does no
    /// chainstate-save-related work on the hot path. Verified by
    /// constructing a SyncEngine with a blockstore but no chainstate
    /// path, running apply_block, and asserting:
    ///
    ///   - apply_block returns Ok (no panic / no side-channel error
    ///     from a missing-path-but-attempted-save mismatch);
    ///   - no chainstate.json file is created in the data dir.
    ///
    /// Full end-to-end coverage of the >4096-UTXO + off-interval skip
    /// path requires synthesising valid PoW blocks at specific heights
    /// (height % 32 != 0) and is tracked as a follow-up Q (see #1246
    /// thread).
    #[test]
    fn sync_engine_apply_block_no_chainstate_path_skips_save_path() {
        let dir = unique_temp_path("rubin-node-sync-no-chainstate-path");
        let block_store_root = block_store_path(&dir);
        let store = BlockStore::open(block_store_root).expect("open blockstore");

        let st = ChainState::new();
        let cfg = default_sync_config(Some(POW_LIMIT), [0u8; 32], None /* chain_state_path */);
        let mut engine = SyncEngine::new(st, Some(store), cfg).expect("new sync");

        let block = hex_to_bytes(VALID_BLOCK_HEX);
        let summary = engine.apply_block(&block, None).expect("apply block");
        assert_eq!(summary.block_height, 0);

        // Chainstate file must NOT exist — the early-return on
        // `chain_state_path == None` skipped the save call entirely.
        let would_have_been_path = chain_state_path(&dir);
        assert!(
            !would_have_been_path.exists(),
            "chainstate file at {} must not be written when chain_state_path is None",
            would_have_been_path.display()
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn sync_engine_shadow_mode_executes_rust_pv_lane() {
        let mut cfg = default_sync_config(Some(POW_LIMIT), devnet_genesis_chain_id(), None);
        cfg.parallel_validation_mode = "shadow".to_string();
        cfg.pv_shadow_max_samples = 2;
        let mut engine = SyncEngine::new(ChainState::new(), None, cfg).expect("new sync");

        engine
            .apply_block(&devnet_genesis_block_bytes(), None)
            .expect("apply genesis in shadow mode");

        let telemetry = engine.pv_telemetry_snapshot();
        assert_eq!(telemetry.mode, "shadow");
        assert_eq!(telemetry.blocks_validated, 1);
        assert_eq!(telemetry.blocks_skipped, 0);
        assert_eq!(telemetry.mismatch_verdict, 0);
        assert_eq!(telemetry.mismatch_error, 0);
        assert_eq!(telemetry.mismatch_state, 0);
        assert_eq!(telemetry.validate_count, 1);
        assert_eq!(telemetry.commit_count, 1);
        assert!(telemetry.commit_avg_ns > 0);

        let (mismatches, samples) = engine.pv_shadow_stats();
        assert_eq!(mismatches, 0);
        assert!(samples.is_empty());
    }

    #[test]
    fn sync_engine_caps_pv_shadow_max_samples() {
        let mut cfg = default_sync_config(Some(POW_LIMIT), devnet_genesis_chain_id(), None);
        cfg.pv_shadow_max_samples = u64::MAX;
        let engine = SyncEngine::new(ChainState::new(), None, cfg).expect("new sync");
        assert_eq!(engine.pv_shadow_max_samples, MAX_PV_SHADOW_MAX_SAMPLES);
    }

    #[test]
    fn pv_shadow_validation_guarded_converts_panics_to_error() {
        let err = run_pv_shadow_validation_guarded(|| -> Result<[u8; 32], String> {
            panic!("boom");
        })
        .unwrap_err();
        assert_eq!(err, "pv_shadow panic");
    }

    #[test]
    fn sync_engine_shadow_mismatch_samples_are_bounded() {
        let mut cfg = default_sync_config(Some(POW_LIMIT), devnet_genesis_chain_id(), None);
        cfg.parallel_validation_mode = "shadow".to_string();
        cfg.pv_shadow_max_samples = 1;
        let mut engine = SyncEngine::new(ChainState::new(), None, cfg).expect("new sync");

        engine.record_pv_shadow_mismatch("first".to_string());
        engine.record_pv_shadow_mismatch("second".to_string());

        let (mismatches, samples) = engine.pv_shadow_stats();
        assert_eq!(mismatches, 2);
        assert_eq!(samples, vec!["first".to_string()]);
    }

    #[test]
    fn sync_engine_hydrates_tip_timestamp_from_persisted_tip_header() {
        let dir = unique_temp_path("rubin-node-sync-tip-timestamp");
        let block_store_root = block_store_path(&dir);
        let mut store = BlockStore::open(block_store_root).expect("open blockstore");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("unix time")
            .as_secs();
        let block = build_block_bytes([0u8; 32], [0x11; 32], POW_LIMIT, now, &[]);
        let tip_hash = block_hash(&block[..BLOCK_HEADER_BYTES]).expect("tip hash");
        store
            .put_block(0, tip_hash, &block[..BLOCK_HEADER_BYTES], &block)
            .expect("persist tip block");

        let mut chain_state = ChainState::new();
        chain_state.has_tip = true;
        chain_state.height = 0;
        chain_state.tip_hash = tip_hash;

        let mut cfg = default_sync_config(Some(POW_LIMIT), devnet_genesis_chain_id(), None);
        cfg.parallel_validation_mode = "shadow".to_string();
        cfg.ibd_lag_seconds = 60;

        let engine = SyncEngine::new(chain_state, Some(store), cfg).expect("new sync");
        assert_eq!(engine.tip_timestamp, now);
        assert!(!engine.pv_shadow_active());

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn sync_engine_apply_block_no_mutation_on_failure() {
        let mut st = ChainState::new();
        st.has_tip = true;
        st.height = 5;
        st.tip_hash = [0xaa; 32];
        st.already_generated = 10;
        st.utxos.insert(
            Outpoint {
                txid: [0xbb; 32],
                vout: 0,
            },
            UtxoEntry {
                value: 1,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: {
                    let mut bytes = Vec::with_capacity(33);
                    bytes.push(0x01);
                    bytes.extend_from_slice(&[0x22; 32]);
                    bytes
                },
                creation_height: 1,
                created_by_coinbase: false,
            },
        );

        let cfg = default_sync_config(None, [0u8; 32], None);
        let mut engine = SyncEngine::new(st, None, cfg).expect("new sync");
        engine.tip_timestamp = 333;
        engine.best_known_height = 777;

        let before = engine.chain_state.clone();
        let before_tip_timestamp = engine.tip_timestamp;
        let before_best_known = engine.best_known_height;

        let err = engine.apply_block(&[0x01, 0x02], None).unwrap_err();
        assert!(!err.is_empty());
        assert_eq!(engine.chain_state, before);
        assert_eq!(engine.tip_timestamp, before_tip_timestamp);
        assert_eq!(engine.best_known_height, before_best_known);
    }

    #[test]
    fn sync_engine_mainnet_guard_requires_explicit_non_devnet_target() {
        let st = ChainState::new();

        let mut cfg = default_sync_config(None, [0u8; 32], None);
        cfg.network = "mainnet".to_string();
        let err = SyncEngine::new(st.clone(), None, cfg).unwrap_err();
        assert_eq!(err, "mainnet requires explicit expected_target");

        let mut cfg = default_sync_config(Some(POW_LIMIT), [0u8; 32], None);
        cfg.network = "mainnet".to_string();
        let err = SyncEngine::new(st.clone(), None, cfg).unwrap_err();
        assert_eq!(
            err,
            "mainnet expected_target must not equal devnet POW_LIMIT (all-ff)"
        );

        let mut target = POW_LIMIT;
        target[0] = 0x7f;
        let mut cfg = default_sync_config(Some(target), [0u8; 32], None);
        cfg.network = "mainnet".to_string();
        let engine = SyncEngine::new(st, None, cfg);
        assert!(engine.is_ok());
    }

    #[test]
    fn suite_context_none_returns_none_pair() {
        let cfg = default_sync_config(Some(POW_LIMIT), devnet_genesis_chain_id(), None);
        let engine = SyncEngine::new(ChainState::new(), None, cfg).expect("new sync");
        let (rot, reg) = engine.suite_context();
        // When suite_context is None, both should be None
        // (consensus functions internally fallback to DefaultRotationProvider)
        assert!(rot.is_none());
        assert!(reg.is_none());
    }

    #[test]
    fn suite_context_with_stored_context_returns_some() {
        use std::sync::Arc;
        let mut cfg = default_sync_config(Some(POW_LIMIT), devnet_genesis_chain_id(), None);
        cfg.suite_context = Some(SuiteContext {
            rotation: Arc::new(DefaultRotationProvider),
            registry: Arc::new(SuiteRegistry::default_registry().clone()),
        });
        let engine = SyncEngine::new(ChainState::new(), None, cfg).expect("new sync");
        let (rot, reg) = engine.suite_context();
        assert!(rot.is_some());
        assert!(reg.is_some());
        // DefaultRotationProvider should include ML-DSA-87 at any height
        let spend_set = rot.unwrap().native_spend_suites(0);
        assert!(spend_set.contains(SUITE_ID_ML_DSA_87));
    }

    #[test]
    fn sync_engine_default_rotation_connects_genesis() {
        // Regression: SyncEngine without explicit suite_context connects genesis normally
        let cfg = default_sync_config(Some(POW_LIMIT), devnet_genesis_chain_id(), None);
        let mut engine = SyncEngine::new(ChainState::new(), None, cfg).expect("new sync");
        engine
            .apply_block(&devnet_genesis_block_bytes(), None)
            .expect("default rotation must accept genesis");
        assert!(engine.chain_state.has_tip);
        assert_eq!(engine.chain_state.height, 0);
    }

    #[test]
    fn sync_engine_rejects_post_activation_core_ext_spend_without_pre_active_bypass() {
        let dir = unique_temp_path("rubin-node-sync-core-ext");
        let chain_state_file = chain_state_path(&dir);
        let block_store_root = block_store_path(&dir);
        let store = BlockStore::open(block_store_root).expect("open blockstore");

        let mut cfg = default_sync_config(
            Some(POW_LIMIT),
            devnet_genesis_chain_id(),
            Some(chain_state_file),
        );
        cfg.core_ext_deployments = CoreExtDeploymentProfiles {
            deployments: vec![CoreExtDeploymentProfile {
                ext_id: 1,
                activation_height: 1,
                tx_context_enabled: false,
                allowed_suite_ids: vec![3],
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: Vec::new(),
                ext_payload_schema: Vec::new(),
                governance_nonce: 0,
            }],
        };
        let mut engine = SyncEngine::new(ChainState::new(), Some(store), cfg).expect("new sync");
        engine
            .apply_block(&devnet_genesis_block_bytes(), None)
            .expect("apply genesis");

        engine.chain_state.utxos.insert(
            Outpoint {
                txid: [0xee; 32],
                vout: 0,
            },
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_EXT,
                covenant_data: vec![0x01, 0x00, 0x00],
                creation_height: 0,
                created_by_coinbase: false,
            },
        );

        let spend_tx = hex_to_bytes(CORE_EXT_NATIVE_BINDING_SPEND_TX_HEX);
        let (_, spend_txid, spend_wtxid, consumed) = parse_tx(&spend_tx).expect("parse spend");
        assert_eq!(consumed, spend_tx.len());
        let witness_root =
            witness_merkle_root_wtxids(&[[0u8; 32], spend_wtxid]).expect("witness root");
        let witness_commitment = witness_commitment_hash(witness_root);
        let coinbase =
            build_coinbase_tx(1, 0, &default_mine_address(), witness_commitment).expect("coinbase");
        let (_, coinbase_txid, _, coinbase_consumed) = parse_tx(&coinbase).expect("parse coinbase");
        assert_eq!(coinbase_consumed, coinbase.len());
        let merkle_root = merkle_root_txids(&[coinbase_txid, spend_txid]).expect("merkle root");
        let genesis = devnet_genesis_block_bytes();
        let genesis_hash = block_hash(&genesis[..BLOCK_HEADER_BYTES]).expect("genesis hash");
        let parsed_genesis = parse_block_bytes(&genesis).expect("parse genesis");
        let block = build_block_bytes(
            genesis_hash,
            merkle_root,
            POW_LIMIT,
            parsed_genesis.header.timestamp.saturating_add(1),
            &[coinbase, spend_tx],
        );

        let err = engine.apply_block(&block, None).unwrap_err();
        assert!(
            err.contains("TX_ERR_SIG_ALG_INVALID"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sync_engine_shadow_mode_reuses_shared_suite_context_sequentially() {
        let dir = unique_temp_path("rubin-node-sync-pv-shared-suite-context");
        let chain_state_file = chain_state_path(&dir);
        let block_store_root = block_store_path(&dir);
        let store = BlockStore::open(block_store_root).expect("open blockstore");

        let rotation = Arc::new(CountingRotationProvider {
            spend_calls: AtomicUsize::new(0),
        });

        let mut cfg = default_sync_config(
            Some(POW_LIMIT),
            devnet_genesis_chain_id(),
            Some(chain_state_file),
        );
        cfg.parallel_validation_mode = "shadow".to_string();
        cfg.suite_context = Some(SuiteContext {
            rotation: rotation.clone(),
            registry: Arc::new(SuiteRegistry::default_registry().clone()),
        });
        cfg.core_ext_deployments = CoreExtDeploymentProfiles {
            deployments: vec![CoreExtDeploymentProfile {
                ext_id: 1,
                activation_height: 1,
                tx_context_enabled: false,
                allowed_suite_ids: vec![3],
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: Vec::new(),
                ext_payload_schema: Vec::new(),
                governance_nonce: 0,
            }],
        };

        let mut engine = SyncEngine::new(ChainState::new(), Some(store), cfg).expect("new sync");
        engine
            .apply_block(&devnet_genesis_block_bytes(), None)
            .expect("apply genesis");

        engine.chain_state.utxos.insert(
            Outpoint {
                txid: [0xee; 32],
                vout: 0,
            },
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_EXT,
                covenant_data: vec![0x01, 0x00, 0x00],
                creation_height: 0,
                created_by_coinbase: false,
            },
        );

        let spend_tx = hex_to_bytes(CORE_EXT_NATIVE_BINDING_SPEND_TX_HEX);
        let (_, spend_txid, spend_wtxid, consumed) = parse_tx(&spend_tx).expect("parse spend");
        assert_eq!(consumed, spend_tx.len());
        let witness_root =
            witness_merkle_root_wtxids(&[[0u8; 32], spend_wtxid]).expect("witness root");
        let witness_commitment = witness_commitment_hash(witness_root);
        let coinbase =
            build_coinbase_tx(1, 0, &default_mine_address(), witness_commitment).expect("coinbase");
        let (_, coinbase_txid, _, coinbase_consumed) = parse_tx(&coinbase).expect("parse coinbase");
        assert_eq!(coinbase_consumed, coinbase.len());
        let merkle_root = merkle_root_txids(&[coinbase_txid, spend_txid]).expect("merkle root");
        let genesis = devnet_genesis_block_bytes();
        let genesis_hash = block_hash(&genesis[..BLOCK_HEADER_BYTES]).expect("genesis hash");
        let parsed_genesis = parse_block_bytes(&genesis).expect("parse genesis");
        let block = build_block_bytes(
            genesis_hash,
            merkle_root,
            POW_LIMIT,
            parsed_genesis.header.timestamp.saturating_add(1),
            &[coinbase, spend_tx],
        );

        let err = engine.apply_block(&block, None).unwrap_err();
        assert!(
            err.contains("TX_ERR_SIG_ALG_INVALID"),
            "unexpected error: {err}"
        );
        assert!(
            rotation.spend_calls.load(Ordering::SeqCst) >= 2,
            "shared suite context should be exercised by both primary and shadow validation paths"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
