use std::fmt::Write as _;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rubin_consensus::constants::POW_LIMIT;
use rubin_consensus::{block_hash, parse_block_bytes, parse_block_header_bytes};
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

/// RUB-12 / GitHub #1156: escape a Prometheus label value to match
/// Go's `fmt.Sprintf` `%q` verb (`strconv.Quote` semantics, used at
/// `clients/go/node/pv_telemetry.go:250` for the `rubin_pv_mode`
/// label) for ASCII inputs and a focused subset of non-ASCII non-
/// printable runes — NOT the full Go `%q` surface. The exact scope:
/// byte-for-byte aligned with Go `%q` for any string composed of
/// printable ASCII + the explicitly handled escape classes below
/// (the production caller's domain); for arbitrary non-ASCII runes
/// outside `is_go_quote_nonprintable`'s focused subset, output
/// diverges from Go `%q` per the deliberate scope-narrowing
/// disclosed on `is_go_quote_nonprintable`.
///
/// Handled escape classes (covers the `%q` byte set Wave-1..8 of
/// PR #1477 enumerated; intentionally narrower than the full Go
/// `strconv.IsPrint` table):
/// - `\` -> `\\`
/// - `"` -> `\"`
/// - named control-char escapes: `\a` (BEL 0x07), `\b` (BS 0x08),
///   `\t`, `\n`, `\v`, `\f`, `\r`
/// - any other rune for which `is_go_quote_nonprintable` returns true
///   (General Category Cc plus a focused subset of well-known Cf
///   format characters, Zl/Zp separators, non-ASCII Zs whitespace,
///   bidi controls, and BOM):
///   * codepoint < 0x80 (C0 + DEL minus the named ones): two-hex-digit
///     lowercase form `\xNN` (literal output examples: `\x00`,
///     `\x1f`, `\x7f`)
///   * codepoint 0x80..=0xffff (C1 + other BMP non-printables):
///     four-hex-digit lowercase form `\uNNNN` (literal output
///     examples: U+0080 renders as backslash-u-0-0-8-0, U+00A0 as
///     backslash-u-0-0-a-0, U+2028 as backslash-u-2-0-2-8, U+FEFF
///     as backslash-u-f-e-f-f -- note: NOT a fixed `\u00NN` prefix,
///     all four hex digits are codepoint-derived)
///   * codepoint > 0xffff (astral non-printable): eight-hex-digit
///     lowercase form `\UNNNNNNNN` (literal output example: U+E0001
///     renders as backslash-U-0-0-0-e-0-0-0-1 -- note: NOT a fixed
///     `\U00NNNNNN` prefix, all eight hex digits are codepoint-derived)
/// - everything else (printable ASCII, printable Unicode, multi-
///   byte UTF-8): passes through unchanged
///
/// Defense-in-depth: today's only production caller is
/// `ParallelValidationMode::as_str()` returning the static literal
/// "off"/"shadow"/"on" (escape is identity on that input, byte-aligned
/// with Go's `%q`), but `PVTelemetrySnapshot` is a `pub` struct with
/// `pub mode: String` so a future external constructor passing a
/// runtime-shaped value must neither break the label literal nor
/// silently emit a non-printable rune (for example C1 NEL `U+0085`,
/// line separator `U+2028`, NBSP `U+00A0`, BOM `U+FEFF`) that Go's
/// `%q` would have escaped. See `is_go_quote_nonprintable` for the
/// full predicate and a note on the deliberate scope-narrowing vs
/// the full Go `strconv.IsPrint` table.
pub(crate) fn escape_prometheus_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            '\x07' => out.push_str(r"\a"),
            '\x08' => out.push_str(r"\b"),
            '\t' => out.push_str(r"\t"),
            '\n' => out.push_str(r"\n"),
            '\x0b' => out.push_str(r"\v"),
            '\x0c' => out.push_str(r"\f"),
            '\r' => out.push_str(r"\r"),
            c if is_go_quote_nonprintable(c) => {
                let cp = c as u32;
                // `write!` into the existing `String` (which implements
                // `fmt::Write`) avoids the per-rune heap allocation that
                // an interim `format!(...)` would incur. Writing to a
                // `String` cannot fail at runtime, so the `Result` is
                // safely discarded via `let _ = ...`.
                let _ = if cp < 0x80 {
                    write!(&mut out, r"\x{:02x}", cp)
                } else if cp <= 0xffff {
                    write!(&mut out, r"\u{:04x}", cp)
                } else {
                    write!(&mut out, r"\U{:08x}", cp)
                };
            }
            _ => out.push(c),
        }
    }
    out
}

/// RUB-12 / GitHub #1156 + Codex wave-5 P2 on PR #1477: predicate for
/// runes that `escape_prometheus_label_value` must emit as an escape
/// sequence (any of `\\`/`\"`/named-control/`\xNN`/`\uNNNN`/`\UNNNNNNNN`,
/// dispatched by the codepoint-width branches in the caller) rather
/// than as a literal byte. The named control escapes (`\a`/`\b`/`\t`/
/// `\n`/`\v`/`\f`/`\r`) are matched by earlier arms in
/// `escape_prometheus_label_value` and therefore never reach this
/// predicate; for the runes that DO reach it, the caller dispatches
/// to `\xNN` (codepoint < 0x80), `\uNNNN` (BMP non-printable), or
/// `\UNNNNNNNN` (astral non-printable). Used so a future runtime-
/// shaped `mode` value cannot pass an invisible bidi/format/separator
/// rune through the `rubin_pv_mode{mode="…"}` label and forge a
/// downstream parser surprise (line break, BOM, NBSP-as-space, RTL
/// override). Aligns with what Go's `strconv.Quote` /
/// `fmt.Sprintf("%q", ...)` would emit for ASCII input plus the
/// focused non-ASCII subset enumerated below.
///
/// Returns true for:
/// - `char::is_control()` — General Category Cc, exactly Go's
///   `unicode.IsControl`.
/// - A focused subset of Go's `strconv.IsPrint` non-printable BMP
///   codepoints covering the well-known invisible categories that
///   Go's `%q` escapes:
///   * Cf format characters: `U+00AD` (SHY), `U+061C` (Arabic letter
///     mark), `U+070F` (Syriac abbrev mark), `U+180E` (Mongolian
///     vowel separator), `U+200B..=U+200F` (zero-width space + bidi),
///     `U+202A..=U+202E` (bidi embeds/overrides), `U+2060..=U+206F`
///     (word joiner + invisible math operators + bidi isolates +
///     deprecated format; range merged across U+2065 reserved
///     codepoint to match Go's `strconv.IsPrint`), `U+FEFF` (BOM /
///     zero-width no-break space), `U+FFF9..=U+FFFB` (interlinear
///     annotation anchors).
///   * Zl line separator: `U+2028`. Zp paragraph separator: `U+2029`.
///   * Zs non-ASCII whitespace: `U+00A0` (NBSP), `U+1680` (Ogham
///     space), `U+2000..=U+200A` (en/em/figure/etc. spaces, includes
///     `U+2007` figure space), `U+202F` (narrow no-break space),
///     `U+205F` (medium math space), `U+3000` (ideographic space).
///
/// Returns false otherwise (printable ASCII, all of Latin-1 supplement
/// minus the listed non-printables, all printable Unicode planes).
///
/// Scope-narrowing vs Go's full `strconv.IsPrint`: Go ships a
/// generated table (`go/src/strconv/isprint.go`, ~30 KB binary) of
/// every non-printable codepoint across all Unicode planes. Porting
/// the full table inline here is rejected as dead weight — production
/// caller `ParallelValidationMode::as_str()` returns ASCII literals
/// only, and the predicate above already covers every well-known
/// invisible non-ASCII rune cited in the upstream parity discussion.
/// Untracked supplementary-plane non-printable runes (mostly tag
/// characters `U+E0000..=U+E007F` and variation selectors supplement
/// `U+E0100..=U+E01EF`) pass through unescaped — operators reading
/// both clients on the same `mode` value would see those bytes
/// literal-on-Rust vs `\U…` -on-Go, but Rust's safe `Display` impl
/// on `String` already prevents UTF-8 corruption and the production
/// caller's input is constrained.
fn is_go_quote_nonprintable(c: char) -> bool {
    if c.is_control() {
        return true;
    }
    matches!(
        c as u32,
        0x00a0 | 0x00ad
            | 0x061c
            | 0x070f
            | 0x180e
            | 0x1680
            | 0x2000..=0x200f
            | 0x2028..=0x202f
            | 0x205f
            | 0x2060..=0x206f
            | 0x3000
            | 0xfeff
            | 0xfff9..=0xfffb
    )
}

impl PVTelemetrySnapshot {
    /// RUB-12 / GitHub #1156: Prometheus exposition for the PV
    /// telemetry snapshot, format-aligned to the upstream Go emission
    /// at `clients/go/node/pv_telemetry.go::PVTelemetrySnapshot.PrometheusLines`
    /// (L246-291). Ten distinct HELP/TYPE metric blocks expanding to
    /// thirteen Prometheus time series (the
    /// `rubin_pv_shadow_mismatches_total` block carries four `type=`
    /// buckets), in the same order Go emits.
    ///
    /// Scope of the parity claim is exposition format only: HELP
    /// strings, TYPE keywords, metric NAMEs, label shapes, line
    /// order, and value-token format are byte-aligned with Go. The
    /// emitted VALUES are NOT byte-stable across runtimes — see the
    /// disclosure below. The single label-bearing line
    /// (`rubin_pv_mode{mode="…"}`) escapes the `mode` value through
    /// `escape_prometheus_label_value`, which is byte-for-byte
    /// aligned with Go's `%q` verb on the same field for ASCII
    /// inputs (the production happy path; `mode` is sourced from
    /// `ParallelValidationMode::as_str()` returning "off"/"shadow"/
    /// "on") and for the focused non-ASCII subset listed on
    /// `is_go_quote_nonprintable`; for arbitrary non-ASCII runes
    /// outside that subset, output diverges from Go `%q` per the
    /// deliberate scope-narrowing disclosed there. So a runtime-
    /// shaped `mode` cannot break out of the label literal and
    /// forge synthetic lines (the `\\` -> `\\\\`, `"` -> `\\"`,
    /// LF -> `\\n` cases that allow injection are all in the
    /// byte-for-byte-aligned ASCII subset).
    ///
    /// Rust-side tracker disclosure (operators reading both clients):
    /// the internal `PVTelemetry` struct currently zero-stubs four
    /// snapshot fields whose Prometheus lines therefore render as
    /// `... 0` regardless of node activity:
    /// - `worker_tasks_total`: Go production wires
    ///   `RecordWorkerTasks(parSummary.SigTaskCount)` at
    ///   `clients/go/node/sync.go:675`; Rust has no `record_worker_tasks`
    ///   call site, so this counter diverges from Go under load.
    /// - `sig_total`, `sig_cache_hits`, `mismatch_witness`: neither
    ///   client wires these in production today, so both report `0`;
    ///   when either side wires its tracker, this disclosure must be
    ///   re-checked.
    ///
    /// Wiring the missing trackers is out of this slice's scope per
    /// `class_change_stop_rule` (single_contract_delta is exposition
    /// alignment, not tracker plumbing).
    ///
    /// The two latency-count fields `validate_count` / `commit_count`
    /// are NOT emitted by `prometheus_lines` directly. They are
    /// consumed earlier by `PVTelemetry::snapshot()`, which divides
    /// `validate_total_ns` / `commit_total_ns` by the corresponding
    /// count via `averaged_latency_ns(...)` to populate the snapshot's
    /// `validate_avg_ns` / `commit_avg_ns` fields; only those `_avg_ns`
    /// gauges are then emitted here. The upstream Go exposition emits
    /// no standalone count counter either, so this slice neither adds
    /// nor drops a metric line. Renaming the latency gauges to
    /// `*_latency_avg_ns` (was `*_avg_ns`) closes a metric-NAME
    /// contract break — Prometheus queries by exact name, and the
    /// upstream uses the longer form. (Pre-existing helper
    /// `averaged_latency_ns(...)` applies a `.max(1)` floor when
    /// count > 0; Go uses raw integer division. For sub-1-ns averages
    /// this would emit `1` on Rust vs `0` on Go. Pre-existing
    /// divergence not introduced by this slice; flagged here so the
    /// disclosure stays honest.)
    pub fn prometheus_lines(&self) -> Vec<String> {
        vec![
            "# HELP rubin_pv_mode Current parallel validation mode (0=off, 1=shadow, 2=on)."
                .to_string(),
            "# TYPE rubin_pv_mode gauge".to_string(),
            format!(
                "rubin_pv_mode{{mode=\"{}\"}} 1",
                escape_prometheus_label_value(&self.mode)
            ),
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
            "# HELP rubin_pv_sig_total Total signature verifications attempted.".to_string(),
            "# TYPE rubin_pv_sig_total counter".to_string(),
            format!("rubin_pv_sig_total {}", self.sig_total),
            "# HELP rubin_pv_sig_cache_hits_total Signature cache hits (skipped crypto)."
                .to_string(),
            "# TYPE rubin_pv_sig_cache_hits_total counter".to_string(),
            format!("rubin_pv_sig_cache_hits_total {}", self.sig_cache_hits),
            "# HELP rubin_pv_worker_tasks_total Tasks dispatched to worker pool.".to_string(),
            "# TYPE rubin_pv_worker_tasks_total counter".to_string(),
            format!("rubin_pv_worker_tasks_total {}", self.worker_tasks_total),
            "# HELP rubin_pv_worker_panics_total Recovered panics in worker pool.".to_string(),
            "# TYPE rubin_pv_worker_panics_total counter".to_string(),
            format!("rubin_pv_worker_panics_total {}", self.worker_panics),
            "# HELP rubin_pv_validate_latency_avg_ns Average validation phase latency (ns)."
                .to_string(),
            "# TYPE rubin_pv_validate_latency_avg_ns gauge".to_string(),
            format!("rubin_pv_validate_latency_avg_ns {}", self.validate_avg_ns),
            "# HELP rubin_pv_commit_latency_avg_ns Average commit phase latency (ns).".to_string(),
            "# TYPE rubin_pv_commit_latency_avg_ns gauge".to_string(),
            format!("rubin_pv_commit_latency_avg_ns {}", self.commit_avg_ns),
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
    last_reorg_depth: u64,
    reorg_count: u64,
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
    pub last_reorg_depth: u64,
    pub reorg_count: u64,
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
            last_reorg_depth: 0,
            reorg_count: 0,
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

    pub fn last_reorg_depth(&self) -> u64 {
        self.last_reorg_depth
    }

    pub fn reorg_count(&self) -> u64 {
        self.reorg_count
    }

    pub(crate) fn note_reorg(&mut self, depth: u64) {
        self.last_reorg_depth = depth;
        if depth > 0 {
            self.reorg_count = self.reorg_count.saturating_add(1);
        }
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
        let summary = match self.chain_state.connect_block_with_suite_context(
            block_bytes,
            self.cfg.expected_target,
            prev_timestamps,
            self.cfg.chain_id,
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
        // Direct canonical apply clears the last-depth gauge; successful reorg
        // reconnects set it again after the whole branch commits.
        self.last_reorg_depth = 0;
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
            last_reorg_depth: self.last_reorg_depth,
            reorg_count: self.reorg_count,
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
            last_reorg_depth: self.last_reorg_depth,
            reorg_count: self.reorg_count,
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
        self.last_reorg_depth = rb.last_reorg_depth;
        self.reorg_count = rb.reorg_count;

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
    shadow_state.connect_block_with_suite_context(
        block_bytes,
        cfg.expected_target,
        prev_timestamps,
        cfg.chain_id,
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use rubin_consensus::constants::{COV_TYPE_P2PK, POW_LIMIT, SUITE_ID_ML_DSA_87};
    use rubin_consensus::{
        block_hash, encode_compact_size, Outpoint, UtxoEntry, BLOCK_HEADER_BYTES,
    };
    use rubin_consensus::{DefaultRotationProvider, SuiteRegistry};

    use crate::blockstore::{block_store_path, BlockStore};
    use crate::chainstate::{chain_state_path, load_chain_state, ChainState};
    use crate::genesis::{devnet_genesis_block_bytes, devnet_genesis_chain_id};
    use crate::io_utils::unique_temp_path;
    use crate::sync::{
        default_sync_config, run_pv_shadow_validation_guarded, SuiteContext, SyncEngine,
        MAX_PV_SHADOW_MAX_SAMPLES,
    };

    const VALID_BLOCK_HEX: &str = "01000000111111111111111111111111111111111111111111111111111111111111111102e66000bf8ce870908df4a8689554852ccef681ee0b5df32246162a53e36e290100000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff07000000000000000101000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff010000000000000000020020b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34cf37071a8000000000000";

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

    /// B.1 sub-issue #1246: when `cfg.chain_state_path == None`,
    /// `apply_block` should skip the chainstate snapshot save path.
    /// Verified by constructing a `SyncEngine` with a blockstore but
    /// no chainstate path, running `apply_block`, and asserting:
    ///
    ///   - `apply_block` returns `Ok` (no panic / no error from a
    ///     missing-path-but-attempted-save mismatch);
    ///   - no `chainstate.json` file is created in the data dir.
    ///
    /// This test does not assert whether
    /// `should_persist_chainstate_snapshot` is evaluated internally;
    /// it only verifies that no snapshot file is written when the
    /// chainstate path is absent.
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

    /// RUB-12 / GitHub #1156: pin the exact 33-line Prometheus
    /// exposition `prometheus_lines()` produces for a fully populated
    /// `PVTelemetrySnapshot`. The 33 lines correspond to ten distinct
    /// HELP/TYPE metric blocks (nine simple 3-line blocks plus the
    /// `rubin_pv_shadow_mismatches_total` block which is HELP+TYPE+four
    /// `type=`-bucketed value lines), expanding to thirteen distinct
    /// Prometheus time series in total. Each emitted line is asserted
    /// against a literal string that matches the upstream Go emission
    /// at `clients/go/node/pv_telemetry.go::PrometheusLines` (L246-291)
    /// token-for-token. A drift in any HELP string, metric NAME, label
    /// shape, or numeric format trips this test.
    ///
    /// Proof assertion: the ten HELP/TYPE metric blocks (thirteen
    /// time series) render in the exact order Go emits, with
    /// HELP/TYPE/value lines positionally identical. The dropped
    /// Rust-only `rubin_pv_validate_runs_total` and
    /// `rubin_pv_commit_runs_total` counters are confirmed absent;
    /// the renamed `rubin_pv_validate_latency_avg_ns` and
    /// `rubin_pv_commit_latency_avg_ns` gauges are confirmed present
    /// with the longer upstream NAME (was `*_avg_ns` only, a metric-
    /// NAME contract break vs Go).
    ///
    /// Proof scope: this is a renderer-format proof (the helper
    /// formats a synthetic snapshot correctly), NOT a behavioral
    /// proof that the Rust runtime emits values matching Go under
    /// load. See `prometheus_lines` doc for the unwired-tracker
    /// disclosure (`worker_tasks_total`, `sig_total`,
    /// `sig_cache_hits`, `mismatch_witness` zero-stub in the Rust
    /// `PVTelemetry` tracker today).
    #[test]
    fn pv_telemetry_prometheus_lines_match_go_exposition_byte_for_byte() {
        let snapshot = super::PVTelemetrySnapshot {
            mode: "shadow".to_string(),
            blocks_validated: 7,
            blocks_skipped: 3,
            mismatch_verdict: 1,
            mismatch_error: 2,
            mismatch_state: 4,
            mismatch_witness: 8,
            sig_total: 16,
            sig_cache_hits: 9,
            worker_tasks_total: 32,
            worker_panics: 0,
            validate_count: 5,
            validate_avg_ns: 12345,
            commit_count: 5,
            commit_avg_ns: 678,
        };
        let lines = snapshot.prometheus_lines();
        let expected: Vec<&str> = vec![
            "# HELP rubin_pv_mode Current parallel validation mode (0=off, 1=shadow, 2=on).",
            "# TYPE rubin_pv_mode gauge",
            "rubin_pv_mode{mode=\"shadow\"} 1",
            "# HELP rubin_pv_blocks_validated_total Blocks processed through PV path.",
            "# TYPE rubin_pv_blocks_validated_total counter",
            "rubin_pv_blocks_validated_total 7",
            "# HELP rubin_pv_blocks_skipped_total Blocks skipped (mode=off or not in IBD).",
            "# TYPE rubin_pv_blocks_skipped_total counter",
            "rubin_pv_blocks_skipped_total 3",
            "# HELP rubin_pv_shadow_mismatches_total Shadow mismatch count by type.",
            "# TYPE rubin_pv_shadow_mismatches_total counter",
            "rubin_pv_shadow_mismatches_total{type=\"verdict\"} 1",
            "rubin_pv_shadow_mismatches_total{type=\"error\"} 2",
            "rubin_pv_shadow_mismatches_total{type=\"state\"} 4",
            "rubin_pv_shadow_mismatches_total{type=\"witness\"} 8",
            "# HELP rubin_pv_sig_total Total signature verifications attempted.",
            "# TYPE rubin_pv_sig_total counter",
            "rubin_pv_sig_total 16",
            "# HELP rubin_pv_sig_cache_hits_total Signature cache hits (skipped crypto).",
            "# TYPE rubin_pv_sig_cache_hits_total counter",
            "rubin_pv_sig_cache_hits_total 9",
            "# HELP rubin_pv_worker_tasks_total Tasks dispatched to worker pool.",
            "# TYPE rubin_pv_worker_tasks_total counter",
            "rubin_pv_worker_tasks_total 32",
            "# HELP rubin_pv_worker_panics_total Recovered panics in worker pool.",
            "# TYPE rubin_pv_worker_panics_total counter",
            "rubin_pv_worker_panics_total 0",
            "# HELP rubin_pv_validate_latency_avg_ns Average validation phase latency (ns).",
            "# TYPE rubin_pv_validate_latency_avg_ns gauge",
            "rubin_pv_validate_latency_avg_ns 12345",
            "# HELP rubin_pv_commit_latency_avg_ns Average commit phase latency (ns).",
            "# TYPE rubin_pv_commit_latency_avg_ns gauge",
            "rubin_pv_commit_latency_avg_ns 678",
        ];
        assert_eq!(
            lines.len(),
            expected.len(),
            "line count mismatch: got {} expected {}; lines={:?}",
            lines.len(),
            expected.len(),
            lines
        );
        for (i, (got, want)) in lines.iter().zip(expected.iter()).enumerate() {
            assert_eq!(got, want, "line {i} mismatch: got {got:?} want {want:?}");
        }
    }

    /// RUB-12 / GitHub #1156: the dropped Rust-only counters
    /// `rubin_pv_validate_runs_total` and `rubin_pv_commit_runs_total`
    /// must NOT appear in the Prometheus exposition under any populated
    /// snapshot — they were Rust-only emissions with no upstream Go
    /// counterpart and would inflate the Rust client's metric surface
    /// vs. Go for mixed-client devnet evidence consumers.
    ///
    /// Proof assertion: even with non-zero `validate_count` /
    /// `commit_count` (which used to populate those counters), the
    /// joined exposition contains neither `rubin_pv_validate_runs_total`
    /// nor `rubin_pv_commit_runs_total` as a substring.
    ///
    /// Proof scope: renderer-format proof on a synthetic snapshot,
    /// not a runtime-tracker proof. See `prometheus_lines` doc for
    /// the unwired-tracker disclosure (`worker_tasks_total`,
    /// `sig_total`, `sig_cache_hits`, `mismatch_witness` zero-stub
    /// in the Rust `PVTelemetry` tracker today).
    #[test]
    fn pv_telemetry_prometheus_lines_dropped_rust_only_counters_absent() {
        let snapshot = super::PVTelemetrySnapshot {
            mode: "on".to_string(),
            blocks_validated: 0,
            blocks_skipped: 0,
            mismatch_verdict: 0,
            mismatch_error: 0,
            mismatch_state: 0,
            mismatch_witness: 0,
            sig_total: 0,
            sig_cache_hits: 0,
            worker_tasks_total: 0,
            worker_panics: 0,
            validate_count: 99,
            validate_avg_ns: 0,
            commit_count: 99,
            commit_avg_ns: 0,
        };
        let body = snapshot.prometheus_lines().join("\n");
        assert!(
            !body.contains("rubin_pv_validate_runs_total"),
            "validate_runs_total must be dropped (Go has no counterpart); body=\n{body}"
        );
        assert!(
            !body.contains("rubin_pv_commit_runs_total"),
            "commit_runs_total must be dropped (Go has no counterpart); body=\n{body}"
        );
        // The renamed latency gauges with the longer upstream NAME
        // must be present — Prometheus consumers query by exact name.
        assert!(
            body.contains("\nrubin_pv_validate_latency_avg_ns 0"),
            "validate_latency_avg_ns line missing; body=\n{body}"
        );
        assert!(
            body.contains("\nrubin_pv_commit_latency_avg_ns 0"),
            "commit_latency_avg_ns line missing; body=\n{body}"
        );
        // The shorter Rust-historical names must NOT remain in any
        // form so a future regression cannot silently restore them.
        assert!(
            !body.contains("rubin_pv_validate_avg_ns "),
            "old short-name validate_avg_ns must not appear; body=\n{body}"
        );
        assert!(
            !body.contains("rubin_pv_commit_avg_ns "),
            "old short-name commit_avg_ns must not appear; body=\n{body}"
        );
    }

    /// RUB-12 / GitHub #1156 + Copilot wave-2 P2 on PR #1477:
    /// `escape_prometheus_label_value` is byte-for-byte aligned with
    /// Go's `%q` verb on the `rubin_pv_mode` label for ASCII inputs
    /// and the focused non-ASCII subset listed on
    /// `is_go_quote_nonprintable` (NOT full Go-`%q` parity for
    /// arbitrary non-ASCII), so a runtime-shaped `mode` value cannot
    /// inject `"` or `\` to close the label literal early and forge
    /// synthetic metric lines downstream of the formatter. Today the
    /// only production caller is `ParallelValidationMode::as_str()`
    /// returning the literal "off"/"shadow"/"on" (none contain
    /// special chars), so the validator is purely defense-in-depth
    /// for a future external constructor of the `pub`
    /// `PVTelemetrySnapshot { mode: String, ... }`.
    ///
    /// Proof assertion: `\` -> `\\`, `"` -> `\"`, LF -> `\n` (literal
    /// backslash-n), and other ASCII / UTF-8 bytes pass through
    /// unchanged. Plus: the rendered exposition for an injected mode
    /// `shadow"} 1\n# malicious_metric 1` does not gain a second
    /// `# HELP` / new metric line — the entire injected payload sits
    /// inside the escaped label literal.
    #[test]
    fn escape_prometheus_label_value_matches_go_q_verb_and_blocks_injection() {
        // Identity for safe ASCII (the production happy path).
        assert_eq!(super::escape_prometheus_label_value("shadow"), "shadow");
        assert_eq!(super::escape_prometheus_label_value("off"), "off");
        assert_eq!(super::escape_prometheus_label_value("on"), "on");
        assert_eq!(super::escape_prometheus_label_value(""), "");
        // Three Prometheus-spec escapes.
        assert_eq!(super::escape_prometheus_label_value("a\\b"), r"a\\b");
        assert_eq!(super::escape_prometheus_label_value("a\"b"), r#"a\"b"#);
        assert_eq!(super::escape_prometheus_label_value("a\nb"), r"a\nb");
        // Combined.
        assert_eq!(super::escape_prometheus_label_value("\"\\\n"), r#"\"\\\n"#);
        // Go-%q named control-char escapes beyond the Prometheus
        // spec subset: BEL, BS, TAB, VT, FF, CR — must match Go's
        // strconv.Quote byte-for-byte.
        assert_eq!(super::escape_prometheus_label_value("\x07"), r"\a");
        assert_eq!(super::escape_prometheus_label_value("\x08"), r"\b");
        assert_eq!(super::escape_prometheus_label_value("\t"), r"\t");
        assert_eq!(super::escape_prometheus_label_value("\x0b"), r"\v");
        assert_eq!(super::escape_prometheus_label_value("\x0c"), r"\f");
        assert_eq!(super::escape_prometheus_label_value("\r"), r"\r");
        // Other control chars fall through to `\xNN` two-digit
        // lowercase hex form, matching Go's strconv.Quote.
        assert_eq!(super::escape_prometheus_label_value("\x00"), r"\x00");
        assert_eq!(super::escape_prometheus_label_value("\x01"), r"\x01");
        assert_eq!(super::escape_prometheus_label_value("\x1f"), r"\x1f");
        assert_eq!(super::escape_prometheus_label_value("\x7f"), r"\x7f");
        // Combined: a control sandwich.
        assert_eq!(
            super::escape_prometheus_label_value("a\rb\tc\x01d"),
            r"a\rb\tc\x01d"
        );
        // C1 control chars (U+0080..=U+009F) are caught by
        // `char::is_control()` (Cc) and emitted as `\uNNNN` (four
        // lowercase hex digits, e.g. U+0080 -> backslash-u-0-0-8-0,
        // U+00A0 -> backslash-u-0-0-a-0, U+2028 -> backslash-u-2-0-2-8),
        // matching Go's `strconv.Quote` for codepoints in the BMP.
        assert_eq!(super::escape_prometheus_label_value("\u{80}"), "\\u0080");
        assert_eq!(super::escape_prometheus_label_value("\u{85}"), "\\u0085");
        assert_eq!(super::escape_prometheus_label_value("\u{9f}"), "\\u009f");
        // Wave-5 (Codex P2): non-Cc runes Go's `%q` still escapes —
        // Zs non-ASCII whitespace (NBSP, Ogham space, ideographic
        // space), Zl/Zp separators, BOM, bidi/format controls — must
        // also escape via `is_go_quote_nonprintable`.
        assert_eq!(super::escape_prometheus_label_value("\u{a0}"), "\\u00a0");
        assert_eq!(super::escape_prometheus_label_value("\u{ad}"), "\\u00ad");
        assert_eq!(super::escape_prometheus_label_value("\u{1680}"), "\\u1680");
        assert_eq!(super::escape_prometheus_label_value("\u{2007}"), "\\u2007");
        assert_eq!(super::escape_prometheus_label_value("\u{2028}"), "\\u2028");
        assert_eq!(super::escape_prometheus_label_value("\u{2029}"), "\\u2029");
        assert_eq!(super::escape_prometheus_label_value("\u{200b}"), "\\u200b");
        assert_eq!(super::escape_prometheus_label_value("\u{202e}"), "\\u202e");
        assert_eq!(super::escape_prometheus_label_value("\u{202f}"), "\\u202f");
        assert_eq!(super::escape_prometheus_label_value("\u{2060}"), "\\u2060");
        assert_eq!(super::escape_prometheus_label_value("\u{2065}"), "\\u2065");
        assert_eq!(super::escape_prometheus_label_value("\u{206f}"), "\\u206f");
        assert_eq!(super::escape_prometheus_label_value("\u{3000}"), "\\u3000");
        assert_eq!(super::escape_prometheus_label_value("\u{feff}"), "\\ufeff");
        // Printable Unicode (Latin-1 supplement, Cyrillic, etc.)
        // passes through unchanged.
        assert_eq!(super::escape_prometheus_label_value("режим"), "режим");
        assert_eq!(super::escape_prometheus_label_value("é"), "é");
        assert_eq!(super::escape_prometheus_label_value("漢字"), "漢字");
        // End-to-end injection attempt: malicious `mode` tries to
        // close the label, terminate the line, and inject a fake
        // `# HELP` block. After escape the entire payload is
        // inside the label literal — no second line, no second
        // HELP token at any line start.
        let injected = "shadow\"} 1\n# HELP fake malicious\n# TYPE fake gauge\nfake 1";
        let snapshot = super::PVTelemetrySnapshot {
            mode: injected.to_string(),
            blocks_validated: 0,
            blocks_skipped: 0,
            mismatch_verdict: 0,
            mismatch_error: 0,
            mismatch_state: 0,
            mismatch_witness: 0,
            sig_total: 0,
            sig_cache_hits: 0,
            worker_tasks_total: 0,
            worker_panics: 0,
            validate_count: 0,
            validate_avg_ns: 0,
            commit_count: 0,
            commit_avg_ns: 0,
        };
        let body = snapshot.prometheus_lines().join("\n");
        assert!(
            !body.contains("\nfake "),
            "injected `fake` metric line must NOT appear at line start; body=\n{body}"
        );
        assert!(
            !body.contains("\n# HELP fake"),
            "injected `# HELP fake` must NOT appear at line start; body=\n{body}"
        );
        // The label literal must contain the escaped forms so the
        // line is well-formed Prometheus text (parsers see one
        // metric line, not five).
        assert!(
            body.contains(r#"rubin_pv_mode{mode="shadow\"} 1\n# HELP fake malicious\n# TYPE fake gauge\nfake 1"} 1"#),
            "rendered rubin_pv_mode line must carry the injected payload as an escaped label value, not as separate lines; body=\n{body}"
        );
    }
}
