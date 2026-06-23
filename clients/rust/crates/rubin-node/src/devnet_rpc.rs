use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::da_relay::CompleteDaSetProvider;
use crate::miner::{Miner, MinerConfig};
use crate::p2p_runtime::{orphan_pool_metrics_snapshot, PeerManager};
use crate::txpool::TxSource;
use crate::{BlockStore, SyncEngine, TxPool, TxPoolAdmitErrorKind, TxPoolConfig};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
// Per-line cap for chunk-size and trailer lines.
//
// For CHUNK-SIZE lines this matches Go's
// `src/net/http/internal/chunked.go` `maxLineLength = 4096`: Go rejects
// `len(p) >= maxLineLength` on the POST-CRLF-strip, PRE-OWS-trim byte
// length (chunked.go:178-182 — the `trimTrailingWhitespace` call only
// runs AFTER `readChunkLine` returns, in `chunkedReader.beginChunk`
// line 54, so it never shortens the length the cap sees). We use `>=`
// the same way — a 4095-byte line is the largest accepted, even if a
// trailing SP/HTAB would trim it shorter.
//
// For TRAILER lines this is a Rust-local fail-closed bound, not a
// direct Go parity cap: Go parses trailers via `body.readTrailer`
// (net/http/transfer.go) which calls `seeUpcomingDoubleCRLF` and then
// delegates to `textproto.Reader.ReadMIMEHeader` — a different path
// from `readChunkLine`. Reusing `MAX_CHUNK_LINE_BYTES` here gives the
// same order-of-magnitude upper bound Go imposes via its MIME header
// parser without claiming byte-for-byte parity with `readChunkLine`.
const MAX_CHUNK_LINE_BYTES: usize = 4096;
const MAX_CONCURRENT_RPC_CONNS: usize = 8;
const RPC_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
pub const RPC_READINESS_TRANSITION_FAILED: &str =
    "rpc readiness transition failed: server is already ready or shutdown";

pub type AnnounceTxFn =
    Arc<dyn Fn(&[u8], crate::txpool::RelayTxMetadata) -> Result<(), String> + Send + Sync>;
pub type AnnounceBlockFn = Arc<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>;
pub type AcceptedBlockFn = Arc<dyn Fn([u8; 32]) -> Result<(), String> + Send + Sync>;
/// Fail-closed DA-relay cleanup hook for the just-mined block bytes. Mirrors the
/// Go `acceptedBlockDASetConsumer` consumer hook.
pub type AcceptedBlockDaConsumerFn = Arc<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>;

#[derive(Clone)]
pub struct DevnetRPCState {
    sync_engine: Arc<Mutex<SyncEngine>>,
    block_store: Option<BlockStore>,
    tx_pool: Arc<Mutex<TxPool>>,
    peer_manager: Arc<PeerManager>,
    metrics: Arc<RpcMetrics>,
    now_unix: fn() -> u64,
    announce_tx: Option<AnnounceTxFn>,
    announce_block: Option<AnnounceBlockFn>,
    accepted_block: Option<AcceptedBlockFn>,
    /// When set, POST `/mine_next` fail-closed consumes the mined block's
    /// complete DA sets after a successful mine+apply (RUB-435).
    accepted_block_da_consumer: Option<AcceptedBlockDaConsumerFn>,
    /// Serializes mutating devnet RPC (submit_tx + mine_next).
    rpc_op_lock: Arc<Mutex<()>>,
    /// When set, POST `/mine_next` mines one block using this config (devnet + loopback RPC only).
    live_mining_cfg: Option<MinerConfig>,
    live_complete_da_set_provider: Option<Arc<dyn CompleteDaSetProvider + Send + Sync>>,
    /// RUB-10 / GitHub #1151: readiness gate driving `/ready` semantics.
    /// Mirrors Go's `clients/go/cmd/rubin-node/http_rpc.go::readinessGate`
    /// (type at line 125; methods 143-219). Three-state machine:
    /// `NotReady` -> `Ready` (one-shot via `try_mark_ready_on_startup`)
    /// -> `Shutdown` (sticky terminal, via `mark_shutdown`).
    ///
    /// Production Rust delivers all three states observable to mixed-client
    /// devnet evidence consumers: `NotReady` (pre-`start_devnet_rpc_server`
    /// stamp), `Ready` (post-stamp), and `Shutdown`. The `Shutdown`
    /// state is reachable via `RunningDevnetRPCServer::close`, `Drop`,
    /// and the production `clients/rust/crates/rubin-node/src/main.rs`
    /// stop-signal lifecycle, which routes the configured process stop
    /// signal set through `close()` before owned runtime services are torn down. Tests
    /// exercise all three states (`ready_endpoint_reports_503_after_shutdown_sticky`
    /// drives the gate through `Shutdown` via `RunningDevnetRPCServer::close`).
    readiness: Arc<ReadinessGate>,
}

pub struct RunningDevnetRPCServer {
    addr: String,
    stop: Arc<AtomicBool>,
    active_handlers: Arc<AtomicUsize>,
    join: Option<JoinHandle<()>>,
    done: Option<mpsc::Receiver<()>>,
    /// RUB-10 / GitHub #1151: handle to the same `ReadinessGate` the
    /// `DevnetRPCState` references, kept on the server so `close()`
    /// can stamp `Shutdown` before stopping the accept loop. Mirrors
    /// Go's `runningDevnetRPCServer.MarkShutdown` (`clients/go/cmd/rubin-node/http_rpc.go:308`).
    readiness: Arc<ReadinessGate>,
}

/// RUB-10 / GitHub #1151: three-state readiness machine mirroring Go's
/// `readyState` constants in `clients/go/cmd/rubin-node/http_rpc.go`
/// (lines 85-89). Transitions are monotone: `NotReady` is the initial
/// boot state; `try_mark_ready_on_startup` flips it to `Ready` exactly
/// once; `mark_shutdown` flips any state to the sticky terminal
/// `Shutdown`. `Shutdown` is observable via `is_ready() == false` and
/// is the operational signal mixed-client devnet evidence consumers
/// use to stop submitting work to a draining node.
///
/// RUB-41 / GitHub #1329 readiness-meaning matrix (the `go_rust_parity_matrix`
/// row "not-started/starting/ready/unavailable meaning" enumerated
/// per state). The semantics that `is_ready() == true` claims and what
/// it does NOT claim are pinned here so future readers can recover
/// the bounded readiness contract from the source alone:
///
/// - `NotReady` (boot zero-value): means "the
///   `ReadinessGate::try_mark_ready_on_startup` path has not yet
///   completed its `NotReady` -> `Ready` transition". `GET /ready`
///   reports 503 + `{"ready":false}` (the JSON envelope byte-pinned by
///   `ready_response_body_byte_pinned_rust_wire_format`); non-GET
///   methods on `/ready` always return 405 + `Allow: GET` regardless
///   of gate state per RFC 9110 §15.5.6 (handler dispatch order:
///   method check first, then state read). This is the state a
///   freshly constructed `DevnetRPCState` exposes BEFORE
///   `start_devnet_rpc_server` runs the post-bind stamp at the
///   `try_mark_ready_on_startup` call site below; orchestrators MUST
///   treat 503 as "not-ready / unavailable" and not interleave work.
///   Note: 503 alone does NOT distinguish `NotReady` (pre-stamp) from
///   `Shutdown` (post-stamp) — both report 503 + `{"ready":false}` by
///   design. Consumers that need to distinguish boot-up from drain
///   must use process-level signals (start log line, supervisor
///   state) rather than reading meaning into the 503 source state.
/// - `Ready` (post-`start_devnet_rpc_server` happy path):
///   `is_ready() == true` claims ONLY that the boot-time
///   `try_mark_ready_on_startup` stamp has completed exactly once on
///   the gate (the gate is a state latch, not a listener-bound
///   invariant; production wiring at `start_devnet_rpc_server`
///   stamps the gate post-bind so on the production happy path
///   `is_ready() == true` coincides with a bound RPC listener, but
///   nothing inside the gate enforces that — tests can stamp the
///   gate without binding a listener, and a code change that moved
///   the production stamp pre-bind would silently widen the
///   readiness window). It does NOT claim:
///     * mempool admit-path is fault-free (`/ready` does not gate on
///       mempool policy or admission health here);
///     * miner is configured (live mining is opt-in via
///       `live_mining_cfg`; absence does not flip the gate to false);
///     * sync engine has reached chain tip or has any peer
///       (`PeerManager` peer count is observable via `/peers`, not
///       `/ready`);
///     * the lifecycle context has not been canceled by an external
///       signal before production lifecycle shutdown starts. Rust
///       production `main.rs` wires the process stop flag into this
///       gate for the Go-aligned graceful-stop set: SIGINT and SIGTERM
///       on Unix, and Ctrl-C on non-Unix platforms. SIGHUP is not part
///       of the graceful-stop contract. A stop observed before or during
///       RPC startup stamps `Shutdown` and `/ready` reports 503 before
///       `RunningDevnetRPCServer::close` tears the listener down.
///
///   The mempool/miner/sync absence rows above are explicitly the
///   `go_rust_parity_matrix` row "mempool/miner/sync prerequisites
///   if claimed" answered with NOT CLAIMED. Operators reading
///   `/ready == true` who need stronger guarantees must layer
///   additional checks on top (e.g. `/peers` count for peer
///   liveness, `/get_tip` `has_tip == true` for chain initialization
///   — note "non-zero height" is NOT a sound heuristic because a
///   genesis-only chain legitimately reports height 0) and treat
///   `/ready` as the boot-stamp latch only.
///
/// - `Shutdown` (post-`mark_shutdown` terminal): sticky; once entered
///   the gate never returns to `Ready`. `GET /ready` reports 503 +
///   `{"ready":false}` permanently for this gate's lifetime; non-GET
///   methods on `/ready` continue to return 405 + `Allow: GET`
///   independently of gate state. Operator-facing recovery is
///   process restart, not a /ready-driven re-arm.
///
/// `go_rust_parity_matrix` row "error status and response shape" is
/// pinned by `handle_ready` below (200 vs 503 status code; `{ready:
/// bool}` body; `application/json` Content-Type; `Allow: GET` header
/// on 405 method-not-allowed) and by the `ReadyResponse` struct
/// envelope. `coverage_reachability_matrix` row "public readiness
/// check used by localhost/devnet tooling" is satisfied by the
/// `ready_endpoint_*` test family in `tests` module which asserts
/// `/ready` HTTP behavior via the public `route_request` dispatch.
/// Some tests in the family additionally call `state.readiness.*`
/// directly for setup (driving the gate to a target state) or for
/// secondary post-condition assertions (e.g.
/// `ready_endpoint_partial_start_returns_503` calls
/// `try_mark_ready_on_startup` after the dispatch to prove the
/// gate stayed in NotReady, not Shutdown). The PRIMARY readiness
/// assertion in every `ready_endpoint_*` test is the public
/// `route_request` response (status code + body bytes); helper
/// calls supplement that, they do not replace it.
///
/// Routes that Go's mixed-client tooling can scrape but Rust does
/// NOT serve today: `GET /health` (rich operator snapshot at
/// `clients/go/cmd/rubin-node/http_rpc.go::handleHealth` L1517+,
/// returning ready+chain_context+mempool counts+peer_count) and
/// `GET /chain_identity` (chain identity mux at the same Go file
/// L701-703; `/health` mux follows at L704). Adding either Rust
/// mirror is explicitly out of
/// scope for RUB-41 because the `class_change_stop_rule` would
/// trigger ("If readiness needs new endpoint/schema/lifecycle
/// behavior, stop and split"). RUB-41 narrows to `/ready` SEMANTICS
/// only; the missing routes are deferred to a follow-up slice once
/// the contract for adding them has its own architect review.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadyState {
    NotReady,
    Ready,
    Shutdown,
}

struct ReadinessGate {
    state: Mutex<ReadyStateCell>,
    shutdown_requested: Option<Arc<AtomicBool>>,
}

struct ReadyStateCell(ReadyState);

impl Default for ReadyStateCell {
    fn default() -> Self {
        Self(ReadyState::NotReady)
    }
}

impl Default for ReadinessGate {
    fn default() -> Self {
        Self {
            state: Mutex::new(ReadyStateCell::default()),
            shutdown_requested: None,
        }
    }
}

impl ReadinessGate {
    fn with_shutdown_requested(shutdown_requested: Arc<AtomicBool>) -> Self {
        Self {
            state: Mutex::new(ReadyStateCell::default()),
            shutdown_requested: Some(shutdown_requested),
        }
    }

    fn shutdown_requested(&self) -> bool {
        self.shutdown_requested
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::SeqCst))
    }

    /// RUB-10 / GitHub #1151: boot-time `NotReady` -> `Ready` transition.
    /// Mirrors Go `readinessGate.TryMarkReadyOnStartup`
    /// (`clients/go/cmd/rubin-node/http_rpc.go:166-180`). Returns true iff the gate WAS `NotReady`
    /// at the moment of the call AND the transition won. Returns false
    /// if already `Ready` (idempotent re-call) or `Shutdown` (sticky;
    /// post-shutdown re-readiness is forbidden by design — operators
    /// must restart the node, matching Go's contract).
    ///
    /// Mirrors Go's `observeShutdownLocked` behavior for production
    /// signal shutdown when this gate has a wired stop flag: a
    /// pre-requested stop stamps `Shutdown` and prevents the startup
    /// ready transition. A poisoned mutex is treated as not-ready (the
    /// function returns early without flipping the cell value) —
    /// defense-in-depth so a panicked operation that left the gate
    /// inconsistent cannot quietly succeed here.
    fn try_mark_ready_on_startup(&self) -> bool {
        let Ok(mut cell) = self.state.lock() else {
            return false;
        };
        if self.shutdown_requested() {
            cell.0 = ReadyState::Shutdown;
            return false;
        }
        if cell.0 != ReadyState::NotReady {
            return false;
        }
        cell.0 = ReadyState::Ready;
        true
    }

    /// RUB-10 / GitHub #1151: stamp the gate into the sticky `Shutdown`
    /// state. Mirrors Go `readinessGate.MarkShutdown` (`clients/go/cmd/rubin-node/http_rpc.go:184-191`).
    /// Idempotent. Once `Shutdown` is set, `is_ready()` returns false
    /// permanently (matches Go's design: a draining node must not
    /// re-advertise readiness without a process restart).
    fn mark_shutdown(&self) {
        if let Ok(mut cell) = self.state.lock() {
            cell.0 = ReadyState::Shutdown;
        }
    }

    /// RUB-10 / GitHub #1151: returns true iff the gate is currently in
    /// the `Ready` state and no wired production stop signal has been
    /// observed. Mirrors Go `readinessGate.IsReady`
    /// (`clients/go/cmd/rubin-node/http_rpc.go:198-208`) including
    /// cancellation observation when this gate has a wired stop flag.
    /// A poisoned mutex is treated as not-ready (defense-in-depth: a
    /// panicked operation that left the gate in inconsistent state
    /// defaults to reporting not-ready).
    fn is_ready(&self) -> bool {
        let Ok(mut cell) = self.state.lock() else {
            return false;
        };
        if self.shutdown_requested() {
            cell.0 = ReadyState::Shutdown;
            return false;
        }
        cell.0 == ReadyState::Ready
    }
}

#[derive(Default)]
struct RpcMetrics {
    inner: Mutex<RpcMetricsInner>,
}

#[derive(Default)]
struct RpcMetricsInner {
    route_status: HashMap<(String, u16), u64>,
    submit_results: HashMap<String, u64>,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    target: String,
    body: Vec<u8>,
}

#[derive(Serialize)]
struct GetTipResponse {
    has_tip: bool,
    height: Option<u64>,
    tip_hash: Option<String>,
    best_known_height: u64,
    in_ibd: bool,
}

#[derive(Serialize)]
struct GetBlockResponse {
    hash: String,
    height: u64,
    canonical: bool,
    block_hex: String,
}

#[derive(Serialize)]
struct SubmitTxResponse {
    accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct SubmitTxRequest {
    tx_hex: String,
}

#[derive(Serialize)]
struct MineNextResponse {
    mined: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct GetMempoolResponse {
    count: usize,
    txids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct GetTxResponse {
    found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct TxStatusResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// RUB-10 / GitHub #1151: `/ready` JSON envelope.
/// Mirrors Go's `readyResponse` struct in
/// `clients/go/cmd/rubin-node/http_rpc.go:641-643`: a single boolean
/// field describing whether the node is currently in the `Ready`
/// state. Per Go's parity-reference comment (`clients/go/cmd/rubin-node/http_rpc.go:638-640`):
/// the response status code (200 vs 503) is the primary contract for
/// orchestrators; the `{ready: bool}` body is the human-readable
/// secondary signal. Mixed-client devnet evidence consumers parse
/// both — the test
/// `ready_endpoint_reports_503_after_shutdown_sticky` and its
/// siblings assert both signals together.
#[derive(Serialize)]
struct ReadyResponse {
    ready: bool,
}

/// RUB-14 / GitHub #1159: bounded JSON projection of a single
/// `PeerState` for the `/peers` snapshot. Mirrors Go's `peerEntry`
/// struct in `clients/go/cmd/rubin-node/http_rpc.go:418-428` field-
/// for-field at the wire level — same JSON keys, same types
/// (Rust's `i32`/`u32`/`u64` map to Go's `int`/`uint32`/`uint64`
/// numeric tokens; serde encodes them identically). Five fields
/// live on the embedded `remote_version: VersionPayloadV1`
/// (`protocol_version`, `best_height`, `tx_relay`,
/// `pruned_below_height`, `da_mempool_size`); the other four come
/// from the top-level `PeerState` (`addr`, `handshake_complete`,
/// `ban_score`, `last_error`).
#[derive(Serialize)]
struct PeerEntry {
    addr: String,
    handshake_complete: bool,
    ban_score: i32,
    last_error: String,
    protocol_version: u32,
    best_height: u64,
    tx_relay: bool,
    pruned_below_height: u64,
    da_mempool_size: u32,
}

/// RUB-14 / GitHub #1159: bounded payload served by GET `/peers`.
/// Mirrors Go's `peersResponse` in `clients/go/cmd/rubin-node/http_rpc.go:430-437`.
/// `count` equals `peers.len()` by construction in `handle_peers`;
/// `peers` is sorted by `addr` ascending so two consecutive scrapes
/// are byte-stable across `HashMap` iteration randomization. Empty
/// initialized peer set serializes to `{"count":0,"peers":[]}`
/// (NOT `null` — `Vec::new()` produces an empty JSON array).
#[derive(Serialize)]
struct PeersResponse {
    count: usize,
    peers: Vec<PeerEntry>,
}

/// True when the host in `host:port` is loopback-only (safe for devnet live mining RPC).
/// Requires a non-empty, valid `u16` port (rejects `127.0.0.1:` and similar).
pub fn rpc_bind_host_is_loopback(bind_addr: &str) -> bool {
    let addr = bind_addr.trim();
    if addr.is_empty() {
        return false;
    }
    let (host, port) = if addr.starts_with('[') {
        let Some(bracket_end) = addr.find("]:") else {
            return false;
        };
        if bracket_end < 2 {
            return false;
        }
        let port = &addr[bracket_end + 2..];
        (&addr[1..bracket_end], port)
    } else if let Some(colon_pos) = addr.rfind(':') {
        if colon_pos == 0 || colon_pos + 1 == addr.len() {
            return false;
        }
        let host = &addr[..colon_pos];
        if host.contains(':') {
            return false;
        }
        let port = &addr[(colon_pos + 1)..];
        (host, port)
    } else {
        return false;
    };
    let host = host.trim();
    if host.is_empty() {
        return false;
    }
    let port = port.trim();
    if port.is_empty() || port.parse::<u16>().is_err() {
        return false;
    }
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .ok()
        .is_some_and(|ip| ip.is_loopback())
}

pub fn new_devnet_rpc_state(
    sync_engine: Arc<Mutex<SyncEngine>>,
    block_store: Option<BlockStore>,
    peer_manager: Arc<PeerManager>,
    announce_tx: Option<AnnounceTxFn>,
    announce_block: Option<AnnounceBlockFn>,
) -> DevnetRPCState {
    let tx_pool = new_shared_runtime_tx_pool(&sync_engine);
    new_devnet_rpc_state_with_tx_pool(
        sync_engine,
        block_store,
        tx_pool,
        peer_manager,
        announce_tx,
        announce_block,
        None,
    )
}

pub fn new_devnet_rpc_state_with_tx_pool(
    sync_engine: Arc<Mutex<SyncEngine>>,
    block_store: Option<BlockStore>,
    tx_pool: Arc<Mutex<TxPool>>,
    peer_manager: Arc<PeerManager>,
    announce_tx: Option<AnnounceTxFn>,
    announce_block: Option<AnnounceBlockFn>,
    live_mining_cfg: Option<MinerConfig>,
) -> DevnetRPCState {
    DevnetRPCState {
        sync_engine,
        block_store,
        tx_pool,
        peer_manager,
        metrics: Arc::new(RpcMetrics::default()),
        now_unix: current_unix,
        announce_tx,
        announce_block,
        accepted_block: None,
        accepted_block_da_consumer: None,
        rpc_op_lock: Arc::new(Mutex::new(())),
        live_mining_cfg,
        live_complete_da_set_provider: None,
        // RUB-10 / GitHub #1151: gate starts in `NotReady`. The
        // `try_mark_ready_on_startup` transition runs inside
        // `start_devnet_rpc_server` after the listener is bound, so
        // `GET /ready` cannot report 200 before the node is actually
        // serving requests.
        readiness: Arc::new(ReadinessGate::default()),
    }
}

impl DevnetRPCState {
    pub fn set_accepted_block_hook(&mut self, accepted_block: AcceptedBlockFn) {
        self.accepted_block = Some(accepted_block);
    }

    pub fn set_accepted_block_da_consumer(&mut self, consumer: AcceptedBlockDaConsumerFn) {
        self.accepted_block_da_consumer = Some(consumer);
    }

    pub fn set_complete_da_set_provider(
        &mut self,
        provider: Arc<dyn CompleteDaSetProvider + Send + Sync>,
    ) {
        self.live_complete_da_set_provider = Some(provider);
    }
}

pub fn attach_shutdown_signal_to_devnet_rpc_state(
    mut state: DevnetRPCState,
    shutdown_requested: Arc<AtomicBool>,
) -> DevnetRPCState {
    state.readiness = Arc::new(ReadinessGate::with_shutdown_requested(shutdown_requested));
    state
}

pub fn new_shared_runtime_tx_pool(sync_engine: &Arc<Mutex<SyncEngine>>) -> Arc<Mutex<TxPool>> {
    let suite_context = sync_engine
        .lock()
        .map(|engine| engine.cfg.suite_context.clone())
        .unwrap_or(None);
    Arc::new(Mutex::new(TxPool::new_with_config(TxPoolConfig {
        suite_context,
        ..TxPoolConfig::default()
    })))
}

pub fn start_devnet_rpc_server(
    bind_addr: &str,
    state: DevnetRPCState,
) -> Result<RunningDevnetRPCServer, String> {
    let listener =
        TcpListener::bind(bind_addr).map_err(|err| format!("bind {bind_addr}: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("set_nonblocking: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("local_addr: {err}"))?
        .to_string();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let active_handlers = Arc::new(AtomicUsize::new(0));
    let active_handlers_for_loop = Arc::clone(&active_handlers);
    let (done_tx, done_rx) = mpsc::channel();
    let state = Arc::new(state);
    // RUB-10 / GitHub #1151: stamp `Ready` BEFORE the accept thread
    // spawns. The lifecycle position matches Go's stamp at
    // `clients/go/cmd/rubin-node/main.go:768` (called via
    // `maybeFlipReadyOnStartup` from `clients/go/cmd/rubin-node/main.go:572`) — both run after
    // the listener is bound but before the first request is served —
    // even though the call site differs structurally: Go's stamp
    // runs from the bin's main after `startDevnetRPCServer` returns
    // and additional state wiring (SetIdentity, peer-lifecycle hooks)
    // completes, while Rust folds the stamp inside
    // `start_devnet_rpc_server` because the equivalent state wiring
    // already happened in `clients/rust/crates/rubin-node/src/main.rs`
    // before this function was called (so the operational invariant —
    // "Ready iff serving + state wired" — is preserved despite the
    // call-site difference). The `Arc::clone` keeps a handle past
    // the move into the thread so `RunningDevnetRPCServer` can
    // `mark_shutdown` on close.
    let readiness = Arc::clone(&state.readiness);
    if !readiness.try_mark_ready_on_startup() {
        return Err(RPC_READINESS_TRANSITION_FAILED.to_string());
    }
    let join = thread::Builder::new()
        .name("rubin-devnet-rpc".to_string())
        .spawn(move || {
            let _done = AcceptLoopDone(Some(done_tx));
            run_accept_loop(listener, state, stop_flag, active_handlers_for_loop);
        })
        .map_err(|err| {
            readiness.mark_shutdown();
            format!("spawn rpc accept loop: {err}")
        })?;
    Ok(RunningDevnetRPCServer {
        addr,
        stop,
        active_handlers,
        join: Some(join),
        done: Some(done_rx),
        readiness,
    })
}

impl RunningDevnetRPCServer {
    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn close(&mut self) -> Result<(), String> {
        self.close_with_timeout(RPC_SHUTDOWN_TIMEOUT)
    }

    fn close_with_timeout(&mut self, timeout: Duration) -> Result<(), String> {
        let started = Instant::now();
        // RUB-10 / GitHub #1151: stamp `Shutdown` BEFORE stopping the
        // accept loop so any in-flight `/ready` request that races the
        // close sees the sticky terminal state. Mirrors Go's
        // `runningDevnetRPCServer.MarkShutdown` (`clients/go/cmd/rubin-node/http_rpc.go:308`) which
        // is called from `clients/go/cmd/rubin-node/main.go:598` before the listener tear-down.
        // Idempotent: re-calling close (e.g., explicit close + Drop)
        // re-stamps Shutdown without effect.
        self.readiness.mark_shutdown();
        if self.join.is_none() {
            return self.wait_for_handlers(started, timeout);
        }
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.addr);
        let done = self
            .done
            .as_ref()
            .ok_or_else(|| "rpc shutdown missing accept-loop completion channel".to_string())?;
        Self::wait_for_accept_loop_done(done, started, timeout)?;
        let join = self
            .join
            .take()
            .ok_or_else(|| "rpc shutdown missing accept-loop handle".to_string())?;
        self.done.take();
        join.join()
            .map_err(|_| "rpc accept loop panicked during shutdown".to_string())?;
        self.wait_for_handlers(started, timeout)
    }

    fn wait_for_accept_loop_done(
        done: &mpsc::Receiver<()>,
        started: Instant,
        timeout: Duration,
    ) -> Result<(), String> {
        if Self::accept_loop_done_now(done) {
            return Ok(());
        }

        let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
            return Self::accept_loop_timeout_if_still_pending(done, timeout);
        };
        if remaining.is_zero() {
            return Self::accept_loop_timeout_if_still_pending(done, timeout);
        }

        match done.recv_timeout(remaining) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => Ok(()),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Self::accept_loop_timeout_if_still_pending(done, timeout)
            }
        }
    }

    fn accept_loop_done_now(done: &mpsc::Receiver<()>) -> bool {
        matches!(
            done.try_recv(),
            Ok(()) | Err(mpsc::TryRecvError::Disconnected)
        )
    }

    fn accept_loop_timeout_if_still_pending(
        done: &mpsc::Receiver<()>,
        timeout: Duration,
    ) -> Result<(), String> {
        if Self::accept_loop_done_now(done) {
            return Ok(());
        }
        Err(Self::accept_loop_timeout_error(timeout))
    }

    fn accept_loop_timeout_error(timeout: Duration) -> String {
        format!(
            "rpc shutdown timeout after {} ms: accept loop still running",
            timeout.as_millis()
        )
    }

    fn wait_for_handlers(&self, started: Instant, timeout: Duration) -> Result<(), String> {
        loop {
            let active = self.active_handlers.load(Ordering::SeqCst);
            if active == 0 {
                return Ok(());
            }
            let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
                return self.handler_timeout_if_still_active(timeout);
            };
            if remaining.is_zero() {
                return self.handler_timeout_if_still_active(timeout);
            }
            thread::sleep(remaining.min(Duration::from_millis(25)));
        }
    }

    fn handler_timeout_if_still_active(&self, timeout: Duration) -> Result<(), String> {
        let active = self.active_handlers.load(Ordering::SeqCst);
        if active == 0 {
            return Ok(());
        }
        Err(format!(
            "rpc shutdown timeout after {} ms: {active} handler(s) still running",
            timeout.as_millis()
        ))
    }
}

impl Drop for RunningDevnetRPCServer {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

struct AcceptLoopDone(Option<mpsc::Sender<()>>);

impl Drop for AcceptLoopDone {
    fn drop(&mut self) {
        if let Some(done) = self.0.take() {
            let _ = done.send(());
        }
    }
}

impl RpcMetrics {
    fn note(&self, route: &str, status: u16) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        *guard
            .route_status
            .entry((route.to_string(), status))
            .or_insert(0) += 1;
    }

    fn note_submit(&self, result: &str) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        *guard.submit_results.entry(result.to_string()).or_insert(0) += 1;
    }

    fn snapshot(&self) -> (HashMap<(String, u16), u64>, HashMap<String, u64>) {
        let Ok(guard) = self.inner.lock() else {
            return (HashMap::new(), HashMap::new());
        };
        (guard.route_status.clone(), guard.submit_results.clone())
    }
}

fn run_accept_loop(
    listener: TcpListener,
    state: Arc<DevnetRPCState>,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if active.load(Ordering::SeqCst) >= MAX_CONCURRENT_RPC_CONNS {
                    drop(stream);
                    thread::sleep(Duration::from_millis(25));
                    continue;
                }
                let st = Arc::clone(&state);
                let ctr = Arc::clone(&active);
                ctr.fetch_add(1, Ordering::SeqCst);
                if thread::Builder::new()
                    .spawn(move || {
                        let _active = ActiveHandler(ctr);
                        let _ = handle_connection(stream, &st);
                    })
                    .is_err()
                {
                    active.fetch_sub(1, Ordering::SeqCst);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

struct ActiveHandler(Arc<AtomicUsize>);

impl Drop for ActiveHandler {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn handle_connection(mut stream: TcpStream, state: &DevnetRPCState) -> Result<(), String> {
    stream
        .set_nonblocking(false)
        .map_err(|err| format!("set_nonblocking: {err}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| format!("set_read_timeout: {err}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| format!("set_write_timeout: {err}"))?;
    // Translate recognised request-framing errors into structured HTTP
    // responses so callers see the same 413/400 surface that the Go devnet
    // RPC emits (parity with the #1148 Go-first slice merged as PR #1279).
    // Anything unrecognised falls through to a generic 400 "invalid request".
    let req = match read_http_request(&mut stream) {
        Ok(req) => req,
        Err(err) => {
            let response = read_http_error_response(&err);
            return write_http_response(&mut stream, response);
        }
    };
    let response = route_request(state, req);
    write_http_response(&mut stream, response)
}

fn read_http_error_response(err: &str) -> HttpResponse {
    // Preserve the specific framing-class error string emitted by the reader
    // so debugging/parity checks see the exact class, not a generic fallback.
    // Any unrecognised error falls through to the generic "invalid request"
    // 400 body — kept deliberately broad so transient I/O or unknown classes
    // surface as a safe default.
    let (status, message) = match err {
        "body too large" | "request too large" => (413, "request body too large"),
        "conflicting transfer-encoding and content-length" => {
            (400, "conflicting transfer-encoding and content-length")
        }
        "conflicting Content-Length" => (400, "conflicting Content-Length"),
        "unsupported transfer-encoding" => (400, "unsupported transfer-encoding"),
        "duplicate Transfer-Encoding" => (400, "duplicate Transfer-Encoding"),
        "invalid chunk size" | "invalid chunk terminator" | "invalid chunked body" => {
            (400, "invalid chunked body")
        }
        "headers too large" => (400, "headers too large"),
        "invalid Content-Length" => (400, "invalid Content-Length"),
        "invalid request headers" => (400, "invalid request headers"),
        "malformed header" => (400, "malformed header"),
        "malformed HTTP version" => (400, "malformed HTTP version"),
        "missing request line" => (400, "missing request line"),
        "missing method" => (400, "missing method"),
        "missing target" => (400, "missing target"),
        "missing http version" => (400, "missing http version"),
        _ => (400, "invalid request"),
    };
    let body = serde_json::to_vec(&SubmitTxResponse {
        accepted: false,
        txid: None,
        error: Some(message.to_string()),
    })
    .unwrap_or_else(|_| b"{\"accepted\":false,\"error\":\"invalid request\"}".to_vec());
    HttpResponse::plain(status, "application/json", body)
}

fn route_request(state: &DevnetRPCState, req: HttpRequest) -> HttpResponse {
    let (path, query) = split_target(&req.target);
    match path {
        "/ready" => handle_ready(state, &req.method),
        "/peers" => handle_peers(state, &req.method),
        "/get_tip" => handle_get_tip(state, &req.method),
        "/get_block" => handle_get_block(state, &req.method, &query),
        "/submit_tx" => handle_submit_tx(state, &req.method, &req.body),
        "/mine_next" => handle_mine_next(state, &req.method, &req.body),
        "/get_mempool" => handle_get_mempool(state, &req.method),
        "/get_tx" => handle_get_tx(state, &req.method, &query),
        "/tx_status" => handle_tx_status(state, &req.method, &query),
        "/metrics" => handle_metrics(state, &req.method),
        _ => json_response(
            state,
            "/unknown",
            404,
            &SubmitTxResponse {
                accepted: false,
                txid: None,
                error: Some("route not found".to_string()),
            },
        ),
    }
}

/// RUB-10 / GitHub #1151: `/ready` endpoint for mixed-client devnet
/// evidence consumers. Returns one of:
///   - 200 `{"ready":true}` when the gate is in `Ready` state
///     (post-`try_mark_ready_on_startup`, pre-`mark_shutdown`)
///   - 503 `{"ready":false}` when the gate is in `NotReady`
///     (pre-startup) or `Shutdown` (post-shutdown) state
///   - 405 `{"accepted":false,"error":"GET required"}` with
///     `Allow: GET` header on non-GET methods, per RFC 9110 §15.5.6
///
/// Mirrors Go's `handleReady` at
/// `clients/go/cmd/rubin-node/http_rpc.go:645-670` at the JSON shape
/// and status-code level (`{ready: bool}` payload; same 200/503
/// split; same 405+`Allow: GET` envelope shared with the rest of the
/// surface via the `accepted/error` JSON shape). Documented
/// byte-level divergence (pre-existing, applies to every Rust
/// devnet RPC handler not just `/ready`): Go's `writeJSONResponse`
/// uses `json.NewEncoder(w).Encode` which appends a trailing `\n`,
/// while Rust's `json_response` uses `serde_json::to_vec` which
/// does not. JSON-parsing consumers tolerate either; this divergence
/// is not introduced by RUB-10.
///
/// Status code 405 (vs the 400 used by other Rust query handlers like
/// `handle_get_tip` / `handle_get_block`) is intentional and matches
/// Go's `/ready`-specific choice — readiness probes from monitoring
/// systems rely on the standard 405+Allow contract for self-correction.
/// Migrating the other query handlers from 400 to 405 is a separate
/// concern outside RUB-10's scope (would change established endpoint
/// behavior, class change risk).
fn handle_ready(state: &DevnetRPCState, method: &str) -> HttpResponse {
    const ROUTE: &str = "/ready";
    if method != "GET" {
        // Copilot wave-1 P2 on PR #1472: build the 405 body via the
        // shared `json_response` helper for encoder/fallback/metrics
        // parity with every other handler, then attach `Allow: GET`
        // separately. The Go counterpart `handleReady` writes JSON
        // inline, but Rust idiom + bug-class consistency favors the
        // helper here; the wire envelope is identical.
        return json_response(
            state,
            ROUTE,
            405,
            &SubmitTxResponse {
                accepted: false,
                txid: None,
                error: Some("GET required".to_string()),
            },
        )
        .with_header("Allow", "GET");
    }
    let ready = state.readiness.is_ready();
    let status: u16 = if ready { 200 } else { 503 };
    json_response(state, ROUTE, status, &ReadyResponse { ready })
}

/// RUB-14 / GitHub #1159: GET `/peers` — deterministic snapshot of
/// the live `PeerManager` projected to a bounded JSON shape. Returns:
///   - 200 `{count: usize, peers: [PeerEntry...]}` sorted by `addr`
///     ascending, on a successful GET (any peer count, including
///     zero — empty peer set is `{"count":0,"peers":[]}`)
///   - 405 `{"accepted":false,"error":"GET required"}` with
///     `Allow: GET` header on non-GET methods, per RFC 9110 §15.5.6
///
/// Mirrors Go's `handlePeers` at `clients/go/cmd/rubin-node/http_rpc.go:1584-1621`
/// at the JSON envelope, sort order, and status grammar level. Read-
/// only by construction: `PeerManager::snapshot()` returns owned
/// `Vec<PeerState>` (cloned values, not references), so the
/// projection cannot mutate runtime peer state.
///
/// Documented divergence from Go's 503 path (out of RUB-14 narrow
/// scope per `class_change_stop_rule`): Go's handler emits 503
/// `{accepted:false,error:"peer manager unavailable"}` when
/// `state.peerManager == nil`. Rust's `DevnetRPCState.peer_manager`
/// is `Arc<PeerManager>` and is structurally non-null — there is no
/// reachable nil path through the public construction surface. The
/// closest Rust analogue would be a poisoned `RwLock` inside
/// `PeerManager`, but `PeerManager::snapshot()`
/// (`clients/rust/crates/rubin-node/src/p2p_runtime.rs:235-240`)
/// already absorbs poison as `Vec::new()`, so an unhealthy lock
/// surfaces here as 200 `{count:0,peers:[]}` (operationally
/// indistinguishable from a real zero-peer startup at this layer).
/// Lifting this divergence requires extending `PeerManager`'s
/// public API to surface lock health, an edit that touches
/// `p2p_runtime.rs` and is excluded from RUB-14's narrowed
/// `devnet_rpc.rs`-only scope; deferred to a follow-up issue if
/// mixed-client orchestrators ever need to distinguish the two
/// cases (RUB-12 owns later operator surface elaboration).
///
/// Sort discipline: stable sort on `addr` (`String::cmp`, byte-wise
/// lexicographic) — same total order Go's `sort.Slice` produces on
/// `string` comparison. Two scrapes against an unchanging peer set
/// are byte-stable.
fn handle_peers(state: &DevnetRPCState, method: &str) -> HttpResponse {
    const ROUTE: &str = "/peers";
    if method != "GET" {
        return json_response(
            state,
            ROUTE,
            405,
            &SubmitTxResponse {
                accepted: false,
                txid: None,
                error: Some("GET required".to_string()),
            },
        )
        .with_header("Allow", "GET");
    }
    let mut snapshot = state.peer_manager.snapshot();
    snapshot.sort_by(|a, b| a.addr.cmp(&b.addr));
    let peers: Vec<PeerEntry> = snapshot
        .into_iter()
        .map(|p| PeerEntry {
            addr: p.addr,
            handshake_complete: p.handshake_complete,
            ban_score: p.ban_score,
            last_error: p.last_error,
            protocol_version: p.remote_version.protocol_version,
            best_height: p.remote_version.best_height,
            tx_relay: p.remote_version.tx_relay,
            pruned_below_height: p.remote_version.pruned_below_height,
            da_mempool_size: p.remote_version.da_mempool_size,
        })
        .collect();
    let count = peers.len();
    json_response(state, ROUTE, 200, &PeersResponse { count, peers })
}

fn handle_get_tip(state: &DevnetRPCState, method: &str) -> HttpResponse {
    const ROUTE: &str = "/get_tip";
    if method != "GET" {
        return json_response(
            state,
            ROUTE,
            400,
            &SubmitTxResponse {
                accepted: false,
                txid: None,
                error: Some("GET required".to_string()),
            },
        );
    }
    let engine = match state.sync_engine.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return json_response(
                state,
                ROUTE,
                503,
                &SubmitTxResponse {
                    accepted: false,
                    txid: None,
                    error: Some("sync engine unavailable".to_string()),
                },
            )
        }
    };
    let best_known_height = engine.best_known_height();
    let in_ibd = engine.is_in_ibd((state.now_unix)());
    let tip = match engine.tip() {
        Ok(tip) => tip,
        Err(err) => {
            return json_response(
                state,
                ROUTE,
                503,
                &SubmitTxResponse {
                    accepted: false,
                    txid: None,
                    error: Some(err),
                },
            )
        }
    };
    match tip {
        Some((height, hash)) => json_response(
            state,
            ROUTE,
            200,
            &GetTipResponse {
                has_tip: true,
                height: Some(height),
                tip_hash: Some(hex::encode(hash)),
                best_known_height,
                in_ibd,
            },
        ),
        None => json_response(
            state,
            ROUTE,
            200,
            &GetTipResponse {
                has_tip: false,
                height: None,
                tip_hash: None,
                best_known_height,
                in_ibd,
            },
        ),
    }
}

fn handle_get_block(state: &DevnetRPCState, method: &str, query: &str) -> HttpResponse {
    const ROUTE: &str = "/get_block";
    if method != "GET" {
        return json_response(
            state,
            ROUTE,
            400,
            &SubmitTxResponse {
                accepted: false,
                txid: None,
                error: Some("GET required".to_string()),
            },
        );
    }
    let block_store = match fresh_block_store(state) {
        Ok(Some(block_store)) => block_store,
        Ok(None) => {
            return json_response(
                state,
                ROUTE,
                503,
                &SubmitTxResponse {
                    accepted: false,
                    txid: None,
                    error: Some("blockstore unavailable".to_string()),
                },
            );
        }
        Err(err) => {
            return json_response(
                state,
                ROUTE,
                503,
                &SubmitTxResponse {
                    accepted: false,
                    txid: None,
                    error: Some(err),
                },
            );
        }
    };
    let params = parse_query_map(query);
    let height_raw = params.get("height").map(|v| v.trim()).unwrap_or("");
    let hash_raw = params.get("hash").map(|v| v.trim()).unwrap_or("");
    if (height_raw.is_empty() && hash_raw.is_empty())
        || (!height_raw.is_empty() && !hash_raw.is_empty())
    {
        return json_response(
            state,
            ROUTE,
            400,
            &SubmitTxResponse {
                accepted: false,
                txid: None,
                error: Some("exactly one of height or hash is required".to_string()),
            },
        );
    }

    let (height, block_hash) = if !height_raw.is_empty() {
        let height = match height_raw.parse::<u64>() {
            Ok(height) => height,
            Err(_) => {
                return json_response(
                    state,
                    ROUTE,
                    400,
                    &SubmitTxResponse {
                        accepted: false,
                        txid: None,
                        error: Some("invalid height".to_string()),
                    },
                )
            }
        };
        let hash = match block_store.canonical_hash(height) {
            Ok(Some(hash)) => hash,
            Ok(None) => {
                return json_response(
                    state,
                    ROUTE,
                    404,
                    &SubmitTxResponse {
                        accepted: false,
                        txid: None,
                        error: Some("block not found".to_string()),
                    },
                )
            }
            Err(err) => {
                return json_response(
                    state,
                    ROUTE,
                    503,
                    &SubmitTxResponse {
                        accepted: false,
                        txid: None,
                        error: Some(err),
                    },
                )
            }
        };
        (height, hash)
    } else {
        let hash = match parse_hex32(hash_raw) {
            Ok(hash) => hash,
            Err(_) => {
                return json_response(
                    state,
                    ROUTE,
                    400,
                    &SubmitTxResponse {
                        accepted: false,
                        txid: None,
                        error: Some("invalid hash".to_string()),
                    },
                )
            }
        };
        let height = match block_store.find_canonical_height(hash) {
            Ok(Some(height)) => height,
            Ok(None) => {
                return json_response(
                    state,
                    ROUTE,
                    404,
                    &SubmitTxResponse {
                        accepted: false,
                        txid: None,
                        error: Some("block not found".to_string()),
                    },
                )
            }
            Err(err) => {
                return json_response(
                    state,
                    ROUTE,
                    503,
                    &SubmitTxResponse {
                        accepted: false,
                        txid: None,
                        error: Some(err),
                    },
                )
            }
        };
        (height, hash)
    };
    match block_store.get_block_by_hash(block_hash) {
        Ok(block_bytes) => json_response(
            state,
            ROUTE,
            200,
            &GetBlockResponse {
                hash: hex::encode(block_hash),
                height,
                canonical: true,
                block_hex: hex::encode(block_bytes),
            },
        ),
        Err(err) => json_response(
            state,
            ROUTE,
            503,
            &SubmitTxResponse {
                accepted: false,
                txid: None,
                error: Some(err),
            },
        ),
    }
}

fn handle_submit_tx(state: &DevnetRPCState, method: &str, body: &[u8]) -> HttpResponse {
    const ROUTE: &str = "/submit_tx";
    if method != "POST" {
        return json_response(
            state,
            ROUTE,
            400,
            &SubmitTxResponse {
                accepted: false,
                txid: None,
                error: Some("POST required".to_string()),
            },
        );
    }
    let req: SubmitTxRequest = match serde_json::from_slice(body) {
        Ok(req) => req,
        Err(_) => {
            state.metrics.note_submit("bad_request");
            return json_response(
                state,
                ROUTE,
                400,
                &SubmitTxResponse {
                    accepted: false,
                    txid: None,
                    error: Some("invalid JSON body".to_string()),
                },
            );
        }
    };
    let tx_bytes = match decode_hex_payload(&req.tx_hex) {
        Ok(bytes) => bytes,
        Err(err) => {
            state.metrics.note_submit("bad_request");
            return json_response(
                state,
                ROUTE,
                400,
                &SubmitTxResponse {
                    accepted: false,
                    txid: None,
                    error: Some(err),
                },
            );
        }
    };
    let _rpc_op = match state.rpc_op_lock.lock() {
        Ok(guard) => guard,
        Err(_) => {
            state.metrics.note_submit("unavailable");
            return json_response(
                state,
                ROUTE,
                503,
                &SubmitTxResponse {
                    accepted: false,
                    txid: None,
                    error: Some("rpc unavailable".to_string()),
                },
            );
        }
    };
    let (chain_state, chain_id) = match state.sync_engine.lock() {
        Ok(engine) => (engine.chain_state_snapshot(), engine.chain_id()),
        Err(_) => {
            state.metrics.note_submit("unavailable");
            return json_response(
                state,
                ROUTE,
                503,
                &SubmitTxResponse {
                    accepted: false,
                    txid: None,
                    error: Some("sync engine unavailable".to_string()),
                },
            );
        }
    };
    let fresh_block_store = match fresh_block_store(state) {
        Ok(block_store) => block_store,
        Err(err) => {
            state.metrics.note_submit("unavailable");
            return json_response(
                state,
                ROUTE,
                503,
                &SubmitTxResponse {
                    accepted: false,
                    txid: None,
                    error: Some(err),
                },
            );
        }
    };
    // RUB-171 producer-wiring slice (RUB-163 child). Devnet RPC submit_tx is
    // the canonical Local producer entry into the txpool: it admits a
    // user-submitted transaction on the local node, mirroring Go
    // `handleSubmitTx` (`clients/go/cmd/rubin-node/http_rpc.go:924`) which
    // calls `mempool.AddTx` -> `addTxWithSource(_, mempoolTxSourceLocal)`
    // (clients/go/node/mempool.go:411). Tagging the admission as
    // `TxSource::Local` is observability metadata only — admission ordering,
    // eviction priority and consensus semantics remain source-blind (see
    // `txpool.rs::compare_entries_for_mining` and the
    // `source_does_not_affect_admission_ordering` test from RUB-174). Source
    // is recorded on the resulting `TxPoolEntry` and surfaced via
    // `TxPool::entry_source` for downstream parity tests.
    let admit_result = match state.tx_pool.lock() {
        Ok(mut pool) => pool.add_tx_with_source(
            &tx_bytes,
            &chain_state,
            fresh_block_store.as_ref(),
            chain_id,
            TxSource::Local,
        ),
        Err(_) => Err(crate::TxPoolAdmitError {
            kind: TxPoolAdmitErrorKind::Unavailable,
            message: "tx pool unavailable".to_string(),
        }),
    };
    // Release rpc_op_lock before announce: announce is p2p broadcast, not
    // chain/tx-pool mutation, so holding the RPC op lock across a slow
    // network callback would block concurrent /mine_next for no benefit.
    // Matches the narrowed Go scope in
    // `clients/go/cmd/rubin-node/http_rpc.go::handleSubmitTx`.
    drop(_rpc_op);
    match admit_result {
        Ok((txid, relay_meta)) => {
            // Relay tx to peers (fire-and-forget, matches Go behavior).
            if let Some(ref announce) = state.announce_tx {
                if let Err(err) = announce(&tx_bytes, relay_meta) {
                    eprintln!("rpc: announce-tx: {err}");
                }
            }
            state.metrics.note_submit("accepted");
            json_response(
                state,
                ROUTE,
                200,
                &SubmitTxResponse {
                    accepted: true,
                    txid: Some(hex::encode(txid)),
                    error: None,
                },
            )
        }
        Err(err) => {
            let (status, result) = match err.kind {
                TxPoolAdmitErrorKind::Conflict => (409, "conflict"),
                TxPoolAdmitErrorKind::Rejected => (422, "rejected"),
                TxPoolAdmitErrorKind::Unavailable => (503, "unavailable"),
            };
            state.metrics.note_submit(result);
            json_response(
                state,
                ROUTE,
                status,
                &SubmitTxResponse {
                    accepted: false,
                    txid: None,
                    error: Some(err.message),
                },
            )
        }
    }
}

fn handle_mine_next(state: &DevnetRPCState, method: &str, _body: &[u8]) -> HttpResponse {
    const ROUTE: &str = "/mine_next";
    if method != "POST" {
        return json_response(
            state,
            ROUTE,
            400,
            &MineNextResponse {
                mined: false,
                height: None,
                block_hash: None,
                timestamp: None,
                nonce: None,
                tx_count: None,
                error: Some("POST required".to_string()),
            },
        );
    }
    let Some(miner_cfg) = state.live_mining_cfg.as_ref() else {
        return json_response(
            state,
            ROUTE,
            503,
            &MineNextResponse {
                mined: false,
                height: None,
                block_hash: None,
                timestamp: None,
                nonce: None,
                tx_count: None,
                error: Some("live mining unavailable".to_string()),
            },
        );
    };
    let block_store = state.block_store.clone();
    let _rpc_op = match state.rpc_op_lock.lock() {
        Ok(g) => g,
        Err(_) => {
            return json_response(
                state,
                ROUTE,
                503,
                &MineNextResponse {
                    mined: false,
                    height: None,
                    block_hash: None,
                    timestamp: None,
                    nonce: None,
                    tx_count: None,
                    error: Some("rpc unavailable".to_string()),
                },
            );
        }
    };
    let mut sync_engine = match state.sync_engine.lock() {
        Ok(g) => g,
        Err(_) => {
            return json_response(
                state,
                ROUTE,
                503,
                &MineNextResponse {
                    mined: false,
                    height: None,
                    block_hash: None,
                    timestamp: None,
                    nonce: None,
                    tx_count: None,
                    error: Some("sync engine unavailable".to_string()),
                },
            );
        }
    };
    let mut pool = match state.tx_pool.lock() {
        Ok(g) => g,
        Err(_) => {
            return json_response(
                state,
                ROUTE,
                503,
                &MineNextResponse {
                    mined: false,
                    height: None,
                    block_hash: None,
                    timestamp: None,
                    nonce: None,
                    tx_count: None,
                    error: Some("tx pool unavailable".to_string()),
                },
            );
        }
    };
    let mut miner = match Miner::new(&mut sync_engine, Some(&mut pool), miner_cfg.clone()) {
        Ok(m) => m,
        Err(err) => {
            return json_response(
                state,
                ROUTE,
                503,
                &MineNextResponse {
                    mined: false,
                    height: None,
                    block_hash: None,
                    timestamp: None,
                    nonce: None,
                    tx_count: None,
                    error: Some(err),
                },
            );
        }
    };
    if let Some(provider) = state.live_complete_da_set_provider.as_ref() {
        miner.set_complete_da_set_provider(provider.as_ref());
    }
    let mined = match miner.mine_one(&[]) {
        Ok(b) => b,
        Err(err) => {
            return json_response(
                state,
                ROUTE,
                422,
                &MineNextResponse {
                    mined: false,
                    height: None,
                    block_hash: None,
                    timestamp: None,
                    nonce: None,
                    tx_count: None,
                    error: Some(err),
                },
            )
        }
    };
    let mined_hash = mined.hash;
    drop(miner);
    drop(pool);
    drop(sync_engine);
    if let Some(ref accepted) = state.accepted_block {
        if let Err(err) = accepted(mined_hash) {
            eprintln!("rpc: accepted-block: {err}");
        }
    }
    // Load the mined block bytes once for the fail-closed DA consume and the
    // best-effort announce.
    let block_bytes = match block_store {
        Some(store) => match store.get_block_by_hash(mined.hash) {
            Ok(bytes) => Some(bytes),
            Err(err) => {
                eprintln!(
                    "rpc: announce-block: get mined block {}: {err}",
                    hex::encode(mined.hash)
                );
                None
            }
        },
        None => {
            eprintln!(
                "rpc: announce-block: block store unavailable for {}",
                hex::encode(mined.hash)
            );
            None
        }
    };
    // Consume the just-mined block's complete DA sets while rpc_op_lock is still
    // held, before announce. Only the mine+apply success branch reaches here.
    if let Some(consumer) = state.accepted_block_da_consumer.as_ref() {
        let Some(bytes) = block_bytes.as_ref() else {
            return mine_next_consume_error(state, ROUTE, "load mined block for DA consume");
        };
        if let Err(err) = consumer(bytes) {
            return mine_next_consume_error(
                state,
                ROUTE,
                &format!("consume accepted DA sets: {err}"),
            );
        }
    }
    drop(_rpc_op);
    if let (Some(announce), Some(bytes)) = (state.announce_block.as_ref(), block_bytes.as_ref()) {
        if let Err(err) = announce(bytes) {
            eprintln!("rpc: announce-block: {err}");
        }
    }
    json_response(
        state,
        ROUTE,
        200,
        &MineNextResponse {
            mined: true,
            height: Some(mined.height),
            block_hash: Some(hex::encode(mined.hash)),
            timestamp: Some(mined.timestamp),
            nonce: Some(mined.nonce),
            tx_count: Some(mined.tx_count),
            error: None,
        },
    )
}

/// Builds a `/mine_next` HTTP 500 JSON response with `mined: false` and `msg`.
fn mine_next_consume_error(state: &DevnetRPCState, route: &str, msg: &str) -> HttpResponse {
    json_response(
        state,
        route,
        500,
        &MineNextResponse {
            mined: false,
            height: None,
            block_hash: None,
            timestamp: None,
            nonce: None,
            tx_count: None,
            error: Some(msg.to_string()),
        },
    )
}

/// Percent-decode a query component to raw bytes.  Returns `None` only on
/// malformed `%XX` escapes (truncated or non-hex digits), matching Go
/// `net/url.QueryUnescape` error semantics.  Returns `Vec<u8>` (not
/// `String`) because Go strings are arbitrary byte sequences and
/// `QueryUnescape` never rejects on UTF-8 grounds — keeping raw bytes
/// ensures `len()` matches Go's `len()` for the downstream length check
/// in `parse_txid_query`.
fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = (bytes[i + 1] as char).to_digit(16)?;
                let lo = (bytes[i + 2] as char).to_digit(16)?;
                out.push(((hi << 4) | lo) as u8);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    Some(out)
}

/// Decode a 64-hex-char "txid" query parameter to a [u8; 32]. Returns Err with
/// an operator-facing message on missing, wrong length, or non-hex input.
/// Parity contract with Go `r.URL.Query().Get("txid")`:
///   - A key without `=` (e.g. `?txid`) or with empty value (e.g. `?txid=`)
///     is classified as missing; Go's parseQuery stores `url.Values{"txid":
///     [""]}` and `Get` returns `""`, which the Go parser maps to
///     "missing required query parameter".
///   - First-match semantic via `break` mirrors Go's `Values.Get` returning
///     `values[0]`.
///   - Both key and value are percent-decoded; pairs that fail to decode
///     (malformed `%XX`) are silently skipped and the loop continues,
///     matching Go's `parseQuery` which `continue`s on either
///     `QueryUnescape` error and never stores the pair. This means
///     `?txid=%ZZ&txid=<hex>` resolves to the valid second occurrence on
///     BOTH clients, and `?%74%78%69%64=<hex>` (encoded "txid" key) is
///     accepted on BOTH clients.
fn parse_txid_query(query: &str) -> Result<[u8; 32], String> {
    let mut txid_bytes: Option<Vec<u8>> = None;
    for pair in query.split('&') {
        // Go 1.17+ (CVE-2021-44716): parseQuery rejects pairs containing
        // an unescaped semicolon.
        if pair.contains(';') {
            continue;
        }
        let (k_raw, v_raw) = pair.split_once('=').unwrap_or((pair, ""));
        let Some(k) = percent_decode(k_raw) else {
            continue;
        };
        // Key comparison on raw bytes — "txid" is ASCII so this is exact.
        if k != b"txid" {
            continue;
        }
        let Some(v) = percent_decode(v_raw) else {
            continue;
        };
        txid_bytes = Some(v);
        break;
    }
    let raw = txid_bytes
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "missing required query parameter: txid".to_string())?;
    // Length check on raw decoded bytes — matches Go's len(raw) which
    // counts bytes, not UTF-8 characters.
    if raw.len() != 64 {
        return Err(format!(
            "txid must be 64 hex characters (got {})",
            raw.len()
        ));
    }
    // Convert to UTF-8 string for hex::decode.  Valid hex is always ASCII,
    // so non-UTF-8 bytes (e.g. %ff decoded to 0xFF) fail here with the
    // same error class as Go's hex.DecodeString.
    let raw_str = std::str::from_utf8(&raw)
        .map_err(|_| "txid is not valid hex: contains non-ASCII decoded bytes".to_string())?;
    let decoded = hex::decode(raw_str).map_err(|err| format!("txid is not valid hex: {err}"))?;
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&decoded);
    Ok(txid)
}

fn handle_get_mempool(state: &DevnetRPCState, method: &str) -> HttpResponse {
    const ROUTE: &str = "/get_mempool";
    if method != "GET" {
        return json_response(
            state,
            ROUTE,
            400,
            &GetMempoolResponse {
                count: 0,
                txids: Vec::new(),
                error: Some("GET required".to_string()),
            },
        );
    }
    let pool = match state.tx_pool.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return json_response(
                state,
                ROUTE,
                503,
                &GetMempoolResponse {
                    count: 0,
                    txids: Vec::new(),
                    error: Some("mempool unavailable".to_string()),
                },
            );
        }
    };
    let mut ids = pool.all_txids();
    drop(pool);
    // Sort for deterministic response ordering; HashMap iteration is not
    // stable across calls.
    ids.sort();
    let txids: Vec<String> = ids.iter().map(hex::encode).collect();
    json_response(
        state,
        ROUTE,
        200,
        &GetMempoolResponse {
            count: txids.len(),
            txids,
            error: None,
        },
    )
}

fn handle_get_tx(state: &DevnetRPCState, method: &str, query: &str) -> HttpResponse {
    const ROUTE: &str = "/get_tx";
    if method != "GET" {
        return json_response(
            state,
            ROUTE,
            400,
            &GetTxResponse {
                found: false,
                txid: None,
                raw_hex: None,
                error: Some("GET required".to_string()),
            },
        );
    }
    // Fail-closed on tx pool unavailability BEFORE parsing the query, so a
    // poisoned pool + invalid/missing txid surfaces as 503 rather than 400.
    // Mirrors the Go handleGetTx contract (nil-mempool check runs first).
    if state.tx_pool.is_poisoned() {
        return json_response(
            state,
            ROUTE,
            503,
            &GetTxResponse {
                found: false,
                txid: None,
                raw_hex: None,
                error: Some("mempool unavailable".to_string()),
            },
        );
    }
    let txid = match parse_txid_query(query) {
        Ok(txid) => txid,
        Err(err) => {
            return json_response(
                state,
                ROUTE,
                400,
                &GetTxResponse {
                    found: false,
                    txid: None,
                    raw_hex: None,
                    error: Some(err),
                },
            );
        }
    };
    let pool = match state.tx_pool.lock() {
        Ok(guard) => guard,
        Err(_) => {
            // Race: pool became poisoned between is_poisoned() and lock().
            // Still fail-closed with 503.
            return json_response(
                state,
                ROUTE,
                503,
                &GetTxResponse {
                    found: false,
                    txid: None,
                    raw_hex: None,
                    error: Some("mempool unavailable".to_string()),
                },
            );
        }
    };
    let raw = pool.tx_by_id(&txid);
    drop(pool);
    match raw {
        Some(bytes) => json_response(
            state,
            ROUTE,
            200,
            &GetTxResponse {
                found: true,
                txid: Some(hex::encode(txid)),
                raw_hex: Some(hex::encode(bytes)),
                error: None,
            },
        ),
        None => json_response(
            state,
            ROUTE,
            200,
            &GetTxResponse {
                found: false,
                txid: Some(hex::encode(txid)),
                raw_hex: None,
                error: None,
            },
        ),
    }
}

fn handle_tx_status(state: &DevnetRPCState, method: &str, query: &str) -> HttpResponse {
    const ROUTE: &str = "/tx_status";
    if method != "GET" {
        return json_response(
            state,
            ROUTE,
            400,
            &TxStatusResponse {
                status: "missing".to_string(),
                txid: None,
                error: Some("GET required".to_string()),
            },
        );
    }
    // Fail-closed on tx pool unavailability BEFORE parsing the query
    // (mirrors handle_get_tx and the Go handleTxStatus contract).
    if state.tx_pool.is_poisoned() {
        return json_response(
            state,
            ROUTE,
            503,
            &TxStatusResponse {
                status: "missing".to_string(),
                txid: None,
                error: Some("mempool unavailable".to_string()),
            },
        );
    }
    let txid = match parse_txid_query(query) {
        Ok(txid) => txid,
        Err(err) => {
            return json_response(
                state,
                ROUTE,
                400,
                &TxStatusResponse {
                    status: "missing".to_string(),
                    txid: None,
                    error: Some(err),
                },
            );
        }
    };
    let pool = match state.tx_pool.lock() {
        Ok(guard) => guard,
        Err(_) => {
            // Race: pool became poisoned between is_poisoned() and lock().
            // Still fail-closed with 503.
            return json_response(
                state,
                ROUTE,
                503,
                &TxStatusResponse {
                    status: "missing".to_string(),
                    txid: None,
                    error: Some("mempool unavailable".to_string()),
                },
            );
        }
    };
    let status = if pool.contains(&txid) {
        "pending"
    } else {
        "missing"
    };
    drop(pool);
    json_response(
        state,
        ROUTE,
        200,
        &TxStatusResponse {
            status: status.to_string(),
            txid: Some(hex::encode(txid)),
            error: None,
        },
    )
}

fn handle_metrics(state: &DevnetRPCState, method: &str) -> HttpResponse {
    const ROUTE: &str = "/metrics";
    if method != "GET" {
        return json_response(
            state,
            ROUTE,
            400,
            &SubmitTxResponse {
                accepted: false,
                txid: None,
                error: Some("GET required".to_string()),
            },
        );
    }
    let body = render_prometheus_metrics(state);
    state.metrics.note(ROUTE, 200);
    HttpResponse::plain(200, "text/plain; version=0.0.4", body)
}

fn render_prometheus_metrics(state: &DevnetRPCState) -> String {
    let (tip_height, best_known_height, in_ibd, reorg_count, last_reorg_depth, pv_lines) =
        match state.sync_engine.lock() {
            Ok(engine) => {
                let tip_height = match engine.tip() {
                    Ok(Some((height, _))) => height,
                    _ => 0,
                };
                let best_known_height = engine.best_known_height();
                let in_ibd = if engine.is_in_ibd((state.now_unix)()) {
                    1
                } else {
                    0
                };
                let reorg_count = engine.reorg_count();
                let last_reorg_depth = engine.last_reorg_depth();
                let pv_lines = engine.pv_telemetry_snapshot().prometheus_lines();
                (
                    tip_height,
                    best_known_height,
                    in_ibd,
                    reorg_count,
                    last_reorg_depth,
                    pv_lines,
                )
            }
            Err(_) => (0, 0, 1, 0, 0, Vec::new()),
        };
    let mempool_txs = match state.tx_pool.lock() {
        Ok(pool) => pool.len() as u64,
        Err(_) => 0,
    };
    let peer_count = state.peer_manager.snapshot().len() as u64;
    let orphan_metrics = orphan_pool_metrics_snapshot();
    let (route_status, submit_results) = state.metrics.snapshot();

    let mut lines = vec![
        "# HELP rubin_node_tip_height Current canonical tip height.".to_string(),
        "# TYPE rubin_node_tip_height gauge".to_string(),
        format!("rubin_node_tip_height {tip_height}"),
        "# HELP rubin_node_best_known_height Best known height recorded by sync engine."
            .to_string(),
        "# TYPE rubin_node_best_known_height gauge".to_string(),
        format!("rubin_node_best_known_height {best_known_height}"),
        "# HELP rubin_node_in_ibd Whether the node currently considers itself in IBD (0 or 1)."
            .to_string(),
        "# TYPE rubin_node_in_ibd gauge".to_string(),
        format!("rubin_node_in_ibd {in_ibd}"),
        "# HELP rubin_node_reorg_total Total canonical reorg events observed by the sync engine."
            .to_string(),
        "# TYPE rubin_node_reorg_total counter".to_string(),
        format!("rubin_node_reorg_total {reorg_count}"),
        "# HELP rubin_node_last_reorg_depth Depth of the most recent canonical reorg, or 0 when no reorg depth is currently recorded."
            .to_string(),
        "# TYPE rubin_node_last_reorg_depth gauge".to_string(),
        format!("rubin_node_last_reorg_depth {last_reorg_depth}"),
        "# HELP rubin_node_peer_count Currently tracked peers.".to_string(),
        "# TYPE rubin_node_peer_count gauge".to_string(),
        format!("rubin_node_peer_count {peer_count}"),
        "# HELP rubin_node_p2p_orphan_pool_blocks Live Rust P2P orphan blocks retained in memory across peer sessions."
            .to_string(),
        "# TYPE rubin_node_p2p_orphan_pool_blocks gauge".to_string(),
        format!(
            "rubin_node_p2p_orphan_pool_blocks {}",
            orphan_metrics.live_blocks
        ),
        "# HELP rubin_node_p2p_orphan_pool_bytes Live Rust P2P orphan block bytes retained in memory across peer sessions."
            .to_string(),
        "# TYPE rubin_node_p2p_orphan_pool_bytes gauge".to_string(),
        format!(
            "rubin_node_p2p_orphan_pool_bytes {}",
            orphan_metrics.live_bytes
        ),
        "# HELP rubin_node_mempool_txs Number of transactions currently in the mempool."
            .to_string(),
        "# TYPE rubin_node_mempool_txs gauge".to_string(),
        format!("rubin_node_mempool_txs {mempool_txs}"),
        "# HELP rubin_node_rpc_requests_total Total HTTP RPC requests by route and status."
            .to_string(),
        "# TYPE rubin_node_rpc_requests_total counter".to_string(),
    ];

    let mut route_entries: Vec<_> = route_status.into_iter().collect();
    route_entries.sort_by(|a, b| a.0.cmp(&b.0));
    for ((route, status), value) in route_entries {
        // RUB-12 / GitHub #1156 class-sweep: Go counterpart at
        // `clients/go/cmd/rubin-node/http_rpc.go:1314` formats this
        // line via `fmt.Sprintf("...{route=%q,status=%q}...", route,
        // status, ...)`. The `route` label is a `String` and must be
        // run through `escape_prometheus_label_value` for the same
        // injection / byte-parity reasons as `rubin_pv_mode{mode=...}`
        // (the wave-2 fix on the PV telemetry emitter). `status` on
        // the Rust side is a `u16` whose `Display` impl can only emit
        // ASCII digits, so it cannot inject special characters;
        // quoting it via the surrounding literal `"..."` is byte-
        // identical to what `%q` emits on the Go side, because Goʼs
        // `status` is itself a `string` (split from the `route|status`
        // metric key at `http_rpc.go:1306-1310`) populated with the
        // same ASCII-digit HTTP status code, and `%q` on an ASCII-
        // only string emits exactly the same outer `"..."` wrapper
        // the Rust literal already provides.
        let escaped_route = crate::sync::escape_prometheus_label_value(&route);
        lines.push(format!(
            "rubin_node_rpc_requests_total{{route=\"{escaped_route}\",status=\"{status}\"}} {value}"
        ));
    }

    lines.push(
        "# HELP rubin_node_submit_tx_total Total submit_tx outcomes by result label.".to_string(),
    );
    lines.push("# TYPE rubin_node_submit_tx_total counter".to_string());
    let mut submit_entries: Vec<_> = submit_results.into_iter().collect();
    submit_entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (result, value) in submit_entries {
        // RUB-12 / GitHub #1156 class-sweep: Go counterpart at
        // `clients/go/cmd/rubin-node/http_rpc.go:1334` formats this
        // line via `fmt.Sprintf("...{result=%q}...", key, ...)`.
        // Reuse the wave-2 escape helper on `result` for symmetry
        // with the `rubin_pv_mode{mode=...}` emitter and Goʼs `%q`
        // byte stream.
        let escaped_result = crate::sync::escape_prometheus_label_value(&result);
        lines.push(format!(
            "rubin_node_submit_tx_total{{result=\"{escaped_result}\"}} {value}"
        ));
    }
    lines.extend(pv_lines);
    lines.join("\n") + "\n"
}

fn fresh_block_store(state: &DevnetRPCState) -> Result<Option<BlockStore>, String> {
    let Some(block_store) = state.block_store.as_ref() else {
        return Ok(None);
    };
    BlockStore::open(block_store.root_dir()).map(Some)
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 4096];
    let header_end = loop {
        let read = stream
            .read(&mut temp)
            .map_err(|err| format!("read: {err}"))?;
        if read == 0 {
            return Err("unexpected eof".to_string());
        }
        buf.extend_from_slice(&temp[..read]);
        if buf.len() > MAX_HEADER_BYTES + MAX_BODY_BYTES {
            return Err("request too large".to_string());
        }
        if let Some(pos) = find_header_end(&buf) {
            // Enforce the header-block cap BEFORE accepting a terminator
            // that arrives in a crossing read: a sender can leave the
            // parser at exactly MAX_HEADER_BYTES bytes without CRLFCRLF
            // (still below the post-read cap below) and then deliver the
            // terminator plus one more byte in the next read. Go's net/http
            // header reader rejects equivalent over-cap terminated lines
            // (textproto.Reader.readContinuedLineSlice); so do we.
            if pos > MAX_HEADER_BYTES {
                return Err("headers too large".to_string());
            }
            break pos;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err("headers too large".to_string());
        }
    };

    let header_text = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| "invalid request headers".to_string())?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_string())?;
    // Go `src/net/http/request.go parseRequestLine` uses exactly two
    // `strings.Cut(line, " ")` on single spaces, so the proto segment is
    // the FULL remainder after the second cut (not a third whitespace
    // token). That lets `ParseHTTPVersion` reject both trailing junk
    // (`"HTTP/1.1 EXTRA"`) and multi-space-separated requests
    // (`"POST  /submit_tx HTTP/1.1"` → method="POST", rest=" /submit_tx …",
    // target="", version="/submit_tx HTTP/1.1" → malformed). Mirror that
    // here via `split_once(' ')` — whitespace other than a single ASCII
    // space is NOT a token separator.
    let (method, rest) = request_line
        .split_once(' ')
        .ok_or_else(|| "missing target".to_string())?;
    let (target, version) = rest
        .split_once(' ')
        .ok_or_else(|| "missing http version".to_string())?;
    if method.is_empty() {
        return Err("missing method".to_string());
    }
    // Go `parseRequestLine` returns an empty target on inputs like
    // `"POST  HTTP/1.1"` but the downstream URL parse (`NewRequest`)
    // rejects the empty URI as `"parse \"\": empty url"`. We fold the
    // URL-level rejection into the request-line parse here so the
    // handler is never reached with an empty target.
    if target.is_empty() {
        return Err("missing target".to_string());
    }
    let method = method.to_string();
    let target = target.to_string();
    // Go `src/net/http/request.go readRequest` calls `ParseHTTPVersion` and
    // returns `badStringError("malformed HTTP version", req.Proto)` when
    // the result is not ok, so the handler never runs on a malformed
    // version string. Mirror that: reject outright on malformed shape,
    // then use `protoAtLeast(1, 1)` to gate Transfer-Encoding parsing per
    // `src/net/http/transfer.go parseTransferEncoding` (Issue 12785 — TE is
    // silently ignored on HTTP/1.0 but still processed on HTTP/1.1+).
    let (proto_major, proto_minor) = parse_http_version(version)?;
    let http_proto_at_least_11 = proto_major > 1 || (proto_major == 1 && proto_minor >= 1);

    let mut content_length: Option<usize> = None;
    let mut content_length_raw: Option<String> = None;
    let mut is_chunked = false;
    let mut te_seen = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("malformed header".to_string());
        };
        // RFC 7230 §3.2.4: no whitespace is permitted between the header
        // field-name and colon. Differences in handling whitespace here have
        // led to request-smuggling vulnerabilities. This is a deliberate
        // RFC fail-closed rejection and is STRICTER than Go's `textproto`
        // legacy behaviour — Go accepts such messages, stores the name
        // uncanonicalized (`canonicalMIMEHeaderKey` returns the raw bytes
        // unchanged, see src/net/textproto/reader.go:753-770), and lets
        // downstream canonical-key lookups (`Header.Get("Transfer-Encoding")`)
        // silently miss the spaced variant. That silent miss is itself a
        // smuggling hazard when an upstream component canonicalises
        // differently, so we reject outright. Enforce the token rule
        // directly on the raw `name` slice (no `.trim()`): field-name is
        // `1*tchar` per RFC 7230 §3.2.6, so any leading/trailing/interior
        // whitespace (or other non-token byte) is a framing error.
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err("malformed header".to_string());
        }
        let name_trimmed = name;
        if name_trimmed.eq_ignore_ascii_case("content-length") {
            let value_trimmed = value.trim();
            // RFC 7230 §3.3.2 + Go net/http fixLength parity: duplicate
            // Content-Length headers are accepted only when their trimmed
            // byte values are IDENTICAL. Go uses `textproto.TrimString(first)
            // != textproto.TrimString(ct)` (src/net/http/transfer.go:671-674),
            // so "4" + "04" is rejected as smuggling vector even though the
            // numeric values are equal. Storing the raw trimmed string and
            // doing a byte-equality check matches Go exactly.
            if let Some(existing) = content_length_raw.as_deref() {
                if existing != value_trimmed {
                    return Err("conflicting Content-Length".to_string());
                }
                // Exact duplicate — already parsed, skip re-parse.
                continue;
            }
            let parsed = value_trimmed
                .parse::<usize>()
                .map_err(|_| "invalid Content-Length".to_string())?;
            content_length_raw = Some(value_trimmed.to_string());
            content_length = Some(parsed);
        } else if name_trimmed.eq_ignore_ascii_case("transfer-encoding") {
            if !http_proto_at_least_11 {
                // Pre-HTTP/1.1 request: ignore Transfer-Encoding per Go
                // `parseTransferEncoding` (src/net/http/transfer.go). The
                // header is silently dropped so the request falls through
                // to the Content-Length-or-empty body path.
                continue;
            }
            // Matches Go net/http readTransfer: more than one Transfer-Encoding
            // header is rejected as `too many transfer encodings`, regardless
            // of whether both values are `chunked`. Accepting duplicates would
            // desync Rust from upstream components that reject them.
            if te_seen {
                return Err("duplicate Transfer-Encoding".to_string());
            }
            te_seen = true;
            // Only "chunked" is supported; anything else is rejected so we
            // never read a body under a framing we cannot decode correctly.
            if !value.trim().eq_ignore_ascii_case("chunked") {
                return Err("unsupported transfer-encoding".to_string());
            }
            is_chunked = true;
        }
    }
    // RFC 7230 §3.3.3: a request that carries both Transfer-Encoding and
    // Content-Length is ambiguous and must be rejected to prevent request
    // smuggling.
    if is_chunked && content_length.is_some() {
        return Err("conflicting transfer-encoding and content-length".to_string());
    }

    let body_start = header_end + 4;

    if is_chunked {
        let body = read_chunked_body(&mut buf, stream, body_start, &mut temp)?;
        return Ok(HttpRequest {
            method,
            target,
            body,
        });
    }

    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err("body too large".to_string());
    }

    // `content_length` was already bounded by MAX_BODY_BYTES above, so this
    // loop terminates as soon as `body_start + content_length` bytes are
    // buffered. A single `stream.read` may pull a few extra bytes past that
    // point (e.g. the start of a pipelined next request on the same
    // connection); those are discarded when we slice the body below, so no
    // in-loop raw-buffer cap is needed here — adding one would spuriously
    // reject a boundary-valid body whose last read coalesced with trailing
    // bytes.
    while buf.len() < body_start + content_length {
        let read = stream
            .read(&mut temp)
            .map_err(|err| format!("read body: {err}"))?;
        if read == 0 {
            return Err("unexpected eof".to_string());
        }
        buf.extend_from_slice(&temp[..read]);
    }
    let body = buf[body_start..body_start + content_length].to_vec();
    Ok(HttpRequest {
        method,
        target,
        body,
    })
}

// read_chunked_body decodes an HTTP/1.1 `Transfer-Encoding: chunked` body
// from a stream into a flat Vec<u8>. The returned body is capped at
// MAX_BODY_BYTES to match the Go `/submit_tx` cap; any chunk (or accumulation
// of chunks) that would push the *decoded* body past the cap returns
// `Err("body too large")`, which handle_connection translates into a 413 JSON
// response. The parser compacts the raw buffer on an amortized basis rather
// than draining it after every chunk segment, but retained unread state stays
// bounded to the current parse window: at most one chunk-size or trailer line
// (< MAX_CHUNK_LINE_BYTES) plus at most one chunk-data window. This prevents
// a tiny-chunk DoS without rejecting valid high-overhead chunked bodies whose
// decoded size is still below the cap.
//
// In addition to the decoded-body cap, the decoder tracks a Go-style
// "excess" counter mirroring `src/net/http/internal/chunked.go`:
//   excess += size_line_len + 2           // per chunk
//   excess -= 16 + 2 * chunk_size         // per-chunk allowance
//   excess  = max(excess, 0)
// if excess > 16 * 1024 then reject. This prevents the "chunked encoding
// contains too much non-data" DoS class where a sender uses large chunk
// extensions to inflate encoded overhead relative to decoded payload. The
// trailer section is separately capped by a total-bytes counter so a
// peer cannot stream valid-looking short trailer lines forever.
const CHUNK_EXCESS_LIMIT: i64 = 16 * 1024;

fn read_chunked_body(
    buf: &mut Vec<u8>,
    stream: &mut TcpStream,
    body_start: usize,
    temp: &mut [u8],
) -> Result<Vec<u8>, String> {
    let mut pos = body_start;
    let mut body: Vec<u8> = Vec::new();
    let mut excess: i64 = 0;
    // Compact the parser window so retained raw state never exceeds roughly
    // MAX_HEADER_BYTES plus one chunk read's worth of unread bytes. This runs
    // amortized O(N_decoded) across all chunks rather than O(N_decoded^2) that
    // a per-chunk drain would cost for a very-high-overhead body.
    let compact = |buf: &mut Vec<u8>, pos: &mut usize| {
        if *pos >= MAX_HEADER_BYTES {
            buf.drain(..*pos);
            *pos = 0;
        }
    };
    loop {
        // Wait for the CRLF that terminates the chunk-size line. A size line
        // that grows past MAX_CHUNK_LINE_BYTES without finding a CRLF is
        // treated as malformed rather than allowed to grow unbounded.
        let size_end = loop {
            if let Some(rel) = find_crlf(&buf[pos..]) {
                // Enforce per-line cap BEFORE accepting the terminator. A
                // crossing read can deliver the byte that pushes the line
                // over the cap together with the CRLF in the same syscall,
                // where the post-read cap below has not fired yet. Matches
                // Go's `readChunkLine` which rejects
                // `len(p) >= maxLineLength` on the POST-CRLF-strip,
                // PRE-OWS-trim byte length (`src/net/http/internal/
                // chunked.go:178-182`). `trimTrailingWhitespace` only runs
                // AFTER `readChunkLine` returns (in
                // `chunkedReader.beginChunk` line 54), so the cap check
                // takes the raw length; a line of 4096 raw bytes with a
                // trailing OWS is rejected by both Go and Rust, matching
                // exactly.
                if rel >= MAX_CHUNK_LINE_BYTES {
                    return Err("invalid chunk size".to_string());
                }
                break pos + rel;
            }
            if buf.len() - pos >= MAX_CHUNK_LINE_BYTES {
                return Err("invalid chunk size".to_string());
            }
            let read = stream
                .read(temp)
                .map_err(|err| format!("read chunk size: {err}"))?;
            if read == 0 {
                // Peer closed while the chunk-size line was still being read;
                // classify as chunked-framing error so handle_connection
                // returns the same 400 "invalid chunked body" JSON it emits
                // for other malformed chunked framing (not the generic
                // "invalid request" default).
                return Err("invalid chunked body".to_string());
            }
            buf.extend_from_slice(&temp[..read]);
        };
        let size_line_len = size_end - pos;
        let size_text = std::str::from_utf8(&buf[pos..size_end])
            .map_err(|_| "invalid chunk size".to_string())?;
        // Match Go's chunked.go:54-59 byte-strict parse order:
        //   1. trimTrailingWhitespace over the full line (OWS = space|tab)
        //   2. removeChunkExtension (`split on ';'`)
        //   3. parseHexUint byte-strict (every remaining byte must be a hex
        //      digit; leading OWS, internal OWS, or any other non-hex byte
        //      yields `invalid byte in chunk length`).
        // Only stripping trailing OWS at step 1 is critical — the prior
        // `.trim()` accepted malformed lines like `" 1"` and `"1 ;ext"` that
        // Go rejects.
        let size_trimmed = size_text.trim_end_matches([' ', '\t']);
        let size_hex = size_trimmed.split(';').next().unwrap_or("");
        if size_hex.is_empty() || !size_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid chunk size".to_string());
        }
        let chunk_size =
            usize::from_str_radix(size_hex, 16).map_err(|_| "invalid chunk size".to_string())?;
        pos = size_end + 2;

        // Go-style non-data budget (see module doc above). The increment uses
        // saturating casts so a malicious size line close to isize::MAX does
        // not panic; the decrement floor-at-0 matches Go semantics.
        // `chunk_size: usize` can exceed `i64::MAX`; the bare `as i64` cast
        // would sign-wrap for values in [i64::MAX + 1, usize::MAX] and
        // produce a huge negative `allowance`, which then inflates `excess`
        // past CHUNK_EXCESS_LIMIT and returns "invalid chunked body" (400)
        // when the decoded-body cap below would have returned
        // "body too large" (413). `i64::try_from + unwrap_or(i64::MAX)`
        // saturates the conversion so oversized chunks hit the correct
        // 413 class.
        excess = excess
            .saturating_add(size_line_len as i64)
            .saturating_add(2);
        let chunk_size_i64 = i64::try_from(chunk_size).unwrap_or(i64::MAX);
        let allowance = 16i64.saturating_add(chunk_size_i64.saturating_mul(2));
        excess = excess.saturating_sub(allowance);
        if excess < 0 {
            excess = 0;
        }
        if excess > CHUNK_EXCESS_LIMIT {
            return Err("invalid chunked body".to_string());
        }

        if chunk_size == 0 {
            // Last-chunk marker. Consume optional trailer headers until the
            // empty line that terminates the message. EOF before the
            // terminating empty-line CRLF is rejected as malformed framing to
            // match Go's net/http chunked reader (which returns
            // io.ErrUnexpectedEOF); this also keeps parity with this module's
            // strict CRLF check for individual chunk terminators.
            //
            // The trailer section is bounded by total bytes (not just per
            // line): a peer that streams unlimited valid-looking short
            // trailer lines would otherwise keep one of the RPC workers busy
            // indefinitely under the decoded-body cap.
            let mut trailer_bytes: usize = 0;
            loop {
                compact(buf, &mut pos);
                if let Some(rel) = find_crlf(&buf[pos..]) {
                    if rel == 0 {
                        return Ok(body);
                    }
                    // Per-line cap before accepting the terminator (same
                    // crossing-read guard as the chunk-size loop above).
                    // Go trailer parsing goes through `body.readTrailer`
                    // (`net/http/transfer.go`) plus
                    // `textproto.Reader.ReadMIMEHeader`, not
                    // `readChunkLine` — so this is a Rust-local raw-line
                    // fail-closed bound sized at `MAX_CHUNK_LINE_BYTES`
                    // (same constant as the chunk-size cap), not a
                    // byte-for-byte Go-parity cap.
                    if rel >= MAX_CHUNK_LINE_BYTES {
                        return Err("invalid chunked body".to_string());
                    }
                    // Trailer lines are HTTP header fields per RFC 7230 §4.1.
                    // Enforce the full field-name + field-value syntax:
                    //   field-name = 1*tchar  (RFC 7230 §3.2.6)
                    //   field-value = *( field-content / obs-fold )
                    //     field-vchar = VCHAR / obs-text
                    //     obs-text = %x80-FF
                    // The name check is an RFC fail-closed divergence from
                    // Go's textproto which accepts a non-canonical key and
                    // silently fails lookups (`canonicalMIMEHeaderKey`
                    // returns the raw bytes unchanged at
                    // src/net/textproto/reader.go:753-770). We reject
                    // `": v"` (empty name), `"Bad\tName: v"` (tab in name),
                    // `" Leading: v"` (leading OWS), and `"X:\0"` (control
                    // byte in value); empty values (`"X:"`) are allowed per
                    // the `*( ... )` grammar.
                    let line_bytes = &buf[pos..pos + rel];
                    let colon_idx = line_bytes
                        .iter()
                        .position(|&b| b == b':')
                        .ok_or_else(|| "invalid chunked body".to_string())?;
                    let name = &line_bytes[..colon_idx];
                    if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
                        return Err("invalid chunked body".to_string());
                    }
                    let value = &line_bytes[colon_idx + 1..];
                    if !value.iter().all(|&b| is_field_vchar_or_ows(b)) {
                        return Err("invalid chunked body".to_string());
                    }
                    trailer_bytes = trailer_bytes.saturating_add(rel + 2);
                    if trailer_bytes > MAX_HEADER_BYTES {
                        return Err("invalid chunked body".to_string());
                    }
                    pos += rel + 2;
                    continue;
                }
                if buf.len() - pos >= MAX_CHUNK_LINE_BYTES {
                    return Err("invalid chunked body".to_string());
                }
                let read = stream
                    .read(temp)
                    .map_err(|err| format!("read trailer: {err}"))?;
                if read == 0 {
                    return Err("invalid chunked body".to_string());
                }
                buf.extend_from_slice(&temp[..read]);
            }
        }

        // Enforce the decoded body cap BEFORE reading or allocating chunk
        // bytes so a single oversized chunk does not trigger an OOM-sized
        // allocation and a cumulative overflow is rejected at the earliest
        // chunk that would cross the cap.
        if chunk_size > MAX_BODY_BYTES.saturating_sub(body.len()) {
            return Err("body too large".to_string());
        }

        // Wait until the chunk data + trailing CRLF are buffered.
        while buf.len() < pos + chunk_size + 2 {
            let read = stream
                .read(temp)
                .map_err(|err| format!("read chunk data: {err}"))?;
            if read == 0 {
                // Peer closed mid-chunk before chunk_size+CRLF was delivered;
                // same chunked-framing classification as above.
                return Err("invalid chunked body".to_string());
            }
            buf.extend_from_slice(&temp[..read]);
        }
        if buf[pos + chunk_size] != b'\r' || buf[pos + chunk_size + 1] != b'\n' {
            return Err("invalid chunk terminator".to_string());
        }
        body.extend_from_slice(&buf[pos..pos + chunk_size]);
        pos += chunk_size + 2;
        compact(buf, &mut pos);
    }
}

fn find_crlf(slice: &[u8]) -> Option<usize> {
    slice.windows(2).position(|w| w == b"\r\n")
}

// Parses the HTTP request-line version string to `(major, minor)`.
// Mirrors Go's `ParseHTTPVersion` (`src/net/http/request.go`): only the
// exact 8-byte form `"HTTP/X.Y"` with single-digit major and minor is
// accepted. Any deviation (length mismatch, missing `HTTP/` prefix,
// missing `.` separator, non-digit byte) returns
// `Err("malformed HTTP version")`, which `read_http_error_response`
// maps to a 400 JSON body — matching Go's
// `badStringError("malformed HTTP version", req.Proto)` reject-before-
// handler path.
fn parse_http_version(version: &str) -> Result<(u8, u8), String> {
    // "HTTP/X.Y" is exactly 8 ASCII bytes.
    if version.len() != 8 {
        return Err("malformed HTTP version".to_string());
    }
    let bytes = version.as_bytes();
    if &bytes[..5] != b"HTTP/" || bytes[6] != b'.' {
        return Err("malformed HTTP version".to_string());
    }
    let maj = match bytes[5] {
        b'0'..=b'9' => bytes[5] - b'0',
        _ => return Err("malformed HTTP version".to_string()),
    };
    let min = match bytes[7] {
        b'0'..=b'9' => bytes[7] - b'0',
        _ => return Err("malformed HTTP version".to_string()),
    };
    Ok((maj, min))
}

// RFC 7230 §3.2.6 token: any VCHAR except delimiters.
//   tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//           "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

// RFC 7230 §3.2.6 field-value body-char:
//   field-vchar = VCHAR / obs-text
//   OWS         = *( SP / HTAB )
// i.e. visible ASCII, horizontal tab, space, or obs-text (0x80-0xFF).
// Control bytes (0x00-0x08, 0x0A-0x1F, 0x7F) are rejected — Go's net/http
// mimeReader treats them as malformed and so do we.
fn is_field_vchar_or_ows(b: u8) -> bool {
    b == b' ' || b == b'\t' || (0x21..=0x7e).contains(&b) || b >= 0x80
}

fn write_http_response(stream: &mut TcpStream, response: HttpResponse) -> Result<(), String> {
    let status_text = status_text(response.status);
    let mut headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        status_text,
        response.content_type,
        response.body.len()
    );
    // RUB-10 / GitHub #1151: emit any opt-in headers attached via
    // `HttpResponse::with_header` (currently used only by `/ready`'s
    // 405 path for `Allow: GET`). Names are `&'static str` so they
    // cannot carry runtime-injected CRLF. Values are owned `String`
    // but `with_header` rejects any value containing CR/LF before
    // append (Copilot wave-1 P1 on PR #1472), so by the time this
    // loop runs no value can contain `\r` or `\n` — response-splitting
    // is closed at the API entry, not here.
    for (name, value) in &response.extra_headers {
        headers.push_str(name);
        headers.push_str(": ");
        headers.push_str(value);
        headers.push_str("\r\n");
    }
    headers.push_str("\r\n");
    stream
        .write_all(headers.as_bytes())
        .and_then(|_| stream.write_all(&response.body))
        .map_err(|err| format!("write response: {err}"))
}

fn json_response<T: Serialize>(
    state: &DevnetRPCState,
    route: &str,
    status: u16,
    payload: &T,
) -> HttpResponse {
    let body = serde_json::to_vec(payload)
        .unwrap_or_else(|_| b"{\"accepted\":false,\"error\":\"encode failed\"}".to_vec());
    state.metrics.note(route, status);
    HttpResponse::plain(status, "application/json", body)
}

fn split_target(target: &str) -> (&str, String) {
    match target.split_once('?') {
        Some((path, query)) => (path, query.to_string()),
        None => (target, String::new()),
    }
}

fn parse_query_map(query: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        out.insert(key.to_string(), value.to_string());
    }
    out
}

fn decode_hex_payload(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    if trimmed.is_empty() {
        return Err("tx_hex is required".to_string());
    }
    if !trimmed.len().is_multiple_of(2) {
        return Err("tx_hex must be even-length hex".to_string());
    }
    hex::decode(trimmed).map_err(|_| "tx_hex must be valid hex".to_string())
}

fn parse_hex32(value: &str) -> Result<[u8; 32], String> {
    let raw = decode_hex_payload(value)?;
    if raw.len() != 32 {
        return Err(format!("expected 32-byte hex, got {} bytes", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_secs())
        .unwrap_or(0)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        // RUB-10 / GitHub #1151: 405 emitted by `/ready` for non-GET
        // (mirrors Go's `handleReady` at `clients/go/cmd/rubin-node/http_rpc.go:659` which uses
        // `http.StatusMethodNotAllowed`). Not used by the existing
        // 6 query handlers (they emit 400 for non-GET; migrating
        // them to 405 is a separate concern outside RUB-10's scope).
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Request Entity Too Large",
        422 => "Unprocessable Entity",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

struct HttpResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    /// RUB-10 / GitHub #1151: optional extra `name: value` header pairs.
    /// Used by `/ready` to emit the RFC 9110 §15.5.6-required `Allow`
    /// header on its 405 method-rejection response, matching Go's
    /// `handleReady` at `clients/go/cmd/rubin-node/http_rpc.go:653`.
    /// Default empty for every existing response (current callers go
    /// through `HttpResponse::plain` which leaves this empty).
    /// Names are `&'static str` to match the rest of the type's
    /// reliance on static lifetimes; values are owned `String` so
    /// runtime-shaped values are accepted, with CR/LF rejected at the
    /// `with_header` API entry (response-splitting is closed in code).
    extra_headers: Vec<(&'static str, String)>,
}

impl HttpResponse {
    fn plain(status: u16, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type,
            body: body.into(),
            extra_headers: Vec::new(),
        }
    }

    /// RUB-10 / GitHub #1151: chainable header setter. Used by
    /// `handle_ready` to attach `Allow: GET` to its 405 response.
    /// Each call appends; duplicates are not deduplicated (no current
    /// caller writes the same header twice).
    ///
    /// HTTP response-splitting hardening (Copilot wave-1 P1 on PR #1472):
    /// header values containing CR (`\r`) or LF (`\n`) are dropped on the
    /// floor — the response is returned without that header pair so a
    /// future caller passing a runtime-shaped value cannot inject a
    /// CRLF sequence and forge a second response. Names are
    /// `&'static str` and therefore cannot carry runtime CRLF.
    /// Production callers in this PR pass the literal `"GET"` which
    /// contains no CRLF; the validator is defense-in-depth for future
    /// runtime-shaped values.
    ///
    /// Proof assertion: `with_header_drops_crlf_injected_value` (test
    /// in this file) builds a response with `value="GET\r\nX-Inject: 1"`
    /// and verifies the rendered HTTP head does NOT contain
    /// `X-Inject:`, i.e. the injection is filtered.
    fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        let value = value.into();
        if value.bytes().any(|b| b == b'\r' || b == b'\n') {
            return self;
        }
        self.extra_headers.push((name, value));
        self
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use rubin_consensus::{block_hash, parse_block_bytes, parse_tx, Outpoint, UtxoEntry};
    use serde_json::Value;

    use crate::io_utils::unique_temp_path;
    use crate::p2p_runtime::{PeerState, VersionPayloadV1};
    use crate::test_helpers::{
        coinbase_only_block, coinbase_only_block_with_gen, genesis_info,
        signed_conflicting_p2pk_state_and_txs,
    };
    use crate::txpool::TxSource;
    use crate::{
        block_store_path, default_peer_runtime_config, default_sync_config,
        devnet_genesis_block_bytes, devnet_genesis_chain_id, BlockStore, ChainState, MinerConfig,
        PeerManager, SyncEngine, TxPool,
    };

    use super::{
        decode_hex_payload, handle_connection, new_devnet_rpc_state,
        new_devnet_rpc_state_with_tx_pool, new_shared_runtime_tx_pool, parse_hex32,
        parse_query_map, read_http_error_response, read_http_request, render_prometheus_metrics,
        route_request, split_target, start_devnet_rpc_server, status_text, HttpRequest, ReadyState,
    };

    impl crate::da_relay::CompleteDaSetProvider for AtomicUsize {
        fn complete_da_set_candidates(
            &self,
            _max_payload_bytes: u64,
        ) -> Vec<crate::da_relay::CompleteDaSetCandidate> {
            self.fetch_add(1, Ordering::SeqCst);
            Vec::new()
        }
    }

    fn build_state(with_genesis: bool) -> (super::DevnetRPCState, PathBuf) {
        let dir = unique_temp_path("rubin-devnet-rpc");
        fs::create_dir_all(&dir).expect("mkdir");
        let block_store = BlockStore::open(block_store_path(&dir)).expect("blockstore");
        let mut engine = SyncEngine::new(
            ChainState::new(),
            Some(block_store.clone()),
            default_sync_config(None, devnet_genesis_chain_id(), None),
        )
        .expect("sync");
        if with_genesis {
            engine
                .apply_block(&devnet_genesis_block_bytes(), None)
                .expect("apply genesis");
        }
        let rpc_block_store = BlockStore::open(block_store_path(&dir)).expect("reopen blockstore");
        let state = new_devnet_rpc_state(
            Arc::new(Mutex::new(engine)),
            Some(rpc_block_store),
            Arc::new(PeerManager::new(default_peer_runtime_config("devnet", 8))),
            None,
            None,
        );
        (state, dir)
    }

    fn build_state_with_live_mining(with_genesis: bool) -> (super::DevnetRPCState, PathBuf) {
        let dir = unique_temp_path("rubin-devnet-rpc-live");
        fs::create_dir_all(&dir).expect("mkdir");
        let block_store = BlockStore::open(block_store_path(&dir)).expect("blockstore");
        let mut engine = SyncEngine::new(
            ChainState::new(),
            Some(block_store.clone()),
            default_sync_config(None, devnet_genesis_chain_id(), None),
        )
        .expect("sync");
        if with_genesis {
            engine
                .apply_block(&devnet_genesis_block_bytes(), None)
                .expect("apply genesis");
        }
        let rpc_block_store = BlockStore::open(block_store_path(&dir)).expect("reopen blockstore");
        let sync_engine = Arc::new(Mutex::new(engine));
        let tx_pool = new_shared_runtime_tx_pool(&sync_engine);
        let live_cfg = MinerConfig {
            ..MinerConfig::default()
        };
        let state = new_devnet_rpc_state_with_tx_pool(
            sync_engine,
            Some(rpc_block_store),
            tx_pool,
            Arc::new(PeerManager::new(default_peer_runtime_config("devnet", 8))),
            None,
            None,
            Some(live_cfg),
        );
        (state, dir)
    }

    fn read_request_from_bytes(raw: &[u8]) -> Result<HttpRequest, String> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let payload = raw.to_vec();
        // RUB-202 / GitHub #1467: bound the writer thread so a reader-side
        // early reject (e.g., the body-too-large cap firing in
        // `read_http_request_rejects_chunked_body_accumulation_over_cap`
        // before the producer finishes pushing 2 MiB+) cannot block on
        // `sendto` once the OS TCP send buffer fills. Production HTTP
        // servers RST the connection on early reject, which surfaces as
        // a write error on the client; the helper mirrors that semantic
        // here by setting a bounded `set_write_timeout` and ignoring
        // partial-write / TimedOut / BrokenPipe outcomes (issue
        // contract: "Writer-side BrokenPipe/timeout after reader-side
        // reject is acceptable and must not fail the test"). The
        // half-shutdown is best-effort for the same reason.
        let writer = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let _ = stream.write_all(&payload);
            let _ = stream.shutdown(std::net::Shutdown::Write);
        });
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set read timeout");
        let result = read_http_request(&mut stream);
        // RUB-202: drain residual bytes ONLY on the early-reject path.
        // On the success path the parser already consumed exactly the
        // bytes it needed and the writer's small payload + shutdown
        // were issued before the parser returned, so dropping the
        // socket at function exit is sufficient and avoids burning the
        // 100ms read-timeout budget on the FIN-propagation race for
        // every successful test. On the early-reject path (e.g.,
        // `Err("body too large")` after the cap fires inside
        // `read_chunked_body`) the parser stops draining mid-stream
        // and the writer remains blocked in `sendto` until its
        // 2s `set_write_timeout` (above) fires; this drain releases
        // that back-pressure so the writer's `write_all` completes
        // promptly and `writer.join()` returns. Bounded by the
        // per-read 100ms timeout + 2s writer-side timeout: worst-case
        // ~2s before the helper unwedges. Reads that hit the timeout
        // return `Err`, which exits the `while let Ok(n) = ...` loop
        // cleanly without surfacing into the test result.
        if result.is_err() {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
            let mut sink = [0u8; 4096];
            while let Ok(n) = stream.read(&mut sink) {
                if n == 0 {
                    break;
                }
            }
        }
        // RUB-202: propagate writer-thread panics (e.g., a failed
        // `TcpStream::connect` — the only remaining `.expect` in the
        // closure) so a broken test-infra environment surfaces loudly
        // instead of letting tests pass on a never-attempted send.
        // Writer-side `write_all` / `shutdown` / `set_write_timeout`
        // errors are swallowed inside the closure (per issue contract:
        // "Writer-side BrokenPipe/timeout after reader-side reject is
        // acceptable and must not fail the test"), so this expect only
        // fires when the closure panicked, not on the expected
        // BrokenPipe / TimedOut paths.
        writer.join().expect("writer thread panicked");
        result
    }

    fn request_until_response(addr: &str, request: &[u8], required: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut response = String::new();
        loop {
            if let Ok(mut stream) = TcpStream::connect(addr) {
                if stream.write_all(request).is_ok()
                    && stream.shutdown(std::net::Shutdown::Write).is_ok()
                {
                    response.clear();
                    if stream.read_to_string(&mut response).is_ok() && response.contains(required) {
                        return response;
                    }
                }
            }
            if Instant::now() >= deadline {
                panic!("timed out waiting for {required:?} from {addr}; last response: {response}");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn wait_until_connect_fails(addr: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            match TcpStream::connect(addr) {
                Ok(stream) => {
                    drop(stream);
                    if Instant::now() >= deadline {
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(_) => return true,
            }
        }
    }

    fn wait_until_active_handlers(server: &super::RunningDevnetRPCServer, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let active = server.active_handlers.load(Ordering::SeqCst);
            if active >= expected {
                return;
            }
            if Instant::now() >= deadline {
                panic!("timed out waiting for {expected} active handler(s); observed {active}");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn response_json(response: &super::HttpResponse) -> Value {
        serde_json::from_slice(&response.body).expect("json")
    }

    #[derive(Debug, serde::Deserialize)]
    struct FixtureFile<T> {
        vectors: Vec<T>,
    }

    #[derive(Clone, Debug, serde::Deserialize)]
    struct FixtureUtxo {
        txid: String,
        vout: u32,
        value: u64,
        covenant_type: u16,
        covenant_data: String,
        creation_height: u64,
        created_by_coinbase: bool,
    }

    #[derive(Clone, Debug, serde::Deserialize)]
    struct PositiveTxVector {
        id: String,
        tx_hex: String,
        #[serde(default)]
        chain_id: Option<String>,
        height: u64,
        expect_ok: bool,
        utxos: Vec<FixtureUtxo>,
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

    /// RUB-162 Phase A test helper (per controller Q2 / Path A approval
    /// 2026-05-03). Builds a fee-floor-compliant signed P2PK tx + matching
    /// chain_state for /submit_tx tests. Pre-RUB-162 tests used the
    /// conformance fixture (fee=10/weight=7653, fee_rate ≪ 1) which the
    /// post-RUB-162 admit_with_metadata correctly rejects with Unavailable
    /// from validate_fee_floor.
    ///
    /// Returns (chain_state, raw_tx_bytes, chain_id). chain_id is the
    /// devnet genesis chain id — same as the production call site uses.
    /// input_value=7700 / output=10 → fee=7690 ≥ weight≈7653 ⇒ admits.
    /// chain_state is bumped to has_tip=true / height=1 so admit_with_metadata
    /// reaches the policy path (not the coinbase-context branch).
    fn floor_compliant_signed_tx_and_state() -> (ChainState, Vec<u8>, [u8; 32]) {
        let (mut state, raw, _other) = signed_conflicting_p2pk_state_and_txs(7700, 10, 9);
        state.has_tip = true;
        state.height = 1;
        (state, raw, devnet_genesis_chain_id())
    }

    fn build_state_with_chain_state(
        chain_state: ChainState,
        chain_id: [u8; 32],
    ) -> super::DevnetRPCState {
        let engine = SyncEngine::new(chain_state, None, default_sync_config(None, chain_id, None))
            .expect("sync");
        super::DevnetRPCState {
            sync_engine: Arc::new(Mutex::new(engine)),
            block_store: None,
            tx_pool: Arc::new(Mutex::new(TxPool::new())),
            peer_manager: Arc::new(PeerManager::new(default_peer_runtime_config("devnet", 8))),
            metrics: Arc::new(super::RpcMetrics::default()),
            now_unix: super::current_unix,
            announce_tx: None,
            announce_block: None,
            accepted_block: None,
            accepted_block_da_consumer: None,
            rpc_op_lock: Arc::new(Mutex::new(())),
            live_mining_cfg: None,
            live_complete_da_set_provider: None,
            // RUB-10 / GitHub #1151: this helper bypasses the public
            // constructor (`new_devnet_rpc_state*`) so it does not
            // benefit from the default-NotReady wiring there. Keep
            // the boot value explicit here for parity.
            readiness: Arc::new(super::ReadinessGate::default()),
        }
    }

    #[test]
    fn get_tip_returns_empty_chain_shape() {
        let (state, dir) = build_state(false);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_tip".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200);
        let json: Value = serde_json::from_slice(&response.body).expect("json");
        assert_eq!(json["has_tip"].as_bool(), Some(false));
        assert!(json["height"].is_null());
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tip_returns_genesis_tip_shape() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_tip".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200);
        let json = response_json(&response);
        assert_eq!(json["has_tip"].as_bool(), Some(true));
        assert_eq!(json["height"].as_u64(), Some(0));
        assert_eq!(json["tip_hash"].as_str().map(|s| s.len()), Some(64));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn rpc_bind_host_is_loopback_accepts_loopback_hosts_only() {
        assert!(super::rpc_bind_host_is_loopback("127.0.0.1:19112"));
        assert!(super::rpc_bind_host_is_loopback("[::1]:19112"));
        assert!(super::rpc_bind_host_is_loopback("localhost:19112"));
        assert!(!super::rpc_bind_host_is_loopback("0.0.0.0:19112"));
        assert!(!super::rpc_bind_host_is_loopback("example.com:19112"));
        assert!(!super::rpc_bind_host_is_loopback(""));
        assert!(!super::rpc_bind_host_is_loopback("[::1]"));
        assert!(!super::rpc_bind_host_is_loopback("abcd::1:19112"));
        assert!(!super::rpc_bind_host_is_loopback("127.0.0.1"));
        assert!(!super::rpc_bind_host_is_loopback("127.0.0.1:"));
        assert!(!super::rpc_bind_host_is_loopback("[::1]:"));
        assert!(!super::rpc_bind_host_is_loopback("localhost:"));
        assert!(!super::rpc_bind_host_is_loopback("127.0.0.1:99999"));
        assert!(super::rpc_bind_host_is_loopback("127.0.0.1:0"));
    }

    #[test]
    fn submit_tx_reports_unavailable_when_rpc_op_lock_is_poisoned() {
        let (state, dir) = build_state(true);
        let rpc_lock = Arc::clone(&state.rpc_op_lock);
        let _ = std::thread::spawn(move || {
            let _guard = rpc_lock.lock().expect("lock");
            panic!("poison rpc op lock");
        })
        .join();
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/submit_tx".to_string(),
                body: br#"{"tx_hex":"00"}"#.to_vec(),
            },
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("rpc unavailable")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn mine_next_reports_unavailable_when_rpc_op_lock_is_poisoned() {
        let (state, dir) = build_state_with_live_mining(true);
        let rpc_lock = Arc::clone(&state.rpc_op_lock);
        let _ = std::thread::spawn(move || {
            let _guard = rpc_lock.lock().expect("lock");
            panic!("poison rpc op lock");
        })
        .join();
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/mine_next".to_string(),
                body: b"{}".to_vec(),
            },
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("rpc unavailable")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn mine_next_reports_unavailable_when_sync_engine_is_poisoned() {
        let (state, dir) = build_state_with_live_mining(true);
        let sync_engine = Arc::clone(&state.sync_engine);
        let _ = std::thread::spawn(move || {
            let _guard = sync_engine.lock().expect("lock");
            panic!("poison sync engine");
        })
        .join();
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/mine_next".to_string(),
                body: b"{}".to_vec(),
            },
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("sync engine unavailable")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn mine_next_reports_unavailable_when_tx_pool_is_poisoned() {
        let (state, dir) = build_state_with_live_mining(true);
        let tx_pool = Arc::clone(&state.tx_pool);
        let _ = std::thread::spawn(move || {
            let _guard = tx_pool.lock().expect("lock");
            panic!("poison tx pool");
        })
        .join();
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/mine_next".to_string(),
                body: b"{}".to_vec(),
            },
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("tx pool unavailable")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn mine_next_rejects_get() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/mine_next".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("POST required")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn mine_next_unavailable_without_live_cfg() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/mine_next".to_string(),
                body: b"{}".to_vec(),
            },
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("live mining unavailable")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn mine_next_passes_live_complete_da_provider_to_miner() {
        let (mut state, dir) = build_state_with_live_mining(true);
        let calls = Arc::new(AtomicUsize::new(0));
        state.set_complete_da_set_provider(calls.clone());

        let response = post_mine_next(&state);

        assert_eq!(response.status, 200);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    fn post_mine_next(state: &super::DevnetRPCState) -> super::HttpResponse {
        route_request(
            state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/mine_next".to_string(),
                body: b"{}".to_vec(),
            },
        )
    }

    #[test]
    fn mine_next_consumes_accepted_da_sets_on_success() {
        let (mut state, dir) = build_state_with_live_mining(true);
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        state.set_accepted_block_da_consumer(Arc::new(move |_block_bytes| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));

        let response = post_mine_next(&state);

        assert_eq!(response.status, 200);
        assert_eq!(response_json(&response)["mined"].as_bool(), Some(true));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn mine_next_fail_closed_when_da_consume_fails() {
        let (mut state, dir) = build_state_with_live_mining(true);
        state.set_accepted_block_da_consumer(Arc::new(|_block_bytes| {
            Err("boom da consume".to_string())
        }));

        let response = post_mine_next(&state);

        assert_eq!(response.status, 500);
        let json = response_json(&response);
        assert_eq!(json["mined"].as_bool(), Some(false));
        assert!(json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("boom da consume"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn mine_next_does_not_consume_when_mine_fails() {
        let (mut state, dir) = build_state_with_live_mining(true);
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        state.set_accepted_block_da_consumer(Arc::new(move |_block_bytes| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        // Poison the sync engine so mine+apply cannot complete; the consumer
        // sits after the success branch and must never run.
        let sync_engine = Arc::clone(&state.sync_engine);
        let _ = std::thread::spawn(move || {
            let _guard = sync_engine.lock().expect("lock");
            panic!("poison sync engine");
        })
        .join();

        let response = post_mine_next(&state);

        assert_ne!(response.status, 200);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn mine_next_mines_after_genesis() {
        let (state, dir) = build_state_with_live_mining(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/mine_next".to_string(),
                body: b"{}".to_vec(),
            },
        );
        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        let json = response_json(&response);
        assert_eq!(json["mined"].as_bool(), Some(true));
        assert_eq!(json["height"].as_u64(), Some(1));
        assert!(json["tx_count"].as_u64().is_some_and(|n| n >= 1));
        assert!(
            json["nonce"].as_u64().is_some(),
            "nonce must be present for Go/Rust RPC parity"
        );
        assert!(
            json["block_hash"].as_str().is_some_and(|s| s.len() == 64),
            "block_hash must be 32-byte hex"
        );
        assert!(
            json["timestamp"].as_u64().is_some(),
            "timestamp must be present"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn mine_next_announces_mined_block_on_success() {
        let (mut state, dir) = build_state_with_live_mining(true);
        let announced = Arc::new(Mutex::new(None::<Vec<u8>>));
        let hook_lock_order = Arc::new(Mutex::new((false, false, false, false)));
        let announced_clone = Arc::clone(&announced);
        let accepted_order = Arc::clone(&hook_lock_order);
        let accepted_lock = Arc::clone(&state.rpc_op_lock);
        let accepted_engine = Arc::clone(&state.sync_engine);
        let accepted_pool = Arc::clone(&state.tx_pool);
        state.set_accepted_block_hook(Arc::new(move |_| {
            let rpc_op_held = accepted_lock.try_lock().is_err();
            let engine_free = accepted_engine.try_lock().is_ok();
            let pool_free = accepted_pool.try_lock().is_ok();
            // Proof assertion: capture accepted-hook lock state before announce runs.
            let mut order = accepted_order.lock().expect("order lock");
            order.0 = rpc_op_held;
            order.2 = engine_free;
            order.3 = pool_free;
            Err("accepted hook test error".to_string())
        }));
        let announce_order = Arc::clone(&hook_lock_order);
        let announce_lock = Arc::clone(&state.rpc_op_lock);
        state.announce_block = Some(Arc::new(move |block_bytes: &[u8]| {
            *announced_clone.lock().expect("announce lock") = Some(block_bytes.to_vec());
            announce_order.lock().expect("order lock").1 = announce_lock.try_lock().is_ok();
            Ok(())
        }));

        let response = post_mine_next(&state);

        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        let json = response_json(&response);
        let expected_hash = json["block_hash"]
            .as_str()
            .expect("mine_next block_hash")
            .to_string();
        let block_bytes = announced
            .lock()
            .expect("announce lock")
            .take()
            .expect("announce_block must receive mined block bytes");
        let parsed = parse_block_bytes(&block_bytes).expect("parse announced block");
        let announced_hash = block_hash(&parsed.header_bytes).expect("announced block hash");
        assert_eq!(hex::encode(announced_hash), expected_hash);
        // Proof assertion: accepted hook sees RPC held; announce hook sees it released.
        let observed_order = *hook_lock_order.lock().expect("order lock");
        assert_eq!(observed_order, (true, true, true, true));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn mine_next_returns_422_when_miner_rejects_block() {
        let (state, dir) = build_state_with_live_mining(true);
        {
            let mut engine = state.sync_engine.lock().expect("sync engine");
            engine.chain_state.has_tip = true;
            engine.chain_state.height = u64::MAX;
        }

        let response = post_mine_next(&state);

        assert_eq!(response.status, 422);
        let json = response_json(&response);
        assert_eq!(json["mined"].as_bool(), Some(false));
        assert_eq!(json["error"].as_str(), Some("height overflow"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn mine_next_logs_announce_block_error_without_failing_rpc() {
        let (mut state, dir) = build_state_with_live_mining(true);
        state.announce_block = Some(Arc::new(|_| Err("forced announce failure".to_string())));

        let response = post_mine_next(&state);

        assert_eq!(response.status, 200);
        assert_eq!(response_json(&response)["mined"].as_bool(), Some(true));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tip_rejects_bad_method() {
        let (state, dir) = build_state(false);
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/get_tip".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("GET required")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tip_returns_unavailable_when_sync_engine_is_poisoned() {
        let (state, dir) = build_state(false);
        let sync_engine = Arc::clone(&state.sync_engine);
        let _ = std::thread::spawn(move || {
            let _guard = sync_engine.lock().expect("lock");
            panic!("poison sync engine");
        })
        .join();
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_tip".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("sync engine unavailable")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_block_requires_exactly_one_selector() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_block".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_block_rejects_bad_method() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/get_block?height=0".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("GET required")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_block_by_height_returns_genesis() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_block?height=0".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200);
        let json = response_json(&response);
        assert_eq!(json["height"].as_u64(), Some(0));
        assert_eq!(json["canonical"].as_bool(), Some(true));
        assert!(!json["hash"].as_str().unwrap_or_default().is_empty());
        assert!(!json["block_hex"].as_str().unwrap_or_default().is_empty());
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_block_by_hash_returns_genesis() {
        let (state, dir) = build_state(true);
        let (_height, tip_hash) = state
            .block_store
            .as_ref()
            .expect("blockstore")
            .tip()
            .expect("tip")
            .expect("tip value");
        let tip_hex = hex::encode(tip_hash);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: format!("/get_block?hash={tip_hex}"),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200);
        assert_eq!(
            response_json(&response)["hash"].as_str(),
            Some(tip_hex.as_str())
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_block_rejects_invalid_hash() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_block?hash=zz".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("invalid hash")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_block_rejects_invalid_height() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_block?height=nope".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("invalid height")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_block_returns_not_found_for_missing_height() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_block?height=9".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 404);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("block not found")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_block_returns_not_found_for_unknown_hash() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: format!("/get_block?hash={}", hex::encode([0x55; 32])),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 404);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("block not found")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_block_still_serves_block_bytes_when_header_is_missing() {
        let (state, dir) = build_state(true);
        let (_height, tip_hash) = state
            .block_store
            .as_ref()
            .expect("blockstore")
            .tip()
            .expect("tip")
            .expect("tip value");
        let header_path = state
            .block_store
            .as_ref()
            .expect("blockstore")
            .root_dir()
            .join("headers")
            .join(format!("{}.bin", hex::encode(tip_hash)));
        fs::remove_file(&header_path).expect("remove header");

        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_block?height=0".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200);
        assert_eq!(response_json(&response)["height"].as_u64(), Some(0));
        assert!(!response_json(&response)["block_hex"]
            .as_str()
            .unwrap_or_default()
            .is_empty());
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_block_returns_unavailable_without_blockstore() {
        let (mut state, dir) = build_state(true);
        state.block_store = None;
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_block?height=0".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("blockstore unavailable")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn submit_tx_rejects_bad_hex() {
        let (state, dir) = build_state(false);
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/submit_tx".to_string(),
                body: br#"{"tx_hex":"zz"}"#.to_vec(),
            },
        );
        assert_eq!(response.status, 400);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn submit_tx_rejects_bad_method() {
        let (state, dir) = build_state(false);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/submit_tx".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("POST required")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn submit_tx_rejects_invalid_json() {
        let (state, dir) = build_state(false);
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/submit_tx".to_string(),
                body: b"{\"tx_hex\":".to_vec(),
            },
        );
        assert_eq!(response.status, 400);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("invalid JSON body")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn submit_tx_rejects_invalid_tx() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/submit_tx".to_string(),
                body: br#"{"tx_hex":"00"}"#.to_vec(),
            },
        );
        assert_eq!(response.status, 422);
        let body = response_json(&response);
        assert_eq!(body["accepted"].as_bool(), Some(false));
        assert!(body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("transaction rejected"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn submit_tx_accepts_floor_compliant_p2pk_tx() {
        // RUB-162 Phase A migration rationale (per controller Q2 / Path A
        // approval 2026-05-03; PR-1410 wave-3 Copilot Thread C update):
        //   - old assumption: positive_fixture_vector tx (fee=10/weight=
        //     7653) admits via /submit_tx; pre-RUB-162 admit_with_metadata
        //     did not enforce the rolling fee floor.
        //   - new invariant: admit_with_metadata enforces the rolling fee
        //     floor (DEFAULT=1) via the
        //     `apply_post_consensus_policy_with_floor` helper. The
        //     conformance fixture is sub-floor and admits Unavailable.
        //   - reachability: the test pins /submit_tx returning 200 +
        //     duplicate detection + metrics increment — all of which require
        //     a successful admit on the FIRST request. Reaches the txpool
        //     admission path through DevnetRPC -> TxPool::admit.
        //   - replacement coverage: floor_compliant_signed_tx_and_state()
        //     builds a fee-floor-compliant signed tx (input=7700/output=10
        //     ⇒ fee=7690 ≥ weight≈7653) using the in-tree
        //     signed_conflicting_p2pk_state_and_txs helper. The test's
        //     /submit_tx + duplicate + metrics invariants remain under
        //     test. The conformance fixture's parsing/signature paths are
        //     covered by relay_metadata +
        //     admit_rejects_sub_floor_conformance_tx_as_unavailable_with_atomicity
        //     (which asserts Unavailable in txpool.rs).
        //   - PR-1410 wave-3 Copilot Thread C: removed the
        //     `let vector = positive_fixture_vector(); assert!(vector.expect_ok, ...);`
        //     prelude that was vestigial after the migration to
        //     `floor_compliant_signed_tx_and_state()`. The test no longer
        //     consumes the conformance fixture, so coupling its assertions
        //     to CV-U-06 churn would be a stale-fixture coupling bug.
        let (chain_state, raw, chain_id) = floor_compliant_signed_tx_and_state();
        let (_tx, txid, _wtxid, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len());
        let expected_txid = hex::encode(txid);

        let state = build_state_with_chain_state(chain_state, chain_id);
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/submit_tx".to_string(),
                body: format!(r#"{{"tx_hex":"{}"}}"#, hex::encode(&raw)).into_bytes(),
            },
        );

        assert_eq!(response.status, 200);
        let body = response_json(&response);
        assert_eq!(body["accepted"].as_bool(), Some(true));
        assert_eq!(body["txid"].as_str(), Some(expected_txid.as_str()));
        let pool = state.tx_pool.lock().expect("tx pool");
        assert_eq!(pool.len(), 1);
        drop(pool);
        let duplicate = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/submit_tx".to_string(),
                body: format!(r#"{{"tx_hex":"{}"}}"#, hex::encode(&raw)).into_bytes(),
            },
        );
        assert_eq!(duplicate.status, 409);
        let metrics = render_prometheus_metrics(&state);
        assert!(metrics.contains("rubin_node_mempool_txs 1"), "{metrics}");
        assert!(metrics.contains(r#"rubin_node_submit_tx_total{result="accepted"} 1"#));
        assert!(
            metrics.contains(r#"rubin_node_rpc_requests_total{route="/submit_tx",status="200"} 1"#)
        );
    }

    #[test]
    fn submit_tx_records_local_source_provenance_on_accepted_admission() {
        // RUB-171 producer-wiring slice (RUB-163 child). Devnet RPC
        // /submit_tx admits user-submitted transactions as the canonical
        // Local txpool producer (mirrors Go handleSubmitTx ->
        // mempool.AddTx -> addTxWithSource(_, mempoolTxSourceLocal)).
        //
        // Reachability: the test drives a real /submit_tx request through
        // `route_request` (NOT via TxPool::add_tx_with_source helper) so
        // the full RPC handler -> rpc_op lock -> tx_pool lock ->
        // add_tx_with_source(_, TxSource::Local) chain runs end to end.
        // Helper-only coverage of source recording is already exercised
        // by RUB-174 baseline tests in txpool.rs; this slice's invariant
        // is the runtime path through the RPC producer surface.
        //
        // Proof assertion: assert_eq!(pool.entry_source(&txid),
        // Some(TxSource::Local)) below pins the producer-source variant
        // recorded by handle_submit_tx for the admitted entry. Mutating
        // the production line from TxSource::Local to TxSource::Remote
        // or TxSource::Reorg makes this exact assertion fail with
        // `left: Some(Remote|Reorg), right: Some(Local)`. Reverting to
        // the legacy pool.admit_with_metadata wrapper still defaults to
        // Local under the RUB-174 wrapper-chain, so that revert is a
        // code-readability / grep-discoverability regression rather than
        // a runtime-asserted regression.
        //
        // Proof assertion (control): assert_eq!(control_pool.entry_source(
        // &control_txid), Some(TxSource::Reorg)) below admits a separate
        // tx via add_tx_with_source(_, TxSource::Reorg) on a fresh
        // TxPool::new() and pins the recorded variant. This proves the
        // accessor is genuinely variant-discriminating: a regression
        // that hardcoded entry_source to a single variant would still
        // pass the primary Local assertion above but fail the Reorg
        // assertion in the control branch below.
        let (chain_state, raw, chain_id) = floor_compliant_signed_tx_and_state();
        let (_tx, txid, _wtxid, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len());

        let state = build_state_with_chain_state(chain_state, chain_id);
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/submit_tx".to_string(),
                body: format!(r#"{{"tx_hex":"{}"}}"#, hex::encode(&raw)).into_bytes(),
            },
        );

        assert_eq!(response.status, 200);
        let body = response_json(&response);
        assert_eq!(body["accepted"].as_bool(), Some(true));

        // Primary assertion: the entry admitted through the RPC submit
        // path carries the Local source tag (would FAIL with Remote /
        // Reorg / None on any mutation of the production line).
        let pool = state.tx_pool.lock().expect("tx pool");
        assert_eq!(
            pool.entry_source(&txid),
            Some(TxSource::Local),
            "RPC /submit_tx must record TxSource::Local provenance on the admitted entry",
        );
        drop(pool);

        // Mutation-distinguishing control: admit a SEPARATE tx into a
        // FRESH pool (with its own state) directly via the source-aware
        // API with TxSource::Reorg, and verify entry_source returns
        // Reorg. This proves entry_source is genuinely variant-aware
        // and is not silently returning a constant. If the accessor or
        // recording was hardcoded to a single variant, the primary
        // assertion above would still pass for that variant — this
        // control catches that class of regression.
        let (control_state, control_raw, control_chain_id) = floor_compliant_signed_tx_and_state();
        let (_ctx, control_txid, _cwtxid, ccons) =
            parse_tx(&control_raw).expect("parse control tx");
        assert_eq!(ccons, control_raw.len());
        let mut control_pool = TxPool::new();
        control_pool
            .add_tx_with_source(
                &control_raw,
                &control_state,
                None,
                control_chain_id,
                TxSource::Reorg,
            )
            .expect("control admit");
        assert_eq!(
            control_pool.entry_source(&control_txid),
            Some(TxSource::Reorg),
            "TxPool::entry_source must return the variant recorded at admission time",
        );
    }

    #[test]
    fn submit_tx_reports_unavailable_when_tx_pool_is_poisoned() {
        let (state, dir) = build_state(false);
        let tx_pool = Arc::clone(&state.tx_pool);
        let _ = std::thread::spawn(move || {
            let _guard = tx_pool.lock().expect("lock");
            panic!("poison tx pool");
        })
        .join();
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/submit_tx".to_string(),
                body: br#"{"tx_hex":"00"}"#.to_vec(),
            },
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("tx pool unavailable")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn submit_tx_reports_unavailable_when_sync_engine_is_poisoned() {
        let vector = positive_fixture_vector();
        assert!(vector.expect_ok, "{} should be positive fixture", vector.id);
        let state = build_state_with_chain_state(
            chain_state_from_positive_fixture(&vector),
            fixture_chain_id(vector.chain_id.as_deref()),
        );
        let sync_engine = Arc::clone(&state.sync_engine);
        let _ = std::thread::spawn(move || {
            let _guard = sync_engine.lock().expect("lock");
            panic!("poison sync engine");
        })
        .join();

        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/submit_tx".to_string(),
                body: format!(r#"{{"tx_hex":"{}"}}"#, vector.tx_hex).into_bytes(),
            },
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("sync engine unavailable")
        );
        let metrics = render_prometheus_metrics(&state);
        assert!(metrics.contains(r#"rubin_node_submit_tx_total{result="unavailable"} 1"#));
    }

    #[test]
    fn submit_tx_calls_announce_callback_on_success() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // RUB-162 Phase A migration rationale (per controller Q2 / Path A
        // approval 2026-05-03):
        //   - old assumption: positive_fixture_vector tx admits via
        //     /submit_tx and triggers the announce_tx callback.
        //   - new invariant: admit_with_metadata enforces the rolling fee
        //     floor; conformance fixture admits Unavailable and the
        //     announce callback would never fire.
        //   - reachability: test pins announce_tx invocation AFTER
        //     successful admit. Reaches the txpool admission path through
        //     DevnetRPC -> TxPool::admit success → announce side-effect.
        //   - replacement coverage: same floor-compliant tx as the sibling
        //     submit_tx_accepts_floor_compliant_p2pk_tx test; announce
        //     side-effect on success invariant remains under test.
        let (chain_state, raw, chain_id) = floor_compliant_signed_tx_and_state();
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let mut state = build_state_with_chain_state(chain_state, chain_id);
        state.announce_tx = Some(Arc::new(move |_tx_bytes: &[u8], _meta| {
            called_clone.store(true, Ordering::SeqCst);
            Ok(())
        }));

        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/submit_tx".to_string(),
                body: format!(r#"{{"tx_hex":"{}"}}"#, hex::encode(&raw)).into_bytes(),
            },
        );
        assert_eq!(response.status, 200);
        assert!(
            called.load(Ordering::SeqCst),
            "announce_tx should be called"
        );
    }

    #[test]
    fn submit_tx_logs_announce_error_without_failing_rpc() {
        // RUB-162 Phase A migration rationale (per controller Q2 / Path A
        // approval 2026-05-03):
        //   - old assumption: positive_fixture_vector tx admits via
        //     /submit_tx and the announce_tx Err is logged but not
        //     propagated; RPC still returns 200.
        //   - new invariant: admit_with_metadata enforces the rolling fee
        //     floor; conformance fixture admits Unavailable and the RPC
        //     would return 503 without ever invoking announce_tx.
        //   - reachability: test pins /submit_tx returning 200 even when
        //     announce_tx returns Err — requires successful admit AND
        //     announce invocation.
        //   - replacement coverage: same floor-compliant tx as the sibling
        //     submit_tx_accepts_floor_compliant_p2pk_tx test; "RPC succeeds
        //     even with announce Err" invariant remains under test.
        let (chain_state, raw, chain_id) = floor_compliant_signed_tx_and_state();

        let mut state = build_state_with_chain_state(chain_state, chain_id);
        state.announce_tx = Some(Arc::new(|_tx_bytes: &[u8], _meta| {
            Err("relay failure".to_string())
        }));

        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/submit_tx".to_string(),
                body: format!(r#"{{"tx_hex":"{}"}}"#, hex::encode(&raw)).into_bytes(),
            },
        );
        // RPC should still succeed — announce failure is fire-and-forget.
        assert_eq!(response.status, 200);
        let body = response_json(&response);
        assert_eq!(body["accepted"].as_bool(), Some(true));
    }

    #[test]
    fn get_block_returns_unavailable_when_block_bytes_are_missing() {
        let (state, dir) = build_state(true);
        let (_height, tip_hash) = state
            .block_store
            .as_ref()
            .expect("blockstore")
            .tip()
            .expect("tip")
            .expect("tip value");
        let block_path = state
            .block_store
            .as_ref()
            .expect("blockstore")
            .root_dir()
            .join("blocks")
            .join(format!("{}.bin", hex::encode(tip_hash)));
        fs::remove_file(&block_path).expect("remove block");

        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_block?height=0".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 503);
        assert!(response_json(&response)["error"]
            .as_str()
            .unwrap_or_default()
            .contains("read block"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn metrics_reject_bad_method() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/metrics".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("GET required")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn read_http_request_rejects_malformed_headers_and_bad_lengths() {
        let malformed_header = b"GET /get_tip HTTP/1.1\r\nHost: localhost\r\nBrokenHeader\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(malformed_header).unwrap_err(),
            "malformed header"
        );

        let invalid_length =
            b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nContent-Length: nope\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(invalid_length).unwrap_err(),
            "invalid Content-Length"
        );

        let too_large = format!(
            "POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            2 * 1024 * 1024 + 1
        );
        assert_eq!(
            read_request_from_bytes(too_large.as_bytes()).unwrap_err(),
            "body too large"
        );
    }

    #[test]
    fn read_http_request_rejects_truncated_body_and_parses_bare_query_keys() {
        let truncated =
            b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n{}";
        assert_eq!(
            read_request_from_bytes(truncated).unwrap_err(),
            "unexpected eof"
        );

        let params = parse_query_map("height=7&flag");
        assert_eq!(params.get("height").map(String::as_str), Some("7"));
        assert_eq!(params.get("flag").map(String::as_str), Some(""));
    }

    #[test]
    fn read_http_request_rejects_missing_request_parts_and_oversized_headers() {
        assert_eq!(read_request_from_bytes(b"").unwrap_err(), "unexpected eof");
        assert_eq!(
            read_request_from_bytes(b"GET\r\n\r\n").unwrap_err(),
            "missing target"
        );
        assert_eq!(
            read_request_from_bytes(b"GET /get_tip\r\n\r\n").unwrap_err(),
            "missing http version"
        );

        let oversized_header = format!(
            "GET /get_tip HTTP/1.1\r\nX-Test: {}",
            "a".repeat(super::MAX_HEADER_BYTES + 1)
        );
        assert_eq!(
            read_request_from_bytes(oversized_header.as_bytes()).unwrap_err(),
            "headers too large"
        );
    }

    #[test]
    fn read_http_request_accepts_chunked_body_under_cap() {
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n5\r\n-more\r\n0\r\n\r\n";
        let req = read_request_from_bytes(raw).expect("chunked body accepted");
        assert_eq!(req.method, "POST");
        assert_eq!(req.target, "/submit_tx");
        assert_eq!(req.body, b"data-more");
    }

    #[test]
    fn read_http_request_accepts_chunked_body_with_trailer() {
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Trace-Id: 42\r\n\r\n";
        let req = read_request_from_bytes(raw).expect("chunked body with trailer accepted");
        assert_eq!(req.body, b"abc");
    }

    fn skip_under_coverage_instrumentation() -> bool {
        // cargo-tarpaulin's LLVM backend (macOS) intermittently deadlocks on
        // tests that push multi-MiB of data through a TCP loopback under its
        // ptrace/profile instrumentation. Regular `cargo test` runs these at
        // full size; coverage runs skip them. Every branch in
        // `read_chunked_body` is still exercised under coverage by the
        // smaller chunked tests (under-cap, with-trailer, oversize single
        // chunk, CRLF terminator, EOF classes).
        std::env::var_os("LLVM_PROFILE_FILE").is_some()
    }

    #[test]
    fn read_http_request_accepts_chunked_body_with_high_framing_overhead() {
        if skip_under_coverage_instrumentation() {
            return;
        }
        // Many 1-byte chunks ("1\r\nx\r\n" = 6 raw bytes per 1 decoded byte).
        // Decoded body is 1.1 MiB (under MAX_BODY_BYTES = 2 MiB), but the raw
        // wire bytes are ~6.6 MiB. This regression pins the decoder to the
        // decoded-body cap so valid chunked bodies below the cap are not
        // rejected on framing overhead alone.
        let decoded_size: usize = 1_100_000;
        let mut raw = Vec::with_capacity(decoded_size * 6 + 128);
        raw.extend_from_slice(
            b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        for _ in 0..decoded_size {
            raw.extend_from_slice(b"1\r\nx\r\n");
        }
        raw.extend_from_slice(b"0\r\n\r\n");
        let req = read_request_from_bytes(&raw).expect("high-overhead chunked body accepted");
        assert_eq!(req.body.len(), decoded_size);
        assert!(req.body.iter().all(|&b| b == b'x'));
    }

    #[test]
    fn read_http_request_rejects_chunked_body_over_cap() {
        // chunk size 0x200001 = MAX_BODY_BYTES + 1, rejected before the data
        // slice is even read so there is no allocation cliff.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n200001\r\n";
        assert_eq!(read_request_from_bytes(raw).unwrap_err(), "body too large");
    }

    #[test]
    fn read_http_request_rejects_chunk_size_over_i64_max_with_body_too_large() {
        // chunk size 0xFFFF_FFFF_FFFF_FFFF (usize::MAX on 64-bit) exceeds
        // i64::MAX; the saturating `i64::try_from + unwrap_or(i64::MAX)`
        // conversion keeps `allowance` monotonic so the decoded-body cap
        // below fires with "body too large" (413) instead of leaking into
        // the chunk-excess class "invalid chunked body" (400) via a
        // sign-bit wrap during i64 accounting.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\n";
        assert_eq!(read_request_from_bytes(raw).unwrap_err(), "body too large");
    }

    #[test]
    fn read_http_request_rejects_chunked_body_accumulation_over_cap() {
        if skip_under_coverage_instrumentation() {
            return;
        }
        // Two chunks that individually fit but together would exceed the cap.
        // 100000 + 100001 = 2 MiB + 1 byte.
        let mut raw = Vec::from(&b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n100000\r\n"[..]);
        raw.extend(std::iter::repeat_n(b'a', 0x100000));
        raw.extend_from_slice(b"\r\n100001\r\n");
        raw.extend(std::iter::repeat_n(b'b', 0x100001));
        raw.extend_from_slice(b"\r\n0\r\n\r\n");
        assert_eq!(read_request_from_bytes(&raw).unwrap_err(), "body too large");
    }

    #[test]
    fn read_http_request_rejects_chunked_and_content_length_conflict() {
        // RFC 7230 §3.3.3: both framings present MUST be rejected to prevent
        // request smuggling.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "conflicting transfer-encoding and content-length"
        );
    }

    #[test]
    fn read_http_request_rejects_conflicting_content_length_headers() {
        // RFC 7230 §3.3.2: multiple Content-Length headers with differing
        // values is a request-smuggling vector and must be rejected.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nContent-Length: 8\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "conflicting Content-Length"
        );
    }

    #[test]
    fn read_http_request_accepts_duplicate_content_length_headers_with_same_value() {
        // Identical duplicate Content-Length is permissive (matches Go net/http
        // behaviour). Body must be present and equal to the declared length.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nbody";
        let req =
            read_request_from_bytes(raw).expect("identical duplicate Content-Length accepted");
        assert_eq!(req.body, b"body");
    }

    #[test]
    fn read_http_request_accepts_content_length_at_exact_cap() {
        if skip_under_coverage_instrumentation() {
            return;
        }
        // Content-Length exactly at MAX_BODY_BYTES must be accepted. This
        // pins the boundary-safe raw-buffer cap (`body_start + MAX_BODY_BYTES`)
        // that replaced the earlier `MAX_HEADER_BYTES + MAX_BODY_BYTES` check
        // which falsely rejected boundary-valid requests because `body_start`
        // already accounts for the 4-byte `\r\n\r\n` delimiter.
        let body_len = super::MAX_BODY_BYTES;
        let headers = format!(
            "POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nContent-Length: {body_len}\r\n\r\n"
        );
        let mut raw = headers.into_bytes();
        raw.extend(std::iter::repeat_n(b'x', body_len));
        let req = read_request_from_bytes(&raw).expect("body at MAX_BODY_BYTES accepted");
        assert_eq!(req.body.len(), body_len);
    }

    #[test]
    fn read_http_request_accepts_content_length_body_with_trailing_garbage() {
        // A TCP read that coalesces the declared body with a few trailing
        // bytes (e.g. start of a pipelined next request on the same
        // connection) must NOT cause the body-read loop to reject the
        // current request. The body is sliced by exact `content_length`;
        // trailing bytes are discarded.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nbodyGARBAGEafter";
        let req =
            read_request_from_bytes(raw).expect("body + trailing bytes in coalesced read accepted");
        assert_eq!(req.body, b"body");
    }

    #[test]
    fn read_http_request_rejects_duplicate_content_length_headers_with_leading_zeros() {
        // Go parity: duplicate Content-Length headers are accepted only when
        // their trimmed byte values are IDENTICAL. `4` and `004` trim to
        // different byte strings ("4" vs "004") even though they parse to the
        // same usize, so Go's `src/net/http/transfer.go:671-674` rejects this
        // case (`textproto.TrimString(first) != textproto.TrimString(ct)`).
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nContent-Length: 004\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "conflicting Content-Length"
        );
    }

    #[test]
    fn read_http_request_rejects_chunked_body_eof_before_final_crlf() {
        // Matches Go net/http chunked reader: EOF after the last-chunk marker
        // without the terminating empty-line CRLF is io.ErrUnexpectedEOF and
        // returns a 400 framing error on this path.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "invalid chunked body"
        );
    }

    #[test]
    fn read_http_request_rejects_chunked_body_eof_in_chunk_size_line() {
        // Peer closes while the parser is still reading the chunk-size line
        // (no CRLF yet). Classified as a chunked-framing error so callers see
        // the same 400 JSON "invalid chunked body" the other framing failures
        // surface — not the generic "invalid request" fallback.
        let raw =
            b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n100";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "invalid chunked body"
        );
    }

    #[test]
    fn read_http_request_rejects_chunked_body_eof_mid_chunk_data() {
        // Size line declares 5 bytes; peer sends only 3 then closes before
        // the chunk data + trailing CRLF completes. Same chunked-framing
        // classification as above.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "invalid chunked body"
        );
    }

    #[test]
    fn read_http_request_rejects_chunked_body_excess_extension_overhead() {
        // Matches Go chunked.go excess counter (src/net/http/internal/chunked.go
        // :43-82): per chunk, excess grows by `size_line_len + 2` and is
        // reduced by the `16 + 2 * chunk_size` allowance; if total excess
        // crosses 16 KiB the request is rejected. Six 1-byte chunks whose
        // size lines carry a 4 KiB chunk extension each push excess past the
        // cap before any legitimate payload is decoded.
        let ext = "a".repeat(4000);
        let mut raw = Vec::from(
            &b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
        );
        for _ in 0..6 {
            raw.extend_from_slice(format!("1;{ext}\r\nx\r\n").as_bytes());
        }
        raw.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(
            read_request_from_bytes(&raw).unwrap_err(),
            "invalid chunked body"
        );
    }

    #[test]
    fn read_http_request_rejects_chunked_body_excessive_trailer_bytes() {
        // A peer that streams unlimited valid-looking short trailer lines
        // after the zero chunk must not be able to keep an RPC worker busy
        // indefinitely under the decoded-body cap. The trailer section is
        // bounded by total bytes (not just per-line), so 1100 short valid
        // trailer lines totaling > MAX_HEADER_BYTES (64 KiB) are rejected.
        let mut raw = Vec::from(
            &b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n"
                [..],
        );
        for i in 0..1100 {
            raw.extend_from_slice(
                format!("X-Trailer-{i:04}: value-that-is-padded-to-60-bytes-abcdefghijklmnop\r\n")
                    .as_bytes(),
            );
        }
        raw.extend_from_slice(b"\r\n");
        assert_eq!(
            read_request_from_bytes(&raw).unwrap_err(),
            "invalid chunked body"
        );
    }

    #[test]
    fn read_http_request_rejects_chunked_body_malformed_trailer_line() {
        // Trailer lines are HTTP header fields per RFC 7230 §4.1, so a line
        // without a `:` is not a valid trailer. Go's net/http reports this
        // as a malformed trailer; we mirror that behaviour so malformed
        // chunked requests do not reach /submit_tx.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nBadTrailer\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "invalid chunked body"
        );
    }

    #[test]
    fn read_http_request_rejects_chunk_size_line_with_leading_whitespace() {
        // Go's parseHexUint (src/net/http/internal/chunked.go:278-294) is
        // byte-strict: any non-hex byte at any position returns
        // `invalid byte in chunk length`. Leading OWS is NOT stripped —
        // Go's trimTrailingWhitespace only strips the trailing side.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n 1\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "invalid chunk size"
        );
    }

    #[test]
    fn read_http_request_rejects_chunk_size_line_with_internal_whitespace_before_extension() {
        // `1 ;ext` — after Go's `removeChunkExtension` strips ';ext', the
        // remaining "1 " has a non-hex byte at index 1, which parseHexUint
        // rejects. The prior `.trim()` accepted this; the new byte-strict
        // check rejects it.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1 ;ext\r\nx\r\n0\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "invalid chunk size"
        );
    }

    #[test]
    fn read_http_request_accepts_chunk_size_line_with_trailing_whitespace() {
        // Go's trimTrailingWhitespace (chunked.go:186-190) strips trailing
        // space/tab BEFORE parseHexUint; trailing OWS like "1 " or "1\t"
        // must still be accepted.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1 \t\r\nx\r\n0\r\n\r\n";
        let req = read_request_from_bytes(raw).expect("trailing OWS in size line accepted");
        assert_eq!(req.body, b"x");
    }

    #[test]
    fn read_http_request_rejects_trailer_with_empty_field_name() {
        // `: value` has an empty field-name. Go's mimeReader rejects this
        // as a malformed header; we enforce the RFC 7230 §3.2.6 token rule
        // (field-name must be 1*tchar) so trailers match.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n: value\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "invalid chunked body"
        );
    }

    #[test]
    fn read_http_request_rejects_trailer_with_whitespace_in_field_name() {
        // A tab inside the field-name makes it a non-token. RFC 7230 §3.2.6
        // tchar excludes whitespace; Go rejects `"Bad\tName: v"` as
        // malformed. Same here.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nBad\tName: v\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "invalid chunked body"
        );
    }

    #[test]
    fn read_http_request_rejects_trailer_with_leading_whitespace_before_field_name() {
        // Leading OWS before field-name violates RFC 7230 §3.2.6 (token is
        // 1*tchar, OWS is not a tchar). Go rejects such a line during
        // mimeReader parse. Mirror that here.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n Leading: v\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "invalid chunked body"
        );
    }

    #[test]
    fn read_http_request_rejects_header_with_whitespace_between_field_name_and_colon() {
        // RFC 7230 §3.2.4: no whitespace is permitted between header
        // field-name and colon. This reject is an RFC fail-closed
        // divergence from Go's `textproto` legacy behaviour, which accepts
        // the message but stores the name uncanonicalised so canonical-key
        // lookups (`Header.Get("Transfer-Encoding")`) silently miss the
        // spaced variant — itself a smuggling hazard when upstreams
        // canonicalise differently. We reject outright with
        // `"malformed header"` (400 JSON "malformed header").
        let raw =
            b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding : chunked\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "malformed header"
        );
    }

    #[test]
    fn read_http_request_rejects_headers_terminated_just_over_cap() {
        // A header block whose CRLFCRLF terminator arrives at byte
        // MAX_HEADER_BYTES + 1 (i.e. header bytes plus the terminator cross
        // the cap only in the same read that delivers the terminator) must
        // be rejected. Without the pre-break cap this crossing-read case
        // slips through the post-read `buf.len() > MAX_HEADER_BYTES` guard.
        // Matches Go's textproto header read bound.
        // Place the CRLFCRLF so `find_header_end` returns MAX_HEADER_BYTES + 1
        // — the position of the `\r` at the start of the terminator sequence.
        let prefix = b"GET /get_tip HTTP/1.1\r\nX-Test: ";
        let pad = super::MAX_HEADER_BYTES + 1 - prefix.len();
        let raw = format!(
            "GET /get_tip HTTP/1.1\r\nX-Test: {}\r\n\r\n",
            "a".repeat(pad)
        );
        assert_eq!(
            read_request_from_bytes(raw.as_bytes()).unwrap_err(),
            "headers too large"
        );
    }

    #[test]
    fn read_http_request_rejects_chunk_size_line_at_go_max_line_length() {
        // Go `src/net/http/internal/chunked.go:19,178-182`:
        //   const maxLineLength = 4096
        //   p = p[:len(p)-2]        // strip CRLF
        //   if len(p) >= maxLineLength { return nil, ErrLineTooLong }
        // The cap is measured on the POST-CRLF-strip, PRE-OWS-trim byte
        // length. `trimTrailingWhitespace` is only applied later in
        // `chunkedReader.beginChunk` line 54, AFTER `readChunkLine`
        // returns — so the cap never sees the trimmed length. We mirror
        // this with `MAX_CHUNK_LINE_BYTES = 4096` and a `>=` check.
        // A chunk-size line of exactly 4096 bytes before CRLF must be
        // rejected. The chunk_size hex itself is kept small (1 byte) so
        // the excess-overhead counter (16 KiB cap) cannot reject first.
        let chunk_hex = "1";
        let ext_len = super::MAX_CHUNK_LINE_BYTES - chunk_hex.len() - ";ext=".len();
        let ext = "a".repeat(ext_len);
        let raw = format!(
            "POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n{chunk_hex};ext={ext}\r\nx\r\n0\r\n\r\n"
        );
        assert_eq!(
            read_request_from_bytes(raw.as_bytes()).unwrap_err(),
            "invalid chunk size"
        );
    }

    #[test]
    fn read_http_request_accepts_chunk_size_line_at_largest_go_allowed_length() {
        // Largest Go-accepted length is `maxLineLength - 1 = 4095` bytes
        // before CRLF. Must still be accepted here so legal boundary
        // extensions are not rejected.
        let chunk_hex = "1";
        let ext_len = super::MAX_CHUNK_LINE_BYTES - chunk_hex.len() - ";ext=".len() - 1;
        let ext = "a".repeat(ext_len);
        let raw = format!(
            "POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n{chunk_hex};ext={ext}\r\nx\r\n0\r\n\r\n"
        );
        let req = read_request_from_bytes(raw.as_bytes())
            .expect("chunk-size line at MAX_CHUNK_LINE_BYTES - 1 accepted");
        assert_eq!(req.body, b"x");
    }

    #[test]
    fn read_http_request_rejects_trailer_with_control_byte_in_field_value() {
        // RFC 7230 §3.2.6 field-value body is VCHAR / obs-text / OWS;
        // control bytes (NUL, other C0 chars except HTAB) are not allowed.
        // Go rejects malformed trailer headers; we mirror.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trace: v\x00\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "invalid chunked body"
        );
    }

    #[test]
    fn read_http_request_accepts_trailer_with_tab_and_obs_text_in_field_value() {
        // HTAB and obs-text (0x80-0xFF) are both valid in field-value per
        // RFC 7230 §3.2.6; the check must accept these so legitimate
        // trailers with non-ASCII UTF-8 content continue to work.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trace:\t\xd1\x82\xd0\xb5\xd1\x81\xd1\x82\r\n\r\n";
        let req = read_request_from_bytes(raw).expect("trailer with HTAB + obs-text accepted");
        // Body has no data chunks in this case, so the decoded body is empty
        // and only the trailer parse is under test.
        assert!(req.body.is_empty());
    }

    #[test]
    fn read_http_request_rejects_unsupported_transfer_encoding() {
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "unsupported transfer-encoding"
        );
    }

    #[test]
    fn read_http_request_ignores_transfer_encoding_on_http_1_0() {
        // Go `src/net/http/transfer.go parseTransferEncoding` returns early
        // for `!protoAtLeast(1, 1)`, so an HTTP/1.0 request with
        // `Transfer-Encoding: chunked` is NOT decoded as chunked. Mirror
        // that here: the TE header is ignored and the body falls through to
        // the Content-Length-or-empty path (no CL here → zero-length body).
        let raw =
            b"POST /submit_tx HTTP/1.0\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n";
        let req =
            read_request_from_bytes(raw).expect("HTTP/1.0 TE:chunked accepted with empty body");
        assert_eq!(req.method, "POST");
        assert!(req.body.is_empty());
    }

    #[test]
    fn read_http_request_processes_transfer_encoding_on_http_1_1() {
        // Sanity: HTTP/1.1 with TE:chunked continues to decode chunked.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let req = read_request_from_bytes(raw).expect("HTTP/1.1 TE:chunked decoded as chunked");
        assert_eq!(req.body, b"abc");
    }

    #[test]
    fn read_http_request_rejects_malformed_http_version() {
        // Go `readRequest` (src/net/http/request.go) returns
        // `badStringError("malformed HTTP version", req.Proto)` when
        // `ParseHTTPVersion` rejects the version string — the handler
        // never runs. Mirror that: `parse_http_version` returns
        // `Err("malformed HTTP version")` for the multi-digit form
        // `HTTP/1.10`, which maps to 400 JSON at the handler boundary.
        let raw =
            b"POST /submit_tx HTTP/1.10\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "malformed HTTP version"
        );
    }

    #[test]
    fn read_http_request_rejects_malformed_http_version_leading_zero() {
        // `HTTP/01.1` is 9 bytes → length check rejects.
        let raw = b"POST /submit_tx HTTP/01.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "malformed HTTP version"
        );
    }

    #[test]
    fn read_http_request_rejects_malformed_http_version_non_digit() {
        // `HTTP/1.A` has the right shape but a non-digit minor → rejected.
        let raw = b"POST /submit_tx HTTP/1.A\r\nHost: localhost\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "malformed HTTP version"
        );
    }

    #[test]
    fn read_http_request_rejects_request_line_with_extra_trailing_token() {
        // Go `parseRequestLine` does two single-space cuts, so the proto
        // segment is the full remainder and `ParseHTTPVersion` rejects
        // `"HTTP/1.1 EXTRA"`. We mirror that by splitting on exactly one
        // space twice and passing the whole proto remainder to
        // `parse_http_version`, which rejects the 14-byte string.
        let raw = b"POST /submit_tx HTTP/1.1 EXTRA\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "malformed HTTP version"
        );
    }

    #[test]
    fn read_http_request_rejects_request_line_with_empty_target() {
        // `"POST  HTTP/1.1"` — double space after method places `target=""`
        // and `version="HTTP/1.1"` under the two-single-space tokeniser.
        // `parse_http_version("HTTP/1.1")` is OK, so without the empty-target
        // guard the handler would see `target == ""` and route it to 404.
        // Go folds this rejection into the URL parse layer
        // (`NewRequest("POST", "", ...)` → `parse "": empty url`); we fold
        // it into the request-line parse here.
        let raw = b"POST  HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(read_request_from_bytes(raw).unwrap_err(), "missing target");
    }

    #[test]
    fn read_http_request_rejects_request_line_with_double_space_after_method() {
        // Double space after method yields `target=""` under the
        // two-single-space tokeniser. The empty-target guard fires
        // FIRST (before `parse_http_version` sees the remainder
        // "/submit_tx HTTP/1.1"), so this case rejects with
        // `"missing target"` — the earlier / more informative class for
        // this input.
        let raw = b"POST  /submit_tx HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(read_request_from_bytes(raw).unwrap_err(), "missing target");
    }

    #[test]
    fn read_http_request_rejects_duplicate_transfer_encoding() {
        // Matches Go net/http readTransfer: two Transfer-Encoding headers is
        // `too many transfer encodings`, even when both values are `chunked`.
        // Accepting this would desync Rust from any upstream component that
        // enforces the Go rule and open a request-smuggling vector.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "duplicate Transfer-Encoding"
        );
    }

    #[test]
    fn read_http_request_rejects_invalid_chunk_size() {
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "invalid chunk size"
        );
    }

    #[test]
    fn read_http_request_rejects_invalid_chunk_terminator() {
        // Chunk size "4" promises 4 data bytes followed by CRLF. Replace the
        // CRLF with "!!" so the reader sees a mis-framed chunk.
        let raw = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata!!0\r\n\r\n";
        assert_eq!(
            read_request_from_bytes(raw).unwrap_err(),
            "invalid chunk terminator"
        );
    }

    #[test]
    fn read_http_error_response_maps_classes_to_status_and_json() {
        let cases = [
            ("body too large", 413u16, "request body too large"),
            ("request too large", 413, "request body too large"),
            (
                "conflicting transfer-encoding and content-length",
                400,
                "conflicting transfer-encoding and content-length",
            ),
            (
                "conflicting Content-Length",
                400,
                "conflicting Content-Length",
            ),
            (
                "unsupported transfer-encoding",
                400,
                "unsupported transfer-encoding",
            ),
            (
                "duplicate Transfer-Encoding",
                400,
                "duplicate Transfer-Encoding",
            ),
            ("invalid chunk size", 400, "invalid chunked body"),
            ("invalid chunk terminator", 400, "invalid chunked body"),
            ("invalid chunked body", 400, "invalid chunked body"),
            ("headers too large", 400, "headers too large"),
            ("invalid Content-Length", 400, "invalid Content-Length"),
            ("invalid request headers", 400, "invalid request headers"),
            ("malformed header", 400, "malformed header"),
            ("malformed HTTP version", 400, "malformed HTTP version"),
            ("missing request line", 400, "missing request line"),
            ("missing method", 400, "missing method"),
            ("missing target", 400, "missing target"),
            ("missing http version", 400, "missing http version"),
            ("unexpected eof", 400, "invalid request"),
        ];
        for (err, expected_status, expected_error) in cases {
            let response = read_http_error_response(err);
            assert_eq!(response.status, expected_status, "err={err}");
            assert_eq!(response.content_type, "application/json", "err={err}");
            let json: Value = serde_json::from_slice(&response.body)
                .unwrap_or_else(|e| panic!("json parse for {err}: {e}"));
            assert_eq!(
                json.get("accepted").and_then(Value::as_bool),
                Some(false),
                "err={err}"
            );
            assert_eq!(
                json.get("error").and_then(Value::as_str),
                Some(expected_error),
                "err={err}"
            );
            assert!(json.get("txid").is_none(), "err={err}");
        }
    }

    struct TempDirCleanupGuard {
        path: PathBuf,
    }

    impl Drop for TempDirCleanupGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn handle_connection_roundtrip(raw: &[u8]) -> (u16, String, Value) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let (state, dir) = build_state(false);
        // `handle_connection_roundtrip` hides the `dir` PathBuf from its
        // callers, so wrap it in a Drop guard that cleans up after the
        // test returns. Without this the helper would leave a
        // `rubin-devnet-rpc*` directory per invocation (matches the
        // `_dir` hygiene used by tests that call `build_state` directly).
        let _cleanup = TempDirCleanupGuard { path: dir };
        let payload = raw.to_vec();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            // RUB-171 wave-1 fix: set the read timeout BEFORE
            // `shutdown(Write)`. On macOS, `setsockopt(SO_RCVTIMEO)` after
            // a half-close transitions can return `EINVAL` (errno 22)
            // because the socket leaves the state where `setsockopt` is
            // accepted on the receive direction. Under regular `cargo
            // test` the close completes after this call so the test races
            // through; under `cargo tarpaulin` instrumentation the close
            // serializes earlier and the call deterministically fails.
            // Setting the timeout first preserves the read-timeout
            // semantics needed below and is portable across macOS / Linux
            // socket behaviour.
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            stream.write_all(&payload).expect("write payload");
            stream
                .shutdown(std::net::Shutdown::Write)
                .expect("shutdown write");
            let mut response = Vec::new();
            let _ = stream.read_to_end(&mut response);
            response
        });
        let (server_stream, _) = listener.accept().expect("accept");
        let _ = handle_connection(server_stream, &state);
        let response = client.join().expect("join client");
        let head_end = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response head");
        let head_text = std::str::from_utf8(&response[..head_end]).expect("response head utf8");
        let mut head_lines = head_text.split("\r\n");
        let status_line = head_lines.next().expect("status line");
        let mut parts = status_line.splitn(3, ' ');
        parts.next().expect("http version");
        let status: u16 = parts.next().expect("status code").parse().expect("status");
        let reason = parts.next().expect("reason phrase").to_string();
        let body = &response[head_end + 4..];
        let json: Value = serde_json::from_slice(body).expect("json body");
        (status, reason, json)
    }

    #[test]
    fn handle_connection_returns_413_json_for_content_length_oversize() {
        let request = format!(
            "POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            2 * 1024 * 1024 + 1
        );
        let (status, reason, json) = handle_connection_roundtrip(request.as_bytes());
        assert_eq!(status, 413, "status={reason}");
        assert_eq!(reason, "Request Entity Too Large");
        assert_eq!(json.get("accepted").and_then(Value::as_bool), Some(false));
        assert_eq!(
            json.get("error").and_then(Value::as_str),
            Some("request body too large")
        );
    }

    #[test]
    fn handle_connection_returns_413_json_for_chunked_oversize() {
        // 0x200001 = MAX_BODY_BYTES + 1, rejected before any chunk bytes are
        // allocated.
        let request = b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n200001\r\n";
        let (status, reason, json) = handle_connection_roundtrip(request);
        assert_eq!(status, 413, "reason={reason}");
        assert_eq!(reason, "Request Entity Too Large");
        assert_eq!(
            json.get("error").and_then(Value::as_str),
            Some("request body too large")
        );
    }

    #[test]
    fn handle_connection_returns_400_json_for_conflicting_framing() {
        let request =
            b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n";
        let (status, _reason, json) = handle_connection_roundtrip(request);
        assert_eq!(status, 400);
        assert_eq!(
            json.get("error").and_then(Value::as_str),
            Some("conflicting transfer-encoding and content-length")
        );
    }

    #[test]
    fn handle_connection_returns_400_json_for_unsupported_transfer_encoding() {
        let request =
            b"POST /submit_tx HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip\r\n\r\n";
        let (status, _reason, json) = handle_connection_roundtrip(request);
        assert_eq!(status, 400);
        assert_eq!(
            json.get("error").and_then(Value::as_str),
            Some("unsupported transfer-encoding")
        );
    }

    #[test]
    fn handle_connection_returns_400_json_for_empty_request_target() {
        // Double space after method yields an empty request-target after the
        // two `split_once(' ')` calls in `read_http_request`. Before the
        // structured-error mapping was extended to the request-line classes,
        // this collapsed to the generic `"invalid request"` JSON; now it
        // preserves the specific `"missing target"` class on the wire.
        let request = b"POST  HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (status, _reason, json) = handle_connection_roundtrip(request);
        assert_eq!(status, 400);
        assert_eq!(
            json.get("error").and_then(Value::as_str),
            Some("missing target")
        );
    }

    #[test]
    fn metrics_render_reports_live_tip_best_known_height_and_ibd_zero() {
        let mut chain_state = ChainState::new();
        chain_state.has_tip = true;
        chain_state.height = 7;
        chain_state.tip_hash = [0x33; 32];
        let mut engine = SyncEngine::new(
            chain_state,
            None,
            default_sync_config(None, devnet_genesis_chain_id(), None),
        )
        .expect("sync");
        engine.record_best_known_height(9);
        let state = super::DevnetRPCState {
            sync_engine: Arc::new(Mutex::new(engine)),
            block_store: None,
            tx_pool: Arc::new(Mutex::new(TxPool::new())),
            peer_manager: Arc::new(PeerManager::new(default_peer_runtime_config("devnet", 8))),
            metrics: Arc::new(super::RpcMetrics::default()),
            now_unix: || 0,
            announce_tx: None,
            announce_block: None,
            accepted_block: None,
            accepted_block_da_consumer: None,
            rpc_op_lock: Arc::new(Mutex::new(())),
            live_mining_cfg: None,
            live_complete_da_set_provider: None,
            // RUB-10 / GitHub #1151: render_prometheus_metrics test does
            // not exercise `/ready`; default `NotReady` is fine.
            readiness: Arc::new(super::ReadinessGate::default()),
        };

        let body = render_prometheus_metrics(&state);
        assert!(body.contains("rubin_node_tip_height 7"), "{body}");
        assert!(body.contains("rubin_node_best_known_height 9"), "{body}");
        assert!(body.contains("rubin_node_in_ibd 0"), "{body}");
    }

    #[test]
    fn metrics_render_includes_v1_names() {
        let _orphan_guard = crate::p2p_runtime::orphan_pool_metrics_test_guard();
        crate::p2p_runtime::reset_orphan_pool_metrics_for_test();
        let (state, dir) = build_state(true);
        let _ = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_tip".to_string(),
                body: Vec::new(),
            },
        );
        let _ = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/submit_tx".to_string(),
                body: br#"{"tx_hex":"00"}"#.to_vec(),
            },
        );
        let body = render_prometheus_metrics(&state);
        for name in [
            "rubin_node_tip_height",
            "rubin_node_best_known_height",
            "rubin_node_in_ibd",
            "rubin_node_reorg_total",
            "rubin_node_last_reorg_depth",
            "rubin_node_peer_count",
            "rubin_node_p2p_orphan_pool_blocks",
            "rubin_node_p2p_orphan_pool_bytes",
            "rubin_node_mempool_txs",
            "rubin_node_rpc_requests_total",
            "rubin_node_submit_tx_total",
            "rubin_pv_mode",
            "rubin_pv_blocks_validated_total",
            "rubin_pv_blocks_skipped_total",
            "rubin_pv_shadow_mismatches_total",
            // RUB-12 / GitHub #1156: metric NAME alignment to Go's
            // `clients/go/node/pv_telemetry.go::PrometheusLines` —
            // the previous Rust-only `rubin_pv_validate_runs_total`
            // and `rubin_pv_commit_runs_total` are no longer emitted
            // (Go exposition has no counterpart), and the latency
            // gauges are now the longer `rubin_pv_validate_latency_avg_ns`
            // and `rubin_pv_commit_latency_avg_ns` to match the
            // upstream metric names exactly. Both renamed gauges are
            // pinned through the production render path so a future
            // regression that drops either rename is caught here, not
            // only by the unit tests in sync.rs.
            "rubin_pv_validate_latency_avg_ns",
            "rubin_pv_commit_latency_avg_ns",
        ] {
            assert!(body.contains(name), "missing metric {name}");
        }
        // RUB-12 / GitHub #1156: production-path absence assertion for
        // the dropped Rust-only counters. The unit test in
        // `clients/rust/crates/rubin-node/src/sync.rs::pv_telemetry_prometheus_lines_dropped_rust_only_counters_absent`
        // pins absence on a synthetic snapshot; this loop pins absence
        // through the production render path so a future regression
        // that reintroduces the dropped names anywhere downstream of
        // `prometheus_lines()` (for example via a new `lines.push(...)`
        // in `render_prometheus_metrics`) cannot slip past unit tests
        // alone.
        for dropped in ["rubin_pv_validate_runs_total", "rubin_pv_commit_runs_total"] {
            assert!(
                !body.contains(dropped),
                "dropped Rust-only counter {dropped} reappeared in production rendering; body=\n{body}"
            );
        }
        assert!(body.contains(r#"rubin_node_rpc_requests_total{route="/get_tip",status="200"} 1"#));
        assert!(body.contains(r#"rubin_node_submit_tx_total{result="rejected"} 1"#));
        assert!(body.contains(r#"rubin_pv_mode{mode="off"} 1"#));
        assert!(body.contains("rubin_node_reorg_total 0"), "{body}");
        assert!(body.contains("rubin_node_last_reorg_depth 0"), "{body}");
        assert!(
            body.contains("rubin_node_p2p_orphan_pool_blocks 0"),
            "{body}"
        );
        assert!(
            body.contains("rubin_node_p2p_orphan_pool_bytes 0"),
            "{body}"
        );
        crate::p2p_runtime::reset_orphan_pool_metrics_for_test();
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn metrics_render_exposes_reorg_counters_read_only() {
        let (state, dir) = build_state(true);
        let (_genesis, genesis_hash, gen_ts) = genesis_info();
        let block3;

        {
            let mut engine = state.sync_engine.lock().expect("sync engine");
            assert_eq!(engine.reorg_count(), 0);
            assert_eq!(engine.last_reorg_depth(), 0);

            let block1 = coinbase_only_block(1, genesis_hash, gen_ts + 1);
            engine
                .apply_block_with_reorg(&block1, None)
                .expect("block1 canonical");
            assert_eq!(engine.reorg_count(), 0);
            assert_eq!(engine.last_reorg_depth(), 0);

            let block1_alt = coinbase_only_block(1, genesis_hash, gen_ts + 2);
            let block1_alt_hash = block_hash(&block1_alt[..rubin_consensus::BLOCK_HEADER_BYTES])
                .expect("block1 alt hash");
            engine
                .block_store
                .as_ref()
                .expect("blockstore")
                .store_block(
                    block1_alt_hash,
                    &block1_alt[..rubin_consensus::BLOCK_HEADER_BYTES],
                    &block1_alt,
                )
                .expect("store block1 alt");

            let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
            let block2_alt = coinbase_only_block_with_gen(2, subsidy1, block1_alt_hash, gen_ts + 3);
            engine
                .apply_block_with_reorg(&block2_alt, None)
                .expect("reorg to heavier branch");
            assert_eq!(engine.reorg_count(), 1);
            assert_eq!(engine.last_reorg_depth(), 1);

            let block2_alt_hash = block_hash(&block2_alt[..rubin_consensus::BLOCK_HEADER_BYTES])
                .expect("block2 alt hash");
            let subsidy2 = rubin_consensus::subsidy::block_subsidy(2, u128::from(subsidy1));
            block3 =
                coinbase_only_block_with_gen(3, subsidy1 + subsidy2, block2_alt_hash, gen_ts + 4);
        }

        let body1 = render_prometheus_metrics(&state);
        let body2 = render_prometheus_metrics(&state);
        for body in [&body1, &body2] {
            for want in [
                "# HELP rubin_node_reorg_total Total canonical reorg events observed by the sync engine.",
                "# TYPE rubin_node_reorg_total counter",
                "rubin_node_reorg_total 1",
                "# HELP rubin_node_last_reorg_depth Depth of the most recent canonical reorg, or 0 when no reorg depth is currently recorded.",
                "# TYPE rubin_node_last_reorg_depth gauge",
                "rubin_node_last_reorg_depth 1",
            ] {
                assert!(body.contains(want), "missing {want:?} in {body}");
            }
            assert!(
                !body.contains("rubin_node_reorg_total{")
                    && !body.contains("rubin_node_last_reorg_depth{"),
                "reorg metrics must stay unlabeled; body=\n{body}"
            );
        }

        let engine = state.sync_engine.lock().expect("sync engine after render");
        assert_eq!(engine.reorg_count(), 1);
        assert_eq!(engine.last_reorg_depth(), 1);
        drop(engine);

        {
            let mut engine = state.sync_engine.lock().expect("sync engine direct");
            engine
                .apply_block_with_reorg(&block3, None)
                .expect("direct extension after reorg");
            assert_eq!(engine.reorg_count(), 1);
            assert_eq!(engine.last_reorg_depth(), 0);
        }

        let body3 = render_prometheus_metrics(&state);
        assert!(body3.contains("rubin_node_reorg_total 1"), "{body3}");
        assert!(body3.contains("rubin_node_last_reorg_depth 0"), "{body3}");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// RUB-12 / GitHub #1156 class-sweep: extends the wave-2
    /// `rubin_pv_mode{mode=...}` escape coverage to the other two
    /// labeled metric emitters in `render_prometheus_metrics`,
    /// `rubin_node_rpc_requests_total{route=...,status=...}` (counter
    /// label `route`) and `rubin_node_submit_tx_total{result=...}`
    /// (counter label `result`). Goʼs counterpart at
    /// `clients/go/cmd/rubin-node/http_rpc.go:1314,1334` formats both
    /// labels via `%q`, so for byte-parity with Goʼs `/metrics` text
    /// stream the Rust side must escape them too.
    ///
    /// Today both label sources are static ASCII enum literals (route
    /// is a `const ROUTE: &str = "/...";` constant on every `note()`
    /// call site, result is one of `"accepted"/"rejected"/"conflict"/
    /// "unavailable"/"bad_request"`). The escape is therefore purely
    /// defense-in-depth — the production happy path is identity — but
    /// `RpcMetrics::note` and `RpcMetrics::note_submit` accept `&str`
    /// (not enums) so a future caller that funnels in a runtime-shaped
    /// string must not be able to break out of the label literal.
    ///
    /// This test forges adversarial values via direct calls to the
    /// private `RpcMetrics::note` / `note_submit` methods, then asserts
    /// the rendered metrics body keeps the entire payload inside the
    /// escaped label string and never grows a synthetic line break or
    /// new metric line at any line start.
    #[test]
    fn metrics_render_escapes_labeled_counter_labels_against_injection() {
        let (state, dir) = build_state(true);
        let evil_route = "evil\"} 1\n# HELP fake malicious\nfake 1";
        let evil_result = "shadow\"} 1\n# fake_metric_via_result 1\nattacker 1";
        state.metrics.note(evil_route, 200);
        state.metrics.note_submit(evil_result);
        let body = render_prometheus_metrics(&state);
        // The escape must turn `"` into `\"` and `\n` into `\n` (literal
        // backslash-n) so the injected payload sits entirely inside the
        // label literal.
        let escaped_route_inline = "evil\\\"} 1\\n# HELP fake malicious\\nfake 1";
        let escaped_result_inline = "shadow\\\"} 1\\n# fake_metric_via_result 1\\nattacker 1";
        assert!(
            body.contains(&format!(
                "rubin_node_rpc_requests_total{{route=\"{escaped_route_inline}\",status=\"200\"}} 1"
            )),
            "route label not escaped properly; body=\n{body}"
        );
        assert!(
            body.contains(&format!(
                "rubin_node_submit_tx_total{{result=\"{escaped_result_inline}\"}} 1"
            )),
            "result label not escaped properly; body=\n{body}"
        );
        // Verify no synthetic `# HELP` line was forged outside an
        // existing HELP block. The legitimate HELP/TYPE blocks live at
        // line starts; an injected `# HELP fake malicious` would too if
        // escape were missing. Scan every line for a `# HELP fake`
        // prefix — there must be none.
        for line in body.lines() {
            assert!(
                !line.starts_with("# HELP fake"),
                "injected # HELP line forged at line start: {line:?}"
            );
            assert!(
                !line.starts_with("fake "),
                "injected fake metric line forged at line start: {line:?}"
            );
            assert!(
                !line.starts_with("attacker "),
                "injected attacker metric line forged at line start: {line:?}"
            );
        }
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn route_request_returns_unknown_route_404() {
        let (state, dir) = build_state(false);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/nope".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 404);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("route not found")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn decode_hex_payload_accepts_prefix_and_rejects_empty_or_odd_length() {
        assert_eq!(
            decode_hex_payload("0x00ff").expect("decode"),
            vec![0x00, 0xff]
        );
        assert_eq!(
            decode_hex_payload(" ").unwrap_err(),
            "tx_hex is required".to_string()
        );
        assert_eq!(
            decode_hex_payload("abc").unwrap_err(),
            "tx_hex must be even-length hex".to_string()
        );
    }

    #[test]
    fn decode_hex_payload_rejects_invalid_hex() {
        assert_eq!(
            decode_hex_payload("zz").unwrap_err(),
            "tx_hex must be valid hex".to_string()
        );
    }

    #[test]
    fn parse_hex32_rejects_wrong_length() {
        assert!(parse_hex32("00").is_err());
    }

    #[test]
    fn split_target_and_query_helpers_work() {
        let (path, query) = split_target("/get_block?height=7&hash=");
        assert_eq!(path, "/get_block");
        let params = parse_query_map(&query);
        assert_eq!(params.get("height").map(String::as_str), Some("7"));
        assert_eq!(params.get("hash").map(String::as_str), Some(""));
    }

    #[test]
    fn status_text_maps_known_values() {
        assert_eq!(status_text(200), "OK");
        assert_eq!(status_text(400), "Bad Request");
        assert_eq!(status_text(404), "Not Found");
        assert_eq!(status_text(409), "Conflict");
        assert_eq!(status_text(422), "Unprocessable Entity");
        assert_eq!(status_text(503), "Service Unavailable");
        assert_eq!(status_text(999), "Unknown");
    }

    #[test]
    fn start_server_serves_get_tip() {
        let (state, dir) = build_state(false);
        let mut server =
            start_devnet_rpc_server("127.0.0.1:0", state.clone()).expect("start server");
        let mut response = String::new();
        for _ in 0..10 {
            let Ok(mut stream) = TcpStream::connect(server.addr()) else {
                std::thread::sleep(std::time::Duration::from_millis(25));
                continue;
            };
            if stream
                .write_all(b"GET /get_tip HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .is_err()
            {
                std::thread::sleep(std::time::Duration::from_millis(25));
                continue;
            }
            if stream.shutdown(std::net::Shutdown::Write).is_err() {
                std::thread::sleep(std::time::Duration::from_millis(25));
                continue;
            }
            response.clear();
            if stream.read_to_string(&mut response).is_err() {
                std::thread::sleep(std::time::Duration::from_millis(25));
                continue;
            }
            if response.contains("HTTP/1.1 200 OK") && response.contains("has_tip") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(response.contains("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("has_tip"), "{response}");
        server.close().expect("close server");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn shutdown_close_is_bounded_idempotent_and_stops_listener() {
        let (state, dir) = build_state(false);
        let mut server =
            start_devnet_rpc_server("127.0.0.1:0", state.clone()).expect("start server");
        let addr = server.addr().to_string();
        let ready_response = request_until_response(
            &addr,
            b"GET /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK",
        );
        assert!(
            ready_response.contains("\"ready\":true"),
            "ready response must come from public RPC path: {ready_response}"
        );

        server.close().expect("first close must drain accept loop");
        assert!(
            wait_until_connect_fails(&addr, Duration::from_secs(1)),
            "listener still accepted connections after close returned"
        );
        assert!(
            !state.readiness.is_ready(),
            "close must stamp sticky shutdown readiness"
        );
        server.close().expect("second close must be idempotent");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn shutdown_state_cannot_restart_live_listener() {
        let reserved = TcpListener::bind("127.0.0.1:0").expect("reserve listener addr");
        let addr = reserved.local_addr().expect("reserved addr").to_string();
        drop(reserved);
        let (state, dir) = build_state(false);
        let mut server = start_devnet_rpc_server(&addr, state.clone()).expect("start server");
        assert!(state.readiness.is_ready());
        server.close().expect("shutdown first server");
        assert!(
            wait_until_connect_fails(&addr, Duration::from_secs(1)),
            "listener still accepted connections after first close"
        );

        let err = match start_devnet_rpc_server(&addr, state.clone()) {
            Ok(mut restarted) => {
                let _ = restarted.close();
                panic!("shutdown state unexpectedly restarted a listener on {addr}");
            }
            Err(err) => err,
        };
        assert!(
            err.contains("readiness transition failed"),
            "unexpected restart error: {err}"
        );
        assert!(
            !state.readiness.is_ready(),
            "failed restart from Shutdown must stay not-ready"
        );
        let rebound = TcpListener::bind(&addr).expect("failed restart must not keep listener live");
        drop(rebound);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn failed_bind_does_not_mark_ready() {
        let occupied = TcpListener::bind("127.0.0.1:0").expect("bind occupied listener");
        let addr = occupied.local_addr().expect("occupied addr").to_string();
        let (state, dir) = build_state(false);
        let err = match start_devnet_rpc_server(&addr, state.clone()) {
            Ok(mut server) => {
                let _ = server.close();
                panic!("start_devnet_rpc_server unexpectedly succeeded on occupied {addr}");
            }
            Err(err) => err,
        };
        assert!(err.contains("bind "), "unexpected bind error: {err}");
        assert!(
            !state.readiness.is_ready(),
            "failed bind must not report ready"
        );
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/ready".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 503);
        assert_eq!(response_json(&response)["ready"], serde_json::json!(false));
        drop(occupied);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn shutdown_close_accepts_queued_accept_loop_completion_at_timeout_boundary() {
        let (state, dir) = build_state(false);
        assert!(state.readiness.try_mark_ready_on_startup());
        let stop = Arc::new(AtomicBool::new(false));
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        done_tx.send(()).expect("queue synthetic completion");
        drop(done_tx);
        let join = std::thread::spawn(|| {});
        let mut server = super::RunningDevnetRPCServer {
            addr: "127.0.0.1:9".to_string(),
            stop,
            active_handlers: Arc::new(AtomicUsize::new(0)),
            join: Some(join),
            done: Some(done_rx),
            readiness: Arc::clone(&state.readiness),
        };

        server
            .close_with_timeout(Duration::ZERO)
            .expect("queued accept-loop completion must win over zero remaining timeout");
        assert!(
            server.join.is_none(),
            "successful shutdown must consume the completed accept-loop handle"
        );
        assert!(
            server.stop.load(Ordering::SeqCst),
            "close must still request stop before observing queued completion"
        );
        assert!(
            !state.readiness.is_ready(),
            "queued-completion shutdown still stamps sticky readiness"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn shutdown_close_reports_timeout_without_consuming_live_handle() {
        let (state, dir) = build_state(false);
        assert!(state.readiness.try_mark_ready_on_startup());
        let stop = Arc::new(AtomicBool::new(false));
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            release_rx.recv().expect("wait for synthetic release");
            done_tx.send(()).expect("report synthetic completion");
        });
        let mut server = super::RunningDevnetRPCServer {
            addr: "127.0.0.1:9".to_string(),
            stop,
            active_handlers: Arc::new(AtomicUsize::new(0)),
            join: Some(join),
            done: Some(done_rx),
            readiness: Arc::clone(&state.readiness),
        };

        let err = server
            .close_with_timeout(Duration::from_millis(25))
            .expect_err("close must report a live accept-loop timeout");
        assert!(
            err.contains("accept loop still running"),
            "unexpected timeout error: {err}"
        );
        assert!(
            server.join.is_some(),
            "timeout must not consume the live join handle"
        );
        assert!(
            server.stop.load(Ordering::SeqCst),
            "timeout path must request the accept loop to stop"
        );
        assert!(
            !state.readiness.is_ready(),
            "timeout path still stamps sticky shutdown"
        );

        release_tx.send(()).expect("release synthetic accept loop");
        server
            .close_with_timeout(Duration::from_secs(1))
            .expect("cleanup close after release");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn shutdown_close_times_out_while_handler_is_live() {
        let (state, dir) = build_state(false);
        let mut server =
            start_devnet_rpc_server("127.0.0.1:0", state.clone()).expect("start server");
        let addr = server.addr().to_string();
        let mut holder = TcpStream::connect(&addr).expect("connect partial holder");
        holder
            .write_all(b"GET /ready HTTP/1.1\r\n")
            .expect("write partial request");
        wait_until_active_handlers(&server, 1);

        let err = server
            .close_with_timeout(Duration::from_millis(50))
            .expect_err("close must report live handler timeout");
        assert!(
            err.contains("handler(s) still running"),
            "unexpected handler timeout error: {err}"
        );
        assert!(
            server.join.is_none(),
            "accept loop should be joined before handler-drain timeout"
        );
        assert!(
            server.active_handlers.load(Ordering::SeqCst) > 0,
            "handler must still be active when timeout is reported"
        );
        drop(holder);
        server
            .close_with_timeout(Duration::from_secs(1))
            .expect("cleanup close after holder drops");
        assert_eq!(server.active_handlers.load(Ordering::SeqCst), 0);
        assert!(
            !state.readiness.is_ready(),
            "handler timeout path must stamp sticky shutdown"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn metrics_render_handles_poisoned_locks() {
        let (state, dir) = build_state(true);
        let sync_engine = Arc::clone(&state.sync_engine);
        let tx_pool = Arc::clone(&state.tx_pool);
        let _ = std::thread::spawn(move || {
            let _guard = sync_engine.lock().expect("lock");
            panic!("poison sync engine");
        })
        .join();
        let _ = std::thread::spawn(move || {
            let _guard = tx_pool.lock().expect("lock");
            panic!("poison tx pool");
        })
        .join();
        let body = render_prometheus_metrics(&state);
        assert!(body.contains("rubin_node_tip_height 0"));
        assert!(body.contains("rubin_node_in_ibd 1"));
        assert!(body.contains("rubin_node_mempool_txs 0"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn metrics_routes_survive_poisoned_metrics_lock() {
        let (state, dir) = build_state(true);
        let metrics = Arc::clone(&state.metrics);
        let _ = std::thread::spawn(move || {
            let _guard = metrics.inner.lock().expect("lock");
            panic!("poison metrics");
        })
        .join();

        let submit_response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/submit_tx".to_string(),
                body: br#"{"tx_hex":"zz"}"#.to_vec(),
            },
        );
        assert_eq!(submit_response.status, 400);

        let metrics_response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/metrics".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(metrics_response.status, 200);
        let body = String::from_utf8(metrics_response.body).expect("utf8");
        assert!(body.contains("rubin_node_tip_height"), "{body}");
        assert!(body.contains("rubin_node_submit_tx_total"), "{body}");
        assert!(
            !body.contains(r#"rubin_node_submit_tx_total{result=""#),
            "{body}"
        );
        assert!(
            !body.contains(r#"rubin_node_rpc_requests_total{route=""#),
            "{body}"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn concurrent_connections_are_handled() {
        let dir = unique_temp_path("rubin-concurrent-rpc");
        fs::create_dir_all(&dir).expect("mkdir");
        let block_store = BlockStore::open(block_store_path(&dir)).expect("blockstore");
        let mut engine = SyncEngine::new(
            ChainState::new(),
            Some(block_store.clone()),
            default_sync_config(None, devnet_genesis_chain_id(), None),
        )
        .expect("sync");
        engine
            .apply_block(&devnet_genesis_block_bytes(), None)
            .expect("apply genesis");
        let rpc_block_store = BlockStore::open(block_store_path(&dir)).expect("reopen blockstore");
        let state = new_devnet_rpc_state(
            Arc::new(Mutex::new(engine)),
            Some(rpc_block_store),
            Arc::new(PeerManager::new(default_peer_runtime_config("devnet", 8))),
            None,
            None,
        );
        let server = start_devnet_rpc_server("127.0.0.1:0", state).expect("start");
        let addr = server.addr().to_string();
        let n = 4;
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let a = addr.clone();
                std::thread::spawn(move || {
                    let mut s = TcpStream::connect(&a).expect("connect");
                    s.set_read_timeout(Some(Duration::from_secs(5)))
                        .expect("timeout");
                    s.write_all(b"GET /get_tip HTTP/1.0\r\n\r\n")
                        .expect("write");
                    let mut buf = Vec::new();
                    let _ = s.read_to_end(&mut buf);
                    let text = String::from_utf8_lossy(&buf);
                    assert!(text.contains("200 OK"), "expected 200 OK, got: {text}");
                })
            })
            .collect();
        for h in handles {
            h.join().expect("join");
        }
        drop(server);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn excess_connections_are_dropped_at_capacity() {
        let dir = unique_temp_path("rubin-capacity-rpc");
        fs::create_dir_all(&dir).expect("mkdir");
        let block_store = BlockStore::open(block_store_path(&dir)).expect("blockstore");
        let mut engine = SyncEngine::new(
            ChainState::new(),
            Some(block_store.clone()),
            default_sync_config(None, devnet_genesis_chain_id(), None),
        )
        .expect("sync");
        engine
            .apply_block(&devnet_genesis_block_bytes(), None)
            .expect("apply genesis");
        let rpc_block_store = BlockStore::open(block_store_path(&dir)).expect("reopen blockstore");
        let state = new_devnet_rpc_state(
            Arc::new(Mutex::new(engine)),
            Some(rpc_block_store),
            Arc::new(PeerManager::new(default_peer_runtime_config("devnet", 8))),
            None,
            None,
        );
        let server = start_devnet_rpc_server("127.0.0.1:0", state).expect("start");
        let addr = server.addr().to_string();
        // Open MAX slow connections that hold slots via partial requests.
        let holders: Vec<_> = (0..super::MAX_CONCURRENT_RPC_CONNS)
            .map(|_| {
                let a = addr.clone();
                let (tx, rx) = std::sync::mpsc::channel::<()>();
                let h = std::thread::spawn(move || {
                    let mut s = TcpStream::connect(&a).expect("connect");
                    s.set_write_timeout(Some(Duration::from_secs(5)))
                        .expect("timeout");
                    // Partial request — server blocks on read waiting for \r\n\r\n.
                    s.write_all(b"GET /get_tip HTTP/1.0\r\n").expect("write");
                    let _ = rx.recv();
                });
                (h, tx)
            })
            .collect();
        // Wait for all connections to be accepted and handler threads started.
        std::thread::sleep(Duration::from_millis(500));
        // The (MAX+1)-th connection should be dropped.
        let excess = TcpStream::connect(&addr);
        if let Ok(mut s) = excess {
            s.set_read_timeout(Some(Duration::from_millis(500)))
                .expect("timeout");
            s.write_all(b"GET /get_tip HTTP/1.0\r\n\r\n").ok();
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            // Dropped connection: empty response or connection reset.
            assert!(
                buf.is_empty() || !String::from_utf8_lossy(&buf).contains("200 OK"),
                "excess connection should not get 200 OK"
            );
        }
        // Release holders.
        for (h, tx) in holders {
            let _ = tx.send(());
            let _ = h.join();
        }
        drop(server);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_mempool_returns_empty_for_fresh_state() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_mempool".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200);
        let body = response_json(&response);
        assert_eq!(body["count"].as_u64(), Some(0));
        assert!(body["txids"].is_array());
        assert_eq!(body["txids"].as_array().unwrap().len(), 0);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_mempool_returns_sorted_txids() {
        // Verify /get_mempool returns txids in lexicographic order
        // regardless of HashMap iteration order.
        let (state, dir) = build_state(true);
        // Inject 3 txids in reverse-lex order to guarantee the sort
        // in handle_get_mempool is exercised.
        let mut ids: Vec<[u8; 32]> = vec![[0xcc; 32], [0xaa; 32], [0xbb; 32]];
        {
            let mut pool = state.tx_pool.lock().expect("pool lock");
            for id in &ids {
                pool.inject_test_entry(*id, vec![0x00]);
            }
        }
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_mempool".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200);
        let body = response_json(&response);
        assert_eq!(body["count"].as_u64(), Some(3));
        let txids: Vec<String> = body["txids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        ids.sort();
        let expected: Vec<String> = ids.iter().map(hex::encode).collect();
        assert_eq!(txids, expected, "txids must be lexicographically sorted");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_mempool_rejects_post() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/get_mempool".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("GET required")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_mempool_reports_unavailable_when_tx_pool_is_poisoned() {
        let (state, dir) = build_state(true);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = state.tx_pool.lock().expect("tx_pool lock");
            panic!("forced to poison tx_pool");
        }));
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_mempool".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("mempool unavailable")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_rejects_missing_txid_param() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_tx".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        let body = response_json(&response);
        assert_eq!(body["found"].as_bool(), Some(false));
        assert!(body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("missing required query parameter"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_rejects_invalid_length() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_tx?txid=deadbeef".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_rejects_non_hex() {
        let (state, dir) = build_state(true);
        let target = format!("/get_tx?txid={}", "z".repeat(64));
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target,
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_missing_returns_found_false_with_200() {
        let (state, dir) = build_state(true);
        let unknown = "11".repeat(32);
        let target = format!("/get_tx?txid={unknown}");
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target,
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200);
        let body = response_json(&response);
        assert_eq!(body["found"].as_bool(), Some(false));
        assert_eq!(body["txid"].as_str(), Some(unknown.as_str()));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn tx_status_missing_returns_missing() {
        let (state, dir) = build_state(true);
        let unknown = "22".repeat(32);
        let target = format!("/tx_status?txid={unknown}");
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target,
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200);
        let body = response_json(&response);
        assert_eq!(body["status"].as_str(), Some("missing"));
        assert_eq!(body["txid"].as_str(), Some(unknown.as_str()));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn tx_status_rejects_invalid_txid() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/tx_status?txid=not-hex".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn tx_status_rejects_post() {
        let (state, dir) = build_state(true);
        let target = format!("/tx_status?txid={}", "33".repeat(32));
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target,
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_empty_txid_value_is_classified_as_missing() {
        // Go/Rust parity: ?txid= (present but empty value) must classify as
        // missing parameter, not length=0, to match Go parseTxIDQuery which
        // uses Query().Get returning "" for both absent and present-empty.
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_tx?txid=".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        let body = response_json(&response);
        assert!(body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("missing required query parameter"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn tx_status_empty_txid_value_is_classified_as_missing() {
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/tx_status?txid=".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        let body = response_json(&response);
        assert!(body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("missing required query parameter"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_valueless_txid_key_classified_as_missing() {
        // ?txid (key without `=`) must classify as missing, matching Go's
        // net/url which parses a valueless key into values=[""].
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_tx?txid".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        let body = response_json(&response);
        assert!(body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("missing required query parameter"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_valueless_first_key_never_accepts_later_hex_duplicate() {
        // First-match semantic (mirrors Go's Values.Get = values[0]):
        // ?txid&txid=<valid hex> — first key is valueless → missing;
        // Rust must NOT fall through to accept the later duplicate's hex.
        let (state, dir) = build_state(true);
        let valid_hex = "ab".repeat(32);
        let target = format!("/get_tx?txid&txid={valid_hex}");
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target,
                body: Vec::new(),
            },
        );
        assert_eq!(
            response.status, 400,
            "first-match semantic violated: accepted duplicate-key hex value"
        );
        let body = response_json(&response);
        assert!(body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("missing required query parameter"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_accepts_percent_encoded_hex_value() {
        // Go's Query().Get percent-decodes the value before returning it,
        // so `?txid=%61b...` becomes `ab...` and validates as valid hex.
        // Rust must match: percent-decode before length/hex checks. A
        // missing-but-syntactically-valid txid returns
        // 200 + found=false, which proves the parser accepted the
        // percent-encoded input (the parse-reject paths would return 400).
        let (state, dir) = build_state(true);

        let encoded_prefix = "%61%62"; // == "ab"
        let literal_rest = "cd".repeat(31); // 62 chars → total 64 after decode
        let target = format!("/get_tx?txid={encoded_prefix}{literal_rest}");
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target,
                body: Vec::new(),
            },
        );
        assert_eq!(
            response.status, 200,
            "percent-encoded valid hex must parse, got status={}",
            response.status
        );
        let body = response_json(&response);
        assert_eq!(body["found"].as_bool(), Some(false));
        // Echoed txid should be the decoded form (lower-case hex 'ab' + rest)
        let expected = format!("ab{literal_rest}");
        assert_eq!(body["txid"].as_str(), Some(expected.as_str()));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_malformed_percent_escape_classified_as_missing() {
        // Go's net/url.parseQuery `continue`s on percent-decode failure
        // (key OR value) and never stores the pair. So `?txid=%ZZ` alone
        // has no stored
        // txid, and `Values.Get("txid")` returns "" → Go handler classifies
        // that as "missing required query parameter". Rust must match:
        // skip the malformed pair and report missing (NOT "malformed
        // percent-escape", which was the prior divergent behavior).
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_tx?txid=%ZZ".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        let body = response_json(&response);
        assert!(body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("missing required query parameter"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_malformed_first_pair_falls_through_to_valid_second() {
        // Go parseQuery drops the first pair (value unescape fails on %ZZ)
        // and stores the second (`txid=<hex>`). `Values.Get` then returns
        // the valid hex. Rust must match.
        let (state, dir) = build_state(true);
        let valid_hex = "cd".repeat(32);
        let target = format!("/get_tx?txid=%ZZ&txid={valid_hex}");
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target,
                body: Vec::new(),
            },
        );
        assert_eq!(
            response.status, 200,
            "expected 200 found-false: malformed first pair should be skipped, second pair's valid hex should parse"
        );
        let body = response_json(&response);
        assert_eq!(body["found"].as_bool(), Some(false));
        assert_eq!(body["txid"].as_str(), Some(valid_hex.as_str()));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_percent_encoded_key_txid_is_accepted() {
        // Go parseQuery percent-decodes BOTH keys and values before
        // comparison/storage. So `?%74%78%69%64=<hex>` (the key "txid"
        // percent-encoded) is stored as `Values{"txid": [<hex>]}`. Rust
        // must match — percent-decode the key before comparing to "txid".
        let (state, dir) = build_state(true);
        let valid_hex = "ef".repeat(32);
        // "%74%78%69%64" decodes to "txid"
        let target = format!("/get_tx?%74%78%69%64={valid_hex}");
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target,
                body: Vec::new(),
            },
        );
        assert_eq!(
            response.status, 200,
            "expected 200: percent-encoded 'txid' key should decode and match"
        );
        let body = response_json(&response);
        assert_eq!(body["found"].as_bool(), Some(false));
        assert_eq!(body["txid"].as_str(), Some(valid_hex.as_str()));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_non_utf8_percent_value_not_classified_as_missing() {
        // %ff decodes to 1 raw byte (0xFF). Length check sees "got 1" —
        // same as Go where len(raw) counts raw decoded bytes.
        let (state, dir) = build_state(true);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_tx?txid=%ff".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        let body = response_json(&response);
        let err = body["error"].as_str().unwrap_or("");
        assert!(
            !err.contains("missing"),
            "non-UTF-8 decoded value must not be classified as missing, got: {err}"
        );
        // Length error with raw byte count: "got 1" (matches Go).
        assert!(
            err.contains("(got 1)"),
            "expected raw byte length 1, got: {err}"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_non_utf8_64_raw_bytes_reaches_hex_check() {
        // 62 hex chars + %c3%28 = 64 raw decoded bytes.
        // Go: len==64 → hex.DecodeString → hex error.
        // Rust: len==64 → from_utf8 fails → hex-class error.
        // Both: 400, hex-class error — NOT length error.
        let (state, dir) = build_state(true);
        let hex62 = "a".repeat(62);
        let target = format!("/get_tx?txid={hex62}%c3%28");
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target,
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        let body = response_json(&response);
        let err = body["error"].as_str().unwrap_or("");
        assert!(
            err.contains("not valid hex"),
            "64 raw bytes with non-UTF-8 must get hex error, got: {err}"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_semicolon_in_pair_is_dropped_like_go() {
        // Go parseQuery (1.17+, CVE-2021-44716) skips pairs containing
        // `;`.  `?txid=<64hex>;foo=1` → pair dropped → "missing txid".
        let (state, dir) = build_state(true);
        let valid_hex = "a".repeat(64);
        let target = format!("/get_tx?txid={valid_hex};foo=1");
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target,
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 400);
        let body = response_json(&response);
        let err = body["error"].as_str().unwrap_or("");
        assert!(
            err.contains("missing"),
            "pair with semicolon must be dropped (Go parity), got: {err}"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn get_tx_reports_unavailable_when_tx_pool_is_poisoned_before_parse() {
        // handle_get_tx must check tx_pool availability BEFORE
        // parse_txid_query, so a poisoned pool + invalid/missing txid
        // returns 503, not 400.  Parity with Go handleGetTx which
        // checks state.mempool == nil first.
        let (state, dir) = build_state(true);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = state.tx_pool.lock().expect("tx_pool lock");
            panic!("forced to poison tx_pool");
        }));
        // Deliberately malformed txid — if the old order still ran, this
        // would surface as 400 rather than the contract's 503.
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/get_tx?txid=not-hex-and-wrong-length".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("mempool unavailable")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn tx_status_reports_unavailable_when_tx_pool_is_poisoned_before_parse() {
        // Parity sibling of the handle_get_tx ordering fix:
        // tx_pool availability check BEFORE parse.
        let (state, dir) = build_state(true);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = state.tx_pool.lock().expect("tx_pool lock");
            panic!("forced to poison tx_pool");
        }));
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/tx_status?txid=not-hex".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            response_json(&response)["error"].as_str(),
            Some("mempool unavailable")
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn percent_decode_basic_cases() {
        // Returns Vec<u8> — raw decoded bytes.
        assert_eq!(super::percent_decode("abc"), Some(b"abc".to_vec()));
        assert_eq!(super::percent_decode("%61"), Some(vec![0x61]));
        assert_eq!(super::percent_decode("%41%42"), Some(vec![0x41, 0x42]));
        assert_eq!(super::percent_decode("a+b"), Some(b"a b".to_vec()));
        assert_eq!(super::percent_decode(""), Some(vec![]));
        // Malformed — non-hex digit in escape
        assert_eq!(super::percent_decode("%ZZ"), None);
        // Malformed — incomplete escape at end
        assert_eq!(super::percent_decode("%a"), None);
        assert_eq!(super::percent_decode("%"), None);
        // Non-UTF-8 decoded bytes — preserved as raw bytes (Go parity).
        assert_eq!(super::percent_decode("%ff"), Some(vec![0xff]));
        assert_eq!(super::percent_decode("%c3%28"), Some(vec![0xc3, 0x28]));
    }

    /// RUB-10 / GitHub #1151: `/ready` endpoint reports 503 + body
    /// `{"ready":false}` when the readiness gate is in the initial
    /// `NotReady` state (before `start_devnet_rpc_server` has stamped
    /// it `Ready`). Mirrors Go's `handleReady` 503 branch at
    /// `clients/go/cmd/rubin-node/http_rpc.go:669`.
    ///
    /// Proof assertion: the `assert_eq!(response.status, 503)` and
    /// `assert_eq!(response_json(&response)["ready"], json!(false))`
    /// below are the regression anchors — any future change that
    /// silently advances `NotReady` to `Ready` (e.g., adding
    /// `try_mark_ready_on_startup` to the constructor) breaks this
    /// test.
    #[test]
    fn ready_endpoint_reports_503_when_not_ready() {
        let (state, dir) = build_state(false);
        // Constructor leaves the gate in `NotReady`. Drive `/ready`
        // through `route_request` (the public dispatch entry the
        // production accept loop uses) without going through
        // `start_devnet_rpc_server`, so the gate stays at the boot
        // value.
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/ready".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 503);
        let body: Value = serde_json::from_slice(&response.body).expect("ready 503 json");
        assert_eq!(body["ready"], serde_json::json!(false));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// RUB-10 / GitHub #1151: `/ready` reports 200 + `{"ready":true}`
    /// after `start_devnet_rpc_server` stamps the gate `Ready`.
    /// Mirrors Go's `handleReady` 200 branch at `clients/go/cmd/rubin-node/http_rpc.go:666` and
    /// proves the production startup wiring (mark-ready post-bind in
    /// `start_devnet_rpc_server`) actually flips the state observable
    /// through the public RPC path.
    ///
    /// Proof assertion: `assert!(state.readiness.is_ready())` after
    /// the start call and the subsequent `200 + ready=true` body
    /// pin both the gate state and the dispatch behavior.
    #[test]
    fn ready_endpoint_reports_200_after_start_devnet_rpc_server() {
        let (state, dir) = build_state(false);
        let server =
            start_devnet_rpc_server("127.0.0.1:0", state.clone()).expect("start_devnet_rpc_server");
        // Production wiring should have stamped Ready before returning.
        assert!(
            state.readiness.is_ready(),
            "start_devnet_rpc_server must stamp Ready before returning"
        );
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/ready".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).expect("ready 200 json");
        assert_eq!(body["ready"], serde_json::json!(true));
        drop(server);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn ready_endpoint_reports_503_after_shutdown_signal_before_close() {
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let (mut state, dir) = build_state(false);
        state.readiness = Arc::new(super::ReadinessGate::with_shutdown_requested(Arc::clone(
            &shutdown_requested,
        )));
        let server =
            start_devnet_rpc_server("127.0.0.1:0", state.clone()).expect("start_devnet_rpc_server");
        assert!(state.readiness.is_ready());

        shutdown_requested.store(true, Ordering::SeqCst);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/ready".to_string(),
                body: Vec::new(),
            },
        );

        assert_eq!(response.status, 503);
        let body: Value = serde_json::from_slice(&response.body).expect("ready signal json");
        assert_eq!(body["ready"], serde_json::json!(false));
        assert!(
            !state.readiness.is_ready(),
            "observed shutdown signal must stamp readiness off before close"
        );
        drop(server);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn ready_endpoint_attach_shutdown_signal_wires_public_readiness_path() {
        let shutdown_requested = Arc::new(AtomicBool::new(true));
        let (state, dir) = build_state(false);
        let state = super::attach_shutdown_signal_to_devnet_rpc_state(
            state,
            Arc::clone(&shutdown_requested),
        );

        let err = match start_devnet_rpc_server("127.0.0.1:0", state.clone()) {
            Ok(_) => panic!("attached shutdown signal must prevent ready startup"),
            Err(err) => err,
        };

        assert!(
            err.contains("readiness transition failed"),
            "unexpected startup error: {err}"
        );
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/ready".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 503);
        let body: Value = serde_json::from_slice(&response.body).expect("ready attach json");
        assert_eq!(body["ready"], serde_json::json!(false));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn ready_endpoint_rejects_ready_startup_after_shutdown_signal() {
        let shutdown_requested = Arc::new(AtomicBool::new(true));
        let (mut state, dir) = build_state(false);
        state.readiness = Arc::new(super::ReadinessGate::with_shutdown_requested(
            shutdown_requested,
        ));

        let err = match start_devnet_rpc_server("127.0.0.1:0", state.clone()) {
            Ok(_) => panic!("shutdown-requested startup must not stamp ready"),
            Err(err) => err,
        };

        assert!(
            err.contains("readiness transition failed"),
            "unexpected startup error: {err}"
        );
        assert!(!state.readiness.is_ready());
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/ready".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 503);
        let body: Value = serde_json::from_slice(&response.body).expect("ready signal json");
        assert_eq!(body["ready"], serde_json::json!(false));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// RUB-10 / GitHub #1151: shutdown is sticky. After
    /// `RunningDevnetRPCServer::close` (or Drop) stamps `Shutdown`,
    /// `/ready` reports 503 + `{"ready":false}` permanently — mixed-
    /// client orchestrators must stop submitting work to a draining
    /// node. Mirrors Go's `MarkShutdown` semantics at
    /// `clients/go/cmd/rubin-node/http_rpc.go:184-191` (sticky
    /// `readyStateShutdown`).
    ///
    /// Proof assertion: after `close()`, `state.readiness.is_ready()`
    /// must be false AND a subsequent `try_mark_ready_on_startup`
    /// must NOT flip the state back to ready (sticky terminal).
    #[test]
    fn ready_endpoint_reports_503_after_shutdown_sticky() {
        let (state, dir) = build_state(false);
        let mut server =
            start_devnet_rpc_server("127.0.0.1:0", state.clone()).expect("start_devnet_rpc_server");
        assert!(state.readiness.is_ready());
        server.close().expect("close server");
        assert!(
            !state.readiness.is_ready(),
            "close() must flip readiness off"
        );
        // Sticky: try_mark_ready_on_startup after Shutdown must NOT
        // re-enable readiness — operators must restart the process,
        // matching Go's design.
        let won = state.readiness.try_mark_ready_on_startup();
        assert!(
            !won,
            "try_mark_ready_on_startup after Shutdown must return false"
        );
        assert!(
            !state.readiness.is_ready(),
            "Shutdown must remain sticky after re-attempt"
        );
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/ready".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 503);
        let body: Value = serde_json::from_slice(&response.body).expect("ready 503 json");
        assert_eq!(body["ready"], serde_json::json!(false));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// RUB-10 / GitHub #1151: non-GET request to `/ready` returns 405
    /// Method Not Allowed with the JSON-error envelope shared with
    /// `handle_submit_tx`/`handle_get_tip` (`{accepted:false,error:"GET required"}`)
    /// AND the RFC 9110 §15.5.6 `Allow: GET` header. Mirrors Go's
    /// `handleReady` 405 branch at `clients/go/cmd/rubin-node/http_rpc.go:647-664`.
    ///
    /// Proof assertion: `assert_eq!(response.status, 405)` and
    /// `assert!(response.extra_headers.iter().any(|(n,v)| *n == "Allow" && v == "GET"))`
    /// below pin both the status code (vs 400 used by other Rust
    /// query handlers) and the Allow-header parity that mixed-client
    /// monitoring tooling depends on.
    #[test]
    fn ready_endpoint_returns_405_with_allow_header_on_post() {
        let (state, dir) = build_state(false);
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/ready".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 405);
        let body: Value = serde_json::from_slice(&response.body).expect("ready 405 json");
        assert_eq!(body["accepted"], serde_json::json!(false));
        assert_eq!(body["error"], serde_json::json!("GET required"));
        assert!(
            response
                .extra_headers
                .iter()
                .any(|(name, value)| *name == "Allow" && value == "GET"),
            "405 response must include Allow: GET header (RFC 9110 §15.5.6); \
             got headers: {:?}",
            response.extra_headers
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// RUB-10 / GitHub #1151 + Copilot wave-1 P1 on PR #1472:
    /// `HttpResponse::with_header` rejects values containing CR/LF
    /// to close HTTP response-splitting at the API entry. Production
    /// callers in this PR pass the static literal `"GET"` so this
    /// path is currently unreachable in production, but the validator
    /// is defense-in-depth and required by the security-self-review
    /// gate for any new public API that accepts runtime-shaped
    /// `String` values.
    ///
    /// Proof assertion: a value containing `\r\nX-Inject: 1` is
    /// dropped (extra_headers stays empty for that pair) AND the
    /// rendered HTTP head emitted by `write_http_response` does NOT
    /// contain `X-Inject:`.
    #[test]
    fn with_header_drops_crlf_injected_value() {
        let r = super::HttpResponse::plain(200, "application/json", b"{}".to_vec())
            .with_header("Allow", "GET\r\nX-Inject: 1");
        assert!(
            r.extra_headers
                .iter()
                .all(|(_, v)| !v.contains('\r') && !v.contains('\n')),
            "CRLF-bearing value must not be appended; got: {:?}",
            r.extra_headers,
        );
        assert!(
            r.extra_headers.iter().all(|(name, _)| *name != "Allow"),
            "the Allow pair must be dropped entirely (not appended with sanitized value); got: {:?}",
            r.extra_headers,
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let writer = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            super::write_http_response(&mut stream, r).expect("write");
        });
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        writer.join().expect("writer joined");
        let head = String::from_utf8_lossy(&buf);
        assert!(
            !head.contains("X-Inject:"),
            "rendered HTTP head must not carry the injected header; got:\n{}",
            head,
        );
    }

    /// RUB-10 / GitHub #1151: end-to-end TCP roundtrip through
    /// `handle_connection` exercising the full public path
    /// (parser -> dispatcher -> `handle_ready` -> wire response).
    /// This complements the route-level tests above by proving the
    /// `Allow: GET` header lands in the actual HTTP wire bytes that
    /// downstream HTTP clients parse.
    ///
    /// Proof assertion: the raw response head must contain the
    /// `Allow: GET` line; the body must be the same JSON envelope.
    #[test]
    fn ready_endpoint_end_to_end_tcp_405_includes_allow_header() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let (state, dir) = build_state(false);
        let raw = b"POST /ready HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n".to_vec();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            stream.write_all(&raw).expect("write");
            stream
                .shutdown(std::net::Shutdown::Write)
                .expect("shutdown write");
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf);
            buf
        });
        let (server_stream, _) = listener.accept().expect("accept");
        let _ = handle_connection(server_stream, &state);
        let response_bytes = client.join().expect("join client");
        let head_end = response_bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response head delimiter");
        let head_text =
            std::str::from_utf8(&response_bytes[..head_end]).expect("response head utf8");
        assert!(
            head_text.starts_with("HTTP/1.1 405 "),
            "expected 405 status line; got: {head_text}"
        );
        assert!(
            head_text
                .lines()
                .any(|line| line.eq_ignore_ascii_case("Allow: GET")),
            "expected `Allow: GET` header in response head; got: {head_text}"
        );
        let body = &response_bytes[head_end + 4..];
        let body_json: Value = serde_json::from_slice(body).expect("body json");
        assert_eq!(body_json["error"], serde_json::json!("GET required"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn readiness_gate_poison_reports_not_ready() {
        let gate = Arc::new(super::ReadinessGate::default());
        let gate_for_panic = Arc::clone(&gate);
        let _ = std::panic::catch_unwind(move || {
            let _guard = gate_for_panic.state.lock().expect("lock readiness");
            panic!("poison readiness");
        });

        assert!(
            !gate.is_ready(),
            "poisoned readiness mutex must fail closed as not ready"
        );
    }

    /// RUB-10 / GitHub #1151: `ReadinessGate::try_mark_ready_on_startup`
    /// is one-shot. The first call from `NotReady` returns true; any
    /// subsequent call (whether re-entering from `Ready` or after
    /// `mark_shutdown` flipped to `Shutdown`) returns false. Mirrors
    /// Go `readinessGate.TryMarkReadyOnStartup` at `clients/go/cmd/rubin-node/http_rpc.go:166-180`.
    ///
    /// Proof assertion: this drives the gate through every documented
    /// transition (NotReady -> Ready, Ready -> Ready idempotent,
    /// Ready -> Shutdown, Shutdown sticky) and verifies the boolean
    /// returns + observable `is_ready()` reads at each step.
    #[test]
    fn readiness_gate_state_transitions_match_go_semantics() {
        // Use the public DevnetRPCState so this test exercises the
        // exact gate the production constructor returns.
        let (state, dir) = build_state(false);
        // 1) NotReady -> Ready: first try wins.
        assert!(!state.readiness.is_ready());
        assert!(state.readiness.try_mark_ready_on_startup());
        assert!(state.readiness.is_ready());
        // 2) Ready -> Ready (idempotent re-call returns false; no flip).
        assert!(!state.readiness.try_mark_ready_on_startup());
        assert!(state.readiness.is_ready());
        // 3) Ready -> Shutdown via mark_shutdown.
        state.readiness.mark_shutdown();
        assert!(!state.readiness.is_ready());
        // 4) Shutdown sticky: try_mark_ready_on_startup must not flip
        //    Shutdown back to Ready.
        assert!(!state.readiness.try_mark_ready_on_startup());
        assert!(!state.readiness.is_ready());
        // 5) mark_shutdown idempotent on Shutdown.
        state.readiness.mark_shutdown();
        assert!(!state.readiness.is_ready());
        // Compile-time anchor that ReadyState enum variants exist (the
        // test itself doesn't read state internals; this prevents
        // accidental enum reshape from making the assertions tautological).
        let _states = [
            ReadyState::NotReady,
            ReadyState::Ready,
            ReadyState::Shutdown,
        ];
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// RUB-41 / GitHub #1329 hostile_case "partial startup": a
    /// `DevnetRPCState` constructed via `new_devnet_rpc_state` but
    /// never passed through `start_devnet_rpc_server` MUST report
    /// `/ready` as 503 + `{"ready":false}` regardless of any other
    /// node wiring already in place. The boot-time
    /// `try_mark_ready_on_startup` stamp lives inside
    /// `start_devnet_rpc_server`, so a
    /// half-spawned node — for example a fixture that constructs the
    /// state to exercise some other handler in isolation, or a
    /// production startup that bails before the listener is bound —
    /// MUST NOT be observed as ready by orchestrators.
    ///
    /// This is the public-path counterpart of the boot-state row in
    /// the `ReadinessGate` parity matrix doc. It complements
    /// `ready_endpoint_reports_503_when_not_ready` (which exercises
    /// the gate-only path) by asserting that a richer state object
    /// (block_store wired, peer_manager wired, sync_engine populated)
    /// still reports 503 when the gate is at boot zero-value.
    ///
    /// Proof assertion: drive `/ready` through `route_request` (the
    /// production HTTP dispatch entry the accept loop calls) WITHOUT
    /// calling `start_devnet_rpc_server`. The asserts below pin the
    /// public-path output (status 503 + body `{"ready":false}`) and
    /// the post-condition that the gate remains eligible for the
    /// boot-time stamp (proof anchor: `try_mark_ready_on_startup`
    /// returns true after the dispatch, which only succeeds from
    /// the `NotReady` initial cell value).
    #[test]
    fn ready_endpoint_partial_start_returns_503() {
        let (state, dir) = build_state(true);
        // Sanity: gate is at boot zero-value, not yet stamped Ready.
        assert!(
            !state.readiness.is_ready(),
            "freshly constructed gate must report not-ready before \
             start_devnet_rpc_server"
        );
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/ready".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(
            response.status, 503,
            "/ready on a partially-started node must report 503 (boot \
             zero-value gate); got status={}",
            response.status
        );
        let body: Value =
            serde_json::from_slice(&response.body).expect("partial-start ready 503 json");
        assert_eq!(body["ready"], serde_json::json!(false));
        // Proof anchor: try_mark_ready_on_startup returns true only
        // when the gate is at the NotReady initial cell value. The
        // assertion below therefore pins that the partial-start path
        // leaves the gate in NotReady (not Shutdown), so the boot-
        // time stamp can still complete on the same state object.
        assert!(
            state.readiness.try_mark_ready_on_startup(),
            "partial-start gate must still be in NotReady (eligible \
             for boot stamp), not Shutdown"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// RUB-41 / GitHub #1329 hostile_case "status field mismatch vs
    /// Go": pin the exact byte format Rust's `/ready` responses
    /// produce so a future change to `json_response` or the
    /// `ReadyResponse` struct cannot silently drift from the wire
    /// shape orchestrators (mixed-client devnet evidence consumers,
    /// Codacy/Copilot health probes, operator scripts) parse.
    ///
    /// Pinned by this test (RUB-10 PR #1472 baseline preserved):
    /// - 200 path: `Content-Type: application/json`, body bytes
    ///   `{"ready":true}` (no trailing newline, no whitespace inside
    ///   braces, fields in declaration order).
    /// - 503 path: `Content-Type: application/json`, body bytes
    ///   `{"ready":false}`.
    /// - 405 path: `Content-Type: application/json` + `Allow: GET`
    ///   header, body bytes `{"accepted":false,"error":"GET required"}`
    ///   (no `txid` field — `Option::None` skipped via
    ///   `skip_serializing_if`).
    ///
    /// Documented divergence vs Go that this test does NOT close
    /// (out of RUB-41 scope per `class_change_stop_rule`): Go's
    /// `writeJSONResponse` calls `json.NewEncoder(w).Encode(payload)`,
    /// which appends a `\n` byte per Go documentation
    /// (`encoding/json.Encoder.Encode`). Rust's `json_response` calls
    /// `serde_json::to_vec(payload)` which does NOT append `\n`. So
    /// Go emits `{"ready":true}\n` (15 bytes) where Rust emits
    /// `{"ready":true}` (14 bytes); both are valid JSON and every
    /// JSON parser accepts both. Aligning the trailing newline is a
    /// broader `json_response` refactor that touches every Rust RPC
    /// handler — out of scope here, deferred to a future slice that
    /// owns "Rust JSON wire-format trailing-newline parity" if
    /// orchestrators ever need byte-exact equality (today the
    /// `Content-Length` header lets parsers terminate cleanly without
    /// the trailing newline).
    ///
    /// Proof assertion: byte-equality on body + content_type +
    /// extra_headers for each of the three response classes.
    #[test]
    fn ready_response_body_byte_pinned_rust_wire_format() {
        let (state, dir) = build_state(true);
        // 200 path requires Ready; stamp it directly without going
        // through start_devnet_rpc_server (no listener needed for a
        // body-only byte-pin test).
        assert!(state.readiness.try_mark_ready_on_startup());
        let r200 = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/ready".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(r200.status, 200);
        assert_eq!(r200.content_type, "application/json");
        assert_eq!(
            r200.body.as_slice(),
            b"{\"ready\":true}".as_slice(),
            "200 body bytes must match the pinned Rust wire format \
             (no trailing newline, no whitespace); got: {:?}",
            String::from_utf8_lossy(&r200.body)
        );
        // 503 path: flip gate to Shutdown, ready=false.
        state.readiness.mark_shutdown();
        let r503 = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/ready".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(r503.status, 503);
        assert_eq!(r503.content_type, "application/json");
        assert_eq!(
            r503.body.as_slice(),
            b"{\"ready\":false}".as_slice(),
            "503 body bytes must match the pinned Rust wire format; \
             got: {:?}",
            String::from_utf8_lossy(&r503.body)
        );
        // 405 path: non-GET method, error envelope + Allow header.
        let r405 = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/ready".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(r405.status, 405);
        assert_eq!(r405.content_type, "application/json");
        assert_eq!(
            r405.body.as_slice(),
            b"{\"accepted\":false,\"error\":\"GET required\"}".as_slice(),
            "405 body bytes must match the pinned Rust error envelope \
             (no `txid` field per skip_serializing_if); got: {:?}",
            String::from_utf8_lossy(&r405.body)
        );
        assert!(
            r405.extra_headers
                .iter()
                .any(|(name, value)| *name == "Allow" && value == "GET"),
            "405 response must carry `Allow: GET` per RFC 9110 \
             §15.5.6 (also pinned by ready_endpoint_returns_405_*)"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// RUB-14 / GitHub #1159: helper to build a `PeerState` with
    /// just the fields each test cares about; everything else
    /// defaults via `PeerState::default()`. Construction stays in-
    /// test (no production helper added) so the test surface
    /// doesn't grow the public API of `p2p_runtime`.
    #[allow(clippy::too_many_arguments)]
    fn make_peer(
        addr: &str,
        handshake_complete: bool,
        ban_score: i32,
        last_error: &str,
        protocol_version: u32,
        best_height: u64,
        tx_relay: bool,
        pruned_below_height: u64,
        da_mempool_size: u32,
    ) -> PeerState {
        PeerState {
            addr: addr.to_string(),
            last_error: last_error.to_string(),
            remote_version: VersionPayloadV1 {
                protocol_version,
                best_height,
                tx_relay,
                pruned_below_height,
                da_mempool_size,
                ..VersionPayloadV1::default()
            },
            ban_score,
            handshake_complete,
            ..PeerState::default()
        }
    }

    /// RUB-14 / GitHub #1159: non-GET method on `/peers` returns 405
    /// with the JSON-error envelope shared by `handle_submit_tx` /
    /// `handle_get_tip` / `handle_ready` (`{accepted:false,error:"GET required"}`)
    /// AND the RFC 9110 §15.5.6 `Allow: GET` header. Mirrors Go's
    /// `handlePeers` 405 branch at `clients/go/cmd/rubin-node/http_rpc.go:1586-1593`.
    ///
    /// Proof assertion: `assert_eq!(response.status, 405)` and
    /// `assert!(response.extra_headers.iter().any(|(n,v)| *n == "Allow" && v == "GET"))`
    /// pin both the status code and the Allow-header parity.
    #[test]
    fn peers_endpoint_returns_405_with_allow_header_on_post() {
        let (state, dir) = build_state(false);
        let response = route_request(
            &state,
            HttpRequest {
                method: "POST".to_string(),
                target: "/peers".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 405);
        let body: Value = serde_json::from_slice(&response.body).expect("peers 405 json");
        assert_eq!(body["accepted"], serde_json::json!(false));
        assert_eq!(body["error"], serde_json::json!("GET required"));
        assert!(
            response
                .extra_headers
                .iter()
                .any(|(name, value)| *name == "Allow" && value == "GET"),
            "405 response must include Allow: GET header (RFC 9110 §15.5.6); \
             got headers: {:?}",
            response.extra_headers
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// RUB-14 / GitHub #1159: empty PeerManager returns 200 +
    /// `{"count":0,"peers":[]}` — NOT `null`. Mirrors Go's empty-
    /// initialized peer-set behavior at
    /// `clients/go/cmd/rubin-node/http_rpc.go:1601-1620`: the slice
    /// allocates with `make([]peerEntry, 0, len(snapshot))` so the
    /// JSON is `[]` not `null`. Rust's `Vec::new()` serialized via
    /// serde produces the same `[]` token.
    ///
    /// Proof assertion: status 200, `body["count"] == 0`,
    /// `body["peers"]` is a JSON array with length 0.
    #[test]
    fn peers_endpoint_empty_returns_200_with_count_zero_and_empty_array() {
        let (state, dir) = build_state(false);
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/peers".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).expect("peers 200 json");
        assert_eq!(body["count"], serde_json::json!(0));
        let peers = body["peers"].as_array().expect("peers must be JSON array");
        assert_eq!(
            peers.len(),
            0,
            "empty peer set must serialize as [] not null"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// RUB-14 / GitHub #1159: populated PeerManager returns peers
    /// sorted by `addr` ascending (lexicographic byte order, matching
    /// Go's `sort.Slice` on `string`). Two consecutive scrapes must
    /// be byte-stable across `HashMap` iteration randomization.
    /// Mirrors Go's sort discipline at
    /// `clients/go/cmd/rubin-node/http_rpc.go:1602`.
    ///
    /// Proof assertion: insert peers in non-sorted order
    /// (`192.168.1.10`, `10.0.0.5`, `203.0.113.7`); the response's
    /// `peers[*].addr` sequence equals the lexicographic-ascending
    /// permutation (`10.0.0.5`, `192.168.1.10`, `203.0.113.7`); and
    /// `body["count"]` equals `peers.len()`. Addresses use port `:0`
    /// because the test exercises only the in-memory `PeerManager`
    /// projection (no TCP bind); the sort key is the full `addr`
    /// string, so the IP octets carry the order regardless of port.
    #[test]
    fn peers_endpoint_returns_count_and_peers_sorted_by_addr_ascending() {
        let (state, dir) = build_state(false);
        for addr in ["192.168.1.10:0", "10.0.0.5:0", "203.0.113.7:0"] {
            state
                .peer_manager
                .add_peer(make_peer(addr, true, 0, "", 1, 0, true, 0, 0))
                .expect("add_peer");
        }
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/peers".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).expect("peers 200 json");
        assert_eq!(body["count"], serde_json::json!(3));
        let peers = body["peers"].as_array().expect("peers must be JSON array");
        let addrs: Vec<&str> = peers.iter().map(|p| p["addr"].as_str().unwrap()).collect();
        assert_eq!(
            addrs,
            vec!["10.0.0.5:0", "192.168.1.10:0", "203.0.113.7:0"],
            "peers must be sorted by addr ascending (lexicographic byte order)"
        );
        assert_eq!(
            peers.len(),
            body["count"].as_u64().expect("count u64") as usize,
            "count must equal peers.len() by construction"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// RUB-14 / GitHub #1159: every JSON key from Go's `peerEntry`
    /// struct (`clients/go/cmd/rubin-node/http_rpc.go:418-428`) is
    /// present and carries the value sourced from the corresponding
    /// `PeerState` / `PeerState.remote_version` field.
    ///
    /// Proof assertion: insert one peer with distinct non-default
    /// values for each of the 9 fields and verify each JSON key
    /// reflects the expected value. Pins the field mapping so a
    /// future refactor of `PeerState` / `VersionPayloadV1` cannot
    /// silently drop a `/peers` field.
    #[test]
    fn peers_endpoint_includes_all_peer_entry_fields_from_state_and_remote_version() {
        let (state, dir) = build_state(false);
        state
            .peer_manager
            .add_peer(make_peer(
                "127.0.0.1:0",
                true,
                7,
                "stale handshake",
                42,
                100_500,
                false,
                90_000,
                12,
            ))
            .expect("add_peer");
        let response = route_request(
            &state,
            HttpRequest {
                method: "GET".to_string(),
                target: "/peers".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).expect("peers 200 json");
        let entry = &body["peers"][0];
        assert_eq!(entry["addr"], serde_json::json!("127.0.0.1:0"));
        assert_eq!(entry["handshake_complete"], serde_json::json!(true));
        assert_eq!(entry["ban_score"], serde_json::json!(7));
        assert_eq!(entry["last_error"], serde_json::json!("stale handshake"));
        assert_eq!(entry["protocol_version"], serde_json::json!(42));
        assert_eq!(entry["best_height"], serde_json::json!(100_500));
        assert_eq!(entry["tx_relay"], serde_json::json!(false));
        assert_eq!(entry["pruned_below_height"], serde_json::json!(90_000));
        assert_eq!(entry["da_mempool_size"], serde_json::json!(12));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// RUB-14 / GitHub #1159: end-to-end TCP roundtrip through
    /// `handle_connection` exercising the full public path
    /// (parser -> dispatcher -> `handle_peers` -> wire response).
    /// Complements the route-level tests above by proving the
    /// envelope shape and sort lands in the actual HTTP wire bytes
    /// downstream HTTP clients parse.
    ///
    /// Proof assertion: raw response head starts with `HTTP/1.1 200`;
    /// the body parses as JSON with `count == 2` and `peers[*].addr`
    /// in sorted order.
    #[test]
    fn peers_endpoint_end_to_end_tcp_returns_sorted_snapshot() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let (state, dir) = build_state(false);
        state
            .peer_manager
            .add_peer(make_peer("198.51.100.4:0", true, 0, "", 1, 1, true, 0, 0))
            .expect("add_peer");
        state
            .peer_manager
            .add_peer(make_peer("10.0.0.1:0", false, 0, "", 1, 0, true, 0, 0))
            .expect("add_peer");
        let raw = b"GET /peers HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n".to_vec();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            stream.write_all(&raw).expect("write");
            stream
                .shutdown(std::net::Shutdown::Write)
                .expect("shutdown write");
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf);
            buf
        });
        let (server_stream, _) = listener.accept().expect("accept");
        let _ = handle_connection(server_stream, &state);
        let response_bytes = client.join().expect("join client");
        let head_end = response_bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response head delimiter");
        let head_text =
            std::str::from_utf8(&response_bytes[..head_end]).expect("response head utf8");
        assert!(
            head_text.starts_with("HTTP/1.1 200 "),
            "expected 200 status line; got: {head_text}"
        );
        let body = &response_bytes[head_end + 4..];
        let body_json: Value = serde_json::from_slice(body).expect("body json");
        assert_eq!(body_json["count"], serde_json::json!(2));
        let addrs: Vec<&str> = body_json["peers"]
            .as_array()
            .expect("peers array")
            .iter()
            .map(|p| p["addr"].as_str().unwrap())
            .collect();
        assert_eq!(
            addrs,
            vec!["10.0.0.1:0", "198.51.100.4:0"],
            "wire-level peers list must be sorted by addr ascending"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
