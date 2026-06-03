use std::collections::HashMap;
use std::io::{self, Cursor, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use rubin_consensus::{
    block_hash, compact_shortid,
    constants::{MAX_BLOCK_BYTES, MAX_DA_CHUNK_COUNT, MAX_RELAY_MSG_BYTES},
    encode_compact_size, parse_block_bytes, parse_tx, read_compact_size_bytes, BLOCK_HEADER_BYTES,
};
use sha3::{Digest, Sha3_256};

use crate::sync::SyncEngine;
use crate::sync_reorg::{TxPoolCleanupPlan, PARENT_BLOCK_NOT_FOUND_ERR};

/// Maximum reasonable best_height delta before clamping peer claims.
/// Prevents malicious peers from forcing unnecessary sync with absurdly high values.
const MAX_BEST_HEIGHT_DELTA: u64 = 100_000;

const DEFAULT_READ_DEADLINE: Duration = Duration::from_secs(15);
const DEFAULT_WRITE_DEADLINE: Duration = Duration::from_secs(15);
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_BAN_THRESHOLD: i32 = 100;
const DEFAULT_ORPHAN_LIMIT: usize = 500;
const DEFAULT_ORPHAN_BYTE_LIMIT: usize = 64 << 20;
const DEFAULT_GLOBAL_ORPHAN_BYTE_LIMIT: usize = 256 << 20;
const WIRE_HEADER_SIZE: usize = 24;
const WIRE_COMMAND_SIZE: usize = 12;
const FUZZ_MAX_P2P_PAYLOAD_BYTES: u64 = 1 << 20;
const VERSION_PAYLOAD_BYTES: u64 = 89;
const MESSAGE_INV: &str = "inv";
const MESSAGE_GETDATA: &str = "getdata";
const MESSAGE_BLOCK: &str = "block";
const MESSAGE_TX: &str = "tx";
const MESSAGE_GETBLOCKS: &str = "getblocks";
const MESSAGE_GETADDR: &str = "getaddr";
const MESSAGE_ADDR: &str = "addr";
const MESSAGE_SENDCMPCT: &str = "sendcmpct";
const MESSAGE_GETBLOCKTXN: &str = "getblocktxn";
const MESSAGE_BLOCKTXN: &str = "blocktxn";
const BLOCKTXN_HASH_PAYLOAD_BYTES: usize = 32;
const COMPACT_RELAY_VERSION: u64 = 1;
const DA_CHUNK_REQUEST_VERSION: u64 = 1;
const SENDCMPCT_PAYLOAD_BYTES: u64 = 9;
const COMPACT_RELAY_INDEX_BYTES: usize = 4;
const GETDACHUNK_PAYLOAD_PREFIX_BYTES: usize = 40;
const COMPACT_SHORT_ID_BYTES: usize = 6;
const MAX_COMPACT_SIZE_BYTES: usize = 9;
const MAX_COMPACT_RELAY_ENTRIES: usize = MAX_INVENTORY_VECTORS;
const MAX_COMPACT_RELAY_INDEX_VALUE: u64 = MAX_BLOCK_BYTES - 1;
const COMPACT_LOCAL_TX_CANDIDATE_LIMIT: usize = 1000;
const COMPACT_LOCAL_TX_CANDIDATE_BYTES_LIMIT: usize = 1 << 20;
const COMPACT_ANNOUNCED_BLOCK_LIMIT: usize = 16;
const MAX_GETBLOCKTXN_PAYLOAD_BYTES: u64 = 32
    + MAX_COMPACT_SIZE_BYTES as u64
    + MAX_COMPACT_RELAY_ENTRIES as u64 * COMPACT_RELAY_INDEX_BYTES as u64;
type CompactShortId = [u8; COMPACT_SHORT_ID_BYTES];
type CompactLocalIndex = HashMap<CompactShortId, Option<Vec<u8>>>;
pub const MSG_BLOCK: u8 = 0x01;
pub const MSG_TX: u8 = 0x02;
const INVENTORY_VECTOR_SIZE: usize = 33;
const MAX_PROTOCOL_VERSION: u32 = 1024;
const MAX_INVENTORY_VECTORS: usize = 4096;
const MAX_GETDATA_RESPONSE_BLOCKS: usize = 16;
/// 128 MiB byte budget for buffered GETDATA block responses.
const MAX_GETDATA_RESPONSE_BYTES: usize = 128 * 1024 * 1024;
// Compile-time: ensure usize can hold our byte limits (rejects 32-bit targets).
const _: () = assert!(
    core::mem::size_of::<usize>() >= 8,
    "rubin-node requires 64-bit target"
);
const MAX_INVENTORY_PAYLOAD_BYTES: u64 =
    (MAX_INVENTORY_VECTORS as u64) * (INVENTORY_VECTOR_SIZE as u64);
const ADDR_PAYLOAD_ENTRY_SIZE: usize = 18;
const MAX_ADDR_PAYLOAD_ENTRIES: usize = 1000;
const MAX_ADDR_COMPACT_SIZE_BYTES: u64 = 3;
const MAX_ADDR_PAYLOAD_BYTES: u64 = MAX_ADDR_COMPACT_SIZE_BYTES
    + (MAX_ADDR_PAYLOAD_ENTRIES as u64) * (ADDR_PAYLOAD_ENTRY_SIZE as u64);
const MAX_HEADERS_BATCH: u64 = 2000;
const MAX_HEADERS_PAYLOAD_BYTES: u64 =
    MAX_HEADERS_BATCH * (rubin_consensus::BLOCK_HEADER_BYTES as u64);
const STREAM_READ_CHUNK_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OrphanPoolMetricsSnapshot {
    pub live_blocks: usize,
    pub live_bytes: usize,
}

static GLOBAL_ORPHAN_TOTAL_BYTES: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_ORPHAN_METRICS: Mutex<OrphanPoolMetricsSnapshot> =
    Mutex::new(OrphanPoolMetricsSnapshot {
        live_blocks: 0,
        live_bytes: 0,
    });
#[cfg(test)]
static GLOBAL_ORPHAN_BYTE_LIMIT_OVERRIDE: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static ORPHAN_POOL_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireMessage {
    pub command: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryVector {
    pub kind: u8,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct GetBlocksPayload {
    pub locator_hashes: Vec<[u8; 32]>,
    pub stop_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct GetBlockTxnPayload {
    pub block_hash: [u8; 32],
    pub indexes: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct GetDAChunkPayload {
    pub version: u64,
    pub da_id: [u8; 32],
    pub indexes: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BlockTxnPayload {
    pub block_hash: [u8; 32],
    pub transactions: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PrefilledTxn {
    pub index: u64,
    pub tx: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CmpctBlockPayload {
    pub header: [u8; BLOCK_HEADER_BYTES],
    pub nonce1: u64,
    pub nonce2: u64,
    pub short_ids: Vec<CompactShortId>,
    pub prefilled: Vec<PrefilledTxn>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompactReconstructionResult {
    pub transactions: Vec<Vec<u8>>,
    pub partial_transactions: Vec<Option<Vec<u8>>>,
    pub missing_indexes: Vec<u64>,
    pub missing_short_ids: Vec<CompactShortId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct VersionPayloadV1 {
    pub protocol_version: u32,
    pub tx_relay: bool,
    pub pruned_below_height: u64,
    pub da_mempool_size: u32,
    pub chain_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub best_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRuntimeConfig {
    pub network: String,
    pub max_peers: usize,
    pub read_deadline: Duration,
    pub write_deadline: Duration,
    pub ban_threshold: i32,
    pub enable_compact_receive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PeerState {
    pub addr: String,
    pub last_error: String,
    pub remote_version: VersionPayloadV1,
    pub ban_score: i32,
    pub handshake_complete: bool,
    pub version_received: bool,
    pub verack_received: bool,
}

/// Context for TX relay operations, passed through the message loop.
/// Optional — tests and block-only peers can omit it.
pub struct PeerRelayContext<'a> {
    pub relay_state: &'a crate::tx_relay::TxRelayState,
    pub peer_manager: &'a PeerManager,
    pub local_addr: &'a str,
    /// Canonical peer address registered in PeerManager (may differ from
    /// socket peer_addr for outbound connections using hostname dial targets).
    pub peer_registered_addr: &'a str,
    /// Outbound relay queues: serialized wire frames enqueued by broadcast,
    /// drained by the peer thread to avoid concurrent TcpStream writes.
    pub peer_writers: &'a std::sync::Mutex<HashMap<String, crate::tx_relay::PeerOutbox>>,
    /// Canonical TxPool admission seam with source-aware classification
    /// (RUB-178 / GitHub #1438 introduced the lifecycle plumbing using
    /// legacy `pool.admit`; RUB-173 / GitHub #1420 swapped the call to
    /// `add_tx_with_source(..., TxSource::Remote, ...)`).
    ///
    /// Threads the existing `shared.tx_pool: Arc<Mutex<TxPool>>` handle
    /// (introduced in PR #876, commit `ce270e3`, already used by the
    /// production block-apply cleanup path in `p2p_service.rs`) into the
    /// peer-tx live message dispatch so peer transactions admit through
    /// the canonical source-aware entry after relay-cache success. The
    /// `Remote` provenance matches Go's `Mempool.AddRemoteTx`
    /// (`clients/go/node/mempool.go:416`). Go's p2p production path
    /// reaches `AddRemoteTx` through three indirections:
    /// `clients/go/node/p2p/handlers_tx.go::handleTx` (line 45) calls
    /// `cfg.TxPool.Put` against the `TxPool` interface, which
    /// production wiring at
    /// `clients/go/cmd/rubin-node/main.go:489`
    /// (`p2p.NewCanonicalMempoolTxPool(mempool)`) routes through
    /// `CanonicalMempoolTxPool.Put`
    /// (`clients/go/node/p2p/mempool.go:45-54`); that method's last
    /// statement (line 53) is `p.mempool.AddRemoteTx(raw)`.
    pub tx_pool: &'a std::sync::Mutex<crate::txpool::TxPool>,
    pub da_relay: &'a std::sync::Mutex<crate::da_relay::DaRelayState>,
}

pub(crate) type PendingDaRelayStaging = (String, Vec<u8>, bool);

#[rustfmt::skip]
fn skip_da(
    tx_bytes: &[u8],
    relay_state: &crate::tx_relay::TxRelayState,
    tx_pool: &Mutex<crate::txpool::TxPool>,
) -> bool {
    if crate::da_relay::relay_da_tx_kind_prefix(tx_bytes) != Some(0x02) {
        return false;
    }
    let Ok(txid) = crate::tx_relay::canonical_txid(tx_bytes) else {
        return false;
    };
    relay_state.tx_seen.has(&txid) && tx_pool.lock().ok().and_then(|pool| pool.tx_by_id(&txid)).is_some_and(|admitted_tx| admitted_tx == tx_bytes)
}

#[derive(Debug, Default)]
pub struct LiveMessageOutcome {
    pub responses: Vec<WireMessage>,
    pub tx_pool_cleanup: TxPoolCleanupPlan,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CompactModeSnapshot {
    mode: u8,
    version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactOutstandingRequest {
    block_hash: [u8; 32],
    header: [u8; BLOCK_HEADER_BYTES],
    missing_indexes: Vec<u64>,
    missing_short_ids: Vec<CompactShortId>,
    partial_transactions: Vec<Option<Vec<u8>>>,
    nonces: [u64; 2],
    blocktxn_payload_cap: u64,
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LateBlockTxnContext {
    block_hash: [u8; 32],
    blocktxn_payload_cap: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OrphanBlockEntry {
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    block_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OrphanBlockMeta {
    parent_hash: [u8; 32],
    size: usize,
}

#[derive(Debug)]
struct OrphanBlockPool {
    limit: usize,
    byte_limit: usize,
    total_bytes: usize,
    pool: HashMap<[u8; 32], Vec<OrphanBlockEntry>>,
    by_hash: HashMap<[u8; 32], OrphanBlockMeta>,
    fifo: std::collections::VecDeque<[u8; 32]>,
}

pub struct PeerSession {
    stream: TcpStream,
    cfg: PeerRuntimeConfig,
    peer: PeerState,
    orphans: OrphanBlockPool,
    pending_tx_pool_cleanup: TxPoolCleanupPlan,
    pending_da_relay_staging: Option<PendingDaRelayStaging>,
    prefetched_read_byte: Option<u8>,
    remote_compact_mode: CompactModeSnapshot,
    compact_outstanding: Option<CompactOutstandingRequest>,
    late_blocktxn: Option<LateBlockTxnContext>,
    compact_announced: Vec<[u8; 32]>,
}

pub struct PeerManager {
    peers: RwLock<HashMap<String, PeerState>>,
    cfg: PeerRuntimeConfig,
}

/// Live Rust P2P orphan-pool observability for `/metrics`.
/// This is not consensus state and is not mixed-client readiness evidence.
pub(crate) fn orphan_pool_metrics_snapshot() -> OrphanPoolMetricsSnapshot {
    with_orphan_pool_metrics(|metrics| *metrics)
}

fn with_orphan_pool_metrics<R>(f: impl FnOnce(&mut OrphanPoolMetricsSnapshot) -> R) -> R {
    let mut metrics = GLOBAL_ORPHAN_METRICS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut metrics)
}

fn orphan_pool_metrics_add(blocks: usize, bytes: usize) {
    with_orphan_pool_metrics(|metrics| {
        metrics.live_blocks = metrics.live_blocks.saturating_add(blocks);
        metrics.live_bytes = metrics.live_bytes.saturating_add(bytes);
    });
}

fn orphan_pool_metrics_sub(blocks: usize, bytes: usize) {
    with_orphan_pool_metrics(|metrics| {
        metrics.live_blocks = metrics.live_blocks.saturating_sub(blocks);
        metrics.live_bytes = metrics.live_bytes.saturating_sub(bytes);
    });
}

#[cfg(test)]
pub(crate) fn orphan_pool_metrics_test_guard() -> std::sync::MutexGuard<'static, ()> {
    ORPHAN_POOL_TEST_LOCK
        .lock()
        .expect("lock orphan metrics tests")
}

#[cfg(test)]
pub(crate) fn reset_orphan_pool_metrics_for_test() {
    with_orphan_pool_metrics(|metrics| *metrics = OrphanPoolMetricsSnapshot::default());
    GLOBAL_ORPHAN_TOTAL_BYTES.store(0, Ordering::SeqCst);
    GLOBAL_ORPHAN_BYTE_LIMIT_OVERRIDE.store(0, Ordering::SeqCst);
}

pub fn default_peer_runtime_config(network: &str, max_peers: usize) -> PeerRuntimeConfig {
    let max_peers = if max_peers == 0 { 64 } else { max_peers };
    PeerRuntimeConfig {
        network: network.to_string(),
        max_peers,
        read_deadline: DEFAULT_READ_DEADLINE,
        write_deadline: DEFAULT_WRITE_DEADLINE,
        ban_threshold: DEFAULT_BAN_THRESHOLD,
        enable_compact_receive: false,
    }
}

impl PeerManager {
    pub fn new(cfg: PeerRuntimeConfig) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            cfg: normalize_peer_runtime_config(cfg),
        }
    }

    pub fn add_peer(&self, state: PeerState) -> Result<(), String> {
        let cfg = &self.cfg;
        let mut peers = self
            .peers
            .write()
            .map_err(|_| "peer manager lock poisoned".to_string())?;
        if peers.len() >= cfg.max_peers {
            return Err("max peers reached".to_string());
        }
        peers.insert(state.addr.clone(), state);
        Ok(())
    }

    pub fn remove_peer(&self, addr: &str) {
        let Ok(mut peers) = self.peers.write() else {
            return;
        };
        peers.remove(addr);
    }

    pub fn snapshot(&self) -> Vec<PeerState> {
        let Ok(peers) = self.peers.read() else {
            return Vec::new();
        };
        peers.values().cloned().collect()
    }
}

impl PeerSession {
    /// Write raw pre-serialized bytes to the peer's TcpStream.
    /// Used for draining relay outbox frames.
    pub fn write_raw(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(data)
    }

    fn new(stream: TcpStream, cfg: PeerRuntimeConfig) -> Result<Self, String> {
        let addr = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        Ok(Self {
            stream,
            cfg: normalize_peer_runtime_config(cfg),
            peer: PeerState {
                addr,
                ..PeerState::default()
            },
            orphans: OrphanBlockPool::new(DEFAULT_ORPHAN_LIMIT, DEFAULT_ORPHAN_BYTE_LIMIT),
            pending_tx_pool_cleanup: TxPoolCleanupPlan::default(),
            pending_da_relay_staging: None,
            prefetched_read_byte: None,
            remote_compact_mode: CompactModeSnapshot::default(),
            compact_outstanding: None,
            late_blocktxn: None,
            compact_announced: Vec::new(),
        })
    }

    pub fn state(&self) -> PeerState {
        self.peer.clone()
    }

    pub fn take_pending_tx_pool_cleanup(&mut self) -> TxPoolCleanupPlan {
        std::mem::take(&mut self.pending_tx_pool_cleanup)
    }

    pub(crate) fn take_pending_da_relay_staging(&mut self) -> Option<PendingDaRelayStaging> {
        self.pending_da_relay_staging.take()
    }

    fn stash_pending_tx_pool_cleanup(&mut self, cleanup: TxPoolCleanupPlan) {
        if cleanup.is_empty() {
            return;
        }
        let pending = self.take_pending_tx_pool_cleanup();
        self.pending_tx_pool_cleanup = pending.merge(cleanup);
    }

    #[rustfmt::skip]
    fn stash_da_staging(&mut self, peer_addr: &str, tx_bytes: Vec<u8>, chunk_hash_prevalidated: bool) {
        self.pending_da_relay_staging = Some((peer_addr.to_string(), tx_bytes, chunk_hash_prevalidated));
    }

    #[rustfmt::skip]
    pub(crate) fn apply_pending_da_relay_staging(
        &mut self,
        da_relay: &std::sync::Mutex<crate::da_relay::DaRelayState>,
        pending: Option<PendingDaRelayStaging>,
    ) {
        let Some((peer_addr, tx_bytes, chunk_hash_prevalidated)) = pending else {
            return;
        };
        let Ok(mut da_relay) = da_relay.lock() else {
            self.peer.last_error = "da relay state poisoned; peer-tx staging skipped".to_string();
            return;
        };
        if let Err(err) = da_relay.stage_relay_da_tx_bytes_checked(&peer_addr, tx_bytes, chunk_hash_prevalidated) {
            self.peer.last_error = format!("DA relay tx staging failed: {err:?}");
        }
    }

    pub fn read_message(&mut self) -> io::Result<WireMessage> {
        self.read_message_with_timeout(self.cfg.read_deadline)
    }

    pub fn read_deadline(&self) -> Duration {
        self.cfg.read_deadline
    }

    pub fn poll_read_ready(&mut self, timeout: Duration) -> io::Result<bool> {
        if self.prefetched_read_byte.is_some() {
            return Ok(true);
        }
        if self.send_expired_compact_outstanding_fallback()? {
            return Ok(false);
        }
        let timeout =
            compact_expiry_bounded_read_timeout(self.compact_outstanding_expiry(), timeout);
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(io::Error::other)?;
        let mut probe = [0u8; 1];
        match self.stream.read(&mut probe) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed connection",
            )),
            Ok(_) => {
                self.prefetched_read_byte = Some(probe[0]);
                Ok(true)
            }
            Err(err) if is_socket_read_timeout(&err) => {
                self.send_expired_compact_outstanding_fallback()?;
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    pub fn read_message_with_timeout(&mut self, timeout: Duration) -> io::Result<WireMessage> {
        if self.prefetched_read_byte.is_some() {
            self.send_expired_compact_outstanding_fallback()?;
        }
        while self.prefetched_read_byte.is_none() {
            let had_outstanding = self.compact_outstanding.is_some();
            if self.poll_read_ready(timeout)? {
                break;
            }
            if had_outstanding && self.compact_outstanding.is_none() {
                continue;
            }
            return Err(io::Error::new(io::ErrorKind::TimedOut, "peer read timeout"));
        }
        let compact_receive = self.compact_receive_active();
        let mut reader = CompactFallbackFrameReader {
            stream: &mut self.stream,
            prefetched_read_byte: self.prefetched_read_byte.take(),
            compact_outstanding: &mut self.compact_outstanding,
            late_blocktxn: &mut self.late_blocktxn,
            read_timeout: timeout,
            write_timeout: self.cfg.write_deadline,
            network_magic: network_magic(&self.cfg.network),
        };
        let payload_cap = move |command: &str| match command {
            "cmpctblock" if compact_receive => MAX_RELAY_MSG_BYTES,
            MESSAGE_GETBLOCKTXN if compact_receive => MAX_GETBLOCKTXN_PAYLOAD_BYTES,
            MESSAGE_GETBLOCKTXN => 0,
            MESSAGE_BLOCKTXN if compact_receive => MAX_RELAY_MSG_BYTES,
            MESSAGE_BLOCKTXN => 0,
            _ => runtime_payload_cap(command),
        };
        // NOTE on tx-oversize ban policy (parity gap with Go's
        // `peer.handleTx`):
        //
        // Wire-level oversize is rejected by `parse_envelope_header`
        // BEFORE `collect_live_responses` / `handle_received_tx` can
        // surface `RelayTxOutcome::Oversized`. The Err propagates up the
        // session loop and tears the peer connection down — which is a
        // hard-stop equivalent to ban_score crossing the threshold.
        //
        // Go's `peer.handleTx` bumps `BanScore += 10` and lets the
        // session continue if still below threshold, accumulating up to
        // ~10 oversize attempts before disconnect. Rust currently
        // disconnects on the first oversize tx — strictly more
        // restrictive but with the same security outcome (offending
        // peer is removed). A future task can soften Rust to bump-only
        // by reading payload length without erroring, then applying
        // ban-score policy at the higher layer; that is intentionally
        // out of scope for this Q-* task (which only aligns the
        // malformed/parse-fail surface).
        read_message_from_compact_reader(
            &mut reader,
            network_magic(&self.cfg.network),
            MAX_RELAY_MSG_BYTES,
            &payload_cap,
            compact_receive,
        )
    }

    pub fn write_message(&mut self, msg: &WireMessage) -> io::Result<()> {
        self.stream
            .set_write_timeout(Some(self.cfg.write_deadline))
            .map_err(io::Error::other)?;
        if msg.payload.len() as u64 > MAX_RELAY_MSG_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("message exceeds cap: {}", msg.payload.len()),
            ));
        }
        let compact_announcement = if msg.command == "cmpctblock" {
            Some(compact_block_hash_from_payload(&msg.payload)?)
        } else {
            None
        };
        let header =
            build_envelope_header(network_magic(&self.cfg.network), &msg.command, &msg.payload)?;
        write_wire_message_to_stream(&mut self.stream, self.cfg.write_deadline, &header, msg)?;
        if let Some(block_hash) = compact_announcement {
            self.mark_compact_block_announced(block_hash);
        }
        Ok(())
    }

    fn bump_ban(&mut self, delta: i32, reason: &str) {
        self.peer.ban_score = self.peer.ban_score.saturating_add(delta);
        self.peer.last_error = reason.to_string();
    }

    pub fn run_message_loop(&mut self) -> io::Result<()> {
        loop {
            let msg = match self.read_message() {
                Ok(m) => m,
                Err(err) => {
                    if matches!(
                        err.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) {
                        continue;
                    }
                    if err.kind() == io::ErrorKind::UnexpectedEof {
                        return Ok(());
                    }
                    return Err(err);
                }
            };
            match msg.command.as_str() {
                "ping" => {
                    let pong = WireMessage {
                        command: "pong".to_string(),
                        payload: Vec::new(),
                    };
                    self.write_message(&pong)?;
                }
                "tx" | "block" | "headers" | "getaddr" | "addr" => {
                    // accepted runtime commands (stub)
                }
                MESSAGE_SENDCMPCT => {
                    self.handle_sendcmpct(&msg.payload)?;
                }
                other => {
                    self.peer.last_error = format!("unknown command: {other}");
                    return Err(unknown_command_err(other));
                }
            }
        }
    }

    pub fn run_block_sync_loop(&mut self, sync_engine: &mut SyncEngine) -> io::Result<u64> {
        self.request_blocks(sync_engine)?;
        loop {
            if let Some((height, _)) = sync_engine.tip().map_err(io::Error::other)? {
                if height >= self.peer.remote_version.best_height {
                    return Ok(height);
                }
            }
            let msg = self.read_message()?;
            // Dispatch through the single live command truth (collect_live_responses).
            // The block-sync loop has no relay context and discards the tx-pool
            // cleanup plan, matching the prior inline-match behavior.
            let _ = self.handle_live_message(msg, sync_engine, None)?;
        }
    }

    pub fn request_blocks(&mut self, sync_engine: &SyncEngine) -> io::Result<()> {
        self.write_message(&self.build_getblocks_message(sync_engine)?)
    }

    pub fn request_blocks_if_behind(&mut self, sync_engine: &SyncEngine) -> io::Result<()> {
        if let Some(msg) = self.prepare_block_request_if_behind(sync_engine)? {
            self.write_message(&msg)?;
        }
        Ok(())
    }

    pub fn prepare_block_request_if_behind(
        &self,
        sync_engine: &SyncEngine,
    ) -> io::Result<Option<WireMessage>> {
        if self.is_behind(sync_engine)? {
            return Ok(Some(self.build_getblocks_message(sync_engine)?));
        }
        Ok(None)
    }

    pub fn collect_live_responses(
        &mut self,
        msg: WireMessage,
        sync_engine: &mut SyncEngine,
        relay_ctx: Option<&PeerRelayContext<'_>>,
    ) -> io::Result<LiveMessageOutcome> {
        if msg.payload.len() > MAX_RELAY_MSG_BYTES as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "message payload too large: {} > {}",
                    msg.payload.len(),
                    MAX_RELAY_MSG_BYTES
                ),
            ));
        }
        match msg.command.as_str() {
            MESSAGE_INV => {
                let requests =
                    self.handle_inv(&msg.payload, sync_engine, relay_ctx.map(|c| c.relay_state))?;
                if requests.is_empty() {
                    Ok(LiveMessageOutcome {
                        responses: Vec::new(),
                        tx_pool_cleanup: TxPoolCleanupPlan::default(),
                    })
                } else {
                    Ok(LiveMessageOutcome {
                        responses: vec![WireMessage {
                            command: MESSAGE_GETDATA.to_string(),
                            payload: encode_inventory_vectors(&requests)?,
                        }],
                        tx_pool_cleanup: TxPoolCleanupPlan::default(),
                    })
                }
            }
            MESSAGE_GETDATA => Ok(LiveMessageOutcome {
                responses: self.collect_getdata_responses(
                    &msg.payload,
                    sync_engine,
                    relay_ctx.map(|c| c.relay_state),
                )?,
                tx_pool_cleanup: TxPoolCleanupPlan::default(),
            }),
            MESSAGE_GETBLOCKS => {
                let items = self.handle_getblocks(&msg.payload, sync_engine)?;
                if items.is_empty() {
                    Ok(LiveMessageOutcome {
                        responses: Vec::new(),
                        tx_pool_cleanup: TxPoolCleanupPlan::default(),
                    })
                } else {
                    Ok(LiveMessageOutcome {
                        responses: vec![WireMessage {
                            command: MESSAGE_INV.to_string(),
                            payload: encode_inventory_vectors(&items)?,
                        }],
                        tx_pool_cleanup: TxPoolCleanupPlan::default(),
                    })
                }
            }
            MESSAGE_BLOCK => {
                let tx_pool_cleanup = self.handle_block(&msg.payload, sync_engine)?;
                Ok(LiveMessageOutcome {
                    responses: self
                        .prepare_block_request_if_behind(sync_engine)?
                        .into_iter()
                        .collect(),
                    tx_pool_cleanup,
                })
            }
            "cmpctblock" => self.handle_cmpctblock(&msg.payload, sync_engine, relay_ctx),
            MESSAGE_GETBLOCKTXN => self.handle_getblocktxn(&msg.payload, sync_engine),
            MESSAGE_BLOCKTXN => self.handle_blocktxn(&msg.payload, sync_engine),
            MESSAGE_TX => {
                if let Some(ctx) = relay_ctx {
                    let hash_checked = !skip_da(&msg.payload, ctx.relay_state, ctx.tx_pool);
                    if hash_checked {
                        if let Err(err) =
                            crate::da_relay::DaRelayState::validate_relay_da_tx_for_admission(
                                &msg.payload,
                            )
                        {
                            let reason =
                                format!("DA relay tx admission validation failed: {err:?}");
                            self.bump_ban(10, &reason);
                            if self.peer.ban_score >= self.cfg.ban_threshold {
                                return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
                            }
                            return Ok(LiveMessageOutcome {
                                responses: Vec::new(),
                                tx_pool_cleanup: TxPoolCleanupPlan::default(),
                            });
                        }
                    }
                    let outcome = crate::tx_relay::handle_received_tx(
                        &msg.payload,
                        sync_engine,
                        ctx.relay_state,
                        ctx.peer_manager,
                        ctx.peer_registered_addr,
                        ctx.local_addr,
                        ctx.peer_writers,
                    )?;
                    use crate::tx_relay::RelayTxOutcome::{DuplicateSeen, Relayed};
                    let relay_da_tx = matches!(
                        crate::da_relay::relay_da_tx_kind_prefix(&msg.payload),
                        Some(0x01) | Some(0x02)
                    );
                    if matches!(&outcome, Relayed { .. })
                        || (relay_da_tx && matches!(&outcome, DuplicateSeen { .. }))
                    {
                        let mut admitted_tx = None;
                        match ctx.tx_pool.lock() {
                            Ok(mut pool) => {
                                if relay_da_tx {
                                    if let Relayed { txid } | DuplicateSeen { txid } = &outcome {
                                        admitted_tx = pool.tx_by_id(txid);
                                    }
                                }
                                if admitted_tx.is_none() && matches!(&outcome, Relayed { .. }) {
                                    #[rustfmt::skip]
                                    let add_remote = pool.add_tx_with_source(&msg.payload, &sync_engine.chain_state, sync_engine.block_store.as_ref(), sync_engine.cfg.chain_id, crate::txpool::TxSource::Remote).ok().and_then(|(txid, _meta)| pool.tx_by_id(&txid));
                                    if relay_da_tx {
                                        admitted_tx = add_remote;
                                    }
                                }
                            }
                            Err(_) => {
                                self.peer.last_error =
                                    "canonical tx_pool poisoned; peer-tx admission skipped"
                                        .to_string();
                            }
                        }
                        if relay_da_tx {
                            if let Some(tx_bytes) = admitted_tx {
                                let prevalid = hash_checked && tx_bytes == msg.payload;
                                let peer_addr = ctx.peer_registered_addr;
                                self.stash_da_staging(peer_addr, tx_bytes, prevalid);
                            }
                        }
                    }
                    // Mirror Go's `peer.handleTx` parse-fail policy: parse
                    // failures bump the peer ban score by 10 and fail the
                    // session only when the cumulative score crosses the
                    // ban threshold. Pool/metadata rejections of a valid
                    // tx stay silent. Wire-level oversize is rejected
                    // earlier in `parse_envelope_header`; this branch only
                    // fires for parse failures that reach
                    // `handle_received_tx` (RPC path or sub-cap garbage).
                    if outcome.is_banworthy() {
                        let reason = match &outcome {
                            crate::tx_relay::RelayTxOutcome::MalformedParse(r) => r.clone(),
                            crate::tx_relay::RelayTxOutcome::Oversized => {
                                format!(
                                    "tx payload exceeds MAX_RELAY_MSG_BYTES: {}",
                                    msg.payload.len()
                                )
                            }
                            _ => String::new(),
                        };
                        self.bump_ban(10, &reason);
                        if self.peer.ban_score >= self.cfg.ban_threshold {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
                        }
                    }
                }
                Ok(LiveMessageOutcome {
                    responses: Vec::new(),
                    tx_pool_cleanup: TxPoolCleanupPlan::default(),
                })
            }
            "headers" | "pong" => Ok(LiveMessageOutcome {
                responses: Vec::new(),
                tx_pool_cleanup: TxPoolCleanupPlan::default(),
            }),
            MESSAGE_SENDCMPCT => {
                self.handle_sendcmpct(&msg.payload)?;
                Ok(LiveMessageOutcome {
                    responses: Vec::new(),
                    tx_pool_cleanup: TxPoolCleanupPlan::default(),
                })
            }
            "ping" => Ok(LiveMessageOutcome {
                responses: vec![WireMessage {
                    command: "pong".to_string(),
                    payload: Vec::new(),
                }],
                tx_pool_cleanup: TxPoolCleanupPlan::default(),
            }),
            MESSAGE_GETADDR => Ok(LiveMessageOutcome {
                responses: vec![WireMessage {
                    command: MESSAGE_ADDR.to_string(),
                    payload: marshal_empty_addr_payload(),
                }],
                tx_pool_cleanup: TxPoolCleanupPlan::default(),
            }),
            MESSAGE_ADDR => {
                let _ = unmarshal_addr_payload(&msg.payload)?;
                Ok(LiveMessageOutcome {
                    responses: Vec::new(),
                    tx_pool_cleanup: TxPoolCleanupPlan::default(),
                })
            }
            other => {
                self.peer.last_error = format!("unknown command: {other}");
                Err(unknown_command_err(other))
            }
        }
    }

    pub fn handle_live_message(
        &mut self,
        msg: WireMessage,
        sync_engine: &mut SyncEngine,
        relay_ctx: Option<&PeerRelayContext<'_>>,
    ) -> io::Result<TxPoolCleanupPlan> {
        let outcome = self.collect_live_responses(msg, sync_engine, relay_ctx)?;
        let pending_da_relay_staging = self.take_pending_da_relay_staging();
        if let Some(ctx) = relay_ctx {
            self.apply_pending_da_relay_staging(ctx.da_relay, pending_da_relay_staging);
        }
        for response in outcome.responses {
            self.write_message(&response)?;
        }
        Ok(outcome.tx_pool_cleanup)
    }

    fn handle_sendcmpct(&mut self, payload: &[u8]) -> io::Result<()> {
        let msg = parse_sendcmpct_runtime_payload(payload)?;
        self.remote_compact_mode = CompactModeSnapshot {
            mode: msg.mode,
            version: msg.version,
        };
        Ok(())
    }

    fn handle_cmpctblock(
        &mut self,
        payload: &[u8],
        sync_engine: &mut SyncEngine,
        relay_ctx: Option<&PeerRelayContext<'_>>,
    ) -> io::Result<LiveMessageOutcome> {
        if !self.cfg.enable_compact_receive
            || self.remote_compact_mode.version != COMPACT_RELAY_VERSION
            || self.remote_compact_mode.mode == 0
        {
            return Err(invalid_data("compact receive disabled"));
        }
        self.clear_expired_compact_outstanding_request();
        let block = match decode_cmpctblock_payload(payload) {
            Ok(block) => block,
            Err(err) => {
                self.bump_ban(10, &err.to_string());
                return Err(err);
            }
        };
        let parsed_header =
            rubin_consensus::parse_block_header_bytes(&block.header).map_err(io::Error::other)?;
        if let Err(err) = rubin_consensus::pow_check(&block.header, parsed_header.target) {
            self.bump_ban(100, &err.to_string());
            return Err(io::Error::new(io::ErrorKind::InvalidData, err.to_string()));
        }
        if matches!(sync_engine.cfg.expected_target, Some(expected) if parsed_header.target != expected)
        {
            self.bump_ban(100, "target mismatch");
            return Err(invalid_data("target mismatch"));
        }
        let block_hash = block_hash(&block.header).map_err(io::Error::other)?;
        if sync_engine
            .has_block(block_hash)
            .map_err(io::Error::other)?
        {
            self.clear_compact_outstanding_request_for_block(block_hash);
            return Ok(LiveMessageOutcome::default());
        }
        let local_txs = match relay_ctx.and_then(|ctx| ctx.tx_pool.lock().ok()) {
            Some(pool) => pool.select_transactions(
                COMPACT_LOCAL_TX_CANDIDATE_LIMIT,
                COMPACT_LOCAL_TX_CANDIDATE_BYTES_LIMIT,
            ),
            None => Vec::new(),
        };
        let result = match reconstruct_compact_block(&block, &local_txs) {
            Ok(result) => result,
            Err(_err) if !block.short_ids.is_empty() => {
                return self.request_compact_full_block_fallback(block_hash);
            }
            Err(err) => return Err(err),
        };
        if !result.transactions.is_empty() {
            return self.process_compact_transactions(
                block_hash,
                block.header,
                &result.transactions,
                sync_engine,
                !block.short_ids.is_empty(),
            );
        }
        self.request_missing_compact_transactions(block, block_hash, result)
    }
    fn request_missing_compact_transactions(
        &mut self,
        block: CmpctBlockPayload,
        block_hash: [u8; 32],
        result: CompactReconstructionResult,
    ) -> io::Result<LiveMessageOutcome> {
        if self.compact_outstanding.is_some() {
            return self.request_compact_full_block_fallback(block_hash);
        }
        let present_bytes = result
            .partial_transactions
            .iter()
            .filter_map(Option::as_ref)
            .try_fold(0u64, |total, tx| {
                validate_blocktxn_transaction_size(tx.len() as u64, total)
            })?;
        let blocktxn_payload_cap =
            32 + compact_size_wire_len(result.missing_indexes.len() as u64) + MAX_BLOCK_BYTES
                - present_bytes
                + result.missing_indexes.len() as u64 * MAX_COMPACT_SIZE_BYTES as u64;
        let payload = encode_getblocktxn_payload(GetBlockTxnPayload {
            block_hash,
            indexes: result.missing_indexes.clone(),
        })?;
        self.compact_outstanding = Some(CompactOutstandingRequest {
            block_hash,
            header: block.header,
            missing_indexes: result.missing_indexes,
            missing_short_ids: result.missing_short_ids,
            partial_transactions: result.partial_transactions,
            nonces: [block.nonce1, block.nonce2],
            blocktxn_payload_cap,
            expires_at: Instant::now() + DEFAULT_READ_DEADLINE,
        });
        Ok(LiveMessageOutcome {
            responses: vec![WireMessage {
                command: MESSAGE_GETBLOCKTXN.to_string(),
                payload,
            }],
            ..Default::default()
        })
    }
    fn handle_getblocktxn(
        &mut self,
        payload: &[u8],
        sync_engine: &SyncEngine,
    ) -> io::Result<LiveMessageOutcome> {
        if !self.compact_receive_active() {
            return Err(invalid_data("compact receive disabled"));
        }
        let req = match decode_getblocktxn_payload(payload) {
            Ok(req) => req,
            Err(err) => {
                self.bump_ban(10, &err.to_string());
                return Err(err);
            }
        };
        if let Err(err) = compact_validate_unique_getblocktxn_indexes(&req.indexes) {
            self.bump_ban(10, &err.to_string());
            return Err(err);
        }
        if !self.consume_compact_block_announcement(req.block_hash) {
            self.peer.last_error = "ignored unannounced getblocktxn request".to_string();
            return Ok(LiveMessageOutcome::default());
        }
        if !sync_engine
            .has_block(req.block_hash)
            .map_err(io::Error::other)?
        {
            return Ok(LiveMessageOutcome::default());
        }
        let block = sync_engine
            .get_block_by_hash(req.block_hash)
            .map_err(io::Error::other)?;
        let txs = match compact_block_transactions_by_index(&block, &req.indexes) {
            Ok(txs) => txs,
            Err(err) if err.kind() == io::ErrorKind::InvalidInput => {
                self.bump_ban(10, &err.to_string());
                return Err(err);
            }
            Err(err) => return Err(err),
        };
        let payload = encode_blocktxn_payload(BlockTxnPayload {
            block_hash: req.block_hash,
            transactions: txs,
        })?;
        Ok(LiveMessageOutcome {
            responses: vec![WireMessage {
                command: MESSAGE_BLOCKTXN.to_string(),
                payload,
            }],
            ..Default::default()
        })
    }
    fn handle_blocktxn(
        &mut self,
        payload: &[u8],
        sync_engine: &mut SyncEngine,
    ) -> io::Result<LiveMessageOutcome> {
        if !self.cfg.enable_compact_receive {
            return Ok(LiveMessageOutcome::default());
        }
        if payload.len() < 32 {
            if self.compact_outstanding.is_none() && self.late_blocktxn.take().is_some() {
                return Err(invalid_data("blocktxn payload missing block hash"));
            }
            self.bump_ban(10, "blocktxn payload missing block hash");
            return Err(invalid_data("blocktxn payload missing block hash"));
        }
        self.clear_expired_compact_outstanding_request();
        let mut response_hash = [0u8; 32];
        response_hash.copy_from_slice(&payload[..32]);
        let active_hash = self.compact_outstanding.as_ref().map(|req| req.block_hash);
        if active_hash != Some(response_hash) {
            if let Some(late) = self.late_blocktxn.take() {
                if response_hash == late.block_hash {
                    if payload.len() as u64 > late.blocktxn_payload_cap {
                        return Err(invalid_data("message exceeds command cap"));
                    }
                    self.peer.last_error = "ignored late blocktxn response".to_string();
                    return Ok(LiveMessageOutcome::default());
                }
                if payload.len() > 32 {
                    return Err(invalid_data("stale blocktxn response has body"));
                }
                self.peer.last_error = "ignored stale blocktxn response".to_string();
                return Ok(LiveMessageOutcome::default());
            }
        }
        let Some(req) = self.compact_outstanding.as_ref() else {
            return Ok(LiveMessageOutcome::default());
        };
        if response_hash != req.block_hash {
            return if payload.len() > 32 {
                Err(invalid_data("stale blocktxn response"))
            } else {
                Ok(LiveMessageOutcome::default())
            };
        }
        if payload.len() as u64 > req.blocktxn_payload_cap {
            self.compact_outstanding = None;
            self.bump_ban(10, "blocktxn payload exceeds outstanding cap");
            return Err(invalid_data("blocktxn payload exceeds outstanding cap"));
        }
        let req = self
            .compact_outstanding
            .take()
            .expect("compact outstanding checked");
        let response = match decode_blocktxn_payload(payload) {
            Ok(response) => response,
            Err(err) => {
                self.bump_ban(10, &err.to_string());
                return Err(err);
            }
        };
        let txs = match compact_fill_response_transactions(&req, response) {
            Ok(txs) => txs,
            Err(err)
                if err
                    .to_string()
                    .contains("blocktxn transaction short id mismatch") =>
            {
                return self.request_compact_full_block_fallback(req.block_hash);
            }
            Err(err) => {
                self.bump_ban(10, &err.to_string());
                return Err(err);
            }
        };
        self.process_compact_transactions(req.block_hash, req.header, &txs, sync_engine, true)
    }
    fn process_compact_transactions(
        &mut self,
        expected_hash: [u8; 32],
        header: [u8; BLOCK_HEADER_BYTES],
        txs: &[Vec<u8>],
        sync_engine: &mut SyncEngine,
        fallback_on_apply_error: bool,
    ) -> io::Result<LiveMessageOutcome> {
        let block_bytes = match compact_block_bytes(header, txs) {
            Ok(block_bytes) => block_bytes,
            Err(_err) => {
                return self.request_compact_full_block_fallback(expected_hash);
            }
        };
        match self.handle_block(&block_bytes, sync_engine) {
            Ok(tx_pool_cleanup) => {
                self.clear_compact_outstanding_request_for_block(expected_hash);
                Ok(LiveMessageOutcome {
                    responses: self
                        .prepare_block_request_if_behind(sync_engine)?
                        .into_iter()
                        .collect(),
                    tx_pool_cleanup,
                })
            }
            Err(err) => {
                self.peer.last_error = err.to_string();
                if fallback_on_apply_error {
                    self.request_compact_full_block_fallback(expected_hash)
                } else {
                    Err(err)
                }
            }
        }
    }
    fn request_compact_full_block_fallback(
        &mut self,
        block_hash: [u8; 32],
    ) -> io::Result<LiveMessageOutcome> {
        self.clear_compact_outstanding_request_for_block(block_hash);
        Ok(LiveMessageOutcome {
            responses: vec![compact_full_block_fallback_message(block_hash)?],
            ..Default::default()
        })
    }
    fn clear_compact_outstanding_request_for_block(&mut self, block_hash: [u8; 32]) {
        if self.compact_outstanding.as_ref().map(|req| req.block_hash) == Some(block_hash) {
            self.compact_outstanding = None;
        }
    }
    fn pop_expired_compact_outstanding_block_hash_and_payload_cap(
        &mut self,
    ) -> Option<([u8; 32], u64)> {
        pop_expired_compact_outstanding(&mut self.compact_outstanding)
    }
    fn send_expired_compact_outstanding_fallback(&mut self) -> io::Result<bool> {
        let Some((block_hash, payload_cap)) =
            self.pop_expired_compact_outstanding_block_hash_and_payload_cap()
        else {
            return Ok(false);
        };
        self.write_message(&compact_full_block_fallback_message(block_hash)?)?;
        self.late_blocktxn = Some(LateBlockTxnContext {
            block_hash,
            blocktxn_payload_cap: payload_cap,
        });
        Ok(true)
    }
    fn clear_expired_compact_outstanding_request(&mut self) {
        let _ = self.pop_expired_compact_outstanding_block_hash_and_payload_cap();
    }
    fn compact_outstanding_expiry(&self) -> Option<Instant> {
        self.compact_outstanding.as_ref().map(|req| req.expires_at)
    }
    fn compact_receive_active(&self) -> bool {
        self.cfg.enable_compact_receive
            && self.remote_compact_mode.version == COMPACT_RELAY_VERSION
            && self.remote_compact_mode.mode != 0
    }
    fn mark_compact_block_announced(&mut self, block_hash: [u8; 32]) {
        self.compact_announced.push(block_hash);
        while self.compact_announced.len() > COMPACT_ANNOUNCED_BLOCK_LIMIT {
            self.compact_announced.remove(0);
        }
    }
    fn consume_compact_block_announcement(&mut self, block_hash: [u8; 32]) -> bool {
        let Some(pos) = self
            .compact_announced
            .iter()
            .rposition(|announced| *announced == block_hash)
        else {
            return false;
        };
        self.compact_announced.remove(pos);
        true
    }
    // Historically used by the inline run_block_sync_loop match; preserved under
    // #[cfg(test)] so the original behavioral test keeps documenting the
    // follow-up getblocks path. Production dispatch routes through
    // collect_live_responses -> prepare_block_request_if_behind instead.
    #[cfg(test)]
    fn request_more_blocks_if_behind(&mut self, sync_engine: &SyncEngine) -> io::Result<()> {
        if self.is_behind(sync_engine)? {
            self.request_blocks(sync_engine)?;
        }
        Ok(())
    }

    fn is_behind(&self, sync_engine: &SyncEngine) -> io::Result<bool> {
        let Some((height, _)) = sync_engine.tip().map_err(io::Error::other)? else {
            return Ok(true);
        };
        // Clamp remote best_height claim: a malicious peer reporting an absurdly
        // high value could force unnecessary sync requests.
        let clamped_remote = self
            .peer
            .remote_version
            .best_height
            .min(height.saturating_add(MAX_BEST_HEIGHT_DELTA));
        Ok(height < clamped_remote)
    }

    pub fn handle_getblocks(
        &mut self,
        payload: &[u8],
        sync_engine: &SyncEngine,
    ) -> io::Result<Vec<InventoryVector>> {
        let req = decode_getblocks_payload(payload)?;
        let hashes = sync_engine
            .hashes_after_locators(&req.locator_hashes, req.stop_hash, 128)
            .map_err(io::Error::other)?;
        Ok(hashes
            .into_iter()
            .map(|hash| InventoryVector {
                kind: MSG_BLOCK,
                hash,
            })
            .collect())
    }

    pub fn handle_inv(
        &mut self,
        payload: &[u8],
        sync_engine: &SyncEngine,
        relay_state: Option<&crate::tx_relay::TxRelayState>,
    ) -> io::Result<Vec<InventoryVector>> {
        let vectors = decode_inventory_vectors(payload)?;
        let mut requests = Vec::new();
        for vector in vectors {
            match vector.kind {
                MSG_BLOCK
                    if !sync_engine
                        .has_block(vector.hash)
                        .map_err(io::Error::other)? =>
                {
                    requests.push(vector);
                }
                MSG_BLOCK => {}
                MSG_TX => {
                    if let Some(rs) = relay_state {
                        if !rs.tx_seen.has(&vector.hash) && !rs.relay_pool.has(&vector.hash) {
                            requests.push(vector);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(requests)
    }

    pub fn handle_block(
        &mut self,
        block_bytes: &[u8],
        sync_engine: &mut SyncEngine,
    ) -> io::Result<TxPoolCleanupPlan> {
        let parsed = parse_block_bytes(block_bytes).map_err(io::Error::other)?;
        let block_hash_bytes = block_hash(&parsed.header_bytes).map_err(io::Error::other)?;
        self.clear_compact_outstanding_request_for_block(block_hash_bytes);
        if sync_engine
            .has_block(block_hash_bytes)
            .map_err(io::Error::other)?
        {
            return Ok(TxPoolCleanupPlan::default());
        }
        if parsed.header.prev_block_hash != [0u8; 32]
            && !sync_engine
                .has_block(parsed.header.prev_block_hash)
                .map_err(io::Error::other)?
        {
            return self.retain_or_resolve_orphan(
                block_hash_bytes,
                parsed.header.prev_block_hash,
                block_bytes,
                sync_engine,
            );
        }
        match sync_engine.apply_block_with_reorg(block_bytes, None) {
            Ok(outcome) => {
                sync_engine.record_best_known_height(outcome.summary.block_height);
                let mut tx_pool_cleanup = outcome.tx_pool_cleanup;
                if let Err(err) =
                    self.resolve_orphans(block_hash_bytes, sync_engine, &mut tx_pool_cleanup)
                {
                    self.stash_pending_tx_pool_cleanup(tx_pool_cleanup);
                    return Err(err);
                }
                Ok(tx_pool_cleanup)
            }
            Err(err) if is_parent_not_found_err(&err) => Err(io::Error::other(format!(
                "unexpected missing-parent after precheck: {err}"
            ))),
            Err(err) => Err(io::Error::other(err)),
        }
    }

    fn retain_or_resolve_orphan(
        &mut self,
        block_hash: [u8; 32],
        parent_hash: [u8; 32],
        block_bytes: &[u8],
        sync_engine: &mut SyncEngine,
    ) -> io::Result<TxPoolCleanupPlan> {
        self.orphans.add(
            block_hash,
            parent_hash,
            block_bytes,
            global_orphan_byte_limit(),
        );
        if sync_engine
            .has_block(parent_hash)
            .map_err(io::Error::other)?
        {
            let mut tx_pool_cleanup = TxPoolCleanupPlan::default();
            if let Err(err) = self.resolve_orphans(parent_hash, sync_engine, &mut tx_pool_cleanup) {
                self.stash_pending_tx_pool_cleanup(tx_pool_cleanup);
                return Err(err);
            }
            return Ok(tx_pool_cleanup);
        }
        Ok(TxPoolCleanupPlan::default())
    }

    fn resolve_orphans(
        &mut self,
        parent_hash: [u8; 32],
        sync_engine: &mut SyncEngine,
        tx_pool_cleanup: &mut TxPoolCleanupPlan,
    ) -> io::Result<()> {
        let mut ready = self.orphans.take_children(parent_hash);
        while let Some(child) = ready.pop() {
            match sync_engine.apply_block_with_reorg(&child.block_bytes, None) {
                Ok(outcome) => {
                    sync_engine.record_best_known_height(outcome.summary.block_height);
                    *tx_pool_cleanup =
                        std::mem::take(tx_pool_cleanup).merge(outcome.tx_pool_cleanup);
                    ready.extend(self.orphans.take_children(child.block_hash));
                }
                Err(err) if is_parent_not_found_err(&err) => {
                    self.orphans.add(
                        child.block_hash,
                        child.parent_hash,
                        &child.block_bytes,
                        global_orphan_byte_limit(),
                    );
                }
                Err(err) => {
                    self.peer.last_error = err.clone();
                    return Err(io::Error::other(err));
                }
            }
        }
        Ok(())
    }

    // Historically used by the inline run_block_sync_loop match; preserved
    // under #[cfg(test)] so the "ignores missing blocks" behavioral test keeps
    // documenting the helper's contract. Production dispatch now returns the
    // block responses through collect_live_responses and writes them via
    // handle_live_message.
    #[cfg(test)]
    fn respond_to_getdata(
        &mut self,
        payload: &[u8],
        sync_engine: &SyncEngine,
        relay_state: Option<&crate::tx_relay::TxRelayState>,
    ) -> io::Result<()> {
        for response in self.collect_getdata_responses(payload, sync_engine, relay_state)? {
            self.write_message(&response)?;
        }
        Ok(())
    }

    fn collect_getdata_responses(
        &mut self,
        payload: &[u8],
        sync_engine: &SyncEngine,
        relay_state: Option<&crate::tx_relay::TxRelayState>,
    ) -> io::Result<Vec<WireMessage>> {
        let mut responses = Vec::new();
        let mut total_bytes: usize = 0;
        let mut block_count: usize = 0;
        for item in decode_inventory_vectors(payload)? {
            match item.kind {
                MSG_BLOCK => {
                    if !sync_engine.has_block(item.hash).map_err(io::Error::other)? {
                        continue;
                    }
                    if block_count >= MAX_GETDATA_RESPONSE_BLOCKS {
                        break;
                    }
                    let block = sync_engine
                        .get_block_by_hash(item.hash)
                        .map_err(io::Error::other)?;
                    if total_bytes.saturating_add(block.len()) > MAX_GETDATA_RESPONSE_BYTES {
                        break;
                    }
                    total_bytes = total_bytes.saturating_add(block.len());
                    block_count += 1;
                    responses.push(WireMessage {
                        command: MESSAGE_BLOCK.to_string(),
                        payload: block,
                    });
                }
                MSG_TX => {
                    if let Some(rs) = relay_state {
                        if let Some(tx_bytes) = rs.relay_pool.get(&item.hash) {
                            if total_bytes.saturating_add(tx_bytes.len())
                                > MAX_GETDATA_RESPONSE_BYTES
                            {
                                break;
                            }
                            total_bytes = total_bytes.saturating_add(tx_bytes.len());
                            responses.push(WireMessage {
                                command: MESSAGE_TX.to_string(),
                                payload: tx_bytes,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(responses)
    }

    fn build_getblocks_message(&self, sync_engine: &SyncEngine) -> io::Result<WireMessage> {
        let payload = encode_getblocks_payload(GetBlocksPayload {
            locator_hashes: sync_engine.locator_hashes(32).map_err(io::Error::other)?,
            stop_hash: [0u8; 32],
        })?;
        Ok(WireMessage {
            command: MESSAGE_GETBLOCKS.to_string(),
            payload,
        })
    }
}

/// A Read adapter that enforces an absolute wall-clock deadline across all
/// `recv()` calls.  Before every `read()` (including the internal ones made
/// by `read_exact()`), it recomputes the remaining time budget and sets
/// `SO_RCVTIMEO` to `remaining`.  This prevents slowloris-style drip-feed
/// attacks where an adversary sends one byte at a time to keep resetting a
/// per-message timeout, while matching Go's single-deadline handshake model.
struct DeadlineReader {
    stream: TcpStream,
    deadline: Instant,
}

impl Read for DeadlineReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "handshake wall-clock deadline exceeded",
            ));
        }
        self.stream
            .set_read_timeout(Some(remaining))
            .map_err(io::Error::other)?;
        self.stream.read(buf)
    }
}

struct CompactFallbackFrameReader<'a> {
    stream: &'a mut TcpStream,
    prefetched_read_byte: Option<u8>,
    compact_outstanding: &'a mut Option<CompactOutstandingRequest>,
    late_blocktxn: &'a mut Option<LateBlockTxnContext>,
    read_timeout: Duration,
    write_timeout: Duration,
    network_magic: [u8; 4],
}

impl CompactFallbackFrameReader<'_> {
    fn send_expired_compact_outstanding_fallback(&mut self) -> io::Result<bool> {
        let Some((block_hash, payload_cap)) =
            pop_expired_compact_outstanding(self.compact_outstanding)
        else {
            return Ok(false);
        };
        let msg = compact_full_block_fallback_message(block_hash)?;
        let header = build_envelope_header(self.network_magic, &msg.command, &msg.payload)?;
        write_wire_message_to_stream(self.stream, self.write_timeout, &header, &msg)?;
        *self.late_blocktxn = Some(LateBlockTxnContext {
            block_hash,
            blocktxn_payload_cap: payload_cap,
        });
        Ok(true)
    }
}

impl Read for CompactFallbackFrameReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(first_byte) = self.prefetched_read_byte.take() {
            buf[0] = first_byte;
            return Ok(1);
        }
        loop {
            if self.send_expired_compact_outstanding_fallback()? {
                continue;
            }
            let expiry = self.compact_outstanding.as_ref().map(|req| req.expires_at);
            let timeout = compact_expiry_bounded_read_timeout(expiry, self.read_timeout);
            self.stream
                .set_read_timeout(Some(timeout))
                .map_err(io::Error::other)?;
            match self.stream.read(buf) {
                Err(err) if is_socket_read_timeout(&err) => {
                    if self.send_expired_compact_outstanding_fallback()? {
                        continue;
                    }
                    return Err(err);
                }
                result => return result,
            }
        }
    }
}

pub fn perform_version_handshake(
    stream: TcpStream,
    cfg: PeerRuntimeConfig,
    local: VersionPayloadV1,
    expected_chain_id: [u8; 32],
    expected_genesis_hash: [u8; 32],
) -> io::Result<PeerSession> {
    let mut session = PeerSession::new(stream, cfg).map_err(io::Error::other)?;

    // Enforce an absolute wall-clock deadline for the entire handshake using
    // DeadlineReader: a Read adapter that recomputes SO_RCVTIMEO before
    // every recv() syscall inside read_exact().  This prevents slowloris
    // drip-feed attacks where one byte per timeout-window keeps the
    // connection alive indefinitely.  Each recv gets the full remaining
    // budget (matching Go's single-deadline handshake model).
    let handshake_budget = handshake_timeout_budget(session.cfg.read_deadline);
    let handshake_deadline = Instant::now() + handshake_budget;
    let mut deadline_reader = DeadlineReader {
        stream: session.stream.try_clone()?,
        deadline: handshake_deadline,
    };

    let version_payload = marshal_version_payload_v1(local);
    session.write_message(&WireMessage {
        command: "version".to_string(),
        payload: version_payload,
    })?;

    let mut sent_verack = false;
    loop {
        let msg = read_message_from_with_payload_limit(
            &mut deadline_reader,
            network_magic(&session.cfg.network),
            MAX_RELAY_MSG_BYTES,
            &pre_handshake_payload_cap,
        )?;
        match msg.command.as_str() {
            "version" => {
                let remote = unmarshal_version_payload_v1(&msg.payload)?;
                validate_remote_version(
                    remote,
                    local.protocol_version,
                    expected_chain_id,
                    expected_genesis_hash,
                )?;
                session.peer.version_received = true;
                session.peer.remote_version = remote;
                if !sent_verack {
                    session.write_message(&WireMessage {
                        command: "verack".to_string(),
                        payload: Vec::new(),
                    })?;
                    sent_verack = true;
                }
            }
            "verack" => {
                session.peer.verack_received = true;
            }
            _other => {
                session.bump_ban(10, "unexpected pre-handshake command");
                if session.peer.ban_score >= session.cfg.ban_threshold {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "peer banned during handshake",
                    ));
                }
            }
        }

        let completed =
            session.peer.version_received && session.peer.verack_received && sent_verack;
        if completed {
            session.peer.handshake_complete = true;
            return Ok(session);
        }
    }
}

fn validate_remote_version(
    remote: VersionPayloadV1,
    local_protocol_version: u32,
    expected_chain_id: [u8; 32],
    expected_genesis_hash: [u8; 32],
) -> io::Result<()> {
    if remote.protocol_version == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid protocol_version",
        ));
    }
    if remote.protocol_version > MAX_PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "protocol_version {} exceeds max {}",
                remote.protocol_version, MAX_PROTOCOL_VERSION
            ),
        ));
    }
    if !protocol_versions_compatible(local_protocol_version, remote.protocol_version) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "protocol_version mismatch: local={} remote={}",
                local_protocol_version, remote.protocol_version
            ),
        ));
    }
    if remote.chain_id != expected_chain_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chain_id mismatch",
        ));
    }
    if remote.genesis_hash != expected_genesis_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "genesis_hash mismatch",
        ));
    }
    Ok(())
}

#[allow(dead_code)]
pub fn fuzz_parse_wire_message(network: &str, data: &[u8]) -> io::Result<WireMessage> {
    let mut cursor = Cursor::new(data);
    read_message_from(
        &mut cursor,
        network_magic(network),
        FUZZ_MAX_P2P_PAYLOAD_BYTES,
    )
}

#[allow(dead_code)]
pub fn fuzz_parse_version_payload(payload: &[u8]) -> io::Result<VersionPayloadV1> {
    unmarshal_version_payload_v1(payload)
}

fn read_message_from<R: Read>(
    reader: &mut R,
    expected_magic: [u8; 4],
    max_payload_bytes: u64,
) -> io::Result<WireMessage> {
    read_message_from_with_payload_limit(
        reader,
        expected_magic,
        max_payload_bytes,
        &runtime_payload_cap,
    )
}

fn is_socket_read_timeout(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn compact_expiry_bounded_read_timeout(expiry: Option<Instant>, timeout: Duration) -> Duration {
    expiry
        .map(|expiry| {
            let remaining = expiry.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                Duration::from_millis(1).min(timeout)
            } else {
                remaining.min(timeout)
            }
        })
        .unwrap_or(timeout)
}

fn pop_expired_compact_outstanding(
    compact_outstanding: &mut Option<CompactOutstandingRequest>,
) -> Option<([u8; 32], u64)> {
    if compact_outstanding
        .as_ref()
        .is_none_or(|req| Instant::now() < req.expires_at)
    {
        return None;
    }
    compact_outstanding
        .take()
        .map(|req| (req.block_hash, req.blocktxn_payload_cap))
}

fn write_wire_message_to_stream(
    stream: &mut TcpStream,
    write_timeout: Duration,
    header: &[u8; WIRE_HEADER_SIZE],
    msg: &WireMessage,
) -> io::Result<()> {
    stream
        .set_write_timeout(Some(write_timeout))
        .map_err(io::Error::other)?;
    stream.write_all(header)?;
    if !msg.payload.is_empty() {
        stream.write_all(&msg.payload)?;
    }
    stream.flush()
}

fn read_message_from_with_payload_limit<R: Read>(
    reader: &mut R,
    expected_magic: [u8; 4],
    max_payload_bytes: u64,
    payload_cap: &dyn Fn(&str) -> u64,
) -> io::Result<WireMessage> {
    let mut header = [0u8; WIRE_HEADER_SIZE];
    reader.read_exact(&mut header)?;
    let envelope = parse_envelope_header(&header, expected_magic, max_payload_bytes, payload_cap)?;
    let payload = read_payload_with_checksum(reader, envelope.payload_len, envelope.checksum)?;

    Ok(WireMessage {
        command: envelope.command,
        payload,
    })
}

fn read_message_from_compact_reader(
    reader: &mut CompactFallbackFrameReader<'_>,
    expected_magic: [u8; 4],
    max_payload_bytes: u64,
    payload_cap: &dyn Fn(&str) -> u64,
    compact_receive: bool,
) -> io::Result<WireMessage> {
    let mut header = [0u8; WIRE_HEADER_SIZE];
    reader.read_exact(&mut header)?;
    let envelope = parse_envelope_header(&header, expected_magic, max_payload_bytes, payload_cap)?;
    if compact_receive && envelope.command == MESSAGE_BLOCKTXN {
        return read_blocktxn_from_compact_reader(reader, envelope);
    }
    let payload = read_payload_with_checksum(reader, envelope.payload_len, envelope.checksum)?;

    Ok(WireMessage {
        command: envelope.command,
        payload,
    })
}

fn read_blocktxn_from_compact_reader(
    reader: &mut CompactFallbackFrameReader<'_>,
    envelope: ParsedEnvelopeHeader,
) -> io::Result<WireMessage> {
    if envelope.payload_len < BLOCKTXN_HASH_PAYLOAD_BYTES {
        let payload = read_payload_with_checksum(reader, envelope.payload_len, envelope.checksum)?;
        return Ok(WireMessage {
            command: envelope.command,
            payload,
        });
    }

    let mut prefix = [0u8; BLOCKTXN_HASH_PAYLOAD_BYTES];
    reader.read_exact(&mut prefix)?;
    let active_cap = reader
        .compact_outstanding
        .as_ref()
        .filter(|req| req.block_hash == prefix)
        .map(|req| req.blocktxn_payload_cap.min(MAX_RELAY_MSG_BYTES));
    let late_cap = reader
        .late_blocktxn
        .as_ref()
        .filter(|req| req.block_hash == prefix)
        .map(|req| req.blocktxn_payload_cap.min(MAX_RELAY_MSG_BYTES));
    let matched_late_only = active_cap.is_none() && late_cap.is_some();

    if let Some(cap) = active_cap.or(late_cap) {
        if envelope.payload_len as u64 > cap {
            if matched_late_only {
                *reader.late_blocktxn = None;
            }
            return Err(invalid_data("message exceeds command cap"));
        }
    } else if envelope.payload_len > BLOCKTXN_HASH_PAYLOAD_BYTES {
        *reader.late_blocktxn = None;
        return Err(invalid_data("stale blocktxn response has body"));
    }

    let mut payload = prefix.to_vec();
    payload.resize(envelope.payload_len, 0);
    if envelope.payload_len > BLOCKTXN_HASH_PAYLOAD_BYTES {
        reader.read_exact(&mut payload[BLOCKTXN_HASH_PAYLOAD_BYTES..])?;
    }
    if envelope.checksum != wire_checksum(&payload) {
        return Err(invalid_data("invalid envelope checksum"));
    }
    Ok(WireMessage {
        command: envelope.command,
        payload,
    })
}

fn read_payload_with_checksum<R: Read>(
    reader: &mut R,
    payload_len: usize,
    want_checksum: [u8; 4],
) -> io::Result<Vec<u8>> {
    if payload_len == 0 {
        if want_checksum != wire_checksum(&[]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid envelope checksum",
            ));
        }
        return Ok(Vec::new());
    }

    let mut hasher = Sha3_256::new();
    let mut payload = Vec::with_capacity(payload_len.min(STREAM_READ_CHUNK_BYTES));
    let mut chunk = [0u8; STREAM_READ_CHUNK_BYTES];
    let mut remaining = payload_len;
    while remaining > 0 {
        let chunk_len = remaining.min(STREAM_READ_CHUNK_BYTES);
        let chunk = &mut chunk[..chunk_len];
        reader.read_exact(chunk)?;
        hasher.update(&*chunk);
        payload.extend_from_slice(chunk);
        remaining -= chunk_len;
    }

    let digest = hasher.finalize();
    let checksum = [digest[0], digest[1], digest[2], digest[3]];
    if want_checksum != checksum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid envelope checksum",
        ));
    }

    Ok(payload)
}

fn protocol_versions_compatible(local: u32, remote: u32) -> bool {
    if local == remote {
        return true;
    }
    if local > remote {
        return local - remote <= 1;
    }
    remote - local <= 1
}

pub fn encode_inventory_vectors(items: &[InventoryVector]) -> io::Result<Vec<u8>> {
    if items.len() > MAX_INVENTORY_VECTORS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inventory count exceeds limit",
        ));
    }
    let capacity = items
        .len()
        .checked_mul(INVENTORY_VECTOR_SIZE)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "inventory payload length overflow",
            )
        })?;
    let mut out = Vec::with_capacity(capacity);
    for item in items {
        if item.kind != MSG_BLOCK && item.kind != MSG_TX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported inventory type: {}", item.kind),
            ));
        }
        out.push(item.kind);
        out.extend_from_slice(&item.hash);
    }
    Ok(out)
}

pub fn decode_inventory_vectors(payload: &[u8]) -> io::Result<Vec<InventoryVector>> {
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    if !payload.len().is_multiple_of(INVENTORY_VECTOR_SIZE) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inventory payload width mismatch",
        ));
    }
    let count = payload.len() / INVENTORY_VECTOR_SIZE;
    if count > MAX_INVENTORY_VECTORS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inventory count exceeds limit",
        ));
    }
    let mut out = Vec::with_capacity(count);
    for chunk in payload.chunks_exact(INVENTORY_VECTOR_SIZE) {
        let kind = chunk[0];
        if kind != MSG_BLOCK && kind != MSG_TX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported inventory type: {kind}"),
            ));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&chunk[1..33]);
        out.push(InventoryVector { kind, hash });
    }
    Ok(out)
}

pub fn encode_getblocks_payload(req: GetBlocksPayload) -> io::Result<Vec<u8>> {
    let count = u16::try_from(req.locator_hashes.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("too many locator hashes: {}", req.locator_hashes.len()),
        )
    })?;
    let mut out = Vec::with_capacity(2 + req.locator_hashes.len() * 32 + 32);
    out.extend_from_slice(&count.to_be_bytes());
    for locator in req.locator_hashes {
        out.extend_from_slice(&locator);
    }
    out.extend_from_slice(&req.stop_hash);
    Ok(out)
}

pub fn decode_getblocks_payload(payload: &[u8]) -> io::Result<GetBlocksPayload> {
    if payload.len() < 34 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "getblocks payload too short",
        ));
    }
    let count = u16::from_be_bytes(
        payload[0..2]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid getblocks count"))?,
    ) as usize;
    let want = 2 + count * 32 + 32;
    if payload.len() != want {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "getblocks payload width mismatch",
        ));
    }
    let mut locator_hashes = Vec::with_capacity(count);
    let mut offset = 2usize;
    for _ in 0..count {
        let mut locator = [0u8; 32];
        locator.copy_from_slice(&payload[offset..offset + 32]);
        locator_hashes.push(locator);
        offset += 32;
    }
    let mut stop_hash = [0u8; 32];
    stop_hash.copy_from_slice(&payload[offset..offset + 32]);
    Ok(GetBlocksPayload {
        locator_hashes,
        stop_hash,
    })
}

pub fn encode_getblocktxn_payload(req: GetBlockTxnPayload) -> io::Result<Vec<u8>> {
    if req.indexes.len() > MAX_COMPACT_RELAY_ENTRIES {
        return Err(invalid_data("too many compact relay indexes"));
    }
    let mut out = Vec::with_capacity(
        32 + MAX_COMPACT_SIZE_BYTES + req.indexes.len() * COMPACT_RELAY_INDEX_BYTES,
    );
    out.extend_from_slice(&req.block_hash);
    encode_compact_size(req.indexes.len() as u64, &mut out);
    for idx in req.indexes {
        if idx > MAX_COMPACT_RELAY_INDEX_VALUE {
            return Err(invalid_data("compact relay index out of range"));
        }
        let idx =
            u32::try_from(idx).map_err(|_| invalid_data("compact relay index out of range"))?;
        out.extend_from_slice(&idx.to_le_bytes());
    }
    Ok(out)
}

pub fn decode_getblocktxn_payload(payload: &[u8]) -> io::Result<GetBlockTxnPayload> {
    if payload.len() < 32 {
        return Err(invalid_data("getblocktxn payload missing block hash"));
    }
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&payload[..32]);
    let (count, consumed) = read_compact_size_bytes(&payload[32..])
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let count = usize::try_from(count).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "too many compact relay indexes")
    })?;
    if count > MAX_COMPACT_RELAY_ENTRIES {
        return Err(invalid_data("too many compact relay indexes"));
    }
    let mut offset = 32 + consumed;
    let mut indexes = Vec::with_capacity(count);
    for _ in 0..count {
        if payload.len() - offset < COMPACT_RELAY_INDEX_BYTES {
            return Err(invalid_data("getblocktxn payload truncated index"));
        }
        let end = offset + COMPACT_RELAY_INDEX_BYTES;
        let idx_bytes: [u8; COMPACT_RELAY_INDEX_BYTES] = payload[offset..end]
            .try_into()
            .map_err(|_| invalid_data("getblocktxn payload truncated index"))?;
        let idx = u64::from(u32::from_le_bytes(idx_bytes));
        if idx > MAX_COMPACT_RELAY_INDEX_VALUE {
            return Err(invalid_data("compact relay index out of range"));
        }
        indexes.push(idx);
        offset = end;
    }
    if offset != payload.len() {
        return Err(invalid_data("getblocktxn payload has trailing bytes"));
    }
    Ok(GetBlockTxnPayload {
        block_hash,
        indexes,
    })
}

pub fn encode_getdachunk_payload(payload: GetDAChunkPayload) -> io::Result<Vec<u8>> {
    if payload.version != DA_CHUNK_REQUEST_VERSION {
        return Err(invalid_data("unsupported DA chunk request version"));
    }
    let count = u64::try_from(payload.indexes.len())
        .map_err(|_| invalid_data("invalid DA chunk request index count"))?;
    validate_da_chunk_request_index_count(count)?;
    let mut out = Vec::with_capacity(
        GETDACHUNK_PAYLOAD_PREFIX_BYTES + MAX_COMPACT_SIZE_BYTES + payload.indexes.len() * 2,
    );
    out.extend_from_slice(&payload.version.to_le_bytes());
    out.extend_from_slice(&payload.da_id);
    encode_compact_size(count, &mut out);
    let mut prev = 0u16;
    for (pos, idx) in payload.indexes.into_iter().enumerate() {
        validate_da_chunk_request_index(pos as u64, idx, prev)?;
        out.extend_from_slice(&idx.to_le_bytes());
        prev = idx;
    }
    Ok(out)
}

pub fn decode_getdachunk_payload(payload: &[u8]) -> io::Result<GetDAChunkPayload> {
    if payload.len() < GETDACHUNK_PAYLOAD_PREFIX_BYTES {
        return Err(invalid_data("getdachunk payload missing version or da_id"));
    }
    let mut version_bytes = [0u8; 8];
    version_bytes.copy_from_slice(&payload[..8]);
    let version = u64::from_le_bytes(version_bytes);
    if version != DA_CHUNK_REQUEST_VERSION {
        return Err(invalid_data("unsupported DA chunk request version"));
    }
    let mut da_id = [0u8; 32];
    da_id.copy_from_slice(&payload[8..GETDACHUNK_PAYLOAD_PREFIX_BYTES]);

    let mut offset = GETDACHUNK_PAYLOAD_PREFIX_BYTES;
    let count = read_compact_size_at(payload, &mut offset)?;
    validate_da_chunk_request_index_count(count)?;
    let mut indexes = Vec::with_capacity(count as usize);
    let mut prev = 0u16;
    for pos in 0..count {
        if payload.len().saturating_sub(offset) < 2 {
            return Err(invalid_data("getdachunk payload truncated index"));
        }
        let idx = u16::from_le_bytes([payload[offset], payload[offset + 1]]);
        validate_da_chunk_request_index(pos, idx, prev)?;
        indexes.push(idx);
        prev = idx;
        offset += 2;
    }
    if offset != payload.len() {
        return Err(invalid_data("getdachunk payload has trailing bytes"));
    }
    Ok(GetDAChunkPayload {
        version,
        da_id,
        indexes,
    })
}

pub fn encode_blocktxn_payload(payload: BlockTxnPayload) -> io::Result<Vec<u8>> {
    if payload.transactions.len() > MAX_COMPACT_RELAY_ENTRIES {
        return Err(invalid_data("too many compact relay transactions"));
    }
    let cap_hint = validate_compact_relay_transactions(
        &payload.transactions,
        "blocktxn transaction is non-canonical",
    )?;
    let mut out = Vec::with_capacity(cap_hint as usize);
    out.extend_from_slice(&payload.block_hash);
    encode_compact_size(payload.transactions.len() as u64, &mut out);
    for tx in payload.transactions {
        encode_compact_size(tx.len() as u64, &mut out);
        out.extend_from_slice(&tx);
    }
    Ok(out)
}

pub fn decode_blocktxn_payload(payload: &[u8]) -> io::Result<BlockTxnPayload> {
    if payload.len() < 32 {
        return Err(invalid_data("blocktxn payload missing block hash"));
    }
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&payload[..32]);
    let (count, consumed) = read_compact_size_bytes(&payload[32..])
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    if count > MAX_COMPACT_RELAY_ENTRIES as u64 {
        return Err(invalid_data("too many compact relay transactions"));
    }
    let count = count as usize;
    let mut offset = 32 + consumed;
    let mut transactions = Vec::with_capacity(count);
    let mut total_tx_bytes = 0u64;
    for _ in 0..count {
        let (tx_len, len_consumed) = read_compact_size_bytes(&payload[offset..])
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        offset += len_consumed;
        if tx_len > payload[offset..].len() as u64 {
            return Err(invalid_data("compact relay transaction truncated"));
        }
        let next_total = validate_blocktxn_transaction_size(tx_len, total_tx_bytes)?;
        let tx_len = tx_len as usize;
        let tx = &payload[offset..offset + tx_len];
        let consumed = parse_tx(tx)
            .map_err(|_| invalid_data("blocktxn transaction is non-canonical"))?
            .3;
        if consumed != tx_len {
            return Err(invalid_data("blocktxn transaction is non-canonical"));
        }
        transactions.push(tx.to_vec());
        offset += tx_len;
        total_tx_bytes = next_total;
    }
    if offset != payload.len() {
        return Err(invalid_data("blocktxn payload has trailing bytes"));
    }
    Ok(BlockTxnPayload {
        block_hash,
        transactions,
    })
}

pub fn encode_cmpctblock_payload(payload: CmpctBlockPayload) -> io::Result<Vec<u8>> {
    let cap_hint = cmpctblock_payload_byte_len(payload.short_ids.len() as u64, &payload.prefilled)?;
    let cap_hint =
        usize::try_from(cap_hint).map_err(|_| invalid_data("cmpctblock payload too large"))?;
    let mut total_tx_bytes = 0u64;
    for entry in &payload.prefilled {
        total_tx_bytes = validate_blocktxn_transaction_size(entry.tx.len() as u64, total_tx_bytes)?;
        validate_compact_relay_tx(
            &entry.tx,
            "cmpctblock prefilled transaction is non-canonical",
        )?;
    }
    let mut out = Vec::with_capacity(cap_hint);
    out.extend_from_slice(&payload.header);
    out.extend_from_slice(&payload.nonce1.to_le_bytes());
    out.extend_from_slice(&payload.nonce2.to_le_bytes());
    encode_compact_size(payload.short_ids.len() as u64, &mut out);
    for short_id in payload.short_ids {
        out.extend_from_slice(&short_id);
    }
    encode_compact_size(payload.prefilled.len() as u64, &mut out);
    for entry in payload.prefilled {
        let index = u32::try_from(entry.index)
            .map_err(|_| invalid_data("compact relay index out of range"))?;
        out.extend_from_slice(&index.to_le_bytes());
        encode_compact_size(entry.tx.len() as u64, &mut out);
        out.extend_from_slice(&entry.tx);
    }
    Ok(out)
}

pub fn decode_cmpctblock_payload(payload: &[u8]) -> io::Result<CmpctBlockPayload> {
    if payload.len() as u64 > MAX_RELAY_MSG_BYTES {
        return Err(invalid_data("cmpctblock payload too large"));
    }
    if payload.len() < BLOCK_HEADER_BYTES + 16 {
        return Err(invalid_data("cmpctblock payload missing header or nonce"));
    }
    let mut header = [0u8; BLOCK_HEADER_BYTES];
    header.copy_from_slice(&payload[..BLOCK_HEADER_BYTES]);
    let mut nonce1 = [0u8; 8];
    nonce1.copy_from_slice(&payload[BLOCK_HEADER_BYTES..BLOCK_HEADER_BYTES + 8]);
    let mut nonce2 = [0u8; 8];
    nonce2.copy_from_slice(&payload[BLOCK_HEADER_BYTES + 8..BLOCK_HEADER_BYTES + 16]);
    let mut offset = BLOCK_HEADER_BYTES + 16;
    let short_count = read_compact_size_at(payload, &mut offset)?;
    if short_count > (payload.len() - offset) as u64 / COMPACT_SHORT_ID_BYTES as u64 {
        return Err(invalid_data("cmpctblock payload truncated short IDs"));
    }
    let short_id_end = offset + (short_count as usize) * COMPACT_SHORT_ID_BYTES;
    let mut next_offset = short_id_end;
    let prefilled_count = read_compact_size_at(payload, &mut next_offset)?;
    let total_entries = validate_cmpctblock_entry_count(short_count, prefilled_count)?;
    let mut short_ids = Vec::new();
    for chunk in payload[offset..short_id_end].chunks_exact(COMPACT_SHORT_ID_BYTES) {
        let mut short_id = [0u8; COMPACT_SHORT_ID_BYTES];
        short_id.copy_from_slice(chunk);
        short_ids.push(short_id);
    }
    offset = next_offset;
    let mut out = CmpctBlockPayload {
        header,
        nonce1: u64::from_le_bytes(nonce1),
        nonce2: u64::from_le_bytes(nonce2),
        short_ids,
        prefilled: Vec::new(),
    };
    let mut prev = 0u64;
    let mut total_tx_bytes = 0u64;
    for entry_pos in 0..prefilled_count {
        if payload.len().saturating_sub(offset) < COMPACT_RELAY_INDEX_BYTES {
            return Err(invalid_data("cmpctblock payload truncated prefilled index"));
        }
        let index_end = offset + COMPACT_RELAY_INDEX_BYTES;
        let index = u64::from(u32::from_le_bytes(
            payload[offset..index_end]
                .try_into()
                .map_err(|_| invalid_data("cmpctblock payload truncated prefilled index"))?,
        ));
        offset = index_end;
        if (entry_pos > 0 && index <= prev) || index >= total_entries {
            return Err(invalid_data("compact relay index out of range"));
        }
        let tx_len = read_compact_size_at(payload, &mut offset)?;
        if tx_len > payload[offset..].len() as u64 {
            return Err(invalid_data("compact relay transaction truncated"));
        }
        total_tx_bytes = validate_blocktxn_transaction_size(tx_len, total_tx_bytes)?;
        let tx_len = usize::try_from(tx_len)
            .map_err(|_| invalid_data("compact relay transaction truncated"))?;
        let tx = &payload[offset..offset + tx_len];
        validate_compact_relay_tx(tx, "cmpctblock prefilled transaction is non-canonical")?;
        out.prefilled.push(PrefilledTxn {
            index,
            tx: tx.to_vec(),
        });
        prev = index;
        offset += tx_len;
    }
    if offset != payload.len() {
        return Err(invalid_data("cmpctblock payload has trailing bytes"));
    }
    Ok(out)
}

pub fn reconstruct_compact_block(
    payload: &CmpctBlockPayload,
    local_txs: &[Vec<u8>],
) -> io::Result<CompactReconstructionResult> {
    let total_entries = validate_cmpctblock_entry_count(
        payload.short_ids.len() as u64,
        payload.prefilled.len() as u64,
    )?;
    cmpctblock_payload_byte_len(payload.short_ids.len() as u64, &payload.prefilled)?;
    let total_entries = usize::try_from(total_entries)
        .map_err(|_| invalid_data("invalid compact relay entry count"))?;
    let prefilled_short_ids =
        compact_prefilled_short_ids(&payload.prefilled, payload.nonce1, payload.nonce2)?;
    if payload.short_ids.is_empty() {
        let transactions: Vec<_> = payload.prefilled.iter().map(|e| e.tx.clone()).collect();
        compact_validate_present_transactions(transactions.iter().map(Vec::as_slice))?;
        return Ok(CompactReconstructionResult {
            transactions,
            ..Default::default()
        });
    }

    let mut local_index = compact_local_tx_index(local_txs, payload.nonce1, payload.nonce2)?;
    for short_id in prefilled_short_ids {
        local_index.insert(short_id, None);
    }
    compact_missing(None, total_entries, payload, &local_index)?;
    let mut partial = vec![None; total_entries];
    for entry in &payload.prefilled {
        partial[entry.index as usize] = Some(entry.tx.clone());
    }
    let missing = compact_missing(Some(&mut partial), total_entries, payload, &local_index)?;
    if missing.0.is_empty() {
        compact_validate_present_transactions(partial.iter().filter_map(Option::as_deref))?;
        return Ok(CompactReconstructionResult {
            transactions: partial
                .into_iter()
                .map(|tx| tx.ok_or_else(|| invalid_data("compact block transaction missing")))
                .collect::<io::Result<Vec<_>>>()?,
            ..Default::default()
        });
    }
    Ok(CompactReconstructionResult {
        partial_transactions: partial,
        missing_indexes: missing.0,
        missing_short_ids: missing.1,
        ..Default::default()
    })
}

fn compact_prefilled_short_ids(
    prefilled: &[PrefilledTxn],
    nonce1: u64,
    nonce2: u64,
) -> io::Result<Vec<CompactShortId>> {
    let err = "cmpctblock prefilled transaction is non-canonical";
    let mut out = Vec::with_capacity(prefilled.len());
    for entry in prefilled {
        let (_, _, wtxid, consumed) = parse_tx(&entry.tx).map_err(|_| invalid_data(err))?;
        if consumed != entry.tx.len() {
            return Err(invalid_data(err));
        }
        out.push(compact_shortid(wtxid, nonce1, nonce2));
    }
    Ok(out)
}

fn compact_local_tx_index(
    local_txs: &[Vec<u8>],
    nonce1: u64,
    nonce2: u64,
) -> io::Result<CompactLocalIndex> {
    if local_txs.len() > COMPACT_LOCAL_TX_CANDIDATE_LIMIT {
        return Err(invalid_data("too many compact relay local candidates"));
    }
    let mut total_tx_bytes = 0usize;
    let mut out = HashMap::with_capacity(local_txs.len());
    for tx in local_txs {
        if validate_blocktxn_transaction_size(tx.len() as u64, 0).is_err() {
            continue;
        }
        if tx.len() > COMPACT_LOCAL_TX_CANDIDATE_BYTES_LIMIT.saturating_sub(total_tx_bytes) {
            continue;
        }
        let Ok((_, _, wtxid, consumed)) = parse_tx(tx) else {
            continue;
        };
        if consumed != tx.len() {
            continue;
        }
        let short_id = compact_shortid(wtxid, nonce1, nonce2);
        if let Some(slot) = out.get_mut(&short_id) {
            *slot = None;
            continue;
        }
        total_tx_bytes += tx.len();
        out.insert(short_id, Some(tx.clone()));
    }
    Ok(out)
}

fn compact_missing(
    mut txs: Option<&mut [Option<Vec<u8>>]>,
    total_entries: usize,
    payload: &CmpctBlockPayload,
    local_index: &CompactLocalIndex,
) -> io::Result<(Vec<u64>, Vec<CompactShortId>)> {
    let mut missing = (Vec::new(), Vec::new());
    let mut first_hit = HashMap::new();
    let mut short_pos = 0usize;
    let mut prefilled_pos = 0usize;
    for absolute_index in 0..total_entries {
        if short_pos >= payload.short_ids.len() {
            break;
        }
        if prefilled_pos < payload.prefilled.len()
            && payload.prefilled[prefilled_pos].index == absolute_index as u64
        {
            prefilled_pos += 1;
            continue;
        }
        let short_id = payload.short_ids[short_pos];
        let tx = local_index.get(&short_id).and_then(Option::as_ref);
        match tx {
            Some(tx) => {
                if let Some(first_index) = first_hit.get(&short_id).copied() {
                    if first_index != u64::MAX {
                        if let Some(txs) = txs.as_deref_mut() {
                            txs[first_index as usize] = None;
                        }
                        first_hit.insert(short_id, u64::MAX);
                        compact_push_missing(&mut missing, first_index, short_id)?;
                    }
                    compact_push_missing(&mut missing, absolute_index as u64, short_id)?;
                } else {
                    first_hit.insert(short_id, absolute_index as u64);
                    if let Some(txs) = txs.as_deref_mut() {
                        txs[absolute_index] = Some(tx.clone());
                    }
                }
            }
            None => compact_push_missing(&mut missing, absolute_index as u64, short_id)?,
        }
        short_pos += 1;
    }
    if let Some(txs) = txs {
        compact_validate_present_transactions(txs.iter().filter_map(Option::as_deref))?;
    }
    Ok(missing)
}

fn compact_push_missing(
    missing: &mut (Vec<u64>, Vec<CompactShortId>),
    index: u64,
    short_id: CompactShortId,
) -> io::Result<()> {
    missing.0.push(index);
    missing.1.push(short_id);
    (missing.0.len() <= MAX_COMPACT_RELAY_ENTRIES)
        .then_some(())
        .ok_or_else(|| invalid_data("too many compact relay missing transactions"))
}

fn compact_validate_present_transactions<'a>(
    txs: impl IntoIterator<Item = &'a [u8]>,
) -> io::Result<()> {
    compact_validate_present_transaction_lengths(txs.into_iter().map(|tx| tx.len() as u64))
}

fn compact_validate_present_transaction_lengths(
    tx_lens: impl IntoIterator<Item = u64>,
) -> io::Result<()> {
    let mut total_tx_bytes = 0u64;
    for tx_len in tx_lens {
        total_tx_bytes = validate_blocktxn_transaction_size(tx_len, total_tx_bytes)?;
    }
    Ok(())
}

fn validate_blocktxn_transaction_size(tx_len: u64, total_tx_bytes: u64) -> io::Result<u64> {
    if tx_len == 0 {
        return Err(invalid_data("blocktxn transaction is empty"));
    }
    if tx_len > MAX_BLOCK_BYTES {
        return Err(invalid_data("blocktxn transaction too large"));
    }
    if total_tx_bytes > MAX_BLOCK_BYTES - tx_len {
        return Err(invalid_data("blocktxn transactions exceed block size"));
    }
    Ok(total_tx_bytes + tx_len)
}

fn validate_compact_relay_tx(tx: &[u8], err_msg: &'static str) -> io::Result<()> {
    let consumed = parse_tx(tx).map_err(|_| invalid_data(err_msg))?.3;
    if consumed != tx.len() {
        return Err(invalid_data(err_msg));
    }
    Ok(())
}

fn validate_da_chunk_request_index_count(count: u64) -> io::Result<()> {
    if count == 0 || count > MAX_DA_CHUNK_COUNT {
        return Err(invalid_data("invalid DA chunk request index count"));
    }
    Ok(())
}

fn validate_da_chunk_request_index(pos: u64, idx: u16, prev: u16) -> io::Result<()> {
    if u64::from(idx) >= MAX_DA_CHUNK_COUNT {
        return Err(invalid_data("DA chunk request index out of range"));
    }
    if pos > 0 && idx <= prev {
        return Err(invalid_data(
            "DA chunk request indexes not strictly increasing",
        ));
    }
    Ok(())
}

fn validate_cmpctblock_entry_count(short_count: u64, prefilled_count: u64) -> io::Result<u64> {
    let total_entries = short_count
        .checked_add(prefilled_count)
        .ok_or_else(|| invalid_data("invalid compact relay entry count"))?;
    if total_entries == 0 || total_entries > MAX_BLOCK_BYTES {
        return Err(invalid_data("invalid compact relay entry count"));
    }
    Ok(total_entries)
}

fn read_compact_size_at(payload: &[u8], offset: &mut usize) -> io::Result<u64> {
    let (value, consumed) = read_compact_size_bytes(&payload[*offset..])
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    *offset += consumed;
    Ok(value)
}

fn cmpctblock_payload_byte_len(short_count: u64, prefilled: &[PrefilledTxn]) -> io::Result<u64> {
    let limit = MAX_RELAY_MSG_BYTES;
    let mut total = BLOCK_HEADER_BYTES as u64
        + 16
        + compact_size_wire_len(short_count)
        + compact_size_wire_len(prefilled.len() as u64);
    if short_count > (limit - total) / COMPACT_SHORT_ID_BYTES as u64 {
        return Err(invalid_data("cmpctblock payload too large"));
    }
    total += short_count * COMPACT_SHORT_ID_BYTES as u64;
    let total_entries = validate_cmpctblock_entry_count(short_count, prefilled.len() as u64)?;
    let mut prev_plus_one = 0u64;
    for entry in prefilled {
        if entry.index < prev_plus_one || entry.index >= total_entries {
            return Err(invalid_data("compact relay index out of range"));
        }
        let add = (COMPACT_RELAY_INDEX_BYTES as u64)
            .checked_add(compact_size_wire_len(entry.tx.len() as u64))
            .and_then(|v| v.checked_add(entry.tx.len() as u64))
            .ok_or_else(|| invalid_data("cmpctblock payload too large"))?;
        if add > limit - total {
            return Err(invalid_data("cmpctblock payload too large"));
        }
        total += add;
        prev_plus_one = entry.index + 1;
    }
    Ok(total)
}

fn validate_compact_relay_transactions(
    transactions: &[Vec<u8>],
    err_msg: &'static str,
) -> io::Result<u64> {
    let mut total_tx_bytes = 0u64;
    let mut total_payload_bytes = 32u64 + compact_size_wire_len(transactions.len() as u64);
    for tx in transactions {
        let next_total = validate_blocktxn_transaction_size(tx.len() as u64, total_tx_bytes)?;
        let payload_add = compact_size_wire_len(tx.len() as u64)
            .checked_add(tx.len() as u64)
            .ok_or_else(|| invalid_data("blocktxn payload too large"))?;
        if payload_add > MAX_RELAY_MSG_BYTES - total_payload_bytes {
            return Err(invalid_data("blocktxn payload too large"));
        }
        let consumed = parse_tx(tx).map_err(|_| invalid_data(err_msg))?.3;
        if consumed != tx.len() {
            return Err(invalid_data(err_msg));
        }
        total_tx_bytes = next_total;
        total_payload_bytes += payload_add;
    }
    Ok(total_payload_bytes)
}

fn compact_full_block_fallback_message(block_hash: [u8; 32]) -> io::Result<WireMessage> {
    Ok(WireMessage {
        command: MESSAGE_GETDATA.to_string(),
        payload: encode_inventory_vectors(&[InventoryVector {
            kind: MSG_BLOCK,
            hash: block_hash,
        }])?,
    })
}
fn compact_block_hash_from_payload(payload: &[u8]) -> io::Result<[u8; 32]> {
    if payload.len() as u64 > MAX_RELAY_MSG_BYTES {
        return Err(invalid_data("cmpctblock payload too large"));
    }
    if payload.len() < BLOCK_HEADER_BYTES + 16 {
        return Err(invalid_data("cmpctblock payload missing header or nonce"));
    }
    let mut offset = BLOCK_HEADER_BYTES + 16;
    let short_count = read_compact_size_at(payload, &mut offset)?;
    if short_count > (payload.len() - offset) as u64 / COMPACT_SHORT_ID_BYTES as u64 {
        return Err(invalid_data("cmpctblock payload truncated short IDs"));
    }
    offset += (short_count as usize) * COMPACT_SHORT_ID_BYTES;
    let prefilled_count = read_compact_size_at(payload, &mut offset)?;
    let total_entries = validate_cmpctblock_entry_count(short_count, prefilled_count)?;
    let mut prev = 0u64;
    let mut total_tx_bytes = 0u64;
    for entry_pos in 0..prefilled_count {
        if payload.len().saturating_sub(offset) < COMPACT_RELAY_INDEX_BYTES {
            return Err(invalid_data("cmpctblock payload truncated prefilled index"));
        }
        let index_end = offset + COMPACT_RELAY_INDEX_BYTES;
        let index = u64::from(u32::from_le_bytes(
            payload[offset..index_end]
                .try_into()
                .map_err(|_| invalid_data("cmpctblock payload truncated prefilled index"))?,
        ));
        offset = index_end;
        if (entry_pos > 0 && index <= prev) || index >= total_entries {
            return Err(invalid_data("compact relay index out of range"));
        }
        let tx_len = read_compact_size_at(payload, &mut offset)?;
        if tx_len > payload[offset..].len() as u64 {
            return Err(invalid_data("compact relay transaction truncated"));
        }
        total_tx_bytes = validate_blocktxn_transaction_size(tx_len, total_tx_bytes)?;
        offset += usize::try_from(tx_len)
            .map_err(|_| invalid_data("compact relay transaction truncated"))?;
        prev = index;
    }
    if offset != payload.len() {
        return Err(invalid_data("cmpctblock payload has trailing bytes"));
    }
    block_hash(&payload[..BLOCK_HEADER_BYTES]).map_err(io::Error::other)
}
fn compact_validate_unique_getblocktxn_indexes(indexes: &[u64]) -> io::Result<()> {
    if indexes.len() < 2 {
        return Ok(());
    }
    let mut seen = indexes.to_vec();
    seen.sort_unstable();
    if seen.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid_data("duplicate getblocktxn index"));
    }
    Ok(())
}

fn compact_block_transactions_by_index(block: &[u8], indexes: &[u64]) -> io::Result<Vec<Vec<u8>>> {
    let (tx_count, mut offset) = compact_block_transaction_count(block)?;
    for &idx in indexes {
        if idx >= tx_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "getblocktxn index out of range",
            ));
        }
    }
    if indexes.is_empty() {
        return Ok(Vec::new());
    }

    let mut positions = HashMap::with_capacity(indexes.len());
    let mut max_index = 0u64;
    for (pos, &idx) in indexes.iter().enumerate() {
        positions.insert(idx, pos);
        max_index = max_index.max(idx);
    }
    let mut txs = vec![Vec::new(); indexes.len()];
    for tx_index in 0..=max_index {
        let consumed = parse_tx(&block[offset..])
            .map_err(|_| invalid_data("stored block transaction is non-canonical"))?
            .3;
        if consumed == 0 {
            return Err(invalid_data("stored block transaction is non-canonical"));
        }
        let end = offset
            .checked_add(consumed)
            .filter(|&end| end <= block.len())
            .ok_or_else(|| invalid_data("stored block transaction is non-canonical"))?;
        if let Some(&pos) = positions.get(&tx_index) {
            txs[pos] = block[offset..end].to_vec();
        }
        offset = end;
    }
    if max_index == tx_count - 1 && offset != block.len() {
        return Err(invalid_data(
            "stored block has trailing bytes after transactions",
        ));
    }
    Ok(txs)
}

fn compact_block_transaction_count(block: &[u8]) -> io::Result<(u64, usize)> {
    if block.len() < BLOCK_HEADER_BYTES {
        return Err(invalid_data("stored block missing header"));
    }
    let (tx_count, count_len) = read_compact_size_bytes(&block[BLOCK_HEADER_BYTES..])
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    Ok((tx_count, BLOCK_HEADER_BYTES + count_len))
}

fn compact_fill_response_transactions(
    req: &CompactOutstandingRequest,
    response: BlockTxnPayload,
) -> io::Result<Vec<Vec<u8>>> {
    if response.transactions.len() != req.missing_indexes.len() {
        return Err(invalid_data("blocktxn transaction count mismatch"));
    }
    let mut txs = req.partial_transactions.clone();
    for ((&index, want_short_id), tx) in req
        .missing_indexes
        .iter()
        .zip(&req.missing_short_ids)
        .zip(&response.transactions)
    {
        let slot = txs
            .get_mut(index as usize)
            .ok_or_else(|| invalid_data("blocktxn transaction index out of range"))?;
        if slot.is_some() {
            return Err(invalid_data(
                "blocktxn transaction duplicates prefilled slot",
            ));
        }
        let (_, _, wtxid, consumed) =
            parse_tx(tx).map_err(|_| invalid_data("blocktxn transaction is non-canonical"))?;
        if consumed != tx.len() {
            return Err(invalid_data("blocktxn transaction is non-canonical"));
        }
        if compact_shortid(wtxid, req.nonces[0], req.nonces[1]) != *want_short_id {
            return Err(invalid_data("blocktxn transaction short id mismatch"));
        }
        *slot = Some(tx.clone());
    }
    let txs = txs
        .into_iter()
        .map(|tx| tx.ok_or_else(|| invalid_data("compact block transaction missing")))
        .collect::<io::Result<Vec<_>>>()?;
    Ok(txs)
}
fn compact_block_bytes(header: [u8; BLOCK_HEADER_BYTES], txs: &[Vec<u8>]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(BLOCK_HEADER_BYTES + MAX_COMPACT_SIZE_BYTES);
    out.extend_from_slice(&header);
    encode_compact_size(txs.len() as u64, &mut out);
    let mut total_tx_bytes = 0u64;
    for tx in txs {
        total_tx_bytes = validate_blocktxn_transaction_size(tx.len() as u64, total_tx_bytes)?;
        if tx.len() > (MAX_BLOCK_BYTES as usize).saturating_sub(out.len()) {
            return Err(invalid_data("compact block exceeds block size"));
        }
        out.extend_from_slice(tx);
    }
    Ok(out)
}

fn compact_size_wire_len(n: u64) -> u64 {
    match n {
        0x00..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn invalid_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn marshal_empty_addr_payload() -> Vec<u8> {
    vec![0u8]
}

fn unmarshal_addr_payload(payload: &[u8]) -> io::Result<Vec<String>> {
    let (count, consumed) = decode_compact_size(payload)?;
    let count = usize::try_from(count)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "addr count overflow"))?;
    if count > MAX_ADDR_PAYLOAD_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "addr count exceeds limit",
        ));
    }
    let remaining = payload
        .len()
        .checked_sub(consumed)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "addr payload width mismatch"))?;
    if count > remaining / ADDR_PAYLOAD_ENTRY_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "addr payload width mismatch",
        ));
    }
    let needed = consumed
        .checked_add(count * ADDR_PAYLOAD_ENTRY_SIZE)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "addr payload length overflow")
        })?;
    if payload.len() != needed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "addr payload width mismatch",
        ));
    }
    let mut out = Vec::with_capacity(count);
    let mut offset = consumed;
    for _ in 0..count {
        let ip = std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(&payload[offset..offset + 16])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ip address"))?,
        );
        offset += 16;
        let port = u16::from_be_bytes(
            payload[offset..offset + 2]
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid port"))?,
        );
        offset += 2;
        out.push(std::net::SocketAddr::new(ip.into(), port).to_string());
    }
    Ok(out)
}

fn decode_compact_size(payload: &[u8]) -> io::Result<(u64, usize)> {
    let Some(first) = payload.first().copied() else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "compactsize truncated",
        ));
    };
    match first {
        0x00..=0xfc => Ok((u64::from(first), 1)),
        0xfd => {
            if payload.len() < 3 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "compactsize truncated",
                ));
            }
            Ok((u64::from(u16::from_le_bytes([payload[1], payload[2]])), 3))
        }
        0xfe => {
            if payload.len() < 5 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "compactsize truncated",
                ));
            }
            Ok((
                u64::from(u32::from_le_bytes(
                    payload[1..5].try_into().expect("u32 compactsize"),
                )),
                5,
            ))
        }
        0xff => {
            if payload.len() < 9 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "compactsize truncated",
                ));
            }
            Ok((
                u64::from_le_bytes(payload[1..9].try_into().expect("u64 compactsize")),
                9,
            ))
        }
    }
}

fn marshal_version_payload_v1(v: VersionPayloadV1) -> Vec<u8> {
    let mut payload = vec![0u8; VERSION_PAYLOAD_BYTES as usize];
    payload[0..4].copy_from_slice(&v.protocol_version.to_le_bytes());
    payload[4] = if v.tx_relay { 1 } else { 0 };
    payload[5..13].copy_from_slice(&v.pruned_below_height.to_le_bytes());
    payload[13..17].copy_from_slice(&v.da_mempool_size.to_le_bytes());
    payload[17..49].copy_from_slice(&v.chain_id);
    payload[49..81].copy_from_slice(&v.genesis_hash);
    payload[81..89].copy_from_slice(&v.best_height.to_le_bytes());
    payload
}

fn unmarshal_version_payload_v1(payload: &[u8]) -> io::Result<VersionPayloadV1> {
    if payload.len() != VERSION_PAYLOAD_BYTES as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            if payload.len() < VERSION_PAYLOAD_BYTES as usize {
                "version payload too short"
            } else {
                "trailing bytes in version payload"
            },
        ));
    }
    let protocol_version = u32::from_le_bytes(payload[0..4].try_into().expect("pv"));
    let tx_relay = payload[4] == 1;
    let pruned_below_height = u64::from_le_bytes(payload[5..13].try_into().expect("pruned"));
    let da_mempool_size = u32::from_le_bytes(payload[13..17].try_into().expect("da"));
    let mut chain_id = [0u8; 32];
    chain_id.copy_from_slice(&payload[17..49]);
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&payload[49..81]);
    let best_height = u64::from_le_bytes(payload[81..89].try_into().expect("best_height"));
    Ok(VersionPayloadV1 {
        protocol_version,
        tx_relay,
        pruned_below_height,
        da_mempool_size,
        chain_id,
        genesis_hash,
        best_height,
    })
}

pub fn build_envelope_header(
    magic: [u8; 4],
    command: &str,
    payload: &[u8],
) -> io::Result<[u8; WIRE_HEADER_SIZE]> {
    let command_bytes = encode_wire_command(command)?;
    let mut header = [0u8; WIRE_HEADER_SIZE];
    header[0..4].copy_from_slice(&magic);
    header[4..16].copy_from_slice(&command_bytes);
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "payload length overflow"))?;
    header[16..20].copy_from_slice(&len.to_le_bytes());
    let sum = wire_checksum(payload);
    header[20..24].copy_from_slice(&sum);
    Ok(header)
}

#[cfg(test)]
fn marshal_wire_message(
    msg: &WireMessage,
    magic: [u8; 4],
    max_message_size: u64,
) -> io::Result<Vec<u8>> {
    if msg.payload.len() as u64 > max_message_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message exceeds cap: {}", msg.payload.len()),
        ));
    }
    let header = build_envelope_header(magic, &msg.command, &msg.payload)?;
    let mut raw = Vec::with_capacity(WIRE_HEADER_SIZE + msg.payload.len());
    raw.extend_from_slice(&header);
    raw.extend_from_slice(&msg.payload);
    Ok(raw)
}

#[cfg(test)]
fn unmarshal_wire_message(
    raw: &[u8],
    expected_magic: [u8; 4],
    max_message_size: u64,
) -> io::Result<WireMessage> {
    if raw.len() < WIRE_HEADER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short envelope header",
        ));
    }
    let header = raw[..WIRE_HEADER_SIZE].try_into().expect("wire header");
    let envelope = parse_envelope_header(
        &header,
        expected_magic,
        max_message_size,
        &runtime_payload_cap,
    )?;
    let total_len = WIRE_HEADER_SIZE + envelope.payload_len;
    if raw.len() < total_len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short envelope payload",
        ));
    }
    let payload = raw[WIRE_HEADER_SIZE..total_len].to_vec();
    let checksum = wire_checksum(&payload);
    if envelope.checksum != checksum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid envelope checksum",
        ));
    }
    Ok(WireMessage {
        command: envelope.command,
        payload,
    })
}

struct ParsedEnvelopeHeader {
    command: String,
    payload_len: usize,
    checksum: [u8; 4],
}

fn parse_envelope_header(
    header: &[u8; WIRE_HEADER_SIZE],
    expected_magic: [u8; 4],
    max_message_size: u64,
    payload_cap: &dyn Fn(&str) -> u64,
) -> io::Result<ParsedEnvelopeHeader> {
    if header[0..4] != expected_magic {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid envelope magic",
        ));
    }
    let command = decode_wire_command(&header[4..4 + WIRE_COMMAND_SIZE])?;
    let payload_len = u32::from_le_bytes(header[16..20].try_into().expect("len"));
    if payload_len as u64 > max_message_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message exceeds cap",
        ));
    }
    if payload_len as u64 > payload_cap(&command) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message exceeds command cap",
        ));
    }
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&header[20..24]);
    Ok(ParsedEnvelopeHeader {
        command,
        payload_len: payload_len as usize,
        checksum,
    })
}

fn wire_checksum(payload: &[u8]) -> [u8; 4] {
    let mut h = Sha3_256::new();
    h.update(payload);
    let out = h.finalize();
    [out[0], out[1], out[2], out[3]]
}

fn encode_wire_command(command: &str) -> io::Result<[u8; WIRE_COMMAND_SIZE]> {
    let bytes = command.as_bytes();
    if bytes.is_empty() || bytes.len() > WIRE_COMMAND_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid command length",
        ));
    }
    for &ch in bytes {
        if !is_printable_ascii_byte(ch) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "command is not ASCII printable",
            ));
        }
    }
    let mut out = [0u8; WIRE_COMMAND_SIZE];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

fn decode_wire_command(raw: &[u8]) -> io::Result<String> {
    if raw.len() != WIRE_COMMAND_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid command width",
        ));
    }
    let mut end = WIRE_COMMAND_SIZE;
    for (i, &b) in raw.iter().enumerate() {
        if b == 0 {
            end = i;
            break;
        }
    }
    if end == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty command"));
    }
    for &b in &raw[end..] {
        if b != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid NUL padding in command",
            ));
        }
    }
    for &b in &raw[..end] {
        if !is_printable_ascii_byte(b) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "command is not ASCII printable",
            ));
        }
    }
    let s = std::str::from_utf8(&raw[..end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid command"))?;
    Ok(s.to_string())
}

fn is_printable_ascii_byte(ch: u8) -> bool {
    (0x21..=0x7e).contains(&ch)
}

fn normalize_peer_runtime_config(mut cfg: PeerRuntimeConfig) -> PeerRuntimeConfig {
    if cfg.max_peers == 0 {
        cfg.max_peers = 64;
    }
    if cfg.read_deadline == Duration::from_secs(0) {
        cfg.read_deadline = DEFAULT_READ_DEADLINE;
    }
    if cfg.write_deadline == Duration::from_secs(0) {
        cfg.write_deadline = DEFAULT_WRITE_DEADLINE;
    }
    if cfg.ban_threshold <= 0 {
        cfg.ban_threshold = DEFAULT_BAN_THRESHOLD;
    }
    cfg
}

fn runtime_payload_cap(command: &str) -> u64 {
    match command {
        "version" => VERSION_PAYLOAD_BYTES,
        "verack" | "ping" | "pong" | MESSAGE_GETADDR => 0,
        MESSAGE_SENDCMPCT => SENDCMPCT_PAYLOAD_BYTES,
        MESSAGE_INV | MESSAGE_GETDATA | MESSAGE_GETBLOCKS => MAX_INVENTORY_PAYLOAD_BYTES,
        MESSAGE_ADDR => MAX_ADDR_PAYLOAD_BYTES,
        MESSAGE_BLOCK | MESSAGE_TX => MAX_BLOCK_BYTES,
        "headers" => MAX_HEADERS_PAYLOAD_BYTES,
        _ => 0,
    }
}

fn parse_sendcmpct_runtime_payload(payload: &[u8]) -> io::Result<CompactModeSnapshot> {
    if payload.len() != SENDCMPCT_PAYLOAD_BYTES as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sendcmpct payload width mismatch",
        ));
    }
    let mut version = [0u8; 8];
    version.copy_from_slice(&payload[1..]);
    let out = CompactModeSnapshot {
        mode: payload[0],
        version: u64::from_le_bytes(version),
    };
    if out.version != COMPACT_RELAY_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported compact relay version",
        ));
    }
    if out.mode > 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported compact relay mode",
        ));
    }
    Ok(out)
}

fn pre_handshake_payload_cap(command: &str) -> u64 {
    match command {
        "version" => VERSION_PAYLOAD_BYTES,
        "verack" | "ping" | "pong" | MESSAGE_GETADDR | MESSAGE_ADDR => 0,
        _ => 0,
    }
}

fn global_orphan_byte_limit() -> usize {
    #[cfg(test)]
    {
        let override_limit = GLOBAL_ORPHAN_BYTE_LIMIT_OVERRIDE.load(Ordering::Relaxed);
        if override_limit > 0 {
            return override_limit;
        }
    }
    DEFAULT_GLOBAL_ORPHAN_BYTE_LIMIT
}

impl OrphanBlockPool {
    fn new(limit: usize, byte_limit: usize) -> Self {
        Self {
            limit,
            byte_limit,
            total_bytes: 0,
            pool: HashMap::new(),
            by_hash: HashMap::new(),
            fifo: std::collections::VecDeque::new(),
        }
    }

    fn add(
        &mut self,
        block_hash: [u8; 32],
        parent_hash: [u8; 32],
        block_bytes: &[u8],
        global_byte_limit: usize,
    ) {
        if self.by_hash.contains_key(&block_hash) {
            return;
        }
        if self.byte_limit > 0 && block_bytes.len() > self.byte_limit {
            return;
        }
        let block_size = block_bytes.len();
        loop {
            let current = GLOBAL_ORPHAN_TOTAL_BYTES.load(Ordering::Acquire);
            let Some(next) = current.checked_add(block_size) else {
                return;
            };
            if global_byte_limit > 0 && next > global_byte_limit {
                if !self.evict_oldest() {
                    return;
                }
                continue;
            }
            match GLOBAL_ORPHAN_TOTAL_BYTES.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
        let entry = OrphanBlockEntry {
            block_hash,
            parent_hash,
            block_bytes: block_bytes.to_vec(),
        };
        self.pool.entry(parent_hash).or_default().push(entry);
        self.by_hash.insert(
            block_hash,
            OrphanBlockMeta {
                parent_hash,
                size: block_bytes.len(),
            },
        );
        orphan_pool_metrics_add(1, block_bytes.len());
        self.total_bytes = self.total_bytes.saturating_add(block_bytes.len());
        self.fifo.push_back(block_hash);
        // Evict until under limits, but remove at least MIN_EVICT_BATCH entries
        // when over capacity to reduce thrashing under sustained pressure.
        let min_evict = if self.by_hash.len() > self.limit
            || (self.byte_limit > 0 && self.total_bytes > self.byte_limit)
        {
            (self.by_hash.len() / 10).max(1)
        } else {
            0
        };
        let mut evicted = 0;
        while evicted < min_evict
            || self.by_hash.len() > self.limit
            || (self.byte_limit > 0 && self.total_bytes > self.byte_limit)
        {
            if !self.evict_oldest() {
                break;
            }
            evicted += 1;
        }
    }

    fn take_children(&mut self, parent_hash: [u8; 32]) -> Vec<OrphanBlockEntry> {
        let children = self.pool.remove(&parent_hash).unwrap_or_default();
        if children.is_empty() {
            return children;
        }
        let removed: HashMap<[u8; 32], ()> = children
            .iter()
            .map(|child| (child.block_hash, ()))
            .collect();
        for child in &children {
            if let Some(meta) = self.by_hash.remove(&child.block_hash) {
                self.total_bytes = self.total_bytes.saturating_sub(meta.size);
                orphan_pool_metrics_sub(1, meta.size);
                GLOBAL_ORPHAN_TOTAL_BYTES.fetch_sub(meta.size, Ordering::AcqRel);
            }
        }
        self.fifo.retain(|hash| !removed.contains_key(hash));
        children
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_hash.len()
    }

    fn evict_oldest(&mut self) -> bool {
        while let Some(oldest) = self.fifo.pop_front() {
            let Some(meta) = self.by_hash.remove(&oldest) else {
                continue;
            };
            self.total_bytes = self.total_bytes.saturating_sub(meta.size);
            orphan_pool_metrics_sub(1, meta.size);
            GLOBAL_ORPHAN_TOTAL_BYTES.fetch_sub(meta.size, Ordering::AcqRel);
            let mut remove_parent = false;
            if let Some(children) = self.pool.get_mut(&meta.parent_hash) {
                if let Some(index) = children.iter().position(|child| child.block_hash == oldest) {
                    children.remove(index);
                }
                remove_parent = children.is_empty();
            }
            if remove_parent {
                self.pool.remove(&meta.parent_hash);
            }
            return true;
        }
        false
    }
}

impl Drop for OrphanBlockPool {
    fn drop(&mut self) {
        orphan_pool_metrics_sub(self.by_hash.len(), self.total_bytes);
        GLOBAL_ORPHAN_TOTAL_BYTES.fetch_sub(self.total_bytes, Ordering::AcqRel);
    }
}

fn is_parent_not_found_err(err: &str) -> bool {
    err == PARENT_BLOCK_NOT_FOUND_ERR
}

fn unknown_command_err(command: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unknown message type: {command}"),
    )
}

fn handshake_timeout_budget(read_deadline: Duration) -> Duration {
    read_deadline.min(DEFAULT_HANDSHAKE_TIMEOUT)
}

pub fn network_magic(network: &str) -> [u8; 4] {
    match network {
        "mainnet" => *b"RBMN",
        "testnet" => *b"RBTN",
        "devnet" | "" => *b"RBDV",
        _ => *b"RBOP",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::blockstore::BlockStore;
    use crate::chainstate::ChainState;
    use crate::coinbase::{build_coinbase_tx, default_mine_address};
    use crate::genesis::{devnet_genesis_block_bytes, devnet_genesis_chain_id};
    use crate::test_helpers::{
        block_with_txs, coinbase_only_block_with_gen, signed_conflicting_p2pk_state_and_txs,
    };
    use crate::TxPool;
    use rubin_consensus::constants::{MAX_FUTURE_DRIFT, POW_LIMIT};
    use rubin_consensus::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
    use rubin_consensus::{
        block_hash, encode_compact_size, merkle_root_txids, parse_block_bytes, parse_tx,
        BLOCK_HEADER_BYTES,
    };
    use serde::Deserialize;

    static NEXT_TEST_ROOT_ID: AtomicU64 = AtomicU64::new(1);

    #[expect(clippy::type_complexity)]
    #[rustfmt::skip]
    fn signed_conflicting_da_chunk_state_and_txs() -> (ChainState, Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32], [u8; 32], [u8; 32]) {
        let keypair = rubin_consensus::Mldsa87Keypair::generate().expect("OpenSSL signer"); let pubkey = keypair.pubkey_bytes(); let outpoint = rubin_consensus::Outpoint { txid: [0xA1; 32], vout: 0 }; let mut state = ChainState::new();
        state.utxos.insert(outpoint.clone(), rubin_consensus::UtxoEntry { value: 20_000, covenant_type: rubin_consensus::constants::COV_TYPE_P2PK, covenant_data: rubin_consensus::p2pk_covenant_data_for_pubkey(&pubkey), creation_height: 0, created_by_coinbase: false }); let utxos = state.utxos.clone();
        let build = |nonce: u64, da_id: [u8; 32], payload: &[u8], valid_hash: bool| { let mut tx = rubin_consensus::Tx { version: rubin_consensus::constants::TX_WIRE_VERSION, tx_kind: 0x02, tx_nonce: nonce, inputs: vec![rubin_consensus::TxInput { prev_txid: outpoint.txid, prev_vout: outpoint.vout, script_sig: Vec::new(), sequence: 0 }], outputs: vec![rubin_consensus::TxOutput { value: 10, covenant_type: rubin_consensus::constants::COV_TYPE_P2PK, covenant_data: rubin_consensus::p2pk_covenant_data_for_pubkey(&vec![nonce as u8; 2592]) }], locktime: 0, da_commit_core: None, da_chunk_core: Some(rubin_consensus::DaChunkCore { da_id, chunk_index: 0, chunk_hash: if valid_hash { Sha3_256::digest(payload).into() } else { [0xE1; 32] } }), witness: Vec::new(), da_payload: payload.to_vec() }; rubin_consensus::sign_transaction(&mut tx, &utxos, devnet_genesis_chain_id(), &keypair).expect("sign DA chunk tx"); rubin_consensus::marshal_tx(&tx).expect("marshal DA chunk tx") };
        let admitted_da_id = [0xD1; 32]; let conflicting_da_id = [0xD2; 32]; let bad_da_id = [0xD3; 32]; let admitted = build(7, admitted_da_id, b"admitted da chunk", true); let conflicting = build(8, conflicting_da_id, b"conflicting da chunk", true); let bad = build(9, bad_da_id, b"bad da chunk", false); (state, admitted, conflicting, bad, admitted_da_id, conflicting_da_id, bad_da_id)
    }

    #[derive(Deserialize)]
    struct SharedRuntimeVectors {
        version_payload_v1: SharedVersionPayloadV1,
        frames: Vec<SharedFrameVector>,
        version_validation: Vec<SharedVersionValidation>,
    }

    #[derive(Deserialize)]
    struct SharedVersionPayloadV1 {
        hex: String,
        protocol_version: u32,
        tx_relay: bool,
        pruned_below_height: u64,
        da_mempool_size: u32,
        chain_id_hex: String,
        genesis_hash_hex: String,
        best_height: u64,
    }

    #[derive(Deserialize)]
    struct SharedFrameVector {
        id: String,
        network: String,
        max_message_size: u64,
        hex: String,
        expect_command: Option<String>,
        expect_payload_hex: Option<String>,
        expect_err: Option<String>,
    }

    #[derive(Deserialize)]
    struct SharedVersionValidation {
        id: String,
        local_protocol_version: u32,
        remote_protocol_version: u32,
        tx_relay: bool,
        pruned_below_height: u64,
        da_mempool_size: u32,
        chain_id_hex: String,
        genesis_hash_hex: String,
        best_height: u64,
        #[serde(default)]
        expect_ok: bool,
        #[serde(default)]
        expect_err: Option<String>,
    }

    fn test_version_payload(best_height: u64) -> VersionPayloadV1 {
        let genesis_bytes = devnet_genesis_block_bytes();
        let genesis_hash = block_hash(&genesis_bytes[..116]).expect("genesis hash");
        VersionPayloadV1 {
            protocol_version: 1,
            tx_relay: true,
            pruned_below_height: 0,
            da_mempool_size: 0,
            chain_id: devnet_genesis_chain_id(),
            genesis_hash,
            best_height,
        }
    }

    fn load_shared_runtime_vectors() -> SharedRuntimeVectors {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../../p2p/testdata/runtime_vectors.json");
        let raw = fs::read_to_string(&path).expect("read runtime_vectors.json");
        serde_json::from_str(&raw).expect("parse runtime_vectors.json")
    }

    fn decode_hex32(raw: &str) -> [u8; 32] {
        let bytes = hex::decode(raw).expect("hex32");
        assert_eq!(bytes.len(), 32, "hex32 len");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn shared_version_payload(v: &SharedVersionPayloadV1) -> VersionPayloadV1 {
        VersionPayloadV1 {
            protocol_version: v.protocol_version,
            tx_relay: v.tx_relay,
            pruned_below_height: v.pruned_below_height,
            da_mempool_size: v.da_mempool_size,
            chain_id: decode_hex32(&v.chain_id_hex),
            genesis_hash: decode_hex32(&v.genesis_hash_hex),
            best_height: v.best_height,
        }
    }

    fn test_sync_engine_with_genesis() -> SyncEngine {
        let unique = NEXT_TEST_ROOT_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("rubin-node-p2p-runtime-{unique}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create temp dir");
        let blockstore_dir = root.join("blockstore");
        let chainstate_path = root.join("chainstate.json");
        let block_store = BlockStore::open(&blockstore_dir).expect("open blockstore");
        let mut engine = SyncEngine::new(
            ChainState::new(),
            Some(block_store),
            crate::sync::default_sync_config(
                Some(rubin_consensus::constants::POW_LIMIT),
                devnet_genesis_chain_id(),
                Some(chainstate_path),
            ),
        )
        .expect("new sync engine");
        engine
            .apply_block(&devnet_genesis_block_bytes(), None)
            .expect("apply genesis");
        engine
    }

    fn sendcmpct_runtime_payload(mode: u8, version: u64) -> Vec<u8> {
        let mut payload = vec![0u8; SENDCMPCT_PAYLOAD_BYTES as usize];
        payload[0] = mode;
        payload[1..].copy_from_slice(&version.to_le_bytes());
        payload
    }

    fn test_peer_session() -> (PeerSession, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let (stream, _) = listener.accept().expect("accept");
        let mut cfg = default_peer_runtime_config("devnet", 8);
        cfg.enable_compact_receive = true;
        let mut session = PeerSession::new(stream, cfg).expect("session");
        session.remote_compact_mode = CompactModeSnapshot {
            mode: 1,
            version: COMPACT_RELAY_VERSION,
        };
        (session, client)
    }

    #[test]
    fn getblocktxn_payload_codec_matches_go_wire() {
        let mut block_hash = [0u8; 32];
        block_hash[..3].copy_from_slice(&[1, 2, 3]);
        let high_index = (MAX_COMPACT_RELAY_ENTRIES as u64) + 2;
        let payload = GetBlockTxnPayload {
            block_hash,
            indexes: vec![0, high_index, MAX_COMPACT_RELAY_ENTRIES as u64],
        };

        let encoded = encode_getblocktxn_payload(payload.clone()).expect("encode getblocktxn");
        let mut want = block_hash.to_vec();
        encode_compact_size(3, &mut want);
        for idx in [0_u32, high_index as u32, MAX_COMPACT_RELAY_ENTRIES as u32] {
            want.extend_from_slice(&idx.to_le_bytes());
        }
        assert_eq!(encoded, want);
        assert_eq!(
            decode_getblocktxn_payload(&encoded).expect("decode getblocktxn"),
            payload
        );
    }

    fn assert_getblocktxn_decode_err(raw: Vec<u8>, want_err: &str) {
        let err = decode_getblocktxn_payload(&raw)
            .err()
            .unwrap_or_else(|| panic!("decode unexpectedly succeeded"));
        assert!(
            err.to_string().contains(want_err),
            "got {err}, want substring {want_err}"
        );
    }

    fn assert_getblocktxn_encode_err(payload: GetBlockTxnPayload, want_err: &str) {
        let err = encode_getblocktxn_payload(payload)
            .err()
            .unwrap_or_else(|| panic!("encode unexpectedly succeeded"));
        assert!(
            err.to_string().contains(want_err),
            "got {err}, want substring {want_err}"
        );
    }

    #[test]
    fn getblocktxn_decode_rejects_invalid_wire() {
        let block_hash = [7u8; 32];

        assert_getblocktxn_decode_err(vec![0u8; 31], "getblocktxn payload missing block hash");
        assert_getblocktxn_decode_err(block_hash.to_vec(), "unexpected EOF (u8)");

        let mut too_many = block_hash.to_vec();
        encode_compact_size((MAX_COMPACT_RELAY_ENTRIES as u64) + 1, &mut too_many);
        assert_getblocktxn_decode_err(too_many, "too many compact relay indexes");

        let mut non_minimal_count = block_hash.to_vec();
        non_minimal_count.extend_from_slice(&[0xfd, 1, 0, 0, 0, 0, 0]);
        assert_getblocktxn_decode_err(non_minimal_count, "non-minimal CompactSize");

        let mut truncated_index = block_hash.to_vec();
        truncated_index.push(1);
        truncated_index.extend_from_slice(&[0, 0, 0]);
        assert_getblocktxn_decode_err(truncated_index, "getblocktxn payload truncated index");

        let mut trailing_bytes = block_hash.to_vec();
        trailing_bytes.push(0);
        trailing_bytes.push(1);
        assert_getblocktxn_decode_err(trailing_bytes, "getblocktxn payload has trailing bytes");

        let mut index_out_of_range = block_hash.to_vec();
        index_out_of_range.push(1);
        index_out_of_range
            .extend_from_slice(&((MAX_COMPACT_RELAY_INDEX_VALUE + 1) as u32).to_le_bytes());
        assert_getblocktxn_decode_err(index_out_of_range, "compact relay index out of range");
    }

    #[test]
    fn getblocktxn_encode_rejects_bounds() {
        let block_hash = [9u8; 32];
        assert_getblocktxn_encode_err(
            GetBlockTxnPayload {
                block_hash,
                indexes: vec![0; MAX_COMPACT_RELAY_ENTRIES + 1],
            },
            "too many compact relay indexes",
        );
        assert_getblocktxn_encode_err(
            GetBlockTxnPayload {
                block_hash,
                indexes: vec![MAX_COMPACT_RELAY_INDEX_VALUE + 1],
            },
            "compact relay index out of range",
        );
    }

    const DA_ERR_VERSION: &str = "unsupported DA chunk request version";
    const DA_ERR_COUNT: &str = "invalid DA chunk request index count";
    const DA_ERR_ORDER: &str = "DA chunk request indexes not strictly increasing";
    const DA_ERR_RANGE: &str = "DA chunk request index out of range";

    fn getdachunk_request(version: u64, indexes: Vec<u16>) -> GetDAChunkPayload {
        GetDAChunkPayload {
            version,
            da_id: [0xaau8; 32],
            indexes,
        }
    }

    fn getdachunk_payload_with_tail(version: u64, tail: &[u8]) -> Vec<u8> {
        let mut out = version.to_le_bytes().to_vec();
        out.extend_from_slice(&[0xaau8; 32]);
        out.extend_from_slice(tail);
        out
    }

    fn getdachunk_indexed_payload(indexes: &[u16]) -> Vec<u8> {
        let mut tail = Vec::new();
        encode_compact_size(indexes.len() as u64, &mut tail);
        indexes
            .iter()
            .for_each(|idx| tail.extend_from_slice(&idx.to_le_bytes()));
        getdachunk_payload_with_tail(DA_CHUNK_REQUEST_VERSION, &tail)
    }

    #[test]
    fn getdachunk_payload_codec_matches_go_wire() {
        let indexes = vec![0, 2, (MAX_DA_CHUNK_COUNT - 1) as u16];
        let payload = getdachunk_request(DA_CHUNK_REQUEST_VERSION, indexes.clone());

        let encoded = encode_getdachunk_payload(payload.clone()).expect("encode getdachunk");
        assert_eq!(encoded, getdachunk_indexed_payload(&indexes));
        assert_eq!(
            decode_getdachunk_payload(&encoded).expect("decode getdachunk"),
            payload
        );
    }

    #[test]
    fn getdachunk_encode_rejects_invalid_requests() {
        let range_index = MAX_DA_CHUNK_COUNT as u16;
        let too_many = vec![0; (MAX_DA_CHUNK_COUNT + 1) as usize];
        for (version, indexes, want) in [
            (DA_CHUNK_REQUEST_VERSION + 1, vec![0], DA_ERR_VERSION),
            (DA_CHUNK_REQUEST_VERSION, Vec::new(), DA_ERR_COUNT),
            (DA_CHUNK_REQUEST_VERSION, too_many, DA_ERR_COUNT),
            (DA_CHUNK_REQUEST_VERSION, vec![2, 1], DA_ERR_ORDER),
            (DA_CHUNK_REQUEST_VERSION, vec![1, 1], DA_ERR_ORDER),
            (DA_CHUNK_REQUEST_VERSION, vec![range_index], DA_ERR_RANGE),
        ] {
            let payload = getdachunk_request(version, indexes);
            let err = encode_getdachunk_payload(payload).expect_err("encode must reject");
            assert!(err.to_string().contains(want), "{err}");
        }
    }

    #[test]
    fn getdachunk_decode_rejects_invalid_wire() {
        let range_index = MAX_DA_CHUNK_COUNT as u16;
        let mut too_many = Vec::new();
        encode_compact_size(MAX_DA_CHUNK_COUNT + 1, &mut too_many);
        let payload = |tail: &[u8]| getdachunk_payload_with_tail(DA_CHUNK_REQUEST_VERSION, tail);
        let bad_version = getdachunk_payload_with_tail(DA_CHUNK_REQUEST_VERSION + 1, &[1, 0, 0]);
        let short_prefix = vec![0u8; GETDACHUNK_PAYLOAD_PREFIX_BYTES - 1];
        let mut trailing = getdachunk_indexed_payload(&[0]);
        trailing.push(0);

        for (raw, want) in [
            (short_prefix, "getdachunk payload missing version or da_id"),
            (bad_version, DA_ERR_VERSION),
            (payload(&[0xfd, 0, 0]), "non-minimal CompactSize"),
            (payload(&[0]), DA_ERR_COUNT),
            (payload(&too_many), DA_ERR_COUNT),
            (payload(&[1, 0x01]), "getdachunk payload truncated index"),
            (getdachunk_indexed_payload(&[2, 1]), DA_ERR_ORDER),
            (getdachunk_indexed_payload(&[1, 1]), DA_ERR_ORDER),
            (getdachunk_indexed_payload(&[range_index]), DA_ERR_RANGE),
            (trailing, "getdachunk payload has trailing bytes"),
        ] {
            let err = decode_getdachunk_payload(&raw).expect_err("decode must reject");
            assert!(err.to_string().contains(want), "{err}");
        }
    }

    #[test]
    fn getblocktxn_serves_announced_block_in_request_order() {
        let (mut session, _client) = test_peer_session();
        let mut engine = test_sync_engine_with_genesis();
        let block = devnet_genesis_block_bytes();
        let block_hash = block_hash(&block[..BLOCK_HEADER_BYTES]).expect("genesis hash");
        let want_txs = compact_block_transactions_by_index(&block, &[0]).expect("expected tx");
        let mut header = [0u8; BLOCK_HEADER_BYTES];
        header.copy_from_slice(&block[..BLOCK_HEADER_BYTES]);
        session
            .write_message(&WireMessage {
                command: "cmpctblock".to_string(),
                payload: encode_cmpctblock_payload(CmpctBlockPayload {
                    header,
                    nonce1: 0,
                    nonce2: 0,
                    short_ids: Vec::new(),
                    prefilled: vec![PrefilledTxn {
                        index: 0,
                        tx: want_txs[0].clone(),
                    }],
                })
                .expect("encode cmpctblock"),
            })
            .expect("write cmpctblock announcement");
        let request = encode_getblocktxn_payload(GetBlockTxnPayload {
            block_hash,
            indexes: vec![0],
        })
        .expect("encode getblocktxn");

        let outcome = session
            .collect_live_responses(
                WireMessage {
                    command: MESSAGE_GETBLOCKTXN.to_string(),
                    payload: request,
                },
                &mut engine,
                None,
            )
            .expect("serve getblocktxn");

        assert_eq!(outcome.responses.len(), 1);
        assert_eq!(outcome.responses[0].command, MESSAGE_BLOCKTXN);
        let got = decode_blocktxn_payload(&outcome.responses[0].payload).expect("blocktxn");
        assert_eq!(got.block_hash, block_hash);
        assert_eq!(got.transactions, want_txs);
    }

    #[test]
    fn getblocktxn_rejects_disabled_duplicate_and_unannounced() {
        let (mut session, _client) = test_peer_session();
        let engine = test_sync_engine_with_genesis();
        let request = |block_hash, indexes| {
            encode_getblocktxn_payload(GetBlockTxnPayload {
                block_hash,
                indexes,
            })
            .expect("encode getblocktxn")
        };

        session.cfg.enable_compact_receive = false;
        let err = session
            .handle_getblocktxn(&request([0x33; 32], vec![0]), &engine)
            .expect_err("disabled compact receive must reject getblocktxn");
        assert!(err.to_string().contains("compact receive disabled"));
        assert_eq!(session.peer.ban_score, 0);

        session.cfg.enable_compact_receive = true;
        let err = session
            .handle_getblocktxn(&request([0x42; 32], vec![0, 0]), &engine)
            .expect_err("duplicate getblocktxn must fail");
        assert!(err.to_string().contains("duplicate getblocktxn index"));
        assert!(session.peer.ban_score > 0);

        session.peer.ban_score = 0;
        let bad_hash = block_hash(&[0u8; BLOCK_HEADER_BYTES]).expect("bad cmpctblock hash");
        assert_cmpctblock_err(
            session.write_message(&WireMessage {
                command: "cmpctblock".to_string(),
                payload: vec![0u8; BLOCK_HEADER_BYTES],
            }),
            "cmpctblock payload missing header or nonce",
        );
        assert!(session.compact_announced.is_empty());
        let outcome = session
            .handle_getblocktxn(&request(bad_hash, vec![0]), &engine)
            .expect("unannounced getblocktxn");
        assert!(outcome.responses.is_empty());
        assert_eq!(session.peer.ban_score, 0);
        assert_eq!(
            session.peer.last_error,
            "ignored unannounced getblocktxn request"
        );
    }

    #[test]
    fn getblocktxn_block_slice_preserves_request_order() {
        let genesis = devnet_genesis_block_bytes();
        let mut block = genesis[..BLOCK_HEADER_BYTES].to_vec();
        encode_compact_size(1, &mut block);
        block.push(0xff);
        let err = compact_block_transactions_by_index(&block, &[1])
            .expect_err("out-of-range getblocktxn must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("getblocktxn index out of range"));

        let txs = vec![
            minimal_blocktxn_test_tx_bytes(301),
            minimal_blocktxn_test_tx_bytes(302),
            minimal_blocktxn_test_tx_bytes(303),
        ];
        let block = build_block_bytes([0u8; 32], [1u8; 32], POW_LIMIT, 0, &txs);

        let got = compact_block_transactions_by_index(&block, &[2, 0, 1]).expect("slice block txs");

        assert_eq!(got, vec![txs[2].clone(), txs[0].clone(), txs[1].clone()]);
        assert_blocktxn_err(
            validate_blocktxn_transaction_size(MAX_BLOCK_BYTES + 1, 0),
            "blocktxn transaction too large",
        );
    }

    #[test]
    fn getblocktxn_cmpctblock_hash_fastpath_avoids_tx_parse() {
        let mut header = [0u8; BLOCK_HEADER_BYTES];
        header[..3].copy_from_slice(&[7, 8, 9]);
        let mut payload = header.to_vec();
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.extend_from_slice(&2u64.to_le_bytes());
        encode_compact_size(0, &mut payload);
        encode_compact_size(1, &mut payload);
        payload.extend_from_slice(&0u32.to_le_bytes());
        encode_compact_size(1, &mut payload);
        payload.push(0xff);

        assert_cmpctblock_err(
            decode_cmpctblock_payload(&payload),
            "cmpctblock prefilled transaction is non-canonical",
        );
        assert_eq!(
            compact_block_hash_from_payload(&payload).expect("structural hash"),
            block_hash(&header).expect("expected hash")
        );

        for (tail, want_err) in [
            (&[0xfd, 0, 0][..], "non-minimal CompactSize"),
            (&[1, 1, 2][..], "cmpctblock payload truncated short IDs"),
            (&[0, 0][..], "invalid compact relay entry count"),
            (&[0, 0xfd, 0, 0][..], "non-minimal CompactSize"),
            (&[0, 1, 1, 0, 0, 0][..], "compact relay index out of range"),
            (
                &[1, 0, 0, 0, 0, 0, 0, 0, 0][..],
                "cmpctblock payload has trailing bytes",
            ),
        ] {
            assert_cmpctblock_err(
                compact_block_hash_from_payload(&cmpctblock_test_payload(tail)),
                want_err,
            );
        }

        let valid_tx = minimal_blocktxn_test_tx_bytes(12);
        let mut truncated_tx = Vec::new();
        encode_compact_size((valid_tx.len() + 1) as u64, &mut truncated_tx);
        truncated_tx.extend_from_slice(&valid_tx);
        assert_cmpctblock_err(
            compact_block_hash_from_payload(&cmpctblock_test_payload(&cmpctblock_prefilled_tail(
                0,
                &truncated_tx,
            ))),
            "compact relay transaction truncated",
        );
        assert_cmpctblock_err(
            compact_block_hash_from_payload(&cmpctblock_test_payload(&cmpctblock_prefilled_tail(
                0,
                &[0],
            ))),
            "blocktxn transaction is empty",
        );
    }

    #[test]
    fn blocktxn_payload_codec_matches_go_wire() {
        let tx1 = minimal_blocktxn_test_tx_bytes(1);
        let block_hash = [4u8; 32];
        let payload = BlockTxnPayload {
            block_hash,
            transactions: vec![tx1.clone()],
        };

        let encoded = encode_blocktxn_payload(payload.clone()).expect("encode blocktxn");
        let mut want = block_hash.to_vec();
        encode_compact_size(1, &mut want);
        encode_compact_size(tx1.len() as u64, &mut want);
        want.extend_from_slice(&tx1);
        assert_eq!(encoded, want);
        assert_eq!(
            decode_blocktxn_payload(&encoded).expect("decode blocktxn"),
            payload
        );
    }

    fn assert_blocktxn_err<T: std::fmt::Debug>(got: io::Result<T>, want_err: &str) {
        let err = got
            .expect_err("operation unexpectedly succeeded")
            .to_string();
        assert!(err.contains(want_err), "got {err}, want {want_err}");
    }

    #[test]
    fn blocktxn_rejects_malformed_and_capped_inputs() {
        let block_hash = [7u8; 32];
        let valid_tx = minimal_blocktxn_test_tx_bytes(5);
        let mut non_minimal_count = block_hash.to_vec();
        non_minimal_count.extend_from_slice(&[0xfd, 0, 0]);
        let mut too_many = block_hash.to_vec();
        encode_compact_size((MAX_COMPACT_RELAY_ENTRIES as u64) + 1, &mut too_many);
        let mut empty_tx = block_hash.to_vec();
        empty_tx.extend_from_slice(&[1, 0]);
        let mut raw_concatenated = block_hash.to_vec();
        encode_compact_size(2, &mut raw_concatenated);
        raw_concatenated.extend_from_slice(&valid_tx);
        let mut trailing = block_hash.to_vec();
        trailing.extend_from_slice(&[0, 0]);
        for (raw, want) in [
            (non_minimal_count, "non-minimal CompactSize"),
            (too_many, "too many compact relay transactions"),
            (empty_tx, "blocktxn transaction is empty"),
            (raw_concatenated, "blocktxn transaction is non-canonical"),
            (trailing, "blocktxn payload has trailing bytes"),
        ] {
            assert_blocktxn_err(decode_blocktxn_payload(&raw), want);
        }

        let mut valid_with_trailing = minimal_blocktxn_test_tx_bytes(3);
        valid_with_trailing.push(0);
        assert_blocktxn_err(
            encode_blocktxn_payload(BlockTxnPayload {
                block_hash,
                transactions: vec![valid_with_trailing],
            }),
            "blocktxn transaction is non-canonical",
        );
        assert_blocktxn_err(
            validate_blocktxn_transaction_size(MAX_BLOCK_BYTES + 1, 0),
            "blocktxn transaction too large",
        );
        assert_blocktxn_err(
            validate_blocktxn_transaction_size(1, MAX_BLOCK_BYTES),
            "blocktxn transactions exceed block size",
        );
    }

    #[test]
    fn cmpctblock_payload_codec_matches_go_wire() {
        let tx = minimal_blocktxn_test_tx_bytes(10);
        let mut header = [0u8; BLOCK_HEADER_BYTES];
        header[..3].copy_from_slice(&[1, 2, 3]);
        let payload = CmpctBlockPayload {
            header,
            nonce1: 0x1122_3344_5566_7788,
            nonce2: 0x8877_6655_4433_2211,
            short_ids: vec![[1, 2, 3, 4, 5, 6]],
            prefilled: vec![PrefilledTxn {
                index: 1,
                tx: tx.clone(),
            }],
        };
        let encoded = encode_cmpctblock_payload(payload.clone()).expect("encode cmpctblock");
        let nonce1 = payload.nonce1.to_le_bytes();
        let nonce2 = payload.nonce2.to_le_bytes();
        let fixed = [1, 1, 2, 3, 4, 5, 6, 1, 1, 0, 0, 0, tx.len() as u8];
        let want = [header.as_slice(), &nonce1, &nonce2, &fixed, tx.as_slice()].concat();
        assert_eq!(encoded, want);
        assert_eq!(
            decode_cmpctblock_payload(&encoded).expect("decode cmpctblock"),
            payload
        );

        let short_ids = vec![[0u8; COMPACT_SHORT_ID_BYTES]; MAX_COMPACT_RELAY_ENTRIES + 1];
        let raw = encode_cmpctblock_payload(cmpctblock_test_value(short_ids.clone(), Vec::new()))
            .expect("encode cmpctblock above inventory vector limit");
        assert_eq!(
            decode_cmpctblock_payload(&raw)
                .expect("decode cmpctblock above inventory vector limit")
                .short_ids,
            short_ids
        );

        let tx_len = 1024usize;
        let mut tx_count =
            ((MAX_BLOCK_BYTES as usize) - BLOCK_HEADER_BYTES - MAX_COMPACT_SIZE_BYTES) / tx_len;
        while compact_full_block_len_for_test(tx_count + 1, tx_len) <= MAX_BLOCK_BYTES {
            tx_count += 1;
        }
        while compact_full_block_len_for_test(tx_count, tx_len) > MAX_BLOCK_BYTES {
            tx_count -= 1;
        }
        let prefilled: Vec<PrefilledTxn> = (0..tx_count)
            .map(|index| PrefilledTxn {
                index: index as u64,
                tx: vec![0u8; tx_len],
            })
            .collect();
        let compact_len =
            cmpctblock_payload_byte_len(0, &prefilled).expect("all-prefilled cmpctblock length");
        assert!(
            compact_len > MAX_BLOCK_BYTES,
            "all-prefilled cmpctblock len={compact_len}, want above MAX_BLOCK_BYTES={MAX_BLOCK_BYTES}"
        );
        assert!(
            compact_len <= MAX_RELAY_MSG_BYTES,
            "all-prefilled cmpctblock len={compact_len}, want below MAX_RELAY_MSG_BYTES={MAX_RELAY_MSG_BYTES}"
        );
    }

    #[test]
    fn cmpctblock_payload_rejects_malformed_and_capped_inputs() {
        let valid_tx = minimal_blocktxn_test_tx_bytes(12);
        assert_cmpctblock_err(
            decode_cmpctblock_payload(&[0u8; BLOCK_HEADER_BYTES + 15]),
            "cmpctblock payload missing header or nonce",
        );
        assert_cmpctblock_err(
            cmpctblock_payload_byte_len(0, &[]),
            "invalid compact relay entry count",
        );
        assert_cmpctblock_err(
            encode_cmpctblock_payload(cmpctblock_test_value(
                Vec::new(),
                vec![PrefilledTxn {
                    index: 0,
                    tx: Vec::new(),
                }],
            )),
            "blocktxn transaction is empty",
        );
        assert_cmpctblock_err(
            encode_cmpctblock_payload(cmpctblock_test_value(
                Vec::new(),
                vec![PrefilledTxn {
                    index: 1,
                    tx: valid_tx.clone(),
                }],
            )),
            "compact relay index out of range",
        );
        assert_cmpctblock_err(
            encode_cmpctblock_payload(cmpctblock_test_value(
                Vec::new(),
                vec![PrefilledTxn {
                    index: MAX_COMPACT_RELAY_INDEX_VALUE + 1,
                    tx: valid_tx.clone(),
                }],
            )),
            "compact relay index out of range",
        );
        assert_cmpctblock_decode_err(
            &vec![0u8; (MAX_RELAY_MSG_BYTES as usize) + 1],
            "cmpctblock payload too large",
        );
        assert_cmpctblock_decode_err(&[0xfd, 0, 0], "non-minimal CompactSize");
        assert_cmpctblock_decode_err(&[1, 1, 2], "cmpctblock payload truncated short IDs");
        assert_cmpctblock_decode_err(&[0, 1, 1, 0, 0, 0], "compact relay index out of range");
        assert_cmpctblock_decode_err(
            &[1, 0, 0, 0, 0, 0, 0, 0, 0],
            "cmpctblock payload has trailing bytes",
        );
        assert_cmpctblock_decode_err(&[0, 0], "invalid compact relay entry count");
        assert_cmpctblock_decode_err(&[0, 0xfd, 0, 0], "non-minimal CompactSize");

        let mut huge_prefilled = vec![0];
        encode_compact_size(MAX_BLOCK_BYTES, &mut huge_prefilled);
        assert_cmpctblock_decode_err(
            &huge_prefilled,
            "cmpctblock payload truncated prefilled index",
        );
        assert_cmpctblock_decode_err(
            &[0, 1, 1, 2],
            "cmpctblock payload truncated prefilled index",
        );

        let mut truncated_tx = Vec::new();
        encode_compact_size((valid_tx.len() + 1) as u64, &mut truncated_tx);
        truncated_tx.extend_from_slice(&valid_tx);
        assert_cmpctblock_decode_err(
            &cmpctblock_prefilled_tail(0, &truncated_tx),
            "compact relay transaction truncated",
        );
        let mut non_canonical_tx = valid_tx.clone();
        non_canonical_tx.push(0);
        assert_cmpctblock_decode_err(
            &cmpctblock_prefilled_tail(0, &cmpctblock_tx_envelope(&non_canonical_tx)),
            "cmpctblock prefilled transaction is non-canonical",
        );

        let tx_envelope = cmpctblock_tx_envelope(&valid_tx);
        let mut duplicate = Vec::new();
        encode_compact_size(0, &mut duplicate);
        encode_compact_size(2, &mut duplicate);
        duplicate.extend_from_slice(&0u32.to_le_bytes());
        duplicate.extend_from_slice(&tx_envelope);
        duplicate.extend_from_slice(&0u32.to_le_bytes());
        duplicate.extend_from_slice(&tx_envelope);
        assert_cmpctblock_decode_err(&duplicate, "compact relay index out of range");
        assert_cmpctblock_decode_err(
            &cmpctblock_prefilled_tail(1, &[]),
            "compact relay index out of range",
        );

        assert_cmpctblock_err(
            encode_cmpctblock_payload(cmpctblock_test_value(
                Vec::new(),
                vec![
                    PrefilledTxn {
                        index: 1,
                        tx: valid_tx.clone(),
                    },
                    PrefilledTxn {
                        index: 1,
                        tx: valid_tx.clone(),
                    },
                ],
            )),
            "compact relay index",
        );
        let mut non_canonical_tx = valid_tx.clone();
        non_canonical_tx.push(0);
        assert_cmpctblock_err(
            encode_cmpctblock_payload(cmpctblock_test_value(
                Vec::new(),
                vec![PrefilledTxn {
                    index: 0,
                    tx: non_canonical_tx.clone(),
                }],
            )),
            "cmpctblock prefilled transaction is non-canonical",
        );
        assert_cmpctblock_err(
            encode_cmpctblock_payload(cmpctblock_test_value(
                Vec::new(),
                vec![
                    PrefilledTxn {
                        index: 0,
                        tx: non_canonical_tx,
                    },
                    PrefilledTxn {
                        index: 1,
                        tx: valid_tx,
                    },
                ],
            )),
            "cmpctblock prefilled transaction is non-canonical",
        );
    }

    #[test]
    fn compact_reconstruct_go_parity_matrix() {
        let prefilled = minimal_blocktxn_test_tx_bytes(101);
        let tx2 = minimal_blocktxn_test_tx_bytes(102);
        let tx3 = minimal_blocktxn_test_tx_bytes(103);
        let full = cmpctblock_test_value(
            vec![
                compact_reconstruct_short_id_for_tx(&tx2),
                compact_reconstruct_short_id_for_tx(&tx3),
            ],
            vec![compact_reconstruct_prefilled(0, prefilled.clone())],
        );
        assert_eq!(
            reconstruct_compact_block(&full, &[tx3.clone(), tx2.clone()])
                .expect("complete")
                .transactions,
            vec![prefilled.clone(), tx2, tx3]
        );

        let missing_payload =
            cmpctblock_test_value(vec![[0x99; COMPACT_SHORT_ID_BYTES]], Vec::new());
        assert_reconstruct_missing(&missing_payload, &[], &[0]);
        let local = minimal_blocktxn_test_tx_bytes(122);
        let short_id = compact_reconstruct_short_id_for_tx(&local);
        let base = cmpctblock_test_value(
            vec![short_id],
            vec![compact_reconstruct_prefilled(0, prefilled.clone())],
        );
        let mut duplicate_payload = base.clone();
        duplicate_payload.short_ids.push(short_id);
        assert_reconstruct_missing(&duplicate_payload, std::slice::from_ref(&local), &[1, 2]);
        assert_reconstruct_missing(&base, &[local.clone(), local], &[1]);
        let prefilled_collision = cmpctblock_test_value(
            vec![compact_reconstruct_short_id_for_tx(&prefilled)],
            base.prefilled,
        );
        assert_reconstruct_missing(&prefilled_collision, std::slice::from_ref(&prefilled), &[1]);
        let valid_tx = minimal_blocktxn_test_tx_bytes(131);
        let short_id = compact_reconstruct_short_id_for_tx(&valid_tx);
        let req = CompactOutstandingRequest {
            block_hash: [9u8; 32],
            header: [0u8; BLOCK_HEADER_BYTES],
            missing_indexes: vec![1],
            missing_short_ids: vec![short_id],
            partial_transactions: vec![Some(prefilled.clone()), None],
            nonces: [0, 0],
            blocktxn_payload_cap: MAX_RELAY_MSG_BYTES,
            expires_at: Instant::now() + DEFAULT_READ_DEADLINE,
        };
        assert_eq!(
            compact_fill_response_transactions(
                &req,
                BlockTxnPayload {
                    block_hash: req.block_hash,
                    transactions: vec![valid_tx.clone()]
                }
            )
            .unwrap(),
            vec![prefilled.clone(), valid_tx.clone()]
        );
        let cases = [
            (
                vec![short_id],
                vec![compact_reconstruct_prefilled(2, valid_tx.clone())],
                "compact relay index out of range",
            ),
            (
                Vec::new(),
                vec![
                    compact_reconstruct_prefilled(0, valid_tx.clone()),
                    compact_reconstruct_prefilled(0, valid_tx.clone()),
                ],
                "compact relay index out of range",
            ),
        ];
        for (short_ids, prefilled, want_err) in cases {
            assert_reconstruct_err(&cmpctblock_test_value(short_ids, prefilled), &[], want_err);
        }
        assert_reconstruct_err(
            &cmpctblock_test_value(
                vec![[0u8; COMPACT_SHORT_ID_BYTES]; MAX_COMPACT_RELAY_ENTRIES + 1],
                Vec::new(),
            ),
            &[],
            "too many compact relay missing transactions",
        );
        let one_missing = cmpctblock_test_value(vec![short_id], Vec::new());
        assert_reconstruct_err(
            &one_missing,
            &vec![valid_tx.clone(); COMPACT_LOCAL_TX_CANDIDATE_LIMIT + 1],
            "too many compact relay local candidates",
        );
        let mut malformed = valid_tx.clone();
        malformed.push(0);
        let result = reconstruct_compact_block(&one_missing, &[malformed, valid_tx.clone()])
            .expect("malformed local candidate ignored");
        assert_eq!(result.transactions, vec![valid_tx.clone()]);
        assert_blocktxn_err(
            compact_validate_present_transaction_lengths([MAX_BLOCK_BYTES, 1]),
            "blocktxn transactions exceed block size",
        );
        let large_tx = large_blocktxn_test_tx_bytes(201);
        let capped_candidates = vec![large_tx.clone(), valid_tx.clone()];
        assert_reconstruct_missing(&one_missing, &capped_candidates, &[0]);
    }
    fn assert_reconstruct_missing(
        payload: &CmpctBlockPayload,
        local_txs: &[Vec<u8>],
        want: &[u64],
    ) {
        assert_eq!(
            reconstruct_compact_block(payload, local_txs)
                .expect("reconstruct")
                .missing_indexes,
            want
        );
    }
    fn compact_reconstruct_prefilled(index: u64, tx: Vec<u8>) -> PrefilledTxn {
        PrefilledTxn { index, tx }
    }

    fn compact_reconstruct_short_id_for_tx(tx: &[u8]) -> CompactShortId {
        let (_, _, wtxid, _) = parse_tx(tx).expect("parse compact tx");
        compact_shortid(wtxid, 0, 0)
    }

    fn assert_reconstruct_err(payload: &CmpctBlockPayload, local_txs: &[Vec<u8>], want_err: &str) {
        let err = reconstruct_compact_block(payload, local_txs)
            .expect_err("compact reconstruction succeeded")
            .to_string();
        assert!(err.contains(want_err), "got {err}, want {want_err}");
    }
    fn assert_cmpctblock_decode_err(tail: &[u8], want_err: &str) {
        assert_cmpctblock_err(
            decode_cmpctblock_payload(&cmpctblock_test_payload(tail)),
            want_err,
        );
    }

    fn assert_cmpctblock_err<T: std::fmt::Debug>(got: io::Result<T>, want_err: &str) {
        let err = got.expect_err("cmpctblock operation succeeded").to_string();
        assert!(err.contains(want_err), "got {err}, want {want_err}");
    }

    fn cmpctblock_test_payload(tail: &[u8]) -> Vec<u8> {
        let mut payload = vec![0u8; BLOCK_HEADER_BYTES + 16];
        payload.extend_from_slice(tail);
        payload
    }

    fn cmpctblock_test_value(
        short_ids: Vec<CompactShortId>,
        prefilled: Vec<PrefilledTxn>,
    ) -> CmpctBlockPayload {
        CmpctBlockPayload {
            header: [0u8; BLOCK_HEADER_BYTES],
            nonce1: 0,
            nonce2: 0,
            short_ids,
            prefilled,
        }
    }

    fn cmpctblock_prefilled_tail(index: u32, tx_envelope: &[u8]) -> Vec<u8> {
        let mut tail = Vec::new();
        encode_compact_size(0, &mut tail);
        encode_compact_size(1, &mut tail);
        tail.extend_from_slice(&index.to_le_bytes());
        tail.extend_from_slice(tx_envelope);
        tail
    }

    fn cmpctblock_tx_envelope(tx: &[u8]) -> Vec<u8> {
        let mut envelope = Vec::new();
        encode_compact_size(tx.len() as u64, &mut envelope);
        envelope.extend_from_slice(tx);
        envelope
    }

    fn minimal_blocktxn_test_tx_bytes(test_tag: u64) -> Vec<u8> {
        let mut out = vec![1, 0, 0, 0, 0];
        out.extend(test_tag.to_le_bytes());
        out.extend([0; 8]);
        out
    }

    fn compact_outstanding_test_request(block_hash: [u8; 32]) -> CompactOutstandingRequest {
        CompactOutstandingRequest {
            block_hash,
            header: [0u8; BLOCK_HEADER_BYTES],
            missing_indexes: vec![0],
            missing_short_ids: vec![[0x01; COMPACT_SHORT_ID_BYTES]],
            partial_transactions: vec![None],
            nonces: [0, 0],
            blocktxn_payload_cap: 64,
            expires_at: Instant::now() + DEFAULT_READ_DEADLINE,
        }
    }

    fn assert_fallback_getdata(client: &mut TcpStream, block_hash: [u8; 32]) {
        let msg = read_message_from(client, network_magic("devnet"), MAX_RELAY_MSG_BYTES)
            .expect("read fallback getdata");
        assert_eq!(msg.command, MESSAGE_GETDATA);
        assert_eq!(
            decode_inventory_vectors(&msg.payload).expect("decode fallback inventory"),
            vec![InventoryVector {
                kind: MSG_BLOCK,
                hash: block_hash
            }]
        );
    }

    fn write_test_wire_message(client: &mut TcpStream, command: &str, payload: &[u8]) {
        let header =
            build_envelope_header(network_magic("devnet"), command, payload).expect("build header");
        client.write_all(&header).expect("write header");
        client.write_all(payload).expect("write payload");
        client.flush().expect("flush payload");
    }

    fn run_late_blocktxn_after_expiry(
        block_hash: [u8; 32],
        payload: Vec<u8>,
    ) -> (PeerSession, TcpStream, io::Result<TxPoolCleanupPlan>) {
        let (mut session, mut client) = test_peer_session();
        let mut req = compact_outstanding_test_request(block_hash);
        req.expires_at = Instant::now() - Duration::from_secs(1);
        session.compact_outstanding = Some(req);
        write_test_wire_message(&mut client, MESSAGE_BLOCKTXN, &payload);
        let mut engine = test_sync_engine_with_genesis();
        let result = session
            .read_message_with_timeout(Duration::from_secs(1))
            .and_then(|msg| session.handle_live_message(msg, &mut engine, None));
        (session, client, result)
    }

    #[test]
    fn compact_outstanding_clear_go_parity_matrix() {
        let (mut session, _client) = test_peer_session();
        let mut engine = test_sync_engine_with_genesis();
        let block = devnet_genesis_block_bytes();
        let block_hash = block_hash(&block[..BLOCK_HEADER_BYTES]).expect("genesis hash");

        session.compact_outstanding = Some(compact_outstanding_test_request(block_hash));
        session
            .handle_block(&block, &mut engine)
            .expect("already-have full block");
        assert!(
            session.compact_outstanding.is_none(),
            "matching full block did not clear outstanding compact request"
        );

        let active_hash = [0x55; 32];
        session.compact_outstanding = Some(compact_outstanding_test_request(active_hash));
        session
            .handle_block(&block, &mut engine)
            .expect("nonmatching full block");
        assert_eq!(
            session
                .compact_outstanding
                .as_ref()
                .map(|req| req.block_hash),
            Some(active_hash),
            "nonmatching full block cleared unrelated outstanding compact request"
        );

        session.clear_compact_outstanding_request_for_block([0x66; 32]);
        assert_eq!(
            session
                .compact_outstanding
                .as_ref()
                .map(|req| req.block_hash),
            Some(active_hash),
            "nonmatching explicit clear corrupted outstanding compact request"
        );
        session.clear_compact_outstanding_request_for_block(active_hash);
        session.clear_compact_outstanding_request_for_block(active_hash);
        assert!(
            session.compact_outstanding.is_none(),
            "matching explicit clear was not idempotent"
        );

        session.compact_outstanding = Some(compact_outstanding_test_request(block_hash));
        session
            .request_compact_full_block_fallback(block_hash)
            .expect("matching fallback");
        assert!(
            session.compact_outstanding.is_none(),
            "matching fallback left outstanding compact request active"
        );

        session.compact_outstanding = Some(compact_outstanding_test_request(active_hash));
        session
            .request_compact_full_block_fallback(block_hash)
            .expect("stale fallback");
        assert_eq!(
            session
                .compact_outstanding
                .as_ref()
                .map(|req| req.block_hash),
            Some(active_hash),
            "stale fallback cleared unrelated outstanding compact request"
        );
    }

    #[test]
    fn compact_fallback_poll_read_ready_emits_expired_fallback() {
        let (mut session, mut client) = test_peer_session();
        let block_hash = [0xaa; 32];
        let mut req = compact_outstanding_test_request(block_hash);
        req.expires_at = Instant::now() - Duration::from_secs(1);
        session.compact_outstanding = Some(req);

        assert!(!session
            .poll_read_ready(Duration::from_millis(10))
            .expect("poll read ready"));
        assert!(session.compact_outstanding.is_none());
        assert_fallback_getdata(&mut client, block_hash);
    }

    #[test]
    fn compact_fallback_read_message_with_ready_frame_emits_expired_fallback() {
        let (mut session, mut client) = test_peer_session();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("client read timeout");
        let block_hash = [0xbb; 32];
        let req = compact_outstanding_test_request(block_hash);
        session.compact_outstanding = Some(req);
        let header =
            build_envelope_header(network_magic("devnet"), "ping", &[]).expect("ping header");
        client.write_all(&header).expect("write ready ping");
        assert!(session
            .poll_read_ready(Duration::from_secs(1))
            .expect("prefetch first byte"));
        session.compact_outstanding.as_mut().unwrap().expires_at =
            Instant::now() - Duration::from_secs(1);

        let msg = session.read_message().expect("read ready ping");
        assert_eq!(msg.command, "ping");
        assert!(session.compact_outstanding.is_none());
        assert_fallback_getdata(&mut client, block_hash);
    }

    #[test]
    fn compact_fallback_read_message_continues_after_expiry_fallback() {
        let (mut session, mut client) = test_peer_session();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("client read timeout");
        let block_hash = [0xcc; 32];
        let mut req = compact_outstanding_test_request(block_hash);
        req.expires_at = Instant::now() + Duration::from_millis(30);
        session.compact_outstanding = Some(req);
        let header =
            build_envelope_header(network_magic("devnet"), "ping", &[]).expect("ping header");
        client.write_all(&header[..1]).expect("write partial ping");

        let reader = thread::spawn(move || {
            let msg = session
                .read_message_with_timeout(Duration::from_secs(2))
                .expect("continue reading after compact expiry fallback");
            assert_eq!(msg.command, "ping");
            assert!(session.compact_outstanding.is_none());
        });

        assert_fallback_getdata(&mut client, block_hash);
        client
            .write_all(&header[1..])
            .expect("write ping after fallback");
        reader.join().expect("read_message thread");
    }

    #[test]
    fn compact_fallback_frame_reader_sends_expired_fallback_before_ready_read() {
        let (mut session, mut client) = test_peer_session();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("client read timeout");
        let block_hash = [0xdd; 32];
        let mut req = compact_outstanding_test_request(block_hash);
        req.expires_at = Instant::now() - Duration::from_secs(1);
        session.compact_outstanding = Some(req);
        client.write_all(b"x").expect("write ready byte");

        {
            let mut reader = CompactFallbackFrameReader {
                stream: &mut session.stream,
                prefetched_read_byte: None,
                compact_outstanding: &mut session.compact_outstanding,
                late_blocktxn: &mut session.late_blocktxn,
                read_timeout: Duration::from_secs(1),
                write_timeout: session.cfg.write_deadline,
                network_magic: network_magic(&session.cfg.network),
            };
            let mut empty = [];
            assert_eq!(reader.read(&mut empty).expect("zero-length read"), 0);
            assert!(reader.compact_outstanding.is_some());

            let mut buf = [0u8; 1];
            assert_eq!(reader.read(&mut buf).expect("read ready byte"), 1);
            assert_eq!(buf[0], b'x');
        }

        assert!(session.compact_outstanding.is_none());
        assert_fallback_getdata(&mut client, block_hash);
    }

    #[test]
    fn late_blocktxn_after_expiry_fallback_matrix() {
        let block_hash = [0xe1; 32];
        let matching = {
            let mut payload = block_hash.to_vec();
            payload.push(0x01);
            payload
        };
        let (mut session, mut client, result) =
            run_late_blocktxn_after_expiry(block_hash, matching);
        result.expect("matching late blocktxn ignored");
        assert_fallback_getdata(&mut client, block_hash);
        assert!(session.compact_outstanding.is_none());
        assert!(session.late_blocktxn.is_none());
        assert_eq!(session.peer.ban_score, 0);
        assert_eq!(session.peer.last_error, "ignored late blocktxn response");
        session
            .handle_blocktxn(&block_hash, &mut test_sync_engine_with_genesis())
            .expect("duplicate hash-only blocktxn");

        let stale_hash = [0xe2; 32];
        let (session, mut client, result) =
            run_late_blocktxn_after_expiry(block_hash, stale_hash.to_vec());
        result.expect("hash-only stale late blocktxn ignored");
        assert_fallback_getdata(&mut client, block_hash);
        assert!(session.compact_outstanding.is_none());
        assert!(session.late_blocktxn.is_none());
        assert_eq!(session.peer.ban_score, 0);
        assert_eq!(session.peer.last_error, "ignored stale blocktxn response");

        let (mut session, mut client) = test_peer_session();
        session.late_blocktxn = Some(LateBlockTxnContext {
            block_hash,
            blocktxn_payload_cap: 64,
        });
        let mut stale_body = stale_hash.to_vec();
        stale_body.push(0x01);
        let header = build_envelope_header(network_magic("devnet"), MESSAGE_BLOCKTXN, &stale_body)
            .expect("build stale blocktxn header");
        client.write_all(&header).expect("write header");
        client.write_all(&stale_hash).expect("write hash prefix");
        let err = session
            .read_message_with_timeout(Duration::from_secs(1))
            .expect_err("stale body must reject before reading body");
        assert_eq!(err.to_string(), "stale blocktxn response has body");
        assert!(session.late_blocktxn.is_none());
    }

    #[test]
    fn late_blocktxn_fragmented_after_expiry_fallback() {
        let (mut session, mut client) = test_peer_session();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("client read timeout");
        let block_hash = [0xe3; 32];
        let mut payload = block_hash.to_vec();
        payload.push(0x01);
        let header = build_envelope_header(network_magic("devnet"), MESSAGE_BLOCKTXN, &payload)
            .expect("build blocktxn header");
        let mut req = compact_outstanding_test_request(block_hash);
        req.expires_at = Instant::now() - Duration::from_secs(1);
        session.compact_outstanding = Some(req);

        let reader = thread::spawn(move || {
            let mut engine = test_sync_engine_with_genesis();
            let msg = session
                .read_message_with_timeout(Duration::from_secs(2))
                .expect("read fragmented late blocktxn");
            session
                .handle_live_message(msg, &mut engine, None)
                .expect("handle fragmented late blocktxn");
            assert!(session.compact_outstanding.is_none());
            assert!(session.late_blocktxn.is_none());
            assert_eq!(session.peer.last_error, "ignored late blocktxn response");
        });

        assert_fallback_getdata(&mut client, block_hash);
        client.write_all(&header).expect("write blocktxn header");
        client
            .write_all(&payload[..1])
            .expect("write first payload byte");
        client.write_all(&payload[1..]).expect("write rest payload");
        reader.join().expect("late blocktxn reader");
    }

    fn large_blocktxn_test_tx_bytes(test_tag: u64) -> Vec<u8> {
        let mut out = vec![1, 0, 0, 0, 0];
        out.extend(test_tag.to_le_bytes());
        out.push(0);
        encode_compact_size(16, &mut out);
        for _ in 0..16 {
            out.extend([0; 10]);
            encode_compact_size(65_521, &mut out);
            out.extend([0; 65_521]);
        }
        out.extend([0; 6]);
        out
    }

    fn compact_full_block_len_for_test(tx_count: usize, tx_len: usize) -> u64 {
        (BLOCK_HEADER_BYTES + compact_size_wire_len(tx_count as u64) as usize + tx_count * tx_len)
            as u64
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

    fn height_one_coinbase_only_block(prev_hash: [u8; 32], timestamp: u64) -> Vec<u8> {
        let witness_root = witness_merkle_root_wtxids(&[[0u8; 32]]).expect("witness root");
        let witness_commitment = witness_commitment_hash(witness_root);
        let coinbase =
            build_coinbase_tx(1, 0, &default_mine_address(), witness_commitment).expect("coinbase");
        let (_, coinbase_txid, _, consumed) = parse_tx(&coinbase).expect("parse coinbase");
        assert_eq!(consumed, coinbase.len());
        let merkle_root = merkle_root_txids(&[coinbase_txid]).expect("merkle root");
        build_block_bytes(prev_hash, merkle_root, POW_LIMIT, timestamp, &[coinbase])
    }

    #[test]
    fn p2p_version_handshake_bidirectional_ok() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = test_version_payload(0);
            perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                .expect("server handshake")
                .state()
        });

        let client = thread::spawn(move || {
            let stream = TcpStream::connect(addr).expect("connect");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = test_version_payload(0);
            perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                .expect("client handshake")
                .state()
        });

        let a = server.join().expect("server join");
        let b = client.join().expect("client join");
        assert!(a.handshake_complete);
        assert!(b.handshake_complete);
        assert_eq!(a.remote_version.protocol_version, 1);
        assert_eq!(b.remote_version.protocol_version, 1);
    }

    #[test]
    fn p2p_invalid_magic_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let mut session =
                PeerSession::new(stream.try_clone().expect("clone"), cfg).expect("session");
            let err = session.read_message().unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "invalid envelope magic");
        });

        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream.set_nodelay(true).expect("set_nodelay");
            let payload = marshal_version_payload_v1(test_version_payload(0));
            let header = build_envelope_header(network_magic("mainnet"), "version", &payload)
                .expect("header");
            stream.write_all(&header).expect("write header");
            stream.write_all(&payload).expect("write payload");
            stream.flush().expect("flush");
        });

        client.join().expect("client join");
        server.join().expect("server join");
    }

    #[test]
    fn p2p_read_message_rejects_oversize_before_payload_read() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let mut session =
                PeerSession::new(stream.try_clone().expect("clone"), cfg).expect("session");
            let err = session.read_message().unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "message exceeds cap");
        });

        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut header = [0u8; WIRE_HEADER_SIZE];
            header[0..4].copy_from_slice(&network_magic("devnet"));
            header[4..16].copy_from_slice(&encode_wire_command("tx").expect("command"));
            let oversize = (MAX_RELAY_MSG_BYTES + 1) as u32;
            header[16..20].copy_from_slice(&oversize.to_le_bytes());
            stream.write_all(&header).expect("write header");
            stream.flush().expect("flush");
        });

        client.join().expect("client join");
        server.join().expect("server join");
    }

    #[test]
    fn p2p_read_message_rejects_inventory_command_cap_before_payload_read() {
        let mut header = [0u8; WIRE_HEADER_SIZE];
        header[0..4].copy_from_slice(&network_magic("devnet"));
        header[4..16].copy_from_slice(&encode_wire_command(MESSAGE_INV).expect("command"));
        let oversize = (MAX_INVENTORY_PAYLOAD_BYTES + 1) as u32;
        header[16..20].copy_from_slice(&oversize.to_le_bytes());

        let mut reader = std::io::Cursor::new(header);
        let err = read_message_from(&mut reader, network_magic("devnet"), MAX_RELAY_MSG_BYTES)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "message exceeds command cap");
    }

    #[test]
    fn p2p_read_message_rejects_addr_command_cap_before_payload_read() {
        let mut header = [0u8; WIRE_HEADER_SIZE];
        header[0..4].copy_from_slice(&network_magic("devnet"));
        header[4..16].copy_from_slice(&encode_wire_command(MESSAGE_ADDR).expect("command"));
        let oversize = (MAX_ADDR_PAYLOAD_BYTES + 1) as u32;
        header[16..20].copy_from_slice(&oversize.to_le_bytes());

        let mut reader = std::io::Cursor::new(header);
        let err = read_message_from(&mut reader, network_magic("devnet"), MAX_RELAY_MSG_BYTES)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "message exceeds command cap");
    }

    #[test]
    fn p2p_read_message_rejects_block_command_cap_before_payload_read() {
        let mut header = [0u8; WIRE_HEADER_SIZE];
        header[0..4].copy_from_slice(&network_magic("devnet"));
        header[4..16].copy_from_slice(&encode_wire_command(MESSAGE_BLOCK).expect("command"));
        let oversize = (MAX_BLOCK_BYTES + 1) as u32;
        header[16..20].copy_from_slice(&oversize.to_le_bytes());

        let mut reader = std::io::Cursor::new(header);
        let err = read_message_from(&mut reader, network_magic("devnet"), MAX_RELAY_MSG_BYTES)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "message exceeds command cap");
    }

    #[test]
    fn p2p_read_message_rejects_tx_command_cap_before_payload_read() {
        let mut header = [0u8; WIRE_HEADER_SIZE];
        header[0..4].copy_from_slice(&network_magic("devnet"));
        header[4..16].copy_from_slice(&encode_wire_command(MESSAGE_TX).expect("command"));
        let oversize = (MAX_BLOCK_BYTES + 1) as u32;
        header[16..20].copy_from_slice(&oversize.to_le_bytes());

        let mut reader = std::io::Cursor::new(header);
        let err = read_message_from(&mut reader, network_magic("devnet"), MAX_RELAY_MSG_BYTES)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "message exceeds command cap");
    }

    #[test]
    fn p2p_read_message_rejects_non_empty_ping_payload() {
        let mut header = [0u8; WIRE_HEADER_SIZE];
        header[0..4].copy_from_slice(&network_magic("devnet"));
        header[4..16].copy_from_slice(&encode_wire_command("ping").expect("command"));
        header[16..20].copy_from_slice(&1u32.to_le_bytes());

        let mut reader = std::io::Cursor::new(header);
        let err = read_message_from(&mut reader, network_magic("devnet"), MAX_RELAY_MSG_BYTES)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "message exceeds command cap");
    }

    #[test]
    fn p2p_read_payload_with_checksum_chunked_roundtrip() {
        let payload = vec![0xabu8; STREAM_READ_CHUNK_BYTES + 17];
        let checksum = wire_checksum(&payload);
        let mut reader = std::io::Cursor::new(payload.clone());
        let got =
            read_payload_with_checksum(&mut reader, payload.len(), checksum).expect("payload");
        assert_eq!(got, payload);
    }

    #[test]
    fn p2p_read_payload_with_checksum_rejects_bad_checksum_after_chunked_read() {
        let payload = vec![0xcdu8; STREAM_READ_CHUNK_BYTES + 9];
        let mut checksum = wire_checksum(&payload);
        checksum[0] ^= 0xff;
        let mut reader = std::io::Cursor::new(payload);
        let err = read_payload_with_checksum(&mut reader, STREAM_READ_CHUNK_BYTES + 9, checksum)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "invalid envelope checksum");
    }

    #[test]
    fn decode_inventory_vectors_rejects_count_over_limit() {
        let count = MAX_INVENTORY_VECTORS + 1;
        let mut payload = vec![0u8; count * INVENTORY_VECTOR_SIZE];
        for chunk in payload.chunks_exact_mut(INVENTORY_VECTOR_SIZE) {
            chunk[0] = MSG_BLOCK;
        }
        let err = decode_inventory_vectors(&payload).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "inventory count exceeds limit");
    }

    #[test]
    fn unmarshal_addr_payload_rejects_count_over_limit() {
        let err = unmarshal_addr_payload(&[0xfd, 0xe9, 0x03]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "addr count exceeds limit");
    }

    #[test]
    fn shared_runtime_vectors_version_payload_v1() {
        let vectors = load_shared_runtime_vectors();
        let expected = shared_version_payload(&vectors.version_payload_v1);
        let want = hex::decode(&vectors.version_payload_v1.hex).expect("payload hex");
        let encoded = marshal_version_payload_v1(expected);
        assert_eq!(encoded, want);
        let decoded = unmarshal_version_payload_v1(&want).expect("decode payload");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn shared_runtime_vectors_frames() {
        let vectors = load_shared_runtime_vectors();
        for frame in vectors.frames {
            let raw = hex::decode(&frame.hex).expect("frame hex");
            let decoded =
                unmarshal_wire_message(&raw, network_magic(&frame.network), frame.max_message_size);
            if let Some(expect_err) = frame.expect_err {
                let err = decoded.expect_err(&frame.id);
                assert_eq!(err.to_string(), expect_err, "{}", frame.id);
                continue;
            }
            let decoded = decoded.expect(&frame.id);
            assert_eq!(
                decoded.command,
                frame.expect_command.expect("command"),
                "{}",
                frame.id
            );
            assert_eq!(
                decoded.payload,
                hex::decode(frame.expect_payload_hex.expect("payload")).expect("payload hex"),
                "{}",
                frame.id
            );
            let reencoded = marshal_wire_message(
                &decoded,
                network_magic(&frame.network),
                frame.max_message_size,
            )
            .expect("marshal");
            assert_eq!(reencoded, raw, "{}", frame.id);
        }
    }

    #[test]
    fn shared_runtime_vectors_version_validation() {
        let vectors = load_shared_runtime_vectors();
        let expected = shared_version_payload(&vectors.version_payload_v1);
        for tc in vectors.version_validation {
            let remote = VersionPayloadV1 {
                protocol_version: tc.remote_protocol_version,
                tx_relay: tc.tx_relay,
                pruned_below_height: tc.pruned_below_height,
                da_mempool_size: tc.da_mempool_size,
                chain_id: decode_hex32(&tc.chain_id_hex),
                genesis_hash: decode_hex32(&tc.genesis_hash_hex),
                best_height: tc.best_height,
            };
            let got = validate_remote_version(
                remote,
                tc.local_protocol_version,
                expected.chain_id,
                expected.genesis_hash,
            );
            if let Some(expect_err) = tc.expect_err {
                let err = got.expect_err(&tc.id);
                assert_eq!(err.to_string(), expect_err, "{}", tc.id);
                continue;
            }
            assert!(tc.expect_ok, "{} should be marked expect_ok", tc.id);
            got.expect(&tc.id);
        }
    }

    #[test]
    fn request_more_blocks_if_behind_sends_followup_getblocks() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8))
                .expect("session");
            session.peer.remote_version.best_height = 2;
            let engine = test_sync_engine_with_genesis();
            session
                .request_more_blocks_if_behind(&engine)
                .expect("follow-up getblocks");
        });

        let mut client = TcpStream::connect(addr).expect("connect");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set_read_timeout");
        let msg = read_message_from(&mut client, network_magic("devnet"), MAX_RELAY_MSG_BYTES)
            .expect("read getblocks");
        assert_eq!(msg.command, MESSAGE_GETBLOCKS);
        server.join().expect("server join");
    }

    #[test]
    fn request_blocks_if_behind_bootstraps_when_local_tip_missing() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8))
                .expect("session");
            session.peer.remote_version.best_height = 0;
            let engine = SyncEngine::new(
                ChainState::new(),
                None,
                crate::sync::default_sync_config(Some(POW_LIMIT), devnet_genesis_chain_id(), None),
            )
            .expect("new sync engine");
            session
                .request_blocks_if_behind(&engine)
                .expect("initial bootstrap getblocks");
        });

        let mut client = TcpStream::connect(addr).expect("connect");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set_read_timeout");
        let msg = read_message_from(&mut client, network_magic("devnet"), MAX_RELAY_MSG_BYTES)
            .expect("read getblocks");
        assert_eq!(msg.command, MESSAGE_GETBLOCKS);
        server.join().expect("server join");
    }

    #[test]
    fn respond_to_getdata_ignores_missing_blocks() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8))
                .expect("session");
            let engine = test_sync_engine_with_genesis();
            let payload = encode_inventory_vectors(&[InventoryVector {
                kind: MSG_BLOCK,
                hash: [0x42; 32],
            }])
            .expect("inventory payload");
            session
                .respond_to_getdata(&payload, &engine, None)
                .expect("missing block should be ignored");
        });

        let mut client = TcpStream::connect(addr).expect("connect");
        client
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set_read_timeout");
        let mut byte = [0u8; 1];
        match client.read(&mut byte) {
            Ok(0) => {}
            Ok(n) => panic!("unexpected block bytes written: {n}"),
            Err(err) => assert!(matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            )),
        }
        server.join().expect("server join");
    }

    #[test]
    fn handle_block_ignores_duplicate_frames() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8))
                .expect("session");
            let mut engine = test_sync_engine_with_genesis();
            session
                .handle_block(&devnet_genesis_block_bytes(), &mut engine)
                .expect("duplicate block should be ignored");
        });

        let _client = TcpStream::connect(addr).expect("connect");
        server.join().expect("server join");
    }

    #[test]
    fn handle_block_evicts_confirmed_pool_transactions_when_pool_provided() {
        // RUB-162 Phase A migration rationale (per controller Q2 / Path A
        // approval 2026-05-03):
        //   - old assumption: signed_conflicting_p2pk_state_and_txs(20,10,9)
        //     produces tx with fee=10/weight≈7653 that admits because
        //     pre-RUB-162 admit_with_metadata did not enforce the rolling
        //     fee floor.
        //   - new invariant: admit_with_metadata enforces the rolling fee
        //     floor (DEFAULT=1) via validate_fee_floor.
        //   - reachability: pool.admit reaches the txpool admission path;
        //     the test then asserts handle_block evicts the confirmed tx
        //     from the shared runtime pool.
        //   - replacement coverage: input bumped to 7700 so fee=7690 ≥
        //     weight (~7653). The handle_block-eviction-on-confirmation
        //     invariant remains under test.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8))
                .expect("session");
            let mut engine = test_sync_engine_with_genesis();
            engine.cfg.chain_id = devnet_genesis_chain_id();

            let (state, admitted_raw, _block_raw) =
                signed_conflicting_p2pk_state_and_txs(7700, 10, 9);
            engine.chain_state.utxos = state.utxos.clone();

            let genesis = parse_block_bytes(&devnet_genesis_block_bytes()).expect("parse genesis");
            let genesis_hash = block_hash(&genesis.header_bytes).expect("genesis hash");
            let mut pool = TxPool::new();
            pool.admit(
                &admitted_raw,
                &engine.chain_state,
                engine.block_store.as_ref(),
                engine.cfg.chain_id,
            )
            .expect("admit");

            let block = block_with_txs(
                1,
                0,
                genesis_hash,
                genesis.header.timestamp + 1,
                &[admitted_raw],
            );
            let cleanup = session
                .handle_block(&block, &mut engine)
                .expect("block with admitted tx");
            cleanup.apply(
                &mut pool,
                &engine.chain_state,
                engine.block_store.as_ref(),
                engine.cfg.chain_id,
            );

            assert!(
                pool.is_empty(),
                "confirmed tx must be evicted from the shared runtime pool"
            );
        });

        let _client = TcpStream::connect(addr).expect("connect");
        server.join().expect("server join");
    }

    #[test]
    fn handle_block_removes_conflicting_pool_transactions_when_pool_provided() {
        // RUB-162 Phase A migration rationale (per controller Q2 / Path A
        // approval 2026-05-03):
        //   - old assumption: signed_conflicting_p2pk_state_and_txs(20,10,9)
        //     admits the first tx and the test then verifies a conflicting
        //     block tx triggers cleanup of the resident.
        //   - new invariant: admit_with_metadata enforces the rolling fee
        //     floor.
        //   - reachability: pool.admit on admitted_raw reaches the
        //     admission path; cleanup.apply then exercises the
        //     remove_conflicting_outpoints path on the block-apply boundary.
        //   - replacement coverage: input bumped to 7700 so both txs have
        //     floor-compliant fees. Conflict-cleanup-on-block-apply
        //     invariant remains under test.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8))
                .expect("session");
            let mut engine = test_sync_engine_with_genesis();
            engine.cfg.chain_id = devnet_genesis_chain_id();

            let (state, admitted_raw, block_raw) =
                signed_conflicting_p2pk_state_and_txs(7700, 10, 9);
            engine.chain_state.utxos = state.utxos.clone();

            let genesis = parse_block_bytes(&devnet_genesis_block_bytes()).expect("parse genesis");
            let genesis_hash = block_hash(&genesis.header_bytes).expect("genesis hash");
            let mut pool = TxPool::new();
            pool.admit(
                &admitted_raw,
                &engine.chain_state,
                engine.block_store.as_ref(),
                engine.cfg.chain_id,
            )
            .expect("admit");

            let block = block_with_txs(
                1,
                0,
                genesis_hash,
                genesis.header.timestamp + 1,
                &[block_raw],
            );
            let cleanup = session
                .handle_block(&block, &mut engine)
                .expect("conflicting block");
            cleanup.apply(
                &mut pool,
                &engine.chain_state,
                engine.block_store.as_ref(),
                engine.cfg.chain_id,
            );

            assert!(
                pool.is_empty(),
                "conflicting mempool tx must be removed on the block-apply boundary"
            );
        });

        let _client = TcpStream::connect(addr).expect("connect");
        server.join().expect("server join");
    }

    #[test]
    fn handle_block_rejects_future_timestamp_during_sync() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8))
                .expect("session");
            let mut engine = test_sync_engine_with_genesis();
            let genesis = parse_block_bytes(&devnet_genesis_block_bytes()).expect("parse genesis");
            let genesis_hash = block_hash(&genesis.header_bytes).expect("genesis hash");
            let block = height_one_coinbase_only_block(
                genesis_hash,
                genesis
                    .header
                    .timestamp
                    .saturating_add(MAX_FUTURE_DRIFT + 1),
            );
            let err = session
                .handle_block(&block, &mut engine)
                .expect_err("future timestamp must be rejected");
            assert_eq!(err.kind(), io::ErrorKind::Other);
            assert!(
                err.to_string().contains("BLOCK_ERR_TIMESTAMP_FUTURE"),
                "unexpected error: {err}"
            );
        });

        let _client = TcpStream::connect(addr).expect("connect");
        server.join().expect("server join");
    }

    #[test]
    fn handle_block_retains_orphan_until_parent_arrives() {
        let _guard = orphan_pool_metrics_test_guard();
        reset_orphan_pool_metrics_for_test();

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8))
                .expect("session");
            let mut engine = test_sync_engine_with_genesis();
            let genesis = parse_block_bytes(&devnet_genesis_block_bytes()).expect("parse genesis");
            let genesis_hash = block_hash(&genesis.header_bytes).expect("genesis hash");
            let block1 = height_one_coinbase_only_block(genesis_hash, genesis.header.timestamp + 1);
            let block1_hash = block_hash(&block1[..BLOCK_HEADER_BYTES]).expect("block1 hash");
            let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
            let block2 = coinbase_only_block_with_gen(
                2,
                subsidy1,
                block1_hash,
                genesis.header.timestamp + 2,
            );
            let block2_hash = block_hash(&block2[..BLOCK_HEADER_BYTES]).expect("block2 hash");

            session
                .handle_block(&block2, &mut engine)
                .expect("orphan block should be retained");
            assert_eq!(
                orphan_pool_metrics_snapshot(),
                OrphanPoolMetricsSnapshot {
                    live_blocks: 1,
                    live_bytes: block2.len()
                },
                "retained orphan must be visible in live observability only"
            );
            assert_eq!(engine.chain_state.height, 0, "orphan must not advance tip");
            assert_eq!(
                engine.chain_state.tip_hash, genesis_hash,
                "tip must remain genesis"
            );
            assert!(
                !engine
                    .has_block(block2_hash)
                    .expect("orphan must not persist before parent"),
                "orphan should remain memory-only until its parent connects"
            );

            session
                .handle_block(&block1, &mut engine)
                .expect("parent block should connect and resolve orphan");

            assert_eq!(session.orphans.len(), 0, "orphan pool should drain");
            assert_eq!(
                orphan_pool_metrics_snapshot(),
                OrphanPoolMetricsSnapshot {
                    live_blocks: 0,
                    live_bytes: 0
                },
                "resolved orphan must drain live observability"
            );
            assert!(engine.has_block(block1_hash).expect("block1 applied"));
            assert!(engine.has_block(block2_hash).expect("block2 resolved"));
            assert_eq!(engine.chain_state.height, 2);
        });

        let _client = TcpStream::connect(addr).expect("connect");
        server.join().expect("server join");
        reset_orphan_pool_metrics_for_test();
    }

    #[test]
    fn handle_block_surfaces_invalid_orphan_after_parent_arrives() {
        let _guard = orphan_pool_metrics_test_guard();
        reset_orphan_pool_metrics_for_test();

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8))
                .expect("session");
            let mut engine = test_sync_engine_with_genesis();
            let genesis = parse_block_bytes(&devnet_genesis_block_bytes()).expect("parse genesis");
            let genesis_hash = block_hash(&genesis.header_bytes).expect("genesis hash");
            let block1 = height_one_coinbase_only_block(genesis_hash, genesis.header.timestamp + 1);
            let block1_hash = block_hash(&block1[..BLOCK_HEADER_BYTES]).expect("block1 hash");
            let subsidy1 = rubin_consensus::subsidy::block_subsidy(1, 0);
            let mut block2 = coinbase_only_block_with_gen(
                2,
                subsidy1,
                block1_hash,
                genesis.header.timestamp + 2,
            );
            block2[36] ^= 0xff; // corrupt merkle root while keeping the block parseable
            let block2_hash = block_hash(&block2[..BLOCK_HEADER_BYTES]).expect("block2 hash");

            session
                .handle_block(&block2, &mut engine)
                .expect("orphan should be retained until parent arrives");
            assert_eq!(
                orphan_pool_metrics_snapshot(),
                OrphanPoolMetricsSnapshot {
                    live_blocks: 1,
                    live_bytes: block2.len()
                },
                "invalid orphan remains live only until its parent arrives"
            );
            assert!(
                !engine
                    .has_block(block2_hash)
                    .expect("invalid orphan must not persist before parent"),
                "invalid orphan should remain memory-only until parent arrives"
            );
            let err = session
                .handle_block(&block1, &mut engine)
                .expect_err("invalid orphan should surface after parent arrives");
            let pending_cleanup = session.take_pending_tx_pool_cleanup();

            assert_eq!(session.orphans.len(), 0, "invalid orphan should be dropped");
            assert_eq!(
                orphan_pool_metrics_snapshot(),
                OrphanPoolMetricsSnapshot {
                    live_blocks: 0,
                    live_bytes: 0
                },
                "invalid orphan must not remain counted after surfacing"
            );
            assert_eq!(
                engine.chain_state.height, 1,
                "parent block must remain connected"
            );
            assert!(
                !pending_cleanup.is_empty(),
                "accepted parent block cleanup must survive the later orphan error"
            );
            assert!(
                session.take_pending_tx_pool_cleanup().is_empty(),
                "pending cleanup should drain once observed"
            );
            assert_eq!(
                session.state().ban_score,
                0,
                "invalid orphan should not ban the peer"
            );
            let err_text = err.to_string();
            assert!(
                err_text.contains("BLOCK_ERR_MERKLE_INVALID")
                    || err_text.contains("merkle_root mismatch"),
                "got: {err_text}"
            );
        });

        let _client = TcpStream::connect(addr).expect("connect");
        server.join().expect("server join");
        reset_orphan_pool_metrics_for_test();
    }

    #[test]
    fn orphan_pool_metrics_start_zero_and_track_take_children() {
        let _guard = orphan_pool_metrics_test_guard();
        reset_orphan_pool_metrics_for_test();

        assert_eq!(
            orphan_pool_metrics_snapshot(),
            OrphanPoolMetricsSnapshot {
                live_blocks: 0,
                live_bytes: 0
            }
        );

        let mut pool = OrphanBlockPool::new(16, usize::MAX);
        let block = vec![7u8; 123];
        let block_hash = [1u8; 32];
        let parent_hash = [2u8; 32];

        pool.add(block_hash, parent_hash, &block, global_orphan_byte_limit());
        assert_eq!(
            orphan_pool_metrics_snapshot(),
            OrphanPoolMetricsSnapshot {
                live_blocks: 1,
                live_bytes: block.len()
            }
        );

        let children = pool.take_children(parent_hash);
        assert_eq!(children.len(), 1);
        assert_eq!(
            orphan_pool_metrics_snapshot(),
            OrphanPoolMetricsSnapshot {
                live_blocks: 0,
                live_bytes: 0
            }
        );
    }

    #[test]
    fn orphan_pool_replaces_local_oldest_when_global_limit_reached() {
        let _guard = orphan_pool_metrics_test_guard();
        reset_orphan_pool_metrics_for_test();
        GLOBAL_ORPHAN_BYTE_LIMIT_OVERRIDE.store(1024, Ordering::SeqCst);

        let mut pool = OrphanBlockPool::new(16, usize::MAX);
        let first = vec![7u8; 800];
        let second = vec![9u8; 800];

        pool.add([1u8; 32], [2u8; 32], &first, global_orphan_byte_limit());
        pool.add([3u8; 32], [4u8; 32], &second, global_orphan_byte_limit());

        assert_eq!(pool.len(), 1, "global cap should still permit local churn");
        assert_eq!(
            orphan_pool_metrics_snapshot(),
            OrphanPoolMetricsSnapshot {
                live_blocks: 1,
                live_bytes: 800
            }
        );
        assert!(
            pool.by_hash.contains_key(&[3u8; 32]),
            "new orphan should be retained"
        );
        assert!(
            !pool.by_hash.contains_key(&[1u8; 32]),
            "old orphan should be evicted to make room"
        );
        assert_eq!(GLOBAL_ORPHAN_TOTAL_BYTES.load(Ordering::SeqCst), 800);

        drop(pool);
        assert_eq!(
            orphan_pool_metrics_snapshot(),
            OrphanPoolMetricsSnapshot {
                live_blocks: 0,
                live_bytes: 0
            },
            "dropping the orphan pool must drain live observability"
        );
        reset_orphan_pool_metrics_for_test();
    }

    #[test]
    fn orphan_pool_enforces_global_byte_limit_across_sessions() {
        let _guard = orphan_pool_metrics_test_guard();
        reset_orphan_pool_metrics_for_test();
        GLOBAL_ORPHAN_BYTE_LIMIT_OVERRIDE.store(1024, Ordering::SeqCst);

        let mut pool_a = OrphanBlockPool::new(16, usize::MAX);
        let mut pool_b = OrphanBlockPool::new(16, usize::MAX);
        let block = vec![7u8; 800];

        pool_a.add([1u8; 32], [2u8; 32], &block, global_orphan_byte_limit());
        pool_b.add([3u8; 32], [4u8; 32], &block, global_orphan_byte_limit());

        assert_eq!(pool_a.len(), 1, "first session should retain orphan");
        assert_eq!(
            pool_b.len(),
            0,
            "second session should be capped by global limit"
        );
        assert_eq!(GLOBAL_ORPHAN_TOTAL_BYTES.load(Ordering::SeqCst), 800);
        assert_eq!(
            orphan_pool_metrics_snapshot(),
            OrphanPoolMetricsSnapshot {
                live_blocks: 1,
                live_bytes: 800
            }
        );

        drop(pool_a);
        drop(pool_b);
        assert_eq!(
            orphan_pool_metrics_snapshot(),
            OrphanPoolMetricsSnapshot {
                live_blocks: 0,
                live_bytes: 0
            },
            "dropping all sessions must drain live observability"
        );
        reset_orphan_pool_metrics_for_test();
    }

    #[test]
    fn runtime_payload_cap_rejects_unknown_commands() {
        // Known commands must have a non-zero cap.
        assert!(runtime_payload_cap("version") > 0);
        assert!(runtime_payload_cap(MESSAGE_BLOCK) > 0);
        assert!(runtime_payload_cap(MESSAGE_TX) > 0);
        assert!(runtime_payload_cap(MESSAGE_INV) > 0);
        assert!(runtime_payload_cap(MESSAGE_GETBLOCKS) > 0);
        assert!(runtime_payload_cap(MESSAGE_GETDATA) > 0);
        assert!(runtime_payload_cap(MESSAGE_ADDR) > 0);
        assert!(runtime_payload_cap(MESSAGE_SENDCMPCT) == SENDCMPCT_PAYLOAD_BYTES);

        // headers gets an explicit cap matching MAX_HEADERS_PAYLOAD_BYTES.
        assert_eq!(runtime_payload_cap("headers"), MAX_HEADERS_PAYLOAD_BYTES);
        const { assert!(MAX_HEADERS_PAYLOAD_BYTES > 0) };

        // Unknown/garbage commands are rejected at the envelope stage.
        assert_eq!(runtime_payload_cap("unknown"), 0);
        assert_eq!(runtime_payload_cap("malicious_cmd"), 0);
        assert_eq!(runtime_payload_cap(""), 0);
    }

    #[test]
    fn sendcmpct_live_dispatch_records_peer_mode() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let (stream, _) = listener.accept().expect("accept");
        let mut session =
            PeerSession::new(stream, default_peer_runtime_config("devnet", 8)).expect("session");
        let mut engine = test_sync_engine_with_genesis();

        let outcome = session
            .collect_live_responses(
                WireMessage {
                    command: MESSAGE_SENDCMPCT.to_string(),
                    payload: sendcmpct_runtime_payload(2, COMPACT_RELAY_VERSION),
                },
                &mut engine,
                None,
            )
            .expect("current sendcmpct");
        assert!(outcome.responses.is_empty());
        assert_eq!(
            session.remote_compact_mode,
            CompactModeSnapshot {
                mode: 2,
                version: COMPACT_RELAY_VERSION
            }
        );

        let second_listener = TcpListener::bind("127.0.0.1:0").expect("bind second");
        let second_client = TcpStream::connect(second_listener.local_addr().expect("second addr"))
            .expect("connect second");
        let (second_stream, _) = second_listener.accept().expect("accept second");
        let mut second_session =
            PeerSession::new(second_stream, default_peer_runtime_config("devnet", 8))
                .expect("second session");
        second_session
            .collect_live_responses(
                WireMessage {
                    command: MESSAGE_SENDCMPCT.to_string(),
                    payload: sendcmpct_runtime_payload(1, COMPACT_RELAY_VERSION),
                },
                &mut engine,
                None,
            )
            .expect("second peer sendcmpct");
        assert_eq!(
            session.remote_compact_mode,
            CompactModeSnapshot {
                mode: 2,
                version: COMPACT_RELAY_VERSION
            }
        );
        assert_eq!(
            second_session.remote_compact_mode,
            CompactModeSnapshot {
                mode: 1,
                version: COMPACT_RELAY_VERSION
            }
        );

        let err = session
            .collect_live_responses(
                WireMessage {
                    command: MESSAGE_SENDCMPCT.to_string(),
                    payload: sendcmpct_runtime_payload(3, COMPACT_RELAY_VERSION + 1),
                },
                &mut engine,
                None,
            )
            .expect_err("future version must fail before future-mode validation");
        assert!(err
            .to_string()
            .contains("unsupported compact relay version"));
        assert_eq!(
            session.remote_compact_mode,
            CompactModeSnapshot {
                mode: 2,
                version: COMPACT_RELAY_VERSION
            }
        );

        let err = second_session
            .collect_live_responses(
                WireMessage {
                    command: MESSAGE_SENDCMPCT.to_string(),
                    payload: vec![1, 2],
                },
                &mut engine,
                None,
            )
            .expect_err("short sendcmpct payload must fail");
        assert!(err.to_string().contains("sendcmpct payload width mismatch"));
        assert_eq!(
            second_session.remote_compact_mode,
            CompactModeSnapshot {
                mode: 1,
                version: COMPACT_RELAY_VERSION
            }
        );
        let err = second_session
            .collect_live_responses(
                WireMessage {
                    command: MESSAGE_SENDCMPCT.to_string(),
                    payload: sendcmpct_runtime_payload(3, COMPACT_RELAY_VERSION),
                },
                &mut engine,
                None,
            )
            .expect_err("current-version unknown mode must fail");
        assert!(err.to_string().contains("unsupported compact relay mode"));
        assert_eq!(
            second_session.remote_compact_mode,
            CompactModeSnapshot {
                mode: 1,
                version: COMPACT_RELAY_VERSION
            }
        );

        session
            .collect_live_responses(
                WireMessage {
                    command: MESSAGE_SENDCMPCT.to_string(),
                    payload: sendcmpct_runtime_payload(0, COMPACT_RELAY_VERSION),
                },
                &mut engine,
                None,
            )
            .expect("sendcmpct mode downgrade to disabled");
        assert_eq!(
            session.remote_compact_mode,
            CompactModeSnapshot {
                mode: 0,
                version: COMPACT_RELAY_VERSION
            }
        );
        assert_eq!(
            second_session.remote_compact_mode,
            CompactModeSnapshot {
                mode: 1,
                version: COMPACT_RELAY_VERSION
            }
        );
        drop(second_client);
        drop(client);
    }

    #[test]
    fn handshake_timeout_budget_matches_go_default() {
        assert_eq!(
            handshake_timeout_budget(DEFAULT_READ_DEADLINE),
            Duration::from_secs(10)
        );
        assert_eq!(
            handshake_timeout_budget(Duration::from_millis(100)),
            Duration::from_millis(100)
        );
    }

    #[test]
    fn handshake_times_out_on_silent_peer() {
        // perform_version_handshake sets read_timeout before reading.
        // A slowloris peer that never sends data must trigger a timeout
        // error instead of hanging indefinitely.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_millis(100);
            let local = test_version_payload(0);
            let chain_id = devnet_genesis_chain_id();
            let genesis = devnet_genesis_block_bytes();
            let genesis_hash = block_hash(&genesis[..BLOCK_HEADER_BYTES]).expect("genesis hash");
            let result = perform_version_handshake(stream, cfg, local, chain_id, genesis_hash);
            let err = match result {
                Err(e) => e,
                Ok(_) => panic!("handshake must time out on silent peer"),
            };
            // Timeout manifests as WouldBlock or TimedOut depending on OS.
            assert!(
                matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
                "unexpected error kind: {:?}",
                err.kind()
            );
        });

        // Connect but never send anything — simulates a slowloris peer.
        let _client = TcpStream::connect(addr).expect("connect");
        server.join().expect("server join");
    }

    #[test]
    fn peer_session_zero_read_deadline_normalizes_to_default() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(0);
            let session = PeerSession::new(stream, cfg).expect("session");
            assert_eq!(session.read_deadline(), DEFAULT_READ_DEADLINE);
        });

        let _client = TcpStream::connect(addr).expect("connect");
        server.join().expect("server join");
    }

    #[test]
    fn poll_read_ready_prefetches_without_consuming_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let header =
                build_envelope_header(network_magic("devnet"), "ping", &[]).expect("ping header");
            stream.write_all(&header).expect("write ping");
            stream.flush().expect("flush ping");
        });

        let stream = TcpStream::connect(addr).expect("connect");
        let mut session =
            PeerSession::new(stream, default_peer_runtime_config("devnet", 8)).expect("session");
        assert!(session
            .poll_read_ready(Duration::from_secs(1))
            .expect("first poll"));
        assert!(session
            .poll_read_ready(Duration::from_secs(1))
            .expect("second poll reuses prefetched byte"));
        let msg = session.read_message().expect("read prefetched ping");
        assert_eq!(msg.command, "ping");
        assert!(msg.payload.is_empty());

        server.join().expect("server join");
    }

    #[test]
    fn run_message_loop_disconnects_unknown_command_without_ban() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8))
                .expect("session");
            let err = session
                .run_message_loop()
                .expect_err("unknown command must disconnect");
            let state = session.state();
            (err.kind(), err.to_string(), state)
        });

        let mut client = TcpStream::connect(addr).expect("connect");
        let msg = WireMessage {
            command: "weird".to_string(),
            payload: Vec::new(),
        };
        let header = build_envelope_header(network_magic("devnet"), &msg.command, &msg.payload)
            .expect("header");
        client.write_all(&header).expect("write header");
        client.flush().expect("flush");

        let (kind, err, state) = server.join().expect("server join");
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(err.contains("unknown message type: weird"), "got: {err}");
        assert_eq!(
            state.ban_score, 0,
            "unknown command should disconnect, not ban"
        );
        assert_eq!(state.last_error, "unknown command: weird");
    }

    // Regression for Q-IMPL-RUST-P2P-DISPATCHER-TRUTH-01 (D.2).
    // Proves run_block_sync_loop dispatches every inbound command through the
    // single live truth (collect_live_responses) rather than a duplicated
    // inline match: a ping received inside the sync loop must produce a pong
    // reply — that reply arm lives in collect_live_responses, so receiving it
    // here means dispatch actually routed through the consolidated path.
    #[test]
    fn run_block_sync_loop_dispatches_via_collect_live_responses() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8))
                .expect("session");
            // Force the loop to stay live past the initial request_blocks write.
            session.peer.remote_version.best_height = 2;
            let mut engine = test_sync_engine_with_genesis();
            let err = session
                .run_block_sync_loop(&mut engine)
                .expect_err("unknown command terminates the sync loop");
            (err.kind(), err.to_string())
        });

        let mut client = TcpStream::connect(addr).expect("connect");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set_read_timeout");

        // Consume the initial bootstrap getblocks the sync loop sends first.
        let bootstrap =
            read_message_from(&mut client, network_magic("devnet"), MAX_RELAY_MSG_BYTES)
                .expect("read bootstrap getblocks");
        assert_eq!(bootstrap.command, MESSAGE_GETBLOCKS);

        // Send a ping — if dispatch truly routes through collect_live_responses,
        // the session will reply with a pong.
        let ping_header =
            build_envelope_header(network_magic("devnet"), "ping", &[]).expect("ping header");
        client.write_all(&ping_header).expect("write ping");
        client.flush().expect("flush ping");

        let pong = read_message_from(&mut client, network_magic("devnet"), MAX_RELAY_MSG_BYTES)
            .expect("read pong");
        assert_eq!(pong.command, "pong");
        assert!(pong.payload.is_empty(), "pong must have empty payload");

        // Terminate the loop deterministically through the shared unknown-command arm.
        let weird_header =
            build_envelope_header(network_magic("devnet"), "weird", &[]).expect("weird header");
        client.write_all(&weird_header).expect("write weird");
        client.flush().expect("flush weird");

        let (kind, err) = server.join().expect("server join");
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(err.contains("unknown message type: weird"), "got: {err}");
    }

    /// RUB-178 / GitHub #1438 introduced this production-path
    /// reachability proof for the canonical TxPool admission seam in
    /// `PeerRelayContext`; RUB-173 / GitHub #1420 paired the seam swap
    /// to `add_tx_with_source(_, _, _, _, TxSource::Remote)` with an
    /// `entry_source` parity update from `Local` to `Remote`.
    ///
    /// Proof assertion: the `assert_eq!(pool_guard.entry_source(&txid),
    /// Some(crate::txpool::TxSource::Remote), ...)` near the end of
    /// this test is the regression anchor that breaks if the seam
    /// regresses to legacy `pool.admit` (Local) or any other source
    /// variant.
    ///
    /// Why this is not helper-only:
    ///
    ///   - The test does NOT call `add_tx_with_source(...)` or
    ///     `pool.admit(...)` directly. Admission happens through
    ///     `PeerSession::collect_live_responses`, the exact public
    ///     method used by the production message loop in
    ///     `clients/rust/crates/rubin-node/src/p2p_service.rs::handle_peer`
    ///     (see the `session.collect_live_responses(msg, &mut engine,
    ///     Some(&relay_ctx))` call in `handle_peer`'s message-loop body).
    ///   - The test constructs a real `PeerRelayContext` whose `tx_pool`
    ///     field uses the same `Mutex<TxPool>` shape that
    ///     `p2p_service.rs::handle_peer` constructs from
    ///     `&shared.tx_pool` (the canonical pool that already drives the
    ///     production block-apply cleanup path).
    ///   - The canonical pool side effect is asserted from outside the
    ///     dispatch: after `collect_live_responses` returns,
    ///     `tx_pool.lock()` is taken and `pool.contains(&txid)` plus
    ///     `pool.entry_source(&txid)` are checked. The seam is the
    ///     only code path that could put the txid there in this scenario.
    ///   - Source classification: `entry_source(&txid)` is asserted to
    ///     equal `Some(TxSource::Remote)` per RUB-173 / GitHub #1420.
    ///     This matches Go's `Mempool.AddRemoteTx` provenance and breaks
    ///     if the seam regresses to legacy `pool.admit` (Local) or any
    ///     other source variant.
    #[test]
    fn collect_live_responses_message_tx_admits_through_canonical_pool_seam() {
        use std::collections::HashMap;
        use std::sync::Mutex;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8))
                .expect("session");

            // Build a sync engine + chain state that admits a single
            // floor-compliant signed P2PK tx (mirrors the existing
            // tx_relay test pattern, intentionally — same fixture so the
            // production tx_relay handle_received_tx leg returns
            // `Relayed` and the canonical seam fires).
            let (chain_state, tx_bytes, _unused) =
                signed_conflicting_p2pk_state_and_txs(20_000, 10, 9);
            let mut sync_cfg = crate::sync::default_sync_config(
                None,
                crate::genesis::devnet_genesis_chain_id(),
                None,
            );
            sync_cfg.core_ext_deployments = rubin_consensus::CoreExtDeploymentProfiles::empty();
            let mut engine =
                crate::sync::SyncEngine::new(chain_state, None, sync_cfg).expect("sync engine");

            // Production analogue of `shared.relay_state` /
            // `shared.peer_manager` / `shared.peer_outboxes` /
            // `shared.tx_pool` — same handles
            // `clients/rust/crates/rubin-node/src/p2p_service.rs` threads
            // into `PeerRelayContext`.
            let relay_state = crate::tx_relay::TxRelayState::new();
            let peer_manager = PeerManager::new(default_peer_runtime_config("devnet", 64));
            let _ = peer_manager.add_peer(PeerState {
                addr: "other:8333".to_string(),
                ..Default::default()
            });
            let peer_outboxes: Mutex<HashMap<String, crate::tx_relay::PeerOutbox>> =
                Mutex::new(HashMap::new());
            peer_outboxes.lock().unwrap().insert(
                "sender:8333".to_string(),
                crate::tx_relay::PeerOutbox::default(),
            );
            peer_outboxes.lock().unwrap().insert(
                "other:8333".to_string(),
                crate::tx_relay::PeerOutbox::default(),
            );
            let canonical_tx_pool: Mutex<TxPool> = Mutex::new(TxPool::new());
            let da_relay_state = Mutex::new(
                crate::da_relay::DaRelayState::new(crate::da_relay::DaRelayCaps::default())
                    .expect("valid DA relay caps"),
            );

            let relay_ctx = PeerRelayContext {
                relay_state: &relay_state,
                peer_manager: &peer_manager,
                local_addr: "local:8333",
                peer_registered_addr: "sender:8333",
                peer_writers: &peer_outboxes,
                tx_pool: &canonical_tx_pool,
                da_relay: &da_relay_state,
            };

            let msg = WireMessage {
                command: MESSAGE_TX.to_string(),
                payload: tx_bytes.clone(),
            };

            let _ = session
                .collect_live_responses(msg, &mut engine, Some(&relay_ctx))
                .expect("collect_live_responses MESSAGE_TX must succeed for floor-compliant tx");
            assert!(
                session.take_pending_da_relay_staging().is_none(),
                "non-DA MESSAGE_TX must not queue DA relay staging work"
            );

            let (_, txid, _, _consumed) = parse_tx(&tx_bytes).expect("parse tx for txid");

            // 1) production-path reachability: the canonical pool side
            //    effect is observable AFTER `collect_live_responses`
            //    returns. No direct `pool.admit(...)` call from the
            //    test reached this state; the only path is through
            //    `collect_live_responses::MESSAGE_TX` -> tx_relay::Relayed
            //    -> ctx.tx_pool seam.
            let pool_guard = canonical_tx_pool.lock().expect("pool lock");
            assert!(
                pool_guard.contains(&txid),
                "canonical TxPool must contain the txid after MESSAGE_TX dispatch — \
                 the seam is the only code path that could place it there in this test"
            );
            // RUB-173 / GitHub #1420 source-provenance pin: the seam
            // uses `add_tx_with_source(_, _, _, _, TxSource::Remote)`
            // which records `Remote` on `TxPoolEntry.source` to match
            // Go's `Mempool.AddRemoteTx` provenance. Proof assertion:
            // the `assert_eq!` below comparing
            // `pool_guard.entry_source(&txid)` against
            // `Some(crate::txpool::TxSource::Remote)` is the parity
            // anchor; any regression that drops back to legacy
            // `pool.admit` (Local) or any other source variant
            // produces a test failure here.
            assert_eq!(
                pool_guard.entry_source(&txid),
                Some(crate::txpool::TxSource::Remote),
                "RUB-173 / GitHub #1420 seam uses \
                 add_tx_with_source(_, _, _, _, TxSource::Remote) — \
                 peer-relayed txs must record Remote provenance to match \
                 Go AddRemoteTx"
            );
            drop(pool_guard);

            // 2) relay-cache-only path remains separate: tx_relay's
            //    relay_state still records the tx as well. This proves
            //    the seam is additive on top of the relay-only path,
            //    not a replacement of it.
            assert!(
                relay_state.tx_seen.has(&txid),
                "tx_relay relay-cache `tx_seen` must still record the tx"
            );
            assert!(
                relay_state.relay_pool.has(&txid),
                "tx_relay relay-cache `relay_pool` must still record the tx"
            );
        });

        let _client = TcpStream::connect(addr).expect("connect");
        server.join().expect("server join");
    }

    #[test]
    #[rustfmt::skip]
    fn collect_live_responses_message_tx_stages_da_after_remote_admission() {
        use std::collections::HashMap; use std::sync::Mutex;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind"); let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept"); let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8)).expect("session");
            let (chain_state, admitted_tx, conflicting_tx, bad_tx, da_id, conflict_da_id, bad_da_id) = signed_conflicting_da_chunk_state_and_txs();
            let mut sync_cfg = crate::sync::default_sync_config(None, crate::genesis::devnet_genesis_chain_id(), None);
            sync_cfg.core_ext_deployments = rubin_consensus::CoreExtDeploymentProfiles::empty();
            let mut engine = crate::sync::SyncEngine::new(chain_state, None, sync_cfg).expect("sync engine"); let relay_state = crate::tx_relay::TxRelayState::new(); let peer_manager = PeerManager::new(default_peer_runtime_config("devnet", 64)); let peer_outboxes: Mutex<HashMap<String, crate::tx_relay::PeerOutbox>> = Mutex::new(HashMap::new()); let canonical_tx_pool = Mutex::new(TxPool::new()); let da_relay = Mutex::new(crate::da_relay::DaRelayState::new(crate::da_relay::DaRelayCaps::default()).expect("valid DA relay caps"));
            let relay_ctx = PeerRelayContext { relay_state: &relay_state, peer_manager: &peer_manager, local_addr: "local:8333", peer_registered_addr: "sender:8333", peer_writers: &peer_outboxes, tx_pool: &canonical_tx_pool, da_relay: &da_relay };
            let (_, bad_txid, _, _) = parse_tx(&bad_tx).expect("parse bad DA tx");
            session.collect_live_responses(WireMessage { command: MESSAGE_TX.to_string(), payload: bad_tx }, &mut engine, Some(&relay_ctx)).expect("sub-threshold malformed DA tx is peer-neutral"); assert_eq!(session.state().ban_score, 10); assert!(!relay_state.tx_seen.has(&bad_txid)); assert!(session.take_pending_da_relay_staging().is_none()); assert_eq!(da_relay.lock().unwrap().test_record_summary(bad_da_id), None);
            let (_, txid, _, _) = parse_tx(&admitted_tx).expect("parse admitted DA tx");
            canonical_tx_pool.lock().unwrap().add_tx_with_source(&admitted_tx, &engine.chain_state, engine.block_store.as_ref(), engine.cfg.chain_id, crate::txpool::TxSource::Local).expect("pre-admit DA tx"); assert!(relay_state.tx_seen.add(txid)); session.collect_live_responses(WireMessage { command: MESSAGE_TX.to_string(), payload: admitted_tx.clone() }, &mut engine, Some(&relay_ctx)).expect("already-seen DA tx dispatch"); assert_eq!(canonical_tx_pool.lock().unwrap().entry_source(&txid), Some(crate::txpool::TxSource::Local)); assert_eq!(da_relay.lock().unwrap().test_record_summary(da_id), None); let pending_da_staging = session.take_pending_da_relay_staging(); assert!(pending_da_staging.is_some()); session.apply_pending_da_relay_staging(&da_relay, pending_da_staging); assert_eq!(da_relay.lock().unwrap().test_record_summary(da_id), Some((false, 1, admitted_tx.len() as u64)));
            let (mut bad_seen_tx, _, _, _) = parse_tx(&admitted_tx).expect("parse already-seen DA tx"); bad_seen_tx.da_payload = b"bad already-seen da chunk".to_vec(); let bad_seen_bytes = rubin_consensus::marshal_tx(&bad_seen_tx).expect("marshal bad already-seen DA tx"); assert_eq!(parse_tx(&bad_seen_bytes).unwrap().1, txid); session.collect_live_responses(WireMessage { command: MESSAGE_TX.to_string(), payload: bad_seen_bytes }, &mut engine, Some(&relay_ctx)).expect("already-seen bad DA chunk is sub-threshold peer-neutral"); assert_eq!(session.state().ban_score, 20); assert_eq!(canonical_tx_pool.lock().unwrap().tx_by_id(&txid), Some(admitted_tx.clone())); assert!(session.take_pending_da_relay_staging().is_none()); assert_eq!(da_relay.lock().unwrap().test_record_summary(da_id), Some((false, 1, admitted_tx.len() as u64)));
            let (_, conflicting_txid, _, _) = parse_tx(&conflicting_tx).expect("parse conflicting DA tx");
            let (mut bad_pool_tx, _, _, _) = parse_tx(&conflicting_tx).expect("parse bad-pool DA tx"); bad_pool_tx.da_payload = b"bad pool-resident da chunk".to_vec(); let bad_pool_bytes = rubin_consensus::marshal_tx(&bad_pool_tx).expect("marshal bad-pool DA tx"); assert_eq!(parse_tx(&bad_pool_bytes).unwrap().1, conflicting_txid); let local_relay_state = crate::tx_relay::TxRelayState::new(); let local_peer_outboxes: Mutex<HashMap<String, crate::tx_relay::PeerOutbox>> = Mutex::new(HashMap::new()); assert!(crate::tx_relay::announce_tx(&bad_pool_bytes, crate::txpool::RelayTxMetadata { fee: 1, size: bad_pool_bytes.len() }, &local_relay_state, &peer_manager, "local:8333", &local_peer_outboxes).is_err()); assert!(!local_relay_state.tx_seen.has(&conflicting_txid)); canonical_tx_pool.lock().unwrap().inject_test_entry(conflicting_txid, bad_pool_bytes.clone()); assert!(relay_state.tx_seen.add(conflicting_txid)); session.collect_live_responses(WireMessage { command: MESSAGE_TX.to_string(), payload: bad_pool_bytes }, &mut engine, Some(&relay_ctx)).expect("same bad pool bytes skip precheck but not staging hash check"); let pending_same_bad_pool = session.take_pending_da_relay_staging(); assert!(pending_same_bad_pool.is_some()); session.apply_pending_da_relay_staging(&da_relay, pending_same_bad_pool); assert_eq!(da_relay.lock().unwrap().test_record_summary(conflict_da_id), None);
            session.collect_live_responses(WireMessage { command: MESSAGE_TX.to_string(), payload: conflicting_tx }, &mut engine, Some(&relay_ctx)).expect("valid peer variant does not bless bad pool bytes"); let pending_bad_pool = session.take_pending_da_relay_staging(); assert!(pending_bad_pool.is_some()); session.apply_pending_da_relay_staging(&da_relay, pending_bad_pool); assert_eq!(da_relay.lock().unwrap().test_record_summary(conflict_da_id), None);
        });
        let _client = TcpStream::connect(addr).expect("connect"); server.join().expect("server join");
    }

    /// RUB-178 smoke test for the `relay_ctx = None` branch of
    /// `MESSAGE_TX` dispatch through the production dispatcher
    /// `collect_live_responses`.
    ///
    /// The seam is structurally gated by `PeerRelayContext` itself:
    /// `ctx.tx_pool` is a field of `PeerRelayContext`, so absence of
    /// the context makes the seam unreachable through the type system,
    /// not through a runtime check that this test could observe. What
    /// this test DOES pin:
    ///
    ///   - `collect_live_responses(MESSAGE_TX, _, None)` returns `Ok`
    ///     with an empty `LiveMessageOutcome` (no responses, empty
    ///     `tx_pool_cleanup`, no panic, no error).
    ///   - The dispatch does NOT depend on relay_ctx for parse/cap
    ///     handling — the `MESSAGE_TX` arm simply skips the
    ///     relay+canonical work block when `relay_ctx` is None.
    ///
    /// What this test does NOT pin: it does not observe
    /// absence-of-admission on a canonical pool, because there is no
    /// canonical pool reachable in this configuration — the type
    /// system makes the seam unreachable. The seam-gated invariant
    /// is enforced by the `PeerRelayContext.tx_pool: &Mutex<TxPool>`
    /// field's non-optionality, not by a runtime check.
    #[test]
    fn collect_live_responses_message_tx_without_relay_ctx_does_not_admit() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8))
                .expect("session");

            let (chain_state, tx_bytes, _unused) =
                signed_conflicting_p2pk_state_and_txs(20_000, 10, 9);
            let mut sync_cfg = crate::sync::default_sync_config(
                None,
                crate::genesis::devnet_genesis_chain_id(),
                None,
            );
            sync_cfg.core_ext_deployments = rubin_consensus::CoreExtDeploymentProfiles::empty();
            let mut engine =
                crate::sync::SyncEngine::new(chain_state, None, sync_cfg).expect("sync engine");

            let msg = WireMessage {
                command: MESSAGE_TX.to_string(),
                payload: tx_bytes,
            };

            // No relay_ctx -> the seam never fires.
            let outcome = session
                .collect_live_responses(msg, &mut engine, None)
                .expect("MESSAGE_TX without relay_ctx is a no-op");
            assert!(outcome.responses.is_empty());
            assert!(outcome.tx_pool_cleanup.is_empty());
        });

        let _client = TcpStream::connect(addr).expect("connect");
        server.join().expect("server join");
    }

    /// RUB-178 / GitHub #1438: when `ctx.tx_pool` lock is poisoned,
    /// the seam must produce an explicit signal on
    /// `self.peer.last_error` rather than silently swallowing the
    /// error. This matches the production precedent in
    /// `clients/rust/crates/rubin-node/src/devnet_rpc.rs`'s
    /// `handle_submit_tx` (which surfaces
    /// `TxPoolAdmitErrorKind::Unavailable`) and `handle_mine_next`
    /// (which returns 503).
    ///
    /// Proof assertion: the `assert!` calls below comparing
    /// `session.state().last_error` to the poison-signal substring
    /// and confirming `relay_state` still recorded the tx are the
    /// regression anchors for this case.
    #[test]
    fn collect_live_responses_message_tx_signals_on_canonical_pool_poison() {
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut session = PeerSession::new(stream, default_peer_runtime_config("devnet", 8))
                .expect("session");

            let (chain_state, tx_bytes, _unused) =
                signed_conflicting_p2pk_state_and_txs(20_000, 10, 9);
            let mut sync_cfg = crate::sync::default_sync_config(
                None,
                crate::genesis::devnet_genesis_chain_id(),
                None,
            );
            sync_cfg.core_ext_deployments = rubin_consensus::CoreExtDeploymentProfiles::empty();
            let mut engine =
                crate::sync::SyncEngine::new(chain_state, None, sync_cfg).expect("sync engine");

            let relay_state = crate::tx_relay::TxRelayState::new();
            let peer_manager = PeerManager::new(default_peer_runtime_config("devnet", 64));
            let _ = peer_manager.add_peer(PeerState {
                addr: "other:8333".to_string(),
                ..Default::default()
            });
            let peer_outboxes: Mutex<HashMap<String, crate::tx_relay::PeerOutbox>> =
                Mutex::new(HashMap::new());
            peer_outboxes.lock().unwrap().insert(
                "sender:8333".to_string(),
                crate::tx_relay::PeerOutbox::default(),
            );
            peer_outboxes.lock().unwrap().insert(
                "other:8333".to_string(),
                crate::tx_relay::PeerOutbox::default(),
            );

            // Poison the canonical TxPool Mutex by panicking inside a
            // thread that holds the lock. After join, the Mutex is
            // permanently poisoned for any subsequent `.lock()` call —
            // mirrors the production failure mode where a panic during
            // pool mutation leaves a poisoned shared handle.
            let canonical_tx_pool: Arc<Mutex<TxPool>> = Arc::new(Mutex::new(TxPool::new()));
            let poison_pool = Arc::clone(&canonical_tx_pool);
            let _ = thread::spawn(move || {
                let _guard = poison_pool.lock().unwrap();
                panic!("intentional poison for RUB-178 poison-signal test");
            })
            .join();
            assert!(
                canonical_tx_pool.is_poisoned(),
                "Mutex must be poisoned before exercising the seam"
            );
            let da_relay_state = Mutex::new(
                crate::da_relay::DaRelayState::new(crate::da_relay::DaRelayCaps::default())
                    .expect("valid DA relay caps"),
            );

            let relay_ctx = PeerRelayContext {
                relay_state: &relay_state,
                peer_manager: &peer_manager,
                local_addr: "local:8333",
                peer_registered_addr: "sender:8333",
                peer_writers: &peer_outboxes,
                tx_pool: &canonical_tx_pool,
                da_relay: &da_relay_state,
            };

            let msg = WireMessage {
                command: MESSAGE_TX.to_string(),
                payload: tx_bytes.clone(),
            };

            // Dispatch must NOT propagate the poison as an io::Error —
            // the relay-only path is preserved per issue failure_modes.
            let _ = session
                .collect_live_responses(msg, &mut engine, Some(&relay_ctx))
                .expect("dispatch must succeed even when canonical pool is poisoned");

            // 1) explicit poison signal on peer state — refutes the
            //    silent-swallow operational hazard the bot reviewer
            //    flagged on PR #1455.
            let observed_last_error = session.state().last_error;
            assert!(
                observed_last_error.contains("canonical tx_pool poisoned"),
                "peer.last_error must signal the poisoned pool; got: {observed_last_error:?}"
            );

            // 2) relay-cache-only path remains separate and intact —
            //    relay_state still admitted the tx via tx_relay's
            //    own RelayTxPool, even though canonical admission was
            //    skipped.
            let (_, txid, _, _consumed) = parse_tx(&tx_bytes).expect("parse tx for txid");
            assert!(
                relay_state.tx_seen.has(&txid),
                "tx_relay relay-cache `tx_seen` must still record the tx"
            );
            assert!(
                relay_state.relay_pool.has(&txid),
                "tx_relay relay-cache `relay_pool` must still record the tx"
            );
        });

        let _client = TcpStream::connect(addr).expect("connect");
        server.join().expect("server join");
    }
}
