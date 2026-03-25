use std::collections::HashMap;
use std::io::{self, Cursor, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use rubin_consensus::{
    block_hash,
    constants::{MAX_BLOCK_BYTES, MAX_RELAY_MSG_BYTES},
    parse_block_bytes,
};
use sha3::{Digest, Sha3_256};

use crate::sync::SyncEngine;

/// Maximum reasonable best_height delta before clamping peer claims.
/// Prevents malicious peers from forcing unnecessary sync with absurdly high values.
const MAX_BEST_HEIGHT_DELTA: u64 = 100_000;
use crate::sync_reorg::PARENT_BLOCK_NOT_FOUND_ERR;

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

static GLOBAL_ORPHAN_TOTAL_BYTES: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static GLOBAL_ORPHAN_BYTE_LIMIT_OVERRIDE: AtomicUsize = AtomicUsize::new(0);

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
    pub peer_writers: &'a std::sync::Mutex<
        HashMap<String, std::sync::Arc<std::sync::Mutex<std::net::TcpStream>>>,
    >,
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
}

pub struct PeerManager {
    peers: RwLock<HashMap<String, PeerState>>,
    cfg: PeerRuntimeConfig,
}

pub fn default_peer_runtime_config(network: &str, max_peers: usize) -> PeerRuntimeConfig {
    let max_peers = if max_peers == 0 { 64 } else { max_peers };
    PeerRuntimeConfig {
        network: network.to_string(),
        max_peers,
        read_deadline: DEFAULT_READ_DEADLINE,
        write_deadline: DEFAULT_WRITE_DEADLINE,
        ban_threshold: DEFAULT_BAN_THRESHOLD,
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
    /// Clone the underlying TcpStream for use as a peer writer in tx relay.
    pub fn try_clone_stream(&self) -> io::Result<TcpStream> {
        self.stream.try_clone()
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
        })
    }

    pub fn state(&self) -> PeerState {
        self.peer.clone()
    }

    pub fn read_message(&mut self) -> io::Result<WireMessage> {
        self.stream
            .set_read_timeout(Some(self.cfg.read_deadline))
            .map_err(io::Error::other)?;
        read_message_from(
            &mut self.stream,
            network_magic(&self.cfg.network),
            MAX_RELAY_MSG_BYTES,
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
        let header =
            build_envelope_header(network_magic(&self.cfg.network), &msg.command, &msg.payload)?;
        self.stream.write_all(&header)?;
        if !msg.payload.is_empty() {
            self.stream.write_all(&msg.payload)?;
        }
        self.stream.flush()?;
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
            match msg.command.as_str() {
                MESSAGE_INV => {
                    let requests = self.handle_inv(&msg.payload, sync_engine, None)?;
                    if !requests.is_empty() {
                        let payload = encode_inventory_vectors(&requests)?;
                        self.write_message(&WireMessage {
                            command: MESSAGE_GETDATA.to_string(),
                            payload,
                        })?;
                    }
                }
                MESSAGE_GETDATA => {
                    self.respond_to_getdata(&msg.payload, sync_engine, None)?;
                }
                MESSAGE_GETBLOCKS => {
                    let items = self.handle_getblocks(&msg.payload, sync_engine)?;
                    if items.is_empty() {
                        continue;
                    }
                    self.write_message(&WireMessage {
                        command: MESSAGE_INV.to_string(),
                        payload: encode_inventory_vectors(&items)?,
                    })?;
                }
                MESSAGE_BLOCK => {
                    self.handle_block(&msg.payload, sync_engine)?;
                    self.request_more_blocks_if_behind(sync_engine)?;
                }
                MESSAGE_TX | "headers" | "pong" => {}
                "ping" => {
                    self.write_message(&WireMessage {
                        command: "pong".to_string(),
                        payload: Vec::new(),
                    })?;
                }
                MESSAGE_GETADDR => {
                    self.write_message(&WireMessage {
                        command: MESSAGE_ADDR.to_string(),
                        payload: marshal_empty_addr_payload(),
                    })?;
                }
                MESSAGE_ADDR => {
                    let _ = unmarshal_addr_payload(&msg.payload)?;
                }
                other => {
                    self.peer.last_error = format!("unknown command: {other}");
                    return Err(unknown_command_err(other));
                }
            }
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
    ) -> io::Result<Vec<WireMessage>> {
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
                    Ok(Vec::new())
                } else {
                    Ok(vec![WireMessage {
                        command: MESSAGE_GETDATA.to_string(),
                        payload: encode_inventory_vectors(&requests)?,
                    }])
                }
            }
            MESSAGE_GETDATA => self.collect_getdata_responses(
                &msg.payload,
                sync_engine,
                relay_ctx.map(|c| c.relay_state),
            ),
            MESSAGE_GETBLOCKS => {
                let items = self.handle_getblocks(&msg.payload, sync_engine)?;
                if items.is_empty() {
                    Ok(Vec::new())
                } else {
                    Ok(vec![WireMessage {
                        command: MESSAGE_INV.to_string(),
                        payload: encode_inventory_vectors(&items)?,
                    }])
                }
            }
            MESSAGE_BLOCK => {
                self.handle_block(&msg.payload, sync_engine)?;
                Ok(self
                    .prepare_block_request_if_behind(sync_engine)?
                    .into_iter()
                    .collect())
            }
            MESSAGE_TX => {
                if let Some(ctx) = relay_ctx {
                    crate::tx_relay::handle_received_tx(
                        &msg.payload,
                        ctx.relay_state,
                        ctx.peer_manager,
                        &self.peer.addr,
                        ctx.local_addr,
                        ctx.peer_writers,
                    )?;
                }
                Ok(Vec::new())
            }
            "headers" | "pong" => Ok(Vec::new()),
            "ping" => Ok(vec![WireMessage {
                command: "pong".to_string(),
                payload: Vec::new(),
            }]),
            MESSAGE_GETADDR => Ok(vec![WireMessage {
                command: MESSAGE_ADDR.to_string(),
                payload: marshal_empty_addr_payload(),
            }]),
            MESSAGE_ADDR => {
                let _ = unmarshal_addr_payload(&msg.payload)?;
                Ok(Vec::new())
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
    ) -> io::Result<()> {
        for response in self.collect_live_responses(msg, sync_engine, relay_ctx)? {
            self.write_message(&response)?;
        }
        Ok(())
    }

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
                MSG_BLOCK => {
                    if !sync_engine
                        .has_block(vector.hash)
                        .map_err(io::Error::other)?
                    {
                        requests.push(vector);
                    }
                }
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
    ) -> io::Result<()> {
        let parsed = parse_block_bytes(block_bytes).map_err(io::Error::other)?;
        let block_hash_bytes = block_hash(&parsed.header_bytes).map_err(io::Error::other)?;
        if sync_engine
            .has_block(block_hash_bytes)
            .map_err(io::Error::other)?
        {
            return Ok(());
        }
        if parsed.header.prev_block_hash != [0u8; 32]
            && !sync_engine
                .has_block(parsed.header.prev_block_hash)
                .map_err(io::Error::other)?
        {
            self.retain_or_resolve_orphan(
                block_hash_bytes,
                parsed.header.prev_block_hash,
                block_bytes,
                sync_engine,
            )?;
            return Ok(());
        }
        match sync_engine.apply_block_with_reorg(block_bytes, None, None) {
            Ok(summary) => {
                sync_engine.record_best_known_height(summary.block_height);
                self.resolve_orphans(block_hash_bytes, sync_engine)?;
            }
            Err(err) if is_parent_not_found_err(&err) => {
                return Err(io::Error::other(format!(
                    "unexpected missing-parent after precheck: {err}"
                )));
            }
            Err(err) => return Err(io::Error::other(err)),
        }
        Ok(())
    }

    fn retain_or_resolve_orphan(
        &mut self,
        block_hash: [u8; 32],
        parent_hash: [u8; 32],
        block_bytes: &[u8],
        sync_engine: &mut SyncEngine,
    ) -> io::Result<()> {
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
            self.resolve_orphans(parent_hash, sync_engine)?;
        }
        Ok(())
    }

    fn resolve_orphans(
        &mut self,
        parent_hash: [u8; 32],
        sync_engine: &mut SyncEngine,
    ) -> io::Result<()> {
        let mut ready = self.orphans.take_children(parent_hash);
        while let Some(child) = ready.pop() {
            match sync_engine.apply_block_with_reorg(&child.block_bytes, None, None) {
                Ok(summary) => {
                    sync_engine.record_best_known_height(summary.block_height);
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
        for item in decode_inventory_vectors(payload)? {
            match item.kind {
                MSG_BLOCK => {
                    if !sync_engine.has_block(item.hash).map_err(io::Error::other)? {
                        continue;
                    }
                    if responses.len() >= MAX_GETDATA_RESPONSE_BLOCKS {
                        break;
                    }
                    let block = sync_engine
                        .get_block_by_hash(item.hash)
                        .map_err(io::Error::other)?;
                    if total_bytes.saturating_add(block.len()) > MAX_GETDATA_RESPONSE_BYTES {
                        break;
                    }
                    total_bytes = total_bytes.saturating_add(block.len());
                    responses.push(WireMessage {
                        command: MESSAGE_BLOCK.to_string(),
                        payload: block,
                    });
                }
                MSG_TX => {
                    if let Some(rs) = relay_state {
                        if let Some(tx_bytes) = rs.relay_pool.get(&item.hash) {
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
            pre_handshake_payload_cap,
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
        runtime_payload_cap,
    )
}

fn read_message_from_with_payload_limit<R: Read>(
    reader: &mut R,
    expected_magic: [u8; 4],
    max_payload_bytes: u64,
    payload_cap: fn(&str) -> u64,
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

fn build_envelope_header(
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
        runtime_payload_cap,
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
    payload_cap: fn(&str) -> u64,
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
        MESSAGE_INV | MESSAGE_GETDATA | MESSAGE_GETBLOCKS => MAX_INVENTORY_PAYLOAD_BYTES,
        MESSAGE_ADDR => MAX_ADDR_PAYLOAD_BYTES,
        MESSAGE_BLOCK | MESSAGE_TX => MAX_BLOCK_BYTES,
        "headers" => MAX_HEADERS_PAYLOAD_BYTES,
        _ => 0,
    }
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

fn network_magic(network: &str) -> [u8; 4] {
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
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::blockstore::BlockStore;
    use crate::chainstate::ChainState;
    use crate::coinbase::{build_coinbase_tx, default_mine_address};
    use crate::genesis::{devnet_genesis_block_bytes, devnet_genesis_chain_id};
    use crate::test_helpers::coinbase_only_block_with_gen;
    use rubin_consensus::constants::{MAX_FUTURE_DRIFT, POW_LIMIT};
    use rubin_consensus::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
    use rubin_consensus::{
        block_hash, encode_compact_size, merkle_root_txids, parse_block_bytes, parse_tx,
        BLOCK_HEADER_BYTES,
    };
    use serde::Deserialize;

    static ORPHAN_POOL_TEST_LOCK: Mutex<()> = Mutex::new(());

    static NEXT_TEST_ROOT_ID: AtomicU64 = AtomicU64::new(1);

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
            assert!(engine.has_block(block1_hash).expect("block1 applied"));
            assert!(engine.has_block(block2_hash).expect("block2 resolved"));
            assert_eq!(engine.chain_state.height, 2);
        });

        let _client = TcpStream::connect(addr).expect("connect");
        server.join().expect("server join");
    }

    #[test]
    fn handle_block_surfaces_invalid_orphan_after_parent_arrives() {
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
            assert!(
                !engine
                    .has_block(block2_hash)
                    .expect("invalid orphan must not persist before parent"),
                "invalid orphan should remain memory-only until parent arrives"
            );
            let err = session
                .handle_block(&block1, &mut engine)
                .expect_err("invalid orphan should surface after parent arrives");

            assert_eq!(session.orphans.len(), 0, "invalid orphan should be dropped");
            assert_eq!(
                engine.chain_state.height, 1,
                "parent block must remain connected"
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
    }

    #[test]
    fn orphan_pool_replaces_local_oldest_when_global_limit_reached() {
        let _guard = ORPHAN_POOL_TEST_LOCK.lock().expect("lock orphan tests");
        GLOBAL_ORPHAN_TOTAL_BYTES.store(0, Ordering::SeqCst);
        GLOBAL_ORPHAN_BYTE_LIMIT_OVERRIDE.store(1024, Ordering::SeqCst);

        let mut pool = OrphanBlockPool::new(16, usize::MAX);
        let first = vec![7u8; 800];
        let second = vec![9u8; 800];

        pool.add([1u8; 32], [2u8; 32], &first, global_orphan_byte_limit());
        pool.add([3u8; 32], [4u8; 32], &second, global_orphan_byte_limit());

        assert_eq!(pool.len(), 1, "global cap should still permit local churn");
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
        GLOBAL_ORPHAN_BYTE_LIMIT_OVERRIDE.store(0, Ordering::SeqCst);
        assert_eq!(GLOBAL_ORPHAN_TOTAL_BYTES.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn orphan_pool_enforces_global_byte_limit_across_sessions() {
        let _guard = ORPHAN_POOL_TEST_LOCK.lock().expect("lock orphan tests");
        GLOBAL_ORPHAN_TOTAL_BYTES.store(0, Ordering::SeqCst);
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

        drop(pool_a);
        drop(pool_b);
        GLOBAL_ORPHAN_BYTE_LIMIT_OVERRIDE.store(0, Ordering::SeqCst);
        assert_eq!(GLOBAL_ORPHAN_TOTAL_BYTES.load(Ordering::SeqCst), 0);
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

        // headers gets an explicit cap matching MAX_HEADERS_PAYLOAD_BYTES.
        assert_eq!(runtime_payload_cap("headers"), MAX_HEADERS_PAYLOAD_BYTES);
        const { assert!(MAX_HEADERS_PAYLOAD_BYTES > 0) };

        // Unknown/garbage commands are rejected at the envelope stage.
        assert_eq!(runtime_payload_cap("unknown"), 0);
        assert_eq!(runtime_payload_cap("malicious_cmd"), 0);
        assert_eq!(runtime_payload_cap(""), 0);
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
}
