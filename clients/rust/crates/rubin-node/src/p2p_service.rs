use std::collections::HashSet;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use std::collections::HashMap;

use crate::p2p_runtime::{
    perform_version_handshake, LiveMessageOutcome, PeerManager, PeerRelayContext,
    PeerRuntimeConfig, VersionPayloadV1, WireMessage,
};
use crate::sync_reorg::TxPoolCleanupPlan;
use crate::tx_relay::{PeerOutbox, TxRelayState};
use crate::{SyncEngine, TxPool};

const ACCEPT_LOOP_SLEEP: Duration = Duration::from_millis(100);
const RECONNECT_LOOP_SLEEP: Duration = Duration::from_millis(250);
const RECONNECT_INTERVAL: Duration = Duration::from_secs(5);
const MIN_OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SERVICE_CLOSE_WAIT_SLEEP: Duration = Duration::from_millis(25);
const MAX_SHUTDOWN_WAIT: Duration = Duration::from_secs(30);
const LIVE_LOOP_IDLE_DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Hard ceiling on live worker threads to prevent resource exhaustion.
/// Set to 3× max_peers to allow transient overlap during handshake/teardown.
const WORKER_THREAD_MULTIPLIER: usize = 3;
/// Absolute cap on worker threads regardless of max_peers configuration.
/// Prevents resource exhaustion when max_peers is set very high (e.g., 4096).
const MAX_WORKER_THREADS: usize = 256;
/// Initial accept-error backoff, doubled on each consecutive error up to cap.
const ACCEPT_ERROR_BACKOFF_INIT: Duration = Duration::from_millis(100);
const ACCEPT_ERROR_BACKOFF_CAP: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct NodeP2PServiceConfig {
    pub bind_addr: String,
    pub bootstrap_peers: Vec<String>,
    pub runtime_cfg: PeerRuntimeConfig,
    pub peer_manager: Arc<PeerManager>,
    pub sync_engine: Arc<Mutex<SyncEngine>>,
    pub tx_pool: Arc<Mutex<TxPool>>,
    pub chain_id: [u8; 32],
    pub genesis_hash: [u8; 32],
}

pub struct RunningNodeP2PService {
    addr: String,
    stop: Arc<AtomicBool>,
    shared: SharedServiceState,
    accept_join: Option<JoinHandle<()>>,
    reconnect_join: Option<JoinHandle<()>>,
}

#[derive(Clone)]
struct SharedServiceState {
    stop: Arc<AtomicBool>,
    runtime_cfg: PeerRuntimeConfig,
    active_sessions: Arc<AtomicUsize>,
    worker_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    peer_manager: Arc<PeerManager>,
    sync_engine: Arc<Mutex<SyncEngine>>,
    tx_pool: Arc<Mutex<TxPool>>,
    bootstrap_peers: Arc<Vec<String>>,
    bootstrap_rotate_idx: Arc<AtomicUsize>,
    in_flight_dials: Arc<Mutex<HashSet<String>>>,
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
    relay_state: Arc<TxRelayState>,
    /// Outbound relay message queues per peer. Relay broadcasts enqueue
    /// serialized frames here; each peer's message loop drains its queue
    /// between reads, ensuring writes are serialized on the same TcpStream.
    peer_outboxes: Arc<Mutex<HashMap<String, PeerOutbox>>>,
    local_addr: String,
}

/// Validate peer address at config time using `ToSocketAddrs`.
/// Catches malformed addresses early rather than failing silently at runtime.
/// Rejects: missing port, unmatched brackets, bracketed non-IPv6, unresolvable hosts.
fn validate_peer_addr(addr: &str) -> Result<(), String> {
    // Reject unmatched brackets explicitly
    let open = addr.starts_with('[');
    let has_close = addr.contains(']');
    if open != has_close {
        return Err(format!("unmatched bracket in peer address: {addr}"));
    }
    if open {
        // Bracketed form: must be [IPv6]:port
        let bracket_end = addr.find(']').unwrap();
        let host = &addr[1..bracket_end];
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(format!(
                "bracketed host is not a valid IPv6 address: [{host}]"
            ));
        }
        // Must have :port after ]
        let rest = &addr[bracket_end + 1..];
        if !rest.starts_with(':') || rest.len() < 2 {
            return Err(format!("missing port after bracketed IPv6: {addr}"));
        }
        let port_str = &rest[1..];
        port_str
            .parse::<u16>()
            .map_err(|_| format!("invalid port in bracketed IPv6 address: {addr}"))?;
    }
    // Format-only check: verify host:port structure without DNS resolution.
    // DNS is deferred to connect_with_timeout at runtime, so transient resolver
    // failures don't stall startup.
    if !open {
        // Non-bracketed: must be host:port with at least one colon
        let last_colon = addr
            .rfind(':')
            .ok_or_else(|| format!("missing port separator in peer address: {addr}"))?;
        let port_str = &addr[last_colon + 1..];
        port_str
            .parse::<u16>()
            .map_err(|_| format!("invalid port in peer address: {addr}"))?;
        let host = &addr[..last_colon];
        if host.is_empty() {
            return Err(format!("empty host in peer address: {addr}"));
        }
    }
    Ok(())
}

pub fn start_node_p2p_service(cfg: NodeP2PServiceConfig) -> Result<RunningNodeP2PService, String> {
    for peer in &cfg.bootstrap_peers {
        validate_peer_addr(peer)?;
    }
    let listener = TcpListener::bind(&cfg.bind_addr)
        .map_err(|err| format!("bind {}: {err}", cfg.bind_addr))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("set_nonblocking: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("local_addr: {err}"))?
        .to_string();
    let stop = Arc::new(AtomicBool::new(false));
    let relay_state = Arc::new(TxRelayState::new_with_network(&cfg.runtime_cfg.network));
    let shared = SharedServiceState {
        stop: Arc::clone(&stop),
        runtime_cfg: cfg.runtime_cfg,
        active_sessions: Arc::new(AtomicUsize::new(0)),
        worker_handles: Arc::new(Mutex::new(Vec::new())),
        peer_manager: cfg.peer_manager,
        sync_engine: cfg.sync_engine,
        tx_pool: cfg.tx_pool,
        bootstrap_peers: Arc::new(cfg.bootstrap_peers),
        bootstrap_rotate_idx: Arc::new(AtomicUsize::new(0)),
        in_flight_dials: Arc::new(Mutex::new(HashSet::new())),
        chain_id: cfg.chain_id,
        genesis_hash: cfg.genesis_hash,
        relay_state,
        peer_outboxes: Arc::new(Mutex::new(HashMap::new())),
        local_addr: addr.clone(),
    };
    let accept_shared = shared.clone();
    let accept_join = thread::spawn(move || run_accept_loop(listener, accept_shared));
    let reconnect_shared = shared.clone();
    let reconnect_join = thread::spawn(move || run_reconnect_loop(reconnect_shared));
    for addr in shared.bootstrap_peers.iter() {
        start_outbound_peer(addr.clone(), shared.clone());
    }
    Ok(RunningNodeP2PService {
        addr,
        stop,
        shared,
        accept_join: Some(accept_join),
        reconnect_join: Some(reconnect_join),
    })
}

impl RunningNodeP2PService {
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Relay state for tx dedup + relay pool.
    pub fn relay_state(&self) -> Arc<TxRelayState> {
        Arc::clone(&self.shared.relay_state)
    }

    /// Peer outboxes for tx broadcast.
    pub fn peer_outboxes(&self) -> Arc<Mutex<HashMap<String, PeerOutbox>>> {
        Arc::clone(&self.shared.peer_outboxes)
    }

    pub fn close(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.addr);
        if let Some(join) = self.accept_join.take() {
            let _ = join.join();
        }
        if let Some(join) = self.reconnect_join.take() {
            let _ = join.join();
        }
        // Join workers with bounded timeout so stuck peers don't hang shutdown.
        // Workers observe stop flag and will exit their read loops, but slow
        // read_deadline peers may take up to that duration to notice.
        join_service_workers_bounded(&self.shared, MAX_SHUTDOWN_WAIT);
        wait_for_service_shutdown(&self.shared);
    }
}

impl Drop for RunningNodeP2PService {
    fn drop(&mut self) {
        self.close();
    }
}

fn run_accept_loop(listener: TcpListener, shared: SharedServiceState) {
    let mut error_backoff = ACCEPT_ERROR_BACKOFF_INIT;
    while !shared.stop.load(Ordering::SeqCst) {
        reap_finished_service_workers(&shared);
        match listener.accept() {
            Ok((stream, _)) => {
                error_backoff = ACCEPT_ERROR_BACKOFF_INIT;
                // Session slot acquired INSIDE handle_peer after handshake.
                // Pre-handshake reservation lets unauthenticated peers hold slots.
                let handler_shared = shared.clone();
                let _ = spawn_service_worker(&shared, move || {
                    let _ = handle_peer(stream, None, handler_shared);
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_LOOP_SLEEP);
            }
            Err(_) => {
                thread::sleep(error_backoff);
                error_backoff = (error_backoff * 2).min(ACCEPT_ERROR_BACKOFF_CAP);
            }
        }
    }
}

fn run_reconnect_loop(shared: SharedServiceState) {
    reconnect_loop_with_interval(shared, RECONNECT_INTERVAL, RECONNECT_LOOP_SLEEP);
}

fn reconnect_loop_with_interval(shared: SharedServiceState, interval: Duration, sleep: Duration) {
    let mut waited = Duration::ZERO;
    while !shared.stop.load(Ordering::SeqCst) {
        reap_finished_service_workers(&shared);
        if waited >= interval {
            reconnect_missing_bootstrap_peers(&shared);
            waited = Duration::ZERO;
        }
        thread::sleep(sleep);
        waited += sleep;
    }
}

fn start_outbound_peer(addr: String, shared: SharedServiceState) {
    let mut guard = lock_in_flight_dials(&shared);
    if should_skip_outbound_dial(&shared, &guard, &addr) {
        return;
    }
    guard.insert(addr.clone());
    drop(guard);
    let worker_shared = shared.clone();
    let cleanup_addr = addr.clone();
    let cleanup_shared = shared.clone();
    if !spawn_service_worker(&shared, move || {
        let connect_timeout = outbound_connect_timeout(&worker_shared.runtime_cfg);
        let result = connect_with_timeout(&addr, connect_timeout).and_then(|stream| {
            // Session slot acquired INSIDE handle_peer after handshake, same as
            // inbound path.  No pre-handshake slot reservation — prevents malicious
            // bootstrap peers from holding slots during slow/stalled handshakes.
            // In-flight marker kept through handshake to prevent duplicate dials.
            handle_peer(stream, Some(addr.clone()), worker_shared.clone())
        });
        // Always clear in-flight marker — whether connect, handshake, or session failed.
        {
            let mut guard = lock_in_flight_dials(&worker_shared);
            guard.remove(&addr);
        }
        let _ = result;
    }) {
        // Worker spawn denied (thread cap) — remove stale in_flight marker
        // so this peer can be retried on the next reconnect pass.
        let mut guard = lock_in_flight_dials(&cleanup_shared);
        guard.remove(&cleanup_addr);
    }
}

fn is_connected(peer_manager: &PeerManager, addr: &str) -> bool {
    peer_manager.snapshot().iter().any(|peer| peer.addr == addr)
}

fn reconnect_missing_bootstrap_peers(shared: &SharedServiceState) {
    let n = shared.bootstrap_peers.len();
    if n == 0 {
        return;
    }
    // Rotate starting index each call so later peers get a fair chance
    // when slots are limited.  Without rotation, a dead peer at index 0
    // would permanently starve reachable peers at higher indices.
    let start = shared.bootstrap_rotate_idx.fetch_add(1, Ordering::Relaxed) % n;
    for i in 0..n {
        let addr = &shared.bootstrap_peers[(start + i) % n];
        if !is_connected(&shared.peer_manager, addr) {
            start_outbound_peer(addr.clone(), shared.clone());
        }
    }
}

// accept_error_backoff is now inline exponential in run_accept_loop.

fn should_skip_outbound_dial(
    shared: &SharedServiceState,
    in_flight: &HashSet<String>,
    addr: &str,
) -> bool {
    let occupied = shared
        .active_sessions
        .load(Ordering::SeqCst)
        .saturating_add(in_flight.len());
    in_flight.contains(addr) || occupied >= shared.runtime_cfg.max_peers
}

/// Lock in_flight_dials. Insert happens in the caller thread (start_outbound_peer),
/// remove happens in the worker thread (after connect succeeds or fails).
/// Separate lock scopes are intentional — they span different threads.
fn lock_in_flight_dials(shared: &SharedServiceState) -> std::sync::MutexGuard<'_, HashSet<String>> {
    shared
        .in_flight_dials
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn lock_worker_handles(
    shared: &SharedServiceState,
) -> std::sync::MutexGuard<'_, Vec<JoinHandle<()>>> {
    shared
        .worker_handles
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Spawn a service worker thread. Returns `true` if spawned, `false` if
/// the worker cap was hit and the closure was NOT executed.
/// Worker cap is shared — inbound/outbound reservation is handled at the
/// session slot level (try_acquire_session_slot) not here.
fn spawn_service_worker(
    shared: &SharedServiceState,
    worker: impl FnOnce() + Send + 'static,
) -> bool {
    // Reap finished workers before spawning to prevent unbounded accumulation.
    reap_finished_service_workers(shared);
    let max_workers = shared
        .runtime_cfg
        .max_peers
        .saturating_mul(WORKER_THREAD_MULTIPLIER)
        .min(MAX_WORKER_THREADS);
    // Hold lock through check + spawn + push to prevent TOCTOU race.
    let mut handles = lock_worker_handles(shared);
    if handles.len() >= max_workers {
        eprintln!(
            "p2p: worker limit reached ({}/{}), rejecting spawn",
            handles.len(),
            max_workers
        );
        return false;
    }
    match thread::Builder::new().spawn(worker) {
        Ok(handle) => {
            handles.push(handle);
            true
        }
        Err(err) => {
            eprintln!("p2p: failed to spawn worker thread: {err}");
            false
        }
    }
}

fn reap_finished_service_workers(shared: &SharedServiceState) {
    let finished = {
        let mut handles = lock_worker_handles(shared);
        let mut finished = Vec::new();
        let mut idx = 0;
        while idx < handles.len() {
            if handles[idx].is_finished() {
                finished.push(handles.swap_remove(idx));
            } else {
                idx += 1;
            }
        }
        finished
    };
    for handle in finished {
        let _ = handle.join();
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn join_all_service_workers(shared: &SharedServiceState) {
    loop {
        let handles = {
            let mut handles = lock_worker_handles(shared);
            if handles.is_empty() {
                return;
            }
            std::mem::take(&mut *handles)
        };
        for handle in handles {
            let _ = handle.join();
        }
    }
}

/// Like `join_all_service_workers` but gives up after `timeout` to prevent
/// stuck peers from hanging the shutdown sequence indefinitely.
fn join_service_workers_bounded(shared: &SharedServiceState, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let mut handles = {
            let mut guard = lock_worker_handles(shared);
            if guard.is_empty() {
                return;
            }
            std::mem::take(&mut *guard)
        };
        let mut remaining = Vec::new();
        while !handles.is_empty() {
            if Instant::now() >= deadline {
                // Put ALL remaining handles back so Drop can attempt cleanup.
                eprintln!(
                    "p2p: shutdown timeout reached, {} workers still running",
                    remaining.len() + handles.len()
                );
                let mut guard = lock_worker_handles(shared);
                guard.extend(handles);
                guard.extend(remaining);
                return;
            }
            // Pop from back — avoids shifting, order doesn't matter.
            let handle = handles.pop().unwrap();
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                remaining.push(handle);
            }
        }
        if remaining.is_empty() {
            return;
        }
        // Put unfinished handles back and poll again after a short sleep.
        {
            let mut guard = lock_worker_handles(shared);
            guard.extend(remaining);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Reserve OUTBOUND_SLOT_RESERVE fraction of max_peers for outbound dials.
/// Inbound sessions are capped at max_peers - reserve, so bootstrap reconnects
/// always have room to dial even when inbound slots are saturated.
const OUTBOUND_SLOT_RESERVE: usize = 2;

fn try_acquire_session_slot(
    shared: &SharedServiceState,
    is_outbound: bool,
) -> Option<SessionSlotGuard> {
    loop {
        let current = shared.active_sessions.load(Ordering::SeqCst);
        let cap = if is_outbound {
            shared.runtime_cfg.max_peers
        } else {
            // Inbound: leave up to OUTBOUND_SLOT_RESERVE slots for outbound dials,
            // but never reduce inbound cap below 1 (for max_peers <= 2).
            let reserve = OUTBOUND_SLOT_RESERVE.min(shared.runtime_cfg.max_peers.saturating_sub(1));
            shared.runtime_cfg.max_peers.saturating_sub(reserve)
        };
        if current >= cap {
            return None;
        }
        if shared
            .active_sessions
            .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Some(SessionSlotGuard {
                active_sessions: Arc::clone(&shared.active_sessions),
            });
        }
        // CAS contention — spin_loop tells the CPU to pause briefly (PAUSE
        // on x86, YIELD on ARM) before retrying, reducing bus contention.
        #[cfg(not(tarpaulin_include))]
        std::hint::spin_loop();
    }
}

fn outbound_connect_timeout(cfg: &PeerRuntimeConfig) -> Duration {
    if cfg.read_deadline < MIN_OUTBOUND_CONNECT_TIMEOUT {
        MIN_OUTBOUND_CONNECT_TIMEOUT
    } else if cfg.read_deadline > MAX_OUTBOUND_CONNECT_TIMEOUT {
        MAX_OUTBOUND_CONNECT_TIMEOUT
    } else {
        cfg.read_deadline
    }
}

/// Maximum resolved addresses to try per outbound connect.
/// Prevents unbounded iteration on adversarial DNS responses.
const MAX_RESOLVED_ADDRS: usize = 4;

/// DNS resolution timeout — prevents worker thread stall from slow resolvers.
const DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum concurrent DNS resolver threads.  Prevents unbounded thread
/// accumulation during sustained DNS timeouts.
const MAX_DNS_RESOLVER_THREADS: usize = 4;
static ACTIVE_DNS_RESOLVERS: AtomicUsize = AtomicUsize::new(0);

fn connect_with_timeout(addr: &str, timeout: Duration) -> Result<TcpStream, String> {
    use std::net::ToSocketAddrs;
    use std::sync::mpsc;
    // Fast path: if addr is a literal IP:port, connect directly without DNS
    // resolver gate.  Prevents IP-literal bootstrap peers from being blocked
    // when DNS resolver slots are saturated by slow hostname lookups.
    if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
        return TcpStream::connect_timeout(&socket_addr, timeout)
            .map_err(|err| format!("connect {addr}: {err}"));
    }
    // DNS path: atomically increment resolver count, reject if at capacity.
    // Uses compare_exchange loop to prevent TOCTOU race where concurrent
    // workers all pass a separate load check before incrementing.
    loop {
        let current = ACTIVE_DNS_RESOLVERS.load(Ordering::Acquire);
        if current >= MAX_DNS_RESOLVER_THREADS {
            return Err(format!("DNS resolver limit reached ({addr})"));
        }
        if ACTIVE_DNS_RESOLVERS
            .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
    }
    let addr_owned = addr.to_string();
    let (tx, rx) = mpsc::channel();
    // RAII guard ensures counter is decremented even if thread panics.
    struct DnsResolverGuard;
    impl Drop for DnsResolverGuard {
        fn drop(&mut self) {
            ACTIVE_DNS_RESOLVERS.fetch_sub(1, Ordering::AcqRel);
        }
    }
    let resolver = match thread::Builder::new()
        .name("dns-resolver".into())
        .spawn(move || {
            let _guard = DnsResolverGuard;
            let result = addr_owned
                .to_socket_addrs()
                .map(|iter| iter.take(MAX_RESOLVED_ADDRS).collect::<Vec<_>>());
            let _ = tx.send(result);
        }) {
        Ok(handle) => handle,
        Err(err) => {
            // Thread creation failed — release the reserved slot.
            ACTIVE_DNS_RESOLVERS.fetch_sub(1, Ordering::AcqRel);
            return Err(format!("DNS resolver thread spawn failed ({addr}): {err}"));
        }
    };
    let addrs = match rx.recv_timeout(DNS_RESOLVE_TIMEOUT) {
        Ok(result) => {
            let _ = resolver.join();
            result.map_err(|err| format!("peer address resolution failed ({addr}): {err}"))?
        }
        Err(_) => {
            // Timeout — resolver may be stuck in getaddrinfo.  Detach it;
            // the counter is decremented by the resolver thread itself when
            // it eventually returns, bounding total threads to MAX_DNS_RESOLVER_THREADS.
            return Err(format!("DNS resolution timed out ({addr})"));
        }
    };
    if addrs.is_empty() {
        return Err(format!("peer address resolved to no addresses ({addr})"));
    }
    let mut last_err = String::new();
    for socket_addr in &addrs {
        match TcpStream::connect_timeout(socket_addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = format!("connect {addr} ({socket_addr}): {err}"),
        }
    }
    Err(last_err)
}

fn wait_for_service_shutdown(shared: &SharedServiceState) {
    let wait_budget = (shared
        .runtime_cfg
        .read_deadline
        .max(outbound_connect_timeout(&shared.runtime_cfg))
        + RECONNECT_LOOP_SLEEP)
        .min(MAX_SHUTDOWN_WAIT);
    let deadline = Instant::now() + wait_budget;
    while Instant::now() < deadline {
        let dials_drained = lock_in_flight_dials(shared).is_empty();
        let sessions_drained = shared.active_sessions.load(Ordering::SeqCst) == 0;
        if dials_drained && sessions_drained {
            break;
        }
        thread::sleep(SERVICE_CLOSE_WAIT_SLEEP);
    }
    // Join worker threads with a hard deadline to prevent indefinite hang.
    // Workers that don't exit by the deadline are detached (JoinHandle dropped).
    let join_deadline = Instant::now() + MAX_SHUTDOWN_WAIT;
    let handles: Vec<_> = {
        let mut guard = lock_worker_handles(shared);
        std::mem::take(&mut *guard)
    };
    for handle in handles {
        let remaining = join_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break; // deadline exceeded — detach remaining threads
        }
        // thread::JoinHandle doesn't support timeout; poll via is_finished.
        let poll_start = Instant::now();
        while !handle.is_finished() && poll_start.elapsed() < remaining {
            thread::sleep(Duration::from_millis(10));
        }
        if handle.is_finished() {
            let _ = handle.join();
        }
        // else: handle dropped → thread detached
    }
}

fn handle_peer(
    stream: TcpStream,
    outbound_addr: Option<String>,
    shared: SharedServiceState,
) -> Result<(), String> {
    stream
        .set_nodelay(true)
        .map_err(|err| format!("set_nodelay: {err}"))?;
    let best_height = {
        let engine = shared
            .sync_engine
            .lock()
            .map_err(|_| "sync engine unavailable".to_string())?;
        engine.tip()?.map(|(height, _)| height).unwrap_or(0)
    };
    let local = service_local_version(best_height, shared.chain_id, shared.genesis_hash);
    let mut session = perform_version_handshake(
        stream,
        shared.runtime_cfg.clone(),
        local,
        shared.chain_id,
        shared.genesis_hash,
    )
    .map_err(|err| format!("handshake: {err}"))?;

    // Clear in-flight marker after handshake completes (outbound only).
    // Marker was kept through TCP connect + handshake to prevent duplicate dials.
    // Now that handshake succeeded, active_sessions takes over slot accounting.
    if let Some(ref addr) = outbound_addr {
        let mut guard = lock_in_flight_dials(&shared);
        guard.remove(addr);
    }

    // Acquire session slot AFTER handshake succeeds for BOTH inbound and outbound.
    // No pre-handshake reservation — prevents unauthenticated/malicious peers
    // from holding slots during slow handshakes.
    let is_outbound = outbound_addr.is_some();
    let _session_slot = {
        let Some(slot) = try_acquire_session_slot(&shared, is_outbound) else {
            return Err("session cap reached after handshake".to_string());
        };
        slot
    };

    let mut peer_state = session.state();
    if let Some(addr) = outbound_addr.as_ref() {
        peer_state.addr = addr.clone();
    }
    let peer_addr = peer_state.addr.clone();
    shared
        .peer_manager
        .add_peer(peer_state)
        .map_err(|err| format!("peer register: {err}"))?;
    let _peer_guard = PeerGuard {
        peer_manager: Arc::clone(&shared.peer_manager),
        addr: peer_addr.clone(),
    };

    // Register outbox for this peer so relay broadcasts can enqueue frames.
    if let Ok(mut outboxes) = shared.peer_outboxes.lock() {
        outboxes.insert(peer_addr.clone(), PeerOutbox::default());
    }
    let _outbox_guard = PeerOutboxGuard {
        peer_outboxes: Arc::clone(&shared.peer_outboxes),
        addr: peer_addr.clone(),
    };

    // Build relay context for message loop.
    let relay_ctx = PeerRelayContext {
        relay_state: &shared.relay_state,
        peer_manager: &shared.peer_manager,
        local_addr: &shared.local_addr,
        peer_registered_addr: &peer_addr,
        peer_writers: &shared.peer_outboxes,
    };

    {
        let mut engine = shared
            .sync_engine
            .lock()
            .map_err(|_| "sync engine unavailable".to_string())?;
        engine.record_best_known_height(session.state().remote_version.best_height);
        let initial_request = session
            .prepare_block_request_if_behind(&engine)
            .map_err(|err| format!("initial sync request: {err}"))?;
        drop(engine);
        if let Some(msg) = initial_request {
            session
                .write_message(&msg)
                .map_err(|err| format!("initial sync request: {err}"))?;
        }
    }

    while !shared.stop.load(Ordering::SeqCst) {
        flush_peer_outbox(&shared, &peer_addr, |frame| session.write_raw(frame))?;
        match session.poll_read_ready(live_loop_poll_timeout(session.read_deadline())) {
            Ok(true) => {}
            Ok(false) => {
                flush_peer_outbox(&shared, &peer_addr, |frame| session.write_raw(frame))?;
                continue;
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                flush_peer_outbox(&shared, &peer_addr, |frame| session.write_raw(frame))?;
                continue;
            }
            Err(err) => return Err(format!("poll live message readiness: {err}")),
        }
        let msg = session
            .read_message()
            .map_err(|err| format!("read message: {err}"))?;
        let outbound_messages = {
            // Validate payload size before acquiring engine lock.
            if msg.payload.len() > rubin_consensus::constants::MAX_RELAY_MSG_BYTES as usize {
                return Err(format!(
                    "message payload too large: {} > {}",
                    msg.payload.len(),
                    rubin_consensus::constants::MAX_RELAY_MSG_BYTES,
                ));
            }
            // Lock scope minimized: engine lock held only during
            // collect_live_responses.  Payload size check above ensures
            // no unbounded deserialization under lock.
            let (responses, tx_pool_cleanup) = {
                let mut engine = shared
                    .sync_engine
                    .lock()
                    .map_err(|_| "sync engine unavailable".to_string())?;
                let outcome = session.collect_live_responses(msg, &mut engine, Some(&relay_ctx));
                let pending_cleanup = session.take_pending_tx_pool_cleanup();
                drop(engine);
                finalize_live_message_outcome(&shared, outcome, pending_cleanup)?
            };
            maybe_apply_tx_pool_cleanup(&shared, tx_pool_cleanup)?;
            responses
        };
        for outbound in outbound_messages {
            session
                .write_message(&outbound)
                .map_err(|err| format!("handle live message: {err}"))?;
        }
        flush_peer_outbox(&shared, &peer_addr, |frame| session.write_raw(frame))?;
    }
    Ok(())
}

fn live_loop_poll_timeout(read_deadline: Duration) -> Duration {
    read_deadline.min(LIVE_LOOP_IDLE_DRAIN_POLL_INTERVAL)
}

fn flush_peer_outbox<F>(
    shared: &SharedServiceState,
    peer_addr: &str,
    mut write_frame: F,
) -> Result<(), String>
where
    F: FnMut(&[u8]) -> io::Result<()>,
{
    // Drain relay outbox into a local buffer, then release the lock before
    // performing socket writes so other peers can still enqueue broadcasts.
    let pending: Vec<Vec<u8>> = shared
        .peer_outboxes
        .lock()
        .ok()
        .and_then(|mut ob| ob.get_mut(peer_addr).map(PeerOutbox::take_frames))
        .unwrap_or_default();
    for frame in pending {
        write_frame(&frame).map_err(|err| format!("relay drain: {err}"))?;
    }
    Ok(())
}

fn apply_tx_pool_cleanup(
    shared: &SharedServiceState,
    tx_pool_cleanup: TxPoolCleanupPlan,
) -> Result<(), String> {
    let (chain_state, block_store, chain_id) = {
        let engine = shared
            .sync_engine
            .lock()
            .map_err(|_| "sync engine unavailable".to_string())?;
        (
            engine.chain_state_snapshot(),
            engine.block_store_snapshot(),
            engine.chain_id(),
        )
    };
    let mut tx_pool = shared
        .tx_pool
        .lock()
        .map_err(|_| "tx pool unavailable".to_string())?;
    tx_pool_cleanup.apply(&mut tx_pool, &chain_state, block_store.as_ref(), chain_id);
    Ok(())
}

fn maybe_apply_tx_pool_cleanup(
    shared: &SharedServiceState,
    tx_pool_cleanup: TxPoolCleanupPlan,
) -> Result<(), String> {
    if tx_pool_cleanup.is_empty() {
        return Ok(());
    }
    apply_tx_pool_cleanup(shared, tx_pool_cleanup)
}

fn finalize_live_message_outcome(
    shared: &SharedServiceState,
    outcome: io::Result<LiveMessageOutcome>,
    pending_cleanup: TxPoolCleanupPlan,
) -> Result<(Vec<WireMessage>, TxPoolCleanupPlan), String> {
    match outcome {
        Ok(outcome) => Ok((
            outcome.responses,
            outcome.tx_pool_cleanup.merge(pending_cleanup),
        )),
        Err(err) => {
            maybe_apply_tx_pool_cleanup(shared, pending_cleanup)?;
            Err(format!("handle live message: {err}"))
        }
    }
}

fn service_local_version(
    best_height: u64,
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
) -> VersionPayloadV1 {
    VersionPayloadV1 {
        protocol_version: 1,
        tx_relay: true,
        pruned_below_height: 0,
        da_mempool_size: 0,
        chain_id,
        genesis_hash,
        best_height,
    }
}

struct PeerGuard {
    peer_manager: Arc<PeerManager>,
    addr: String,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        self.peer_manager.remove_peer(&self.addr);
    }
}

struct PeerOutboxGuard {
    peer_outboxes: Arc<Mutex<HashMap<String, PeerOutbox>>>,
    addr: String,
}

impl Drop for PeerOutboxGuard {
    fn drop(&mut self) {
        if let Ok(mut outboxes) = self.peer_outboxes.lock() {
            outboxes.remove(&self.addr);
        }
    }
}

struct SessionSlotGuard {
    active_sessions: Arc<AtomicUsize>,
}

impl Drop for SessionSlotGuard {
    fn drop(&mut self) {
        self.active_sessions.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::io;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use rubin_consensus::{block_hash, constants::POW_LIMIT, BLOCK_HEADER_BYTES};

    use super::{
        apply_tx_pool_cleanup, connect_with_timeout, finalize_live_message_outcome,
        flush_peer_outbox, join_all_service_workers, lock_in_flight_dials,
        maybe_apply_tx_pool_cleanup, outbound_connect_timeout, reconnect_missing_bootstrap_peers,
        should_skip_outbound_dial, start_node_p2p_service, wait_for_service_shutdown,
        NodeP2PServiceConfig, SharedServiceState,
    };
    use crate::genesis::{devnet_genesis_block_bytes, devnet_genesis_chain_id};
    use crate::interop::local_version;
    use crate::p2p_runtime::{
        build_envelope_header, decode_inventory_vectors, default_peer_runtime_config,
        encode_inventory_vectors, network_magic, perform_version_handshake, InventoryVector,
        LiveMessageOutcome, PeerManager, PeerRuntimeConfig, WireMessage, MSG_TX,
    };
    use crate::sync_reorg::TxPoolCleanupPlan;
    use crate::tx_relay::PeerOutbox;
    use crate::tx_relay::TxRelayState;
    use crate::{
        block_store_path, default_sync_config, BlockStore, ChainState, SyncEngine, TxPool,
    };
    use std::collections::HashMap;

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    fn test_engine(prefix: &str) -> (Arc<Mutex<SyncEngine>>, std::path::PathBuf) {
        let dir = unique_temp_dir(prefix);
        let store = BlockStore::open(block_store_path(&dir)).expect("blockstore");
        let cfg = default_sync_config(Some(POW_LIMIT), devnet_genesis_chain_id(), None);
        let engine = SyncEngine::new(ChainState::new(), Some(store), cfg).expect("sync engine");
        (Arc::new(Mutex::new(engine)), dir)
    }

    fn test_genesis_hash() -> [u8; 32] {
        let genesis = devnet_genesis_block_bytes();
        block_hash(&genesis[..BLOCK_HEADER_BYTES]).expect("genesis hash")
    }

    fn test_shared_state(
        runtime_cfg: PeerRuntimeConfig,
        bootstrap_peers: Vec<String>,
        sync_engine: Arc<Mutex<SyncEngine>>,
    ) -> SharedServiceState {
        SharedServiceState {
            stop: Arc::new(AtomicBool::new(false)),
            runtime_cfg: runtime_cfg.clone(),
            active_sessions: Arc::new(AtomicUsize::new(0)),
            worker_handles: Arc::new(Mutex::new(Vec::new())),
            peer_manager: Arc::new(PeerManager::new(runtime_cfg)),
            sync_engine,
            tx_pool: Arc::new(Mutex::new(TxPool::new())),
            bootstrap_peers: Arc::new(bootstrap_peers),
            bootstrap_rotate_idx: Arc::new(AtomicUsize::new(0)),
            in_flight_dials: Arc::new(Mutex::new(HashSet::new())),
            chain_id: devnet_genesis_chain_id(),
            genesis_hash: test_genesis_hash(),
            relay_state: Arc::new(TxRelayState::new()),
            peer_outboxes: Arc::new(Mutex::new(HashMap::new())),
            local_addr: "127.0.0.1:0".to_string(),
        }
    }

    fn wait_until(deadline: Instant, check: impl Fn() -> bool) {
        while Instant::now() < deadline {
            if check() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("condition not reached before deadline");
    }

    #[test]
    fn flush_peer_outbox_drains_without_holding_lock_during_writes() {
        let (sync_engine, _dir) = test_engine("rubin-node-p2p-service-outbox-flush");
        let shared = test_shared_state(
            default_peer_runtime_config("devnet", 8),
            Vec::new(),
            sync_engine,
        );
        {
            let mut outboxes = shared.peer_outboxes.lock().unwrap();
            outboxes.insert("peer:8333".to_string(), PeerOutbox::default());
            outboxes
                .get_mut("peer:8333")
                .unwrap()
                .push_frame(vec![0xAA, 0xBB, 0xCC]);
        }

        let mut drained = Vec::new();
        flush_peer_outbox(&shared, "peer:8333", |frame| {
            drained.push(frame.to_vec());
            Ok(())
        })
        .unwrap();

        assert_eq!(drained, vec![vec![0xAA, 0xBB, 0xCC]]);
        assert!(shared.peer_outboxes.lock().unwrap()["peer:8333"].is_empty());
    }

    #[test]
    fn apply_tx_pool_cleanup_accepts_non_empty_plan() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-apply-cleanup");
        let shared = test_shared_state(
            default_peer_runtime_config("devnet", 8),
            Vec::new(),
            sync_engine,
        );
        let cleanup =
            TxPoolCleanupPlan::from_parts_for_test(vec![[0x11; 32]], Vec::new(), Vec::new());

        apply_tx_pool_cleanup(&shared, cleanup).expect("cleanup should apply");

        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn maybe_apply_tx_pool_cleanup_skips_empty_plan() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-maybe-cleanup");
        let shared = test_shared_state(
            default_peer_runtime_config("devnet", 8),
            Vec::new(),
            sync_engine,
        );

        maybe_apply_tx_pool_cleanup(&shared, TxPoolCleanupPlan::default())
            .expect("empty cleanup should noop");

        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn finalize_live_message_outcome_merges_pending_cleanup_on_success() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-finalize-success");
        let shared = test_shared_state(
            default_peer_runtime_config("devnet", 8),
            Vec::new(),
            sync_engine,
        );
        let outcome = LiveMessageOutcome {
            responses: vec![WireMessage {
                command: "pong".to_string(),
                payload: Vec::new(),
            }],
            tx_pool_cleanup: TxPoolCleanupPlan::default(),
        };
        let pending =
            TxPoolCleanupPlan::from_parts_for_test(vec![[0x22; 32]], Vec::new(), Vec::new());

        let (responses, merged_cleanup) =
            finalize_live_message_outcome(&shared, Ok(outcome), pending).expect("success path");

        assert_eq!(responses.len(), 1);
        assert!(
            !merged_cleanup.is_empty(),
            "pending cleanup must survive the success path"
        );

        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn finalize_live_message_outcome_applies_pending_cleanup_on_error() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-finalize-error");
        let shared = test_shared_state(
            default_peer_runtime_config("devnet", 8),
            Vec::new(),
            sync_engine,
        );
        let pending =
            TxPoolCleanupPlan::from_parts_for_test(vec![[0x33; 32]], Vec::new(), Vec::new());

        let err = finalize_live_message_outcome(&shared, Err(io::Error::other("boom")), pending)
            .expect_err("error path should bubble up");

        assert!(
            err.contains("handle live message: boom"),
            "unexpected error text: {err}"
        );

        fs::remove_dir_all(dir).expect("cleanup");
    }

    fn test_wire_frame(runtime_cfg: &PeerRuntimeConfig, command: &str, payload: &[u8]) -> Vec<u8> {
        let header = build_envelope_header(network_magic(&runtime_cfg.network), command, payload)
            .expect("wire header");
        let mut raw = Vec::with_capacity(header.len() + payload.len());
        raw.extend_from_slice(&header);
        raw.extend_from_slice(payload);
        raw
    }

    #[test]
    fn service_flushes_idle_peer_outbox_within_poll_interval() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-idle-drain");
        let mut runtime_cfg = default_peer_runtime_config("devnet", 8);
        runtime_cfg.read_deadline = Duration::from_secs(2);
        runtime_cfg.write_deadline = Duration::from_secs(1);
        let shared = test_shared_state(runtime_cfg.clone(), Vec::new(), sync_engine);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let handler_shared = shared.clone();
        let handler = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept peer");
            let _ = super::handle_peer(stream, None, handler_shared);
        });

        let mut client_cfg = runtime_cfg.clone();
        client_cfg.read_deadline = Duration::from_millis(1200);
        let stream = TcpStream::connect(addr).expect("connect service");
        let local = local_version(0).expect("local version");
        let mut session = perform_version_handshake(
            stream,
            client_cfg,
            local,
            local.chain_id,
            local.genesis_hash,
        )
        .expect("handshake");

        let peer_addr = {
            let deadline = Instant::now() + Duration::from_secs(2);
            wait_until(deadline, || {
                !shared.peer_outboxes.lock().unwrap().is_empty()
            });
            let addr = {
                let outboxes = shared.peer_outboxes.lock().unwrap();
                outboxes
                    .keys()
                    .next()
                    .expect("registered peer outbox")
                    .clone()
            };
            addr
        };

        thread::sleep(Duration::from_millis(100));
        let payload = encode_inventory_vectors(&[InventoryVector {
            kind: MSG_TX,
            hash: [0xAB; 32],
        }])
        .expect("inv payload");
        let frame = test_wire_frame(&runtime_cfg, "inv", &payload);
        {
            let mut outboxes = shared.peer_outboxes.lock().unwrap();
            outboxes
                .get_mut(&peer_addr)
                .expect("registered peer outbox")
                .push_frame(frame);
        }

        let started = Instant::now();
        let deadline = started + Duration::from_millis(1200);
        let msg = loop {
            let msg = session.read_message().expect("prompt relay frame");
            if msg.command == "inv" {
                break msg;
            }
            assert_eq!(
                msg.command, "getblocks",
                "unexpected pre-relay message before queued frame flush"
            );
            assert!(
                Instant::now() < deadline,
                "queued frame did not arrive within the poll window"
            );
        };
        assert_eq!(msg.payload, payload);
        assert!(
            started.elapsed() < Duration::from_millis(1200),
            "queued frame must flush before the full read_deadline elapses"
        );

        shared.stop.store(true, Ordering::SeqCst);
        drop(session);
        handler.join().expect("handler join");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn quiet_peer_survives_repeated_live_loop_sub_timeouts() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-quiet-peer");
        let mut runtime_cfg = default_peer_runtime_config("devnet", 8);
        runtime_cfg.read_deadline = Duration::from_secs(1);
        runtime_cfg.write_deadline = Duration::from_secs(1);
        let shared = test_shared_state(runtime_cfg.clone(), Vec::new(), sync_engine);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let handler_shared = shared.clone();
        let handler = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept peer");
            let _ = super::handle_peer(stream, None, handler_shared);
        });

        let stream = TcpStream::connect(addr).expect("connect service");
        let local = local_version(0).expect("local version");
        let session = perform_version_handshake(
            stream,
            runtime_cfg,
            local,
            local.chain_id,
            local.genesis_hash,
        )
        .expect("handshake");

        let deadline = Instant::now() + Duration::from_secs(2);
        wait_until(deadline, || {
            !shared.peer_outboxes.lock().unwrap().is_empty()
        });
        thread::sleep(Duration::from_millis(1400));
        assert_eq!(
            shared.peer_outboxes.lock().unwrap().len(),
            1,
            "quiet healthy peer must remain connected across repeated sub-timeouts"
        );

        shared.stop.store(true, Ordering::SeqCst);
        drop(session);
        handler.join().expect("handler join");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn service_handles_live_message_without_waiting_for_timeout() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-live-read");
        let mut runtime_cfg = default_peer_runtime_config("devnet", 8);
        runtime_cfg.read_deadline = Duration::from_secs(2);
        runtime_cfg.write_deadline = Duration::from_secs(1);
        let shared = test_shared_state(runtime_cfg.clone(), Vec::new(), sync_engine);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let handler_shared = shared.clone();
        let handler = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept peer");
            let _ = super::handle_peer(stream, None, handler_shared);
        });

        let mut client_cfg = runtime_cfg.clone();
        client_cfg.read_deadline = Duration::from_millis(1200);
        let stream = TcpStream::connect(addr).expect("connect service");
        let local = local_version(0).expect("local version");
        let mut session = perform_version_handshake(
            stream,
            client_cfg,
            local,
            local.chain_id,
            local.genesis_hash,
        )
        .expect("handshake");

        session
            .write_message(&WireMessage {
                command: "ping".to_string(),
                payload: Vec::new(),
            })
            .expect("send live ping");

        let deadline = Instant::now() + Duration::from_millis(1200);
        loop {
            let msg = session.read_message().expect("read live response");
            if msg.command == "pong" {
                assert!(
                    Instant::now() < deadline,
                    "live loop must process immediate inbound messages without waiting for the full read timeout"
                );
                break;
            }
            assert_eq!(
                msg.command, "getblocks",
                "unexpected pre-pong message while validating live-loop immediate reads"
            );
        }

        shared.stop.store(true, Ordering::SeqCst);
        drop(session);
        handler.join().expect("handler join");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn service_preserves_full_deadline_for_fragmented_live_frames() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-fragmented-live-read");
        let mut runtime_cfg = default_peer_runtime_config("devnet", 8);
        runtime_cfg.read_deadline = Duration::from_secs(2);
        runtime_cfg.write_deadline = Duration::from_secs(1);
        let shared = test_shared_state(runtime_cfg.clone(), Vec::new(), sync_engine);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let handler_shared = shared.clone();
        let handler = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept peer");
            let _ = super::handle_peer(stream, None, handler_shared);
        });

        let mut client_cfg = runtime_cfg.clone();
        client_cfg.read_deadline = Duration::from_secs(2);
        let stream = TcpStream::connect(addr).expect("connect service");
        let local = local_version(0).expect("local version");
        let mut session = perform_version_handshake(
            stream,
            client_cfg,
            local,
            local.chain_id,
            local.genesis_hash,
        )
        .expect("handshake");

        let payload = encode_inventory_vectors(&[InventoryVector {
            kind: MSG_TX,
            hash: [0xCD; 32],
        }])
        .expect("inv payload");
        let frame = test_wire_frame(&runtime_cfg, "inv", &payload);
        let header_len = frame.len() - payload.len();
        session
            .write_raw(&frame[..header_len])
            .expect("write fragmented header");
        thread::sleep(Duration::from_millis(650));
        session
            .write_raw(&frame[header_len..])
            .expect("write fragmented payload");

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let msg = session
                .read_message()
                .expect("read fragmented live response");
            if msg.command == "getdata" {
                let requested = decode_inventory_vectors(&msg.payload).expect("decode getdata");
                assert_eq!(
                    requested,
                    vec![InventoryVector {
                        kind: MSG_TX,
                        hash: [0xCD; 32],
                    }],
                    "service must finish consuming the fragmented frame before responding"
                );
                break;
            }
            assert_eq!(
                msg.command, "getblocks",
                "unexpected pre-getdata message while validating fragmented live reads"
            );
            assert!(
                Instant::now() < deadline,
                "fragmented live frame must complete without disconnecting the peer"
            );
        }

        shared.stop.store(true, Ordering::SeqCst);
        drop(session);
        handler.join().expect("handler join");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn service_respects_short_live_read_deadlines_for_idle_drain() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-short-live-poll");
        let mut runtime_cfg = default_peer_runtime_config("devnet", 8);
        runtime_cfg.read_deadline = Duration::from_millis(120);
        runtime_cfg.write_deadline = Duration::from_secs(1);
        let shared = test_shared_state(runtime_cfg.clone(), Vec::new(), sync_engine);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let handler_shared = shared.clone();
        let handler = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept peer");
            let _ = super::handle_peer(stream, None, handler_shared);
        });

        let mut client_cfg = runtime_cfg.clone();
        client_cfg.read_deadline = Duration::from_millis(600);
        let stream = TcpStream::connect(addr).expect("connect service");
        let local = local_version(0).expect("local version");
        let mut session = perform_version_handshake(
            stream,
            client_cfg,
            local,
            local.chain_id,
            local.genesis_hash,
        )
        .expect("handshake");

        let peer_addr = {
            let deadline = Instant::now() + Duration::from_secs(2);
            wait_until(deadline, || {
                !shared.peer_outboxes.lock().unwrap().is_empty()
            });
            let outboxes = shared.peer_outboxes.lock().unwrap();
            outboxes
                .keys()
                .next()
                .expect("registered peer outbox")
                .clone()
        };

        thread::sleep(Duration::from_millis(50));
        let payload = encode_inventory_vectors(&[InventoryVector {
            kind: MSG_TX,
            hash: [0xEF; 32],
        }])
        .expect("inv payload");
        let frame = test_wire_frame(&runtime_cfg, "inv", &payload);
        {
            let mut outboxes = shared.peer_outboxes.lock().unwrap();
            outboxes
                .get_mut(&peer_addr)
                .expect("registered peer outbox")
                .push_frame(frame);
        }

        let started = Instant::now();
        let deadline = started + Duration::from_millis(300);
        loop {
            let msg = session.read_message().expect("short-poll relay frame");
            if msg.command == "inv" {
                assert!(
                    started.elapsed() < Duration::from_millis(300),
                    "queued frame must honor the shorter configured live-loop deadline"
                );
                assert_eq!(msg.payload, payload);
                break;
            }
            assert_eq!(
                msg.command, "getblocks",
                "unexpected pre-relay message before queued frame flush"
            );
            assert!(
                Instant::now() < deadline,
                "short live-loop poll must flush queued frames promptly"
            );
        }

        shared.stop.store(true, Ordering::SeqCst);
        drop(session);
        handler.join().expect("handler join");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn service_accepts_inbound_peer_handshake() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-service-inbound");
        let mut runtime_cfg = default_peer_runtime_config("devnet", 8);
        // Coverage instrumentation slows the handshake path enough that tight
        // 1s deadlines can fail before the service has done any meaningful
        // work. Widen the test window so the assertion stays about handshake
        // correctness rather than tarpaulin timing jitter.
        runtime_cfg.read_deadline = Duration::from_secs(2);
        runtime_cfg.write_deadline = Duration::from_secs(2);
        let mut service = start_node_p2p_service(NodeP2PServiceConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            bootstrap_peers: Vec::new(),
            runtime_cfg: runtime_cfg.clone(),
            peer_manager: Arc::new(PeerManager::new(runtime_cfg.clone())),
            sync_engine,
            tx_pool: Arc::new(Mutex::new(TxPool::new())),
            chain_id: devnet_genesis_chain_id(),
            genesis_hash: test_genesis_hash(),
        })
        .expect("start service");

        let stream = TcpStream::connect(service.addr()).expect("connect service");
        let local = local_version(0).expect("local version");
        let session = perform_version_handshake(
            stream,
            runtime_cfg,
            local,
            local.chain_id,
            local.genesis_hash,
        )
        .expect("handshake");
        drop(session);

        service.close();
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn service_dials_bootstrap_peer_on_start() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-service-bootstrap");
        let mut runtime_cfg = default_peer_runtime_config("devnet", 8);
        runtime_cfg.read_deadline = Duration::from_secs(1);
        runtime_cfg.write_deadline = Duration::from_secs(1);
        let peer_manager = Arc::new(PeerManager::new(runtime_cfg.clone()));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind bootstrap");
        let bootstrap_addr = listener.local_addr().expect("addr").to_string();
        let handshake_seen = Arc::new(AtomicBool::new(false));
        let handshake_seen_server = Arc::clone(&handshake_seen);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept bootstrap");
            let local = local_version(0).expect("local version");
            let _session = perform_version_handshake(
                stream,
                runtime_cfg,
                local,
                local.chain_id,
                local.genesis_hash,
            )
            .expect("handshake");
            handshake_seen_server.store(true, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(250));
        });

        let mut service = start_node_p2p_service(NodeP2PServiceConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            bootstrap_peers: vec![bootstrap_addr.clone()],
            runtime_cfg: default_peer_runtime_config("devnet", 8),
            peer_manager: Arc::clone(&peer_manager),
            sync_engine,
            tx_pool: Arc::new(Mutex::new(TxPool::new())),
            chain_id: devnet_genesis_chain_id(),
            genesis_hash: test_genesis_hash(),
        })
        .expect("start service");

        wait_until(Instant::now() + Duration::from_secs(2), || {
            handshake_seen.load(Ordering::SeqCst)
                && peer_manager
                    .snapshot()
                    .iter()
                    .any(|peer| peer.addr == bootstrap_addr)
        });

        service.close();
        server.join().expect("server join");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn outbound_connect_attempt_does_not_consume_session_slot_before_connect() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-service-outbound-slot");
        let mut runtime_cfg = default_peer_runtime_config("devnet", 1);
        // Coverage instrumentation slows the handshake path enough that the
        // smaller test deadlines become flaky even though the session-slot
        // behavior is correct. Use a wider window here so the test checks slot
        // accounting rather than timing jitter.
        runtime_cfg.read_deadline = Duration::from_secs(2);
        runtime_cfg.write_deadline = Duration::from_secs(2);
        let peer_manager = Arc::new(PeerManager::new(runtime_cfg.clone()));
        let mut service = start_node_p2p_service(NodeP2PServiceConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            bootstrap_peers: vec!["192.0.2.1:6553".to_string()],
            runtime_cfg: runtime_cfg.clone(),
            peer_manager,
            sync_engine,
            tx_pool: Arc::new(Mutex::new(TxPool::new())),
            chain_id: devnet_genesis_chain_id(),
            genesis_hash: test_genesis_hash(),
        })
        .expect("start service");

        thread::sleep(Duration::from_millis(150));

        let stream = TcpStream::connect(service.addr()).expect("connect inbound");
        let local = local_version(0).expect("local version");
        let session = perform_version_handshake(
            stream,
            runtime_cfg,
            local,
            local.chain_id,
            local.genesis_hash,
        )
        .expect("inbound handshake must not be blocked by pending bootstrap dial");
        drop(session);

        service.close();
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn session_slot_rejects_when_service_is_at_peer_cap() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-service-session-cap");
        let mut runtime_cfg = default_peer_runtime_config("devnet", 1);
        runtime_cfg.read_deadline = Duration::from_millis(250);
        runtime_cfg.write_deadline = Duration::from_millis(250);
        let shared = test_shared_state(runtime_cfg, Vec::new(), sync_engine);

        let first = super::try_acquire_session_slot(&shared, true).expect("first session slot");
        assert!(
            super::try_acquire_session_slot(&shared, true).is_none(),
            "session cap must reject the second slot while the first is active"
        );

        drop(first);
        assert!(
            super::try_acquire_session_slot(&shared, true).is_some(),
            "slot must become available again after the active session drops"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// Race 16 threads for 4 slots to exercise the CAS contention path.
    /// Under tarpaulin instrumentation overhead on x86 CI, CAS failures
    /// are reliable; on fast ARM (Apple M-series) they may not happen,
    /// so we only assert the functional invariant.
    #[test]
    fn session_slot_concurrent_acquire_respects_cap() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-slot-cap");
        let mut runtime_cfg = default_peer_runtime_config("devnet", 4);
        runtime_cfg.read_deadline = Duration::from_millis(250);
        runtime_cfg.write_deadline = Duration::from_millis(250);
        let shared = Arc::new(test_shared_state(runtime_cfg, Vec::new(), sync_engine));

        let n_threads = 16usize;
        let barrier = Arc::new(std::sync::Barrier::new(n_threads));
        let handles: Vec<_> = (0..n_threads)
            .map(|_| {
                let s = Arc::clone(&shared);
                let b = Arc::clone(&barrier);
                thread::spawn(move || {
                    b.wait();
                    super::try_acquire_session_slot(&s, true)
                })
            })
            .collect();

        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("thread panicked"))
            .collect();
        let won = results.iter().filter(|slot| slot.is_some()).count();

        assert_eq!(won, 4, "exactly max_peers threads should acquire slots");
        assert_eq!(
            shared.active_sessions.load(Ordering::SeqCst),
            4,
            "active_sessions must equal won count after all threads finish",
        );

        drop(results);
        assert_eq!(shared.active_sessions.load(Ordering::SeqCst), 0);

        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn accept_error_backoff_constants_valid() {
        use super::{ACCEPT_ERROR_BACKOFF_CAP, ACCEPT_ERROR_BACKOFF_INIT};
        assert_eq!(ACCEPT_ERROR_BACKOFF_INIT, Duration::from_millis(100));
        assert_eq!(ACCEPT_ERROR_BACKOFF_CAP, Duration::from_secs(5));
        assert!(ACCEPT_ERROR_BACKOFF_INIT < ACCEPT_ERROR_BACKOFF_CAP);
    }

    #[test]
    fn outbound_connect_timeout_clamps_runtime_window() {
        let mut cfg = default_peer_runtime_config("devnet", 8);
        cfg.read_deadline = Duration::from_millis(10);
        assert_eq!(outbound_connect_timeout(&cfg), Duration::from_millis(250));
        cfg.read_deadline = Duration::from_secs(30);
        assert_eq!(outbound_connect_timeout(&cfg), Duration::from_secs(5));
        cfg.read_deadline = Duration::from_secs(2);
        assert_eq!(outbound_connect_timeout(&cfg), Duration::from_secs(2));
    }

    #[test]
    fn connect_with_timeout_rejects_unresolvable_addr() {
        let err = connect_with_timeout("bad host:19111", Duration::from_millis(25)).unwrap_err();
        assert!(
            err.contains("peer address resolution failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn should_skip_outbound_dial_covers_duplicate_and_budget_caps() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-dial-capacity");
        let shared = test_shared_state(
            default_peer_runtime_config("devnet", 2),
            vec![],
            sync_engine,
        );
        let mut in_flight = HashSet::new();
        in_flight.insert("127.0.0.1:19111".to_string());
        assert!(should_skip_outbound_dial(
            &shared,
            &in_flight,
            "127.0.0.1:19111"
        ));
        shared.active_sessions.store(1, Ordering::SeqCst);
        assert!(should_skip_outbound_dial(
            &shared,
            &in_flight,
            "127.0.0.1:19112"
        ));
        shared.active_sessions.store(0, Ordering::SeqCst);
        assert!(!should_skip_outbound_dial(
            &shared,
            &in_flight,
            "127.0.0.1:19112"
        ));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn reconnect_missing_bootstrap_peers_only_redials_missing_entries() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-reconnect-helper");
        let mut runtime_cfg = default_peer_runtime_config("devnet", 8);
        runtime_cfg.read_deadline = Duration::from_secs(1);
        runtime_cfg.write_deadline = Duration::from_secs(1);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind bootstrap");
        let bootstrap_addr = listener.local_addr().expect("addr").to_string();
        let shared = test_shared_state(
            runtime_cfg.clone(),
            vec![bootstrap_addr.clone()],
            sync_engine,
        );
        let handshake_seen = Arc::new(AtomicBool::new(false));
        let handshake_seen_server = Arc::clone(&handshake_seen);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept bootstrap");
            let local = local_version(0).expect("local version");
            let _session = perform_version_handshake(
                stream,
                runtime_cfg,
                local,
                local.chain_id,
                local.genesis_hash,
            )
            .expect("handshake");
            handshake_seen_server.store(true, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(100));
        });

        reconnect_missing_bootstrap_peers(&shared);

        wait_until(Instant::now() + Duration::from_secs(2), || {
            handshake_seen.load(Ordering::SeqCst)
                && shared
                    .peer_manager
                    .snapshot()
                    .iter()
                    .any(|peer| peer.addr == bootstrap_addr)
        });

        shared.stop.store(true, Ordering::SeqCst);
        server.join().expect("server join");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn outbound_dial_skips_connect_when_session_cap_is_already_full() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-outbound-cap");
        let mut runtime_cfg = default_peer_runtime_config("devnet", 1);
        runtime_cfg.read_deadline = Duration::from_millis(250);
        runtime_cfg.write_deadline = Duration::from_millis(250);
        let addr = "127.0.0.1:19199".to_string();
        let shared = test_shared_state(runtime_cfg, vec![], sync_engine);
        shared.active_sessions.store(1, Ordering::SeqCst);

        super::start_outbound_peer(addr, shared.clone());

        thread::sleep(Duration::from_millis(200));
        assert!(
            lock_in_flight_dials(&shared).is_empty(),
            "skipped dial must not leave an in-flight marker behind"
        );
        assert!(
            shared.peer_manager.snapshot().is_empty(),
            "skipped dial must not register peer"
        );

        shared.stop.store(true, Ordering::SeqCst);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn wait_for_service_shutdown_returns_when_state_is_already_drained() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-shutdown-drained");
        let runtime_cfg = default_peer_runtime_config("devnet", 8);
        let shared = test_shared_state(runtime_cfg, vec![], sync_engine);
        let started = Instant::now();
        wait_for_service_shutdown(&shared);
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "drained state should not block shutdown"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn join_all_service_workers_waits_for_registered_workers() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-worker-join");
        let shared = test_shared_state(
            default_peer_runtime_config("devnet", 8),
            vec![],
            sync_engine,
        );
        let finished = Arc::new(AtomicBool::new(false));
        let finished_worker = Arc::clone(&finished);
        {
            let mut handles = super::lock_worker_handles(&shared);
            handles.push(thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                finished_worker.store(true, Ordering::SeqCst);
            }));
        }

        join_all_service_workers(&shared);

        assert!(
            finished.load(Ordering::SeqCst),
            "worker must finish before shutdown returns"
        );
        assert!(
            super::lock_worker_handles(&shared).is_empty(),
            "worker registry must drain"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn spawn_service_worker_returns_false_at_capacity() {
        let (sync_engine, dir) = test_engine("rubin-node-spawn-cap");
        let mut cfg = default_peer_runtime_config("devnet", 1);
        cfg.read_deadline = Duration::from_secs(1);
        cfg.write_deadline = Duration::from_secs(1);
        let shared = test_shared_state(cfg, vec![], sync_engine);

        // Fill worker slots to capacity (WORKER_THREAD_MULTIPLIER * max_peers = 3*1 = 3)
        let barrier = Arc::new(std::sync::Barrier::new(4)); // 3 workers + test thread
        for _ in 0..3 {
            let b = Arc::clone(&barrier);
            let spawned = super::spawn_service_worker(&shared, move || {
                b.wait();
            });
            assert!(spawned, "should spawn within capacity");
        }

        // 4th spawn should be denied
        let spawned = super::spawn_service_worker(&shared, || {});
        assert!(!spawned, "should reject when at capacity");

        // Release workers
        barrier.wait();
        super::join_all_service_workers(&shared);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn start_outbound_peer_cleans_in_flight_on_spawn_deny() {
        let (sync_engine, dir) = test_engine("rubin-node-inflight-cleanup");
        let mut cfg = default_peer_runtime_config("devnet", 1);
        cfg.read_deadline = Duration::from_secs(1);
        cfg.write_deadline = Duration::from_secs(1);
        let shared = test_shared_state(cfg, vec![], sync_engine);

        // Fill worker slots
        let barrier = Arc::new(std::sync::Barrier::new(4));
        for _ in 0..3 {
            let b = Arc::clone(&barrier);
            super::spawn_service_worker(&shared, move || {
                b.wait();
            });
        }

        // Try outbound dial — should fail and clean in_flight
        super::start_outbound_peer("1.2.3.4:8333".to_string(), shared.clone());
        {
            let guard = lock_in_flight_dials(&shared);
            assert!(
                !guard.contains("1.2.3.4:8333"),
                "stale in_flight marker must be cleaned on spawn deny"
            );
        }

        barrier.wait();
        super::join_all_service_workers(&shared);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn bootstrap_rotation_advances_start_index() {
        let (sync_engine, dir) = test_engine("rubin-node-rotation");
        let cfg = default_peer_runtime_config("devnet", 8);
        // Use unreachable addresses — we just test the rotation counter, not actual connections
        let shared = test_shared_state(
            cfg,
            vec![
                "192.0.2.1:8333".to_string(), // TEST-NET, unreachable
                "192.0.2.2:8333".to_string(),
                "192.0.2.3:8333".to_string(),
            ],
            sync_engine,
        );

        assert_eq!(
            shared.bootstrap_rotate_idx.load(Ordering::Relaxed),
            0,
            "initial rotation index"
        );

        // Calling reconnect bumps the counter
        reconnect_missing_bootstrap_peers(&shared);
        assert_eq!(
            shared.bootstrap_rotate_idx.load(Ordering::Relaxed),
            1,
            "rotation index after first call"
        );

        reconnect_missing_bootstrap_peers(&shared);
        assert_eq!(
            shared.bootstrap_rotate_idx.load(Ordering::Relaxed),
            2,
            "rotation index after second call"
        );

        // Wait for spawned workers to finish (they'll fail to connect quickly)
        shared.stop.store(true, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(200));
        super::join_all_service_workers(&shared);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn should_skip_outbound_dial_respects_in_flight_count() {
        let (sync_engine, dir) = test_engine("rubin-node-skip-inflight");
        let cfg = default_peer_runtime_config("devnet", 2);
        let shared = test_shared_state(cfg, vec![], sync_engine);
        let mut in_flight = HashSet::new();

        // No occupancy — should not skip
        assert!(
            !should_skip_outbound_dial(&shared, &in_flight, "1.2.3.4:8333"),
            "empty slots should allow dial"
        );

        // Add one in-flight
        in_flight.insert("5.6.7.8:8333".to_string());
        assert!(
            !should_skip_outbound_dial(&shared, &in_flight, "1.2.3.4:8333"),
            "one in-flight with max_peers=2 should allow"
        );

        // Add second in-flight — now at capacity
        in_flight.insert("9.10.11.12:8333".to_string());
        assert!(
            should_skip_outbound_dial(&shared, &in_flight, "1.2.3.4:8333"),
            "at capacity should skip"
        );

        // Already in-flight should skip regardless
        in_flight.clear();
        in_flight.insert("1.2.3.4:8333".to_string());
        assert!(
            should_skip_outbound_dial(&shared, &in_flight, "1.2.3.4:8333"),
            "already in-flight should skip"
        );

        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn validate_peer_addr_accepts_ipv6_bracketed() {
        super::validate_peer_addr("[::1]:8333").expect("valid IPv6 bracketed");
        super::validate_peer_addr("[2001:db8::1]:19111").expect("valid IPv6 bracketed");
    }

    #[test]
    fn validate_peer_addr_rejects_bracketed_non_ipv6() {
        let err = super::validate_peer_addr("[localhost]:19111").unwrap_err();
        assert!(err.contains("not a valid IPv6"), "unexpected: {err}");

        let err = super::validate_peer_addr("[example.com]:8333").unwrap_err();
        assert!(err.contains("not a valid IPv6"), "unexpected: {err}");
    }

    #[test]
    fn validate_peer_addr_accepts_plain_host_port() {
        super::validate_peer_addr("127.0.0.1:8333").expect("plain IPv4");
    }

    #[test]
    fn validate_peer_addr_rejects_unmatched_brackets() {
        assert!(
            super::validate_peer_addr("[::1:19111").is_err(),
            "missing close bracket"
        );
        assert!(
            super::validate_peer_addr("::1]:19111").is_err(),
            "missing open bracket"
        );
    }

    #[test]
    fn validate_peer_addr_rejects_missing_port() {
        assert!(
            super::validate_peer_addr("[::1]").is_err(),
            "no port after bracket"
        );
    }

    #[test]
    fn validate_peer_addr_rejects_empty_host() {
        let err = super::validate_peer_addr(":8333").unwrap_err();
        assert!(err.contains("empty host"), "unexpected: {err}");
    }

    #[test]
    fn validate_peer_addr_rejects_invalid_port() {
        let err = super::validate_peer_addr("example.com:notaport").unwrap_err();
        assert!(err.contains("invalid port"), "unexpected: {err}");
    }

    #[test]
    fn validate_peer_addr_rejects_no_colon() {
        let err = super::validate_peer_addr("example.com").unwrap_err();
        assert!(err.contains("missing port separator"), "unexpected: {err}");
    }

    #[test]
    fn validate_peer_addr_rejects_bracketed_ipv6_invalid_port() {
        let err = super::validate_peer_addr("[::1]:99999").unwrap_err();
        assert!(err.contains("invalid port"), "out-of-range port: {err}");

        let err = super::validate_peer_addr("[::1]:abc").unwrap_err();
        assert!(err.contains("invalid port"), "non-numeric port: {err}");

        let err = super::validate_peer_addr("[::1]:80:90").unwrap_err();
        assert!(err.contains("invalid port"), "double port: {err}");
    }

    #[test]
    fn connect_with_timeout_returns_error_for_unreachable() {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737), guaranteed unreachable.
        let result = super::connect_with_timeout("192.0.2.1:6553", Duration::from_millis(50));
        assert!(result.is_err(), "should fail for unreachable addr");
    }

    #[test]
    fn start_service_rejects_bracketed_non_ipv6_bootstrap() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-bracket-reject");
        let runtime_cfg = default_peer_runtime_config("devnet", 8);
        let peer_manager = Arc::new(PeerManager::new(runtime_cfg.clone()));
        let result = start_node_p2p_service(NodeP2PServiceConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            bootstrap_peers: vec!["[localhost]:19111".to_string()],
            runtime_cfg,
            peer_manager,
            sync_engine,
            tx_pool: Arc::new(Mutex::new(TxPool::new())),
            chain_id: devnet_genesis_chain_id(),
            genesis_hash: test_genesis_hash(),
        });
        assert!(result.is_err(), "should reject bracketed non-IPv6");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn reap_finished_workers_collects_completed_threads() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-reap-finished");
        let runtime_cfg = default_peer_runtime_config("devnet", 8);
        let shared = test_shared_state(runtime_cfg, vec![], sync_engine);
        // Spawn workers that complete immediately.
        for _ in 0..3 {
            super::spawn_service_worker(&shared, || {});
        }
        // Wait for workers to finish.
        thread::sleep(Duration::from_millis(50));
        // Reap: should collect finished handles and join them.
        super::reap_finished_service_workers(&shared);
        let remaining = super::lock_worker_handles(&shared).len();
        assert_eq!(remaining, 0, "all finished workers should be reaped");
        shared.stop.store(true, Ordering::SeqCst);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn bounded_join_times_out_for_stuck_workers() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-bounded-join-timeout");
        let runtime_cfg = default_peer_runtime_config("devnet", 8);
        let shared = test_shared_state(runtime_cfg, vec![], sync_engine);
        // Spawn a worker that blocks for 5 seconds.
        let blocker_shared = shared.clone();
        super::spawn_service_worker(&shared, move || {
            while !blocker_shared.stop.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(50));
            }
        });
        // Bounded join with 100ms timeout — should give up, not hang.
        super::join_service_workers_bounded(&shared, Duration::from_millis(100));
        // Worker handle should be put back (not joined, not lost).
        let remaining = super::lock_worker_handles(&shared).len();
        assert!(remaining > 0, "stuck worker handle should be preserved");
        // Cleanup.
        shared.stop.store(true, Ordering::SeqCst);
        super::join_all_service_workers(&shared);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn connect_with_timeout_rejects_when_dns_resolvers_saturated() {
        let prev = super::ACTIVE_DNS_RESOLVERS.load(Ordering::SeqCst);
        super::ACTIVE_DNS_RESOLVERS.store(super::MAX_DNS_RESOLVER_THREADS, Ordering::SeqCst);
        let result = super::connect_with_timeout("unreachable.test:80", Duration::from_secs(1));
        super::ACTIVE_DNS_RESOLVERS.store(prev, Ordering::SeqCst);
        let err = result.unwrap_err();
        assert!(
            err.contains("DNS resolver limit reached"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn connect_with_timeout_ipv4_literal_fast_path() {
        let result = super::connect_with_timeout("192.0.2.1:6553", Duration::from_millis(100));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("connect") && !err.contains("DNS"),
            "IP literal should bypass DNS: {err}"
        );
    }

    #[test]
    fn connect_with_timeout_hostname_uses_dns_resolver_path() {
        // "localhost:1" resolves via DNS (not IP literal fast path),
        // covering the resolver thread spawn + channel recv + addr iteration.
        // Port 1 is refused immediately, so this is fast.
        let result = super::connect_with_timeout("localhost:1", Duration::from_millis(500));
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Should be a connect error, not DNS error (localhost resolves).
        assert!(
            err.contains("connect"),
            "localhost should resolve but connect to port 1 should fail: {err}"
        );
    }

    #[test]
    fn reconnect_loop_fires_after_interval() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-reconnect-loop");
        let runtime_cfg = default_peer_runtime_config("devnet", 8);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let bootstrap_addr = listener.local_addr().expect("addr").to_string();
        let shared = test_shared_state(runtime_cfg, vec![bootstrap_addr], sync_engine);
        // Run loop with zero interval so it fires immediately, then stop.
        let loop_shared = shared.clone();
        let handle = thread::spawn(move || {
            super::reconnect_loop_with_interval(
                loop_shared,
                Duration::ZERO,
                Duration::from_millis(10),
            );
        });
        // Wait for at least one reconnect pass, then stop.
        thread::sleep(Duration::from_millis(50));
        shared.stop.store(true, Ordering::SeqCst);
        handle.join().expect("loop join");
        shared.stop.store(true, Ordering::SeqCst);
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
