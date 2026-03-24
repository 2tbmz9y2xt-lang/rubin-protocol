use std::collections::HashSet;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::p2p_runtime::VersionPayloadV1;
use crate::p2p_runtime::{perform_version_handshake, PeerManager, PeerRuntimeConfig};
use crate::SyncEngine;

const ACCEPT_LOOP_SLEEP: Duration = Duration::from_millis(100);
const RECONNECT_LOOP_SLEEP: Duration = Duration::from_millis(250);
const RECONNECT_INTERVAL: Duration = Duration::from_secs(5);
const MIN_OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SERVICE_CLOSE_WAIT_SLEEP: Duration = Duration::from_millis(25);

#[derive(Clone)]
pub struct NodeP2PServiceConfig {
    pub bind_addr: String,
    pub bootstrap_peers: Vec<String>,
    pub runtime_cfg: PeerRuntimeConfig,
    pub peer_manager: Arc<PeerManager>,
    pub sync_engine: Arc<Mutex<SyncEngine>>,
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
    bootstrap_peers: Arc<Vec<String>>,
    in_flight_dials: Arc<Mutex<HashSet<String>>>,
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
}

pub fn start_node_p2p_service(cfg: NodeP2PServiceConfig) -> Result<RunningNodeP2PService, String> {
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
    let shared = SharedServiceState {
        stop: Arc::clone(&stop),
        runtime_cfg: cfg.runtime_cfg,
        active_sessions: Arc::new(AtomicUsize::new(0)),
        worker_handles: Arc::new(Mutex::new(Vec::new())),
        peer_manager: cfg.peer_manager,
        sync_engine: cfg.sync_engine,
        bootstrap_peers: Arc::new(cfg.bootstrap_peers),
        in_flight_dials: Arc::new(Mutex::new(HashSet::new())),
        chain_id: cfg.chain_id,
        genesis_hash: cfg.genesis_hash,
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

    pub fn close(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.addr);
        if let Some(join) = self.accept_join.take() {
            let _ = join.join();
        }
        if let Some(join) = self.reconnect_join.take() {
            let _ = join.join();
        }
        join_all_service_workers(&self.shared);
        wait_for_service_shutdown(&self.shared);
    }
}

impl Drop for RunningNodeP2PService {
    fn drop(&mut self) {
        self.close();
    }
}

fn run_accept_loop(listener: TcpListener, shared: SharedServiceState) {
    while !shared.stop.load(Ordering::SeqCst) {
        reap_finished_service_workers(&shared);
        match listener.accept() {
            Ok((stream, _)) => {
                let Some(session_slot) = try_acquire_session_slot(&shared) else {
                    drop(stream);
                    continue;
                };
                let handler_shared = shared.clone();
                spawn_service_worker(&shared, move || {
                    let _session_slot = session_slot;
                    let _ = handle_peer(stream, None, handler_shared);
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_LOOP_SLEEP);
            }
            Err(_) => {
                thread::sleep(accept_error_backoff());
            }
        }
    }
}

fn run_reconnect_loop(shared: SharedServiceState) {
    let mut waited = Duration::ZERO;
    while !shared.stop.load(Ordering::SeqCst) {
        reap_finished_service_workers(&shared);
        if waited >= RECONNECT_INTERVAL {
            reconnect_missing_bootstrap_peers(&shared);
            waited = Duration::ZERO;
        }
        thread::sleep(RECONNECT_LOOP_SLEEP);
        waited += RECONNECT_LOOP_SLEEP;
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
    spawn_service_worker(&shared, move || {
        let connect_timeout = outbound_connect_timeout(&worker_shared.runtime_cfg);
        let result = connect_with_timeout(&addr, connect_timeout).and_then(|stream| {
            let Some(session_slot) = try_acquire_session_slot(&worker_shared) else {
                return Err(format!("session cap reached before handshake: {addr}"));
            };
            let result = handle_peer(stream, Some(addr.clone()), worker_shared.clone());
            drop(session_slot);
            result
        });
        let mut guard = lock_in_flight_dials(&worker_shared);
        guard.remove(&addr);
        drop(guard);
        let _ = result;
    });
}

fn is_connected(peer_manager: &PeerManager, addr: &str) -> bool {
    peer_manager.snapshot().iter().any(|peer| peer.addr == addr)
}

fn reconnect_missing_bootstrap_peers(shared: &SharedServiceState) {
    for addr in shared.bootstrap_peers.iter() {
        if !is_connected(&shared.peer_manager, addr) {
            start_outbound_peer(addr.clone(), shared.clone());
        }
    }
}

fn accept_error_backoff() -> Duration {
    ACCEPT_LOOP_SLEEP
}

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

fn lock_in_flight_dials<'a>(
    shared: &'a SharedServiceState,
) -> std::sync::MutexGuard<'a, HashSet<String>> {
    shared
        .in_flight_dials
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_worker_handles<'a>(
    shared: &'a SharedServiceState,
) -> std::sync::MutexGuard<'a, Vec<JoinHandle<()>>> {
    shared
        .worker_handles
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn spawn_service_worker(shared: &SharedServiceState, worker: impl FnOnce() + Send + 'static) {
    let handle = thread::spawn(worker);
    let mut handles = lock_worker_handles(shared);
    handles.push(handle);
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

fn try_acquire_session_slot(shared: &SharedServiceState) -> Option<SessionSlotGuard> {
    loop {
        let current = shared.active_sessions.load(Ordering::SeqCst);
        if current >= shared.runtime_cfg.max_peers {
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

fn connect_with_timeout(addr: &str, timeout: Duration) -> Result<TcpStream, String> {
    let socket_addr: SocketAddr = addr
        .parse()
        .map_err(|err| format!("bootstrap peer must be literal socket address ({addr}): {err}"))?;
    TcpStream::connect_timeout(&socket_addr, timeout)
        .map_err(|err| format!("connect {addr}: {err}"))
}

fn wait_for_service_shutdown(shared: &SharedServiceState) {
    let wait_budget = shared
        .runtime_cfg
        .read_deadline
        .max(outbound_connect_timeout(&shared.runtime_cfg))
        + RECONNECT_LOOP_SLEEP;
    let deadline = Instant::now() + wait_budget;
    while Instant::now() < deadline {
        let dials_drained = lock_in_flight_dials(shared).is_empty();
        let sessions_drained = shared.active_sessions.load(Ordering::SeqCst) == 0;
        if dials_drained && sessions_drained {
            return;
        }
        thread::sleep(SERVICE_CLOSE_WAIT_SLEEP);
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
        addr: peer_addr,
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
        let msg = match session.read_message() {
            Ok(msg) => msg,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(err) => return Err(format!("read message: {err}")),
        };
        let outbound_messages = {
            let mut engine = shared
                .sync_engine
                .lock()
                .map_err(|_| "sync engine unavailable".to_string())?;
            session
                .collect_live_responses(msg, &mut engine)
                .map_err(|err| format!("handle live message: {err}"))?
        };
        for outbound in outbound_messages {
            session
                .write_message(&outbound)
                .map_err(|err| format!("handle live message: {err}"))?;
        }
    }
    Ok(())
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
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use rubin_consensus::{block_hash, constants::POW_LIMIT, BLOCK_HEADER_BYTES};

    use super::{
        accept_error_backoff, connect_with_timeout, join_all_service_workers, lock_in_flight_dials,
        outbound_connect_timeout, reconnect_missing_bootstrap_peers, should_skip_outbound_dial,
        start_node_p2p_service, wait_for_service_shutdown, NodeP2PServiceConfig,
        SharedServiceState,
    };
    use crate::genesis::{devnet_genesis_block_bytes, devnet_genesis_chain_id};
    use crate::interop::local_version;
    use crate::p2p_runtime::{
        default_peer_runtime_config, perform_version_handshake, PeerManager, PeerRuntimeConfig,
    };
    use crate::{block_store_path, default_sync_config, BlockStore, ChainState, SyncEngine};

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
            bootstrap_peers: Arc::new(bootstrap_peers),
            in_flight_dials: Arc::new(Mutex::new(HashSet::new())),
            chain_id: devnet_genesis_chain_id(),
            genesis_hash: test_genesis_hash(),
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
    fn service_accepts_inbound_peer_handshake() {
        let (sync_engine, dir) = test_engine("rubin-node-p2p-service-inbound");
        let mut runtime_cfg = default_peer_runtime_config("devnet", 8);
        runtime_cfg.read_deadline = Duration::from_secs(1);
        runtime_cfg.write_deadline = Duration::from_secs(1);
        let mut service = start_node_p2p_service(NodeP2PServiceConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            bootstrap_peers: Vec::new(),
            runtime_cfg: runtime_cfg.clone(),
            peer_manager: Arc::new(PeerManager::new(runtime_cfg.clone())),
            sync_engine,
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
        runtime_cfg.read_deadline = Duration::from_millis(250);
        runtime_cfg.write_deadline = Duration::from_millis(250);
        let peer_manager = Arc::new(PeerManager::new(runtime_cfg.clone()));
        let mut service = start_node_p2p_service(NodeP2PServiceConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            bootstrap_peers: vec!["192.0.2.1:6553".to_string()],
            runtime_cfg: runtime_cfg.clone(),
            peer_manager,
            sync_engine,
            chain_id: devnet_genesis_chain_id(),
            genesis_hash: test_genesis_hash(),
        })
        .expect("start service");

        thread::sleep(Duration::from_millis(75));

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

        let first = super::try_acquire_session_slot(&shared).expect("first session slot");
        assert!(
            super::try_acquire_session_slot(&shared).is_none(),
            "session cap must reject the second slot while the first is active"
        );

        drop(first);
        assert!(
            super::try_acquire_session_slot(&shared).is_some(),
            "slot must become available again after the active session drops"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn accept_error_backoff_retries_listener_errors() {
        assert_eq!(accept_error_backoff(), Duration::from_millis(100));
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
    fn connect_with_timeout_rejects_non_literal_bootstrap_addr() {
        let err = connect_with_timeout("bad host:19111", Duration::from_millis(25)).unwrap_err();
        assert!(
            err.starts_with("bootstrap peer must be literal socket address (bad host:19111):"),
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
}
