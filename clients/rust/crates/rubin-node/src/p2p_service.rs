use std::collections::HashSet;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::p2p_runtime::VersionPayloadV1;
use crate::p2p_runtime::{perform_version_handshake, PeerManager, PeerRuntimeConfig};
use crate::SyncEngine;

const ACCEPT_LOOP_SLEEP: Duration = Duration::from_millis(100);
const RECONNECT_LOOP_SLEEP: Duration = Duration::from_millis(250);
const RECONNECT_INTERVAL: Duration = Duration::from_secs(5);

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
    accept_join: Option<JoinHandle<()>>,
    reconnect_join: Option<JoinHandle<()>>,
}

#[derive(Clone)]
struct SharedServiceState {
    stop: Arc<AtomicBool>,
    runtime_cfg: PeerRuntimeConfig,
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
    }
}

impl Drop for RunningNodeP2PService {
    fn drop(&mut self) {
        self.close();
    }
}

fn run_accept_loop(listener: TcpListener, shared: SharedServiceState) {
    while !shared.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let handler_shared = shared.clone();
                thread::spawn(move || {
                    let _ = handle_peer(stream, None, handler_shared);
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_LOOP_SLEEP);
            }
            Err(_) => break,
        }
    }
}

fn run_reconnect_loop(shared: SharedServiceState) {
    let mut waited = Duration::ZERO;
    while !shared.stop.load(Ordering::SeqCst) {
        if waited >= RECONNECT_INTERVAL {
            for addr in shared.bootstrap_peers.iter() {
                if !is_connected(&shared.peer_manager, addr) {
                    start_outbound_peer(addr.clone(), shared.clone());
                }
            }
            waited = Duration::ZERO;
        }
        thread::sleep(RECONNECT_LOOP_SLEEP);
        waited += RECONNECT_LOOP_SLEEP;
    }
}

fn start_outbound_peer(addr: String, shared: SharedServiceState) {
    let Ok(mut guard) = shared.in_flight_dials.lock() else {
        return;
    };
    if guard.contains(&addr) {
        return;
    }
    guard.insert(addr.clone());
    drop(guard);
    thread::spawn(move || {
        let result = TcpStream::connect(&addr)
            .map_err(|err| format!("connect {addr}: {err}"))
            .and_then(|stream| handle_peer(stream, Some(addr.clone()), shared.clone()));
        let Ok(mut guard) = shared.in_flight_dials.lock() else {
            return;
        };
        guard.remove(&addr);
        drop(guard);
        let _ = result;
    });
}

fn is_connected(peer_manager: &PeerManager, addr: &str) -> bool {
    peer_manager.snapshot().iter().any(|peer| peer.addr == addr)
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
        session
            .request_blocks_if_behind(&engine)
            .map_err(|err| format!("initial sync request: {err}"))?;
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
        let mut engine = shared
            .sync_engine
            .lock()
            .map_err(|_| "sync engine unavailable".to_string())?;
        session
            .handle_live_message(msg, &mut engine)
            .map_err(|err| format!("handle live message: {err}"))?;
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use rubin_consensus::{block_hash, constants::POW_LIMIT, BLOCK_HEADER_BYTES};

    use super::{start_node_p2p_service, NodeP2PServiceConfig};
    use crate::genesis::{devnet_genesis_block_bytes, devnet_genesis_chain_id};
    use crate::interop::local_version;
    use crate::p2p_runtime::{default_peer_runtime_config, perform_version_handshake, PeerManager};
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
}
