use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::miner::{Miner, MinerConfig};
use crate::p2p_runtime::PeerManager;
use crate::{BlockStore, SyncEngine, TxPool, TxPoolAdmitErrorKind, TxPoolConfig};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_CONCURRENT_RPC_CONNS: usize = 8;

pub type AnnounceTxFn =
    Arc<dyn Fn(&[u8], crate::txpool::RelayTxMetadata) -> Result<(), String> + Send + Sync>;

#[derive(Clone)]
pub struct DevnetRPCState {
    sync_engine: Arc<Mutex<SyncEngine>>,
    block_store: Option<BlockStore>,
    tx_pool: Arc<Mutex<TxPool>>,
    peer_manager: Arc<PeerManager>,
    metrics: Arc<RpcMetrics>,
    now_unix: fn() -> u64,
    announce_tx: Option<AnnounceTxFn>,
    /// Serializes mutating devnet RPC (submit_tx + mine_next).
    rpc_op_lock: Arc<Mutex<()>>,
    /// When set, POST `/mine_next` mines one block using this config (devnet + loopback RPC only).
    live_mining_cfg: Option<MinerConfig>,
}

pub struct RunningDevnetRPCServer {
    addr: String,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
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

/// True when the host in `host:port` is loopback-only (safe for devnet live mining RPC).
pub fn rpc_bind_host_is_loopback(bind_addr: &str) -> bool {
    let addr = bind_addr.trim();
    if addr.is_empty() {
        return false;
    }
    let host = if addr.starts_with('[') {
        let Some(bracket_end) = addr.find("]:") else {
            return false;
        };
        &addr[1..bracket_end]
    } else if let Some(colon_pos) = addr.rfind(':') {
        let host = &addr[..colon_pos];
        if host.contains(':') {
            return false;
        }
        host
    } else {
        return false;
    };
    let host = host.trim();
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
) -> DevnetRPCState {
    let tx_pool = new_shared_runtime_tx_pool(&sync_engine);
    new_devnet_rpc_state_with_tx_pool(
        sync_engine,
        block_store,
        tx_pool,
        peer_manager,
        announce_tx,
        None,
    )
}

pub fn new_devnet_rpc_state_with_tx_pool(
    sync_engine: Arc<Mutex<SyncEngine>>,
    block_store: Option<BlockStore>,
    tx_pool: Arc<Mutex<TxPool>>,
    peer_manager: Arc<PeerManager>,
    announce_tx: Option<AnnounceTxFn>,
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
        rpc_op_lock: Arc::new(Mutex::new(())),
        live_mining_cfg,
    }
}

pub fn new_shared_runtime_tx_pool(sync_engine: &Arc<Mutex<SyncEngine>>) -> Arc<Mutex<TxPool>> {
    let (core_ext_deployments, suite_context) = sync_engine
        .lock()
        .map(|engine| {
            (
                engine.core_ext_deployments(),
                engine.cfg.suite_context.clone(),
            )
        })
        .unwrap_or_else(|_| (Default::default(), None));
    Arc::new(Mutex::new(TxPool::new_with_config(TxPoolConfig {
        core_ext_deployments,
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
    let state = Arc::new(state);
    let join = thread::spawn(move || {
        run_accept_loop(listener, state, stop_flag);
    });
    Ok(RunningDevnetRPCServer {
        addr,
        stop,
        join: Some(join),
    })
}

impl RunningDevnetRPCServer {
    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn close(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.addr);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for RunningDevnetRPCServer {
    fn drop(&mut self) {
        self.close();
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

fn run_accept_loop(listener: TcpListener, state: Arc<DevnetRPCState>, stop: Arc<AtomicBool>) {
    let active = Arc::new(AtomicUsize::new(0));
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
                        let _ = handle_connection(stream, &st);
                        ctr.fetch_sub(1, Ordering::SeqCst);
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
    let req = read_http_request(&mut stream)?;
    let response = route_request(state, req);
    write_http_response(&mut stream, response)
}

fn route_request(state: &DevnetRPCState, req: HttpRequest) -> HttpResponse {
    let (path, query) = split_target(&req.target);
    match path {
        "/get_tip" => handle_get_tip(state, &req.method),
        "/get_block" => handle_get_block(state, &req.method, &query),
        "/submit_tx" => handle_submit_tx(state, &req.method, &req.body),
        "/mine_next" => handle_mine_next(state, &req.method, &req.body),
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
    let admit_result = match state.tx_pool.lock() {
        Ok(mut pool) => pool.admit_with_metadata(
            &tx_bytes,
            &chain_state,
            fresh_block_store.as_ref(),
            chain_id,
        ),
        Err(_) => Err(crate::TxPoolAdmitError {
            kind: TxPoolAdmitErrorKind::Unavailable,
            message: "tx pool unavailable".to_string(),
        }),
    };
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
    match miner.mine_one(&[]) {
        Ok(b) => json_response(
            state,
            ROUTE,
            200,
            &MineNextResponse {
                mined: true,
                height: Some(b.height),
                block_hash: Some(hex::encode(b.hash)),
                timestamp: Some(b.timestamp),
                nonce: Some(b.nonce),
                tx_count: Some(b.tx_count),
                error: None,
            },
        ),
        Err(err) => json_response(
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
        ),
    }
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
    let (tip_height, best_known_height, in_ibd, pv_lines) = match state.sync_engine.lock() {
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
            let pv_lines = engine.pv_telemetry_snapshot().prometheus_lines();
            (tip_height, best_known_height, in_ibd, pv_lines)
        }
        Err(_) => (0, 0, 1, Vec::new()),
    };
    let mempool_txs = match state.tx_pool.lock() {
        Ok(pool) => pool.len() as u64,
        Err(_) => 0,
    };
    let peer_count = state.peer_manager.snapshot().len() as u64;
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
        "# HELP rubin_node_peer_count Currently tracked peers.".to_string(),
        "# TYPE rubin_node_peer_count gauge".to_string(),
        format!("rubin_node_peer_count {peer_count}"),
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
        lines.push(format!(
            "rubin_node_rpc_requests_total{{route=\"{route}\",status=\"{status}\"}} {value}"
        ));
    }

    lines.push(
        "# HELP rubin_node_submit_tx_total Total submit_tx outcomes by result label.".to_string(),
    );
    lines.push("# TYPE rubin_node_submit_tx_total counter".to_string());
    let mut submit_entries: Vec<_> = submit_results.into_iter().collect();
    submit_entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (result, value) in submit_entries {
        lines.push(format!(
            "rubin_node_submit_tx_total{{result=\"{result}\"}} {value}"
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
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| "missing method".to_string())?
        .to_string();
    let target = request_parts
        .next()
        .ok_or_else(|| "missing target".to_string())?
        .to_string();
    let _version = request_parts
        .next()
        .ok_or_else(|| "missing http version".to_string())?;

    let mut content_length = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("malformed header".to_string());
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            content_length = value
                .trim()
                .parse::<usize>()
                .map_err(|_| "invalid Content-Length".to_string())?;
        }
    }
    if content_length > MAX_BODY_BYTES {
        return Err("body too large".to_string());
    }

    let body_start = header_end + 4;
    while buf.len() < body_start + content_length {
        let read = stream
            .read(&mut temp)
            .map_err(|err| format!("read body: {err}"))?;
        if read == 0 {
            return Err("unexpected eof".to_string());
        }
        buf.extend_from_slice(&temp[..read]);
        if buf.len() > MAX_HEADER_BYTES + MAX_BODY_BYTES {
            return Err("request too large".to_string());
        }
    }
    let body = buf[body_start..body_start + content_length].to_vec();
    Ok(HttpRequest {
        method,
        target,
        body,
    })
}

fn write_http_response(stream: &mut TcpStream, response: HttpResponse) -> Result<(), String> {
    let status_text = status_text(response.status);
    let headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        status_text,
        response.content_type,
        response.body.len()
    );
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
        409 => "Conflict",
        422 => "Unprocessable Entity",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

struct HttpResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl HttpResponse {
    fn plain(status: u16, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type,
            body: body.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use rubin_consensus::{parse_tx, Outpoint, UtxoEntry};
    use serde_json::Value;

    use crate::io_utils::unique_temp_path;
    use crate::{
        block_store_path, default_peer_runtime_config, default_sync_config,
        devnet_genesis_block_bytes, devnet_genesis_chain_id, BlockStore, ChainState, MinerConfig,
        PeerManager, SyncEngine, TxPool,
    };

    use super::{
        decode_hex_payload, new_devnet_rpc_state, new_devnet_rpc_state_with_tx_pool,
        new_shared_runtime_tx_pool, parse_hex32, parse_query_map, read_http_request,
        render_prometheus_metrics, route_request, split_target, start_devnet_rpc_server,
        status_text, HttpRequest,
    };

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
            core_ext_deployments: sync_engine.lock().expect("lock").core_ext_deployments(),
            ..MinerConfig::default()
        };
        let state = new_devnet_rpc_state_with_tx_pool(
            sync_engine,
            Some(rpc_block_store),
            tx_pool,
            Arc::new(PeerManager::new(default_peer_runtime_config("devnet", 8))),
            None,
            Some(live_cfg),
        );
        (state, dir)
    }

    fn read_request_from_bytes(raw: &[u8]) -> Result<HttpRequest, String> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let payload = raw.to_vec();
        let writer = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream.write_all(&payload).expect("write payload");
            stream
                .shutdown(std::net::Shutdown::Write)
                .expect("shutdown write");
        });
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set read timeout");
        let result = read_http_request(&mut stream);
        writer.join().expect("join writer");
        result
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
            rpc_op_lock: Arc::new(Mutex::new(())),
            live_mining_cfg: None,
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
    fn submit_tx_accepts_valid_conformance_tx() {
        let vector = positive_fixture_vector();
        assert!(vector.expect_ok, "{} should be positive fixture", vector.id);
        let raw = hex::decode(&vector.tx_hex).expect("tx hex");
        let (_tx, txid, _wtxid, consumed) = parse_tx(&raw).expect("parse tx");
        assert_eq!(consumed, raw.len(), "{}", vector.id);
        let expected_txid = hex::encode(txid);

        let state = build_state_with_chain_state(
            chain_state_from_positive_fixture(&vector),
            fixture_chain_id(vector.chain_id.as_deref()),
        );
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

        let vector = positive_fixture_vector();
        assert!(vector.expect_ok);
        let raw = hex::decode(&vector.tx_hex).expect("decode tx hex");
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let mut state = build_state_with_chain_state(
            chain_state_from_positive_fixture(&vector),
            fixture_chain_id(vector.chain_id.as_deref()),
        );
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
        let vector = positive_fixture_vector();
        assert!(vector.expect_ok);
        let raw = hex::decode(&vector.tx_hex).expect("decode tx hex");

        let mut state = build_state_with_chain_state(
            chain_state_from_positive_fixture(&vector),
            fixture_chain_id(vector.chain_id.as_deref()),
        );
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
            rpc_op_lock: Arc::new(Mutex::new(())),
            live_mining_cfg: None,
        };

        let body = render_prometheus_metrics(&state);
        assert!(body.contains("rubin_node_tip_height 7"), "{body}");
        assert!(body.contains("rubin_node_best_known_height 9"), "{body}");
        assert!(body.contains("rubin_node_in_ibd 0"), "{body}");
    }

    #[test]
    fn metrics_render_includes_v1_names() {
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
            "rubin_node_peer_count",
            "rubin_node_mempool_txs",
            "rubin_node_rpc_requests_total",
            "rubin_node_submit_tx_total",
            "rubin_pv_mode",
            "rubin_pv_blocks_validated_total",
            "rubin_pv_blocks_skipped_total",
            "rubin_pv_shadow_mismatches_total",
            "rubin_pv_validate_runs_total",
        ] {
            assert!(body.contains(name), "missing metric {name}");
        }
        assert!(body.contains(r#"rubin_node_rpc_requests_total{route="/get_tip",status="200"} 1"#));
        assert!(body.contains(r#"rubin_node_submit_tx_total{result="rejected"} 1"#));
        assert!(body.contains(r#"rubin_pv_mode{mode="off"} 1"#));
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
        server.close();
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
}
