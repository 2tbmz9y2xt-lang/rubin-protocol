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
// Per-line cap for chunk-size and trailer lines: matches Go's
// `src/net/http/internal/chunked.go` `maxLineLength = 4096`. Go rejects
// `len(p) >= maxLineLength` after `trimTrailingWhitespace`, so we use `>=`
// as well — a 4095-byte line is the largest accepted.
const MAX_CHUNK_LINE_BYTES: usize = 4096;
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
    // Release rpc_op_lock before announce: announce is p2p broadcast, not
    // chain/tx-pool mutation, so holding the RPC op lock across a slow
    // network callback would block concurrent /mine_next for no benefit.
    // Matches the narrowed Go scope in handleSubmitTx (http_rpc.go).
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
// response. After each chunk segment is consumed the parser drains the raw
// buffer to keep retained state bounded by one chunk-size or trailer line
// (≤ MAX_HEADER_BYTES) plus at most one chunk-data window; this prevents a
// tiny-chunk DoS without rejecting valid high-overhead chunked bodies whose
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
        // that grows past MAX_HEADER_BYTES without finding a CRLF is treated
        // as malformed rather than allowed to grow unbounded.
        let size_end = loop {
            if let Some(rel) = find_crlf(&buf[pos..]) {
                // Enforce per-line cap BEFORE accepting the terminator. A
                // crossing read can deliver the byte that pushes the line
                // over the cap together with the CRLF in the same syscall,
                // where the post-read cap below has not fired yet. Matches
                // Go's `readChunkLine` which rejects
                // `len(p) >= maxLineLength` after `trimTrailingWhitespace`
                // (src/net/http/internal/chunked.go:19, 180-182) where
                // `maxLineLength = 4096`.
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
                    // crossing-read guard as the chunk-size loop above,
                    // same Go `readChunkLine` `maxLineLength = 4096` limit).
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
        decode_hex_payload, handle_connection, new_devnet_rpc_state,
        new_devnet_rpc_state_with_tx_pool, new_shared_runtime_tx_pool, parse_hex32,
        parse_query_map, read_http_error_response, read_http_request, render_prometheus_metrics,
        route_request, split_target, start_devnet_rpc_server, status_text, HttpRequest,
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
        // Go `src/net/http/internal/chunked.go:19,180-182`:
        //   const maxLineLength = 4096
        //   if len(p) >= maxLineLength { return nil, ErrLineTooLong }
        // (where `p` is the chunk-size line after `trimTrailingWhitespace`).
        // We mirror this with `MAX_CHUNK_LINE_BYTES = 4096` and a `>=`
        // check. A chunk-size line of exactly 4096 bytes before CRLF must
        // be rejected. The chunk_size hex itself is kept small (1 byte) so
        // the excess-overhead counter (16 KiB cap) cannot reject first on
        // a single such chunk.
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
        // trailers with UTF-8 content (e.g. `"тест"`) continue to work.
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
            stream.write_all(&payload).expect("write payload");
            stream
                .shutdown(std::net::Shutdown::Write)
                .expect("shutdown write");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
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
}
