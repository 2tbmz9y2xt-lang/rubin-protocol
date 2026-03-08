use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::p2p_runtime::PeerManager;
use crate::{BlockStore, SyncEngine, TxPool, TxPoolAdmitErrorKind};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct DevnetRPCState {
    sync_engine: Arc<Mutex<SyncEngine>>,
    block_store: Option<BlockStore>,
    tx_pool: Arc<Mutex<TxPool>>,
    peer_manager: Arc<PeerManager>,
    metrics: Arc<RpcMetrics>,
    now_unix: fn() -> u64,
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

pub fn new_devnet_rpc_state(
    sync_engine: Arc<Mutex<SyncEngine>>,
    block_store: Option<BlockStore>,
    peer_manager: Arc<PeerManager>,
) -> DevnetRPCState {
    DevnetRPCState {
        sync_engine,
        block_store,
        tx_pool: Arc::new(Mutex::new(TxPool::new())),
        peer_manager,
        metrics: Arc::new(RpcMetrics::default()),
        now_unix: current_unix,
    }
}

pub fn start_devnet_rpc_server(
    bind_addr: &str,
    state: DevnetRPCState,
) -> Result<RunningDevnetRPCServer, String> {
    let listener = TcpListener::bind(bind_addr).map_err(|err| format!("bind {bind_addr}: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("set_nonblocking: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("local_addr: {err}"))?
        .to_string();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
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

fn run_accept_loop(listener: TcpListener, state: DevnetRPCState, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = handle_connection(stream, &state);
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
    let Some(block_store) = state.block_store.as_ref() else {
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
    };
    let params = parse_query_map(query);
    let height_raw = params.get("height").map(|v| v.trim()).unwrap_or("");
    let hash_raw = params.get("hash").map(|v| v.trim()).unwrap_or("");
    if (height_raw.is_empty() && hash_raw.is_empty()) || (!height_raw.is_empty() && !hash_raw.is_empty()) {
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
    if !block_store.has_block(block_hash) {
        return json_response(
            state,
            ROUTE,
            404,
            &SubmitTxResponse {
                accepted: false,
                txid: None,
                error: Some("block not found".to_string()),
            },
        );
    }
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
    let admit_result = match state.tx_pool.lock() {
        Ok(mut pool) => pool.admit(&tx_bytes, &chain_state, state.block_store.as_ref(), chain_id),
        Err(_) => Err(crate::TxPoolAdmitError {
            kind: TxPoolAdmitErrorKind::Unavailable,
            message: "tx pool unavailable".to_string(),
        }),
    };
    match admit_result {
        Ok(txid) => {
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
    let (tip_height, best_known_height, in_ibd) = match state.sync_engine.lock() {
        Ok(engine) => {
            let tip_height = match engine.tip() {
                Ok(Some((height, _))) => height,
                _ => 0,
            };
            let best_known_height = engine.best_known_height();
            let in_ibd = if engine.is_in_ibd((state.now_unix)()) { 1 } else { 0 };
            (tip_height, best_known_height, in_ibd)
        }
        Err(_) => (0, 0, 1),
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
        "# HELP rubin_node_best_known_height Best known height recorded by sync engine.".to_string(),
        "# TYPE rubin_node_best_known_height gauge".to_string(),
        format!("rubin_node_best_known_height {best_known_height}"),
        "# HELP rubin_node_in_ibd Whether the node currently considers itself in IBD (0 or 1)."
            .to_string(),
        "# TYPE rubin_node_in_ibd gauge".to_string(),
        format!("rubin_node_in_ibd {in_ibd}"),
        "# HELP rubin_node_peer_count Currently tracked peers.".to_string(),
        "# TYPE rubin_node_peer_count gauge".to_string(),
        format!("rubin_node_peer_count {peer_count}"),
        "# HELP rubin_node_mempool_txs Number of transactions currently in the mempool.".to_string(),
        "# TYPE rubin_node_mempool_txs gauge".to_string(),
        format!("rubin_node_mempool_txs {mempool_txs}"),
        "# HELP rubin_node_rpc_requests_total Total HTTP RPC requests by route and status.".to_string(),
        "# TYPE rubin_node_rpc_requests_total counter".to_string(),
    ];

    let mut route_entries: Vec<_> = route_status.into_iter().collect();
    route_entries.sort_by(|a, b| a.0.cmp(&b.0));
    for ((route, status), value) in route_entries {
        lines.push(format!(
            "rubin_node_rpc_requests_total{{route=\"{route}\",status=\"{status}\"}} {value}"
        ));
    }

    lines.push("# HELP rubin_node_submit_tx_total Total submit_tx outcomes by result label.".to_string());
    lines.push("# TYPE rubin_node_submit_tx_total counter".to_string());
    let mut submit_entries: Vec<_> = submit_results.into_iter().collect();
    submit_entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (result, value) in submit_entries {
        lines.push(format!(
            "rubin_node_submit_tx_total{{result=\"{result}\"}} {value}"
        ));
    }
    lines.join("\n") + "\n"
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut temp).map_err(|err| format!("read: {err}"))?;
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

    let header_text = std::str::from_utf8(&buf[..header_end]).map_err(|_| "invalid request headers".to_string())?;
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
        let read = stream.read(&mut temp).map_err(|err| format!("read body: {err}"))?;
        if read == 0 {
            return Err("unexpected eof".to_string());
        }
        buf.extend_from_slice(&temp[..read]);
        if buf.len() > MAX_HEADER_BYTES + MAX_BODY_BYTES {
            return Err("request too large".to_string());
        }
    }
    let body = buf[body_start..body_start + content_length].to_vec();
    Ok(HttpRequest { method, target, body })
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
    let body = serde_json::to_vec(payload).unwrap_or_else(|_| {
        b"{\"accepted\":false,\"error\":\"encode failed\"}".to_vec()
    });
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
    let trimmed = value.trim().trim_start_matches("0x").trim_start_matches("0X");
    if trimmed.is_empty() {
        return Err("tx_hex is required".to_string());
    }
    if trimmed.len() % 2 != 0 {
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
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use serde_json::Value;

    use crate::{
        block_store_path, default_peer_runtime_config, default_sync_config, devnet_genesis_block_bytes,
        devnet_genesis_chain_id, BlockStore, ChainState, PeerManager, SyncEngine,
    };

    use super::{new_devnet_rpc_state, render_prometheus_metrics, route_request, HttpRequest};

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    fn build_state(with_genesis: bool) -> (super::DevnetRPCState, PathBuf) {
        let dir = unique_temp_dir("rubin-devnet-rpc");
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
        let state = new_devnet_rpc_state(
            Arc::new(Mutex::new(engine)),
            Some(block_store),
            Arc::new(PeerManager::new(default_peer_runtime_config("devnet", 8))),
        );
        (state, dir)
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
    fn metrics_render_includes_v1_names() {
        let (state, dir) = build_state(true);
        let body = render_prometheus_metrics(&state);
        for name in [
            "rubin_node_tip_height",
            "rubin_node_best_known_height",
            "rubin_node_in_ibd",
            "rubin_node_peer_count",
            "rubin_node_mempool_txs",
            "rubin_node_rpc_requests_total",
            "rubin_node_submit_tx_total",
        ] {
            assert!(body.contains(name), "missing metric {name}");
        }
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
