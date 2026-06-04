use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rubin_consensus::{
    canonical_rotation_network_name_normalized, normalized_rotation_network_name,
    SUPPORTED_ROTATION_NETWORK_NAMES_CSV,
};
use rubin_node::devnet_rpc::{
    attach_shutdown_signal_to_devnet_rpc_state, RPC_READINESS_TRANSITION_FAILED,
};
use rubin_node::{
    block_store_path, chain_state_path, default_peer_runtime_config, default_sync_config,
    load_chain_state, load_genesis_config, new_devnet_rpc_state_with_tx_pool,
    new_shared_runtime_tx_pool, parse_mine_address_arg, reconcile_chain_state_with_block_store,
    rpc_bind_host_is_loopback, start_devnet_rpc_server, start_node_p2p_service,
    validate_mainnet_genesis_guard, BlockStore, LoadedGenesisConfig, Miner, MinerConfig,
    NodeP2PServiceConfig, PeerManager, RunningDevnetRPCServer, RunningNodeP2PService, SyncEngine,
};
use serde::{Deserialize, Serialize};

const PRODUCTION_STOP_SIGNAL_SET: &str = "SIGINT/SIGTERM";

#[derive(Clone, Debug, PartialEq, Eq)]
struct CliConfig {
    network: String,
    data_dir: PathBuf,
    genesis_file: Option<PathBuf>,
    bind_addr: String,
    peers: Vec<String>,
    max_peers: usize,
    rpc_bind_addr: String,
    mine_address: Option<String>,
    mine_blocks: usize,
    mine_exit: bool,
    pv_mode: String,
    pv_shadow_max: u64,
    legacy_exposure_scan: bool,
    legacy_suite_ids: Vec<u8>,
    legacy_exposure_include_outpoints: bool,
    dry_run: bool,
}

#[derive(Serialize)]
struct EffectiveConfig {
    network: String,
    data_dir: String,
    chain_id_hex: String,
    genesis_file: Option<String>,
    bind_addr: String,
    peers: Vec<String>,
    max_peers: usize,
    rpc_bind_addr: Option<String>,
    mine_address: Option<String>,
    mine_blocks: usize,
    mine_exit: bool,
    pv_mode: String,
    pv_shadow_max: u64,
}

#[derive(Deserialize, Serialize)]
struct LegacyExposureSuiteReport {
    suite_id: u64,
    utxo_exposure_count: u64,
    outpoint_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    outpoints: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize)]
struct LegacyExposureReport {
    report_version: u64,
    measurement_scope: String,
    network: String,
    data_dir: String,
    chainstate_height: u64,
    chainstate_has_tip: bool,
    indexed_suite_ids: Vec<u64>,
    watched_legacy_suite_ids: Vec<u64>,
    legacy_exposure_total: u64,
    sunset_readiness: String,
    warning_hook: String,
    grace_hook: String,
    include_outpoints: bool,
    legacy_suite_reports: Vec<LegacyExposureSuiteReport>,
}

const LEGACY_EXPOSURE_REPORT_VERSION: u64 = 1;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let exit_code = run(&args, &mut io::stdout(), &mut io::stderr());
    std::process::exit(exit_code);
}

fn load_legacy_exposure_scan_chain_state(
    chain_state_file: &PathBuf,
    stderr: &mut dyn Write,
) -> Result<rubin_node::ChainState, i32> {
    if let Err(err) = fs::metadata(chain_state_file) {
        if err.kind() == io::ErrorKind::NotFound {
            let _ = writeln!(
                stderr,
                "legacy exposure scan requires an existing chainstate file with a tip: {}",
                chain_state_file.display()
            );
        } else {
            let _ = writeln!(
                stderr,
                "legacy exposure scan chainstate stat failed ({}): {err}",
                chain_state_file.display()
            );
        }
        return Err(2);
    }
    let chain_state = match load_chain_state(chain_state_file) {
        Ok(chain_state) => chain_state,
        Err(err) => {
            let _ = writeln!(
                stderr,
                "chainstate load failed ({}): {err}",
                chain_state_file.display()
            );
            return Err(2);
        }
    };
    if !chain_state.has_tip {
        let _ = writeln!(
            stderr,
            "legacy exposure scan requires a chainstate with a tip: {}",
            chain_state_file.display()
        );
        return Err(2);
    }
    Ok(chain_state)
}

fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        usage(stdout);
        return 0;
    }

    let mut cfg = match parse_args(args) {
        Ok(cfg) => cfg,
        Err(err) => {
            let _ = writeln!(stderr, "{err}");
            return 2;
        }
    };
    if let Err(err) = validate_config(&mut cfg) {
        let _ = writeln!(stderr, "{err}");
        return 2;
    }

    let chain_state_file = chain_state_path(&cfg.data_dir);
    if cfg.legacy_exposure_scan {
        let chain_state = match load_legacy_exposure_scan_chain_state(&chain_state_file, stderr) {
            Ok(chain_state) => chain_state,
            Err(code) => return code,
        };
        let report = build_legacy_exposure_report(&cfg, &chain_state);
        if let Err(err) = serde_json::to_writer_pretty(&mut *stdout, &report) {
            let _ = writeln!(stderr, "legacy exposure encode failed: {err}");
            return 1;
        }
        let _ = writeln!(stdout);
        return 0;
    }
    if cfg.network != "devnet" && cfg.genesis_file.is_none() {
        let _ = writeln!(
            stderr,
            "error: --network {} requires a genesis file (--genesis-file) with chain_id and genesis_hash",
            cfg.network
        );
        return 2;
    }
    let genesis_cfg = match load_genesis_config(cfg.genesis_file.as_deref(), cfg.network.as_str()) {
        Ok(cfg) => cfg,
        Err(err) => {
            let _ = writeln!(stderr, "invalid genesis file: {err}");
            return 2;
        }
    };
    if let Err(err) = fs::create_dir_all(&cfg.data_dir) {
        let _ = writeln!(
            stderr,
            "datadir create failed ({}): {err}",
            cfg.data_dir.display()
        );
        return 2;
    }
    let mut chain_state = match load_chain_state(&chain_state_file) {
        Ok(chain_state) => chain_state,
        Err(err) => {
            let _ = writeln!(
                stderr,
                "chainstate load failed ({}): {err}",
                chain_state_file.display()
            );
            return 2;
        }
    };
    let chain_id = genesis_cfg.chain_id;

    let mut block_store = match BlockStore::open(block_store_path(&cfg.data_dir)) {
        Ok(block_store) => block_store,
        Err(err) => {
            let _ = writeln!(stderr, "blockstore open failed: {err}");
            return 2;
        }
    };

    let mut sync_cfg = default_sync_config(None, chain_id, Some(chain_state_file.clone()));
    sync_cfg.network = cfg.network.clone();
    sync_cfg.core_ext_deployments = genesis_cfg.core_ext_deployments.clone();
    sync_cfg.suite_context = genesis_cfg.suite_context.clone();
    sync_cfg.parallel_validation_mode = cfg.pv_mode.clone();
    sync_cfg.pv_shadow_max_samples = cfg.pv_shadow_max;

    // Mainnet target / genesis guard runs BEFORE reconcile so a
    // misconfigured `--network mainnet` startup is rejected before
    // any reconcile-driven state mutation: reconcile may rewrite
    // chainstate via truncate / replay, and we must not touch persisted
    // state when the network config itself is invalid. `SyncEngine::new`
    // runs the same guard internally as defence-in-depth: it re-validates
    // the final `SyncConfig` actually passed to the engine, catching any
    // mutation between this early call and engine construction. For
    // callers that construct `SyncEngine` directly (tests, embedded uses)
    // it is the ONLY guard. Do not remove the inner call as a perceived
    // duplicate. Devnet / test networks no-op.
    if let Err(err) = validate_mainnet_genesis_guard(&sync_cfg) {
        let _ = writeln!(stderr, "mainnet genesis guard failed: {err}");
        return 2;
    }

    // Startup reconcile (E.2): repair any chainstate ↔ blockstore
    // mismatch left by a crash (incomplete canonical suffix, stale
    // snapshot, ahead snapshot, mismatched tip hash) BEFORE the live
    // sync engine, P2P, RPC, or miner start. Mirrors the Go
    // `ReconcileChainStateWithBlockStore` call in `cmd/rubin-node/main.go`.
    // A reconcile error is fatal: continuing would let the engine run
    // with a chainstate tip that no longer points at any canonical
    // block on disk.
    if let Err(err) =
        reconcile_chain_state_with_block_store(&mut chain_state, &mut block_store, &sync_cfg)
    {
        let _ = writeln!(stderr, "chainstate reconcile failed: {err}");
        return 2;
    }
    if let Err(err) = chain_state.save(&chain_state_file) {
        let _ = writeln!(
            stderr,
            "chainstate save failed ({}): {err}",
            chain_state_file.display()
        );
        return 2;
    }

    // NOTE: `block_store.clone()` here mirrors the pre-existing
    // pattern in `main.rs` (the RPC handoff at `Some(block_store)`
    // below also moves an independent copy). After reconcile the
    // clone captures the post-truncate snapshot, so the engine
    // starts from the repaired index. The RPC vs SyncEngine
    // BlockStore-divergence (their independent clones do NOT track
    // each other's post-startup canonical advances) is a
    // pre-existing main.rs gap, NOT introduced by E.2 reconcile,
    // and is out of scope for this PR — see the Q-IMPL-RUST-RPC-
    // BLOCKSTORE-SHARING follow-up for the proper Arc<BlockStore>
    // fix that touches both `SyncEngine::new` and
    // `new_devnet_rpc_state_with_tx_pool` signatures.
    let mut sync_engine = match SyncEngine::new(chain_state, Some(block_store.clone()), sync_cfg) {
        Ok(engine) => engine,
        Err(err) => {
            let _ = writeln!(stderr, "sync engine init failed: {err}");
            return 2;
        }
    };
    if let Ok(Some((height, _))) = sync_engine.tip() {
        sync_engine.record_best_known_height(height);
    }

    let effective = EffectiveConfig {
        network: cfg.network.clone(),
        data_dir: cfg.data_dir.display().to_string(),
        chain_id_hex: hex::encode(chain_id),
        genesis_file: cfg
            .genesis_file
            .as_ref()
            .map(|path| path.display().to_string()),
        bind_addr: cfg.bind_addr.clone(),
        peers: cfg.peers.clone(),
        max_peers: cfg.max_peers,
        rpc_bind_addr: if cfg.rpc_bind_addr.trim().is_empty() {
            None
        } else {
            Some(cfg.rpc_bind_addr.clone())
        },
        mine_address: cfg.mine_address.clone(),
        mine_blocks: cfg.mine_blocks,
        mine_exit: cfg.mine_exit,
        pv_mode: cfg.pv_mode.clone(),
        pv_shadow_max: cfg.pv_shadow_max,
    };
    if serde_json::to_writer_pretty(&mut *stdout, &effective).is_err() {
        let _ = writeln!(stderr, "config encode failed");
        return 1;
    }
    let _ = writeln!(stdout);

    // RUB-13 / GitHub #1157: operator-facing startup banners that pin
    // the cross-client format. Mixed-client devnet diagnostic scripts
    // scraping `rubin-node` startup stdout for sync diagnostics or
    // peer-slot occupancy rely on these exact one-line formats on
    // both clients. Same upstream sequencing pinned at
    // `clients/go/cmd/rubin-node/main.go:441-443`: emitted AFTER the
    // effective-config JSON dump and BEFORE the `--dry-run` early
    // exit so a `--dry-run` run on either client emits both banners.
    // PeerManager construction is moved here (from its previous
    // post-dry-run position) so the peer-slots banner can render
    // before the dry-run early exit, matching the upstream's pre-
    // exit emission. The accessors are pre-existing public API on
    // `SyncEngine` (`header_sync_request()` / `is_in_ibd(now_unix)`)
    // and `PeerManager` (`snapshot()`, the same accessor `/peers`
    // uses, RUB-14 / GitHub #1159).
    let header_req = sync_engine.header_sync_request();
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = writeln!(
        stdout,
        "sync: header_request_has_from={} header_request_limit={} ibd={}",
        header_req.has_from,
        header_req.limit,
        sync_engine.is_in_ibd(now_unix)
    );
    let peer_runtime_cfg = default_peer_runtime_config(&cfg.network, cfg.max_peers);
    let peer_manager = Arc::new(PeerManager::new(peer_runtime_cfg.clone()));
    let _ = writeln!(
        stdout,
        "{}",
        format_peer_slots_banner(cfg.max_peers, peer_manager.snapshot().len())
    );

    if cfg.dry_run {
        return 0;
    }
    if cfg.mine_blocks > 0 {
        let mut miner_cfg = MinerConfig {
            core_ext_deployments: genesis_cfg.core_ext_deployments.clone(),
            ..MinerConfig::default()
        };
        if let Some(ref value) = cfg.mine_address {
            let parsed = match parse_mine_address_arg(value) {
                Ok(Some(addr)) => addr,
                Ok(None) => Vec::new(),
                Err(err) => {
                    let _ = writeln!(stderr, "invalid mine-address: {err}");
                    return 2;
                }
            };
            miner_cfg.mine_address = parsed;
        }
        let mut miner = match Miner::new(&mut sync_engine, None, miner_cfg) {
            Ok(miner) => miner,
            Err(err) => {
                let _ = writeln!(stderr, "miner init failed: {err}");
                return 2;
            }
        };
        let mined = match miner.mine_n(cfg.mine_blocks, &[]) {
            Ok(mined) => mined,
            Err(err) => {
                let _ = writeln!(stderr, "mining failed: {err}");
                return 2;
            }
        };
        for block in mined {
            let _ = writeln!(
                stdout,
                "mined: height={} hash={} timestamp={} nonce={} tx_count={}",
                block.height,
                hex::encode(block.hash),
                block.timestamp,
                block.nonce,
                block.tx_count
            );
        }
        if cfg.mine_exit {
            return 0;
        }
    }

    let live_mining_cfg = if cfg.network == "devnet"
        && !cfg.rpc_bind_addr.trim().is_empty()
        && rpc_bind_host_is_loopback(&cfg.rpc_bind_addr)
    {
        let mut miner_cfg = MinerConfig {
            core_ext_deployments: genesis_cfg.core_ext_deployments.clone(),
            ..MinerConfig::default()
        };
        let mut addr_invalid = false;
        if let Some(ref value) = cfg.mine_address {
            match parse_mine_address_arg(value) {
                Ok(Some(addr)) => miner_cfg.mine_address = addr,
                Ok(None) => {}
                Err(err) => {
                    let _ = writeln!(
                        stderr,
                        "rpc: live mining disabled (invalid --mine-address): {err}"
                    );
                    addr_invalid = true;
                }
            }
        }
        if addr_invalid {
            None
        } else {
            match Miner::new(&mut sync_engine, None, miner_cfg.clone()) {
                Ok(_) => Some(miner_cfg),
                Err(err) => {
                    let _ = writeln!(stderr, "rpc: live mining disabled: {err}");
                    None
                }
            }
        }
    } else {
        None
    };

    let genesis_hash = match runtime_genesis_hash(&genesis_cfg) {
        Ok(hash) => hash,
        Err(err) => {
            let _ = writeln!(stderr, "{err}");
            return 2;
        }
    };
    let sync_engine = Arc::new(Mutex::new(sync_engine));
    let tx_pool = new_shared_runtime_tx_pool(&sync_engine);
    let stop_signal = match install_production_stop_signal() {
        Ok(stop_signal) => stop_signal,
        Err(err) => {
            let _ = writeln!(stderr, "signal handler install failed: {err}");
            return 2;
        }
    };
    // peer_runtime_cfg / peer_manager were constructed earlier (above
    // the dry-run early-exit) so the RUB-13 peer-slots banner could
    // render in the dry-run path matching the upstream sequencing at
    // `clients/go/cmd/rubin-node/main.go:441-443`. They are reused
    // here to feed `p2p_service` startup. The Rust-only `p2p: listening=`
    // banner below stays because the post-bind address is operator-
    // useful and the upstream client cannot emit it symmetrically
    // (its bind happens inside `p2pService.Start(ctx)`).
    let mut p2p_service = match start_node_p2p_service(NodeP2PServiceConfig {
        bind_addr: cfg.bind_addr.clone(),
        bootstrap_peers: cfg.peers.clone(),
        runtime_cfg: peer_runtime_cfg,
        peer_manager: Arc::clone(&peer_manager),
        sync_engine: Arc::clone(&sync_engine),
        tx_pool: Arc::clone(&tx_pool),
        chain_id,
        genesis_hash,
    }) {
        Ok(service) => service,
        Err(err) => {
            let _ = writeln!(stderr, "p2p start failed: {err}");
            return 2;
        }
    };
    let _ = writeln!(stdout, "p2p: listening={}", p2p_service.addr());
    let mut server: Option<RunningDevnetRPCServer> = None;
    if let Some(code) =
        maybe_shutdown_if_requested(&stop_signal, &mut server, &mut p2p_service, stdout, stderr)
    {
        return code;
    }

    let announce_tx: Option<rubin_node::devnet_rpc::AnnounceTxFn> = {
        let relay_state = p2p_service.relay_state();
        let da_relay = p2p_service.da_relay_state();
        let pm = Arc::clone(&peer_manager);
        let pw = p2p_service.peer_outboxes();
        let local = p2p_service.addr().to_string();
        Some(Arc::new(move |tx_bytes: &[u8], meta| {
            announce_tx_after_local_admission(
                tx_bytes,
                meta,
                &relay_state,
                &pm,
                &local,
                &pw,
                &da_relay,
            )
        }))
    };
    let da_ttl_relay = p2p_service.da_relay_state();
    let da_ttl_seen = Arc::new(rubin_node::tx_seen::BoundedHashSet::new(
        rubin_node::tx_seen::DEFAULT_BLOCK_SEEN_CAPACITY,
    ));
    let announce_block: Option<rubin_node::devnet_rpc::AnnounceBlockFn> = {
        let relay_state = p2p_service.relay_state();
        let pm = Arc::clone(&peer_manager);
        let pw = p2p_service.peer_outboxes();
        let local = p2p_service.addr().to_string();
        Some(Arc::new(move |block_bytes: &[u8]| {
            rubin_node::tx_relay::announce_block(block_bytes, &relay_state, &pm, &local, &pw)
        }))
    };
    let mut state = new_devnet_rpc_state_with_tx_pool(
        Arc::clone(&sync_engine),
        Some(block_store),
        Arc::clone(&tx_pool),
        Arc::clone(&peer_manager),
        announce_tx,
        announce_block,
        live_mining_cfg,
    );
    state.accepted_block = Some(Arc::new(move |hash| {
        advance_da_ttl_for_block(hash, &da_ttl_relay, &da_ttl_seen)
    }));
    let state =
        attach_shutdown_signal_to_devnet_rpc_state(state, stop_signal.shutdown_requested_flag());
    if !cfg.rpc_bind_addr.trim().is_empty() {
        server = match start_devnet_rpc_server(&cfg.rpc_bind_addr, state) {
            Ok(server) => Some(server),
            Err(err) => {
                return handle_rpc_start_error_after_maybe_stop(
                    &stop_signal,
                    &mut server,
                    &mut p2p_service,
                    err,
                    stdout,
                    stderr,
                );
            }
        };
    }
    if let Some(server) = server.as_ref() {
        let _ = writeln!(stdout, "rpc: listening={}", server.addr());
    }
    if let Some(code) =
        maybe_shutdown_if_requested(&stop_signal, &mut server, &mut p2p_service, stdout, stderr)
    {
        return code;
    }
    let _ = writeln!(stdout, "rubin-node skeleton running");
    let _ = stdout.flush();

    wait_for_stop_and_shutdown(&stop_signal, &mut server, &mut p2p_service, stdout, stderr)
}

trait StopSource {
    fn stop_requested(&self) -> bool;
    fn wait_for_stop(&self);
}

trait RpcLifecycle {
    fn close_rpc(&mut self) -> Result<(), String>;
}

trait P2pLifecycle {
    fn close_p2p(&mut self);
}

#[derive(Clone)]
struct StopHandle {
    requested: Arc<AtomicBool>,
    wake: mpsc::SyncSender<()>,
}

struct StopSignal {
    requested: Arc<AtomicBool>,
    wake_rx: mpsc::Receiver<()>,
}

impl StopHandle {
    fn request_stop(&self) {
        self.requested.store(true, Ordering::SeqCst);
        // A full channel already contains a pending stop wake.
        let _ = self.wake.try_send(());
    }
}

impl StopSource for StopSignal {
    fn stop_requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }

    fn wait_for_stop(&self) {
        if self.stop_requested() {
            return;
        }
        let _ = self.wake_rx.recv();
    }
}

impl StopSignal {
    fn shutdown_requested_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.requested)
    }
}

impl RpcLifecycle for RunningDevnetRPCServer {
    fn close_rpc(&mut self) -> Result<(), String> {
        RunningDevnetRPCServer::close(self)
    }
}

impl P2pLifecycle for RunningNodeP2PService {
    fn close_p2p(&mut self) {
        RunningNodeP2PService::close(self);
    }
}

fn stop_signal_pair() -> (StopHandle, StopSignal) {
    let requested = Arc::new(AtomicBool::new(false));
    let (wake, wake_rx) = mpsc::sync_channel(1);
    (
        StopHandle {
            requested: Arc::clone(&requested),
            wake,
        },
        StopSignal { requested, wake_rx },
    )
}

#[cfg(unix)]
fn production_unix_stop_signals() -> [i32; 2] {
    [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM]
}

#[cfg(unix)]
fn install_production_stop_signal() -> Result<StopSignal, String> {
    let (handle, stop_signal) = stop_signal_pair();
    let mut signals = signal_hook::iterator::Signals::new(production_unix_stop_signals())
        .map_err(|err| format!("install {PRODUCTION_STOP_SIGNAL_SET} handler: {err}"))?;
    std::thread::Builder::new()
        .name("rubin-stop-signal".to_string())
        .spawn(move || {
            if signals.forever().next().is_some() {
                handle.request_stop();
            }
        })
        .map_err(|err| format!("start {PRODUCTION_STOP_SIGNAL_SET} handler: {err}"))?;
    Ok(stop_signal)
}

#[cfg(not(unix))]
fn install_production_stop_signal() -> Result<StopSignal, String> {
    let (handle, stop_signal) = stop_signal_pair();
    ctrlc::set_handler(move || handle.request_stop())
        .map_err(|err| format!("install Ctrl-C handler: {err}"))?;
    Ok(stop_signal)
}

fn handle_rpc_start_error_after_maybe_stop<S, R, P>(
    stop: &S,
    rpc_server: &mut Option<R>,
    p2p_service: &mut P,
    err: String,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32
where
    S: StopSource,
    R: RpcLifecycle,
    P: P2pLifecycle,
{
    if stop.stop_requested() && err == RPC_READINESS_TRANSITION_FAILED {
        return shutdown_owned_services(rpc_server, p2p_service, stdout, stderr);
    }
    let _ = writeln!(stderr, "rpc start failed: {err}");
    p2p_service.close_p2p();
    2
}

fn maybe_shutdown_if_requested<S, R, P>(
    stop: &S,
    rpc_server: &mut Option<R>,
    p2p_service: &mut P,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Option<i32>
where
    S: StopSource,
    R: RpcLifecycle,
    P: P2pLifecycle,
{
    if stop.stop_requested() {
        Some(shutdown_owned_services(
            rpc_server,
            p2p_service,
            stdout,
            stderr,
        ))
    } else {
        None
    }
}

fn wait_for_stop_and_shutdown<S, R, P>(
    stop: &S,
    rpc_server: &mut Option<R>,
    p2p_service: &mut P,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32
where
    S: StopSource,
    R: RpcLifecycle,
    P: P2pLifecycle,
{
    stop.wait_for_stop();
    shutdown_owned_services(rpc_server, p2p_service, stdout, stderr)
}

fn shutdown_owned_services<R, P>(
    rpc_server: &mut Option<R>,
    p2p_service: &mut P,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32
where
    R: RpcLifecycle,
    P: P2pLifecycle,
{
    let mut exit_code = 0;
    if let Some(server) = rpc_server.as_mut() {
        if let Err(err) = server.close_rpc() {
            let _ = writeln!(stderr, "rpc shutdown failed: {err}");
            exit_code = 1;
        }
    }
    p2p_service.close_p2p();
    if exit_code == 0 {
        let _ = writeln!(stdout, "rubin-node skeleton stopped");
        let _ = stdout.flush();
    } else {
        let _ = writeln!(stderr, "rubin-node skeleton stopped with shutdown errors");
        let _ = stderr.flush();
    }
    exit_code
}

/// RUB-13 / GitHub #1157: format the operator-facing `p2p: peer_slots=N
/// connected=K` banner that pins the cross-client format from
/// `clients/go/cmd/rubin-node/main.go:443`. Pure-string helper that
/// the public-path integration test
/// `dry_run_emits_sync_and_peer_slots_banners_after_json_in_order`
/// covers via `--dry-run` (the dry-run early-exit at L345-347 returns
/// `0` immediately after both banners print, well before the post-bind
/// service loop). The companion unit test
/// `format_peer_slots_banner_matches_go_format` exercises the helper
/// with edge inputs that the public path cannot reach because
/// `validate_config` rejects them upstream — most notably
/// `max_peers == 0`, which `clients/go/node/config.go:395-396` and the
/// Rust counterpart at the validate_config block reject before
/// `run()` is ever invoked. Output line is identical to the upstream
/// `fmt.Fprintf` format token-for-token:
/// `p2p: peer_slots=<usize> connected=<usize>` with a trailing newline
/// added by the caller's `writeln!`.
fn format_peer_slots_banner(max_peers: usize, connected: usize) -> String {
    format!("p2p: peer_slots={max_peers} connected={connected}")
}

fn runtime_genesis_hash(genesis_cfg: &LoadedGenesisConfig) -> Result<[u8; 32], String> {
    genesis_cfg.genesis_hash.ok_or_else(|| {
        "runtime p2p requires genesis_hash_hex in the genesis file when chain_id is not devnet"
            .to_string()
    })
}

fn parse_args(args: &[String]) -> Result<CliConfig, String> {
    let mut cfg = CliConfig {
        network: "devnet".to_string(),
        data_dir: default_data_dir(),
        genesis_file: None,
        bind_addr: "0.0.0.0:19111".to_string(),
        peers: Vec::new(),
        max_peers: 64,
        rpc_bind_addr: String::new(),
        mine_address: None,
        mine_blocks: 0,
        mine_exit: false,
        pv_mode: "off".to_string(),
        pv_shadow_max: 3,
        legacy_exposure_scan: false,
        legacy_suite_ids: Vec::new(),
        legacy_exposure_include_outpoints: false,
        dry_run: false,
    };
    let mut peer_tokens = Vec::new();

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--network" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --network".to_string())?;
                cfg.network = value.clone();
            }
            "--datadir" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --datadir".to_string())?;
                cfg.data_dir = PathBuf::from(value);
            }
            "--genesis-file" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --genesis-file".to_string())?;
                cfg.genesis_file = Some(PathBuf::from(value));
            }
            "--bind" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --bind".to_string())?;
                cfg.bind_addr = value.clone();
            }
            "--peers" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --peers".to_string())?;
                peer_tokens.push(value.clone());
            }
            "--peer" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --peer".to_string())?;
                peer_tokens.push(value.clone());
            }
            "--max-peers" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --max-peers".to_string())?;
                cfg.max_peers = value
                    .parse::<usize>()
                    .map_err(|_| "invalid value for --max-peers".to_string())?;
            }
            "--rpc-bind" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --rpc-bind".to_string())?;
                cfg.rpc_bind_addr = value.clone();
            }
            "--mine-address" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --mine-address".to_string())?;
                cfg.mine_address = Some(value.clone());
            }
            "--mine-blocks" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --mine-blocks".to_string())?;
                cfg.mine_blocks = value
                    .parse::<usize>()
                    .map_err(|_| "invalid value for --mine-blocks".to_string())?;
            }
            "--mine-exit" => {
                cfg.mine_exit = true;
            }
            "--pv-mode" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --pv-mode".to_string())?;
                cfg.pv_mode = value.clone();
            }
            "--pv-shadow-max" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --pv-shadow-max".to_string())?;
                cfg.pv_shadow_max = value
                    .parse::<u64>()
                    .map_err(|_| "invalid value for --pv-shadow-max".to_string())?;
            }
            "--legacy-exposure-scan" => {
                cfg.legacy_exposure_scan = true;
            }
            "--legacy-suite-id" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --legacy-suite-id".to_string())?;
                cfg.legacy_suite_ids.push(parse_legacy_suite_id(value)?);
            }
            "--legacy-exposure-include-outpoints" => {
                cfg.legacy_exposure_include_outpoints = true;
            }
            "--dry-run" => {
                cfg.dry_run = true;
            }
            unknown => {
                return Err(format!("unknown flag: {unknown}"));
            }
        }
        idx += 1;
    }
    cfg.peers = normalize_peers(&peer_tokens);
    cfg.legacy_suite_ids.sort_unstable();
    cfg.legacy_suite_ids.dedup();

    Ok(cfg)
}

fn default_data_dir() -> PathBuf {
    match env::var_os("HOME") {
        Some(home) if !home.is_empty() => PathBuf::from(home).join(".rubin"),
        _ => PathBuf::from(".rubin"),
    }
}

fn usage(stdout: &mut dyn Write) {
    let _ = writeln!(
        stdout,
        "usage: rubin-node [--network <name>] [--datadir <path>] [--genesis-file <path>] [--bind <host:port>] [--peer <host:port>]... [--peers <csv>] [--max-peers <n>] [--rpc-bind <host:port>] [--mine-address <hex>] [--mine-blocks <n>] [--mine-exit] [--pv-mode <off|shadow|on>] [--pv-shadow-max <n>] [--legacy-exposure-scan] [--legacy-suite-id <id>]... [--legacy-exposure-include-outpoints] [--dry-run]"
    );
}

fn parse_legacy_suite_id(value: &str) -> Result<u8, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("legacy suite_id is required".to_string());
    }
    let (digits, radix) = if let Some(rest) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        (rest, 16)
    } else {
        (trimmed, 10)
    };
    if digits.is_empty() {
        return Err("legacy suite_id is required".to_string());
    }
    let parsed = u16::from_str_radix(digits, radix)
        .map_err(|_| format!("invalid legacy suite_id '{value}'"))?;
    u8::try_from(parsed).map_err(|_| format!("invalid legacy suite_id '{value}'"))
}

fn format_legacy_exposure_outpoint(txid: &[u8; 32], vout: u32) -> String {
    format!("{}:{vout}", hex::encode(txid))
}

fn legacy_exposure_hooks(has_tip: bool, total: u64) -> (&'static str, &'static str, &'static str) {
    if !has_tip {
        return (
            "invalid_no_chainstate_tip",
            "none",
            "not_applicable_no_chainstate_tip",
        );
    }
    if total == 0 {
        (
            "ready_for_operator_defined_grace_window",
            "none",
            "start_operator_defined_grace_window",
        )
    } else {
        (
            "not_ready_legacy_exposure_present",
            "legacy_exposure_present_notify_operator_and_council",
            "not_applicable_legacy_exposure_present",
        )
    }
}

fn build_legacy_exposure_report(
    cfg: &CliConfig,
    chain_state: &rubin_node::ChainState,
) -> LegacyExposureReport {
    let mut legacy_suite_reports = Vec::with_capacity(cfg.legacy_suite_ids.len());
    let mut legacy_exposure_total = 0u64;
    for suite_id in &cfg.legacy_suite_ids {
        if cfg.legacy_exposure_include_outpoints {
            let outpoints = chain_state.utxo_outpoints_by_suite_id(*suite_id);
            let report_count = outpoints.len() as u64;
            legacy_exposure_total = legacy_exposure_total.saturating_add(report_count);
            let report_outpoints: Vec<String> = outpoints
                .iter()
                .map(|op| format_legacy_exposure_outpoint(&op.txid, op.vout))
                .collect();
            legacy_suite_reports.push(LegacyExposureSuiteReport {
                suite_id: u64::from(*suite_id),
                utxo_exposure_count: report_count,
                outpoint_count: report_count,
                outpoints: Some(report_outpoints),
            });
            continue;
        }
        let report_count = chain_state.utxo_exposure_count_by_suite_id(*suite_id);
        legacy_exposure_total = legacy_exposure_total.saturating_add(report_count);
        legacy_suite_reports.push(LegacyExposureSuiteReport {
            suite_id: u64::from(*suite_id),
            utxo_exposure_count: report_count,
            outpoint_count: report_count,
            outpoints: None,
        });
    }
    let (sunset_readiness, warning_hook, grace_hook) =
        legacy_exposure_hooks(chain_state.has_tip, legacy_exposure_total);
    let indexed_suite_ids = chain_state.indexed_suite_ids();
    LegacyExposureReport {
        report_version: LEGACY_EXPOSURE_REPORT_VERSION,
        measurement_scope: "explicit_suite_id_utxos".to_string(),
        network: cfg.network.clone(),
        data_dir: cfg.data_dir.display().to_string(),
        chainstate_height: chain_state.height,
        chainstate_has_tip: chain_state.has_tip,
        indexed_suite_ids: suite_ids_to_json_numbers(&indexed_suite_ids),
        watched_legacy_suite_ids: suite_ids_to_json_numbers(&cfg.legacy_suite_ids),
        legacy_exposure_total,
        sunset_readiness: sunset_readiness.to_string(),
        warning_hook: warning_hook.to_string(),
        grace_hook: grace_hook.to_string(),
        include_outpoints: cfg.legacy_exposure_include_outpoints,
        legacy_suite_reports,
    }
}

fn suite_ids_to_json_numbers(ids: &[u8]) -> Vec<u64> {
    ids.iter().map(|id| u64::from(*id)).collect()
}

fn normalize_peers(raw: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for token in raw {
        for peer in token.split(',') {
            let peer = peer.trim();
            if peer.is_empty() || out.iter().any(|current| current == peer) {
                continue;
            }
            out.push(peer.to_string());
        }
    }
    out
}

fn validate_config(cfg: &mut CliConfig) -> Result<(), String> {
    if cfg.network.trim().is_empty() {
        return Err("network is required".to_string());
    }
    // Normalize network name: trim + lowercase to prevent wire-magic mismatch.
    // network_magic() in p2p_runtime.rs matches only exact lowercase names.
    let normalized_network = normalized_rotation_network_name(&cfg.network);
    cfg.network = canonical_rotation_network_name_normalized(normalized_network.as_ref())
        .ok_or_else(|| {
            format!(
                "unknown network '{}' (expected: {})",
                normalized_network, SUPPORTED_ROTATION_NETWORK_NAMES_CSV,
            )
        })?
        .to_string();
    if cfg.data_dir.as_os_str().is_empty() {
        return Err("data_dir is required".to_string());
    }
    // Normalise `--data-dir` once so every subsystem
    // (`ChainState::save` / `load_chain_state`, `BlockStore::open`
    // and its block / header / undo / index sub-directories, etc.)
    // derives paths from a single lexically-cleaned root. Internal
    // readers and writers then stay on raw `fs::read` /
    // `write_file_atomic` and remain symmetric with each other
    // (block + index surface live in the same physical tree, and a
    // chainstate read lands on exactly the file a prior chainstate
    // save produced) — even for operator `--data-dir` values that
    // cross a symlink combined with `..` segments.
    cfg.data_dir = rubin_node::normalize_data_dir(&cfg.data_dir)?;
    validate_addr_inner("bind_addr", &cfg.bind_addr, true)?;
    if !cfg.rpc_bind_addr.trim().is_empty() {
        validate_addr_inner("rpc_bind_addr", &cfg.rpc_bind_addr, true)?;
    }
    if cfg.peers.len() > 1000 {
        return Err(format!("too many peers: {} (max 1000)", cfg.peers.len()));
    }
    for peer in &cfg.peers {
        validate_peer_addr(peer)?;
    }
    if cfg.max_peers == 0 {
        return Err("max_peers must be > 0".to_string());
    }
    if cfg.max_peers > 4096 {
        return Err("max_peers must be <= 4096".to_string());
    }
    // RUB-194 / GitHub #1458: validate `mine_address` here so startup,
    // dry-run, and miner setup all share the same Rust accept/reject
    // contract via `parse_mine_address_arg` (already imported from
    // `crate::miner`). Without this gate, a malformed `--mine-address`
    // slipped through dry-run and only failed later inside miner setup
    // at `miner_cfg.mine_address = parsed` (CLI mining path) or
    // `miner_cfg.mine_address = addr` (live RPC mining path). Both
    // assignment sites are unique enough to grep; line numbers are
    // omitted because the RUB-13 banner hoist shifted them and any
    // future re-arrangement would invalidate fixed line refs.
    // Closes hostile-case matrix #2 in the issue contract.
    //
    // Go counterpart anchor: `clients/go/node/config.go::ValidateConfig`
    // lines 407-415 also gates mine_address at config-validation time
    // before any startup side effects, but the parser semantics are NOT
    // strictly identical — full Go/Rust mine_address parity is out of
    // scope for this slice. Documented Rust-vs-Go divergences (all
    // pre-existing in `crate::coinbase::parse_mine_address` /
    // `validate_mine_address`, not introduced here):
    //   * `0x` / `0X` hex prefix: Rust strips and decodes; Go's
    //     `hex.DecodeString` rejects.
    //   * whitespace-only input: Rust trims to empty -> `Ok(None)` ->
    //     run() falls back to `default_mine_address()`; Go errors out.
    //   * 33-byte hex with first byte != `SUITE_ID_ML_DSA_87` (0x01):
    //     Rust rejects via `validate_mine_address`; Go accepts as
    //     opaque length-33 bytes.
    if let Some(ref value) = cfg.mine_address {
        if let Err(err) = parse_mine_address_arg(value) {
            return Err(format!("invalid mine_address: {err}"));
        }
    }
    let pv_mode = cfg.pv_mode.trim().to_ascii_lowercase();
    if !["off", "shadow", "on"].contains(&pv_mode.as_str()) {
        return Err("pv_mode must be one of: off, shadow, on".to_string());
    }
    cfg.pv_mode = pv_mode;
    if cfg.pv_shadow_max == 0 {
        cfg.pv_shadow_max = 3;
    }
    if cfg.legacy_exposure_scan {
        if cfg.legacy_suite_ids.is_empty() {
            return Err("legacy exposure scan requires at least one --legacy-suite-id".to_string());
        }
    } else if !cfg.legacy_suite_ids.is_empty() || cfg.legacy_exposure_include_outpoints {
        return Err("legacy exposure flags require --legacy-exposure-scan".to_string());
    }
    Ok(())
}

fn validate_addr(label: &str, addr: &str) -> Result<(), String> {
    validate_addr_inner(label, addr, false)
}

/// Validate host:port format. `allow_ephemeral` permits port 0 for bind
/// addresses where the OS assigns a random port (test/parallel local runs).
fn validate_addr_inner(label: &str, addr: &str, allow_ephemeral: bool) -> Result<(), String> {
    let addr = addr.trim();
    if addr.is_empty() {
        return Err(format!("{label} is required"));
    }
    // Validate host:port format without blocking DNS resolution.
    // Accept IP:port, hostname:port, and bracketed IPv6 [::1]:port.
    // Actual resolution happens at bind/connect time, not at validation.
    let (host, port_str) = if addr.starts_with('[') {
        // IPv6 bracketed: [::1]:19111 — require proper brackets
        let bracket_end = addr.find("]:").ok_or_else(|| {
            format!("invalid {label}: malformed IPv6 bracket (expected [host]:port)")
        })?;
        let host = &addr[1..bracket_end]; // strip brackets
        if host.is_empty() {
            return Err(format!("invalid {label}: empty IPv6 address in brackets"));
        }
        // Validate IPv6 syntax eagerly — deferring to connect time produces
        // cryptic "invalid socket address" errors that are harder to diagnose.
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(format!(
                "invalid {label}: malformed IPv6 address in brackets"
            ));
        }
        let port = &addr[bracket_end + 2..];
        (host, port)
    } else if addr.contains("]:") || addr.contains('[') {
        // Malformed bracket without leading '[' (e.g., "foo]:19111", "::1]:19111")
        return Err(format!(
            "invalid {label}: malformed bracket notation (expected [host]:port)"
        ));
    } else if let Some(colon_pos) = addr.rfind(':') {
        let host = &addr[..colon_pos];
        // Reject non-bracketed hosts with extra colons (e.g., "foo:bar:80").
        // Bare IPv6 addresses must use bracket notation [::1]:port.
        if host.contains(':') {
            return Err(format!(
                "invalid {label}: host contains ':' — use [host]:port for IPv6"
            ));
        }
        (host, &addr[colon_pos + 1..])
    } else {
        return Err(format!(
            "invalid {label}: missing port (expected host:port)"
        ));
    };
    if host.is_empty() {
        return Err(format!("invalid {label}: empty host"));
    }
    // Reject null bytes and control characters in hostname — these can
    // cause log injection or confuse downstream DNS resolution.
    if host.bytes().any(|b| b == 0 || (b < 0x20 && b != b'\t')) {
        return Err(format!(
            "invalid {label}: hostname contains null or control characters"
        ));
    }
    // RFC 1034: max hostname length is 253 characters.
    if host.len() > 253 {
        return Err(format!(
            "invalid {label}: hostname too long ({} > 253)",
            host.len()
        ));
    }
    // RFC 1034 §3.5: each label (dot-separated) is 1–63 chars, alphanumeric
    // and hyphens only, must not start or end with hyphen.
    // Skip label validation for IP addresses (contain only digits/dots/colons).
    let is_ip = host.parse::<std::net::IpAddr>().is_ok();
    if !is_ip {
        for dns_part in host.split('.') {
            if dns_part.is_empty() || dns_part.len() > 63 {
                return Err(format!(
                    "invalid {label}: DNS label '{}' length {} out of range 1..63",
                    if dns_part.len() > 20 {
                        &dns_part[..20]
                    } else {
                        dns_part
                    },
                    dns_part.len(),
                ));
            }
            if dns_part.starts_with('-') || dns_part.ends_with('-') {
                return Err(format!(
                    "invalid {label}: DNS label must not start or end with hyphen"
                ));
            }
            if !dns_part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(format!(
                    "invalid {label}: DNS label contains invalid character"
                ));
            }
        }
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid {label}: bad port '{port_str}'"))?;
    if port == 0 && !allow_ephemeral {
        return Err(format!("invalid {label}: port 0 is not allowed"));
    }
    Ok(())
}

fn validate_peer_addr(addr: &str) -> Result<(), String> {
    validate_addr("peer", addr)
}

fn announce_tx_after_local_admission(
    tx_bytes: &[u8],
    meta: rubin_node::txpool::RelayTxMetadata,
    relay_state: &rubin_node::tx_relay::TxRelayState,
    peer_manager: &rubin_node::p2p_runtime::PeerManager,
    local_addr: &str,
    peer_writers: &Mutex<std::collections::HashMap<String, rubin_node::tx_relay::PeerOutbox>>,
    da_relay: &Arc<Mutex<rubin_node::da_relay::DaRelayState>>,
) -> Result<(), String> {
    rubin_node::p2p_service::stage_local_da_relay_tx_bytes(da_relay, tx_bytes);
    rubin_node::tx_relay::announce_tx(
        tx_bytes,
        meta,
        relay_state,
        peer_manager,
        local_addr,
        peer_writers,
    )
}

fn advance_da_ttl_for_block(
    hash: [u8; 32],
    da_relay: &Arc<Mutex<rubin_node::da_relay::DaRelayState>>,
    ttl_seen: &rubin_node::tx_seen::BoundedHashSet,
) -> Result<(), String> {
    if !ttl_seen.add(hash) {
        return Ok(());
    }
    let mut da_relay = da_relay
        .lock()
        .map_err(|_| "DA relay lock poisoned during local block TTL advance".to_string())?;
    da_relay
        .advance_orphan_ttl()
        .map(|_| ())
        .map_err(|err| format!("DA relay TTL advance failed: {err:?}"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::{cell::RefCell, rc::Rc};

    use super::{
        advance_da_ttl_for_block, announce_tx_after_local_admission, format_peer_slots_banner,
        handle_rpc_start_error_after_maybe_stop, legacy_exposure_hooks,
        maybe_shutdown_if_requested, parse_args, run, runtime_genesis_hash, stop_signal_pair,
        validate_config, wait_for_stop_and_shutdown, LegacyExposureReport,
        PRODUCTION_STOP_SIGNAL_SET, RPC_READINESS_TRANSITION_FAILED,
    };
    use rubin_consensus::constants::{
        COV_TYPE_DA_COMMIT, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87,
        TX_WIRE_VERSION, VERIFY_COST_ML_DSA_87,
    };
    use rubin_consensus::{marshal_tx, parse_tx, DaChunkCore, DaCommitCore, Tx, TxOutput};
    use rubin_node::da_relay::{DaRelayCaps, DaRelayState};
    use rubin_node::tx_relay::{PeerOutbox, TxRelayState};
    use rubin_node::txpool::RelayTxMetadata;
    use rubin_node::{load_genesis_config, PRODUCTION_LOCAL_ROTATION_DESCRIPTOR_ERR};
    use serde_json::Value;
    use sha3::{Digest, Sha3_256};

    #[derive(serde::Deserialize)]
    struct LegacyExposureHookVectorsDoc {
        contract_version: u64,
        fixture_kind: String,
        cases: Vec<LegacyExposureHookVectorCase>,
    }

    #[derive(Debug, PartialEq, Eq, serde::Deserialize)]
    struct LegacyExposureHookVectorCase {
        name: String,
        has_chainstate_tip: bool,
        legacy_exposure_total: u64,
        sunset_readiness: String,
        warning_hook: String,
        grace_hook: String,
    }

    fn canonical_legacy_exposure_hook_vectors() -> Vec<LegacyExposureHookVectorCase> {
        vec![
            LegacyExposureHookVectorCase {
                name: "no_chainstate_tip_zero_total".to_string(),
                has_chainstate_tip: false,
                legacy_exposure_total: 0,
                sunset_readiness: "invalid_no_chainstate_tip".to_string(),
                warning_hook: "none".to_string(),
                grace_hook: "not_applicable_no_chainstate_tip".to_string(),
            },
            LegacyExposureHookVectorCase {
                name: "no_chainstate_tip_nonzero_total".to_string(),
                has_chainstate_tip: false,
                legacy_exposure_total: 5,
                sunset_readiness: "invalid_no_chainstate_tip".to_string(),
                warning_hook: "none".to_string(),
                grace_hook: "not_applicable_no_chainstate_tip".to_string(),
            },
            LegacyExposureHookVectorCase {
                name: "tipped_chain_zero_exposure".to_string(),
                has_chainstate_tip: true,
                legacy_exposure_total: 0,
                sunset_readiness: "ready_for_operator_defined_grace_window".to_string(),
                warning_hook: "none".to_string(),
                grace_hook: "start_operator_defined_grace_window".to_string(),
            },
            LegacyExposureHookVectorCase {
                name: "tipped_chain_nonzero_exposure".to_string(),
                has_chainstate_tip: true,
                legacy_exposure_total: 3,
                sunset_readiness: "not_ready_legacy_exposure_present".to_string(),
                warning_hook: "legacy_exposure_present_notify_operator_and_council".to_string(),
                grace_hook: "not_applicable_legacy_exposure_present".to_string(),
            },
        ]
    }

    #[rustfmt::skip]
    fn local_da_commit_tx(da_id: [u8; 32], commitment: [u8; 32]) -> Vec<u8> {
        marshal_tx(&Tx { version: TX_WIRE_VERSION, tx_kind: 0x01, tx_nonce: 1, inputs: Vec::new(), outputs: vec![TxOutput { value: 0, covenant_type: COV_TYPE_DA_COMMIT, covenant_data: commitment.to_vec() }], locktime: 0, da_commit_core: Some(DaCommitCore { da_id, chunk_count: 1, retl_domain_id: [0x10; 32], batch_number: 1, tx_data_root: [0x11; 32], state_root: [0x12; 32], withdrawals_root: [0x13; 32], batch_sig_suite: 0, batch_sig: Vec::new() }), da_chunk_core: None, witness: Vec::new(), da_payload: Vec::new() }).expect("marshal local DA commit tx")
    }

    #[rustfmt::skip]
    fn local_da_chunk_tx(da_id: [u8; 32], payload: &[u8]) -> Vec<u8> {
        marshal_tx(&Tx { version: TX_WIRE_VERSION, tx_kind: 0x02, tx_nonce: 2, inputs: Vec::new(), outputs: Vec::new(), locktime: 0, da_commit_core: None, da_chunk_core: Some(DaChunkCore { da_id, chunk_index: 0, chunk_hash: Sha3_256::digest(payload).into() }), witness: Vec::new(), da_payload: payload.to_vec() }).expect("marshal local DA chunk tx")
    }

    #[rustfmt::skip]
    fn local_non_da_tx() -> Vec<u8> {
        marshal_tx(&Tx { version: TX_WIRE_VERSION, tx_kind: 0x00, tx_nonce: 3, inputs: Vec::new(), outputs: Vec::new(), locktime: 0, da_commit_core: None, da_chunk_core: None, witness: Vec::new(), da_payload: Vec::new() }).expect("marshal local non-DA tx")
    }

    struct LocalDaTestContext {
        relay: TxRelayState,
        peers: rubin_node::PeerManager,
        outboxes: Mutex<HashMap<String, PeerOutbox>>,
        da_relay: Arc<Mutex<DaRelayState>>,
        ttl_seen: rubin_node::tx_seen::BoundedHashSet,
    }

    impl LocalDaTestContext {
        fn announce(&self, tx_bytes: &[u8]) -> Result<(), String> {
            announce_tx_after_local_admission(
                tx_bytes,
                RelayTxMetadata {
                    fee: 1,
                    size: tx_bytes.len(),
                },
                &self.relay,
                &self.peers,
                "local:8333",
                &self.outboxes,
                &self.da_relay,
            )
        }
    }

    fn local_da_test_context() -> LocalDaTestContext {
        local_da_test_context_with_peers(&[])
    }

    #[rustfmt::skip]
    fn local_da_test_context_with_peers(addrs: &[&str]) -> LocalDaTestContext {
        let peers = rubin_node::PeerManager::new(rubin_node::default_peer_runtime_config("devnet", 8)); let outboxes = Mutex::new(HashMap::new());
        for addr in addrs { peers.add_peer(rubin_node::p2p_runtime::PeerState { addr: (*addr).to_string(), ..Default::default() }).expect("add peer"); outboxes.lock().unwrap().insert((*addr).to_string(), PeerOutbox::default()); }
        LocalDaTestContext { relay: TxRelayState::new(), peers, outboxes, da_relay: Arc::new(Mutex::new(DaRelayState::new(DaRelayCaps::default()).expect("valid DA relay caps"))), ttl_seen: rubin_node::tx_seen::BoundedHashSet::new(rubin_node::tx_seen::DEFAULT_BLOCK_SEEN_CAPACITY) }
    }

    #[test]
    fn local_da_announce_stages_after_admission_callback() {
        let ctx = local_da_test_context();
        let commit_tx = local_da_commit_tx([0x41; 32], [0x42; 32]);
        ctx.announce(&commit_tx).expect("local DA commit announce");
        assert!(!ctx.da_relay.lock().unwrap().is_empty());

        let ctx = local_da_test_context();
        let chunk_tx = local_da_chunk_tx([0x43; 32], b"local-da-chunk");
        ctx.announce(&chunk_tx).expect("local DA chunk announce");
        assert!(!ctx.da_relay.lock().unwrap().is_empty());

        let ctx = local_da_test_context();
        let non_da_tx = local_non_da_tx();
        let (_tx, txid, _wtxid, consumed) = parse_tx(&non_da_tx).expect("parse non-DA tx");
        assert_eq!(consumed, non_da_tx.len());
        ctx.announce(&non_da_tx).expect("local non-DA announce");
        assert!(ctx.da_relay.lock().unwrap().is_empty());
        assert!(ctx.relay.tx_seen.has(&txid));

        let ctx = local_da_test_context();
        let mut bad_chunk_tx = local_da_chunk_tx([0x44; 32], b"local-da-good");
        let (mut bad_tx, _txid, _wtxid, _consumed) =
            parse_tx(&bad_chunk_tx).expect("parse DA chunk tx");
        bad_tx.da_payload = b"local-da-bad".to_vec();
        bad_chunk_tx = marshal_tx(&bad_tx).expect("marshal bad DA chunk tx");
        let err = ctx
            .announce(&bad_chunk_tx)
            .expect_err("bad local DA chunk must not relay");
        assert!(err.contains("ChunkHashMismatch"), "{err}");
        assert!(ctx.da_relay.lock().unwrap().is_empty());
    }

    #[test]
    #[rustfmt::skip]
    fn local_accepted_block_advances_da_ttl_without_broadcast_coupling() {
        let da_id = [0x51; 32]; let chunk_tx = local_da_chunk_tx(da_id, b"local-block-ttl");
        let ctx = local_da_test_context_with_peers(&["peer:8333"]); ctx.announce(&chunk_tx).expect("stage local DA orphan");
        advance_da_ttl_for_block([1; 32], &ctx.da_relay, &ctx.ttl_seen).expect("local block accepted"); advance_da_ttl_for_block([1; 32], &ctx.da_relay, &ctx.ttl_seen).expect("duplicate accepted block"); advance_da_ttl_for_block([2; 32], &ctx.da_relay, &ctx.ttl_seen).expect("second accepted block"); assert!(!ctx.da_relay.lock().unwrap().is_empty()); advance_da_ttl_for_block([3; 32], &ctx.da_relay, &ctx.ttl_seen).expect("third accepted block"); assert!(ctx.da_relay.lock().unwrap().is_empty());
        let ctx = local_da_test_context_with_peers(&["healthy:8333"]); ctx.announce(&chunk_tx).expect("stage failed-announce DA orphan"); ctx.peers.add_peer(rubin_node::p2p_runtime::PeerState { addr: "missing:8333".to_string(), ..Default::default() }).expect("add missing peer"); let failed = rubin_node::devnet_genesis_block_bytes(); let failed_hash = rubin_consensus::block_hash(&rubin_consensus::parse_block_bytes(&failed).unwrap().header_bytes).unwrap();
        advance_da_ttl_for_block(failed_hash, &ctx.da_relay, &ctx.ttl_seen).expect("failed announce block accepted"); assert!(rubin_node::tx_relay::announce_block(&failed, &ctx.relay, &ctx.peers, "local:8333", &ctx.outboxes).is_err()); assert!(rubin_node::tx_relay::announce_block(&failed, &ctx.relay, &ctx.peers, "local:8333", &ctx.outboxes).is_err()); assert!(!ctx.relay.block_seen.has(&failed_hash)); assert!(!ctx.da_relay.lock().unwrap().is_empty()); advance_da_ttl_for_block([21; 32], &ctx.da_relay, &ctx.ttl_seen).expect("second failed block accepted"); assert!(!ctx.da_relay.lock().unwrap().is_empty()); advance_da_ttl_for_block([22; 32], &ctx.da_relay, &ctx.ttl_seen).expect("third failed block accepted"); assert!(ctx.da_relay.lock().unwrap().is_empty());
    }

    /// RUB-13 / GitHub #1157: stdout helper for tests that parse the
    /// effective-config JSON dump. After RUB-13 the dry-run/full
    /// startup stdout layout is
    /// `{<EffectiveConfig>}\n<sync line>\n<peer_slots line>\n`
    /// rather than the previous `{<EffectiveConfig>}\n` only, so a
    /// caller using the strict `serde_json::from_slice(&buf)` reads
    /// the JSON object cleanly but then hits the trailing post-JSON
    /// banner bytes and rejects via the strict trailing-character
    /// check. This helper finds the first `{` byte (the JSON object
    /// start) and parses with a streaming `serde_json::Deserializer`
    /// that takes only the first JSON value, so the trailing banner
    /// content is tolerated. Both dry-run and post-mining tests use
    /// the same shape.
    fn parse_effective_config_json(stdout: &[u8]) -> Value {
        let json_start = stdout
            .iter()
            .position(|&b| b == b'{')
            .expect("expected JSON object in stdout");
        // Use a streaming Deserializer so trailing post-JSON content
        // (the RUB-13 banner lines that print after the JSON dump)
        // does not trip the strict trailing-character reject path
        // of `serde_json::from_slice`.
        serde_json::Deserializer::from_slice(&stdout[json_start..])
            .into_iter::<Value>()
            .next()
            .expect("first JSON value")
            .expect("json parse")
    }

    struct FailingWriter;

    impl io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("write failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let leaf = format!(
            "{prefix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        );
        assert!(leaf
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        let mut path = std::env::temp_dir();
        path.push(leaf);
        path
    }

    fn legacy_exposure_contract_repo_path(rel: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../")
            .join(rel)
    }

    fn canonical_suite_registry_entry_json(suite_id: u8) -> String {
        format!(
            "{{\"suite_id\":{suite_id},\"pubkey_len\":{ML_DSA_87_PUBKEY_BYTES},\"sig_len\":{ML_DSA_87_SIG_BYTES},\"verify_cost\":{VERIFY_COST_ML_DSA_87},\"alg_name\":\"ML-DSA-87\"}}"
        )
    }

    fn test_legacy_exposure_p2pk_covenant_data(suite_id: u8) -> Vec<u8> {
        let mut cov = vec![0u8; rubin_consensus::constants::MAX_P2PK_COVENANT_DATA as usize];
        cov[0] = suite_id;
        cov
    }

    fn production_rotation_networks() -> [&'static str; 4] {
        ["mainnet", "testnet", " MAINNET ", "\tTestNet\t"]
    }

    #[derive(Clone, Default)]
    struct LifecycleEvents(Rc<RefCell<Vec<&'static str>>>);

    impl LifecycleEvents {
        fn push(&self, event: &'static str) {
            self.0.borrow_mut().push(event);
        }

        fn snapshot(&self) -> Vec<&'static str> {
            self.0.borrow().clone()
        }
    }

    struct FakeRpcLifecycle {
        events: LifecycleEvents,
        close_result: Result<(), String>,
    }

    struct FakeP2pLifecycle {
        events: LifecycleEvents,
    }

    impl super::RpcLifecycle for FakeRpcLifecycle {
        fn close_rpc(&mut self) -> Result<(), String> {
            self.events.push("rpc");
            self.close_result.clone()
        }
    }

    impl super::P2pLifecycle for FakeP2pLifecycle {
        fn close_p2p(&mut self) {
            self.events.push("p2p");
        }
    }

    #[test]
    fn signal_lifecycle_does_not_shutdown_before_stop_requested() {
        let (_handle, stop_signal) = stop_signal_pair();
        let events = LifecycleEvents::default();
        let mut rpc_server = Some(FakeRpcLifecycle {
            events: events.clone(),
            close_result: Ok(()),
        });
        let mut p2p_service = FakeP2pLifecycle {
            events: events.clone(),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = maybe_shutdown_if_requested(
            &stop_signal,
            &mut rpc_server,
            &mut p2p_service,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, None);
        assert_eq!(events.snapshot(), Vec::<&'static str>::new());
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }

    #[test]
    fn signal_lifecycle_contract_names_go_aligned_signal_set() {
        assert_eq!(PRODUCTION_STOP_SIGNAL_SET, "SIGINT/SIGTERM");
    }

    #[cfg(unix)]
    #[test]
    fn signal_lifecycle_unix_signal_set_excludes_sighup_for_go_parity() {
        let signals = super::production_unix_stop_signals();
        assert_eq!(
            signals,
            [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM]
        );
        assert!(
            !signals.contains(&signal_hook::consts::SIGHUP),
            "SIGHUP is not part of the Go-aligned graceful shutdown contract"
        );
    }

    #[test]
    fn signal_lifecycle_waits_for_stop_then_closes_rpc_before_p2p() {
        let (handle, stop_signal) = stop_signal_pair();
        handle.request_stop();
        handle.request_stop();
        let events = LifecycleEvents::default();
        let mut rpc_server = Some(FakeRpcLifecycle {
            events: events.clone(),
            close_result: Ok(()),
        });
        let mut p2p_service = FakeP2pLifecycle {
            events: events.clone(),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = wait_for_stop_and_shutdown(
            &stop_signal,
            &mut rpc_server,
            &mut p2p_service,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, 0);
        assert_eq!(events.snapshot(), vec!["rpc", "p2p"]);
        assert_eq!(
            String::from_utf8(stdout).expect("stdout utf8"),
            "rubin-node skeleton stopped\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn signal_lifecycle_stop_before_rpc_start_closes_p2p_only() {
        let (handle, stop_signal) = stop_signal_pair();
        handle.request_stop();
        let events = LifecycleEvents::default();
        let mut rpc_server: Option<FakeRpcLifecycle> = None;
        let mut p2p_service = FakeP2pLifecycle {
            events: events.clone(),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = maybe_shutdown_if_requested(
            &stop_signal,
            &mut rpc_server,
            &mut p2p_service,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, Some(0));
        assert_eq!(events.snapshot(), vec!["p2p"]);
        assert_eq!(
            String::from_utf8(stdout).expect("stdout utf8"),
            "rubin-node skeleton stopped\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn signal_lifecycle_rpc_start_error_after_stop_is_graceful_shutdown() {
        let (handle, stop_signal) = stop_signal_pair();
        handle.request_stop();
        let events = LifecycleEvents::default();
        let mut rpc_server: Option<FakeRpcLifecycle> = None;
        let mut p2p_service = FakeP2pLifecycle {
            events: events.clone(),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = handle_rpc_start_error_after_maybe_stop(
            &stop_signal,
            &mut rpc_server,
            &mut p2p_service,
            RPC_READINESS_TRANSITION_FAILED.to_string(),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, 0);
        assert_eq!(events.snapshot(), vec!["p2p"]);
        assert_eq!(
            String::from_utf8(stdout).expect("stdout utf8"),
            "rubin-node skeleton stopped\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn signal_lifecycle_stop_does_not_mask_rpc_bind_failure() {
        let (handle, stop_signal) = stop_signal_pair();
        handle.request_stop();
        let events = LifecycleEvents::default();
        let mut rpc_server: Option<FakeRpcLifecycle> = None;
        let mut p2p_service = FakeP2pLifecycle {
            events: events.clone(),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = handle_rpc_start_error_after_maybe_stop(
            &stop_signal,
            &mut rpc_server,
            &mut p2p_service,
            "bind 127.0.0.1:0: synthetic failure".to_string(),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, 2);
        assert_eq!(events.snapshot(), vec!["p2p"]);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).expect("stderr utf8"),
            "rpc start failed: bind 127.0.0.1:0: synthetic failure\n"
        );
    }

    #[test]
    fn signal_lifecycle_rpc_start_error_without_stop_is_startup_failure() {
        let (_handle, stop_signal) = stop_signal_pair();
        let events = LifecycleEvents::default();
        let mut rpc_server: Option<FakeRpcLifecycle> = None;
        let mut p2p_service = FakeP2pLifecycle {
            events: events.clone(),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = handle_rpc_start_error_after_maybe_stop(
            &stop_signal,
            &mut rpc_server,
            &mut p2p_service,
            "bind 127.0.0.1:0: synthetic failure".to_string(),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, 2);
        assert_eq!(events.snapshot(), vec!["p2p"]);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).expect("stderr utf8"),
            "rpc start failed: bind 127.0.0.1:0: synthetic failure\n"
        );
    }

    #[test]
    fn signal_lifecycle_rpc_close_error_reports_failure_and_still_closes_p2p() {
        let (handle, stop_signal) = stop_signal_pair();
        handle.request_stop();
        let events = LifecycleEvents::default();
        let mut rpc_server = Some(FakeRpcLifecycle {
            events: events.clone(),
            close_result: Err("synthetic rpc timeout".to_string()),
        });
        let mut p2p_service = FakeP2pLifecycle {
            events: events.clone(),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = wait_for_stop_and_shutdown(
            &stop_signal,
            &mut rpc_server,
            &mut p2p_service,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, 1);
        assert_eq!(events.snapshot(), vec!["rpc", "p2p"]);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).expect("stderr utf8"),
            "rpc shutdown failed: synthetic rpc timeout\nrubin-node skeleton stopped with shutdown errors\n"
        );
    }

    #[test]
    fn legacy_exposure_hooks_no_tip_returns_invalid_state() {
        let (readiness, warning, grace) = legacy_exposure_hooks(false, 0);
        assert_eq!(readiness, "invalid_no_chainstate_tip");
        assert_eq!(warning, "none");
        assert_eq!(grace, "not_applicable_no_chainstate_tip");
    }

    #[test]
    fn legacy_exposure_hooks_no_tip_with_nonzero_total_returns_invalid_state() {
        let (readiness, warning, grace) = legacy_exposure_hooks(false, 5);
        assert_eq!(readiness, "invalid_no_chainstate_tip");
        assert_eq!(warning, "none");
        assert_eq!(grace, "not_applicable_no_chainstate_tip");
    }

    #[test]
    fn legacy_exposure_hooks_with_tip_zero_total_returns_grace_window() {
        let (readiness, warning, grace) = legacy_exposure_hooks(true, 0);
        assert_eq!(readiness, "ready_for_operator_defined_grace_window");
        assert_eq!(warning, "none");
        assert_eq!(grace, "start_operator_defined_grace_window");
    }

    #[test]
    fn legacy_exposure_hooks_with_tip_nonzero_total_returns_not_ready() {
        let (readiness, warning, grace) = legacy_exposure_hooks(true, 3);
        assert_eq!(readiness, "not_ready_legacy_exposure_present");
        assert_eq!(
            warning,
            "legacy_exposure_present_notify_operator_and_council"
        );
        assert_eq!(grace, "not_applicable_legacy_exposure_present");
    }

    #[test]
    fn legacy_exposure_hook_vectors_fixture_parity() {
        let path = legacy_exposure_contract_repo_path(
            "conformance/fixtures/protocol/legacy_exposure_hook_vectors.json",
        );
        let raw = fs::read_to_string(&path).expect("read hook vectors");
        let doc: LegacyExposureHookVectorsDoc =
            serde_json::from_str(&raw).expect("parse hook vectors");
        assert_eq!(doc.contract_version, super::LEGACY_EXPOSURE_REPORT_VERSION);
        assert_eq!(doc.fixture_kind, "legacy_exposure_hook_vectors");
        assert_eq!(doc.cases, canonical_legacy_exposure_hook_vectors());
        for vector in &doc.cases {
            let (readiness, warning, grace) =
                legacy_exposure_hooks(vector.has_chainstate_tip, vector.legacy_exposure_total);
            assert_eq!(readiness, vector.sunset_readiness, "{}", vector.name);
            assert_eq!(warning, vector.warning_hook, "{}", vector.name);
            assert_eq!(grace, vector.grace_hook, "{}", vector.name);
        }
    }

    #[test]
    fn legacy_exposure_example_fixture_matches_frozen_contract() {
        let path = legacy_exposure_contract_repo_path(
            "conformance/fixtures/protocol/legacy_exposure_report_v1_example.json",
        );
        let raw = fs::read(&path).expect("read example fixture");
        let report: LegacyExposureReport =
            serde_json::from_slice(&raw).expect("parse example fixture");
        assert_eq!(report.report_version, super::LEGACY_EXPOSURE_REPORT_VERSION);
        assert_eq!(report.measurement_scope, "explicit_suite_id_utxos");
        assert_eq!(report.network, "devnet");
        assert!(report.chainstate_has_tip);
        assert_eq!(report.legacy_exposure_total, 3);
        assert!(!report.include_outpoints);
        assert_eq!(
            report.indexed_suite_ids,
            vec![u64::from(SUITE_ID_ML_DSA_87), 66]
        );
        assert_eq!(
            report.watched_legacy_suite_ids,
            vec![u64::from(SUITE_ID_ML_DSA_87), 66]
        );
        assert_eq!(report.legacy_suite_reports.len(), 2);
        let (readiness, warning, grace) =
            legacy_exposure_hooks(report.chainstate_has_tip, report.legacy_exposure_total);
        assert_eq!(report.sunset_readiness, readiness);
        assert_eq!(report.warning_hook, warning);
        assert_eq!(report.grace_hook, grace);
    }

    #[test]
    fn dry_run_defaults_to_devnet_chain_id() {
        let dir = unique_temp_dir("rubin-node-bin-default");
        let args = vec![
            "--dry-run".to_string(),
            "--datadir".to_string(),
            dir.display().to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 0, "stderr={}", String::from_utf8_lossy(&stderr));

        let json: Value = parse_effective_config_json(&stdout);
        assert_eq!(
            json["chain_id_hex"].as_str(),
            Some("88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103")
        );

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn dry_run_loads_chain_id_from_genesis_file() {
        let dir = unique_temp_dir("rubin-node-bin-genesis");
        fs::create_dir_all(&dir).expect("mkdir");
        let genesis_file = dir.join("genesis.json");
        fs::write(
            &genesis_file,
            "{\"chain_id_hex\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}",
        )
        .expect("write genesis");

        let args = vec![
            "--dry-run".to_string(),
            "--datadir".to_string(),
            dir.display().to_string(),
            "--genesis-file".to_string(),
            genesis_file.display().to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 0, "stderr={}", String::from_utf8_lossy(&stderr));

        let json: Value = parse_effective_config_json(&stdout);
        assert_eq!(
            json["chain_id_hex"].as_str(),
            Some("1111111111111111111111111111111111111111111111111111111111111111")
        );

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn dry_run_rejects_production_local_rotation_descriptor() {
        for network in production_rotation_networks() {
            let dir = unique_temp_dir("rubin-node-bin-prod-rotation");
            fs::create_dir_all(&dir).expect("mkdir");
            let genesis_file = dir.join("genesis.json");
            fs::write(
                &genesis_file,
                format!(
                    "{{\
                      \"chain_id_hex\":\"0x1111111111111111111111111111111111111111111111111111111111111111\",\
                      \"suite_registry\":[{},{}],\
                      \"rotation_descriptor\":{{\
                        \"name\":\"prod-rotation\",\
                        \"old_suite_id\":1,\
                        \"new_suite_id\":2,\
                        \"create_height\":1,\
                        \"spend_height\":5,\
                        \"sunset_height\":10\
                      }}\
                    }}",
                    canonical_suite_registry_entry_json(1),
                    canonical_suite_registry_entry_json(2),
                ),
            )
            .expect("write genesis");

            let args = vec![
                "--dry-run".to_string(),
                "--network".to_string(),
                network.to_string(),
                "--datadir".to_string(),
                dir.display().to_string(),
                "--genesis-file".to_string(),
                genesis_file.display().to_string(),
            ];
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();

            let code = run(&args, &mut stdout, &mut stderr);
            assert_eq!(code, 2, "stdout={}", String::from_utf8_lossy(&stdout));
            assert!(
                String::from_utf8_lossy(&stderr).contains(PRODUCTION_LOCAL_ROTATION_DESCRIPTOR_ERR),
                "network={network} stderr={}",
                String::from_utf8_lossy(&stderr)
            );

            fs::remove_dir_all(&dir).expect("cleanup");
        }
    }

    #[test]
    fn runtime_requires_explicit_genesis_hash_for_custom_chain_id() {
        let dir = unique_temp_dir("rubin-node-bin-runtime-genesis-hash");
        fs::create_dir_all(&dir).expect("mkdir");
        let genesis_file = dir.join("genesis.json");
        fs::write(
            &genesis_file,
            "{\"chain_id_hex\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}",
        )
        .expect("write genesis");

        let genesis_cfg = load_genesis_config(Some(&genesis_file), "devnet").expect("load");
        let err = runtime_genesis_hash(&genesis_cfg).unwrap_err();
        assert!(err.contains("genesis_hash_hex"), "unexpected error: {err}");

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn parse_args_accepts_rpc_bind() {
        let cfg = parse_args(&[
            "--datadir".to_string(),
            "/tmp/rubin".to_string(),
            "--rpc-bind".to_string(),
            "127.0.0.1:19112".to_string(),
        ])
        .expect("parse");
        assert_eq!(cfg.rpc_bind_addr, "127.0.0.1:19112");
    }

    #[test]
    fn parse_args_accepts_bind_peer_and_max_peers() {
        let cfg = parse_args(&[
            "--bind".to_string(),
            "127.0.0.1:19111".to_string(),
            "--peer".to_string(),
            "127.0.0.1:19112".to_string(),
            "--peers".to_string(),
            "127.0.0.1:19113,127.0.0.1:19112".to_string(),
            "--max-peers".to_string(),
            "32".to_string(),
        ])
        .expect("parse");
        assert_eq!(cfg.bind_addr, "127.0.0.1:19111");
        assert_eq!(
            cfg.peers,
            vec!["127.0.0.1:19112".to_string(), "127.0.0.1:19113".to_string(),]
        );
        assert_eq!(cfg.max_peers, 32);
    }

    #[test]
    fn validate_config_accepts_hostname_peer_addr() {
        // hostname:port is valid — DNS resolution happens at connect time, not validation
        let mut cfg = parse_args(&[
            "--peer".to_string(),
            "bootstrap.example.org:19111".to_string(),
        ])
        .expect("parse args");
        validate_config(&mut cfg).expect("hostname peer addr must be accepted");
    }

    #[test]
    fn validate_config_rejects_malformed_peer_addr() {
        let mut cfg =
            parse_args(&["--peer".to_string(), "no-port-here".to_string()]).expect("parse args");
        let err = validate_config(&mut cfg).unwrap_err();
        assert!(err.contains("invalid peer"), "unexpected error: {err}");
    }

    #[test]
    fn validate_config_normalizes_network_case() {
        let mut cfg =
            parse_args(&["--network".to_string(), "DevNet".to_string()]).expect("parse args");
        validate_config(&mut cfg).expect("DevNet should normalize to devnet");
        assert_eq!(cfg.network, "devnet", "network should be lowercased");
    }

    #[test]
    fn validate_config_normalizes_network_whitespace() {
        let mut cfg =
            parse_args(&["--network".to_string(), "  devnet  ".to_string()]).expect("parse args");
        validate_config(&mut cfg).expect("trimmed devnet should pass");
        assert_eq!(cfg.network, "devnet");
    }

    #[test]
    fn validate_config_rejects_unknown_network() {
        let mut cfg =
            parse_args(&["--network".to_string(), "foobar".to_string()]).expect("parse args");
        let err = validate_config(&mut cfg).unwrap_err();
        assert!(err.contains("unknown network"), "unexpected error: {err}");
    }

    #[test]
    fn validate_config_rejects_whitespace_only_network() {
        let mut cfg =
            parse_args(&["--network".to_string(), " \t ".to_string()]).expect("parse args");
        let err = validate_config(&mut cfg).unwrap_err();
        assert_eq!(err, "network is required");
    }

    #[test]
    fn validate_config_rejects_oversized_unknown_network() {
        let mut cfg = parse_args(&["--network".to_string(), "M".repeat(1024)]).expect("parse args");
        let err = validate_config(&mut cfg).unwrap_err();
        assert!(err.contains("unknown network"), "unexpected error: {err}");
    }

    #[test]
    fn non_devnet_without_genesis_file_is_rejected_before_datadir_create() {
        let dir = unique_temp_dir("rubin-node-bin-non-devnet-no-genesis");
        fs::create_dir_all(&dir).expect("mkdir");
        let blocker = dir.join("not-a-dir");
        fs::write(&blocker, b"x").expect("write blocker");
        let args = vec![
            "--network".to_string(),
            "testnet".to_string(),
            "--datadir".to_string(),
            blocker.display().to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 2);
        let stderr = String::from_utf8_lossy(&stderr);
        assert!(stderr.contains("requires a genesis file (--genesis-file)"));
        assert!(!stderr.contains("datadir create failed"));

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn parse_args_accepts_mining_flags() {
        let mine_address = "11".repeat(32);
        let cfg = parse_args(&[
            "--mine-address".to_string(),
            mine_address.clone(),
            "--mine-blocks".to_string(),
            "2".to_string(),
            "--mine-exit".to_string(),
        ])
        .expect("parse");
        assert_eq!(cfg.mine_address.as_deref(), Some(mine_address.as_str()));
        assert_eq!(cfg.mine_blocks, 2);
        assert!(cfg.mine_exit);
    }

    #[test]
    fn parse_args_accepts_pv_flags() {
        let cfg = parse_args(&[
            "--pv-mode".to_string(),
            "shadow".to_string(),
            "--pv-shadow-max".to_string(),
            "7".to_string(),
        ])
        .expect("parse");
        assert_eq!(cfg.pv_mode, "shadow");
        assert_eq!(cfg.pv_shadow_max, 7);
    }

    #[test]
    fn validate_config_rejects_invalid_pv_mode() {
        let mut cfg =
            parse_args(&["--pv-mode".to_string(), "bogus".to_string()]).expect("parse args");
        let err = validate_config(&mut cfg).unwrap_err();
        assert!(err.contains("pv_mode"), "unexpected error: {err}");
    }

    /// RUB-194 / GitHub #1458: validate_config must reject a malformed
    /// `--mine-address` BEFORE dry-run completes, mirroring Go
    /// `ValidateConfig` (`clients/go/node/config.go:407-415`). Without
    /// this gate, a bad address slipped through dry-run and only failed
    /// inside `Miner::new` setup (CLI mining path or live RPC mining
    /// path — line numbers omitted because the RUB-13 banner hoist
    /// shifted them; both call sites are unique enough to grep),
    /// causing operators to discover the error after startup-side
    /// effects rather than at config-validation time.
    ///
    /// Proof assertion: each `assert!(err.contains("invalid mine_address"))`
    /// in the rejection tests below is the regression anchor; each
    /// `validate_config(&mut cfg).expect(...)` in the accept tests
    /// pins the 32-byte and 33-byte (canonical `suite_id||key_id`) hex
    /// inputs as continuing to pass through `parse_mine_address_arg`.
    #[test]
    fn validate_config_accepts_32byte_mine_address_hex() {
        let mine_address = "11".repeat(32);
        let mut cfg =
            parse_args(&["--mine-address".to_string(), mine_address]).expect("parse args");
        validate_config(&mut cfg).expect("32-byte hex mine_address must be accepted");
    }

    #[test]
    fn validate_config_accepts_33byte_canonical_mine_address_hex() {
        // Canonical 33-byte form: suite_id (ML-DSA-87 = 0x01) || 32-byte key_id.
        let mut canonical = String::with_capacity(66);
        canonical.push_str(&format!(
            "{:02x}",
            rubin_consensus::constants::SUITE_ID_ML_DSA_87
        ));
        canonical.push_str(&"22".repeat(32));
        let mut cfg = parse_args(&["--mine-address".to_string(), canonical]).expect("parse args");
        validate_config(&mut cfg)
            .expect("33-byte canonical (suite_id||key_id) mine_address must be accepted");
    }

    #[test]
    fn validate_config_rejects_malformed_mine_address_hex() {
        // Non-hex characters: parse_mine_address surfaces hex::FromHexError
        // through parse_mine_address_arg; validate_config must wrap with
        // the "invalid mine_address" prefix.
        let mut cfg =
            parse_args(&["--mine-address".to_string(), "zz".repeat(32)]).expect("parse args");
        let err = validate_config(&mut cfg).unwrap_err();
        assert!(
            err.contains("invalid mine_address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_config_rejects_odd_length_mine_address_hex() {
        // Odd-length hex: parse_mine_address rejects before decode.
        // 63 hex chars is odd-length (canonical 32-byte form is 64 chars
        // and 33-byte canonical form is 66 chars).
        let mut cfg =
            parse_args(&["--mine-address".to_string(), "1".repeat(63)]).expect("parse args");
        let err = validate_config(&mut cfg).unwrap_err();
        assert!(
            err.contains("invalid mine_address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_config_rejects_wrong_byte_count_mine_address_hex() {
        // 1-byte (2 hex chars): valid hex but neither 32-byte key_id
        // nor 33-byte canonical. validate_config should reject it and
        // surface the wrapped "invalid mine_address" prefix.
        let mut cfg =
            parse_args(&["--mine-address".to_string(), "aa".to_string()]).expect("parse args");
        let err = validate_config(&mut cfg).unwrap_err();
        assert!(
            err.contains("invalid mine_address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_config_accepts_whitespace_only_mine_address() {
        // Rust-vs-Go documented divergence (pre-existing in
        // `crate::coinbase::parse_mine_address`, not introduced here):
        // whitespace-only input trims to empty -> `parse_mine_address_arg`
        // returns `Ok(None)` -> validate_config passes; run() then falls
        // back to `default_mine_address()`. Go's `hex.DecodeString` would
        // reject the same input as invalid hex. This test pins the Rust
        // accept-path so the divergence is visible and cannot regress silently.
        let mut cfg =
            parse_args(&["--mine-address".to_string(), "   ".to_string()]).expect("parse args");
        validate_config(&mut cfg)
            .expect("whitespace-only mine_address must be accepted (Rust silent-default path)");
    }

    #[test]
    fn dry_run_emits_rpc_bind_when_present() {
        let dir = unique_temp_dir("rubin-node-bin-rpc-bind");
        let args = vec![
            "--dry-run".to_string(),
            "--datadir".to_string(),
            dir.display().to_string(),
            "--rpc-bind".to_string(),
            "127.0.0.1:19112".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 0, "stderr={}", String::from_utf8_lossy(&stderr));
        let json: Value = parse_effective_config_json(&stdout);
        assert_eq!(json["rpc_bind_addr"].as_str(), Some("127.0.0.1:19112"));

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn dry_run_emits_p2p_runtime_fields() {
        let dir = unique_temp_dir("rubin-node-bin-p2p-runtime");
        let args = vec![
            "--dry-run".to_string(),
            "--datadir".to_string(),
            dir.display().to_string(),
            "--bind".to_string(),
            "127.0.0.1:19111".to_string(),
            "--peer".to_string(),
            "127.0.0.1:19112".to_string(),
            "--max-peers".to_string(),
            "16".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 0, "stderr={}", String::from_utf8_lossy(&stderr));
        let json: Value = parse_effective_config_json(&stdout);
        assert_eq!(json["bind_addr"].as_str(), Some("127.0.0.1:19111"));
        assert_eq!(json["max_peers"].as_u64(), Some(16));
        assert_eq!(json["peers"][0].as_str(), Some("127.0.0.1:19112"));

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn dry_run_emits_pv_fields() {
        let dir = unique_temp_dir("rubin-node-bin-pv");
        let args = vec![
            "--dry-run".to_string(),
            "--datadir".to_string(),
            dir.display().to_string(),
            "--pv-mode".to_string(),
            "on".to_string(),
            "--pv-shadow-max".to_string(),
            "9".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 0, "stderr={}", String::from_utf8_lossy(&stderr));
        let json: Value = parse_effective_config_json(&stdout);
        assert_eq!(json["pv_mode"].as_str(), Some("on"));
        assert_eq!(json["pv_shadow_max"].as_u64(), Some(9));

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// RUB-13 / GitHub #1157: dry-run startup stdout emits BOTH
    /// operator-facing parity banners (sync header_request + p2p
    /// peer_slots) that pin the cross-client format from
    /// `clients/go/cmd/rubin-node/main.go:441-443`. Without these
    /// banners — and without their adjacent placement after the JSON
    /// dump and before the dry-run early-exit — mixed-client devnet
    /// diagnostic scripts scraping `rubin-node` startup output for
    /// sync state or peer-slot occupancy break on the Rust client.
    ///
    /// Proof assertion: stdout contains the two one-line formats
    /// `sync: header_request_has_from=<bool> header_request_limit=<u64> ibd=<bool>`
    /// and `p2p: peer_slots=<usize> connected=<usize>` on adjacent
    /// lines, both AFTER the effective-config JSON dump and BEFORE
    /// the `--dry-run` early-exit. Scraping clients on either runtime
    /// see both banners on a `--dry-run` invocation.
    #[test]
    fn dry_run_emits_sync_and_peer_slots_banners_after_json_in_order() {
        let dir = unique_temp_dir("rubin-node-bin-banners");
        let args = vec![
            "--dry-run".to_string(),
            "--datadir".to_string(),
            dir.display().to_string(),
            "--max-peers".to_string(),
            "12".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 0, "stderr={}", String::from_utf8_lossy(&stderr));
        let stdout_str = String::from_utf8(stdout).expect("stdout utf8");

        // (1) sync banner: pin the exact one-line format token-for-
        // token. Three key=value pairs in order; bool / u64 / bool.
        // ibd depends on wall-clock at test time so any bool is OK.
        let sync_line = stdout_str
            .lines()
            .find(|line| line.starts_with("sync: header_request_has_from="))
            .unwrap_or_else(|| {
                panic!(
                    "missing `sync: header_request_has_from=…` banner; \
                     full stdout=\n{stdout_str}"
                )
            });
        let mut pairs = sync_line.trim_start_matches("sync: ").split(' ');
        let has_from_kv = pairs.next().expect("has_from kv");
        let limit_kv = pairs.next().expect("limit kv");
        let ibd_kv = pairs.next().expect("ibd kv");
        assert!(
            pairs.next().is_none(),
            "extra fields in sync banner: {sync_line}"
        );
        let (has_from_key, has_from_val) = has_from_kv.split_once('=').expect("has_from k=v");
        let (limit_key, limit_val) = limit_kv.split_once('=').expect("limit k=v");
        let (ibd_key, ibd_val) = ibd_kv.split_once('=').expect("ibd k=v");
        assert_eq!(has_from_key, "header_request_has_from");
        assert_eq!(limit_key, "header_request_limit");
        assert_eq!(ibd_key, "ibd");
        assert!(
            has_from_val == "true" || has_from_val == "false",
            "header_request_has_from must be a bool token; got {has_from_val:?}"
        );
        assert!(
            limit_val.parse::<u64>().is_ok(),
            "header_request_limit must parse as u64; got {limit_val:?}"
        );
        assert!(
            ibd_val == "true" || ibd_val == "false",
            "ibd must be a bool token; got {ibd_val:?}"
        );

        // (2) p2p:peer_slots banner: empty PeerManager at startup,
        // so connected=0; --max-peers=12 above pins the slot cap.
        // Direct equality — token-for-token format helper output.
        assert!(
            stdout_str
                .lines()
                .any(|line| line == "p2p: peer_slots=12 connected=0"),
            "missing exact `p2p: peer_slots=12 connected=0` banner; \
             full stdout=\n{stdout_str}"
        );

        // (3) Sequencing: JSON dump BEFORE both banners, sync banner
        // BEFORE peer_slots banner, both BEFORE the (implicit) dry-run
        // exit. Same upstream sequencing pinned at
        // `clients/go/cmd/rubin-node/main.go:441-443`.
        let json_pos = stdout_str.find('{').expect("json open present");
        let json_close_pos = stdout_str.rfind('}').expect("json close present");
        let sync_pos = stdout_str
            .find("sync: header_request_has_from=")
            .expect("sync banner present");
        let peers_pos = stdout_str
            .find("p2p: peer_slots=")
            .expect("peers banner present");
        assert!(
            json_close_pos < sync_pos,
            "JSON dump must close before sync banner; \
             json_close_pos={json_close_pos}, sync_pos={sync_pos}"
        );
        assert!(
            sync_pos < peers_pos,
            "sync banner must appear before peer_slots banner (upstream order); \
             sync_pos={sync_pos}, peers_pos={peers_pos}"
        );
        assert!(
            json_pos < json_close_pos,
            "JSON object well-formed; json_pos={json_pos}, json_close_pos={json_close_pos}"
        );

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// RUB-13 / GitHub #1157: pin the exact one-line format of the
    /// `p2p: peer_slots=N connected=K` banner that mirrors the
    /// upstream emission at `clients/go/cmd/rubin-node/main.go:443`.
    /// The public-path integration test
    /// `dry_run_emits_sync_and_peer_slots_banners_after_json_in_order`
    /// already covers the dry-run public path; this unit test is
    /// the helper-only edge cover. It pins inputs that the public
    /// path cannot reach because `validate_config` rejects them
    /// upstream — most notably `max_peers == 0`, which
    /// `clients/go/node/config.go:395-396` and the Rust counterpart
    /// reject before `run()` is ever invoked, so the format helper
    /// is the only callable surface for the `(0, 0)` row. The
    /// helper input mirrors what production passes: `cfg.max_peers`
    /// (usize from --max-peers flag) and `peer_manager.snapshot().len()`
    /// (usize, the same accessor `/peers` uses, RUB-14).
    ///
    /// Proof assertion: empty peer set produces `connected=0`,
    /// non-empty produces the exact slot count, the slot-cap-reached
    /// edge prints both equal, and the unreachable `(0, 0)` defensive
    /// row still renders honestly. The entire line matches the
    /// upstream format string token-for-token.
    #[test]
    fn format_peer_slots_banner_matches_go_format() {
        // Empty peer set, default max_peers (8 — the devnet default).
        assert_eq!(
            format_peer_slots_banner(8, 0),
            "p2p: peer_slots=8 connected=0"
        );
        // Non-empty peer set with non-default cap.
        assert_eq!(
            format_peer_slots_banner(16, 3),
            "p2p: peer_slots=16 connected=3"
        );
        // Edge: connected at slot cap.
        assert_eq!(
            format_peer_slots_banner(2, 2),
            "p2p: peer_slots=2 connected=2"
        );
        // Defensive renderer test for an input that is rejected
        // upstream by `validate_config` (`--max-peers` must be > 0
        // on both runtimes — `clients/go/node/config.go:395-396`
        // and the Rust counterpart enforce this). The renderer
        // itself stays total: it does not validate, it only formats,
        // so a hypothetical pre-validation caller still gets honest
        // output.
        assert_eq!(
            format_peer_slots_banner(0, 0),
            "p2p: peer_slots=0 connected=0"
        );
    }

    #[test]
    fn legacy_exposure_scan_emits_deterministic_json() {
        let dir = unique_temp_dir("rubin-node-bin-legacy-exposure");
        fs::create_dir_all(&dir).expect("mkdir");
        let mut state = rubin_node::ChainState::new();
        state.has_tip = true;
        state.height = 42;
        let first = rubin_consensus::Outpoint {
            txid: [0x01; 32],
            vout: 0,
        };
        let second = rubin_consensus::Outpoint {
            txid: [0x02; 32],
            vout: 1,
        };
        let third = rubin_consensus::Outpoint {
            txid: [0x03; 32],
            vout: 2,
        };
        let cov_legacy =
            test_legacy_exposure_p2pk_covenant_data(rubin_consensus::constants::SUITE_ID_ML_DSA_87);
        state.utxos.insert(
            first,
            rubin_consensus::UtxoEntry {
                value: 10,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: cov_legacy,
                creation_height: 2,
                created_by_coinbase: false,
            },
        );
        let cov_rotated = test_legacy_exposure_p2pk_covenant_data(0x42);
        state.utxos.insert(
            second,
            rubin_consensus::UtxoEntry {
                value: 11,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: cov_rotated.clone(),
                creation_height: 3,
                created_by_coinbase: false,
            },
        );
        state.utxos.insert(
            third,
            rubin_consensus::UtxoEntry {
                value: 12,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: cov_rotated,
                creation_height: 4,
                created_by_coinbase: false,
            },
        );
        state
            .save(rubin_node::chain_state_path(&dir))
            .expect("save chainstate");

        let args = vec![
            "--datadir".to_string(),
            dir.display().to_string(),
            "--legacy-exposure-scan".to_string(),
            "--legacy-suite-id".to_string(),
            "0x42".to_string(),
            "--legacy-suite-id".to_string(),
            "1".to_string(),
            "--legacy-suite-id".to_string(),
            "0x42".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 0, "stderr={}", String::from_utf8_lossy(&stderr));
        let json: Value = parse_effective_config_json(&stdout);
        assert!(json["indexed_suite_ids"].is_array());
        assert!(json["watched_legacy_suite_ids"].is_array());
        assert_eq!(
            json["report_version"].as_u64(),
            Some(super::LEGACY_EXPOSURE_REPORT_VERSION)
        );
        assert_eq!(
            json["measurement_scope"].as_str(),
            Some("explicit_suite_id_utxos")
        );
        assert_eq!(json["network"].as_str(), Some("devnet"));
        assert_eq!(
            json["indexed_suite_ids"],
            serde_json::json!([rubin_consensus::constants::SUITE_ID_ML_DSA_87, 0x42])
        );
        assert_eq!(
            json["watched_legacy_suite_ids"],
            serde_json::json!([rubin_consensus::constants::SUITE_ID_ML_DSA_87, 0x42])
        );
        assert_eq!(json["legacy_exposure_total"].as_u64(), Some(3));
        assert_eq!(
            json["sunset_readiness"].as_str(),
            Some("not_ready_legacy_exposure_present")
        );
        assert_eq!(
            json["warning_hook"].as_str(),
            Some("legacy_exposure_present_notify_operator_and_council")
        );
        assert_eq!(
            json["grace_hook"].as_str(),
            Some("not_applicable_legacy_exposure_present")
        );

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn legacy_exposure_scan_includes_outpoints() {
        let dir = unique_temp_dir("rubin-node-bin-legacy-outpoints");
        fs::create_dir_all(&dir).expect("mkdir");
        let mut state = rubin_node::ChainState::new();
        state.has_tip = true;
        state.height = 7;
        state.tip_hash = [0x42; 32];
        let first = rubin_consensus::Outpoint {
            txid: [0x02; 32],
            vout: 1,
        };
        let second = rubin_consensus::Outpoint {
            txid: [0x01; 32],
            vout: 0,
        };
        let cov = test_legacy_exposure_p2pk_covenant_data(0x42);
        state.utxos.insert(
            first,
            rubin_consensus::UtxoEntry {
                value: 11,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: cov.clone(),
                creation_height: 3,
                created_by_coinbase: false,
            },
        );
        state.utxos.insert(
            second,
            rubin_consensus::UtxoEntry {
                value: 12,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: cov,
                creation_height: 4,
                created_by_coinbase: false,
            },
        );
        state
            .save(rubin_node::chain_state_path(&dir))
            .expect("save chainstate");

        let args = vec![
            "--datadir".to_string(),
            dir.display().to_string(),
            "--legacy-exposure-scan".to_string(),
            "--legacy-suite-id".to_string(),
            "66".to_string(),
            "--legacy-exposure-include-outpoints".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 0, "stderr={}", String::from_utf8_lossy(&stderr));
        let json: Value = parse_effective_config_json(&stdout);
        assert_eq!(json["include_outpoints"].as_bool(), Some(true));
        assert_eq!(json["legacy_exposure_total"].as_u64(), Some(2));
        assert_eq!(
            json["legacy_suite_reports"][0]["utxo_exposure_count"].as_u64(),
            Some(2)
        );
        assert_eq!(
            json["legacy_suite_reports"][0]["outpoint_count"].as_u64(),
            Some(2)
        );
        assert_eq!(
            json["legacy_suite_reports"][0]["outpoints"][0].as_str(),
            Some("0101010101010101010101010101010101010101010101010101010101010101:0")
        );
        assert_eq!(
            json["legacy_suite_reports"][0]["outpoints"][1].as_str(),
            Some("0202020202020202020202020202020202020202020202020202020202020202:1")
        );

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn legacy_exposure_scan_emits_empty_outpoints_when_detail_mode_has_no_matches() {
        let dir = unique_temp_dir("rubin-node-bin-legacy-empty-outpoints");
        fs::create_dir_all(&dir).expect("mkdir");
        let mut state = rubin_node::ChainState::new();
        state.has_tip = true;
        state.height = 7;
        state.tip_hash = [0x42; 32];
        state
            .save(rubin_node::chain_state_path(&dir))
            .expect("save chainstate");

        let args = vec![
            "--datadir".to_string(),
            dir.display().to_string(),
            "--network".to_string(),
            "mainnet".to_string(),
            "--legacy-exposure-scan".to_string(),
            "--legacy-suite-id".to_string(),
            "1".to_string(),
            "--legacy-exposure-include-outpoints".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 0, "stderr={}", String::from_utf8_lossy(&stderr));
        let json: Value = parse_effective_config_json(&stdout);
        assert_eq!(json["include_outpoints"].as_bool(), Some(true));
        assert_eq!(json["legacy_exposure_total"].as_u64(), Some(0));
        assert_eq!(
            json["legacy_suite_reports"][0]["utxo_exposure_count"].as_u64(),
            Some(0)
        );
        assert_eq!(
            json["legacy_suite_reports"][0]["outpoint_count"].as_u64(),
            Some(0)
        );
        assert_eq!(
            json["legacy_suite_reports"][0]["outpoints"],
            serde_json::json!([])
        );

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn legacy_exposure_scan_requires_suite_ids() {
        let dir = unique_temp_dir("rubin-node-bin-legacy-empty");
        let args = vec![
            "--datadir".to_string(),
            dir.display().to_string(),
            "--legacy-exposure-scan".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 2);
        assert!(String::from_utf8_lossy(&stderr)
            .contains("legacy exposure scan requires at least one --legacy-suite-id"));
    }

    #[test]
    fn legacy_exposure_scan_requires_existing_chainstate_with_tip() {
        let dir = unique_temp_dir("rubin-node-bin-legacy-missing-chainstate");
        let args = vec![
            "--datadir".to_string(),
            dir.display().to_string(),
            "--legacy-exposure-scan".to_string(),
            "--legacy-suite-id".to_string(),
            "1".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 2);
        assert!(String::from_utf8_lossy(&stderr)
            .contains("legacy exposure scan requires an existing chainstate file with a tip"));
    }

    #[test]
    fn legacy_exposure_scan_requires_chainstate_tip() {
        let dir = unique_temp_dir("rubin-node-bin-legacy-no-tip");
        fs::create_dir_all(&dir).expect("mkdir");
        rubin_node::ChainState::new()
            .save(rubin_node::chain_state_path(&dir))
            .expect("save chainstate");
        let args = vec![
            "--datadir".to_string(),
            dir.display().to_string(),
            "--legacy-exposure-scan".to_string(),
            "--legacy-suite-id".to_string(),
            "1".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 2);
        assert!(String::from_utf8_lossy(&stderr)
            .contains("legacy exposure scan requires a chainstate with a tip"));
    }

    #[test]
    fn legacy_exposure_scan_rejects_invalid_suite_id() {
        let dir = unique_temp_dir("rubin-node-bin-legacy-invalid");
        let blocker = dir.join("not-a-dir");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::write(&blocker, b"x").expect("write blocker");
        let args = vec![
            "--datadir".to_string(),
            blocker.display().to_string(),
            "--legacy-exposure-scan".to_string(),
            "--legacy-suite-id".to_string(),
            "0x100".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 2);
        assert!(String::from_utf8_lossy(&stderr).contains("invalid legacy suite_id"));
    }

    #[test]
    fn legacy_exposure_scan_validates_suite_ids_before_datadir_create() {
        let dir = unique_temp_dir("rubin-node-bin-legacy-ordering");
        let blocker = dir.join("not-a-dir");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::write(&blocker, b"x").expect("write blocker");
        let args = vec![
            "--datadir".to_string(),
            blocker.display().to_string(),
            "--legacy-exposure-scan".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 2);
        let stderr = String::from_utf8_lossy(&stderr);
        assert!(stderr.contains("legacy exposure scan requires at least one --legacy-suite-id"));
        assert!(!stderr.contains("datadir create failed"));
    }

    #[test]
    fn legacy_exposure_scan_does_not_require_genesis_file_for_named_network() {
        let dir = unique_temp_dir("rubin-node-bin-legacy-mainnet");
        fs::create_dir_all(&dir).expect("mkdir");
        let mut state = rubin_node::ChainState::new();
        state.has_tip = true;
        state.height = 7;
        state.tip_hash = [0x42; 32];
        state
            .save(rubin_node::chain_state_path(&dir))
            .expect("save chainstate");
        let args = vec![
            "--datadir".to_string(),
            dir.display().to_string(),
            "--network".to_string(),
            "mainnet".to_string(),
            "--legacy-exposure-scan".to_string(),
            "--legacy-suite-id".to_string(),
            "1".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 0, "stderr={}", String::from_utf8_lossy(&stderr));
        let json: Value = parse_effective_config_json(&stdout);
        assert_eq!(json["network"].as_str(), Some("mainnet"));
        assert_eq!(json["legacy_exposure_total"].as_u64(), Some(0));

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn legacy_exposure_scan_propagates_encode_failure_details() {
        let dir = unique_temp_dir("rubin-node-bin-legacy-encode-failure");
        fs::create_dir_all(&dir).expect("mkdir");
        let mut state = rubin_node::ChainState::new();
        state.has_tip = true;
        state.height = 7;
        state.tip_hash = [0x42; 32];
        state
            .save(rubin_node::chain_state_path(&dir))
            .expect("save chainstate");
        let args = vec![
            "--datadir".to_string(),
            dir.display().to_string(),
            "--legacy-exposure-scan".to_string(),
            "--legacy-suite-id".to_string(),
            "1".to_string(),
        ];
        let mut stdout = FailingWriter;
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 1);
        let stderr = String::from_utf8_lossy(&stderr);
        assert!(stderr.contains("legacy exposure encode failed:"));
        assert!(stderr.contains("write failed"));

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn legacy_exposure_flags_require_scan_mode() {
        let dir = unique_temp_dir("rubin-node-bin-legacy-flags-without-scan");
        fs::create_dir_all(&dir).expect("mkdir");
        let blocker = dir.join("not-a-dir");
        fs::write(&blocker, b"x").expect("write blocker");
        let args = vec![
            "--datadir".to_string(),
            blocker.display().to_string(),
            "--legacy-suite-id".to_string(),
            "1".to_string(),
            "--legacy-exposure-include-outpoints".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 2);
        let stderr = String::from_utf8_lossy(&stderr);
        assert!(stderr.contains("legacy exposure flags require --legacy-exposure-scan"));
        assert!(!stderr.contains("datadir create failed"));

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn invalid_genesis_file_is_rejected_before_datadir_create() {
        let dir = unique_temp_dir("rubin-node-bin-invalid-genesis-before-datadir");
        fs::create_dir_all(&dir).expect("mkdir");
        let blocker = dir.join("not-a-dir");
        fs::write(&blocker, b"x").expect("write blocker");
        let genesis_file = dir.join("invalid-genesis.json");
        fs::write(&genesis_file, b"{").expect("write genesis");
        let args = vec![
            "--network".to_string(),
            "mainnet".to_string(),
            "--datadir".to_string(),
            blocker.display().to_string(),
            "--genesis-file".to_string(),
            genesis_file.display().to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 2);
        let stderr = String::from_utf8_lossy(&stderr);
        assert!(stderr.contains("invalid genesis file:"));
        assert!(!stderr.contains("datadir create failed"));

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn mine_exit_mines_requested_blocks_and_returns_zero() {
        let dir = unique_temp_dir("rubin-node-bin-mine-exit");
        let args = vec![
            "--datadir".to_string(),
            dir.display().to_string(),
            "--mine-blocks".to_string(),
            "2".to_string(),
            "--mine-exit".to_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run(&args, &mut stdout, &mut stderr);
        assert_eq!(code, 0, "stderr={}", String::from_utf8_lossy(&stderr));
        let out = String::from_utf8(stdout).expect("utf8");
        assert!(out.contains("\"mine_blocks\": 2"), "stdout={out}");
        assert!(out.contains("mined: height=0"), "stdout={out}");
        assert!(out.contains("mined: height=1"), "stdout={out}");

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn validate_addr_rejects_extra_colons() {
        let r = super::validate_addr("test", "foo:bar:80");
        assert!(r.is_err(), "extra colons must be rejected");
        assert!(r.as_ref().unwrap_err().contains("':'"), "{:?}", r);
    }

    #[test]
    fn validate_addr_rejects_null_in_host() {
        let r = super::validate_addr("test", "foo\0bar:80");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("null"));
    }

    #[test]
    fn validate_addr_rejects_long_hostname() {
        let long = "a".repeat(254);
        let r = super::validate_addr("test", &format!("{long}:80"));
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("too long"));
    }

    #[test]
    fn validate_addr_accepts_bracketed_ipv6() {
        let r = super::validate_addr_inner("test", "[::1]:19111", false);
        assert!(r.is_ok());
    }

    #[test]
    fn validate_addr_rejects_malformed_bracket() {
        assert!(super::validate_addr("test", "[::1:19111").is_err());
        assert!(super::validate_addr("test", "foo]:19111").is_err());
    }

    #[test]
    fn validate_addr_allows_ephemeral_port() {
        assert!(super::validate_addr_inner("test", "127.0.0.1:0", true).is_ok());
        assert!(super::validate_addr_inner("test", "127.0.0.1:0", false).is_err());
    }

    #[test]
    fn validate_addr_rejects_long_dns_label() {
        let long_label = "a".repeat(64);
        let addr = format!("{long_label}.example.com:8333");
        let err = super::validate_addr_inner("test", &addr, false).unwrap_err();
        assert!(err.contains("out of range"), "unexpected: {err}");
    }

    #[test]
    fn validate_addr_rejects_hyphen_start_label() {
        let err = super::validate_addr_inner("test", "-host.example.com:8333", false).unwrap_err();
        assert!(err.contains("hyphen"), "unexpected: {err}");
    }

    #[test]
    fn validate_addr_rejects_invalid_label_chars() {
        let err =
            super::validate_addr_inner("test", "host_name.example.com:8333", false).unwrap_err();
        assert!(err.contains("invalid character"), "unexpected: {err}");
    }

    #[test]
    fn validate_addr_accepts_valid_hostname() {
        assert!(super::validate_addr_inner("test", "node-1.example.com:8333", false).is_ok());
        assert!(super::validate_addr_inner("test", "a.b.c:19111", false).is_ok());
    }
}
