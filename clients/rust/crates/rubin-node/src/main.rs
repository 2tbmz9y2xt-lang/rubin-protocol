use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rubin_consensus::{
    canonical_rotation_network_name_normalized, normalized_rotation_network_name,
    SUPPORTED_ROTATION_NETWORK_NAMES_CSV,
};
use rubin_node::{
    block_store_path, chain_state_path, default_peer_runtime_config, default_sync_config,
    load_chain_state, load_genesis_config, new_devnet_rpc_state_with_tx_pool,
    new_shared_runtime_tx_pool, parse_mine_address_arg, start_devnet_rpc_server,
    start_node_p2p_service, BlockStore, LoadedGenesisConfig, Miner, MinerConfig,
    NodeP2PServiceConfig, PeerManager, SyncEngine,
};
use serde::Serialize;

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

#[derive(Serialize)]
struct LegacyExposureSuiteReport {
    suite_id: u64,
    utxo_exposure_count: u64,
    outpoint_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    outpoints: Option<Vec<String>>,
}

#[derive(Serialize)]
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
    let chain_state = match load_chain_state(&chain_state_file) {
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
    if let Err(err) = chain_state.save(&chain_state_file) {
        let _ = writeln!(
            stderr,
            "chainstate save failed ({}): {err}",
            chain_state_file.display()
        );
        return 2;
    }

    let block_store = match BlockStore::open(block_store_path(&cfg.data_dir)) {
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
    let genesis_hash = match runtime_genesis_hash(&genesis_cfg) {
        Ok(hash) => hash,
        Err(err) => {
            let _ = writeln!(stderr, "{err}");
            return 2;
        }
    };
    let sync_engine = Arc::new(Mutex::new(sync_engine));
    let tx_pool = new_shared_runtime_tx_pool(&sync_engine);
    let peer_runtime_cfg = default_peer_runtime_config(&cfg.network, cfg.max_peers);
    let peer_manager = Arc::new(PeerManager::new(peer_runtime_cfg.clone()));
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

    let announce_tx: Option<rubin_node::devnet_rpc::AnnounceTxFn> = {
        let relay_state = p2p_service.relay_state();
        let pm = Arc::clone(&peer_manager);
        let pw = p2p_service.peer_outboxes();
        let local = p2p_service.addr().to_string();
        Some(Arc::new(move |tx_bytes: &[u8], meta| {
            rubin_node::tx_relay::announce_tx(tx_bytes, meta, &relay_state, &pm, &local, &pw)
        }))
    };
    let state = new_devnet_rpc_state_with_tx_pool(
        Arc::clone(&sync_engine),
        Some(block_store),
        Arc::clone(&tx_pool),
        Arc::clone(&peer_manager),
        announce_tx,
    );
    let server = if cfg.rpc_bind_addr.trim().is_empty() {
        None
    } else {
        match start_devnet_rpc_server(&cfg.rpc_bind_addr, state) {
            Ok(server) => Some(server),
            Err(err) => {
                let _ = writeln!(stderr, "rpc start failed: {err}");
                p2p_service.close();
                return 2;
            }
        }
    };
    if let Some(server) = server.as_ref() {
        let _ = writeln!(stdout, "rpc: listening={}", server.addr());
    }
    let _ = writeln!(stdout, "rubin-node skeleton running");
    let _ = stdout.flush();

    loop {
        thread::sleep(Duration::from_secs(60));
    }
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::path::PathBuf;

    use rubin_consensus::constants::{
        ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, VERIFY_COST_ML_DSA_87,
    };
    use serde_json::Value;

    use super::{legacy_exposure_hooks, parse_args, run, runtime_genesis_hash, validate_config};
    use rubin_node::{load_genesis_config, PRODUCTION_LOCAL_ROTATION_DESCRIPTOR_ERR};

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
        std::env::temp_dir().join(format!(
            "{prefix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    fn canonical_suite_registry_entry_json(suite_id: u8) -> String {
        format!(
            "{{\"suite_id\":{suite_id},\"pubkey_len\":{ML_DSA_87_PUBKEY_BYTES},\"sig_len\":{ML_DSA_87_SIG_BYTES},\"verify_cost\":{VERIFY_COST_ML_DSA_87},\"openssl_alg\":\"ML-DSA-87\"}}"
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
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../conformance/fixtures/protocol/legacy_exposure_hook_vectors.json");
        let raw =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let doc: Value = serde_json::from_str(&raw).expect("hook vectors json");
        assert_eq!(
            doc["contract_version"].as_u64(),
            Some(1),
            "unexpected contract_version in {}",
            path.display()
        );
        assert_eq!(
            doc["fixture_kind"].as_str(),
            Some("legacy_exposure_hook_vectors"),
            "unexpected fixture_kind in {}",
            path.display()
        );
        let cases = doc["cases"].as_array().expect("cases array");
        for c in cases {
            let name = c["name"].as_str().expect("case name");
            let has_tip = c["has_chainstate_tip"]
                .as_bool()
                .expect("has_chainstate_tip");
            let total = c["legacy_exposure_total"]
                .as_u64()
                .expect("legacy_exposure_total");
            let (r, w, g) = legacy_exposure_hooks(has_tip, total);
            assert_eq!(
                r,
                c["sunset_readiness"].as_str().expect("sunset_readiness"),
                "case {name}"
            );
            assert_eq!(
                w,
                c["warning_hook"].as_str().expect("warning_hook"),
                "case {name}"
            );
            assert_eq!(
                g,
                c["grace_hook"].as_str().expect("grace_hook"),
                "case {name}"
            );
        }
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

        let json: Value = serde_json::from_slice(&stdout).expect("json");
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

        let json: Value = serde_json::from_slice(&stdout).expect("json");
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
        let json: Value = serde_json::from_slice(&stdout).expect("json");
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
        let json: Value = serde_json::from_slice(&stdout).expect("json");
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
        let json: Value = serde_json::from_slice(&stdout).expect("json");
        assert_eq!(json["pv_mode"].as_str(), Some("on"));
        assert_eq!(json["pv_shadow_max"].as_u64(), Some(9));

        fs::remove_dir_all(&dir).expect("cleanup");
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
        let json: Value = serde_json::from_slice(&stdout).expect("json");
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
        let json: Value = serde_json::from_slice(&stdout).expect("json");
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
        let json: Value = serde_json::from_slice(&stdout).expect("json");
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
        let json: Value = serde_json::from_slice(&stdout).expect("json");
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
