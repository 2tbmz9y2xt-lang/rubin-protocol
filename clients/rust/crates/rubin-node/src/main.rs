use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rubin_node::{
    block_store_path, chain_state_path, default_peer_runtime_config, default_sync_config,
    load_chain_state, load_genesis_config, new_devnet_rpc_state, parse_mine_address_arg,
    start_devnet_rpc_server, start_node_p2p_service, BlockStore, LoadedGenesisConfig, Miner,
    MinerConfig, NodeP2PServiceConfig, PeerManager, SyncEngine,
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
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let exit_code = run(&args, &mut io::stdout(), &mut io::stderr());
    std::process::exit(exit_code);
}

fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        usage(stdout);
        return 0;
    }

    let cfg = match parse_args(args) {
        Ok(cfg) => cfg,
        Err(err) => {
            let _ = writeln!(stderr, "{err}");
            return 2;
        }
    };
    if let Err(err) = validate_config(&cfg) {
        let _ = writeln!(stderr, "{err}");
        return 2;
    }

    let genesis_cfg = match load_genesis_config(cfg.genesis_file.as_deref()) {
        Ok(cfg) => cfg,
        Err(err) => {
            let _ = writeln!(stderr, "invalid genesis file: {err}");
            return 2;
        }
    };
    let chain_id = genesis_cfg.chain_id;

    if let Err(err) = fs::create_dir_all(&cfg.data_dir) {
        let _ = writeln!(
            stderr,
            "datadir create failed ({}): {err}",
            cfg.data_dir.display()
        );
        return 2;
    }

    let chain_state_file = chain_state_path(&cfg.data_dir);
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
    let peer_runtime_cfg = default_peer_runtime_config(&cfg.network, cfg.max_peers);
    let peer_manager = Arc::new(PeerManager::new(peer_runtime_cfg.clone()));
    let mut p2p_service = match start_node_p2p_service(NodeP2PServiceConfig {
        bind_addr: cfg.bind_addr.clone(),
        bootstrap_peers: cfg.peers.clone(),
        runtime_cfg: peer_runtime_cfg,
        peer_manager: Arc::clone(&peer_manager),
        sync_engine: Arc::clone(&sync_engine),
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

    let state = new_devnet_rpc_state(
        Arc::clone(&sync_engine),
        Some(block_store),
        Arc::clone(&peer_manager),
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
        "usage: rubin-node [--network <name>] [--datadir <path>] [--genesis-file <path>] [--bind <host:port>] [--peer <host:port>]... [--peers <csv>] [--max-peers <n>] [--rpc-bind <host:port>] [--mine-address <hex>] [--mine-blocks <n>] [--mine-exit] [--dry-run]"
    );
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

fn validate_config(cfg: &CliConfig) -> Result<(), String> {
    if cfg.network.trim().is_empty() {
        return Err("network is required".to_string());
    }
    if cfg.data_dir.as_os_str().is_empty() {
        return Err("data_dir is required".to_string());
    }
    validate_addr("bind_addr", &cfg.bind_addr)?;
    if !cfg.rpc_bind_addr.trim().is_empty() {
        validate_addr("rpc_bind_addr", &cfg.rpc_bind_addr)?;
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
    Ok(())
}

fn validate_addr(label: &str, addr: &str) -> Result<(), String> {
    let addr = addr.trim();
    if addr.is_empty() {
        return Err(format!("{label} is required"));
    }
    let Some((host, port)) = addr.rsplit_once(':') else {
        return Err(format!("invalid {label}: missing port"));
    };
    if host.trim().is_empty() || port.trim().is_empty() {
        return Err(format!("invalid {label}: missing host or port"));
    }
    if host.contains(' ') {
        return Err(format!("invalid {label}: invalid host"));
    }
    Ok(())
}

fn validate_peer_addr(addr: &str) -> Result<(), String> {
    validate_addr("peer", addr)?;
    addr.trim()
        .parse::<SocketAddr>()
        .map_err(|err| format!("invalid peer: expected literal socket address ({err})"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use serde_json::Value;

    use super::{parse_args, run, runtime_genesis_hash, validate_config};
    use rubin_node::load_genesis_config;

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
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
    fn runtime_requires_explicit_genesis_hash_for_custom_chain_id() {
        let dir = unique_temp_dir("rubin-node-bin-runtime-genesis-hash");
        fs::create_dir_all(&dir).expect("mkdir");
        let genesis_file = dir.join("genesis.json");
        fs::write(
            &genesis_file,
            "{\"chain_id_hex\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}",
        )
        .expect("write genesis");

        let genesis_cfg = load_genesis_config(Some(&genesis_file)).expect("load");
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
    fn validate_config_rejects_non_literal_peer_addr() {
        let cfg = parse_args(&[
            "--peer".to_string(),
            "bootstrap.example.org:19111".to_string(),
        ])
        .expect("parse args");
        let err = validate_config(&cfg).unwrap_err();
        assert!(
            err.starts_with("invalid peer: expected literal socket address"),
            "unexpected error: {err}"
        );
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
}
