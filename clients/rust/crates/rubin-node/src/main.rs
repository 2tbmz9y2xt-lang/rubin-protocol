use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rubin_node::{
    block_store_path, chain_state_path, default_peer_runtime_config, default_sync_config,
    load_chain_id_from_genesis_file, load_chain_state, new_devnet_rpc_state,
    start_devnet_rpc_server, BlockStore, PeerManager, SyncEngine,
};
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CliConfig {
    network: String,
    data_dir: PathBuf,
    genesis_file: Option<PathBuf>,
    rpc_bind_addr: String,
    dry_run: bool,
}

#[derive(Serialize)]
struct EffectiveConfig {
    network: String,
    data_dir: String,
    chain_id_hex: String,
    genesis_file: Option<String>,
    rpc_bind_addr: Option<String>,
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

    let chain_id = match load_chain_id_from_genesis_file(cfg.genesis_file.as_deref()) {
        Ok(chain_id) => chain_id,
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
        rpc_bind_addr: if cfg.rpc_bind_addr.trim().is_empty() {
            None
        } else {
            Some(cfg.rpc_bind_addr.clone())
        },
    };
    if serde_json::to_writer_pretty(&mut *stdout, &effective).is_err() {
        let _ = writeln!(stderr, "config encode failed");
        return 1;
    }
    let _ = writeln!(stdout);

    if cfg.dry_run {
        return 0;
    }
    if cfg.rpc_bind_addr.trim().is_empty() {
        let _ = writeln!(stdout, "rubin-node skeleton ready");
        return 0;
    }

    let state = new_devnet_rpc_state(
        Arc::new(Mutex::new(sync_engine)),
        Some(block_store),
        Arc::new(PeerManager::new(default_peer_runtime_config(
            &cfg.network,
            8,
        ))),
    );
    let server = match start_devnet_rpc_server(&cfg.rpc_bind_addr, state) {
        Ok(server) => server,
        Err(err) => {
            let _ = writeln!(stderr, "rpc start failed: {err}");
            return 2;
        }
    };
    let _ = writeln!(stdout, "rpc: listening={}", server.addr());
    let _ = writeln!(stdout, "rubin-node skeleton ready");
    let _ = stdout.flush();

    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn parse_args(args: &[String]) -> Result<CliConfig, String> {
    let mut cfg = CliConfig {
        network: "devnet".to_string(),
        data_dir: default_data_dir(),
        genesis_file: None,
        rpc_bind_addr: String::new(),
        dry_run: false,
    };

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
            "--rpc-bind" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --rpc-bind".to_string())?;
                cfg.rpc_bind_addr = value.clone();
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
        "usage: rubin-node [--network <name>] [--datadir <path>] [--genesis-file <path>] [--rpc-bind <host:port>] [--dry-run]"
    );
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use serde_json::Value;

    use super::{parse_args, run};

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
}
