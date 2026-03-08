use std::fs;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use rubin_consensus::block_hash;
use rubin_consensus::constants::POW_LIMIT;

use crate::p2p_runtime::{
    default_peer_runtime_config, perform_version_handshake, PeerSession, VersionPayloadV1,
    WireMessage,
};
use crate::{
    block_store_path, chain_state_path, default_sync_config, BlockStore, ChainState, SyncEngine,
};
use crate::{devnet_genesis_block_bytes, devnet_genesis_chain_id};

pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Server,
    Client,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Idle,
    SendPingExpectPong,
    ExpectTx { payload: Vec<u8> },
    SyncBlocks,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliConfig {
    pub mode: Mode,
    pub action: Action,
    pub bind_addr: String,
    pub connect_addr: Option<String>,
    pub best_height: u64,
}

pub fn run_cli(args: &[String]) -> Result<(), String> {
    run_cli_with_ready(args, |_| Ok(()))
}

pub fn run_cli_with_ready<F>(args: &[String], ready: F) -> Result<(), String>
where
    F: FnMut(&str) -> Result<(), String>,
{
    parse_args(args).and_then(|cfg| run_with_ready(cfg, ready))
}

pub fn parse_args(args: &[String]) -> Result<CliConfig, String> {
    let Some(mode_raw) = args.first() else {
        return Err("usage: p2p-interop-helper <server|client> [flags]".to_string());
    };
    let mode = match mode_raw.as_str() {
        "server" => Mode::Server,
        "client" => Mode::Client,
        other => return Err(format!("unknown mode: {other}")),
    };

    let mut action_name = "idle".to_string();
    let mut bind_addr = DEFAULT_BIND_ADDR.to_string();
    let mut connect_addr = None;
    let mut payload_hex = String::new();
    let mut best_height = 0u64;

    let mut idx = 1usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--action" => {
                idx += 1;
                action_name = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --action".to_string())?
                    .clone();
            }
            "--bind" => {
                idx += 1;
                bind_addr = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --bind".to_string())?
                    .clone();
            }
            "--connect" => {
                idx += 1;
                connect_addr = Some(
                    args.get(idx)
                        .ok_or_else(|| "missing value for --connect".to_string())?
                        .clone(),
                );
            }
            "--payload-hex" => {
                idx += 1;
                payload_hex = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --payload-hex".to_string())?
                    .clone();
            }
            "--best-height" => {
                idx += 1;
                let raw = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --best-height".to_string())?;
                best_height = raw
                    .parse::<u64>()
                    .map_err(|err| format!("invalid --best-height: {err}"))?;
            }
            unknown => return Err(format!("unknown flag: {unknown}")),
        }
        idx += 1;
    }

    let action = match action_name.as_str() {
        "idle" => Action::Idle,
        "send-ping-expect-pong" => Action::SendPingExpectPong,
        "expect-tx" => Action::ExpectTx {
            payload: decode_hex(&payload_hex)?,
        },
        "sync-blocks" => Action::SyncBlocks,
        other => return Err(format!("unknown action: {other}")),
    };

    if mode == Mode::Client && connect_addr.is_none() {
        return Err("--connect is required in client mode".to_string());
    }

    Ok(CliConfig {
        mode,
        action,
        bind_addr,
        connect_addr,
        best_height,
    })
}

pub fn run(cfg: CliConfig) -> Result<(), String> {
    run_with_ready(cfg, |_| Ok(()))
}

fn run_with_ready<F>(cfg: CliConfig, mut ready: F) -> Result<(), String>
where
    F: FnMut(&str) -> Result<(), String>,
{
    let local = local_version(cfg.best_height)?;
    let mut runtime_cfg = default_peer_runtime_config("devnet", 8);
    runtime_cfg.read_deadline = Duration::from_secs(3);
    runtime_cfg.write_deadline = Duration::from_secs(3);

    match cfg.mode {
        Mode::Server => {
            let listener = TcpListener::bind(&cfg.bind_addr)
                .map_err(|err| format!("bind {}: {err}", cfg.bind_addr))?;
            let addr = listener
                .local_addr()
                .map_err(|err| format!("local_addr: {err}"))?;
            ready(&addr.to_string())?;
            let (stream, _) = listener.accept().map_err(|err| format!("accept: {err}"))?;
            stream
                .set_nodelay(true)
                .map_err(|err| format!("set_nodelay: {err}"))?;
            let mut session = perform_version_handshake(
                stream,
                runtime_cfg,
                local,
                local.chain_id,
                local.genesis_hash,
            )
            .map_err(|err| format!("handshake: {err}"))?;
            run_action(&mut session, &cfg.action).map_err(|err| format!("action: {err}"))
        }
        Mode::Client => {
            let connect_addr = cfg.connect_addr.expect("checked above");
            let stream = TcpStream::connect(&connect_addr)
                .map_err(|err| format!("connect {connect_addr}: {err}"))?;
            stream
                .set_nodelay(true)
                .map_err(|err| format!("set_nodelay: {err}"))?;
            let mut session = perform_version_handshake(
                stream,
                runtime_cfg,
                local,
                local.chain_id,
                local.genesis_hash,
            )
            .map_err(|err| format!("handshake: {err}"))?;
            run_action(&mut session, &cfg.action).map_err(|err| format!("action: {err}"))
        }
    }
}

pub fn run_action(session: &mut PeerSession, action: &Action) -> io::Result<()> {
    match action {
        Action::Idle => Ok(()),
        Action::SendPingExpectPong => {
            session.write_message(&WireMessage {
                command: "ping".to_string(),
                payload: Vec::new(),
            })?;
            let reply = session.read_message()?;
            if reply.command != "pong" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected pong, got {}", reply.command),
                ));
            }
            if !reply.payload.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected empty pong payload",
                ));
            }
            Ok(())
        }
        Action::ExpectTx { payload } => {
            let msg = session.read_message()?;
            if msg.command != "tx" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected tx, got {}", msg.command),
                ));
            }
            if msg.payload != *payload {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tx payload mismatch",
                ));
            }
            Ok(())
        }
        Action::SyncBlocks => {
            let mut data_dir = unique_interop_temp_dir();
            let block_store =
                BlockStore::open(block_store_path(&data_dir)).map_err(io::Error::other)?;
            let chain_state_path = chain_state_path(&data_dir);
            let mut cfg = default_sync_config(
                Some(POW_LIMIT),
                devnet_genesis_chain_id(),
                Some(chain_state_path),
            );
            cfg.network = "devnet".to_string();
            let mut engine = SyncEngine::new(ChainState::new(), Some(block_store), cfg)
                .map_err(io::Error::other)?;
            let synced_height = session.run_block_sync_loop(&mut engine)?;
            if synced_height != session.state().remote_version.best_height {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "sync height mismatch: got {} want {}",
                        synced_height,
                        session.state().remote_version.best_height
                    ),
                ));
            }
            let _ = fs::remove_dir_all(&mut data_dir);
            Ok(())
        }
    }
}

pub fn local_version(best_height: u64) -> Result<VersionPayloadV1, String> {
    let genesis_bytes = devnet_genesis_block_bytes();
    let genesis_hash = block_hash(&genesis_bytes[..116]).map_err(|err| err.to_string())?;
    Ok(VersionPayloadV1 {
        protocol_version: 1,
        tx_relay: true,
        pruned_below_height: 0,
        da_mempool_size: 0,
        chain_id: devnet_genesis_chain_id(),
        genesis_hash,
        best_height,
    })
}

pub fn decode_hex(raw: &str) -> Result<Vec<u8>, String> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(raw).map_err(|err| format!("invalid hex: {err}"))
}

fn unique_interop_temp_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "rubin-rust-p2p-interop-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::TcpListener;
    use std::thread;

    use rubin_consensus::{block_hash, BLOCK_HEADER_BYTES};

    use super::*;
    use crate::p2p_runtime::{decode_inventory_vectors, encode_inventory_vectors, MSG_BLOCK};

    #[test]
    fn parse_args_server_defaults() {
        let args = vec!["server".to_string()];
        let cfg = parse_args(&args).expect("parse");
        assert_eq!(cfg.mode, Mode::Server);
        assert_eq!(cfg.action, Action::Idle);
        assert_eq!(cfg.bind_addr, DEFAULT_BIND_ADDR);
        assert_eq!(cfg.connect_addr, None);
        assert_eq!(cfg.best_height, 0);
    }

    #[test]
    fn parse_args_client_expect_tx() {
        let args = vec![
            "client".to_string(),
            "--connect".to_string(),
            "127.0.0.1:9000".to_string(),
            "--action".to_string(),
            "expect-tx".to_string(),
            "--payload-hex".to_string(),
            "c0ffee".to_string(),
            "--best-height".to_string(),
            "42".to_string(),
        ];
        let cfg = parse_args(&args).expect("parse");
        assert_eq!(cfg.mode, Mode::Client);
        assert_eq!(cfg.connect_addr.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(
            cfg.action,
            Action::ExpectTx {
                payload: vec![0xc0, 0xff, 0xee]
            }
        );
        assert_eq!(cfg.best_height, 42);
    }

    #[test]
    fn parse_args_client_sync_blocks() {
        let args = vec![
            "client".to_string(),
            "--connect".to_string(),
            "127.0.0.1:9000".to_string(),
            "--action".to_string(),
            "sync-blocks".to_string(),
        ];
        let cfg = parse_args(&args).expect("parse");
        assert_eq!(cfg.mode, Mode::Client);
        assert_eq!(cfg.connect_addr.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(cfg.action, Action::SyncBlocks);
    }

    #[test]
    fn parse_args_requires_connect_for_client() {
        let args = vec!["client".to_string()];
        let err = parse_args(&args).unwrap_err();
        assert_eq!(err, "--connect is required in client mode");
    }

    #[test]
    fn parse_args_rejects_unknown_mode_and_flag() {
        let err = parse_args(&["peer".to_string()]).unwrap_err();
        assert_eq!(err, "unknown mode: peer");

        let err = parse_args(&["server".to_string(), "--bogus".to_string()]).unwrap_err();
        assert_eq!(err, "unknown flag: --bogus");
    }

    #[test]
    fn parse_args_rejects_missing_flag_values_and_unknown_action() {
        let err = parse_args(&["server".to_string(), "--bind".to_string()]).unwrap_err();
        assert_eq!(err, "missing value for --bind");

        let err = parse_args(&["server".to_string(), "--action".to_string()]).unwrap_err();
        assert_eq!(err, "missing value for --action");

        let err = parse_args(&[
            "server".to_string(),
            "--best-height".to_string(),
            "nope".to_string(),
        ])
        .unwrap_err();
        assert!(err.starts_with("invalid --best-height:"));

        let err = parse_args(&[
            "server".to_string(),
            "--action".to_string(),
            "mystery".to_string(),
        ])
        .unwrap_err();
        assert_eq!(err, "unknown action: mystery");
    }

    #[test]
    fn parse_args_rejects_invalid_payload_hex() {
        let args = vec![
            "client".to_string(),
            "--connect".to_string(),
            "127.0.0.1:9000".to_string(),
            "--action".to_string(),
            "expect-tx".to_string(),
            "--payload-hex".to_string(),
            "xyz".to_string(),
        ];
        let err = parse_args(&args).unwrap_err();
        assert!(err.starts_with("invalid hex:"));
    }

    #[test]
    fn local_version_matches_devnet() {
        let local = local_version(7).expect("local version");
        assert_eq!(local.protocol_version, 1);
        assert!(local.tx_relay);
        assert_eq!(local.pruned_below_height, 0);
        assert_eq!(local.da_mempool_size, 0);
        assert_eq!(local.chain_id, devnet_genesis_chain_id());
        assert_eq!(local.best_height, 7);
    }

    #[test]
    fn run_action_send_ping_expect_pong_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = local_version(0).expect("local");
            let mut session =
                perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                    .expect("handshake");
            run_action(&mut session, &Action::SendPingExpectPong).expect("ping/pong");
        });

        let client = thread::spawn(move || {
            let stream = TcpStream::connect(addr).expect("connect");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = local_version(0).expect("local");
            let mut session =
                perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                    .expect("handshake");
            let msg = session.read_message().expect("read ping");
            assert_eq!(msg.command, "ping");
            assert!(msg.payload.is_empty());
            session
                .write_message(&WireMessage {
                    command: "pong".to_string(),
                    payload: Vec::new(),
                })
                .expect("write pong");
        });

        server.join().expect("server");
        client.join().expect("client");
    }

    #[test]
    fn run_action_expect_tx_accepts_expected_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let payload = vec![1u8, 2, 3, 4];
        let expected = payload.clone();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = local_version(0).expect("local");
            let mut session =
                perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                    .expect("handshake");
            run_action(&mut session, &Action::ExpectTx { payload: expected }).expect("tx");
        });

        let client = thread::spawn(move || {
            let stream = TcpStream::connect(addr).expect("connect");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = local_version(0).expect("local");
            let mut session =
                perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                    .expect("handshake");
            session
                .write_message(&WireMessage {
                    command: "tx".to_string(),
                    payload,
                })
                .expect("write tx");
        });

        server.join().expect("server");
        client.join().expect("client");
    }

    #[test]
    fn run_action_rejects_wrong_reply_shapes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = local_version(0).expect("local");
            let mut session =
                perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                    .expect("handshake");
            let err = run_action(&mut session, &Action::SendPingExpectPong).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "expected pong, got tx");
        });

        let client = thread::spawn(move || {
            let stream = TcpStream::connect(addr).expect("connect");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = local_version(0).expect("local");
            let mut session =
                perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                    .expect("handshake");
            let msg = session.read_message().expect("read ping");
            assert_eq!(msg.command, "ping");
            session
                .write_message(&WireMessage {
                    command: "tx".to_string(),
                    payload: vec![1],
                })
                .expect("write tx");
        });

        server.join().expect("server");
        client.join().expect("client");
    }

    #[test]
    fn run_action_rejects_non_empty_pong_and_payload_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = local_version(0).expect("local");
            let mut session =
                perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                    .expect("handshake");
            let err = run_action(&mut session, &Action::SendPingExpectPong).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "message exceeds command cap");
        });

        let client = thread::spawn(move || {
            let stream = TcpStream::connect(addr).expect("connect");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = local_version(0).expect("local");
            let mut session =
                perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                    .expect("handshake");
            let msg = session.read_message().expect("read ping");
            assert_eq!(msg.command, "ping");
            session
                .write_message(&WireMessage {
                    command: "pong".to_string(),
                    payload: vec![1],
                })
                .expect("write pong");
        });

        server.join().expect("server");
        client.join().expect("client");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = local_version(0).expect("local");
            let mut session =
                perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                    .expect("handshake");
            let err = run_action(
                &mut session,
                &Action::ExpectTx {
                    payload: vec![1, 2],
                },
            )
            .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "tx payload mismatch");
        });

        let client = thread::spawn(move || {
            let stream = TcpStream::connect(addr).expect("connect");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = local_version(0).expect("local");
            let mut session =
                perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                    .expect("handshake");
            session
                .write_message(&WireMessage {
                    command: "tx".to_string(),
                    payload: vec![9, 9],
                })
                .expect("write tx");
        });

        server.join().expect("server");
        client.join().expect("client");
    }

    #[test]
    fn run_server_and_client_modes_complete_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = local_version(0).expect("local");
            perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                .expect("handshake");
        });

        run(CliConfig {
            mode: Mode::Client,
            action: Action::Idle,
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            connect_addr: Some(addr.to_string()),
            best_height: 0,
        })
        .expect("client run");
        server.join().expect("server");

        let ready_addr = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let ready_addr_server = ready_addr.clone();
        let server = thread::spawn(move || {
            run_cli_with_ready(
                &[
                    "server".to_string(),
                    "--action".to_string(),
                    "idle".to_string(),
                ],
                move |addr| {
                    *ready_addr_server.lock().expect("ready lock") = Some(addr.to_string());
                    Ok(())
                },
            )
            .expect("server run");
        });

        let connect_addr = loop {
            if let Some(addr) = ready_addr.lock().expect("ready lock").clone() {
                break addr;
            }
            thread::sleep(Duration::from_millis(10));
        };

        let stream = TcpStream::connect(connect_addr).expect("connect");
        stream.set_nodelay(true).expect("set_nodelay");
        let mut cfg = default_peer_runtime_config("devnet", 8);
        cfg.read_deadline = Duration::from_secs(2);
        cfg.write_deadline = Duration::from_secs(2);
        let local = local_version(0).expect("local");
        perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
            .expect("handshake");

        server.join().expect("server");
    }

    #[test]
    fn run_action_sync_blocks_reaches_remote_best_height() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let server_dir = unique_interop_temp_dir();
            let result = (|| -> Result<(), String> {
                let block = devnet_genesis_block_bytes();
                let block_hash_bytes =
                    block_hash(&block[..BLOCK_HEADER_BYTES]).map_err(|err| err.to_string())?;
                let mut store = BlockStore::open(block_store_path(&server_dir))?;
                store.put_block(0, block_hash_bytes, &block[..BLOCK_HEADER_BYTES], &block)?;

                let mut cfg = default_sync_config(Some(POW_LIMIT), devnet_genesis_chain_id(), None);
                cfg.network = "devnet".to_string();
                let engine = SyncEngine::new(ChainState::new(), Some(store), cfg)?;

                let (stream, _) = listener.accept().map_err(|err| err.to_string())?;
                stream.set_nodelay(true).map_err(|err| err.to_string())?;
                let mut runtime_cfg = default_peer_runtime_config("devnet", 8);
                runtime_cfg.read_deadline = Duration::from_secs(2);
                runtime_cfg.write_deadline = Duration::from_secs(2);
                let local = local_version(0)?;
                let mut session = perform_version_handshake(
                    stream,
                    runtime_cfg,
                    local,
                    local.chain_id,
                    local.genesis_hash,
                )
                .map_err(|err| err.to_string())?;

                let getblocks = session.read_message().map_err(|err| err.to_string())?;
                assert_eq!(getblocks.command, "getblocks");
                let inv = session
                    .handle_getblocks(&getblocks.payload, &engine)
                    .map_err(|err| err.to_string())?;
                session
                    .write_message(&WireMessage {
                        command: "inv".to_string(),
                        payload: encode_inventory_vectors(&inv).map_err(|err| err.to_string())?,
                    })
                    .map_err(|err| err.to_string())?;

                let getdata = session.read_message().map_err(|err| err.to_string())?;
                assert_eq!(getdata.command, "getdata");
                for item in
                    decode_inventory_vectors(&getdata.payload).map_err(|err| err.to_string())?
                {
                    assert_eq!(item.kind, MSG_BLOCK);
                    let block = engine.get_block_by_hash(item.hash)?;
                    session
                        .write_message(&WireMessage {
                            command: "block".to_string(),
                            payload: block,
                        })
                        .map_err(|err| err.to_string())?;
                }
                Ok(())
            })();
            let _ = fs::remove_dir_all(&server_dir);
            result
        });

        let client = thread::spawn(move || {
            let stream = TcpStream::connect(addr).expect("connect");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut runtime_cfg = default_peer_runtime_config("devnet", 8);
            runtime_cfg.read_deadline = Duration::from_secs(2);
            runtime_cfg.write_deadline = Duration::from_secs(2);
            let local = local_version(0).expect("local");
            let mut session = perform_version_handshake(
                stream,
                runtime_cfg,
                local,
                local.chain_id,
                local.genesis_hash,
            )
            .expect("handshake");
            run_action(&mut session, &Action::SyncBlocks).expect("sync blocks");
        });

        server.join().expect("server").expect("server result");
        client.join().expect("client");
    }
}
