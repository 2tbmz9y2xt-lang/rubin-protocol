use std::env;
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::process;
use std::time::Duration;

use rubin_consensus::block_hash;
use rubin_node::p2p_runtime::{
    default_peer_runtime_config, perform_version_handshake, PeerSession, VersionPayloadV1,
    WireMessage,
};
use rubin_node::{devnet_genesis_block_bytes, devnet_genesis_chain_id};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:0";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Mode {
    Server,
    Client,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Action {
    Idle,
    SendPingExpectPong,
    ExpectTx { payload: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CliConfig {
    mode: Mode,
    action: Action,
    bind_addr: String,
    connect_addr: Option<String>,
    network: String,
    best_height: u64,
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let exit_code = match parse_args(&args).and_then(run) {
        Ok(()) => 0,
        Err(err) => {
            let _ = writeln!(io::stderr(), "{err}");
            1
        }
    };
    process::exit(exit_code);
}

fn parse_args(args: &[String]) -> Result<CliConfig, String> {
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
    let mut network = "devnet".to_string();
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
            "--network" => {
                idx += 1;
                network = args
                    .get(idx)
                    .ok_or_else(|| "missing value for --network".to_string())?
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
        network,
        best_height,
    })
}

fn run(cfg: CliConfig) -> Result<(), String> {
    let local = local_version(cfg.best_height)?;
    let mut runtime_cfg = default_peer_runtime_config(&cfg.network, 8);
    runtime_cfg.read_deadline = Duration::from_secs(3);
    runtime_cfg.write_deadline = Duration::from_secs(3);

    match cfg.mode {
        Mode::Server => {
            let listener = TcpListener::bind(&cfg.bind_addr)
                .map_err(|err| format!("bind {}: {err}", cfg.bind_addr))?;
            let addr = listener
                .local_addr()
                .map_err(|err| format!("local_addr: {err}"))?;
            println!("READY {addr}");
            io::stdout().flush().map_err(|err| err.to_string())?;
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

fn run_action(session: &mut PeerSession, action: &Action) -> io::Result<()> {
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
    }
}

fn local_version(best_height: u64) -> Result<VersionPayloadV1, String> {
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

fn decode_hex(raw: &str) -> Result<Vec<u8>, String> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(raw).map_err(|err| format!("invalid hex: {err}"))
}
