use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::RwLock;
use std::time::Duration;

use rubin_consensus::constants::MAX_RELAY_MSG_BYTES;
use sha3::{Digest, Sha3_256};

const DEFAULT_READ_DEADLINE: Duration = Duration::from_secs(15);
const DEFAULT_WRITE_DEADLINE: Duration = Duration::from_secs(15);
const DEFAULT_BAN_THRESHOLD: i32 = 100;
const WIRE_HEADER_SIZE: usize = 24;
const WIRE_COMMAND_SIZE: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireMessage {
    pub command: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct VersionPayloadV1 {
    pub protocol_version: u32,
    pub tx_relay: bool,
    pub pruned_below_height: u64,
    pub da_mempool_size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRuntimeConfig {
    pub network: String,
    pub max_peers: usize,
    pub read_deadline: Duration,
    pub write_deadline: Duration,
    pub ban_threshold: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PeerState {
    pub addr: String,
    pub last_error: String,
    pub remote_version: VersionPayloadV1,
    pub ban_score: i32,
    pub handshake_complete: bool,
    pub version_received: bool,
    pub verack_received: bool,
}

pub struct PeerSession {
    stream: TcpStream,
    cfg: PeerRuntimeConfig,
    peer: PeerState,
}

pub struct PeerManager {
    peers: RwLock<HashMap<String, PeerState>>,
    cfg: PeerRuntimeConfig,
}

pub fn default_peer_runtime_config(network: &str, max_peers: usize) -> PeerRuntimeConfig {
    let max_peers = if max_peers == 0 { 64 } else { max_peers };
    PeerRuntimeConfig {
        network: network.to_string(),
        max_peers,
        read_deadline: DEFAULT_READ_DEADLINE,
        write_deadline: DEFAULT_WRITE_DEADLINE,
        ban_threshold: DEFAULT_BAN_THRESHOLD,
    }
}

impl PeerManager {
    pub fn new(cfg: PeerRuntimeConfig) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            cfg: normalize_peer_runtime_config(cfg),
        }
    }

    pub fn add_peer(&self, state: PeerState) -> Result<(), String> {
        let cfg = &self.cfg;
        let mut peers = self
            .peers
            .write()
            .map_err(|_| "peer manager lock poisoned".to_string())?;
        if peers.len() >= cfg.max_peers {
            return Err("max peers reached".to_string());
        }
        peers.insert(state.addr.clone(), state);
        Ok(())
    }

    pub fn remove_peer(&self, addr: &str) {
        let Ok(mut peers) = self.peers.write() else {
            return;
        };
        peers.remove(addr);
    }

    pub fn snapshot(&self) -> Vec<PeerState> {
        let Ok(peers) = self.peers.read() else {
            return Vec::new();
        };
        peers.values().cloned().collect()
    }
}

impl PeerSession {
    fn new(stream: TcpStream, cfg: PeerRuntimeConfig) -> Result<Self, String> {
        let addr = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        Ok(Self {
            stream,
            cfg: normalize_peer_runtime_config(cfg),
            peer: PeerState {
                addr,
                ..PeerState::default()
            },
        })
    }

    pub fn state(&self) -> PeerState {
        self.peer.clone()
    }

    pub fn read_message(&mut self) -> Result<WireMessage, String> {
        self.stream
            .set_read_timeout(Some(self.cfg.read_deadline))
            .map_err(|e| e.to_string())?;

        let mut header = [0u8; WIRE_HEADER_SIZE];
        self.stream.read_exact(&mut header).map_err(|e| e.to_string())?;

        let expected_magic = network_magic(&self.cfg.network);
        if header[0..4] != expected_magic {
            return Err("invalid envelope magic".to_string());
        }

        let command = decode_wire_command(&header[4..4 + WIRE_COMMAND_SIZE])?;
        let payload_len = u32::from_le_bytes(header[16..20].try_into().expect("len"));
        if payload_len as u64 > MAX_RELAY_MSG_BYTES {
            return Err(format!("relay payload exceeds cap: {payload_len}"));
        }

        let mut payload = vec![0u8; payload_len as usize];
        if payload_len > 0 {
            self.stream
                .read_exact(&mut payload)
                .map_err(|e| e.to_string())?;
        }

        let checksum = wire_checksum(&payload);
        if header[20..24] != checksum {
            return Err("invalid envelope checksum".to_string());
        }

        Ok(WireMessage { command, payload })
    }

    pub fn write_message(&mut self, msg: &WireMessage) -> Result<(), String> {
        self.stream
            .set_write_timeout(Some(self.cfg.write_deadline))
            .map_err(|e| e.to_string())?;

        if msg.payload.len() as u64 > MAX_RELAY_MSG_BYTES {
            return Err(format!("relay payload exceeds cap: {}", msg.payload.len()));
        }

        let header = build_envelope_header(network_magic(&self.cfg.network), &msg.command, &msg.payload)?;
        self.stream.write_all(&header).map_err(|e| e.to_string())?;
        if !msg.payload.is_empty() {
            self.stream
                .write_all(&msg.payload)
                .map_err(|e| e.to_string())?;
        }
        self.stream.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    fn bump_ban(&mut self, delta: i32, reason: &str) {
        self.peer.ban_score = self.peer.ban_score.saturating_add(delta);
        self.peer.last_error = reason.to_string();
    }

    pub fn run_message_loop(&mut self) -> Result<(), String> {
        loop {
            let msg = match self.read_message() {
                Ok(m) => m,
                Err(e) => return Err(e),
            };
            match msg.command.as_str() {
                "ping" => {
                    let pong = WireMessage {
                        command: "pong".to_string(),
                        payload: Vec::new(),
                    };
                    self.write_message(&pong)?;
                }
                "tx" | "block" | "headers" => {
                    // accepted runtime commands (stub)
                }
                other => {
                    self.bump_ban(1, &format!("unknown command: {other}"));
                    if self.peer.ban_score >= self.cfg.ban_threshold {
                        return Err("peer banned".to_string());
                    }
                }
            }
        }
    }
}

pub fn perform_version_handshake(
    stream: TcpStream,
    cfg: PeerRuntimeConfig,
    local: VersionPayloadV1,
) -> Result<PeerState, String> {
    let mut session = PeerSession::new(stream, cfg)?;
    let version_payload = marshal_version_payload_v1(local);
    session.write_message(&WireMessage {
        command: "version".to_string(),
        payload: version_payload,
    })?;

    let mut sent_verack = false;
    loop {
        let msg = session.read_message()?;
        match msg.command.as_str() {
            "version" => {
                let remote = unmarshal_version_payload_v1(&msg.payload)?;
                validate_remote_version(remote)?;
                if !protocol_versions_compatible(local.protocol_version, remote.protocol_version) {
                    return Err(format!(
                        "protocol_version mismatch: local={} remote={}",
                        local.protocol_version, remote.protocol_version
                    ));
                }

                session.peer.version_received = true;
                session.peer.remote_version = remote;
                if !sent_verack {
                    session.write_message(&WireMessage {
                        command: "verack".to_string(),
                        payload: Vec::new(),
                    })?;
                    sent_verack = true;
                }
            }
            "verack" => {
                session.peer.verack_received = true;
            }
            other => {
                session.bump_ban(1, &format!("unexpected handshake command: {other}"));
                if session.peer.ban_score >= session.cfg.ban_threshold {
                    return Err("peer banned".to_string());
                }
            }
        }

        if session.peer.version_received && session.peer.verack_received {
            session.peer.handshake_complete = true;
            return Ok(session.peer);
        }
    }
}

fn validate_remote_version(remote: VersionPayloadV1) -> Result<(), String> {
    if remote.protocol_version == 0 {
        return Err("invalid protocol_version".to_string());
    }
    Ok(())
}

fn protocol_versions_compatible(local: u32, remote: u32) -> bool {
    if local == remote {
        return true;
    }
    if local > remote {
        return local - remote <= 1;
    }
    remote - local <= 1
}

fn marshal_version_payload_v1(v: VersionPayloadV1) -> Vec<u8> {
    let mut payload = vec![0u8; 17];
    payload[0..4].copy_from_slice(&v.protocol_version.to_le_bytes());
    payload[4] = if v.tx_relay { 1 } else { 0 };
    payload[5..13].copy_from_slice(&v.pruned_below_height.to_le_bytes());
    payload[13..17].copy_from_slice(&v.da_mempool_size.to_le_bytes());
    payload
}

fn unmarshal_version_payload_v1(payload: &[u8]) -> Result<VersionPayloadV1, String> {
    if payload.len() < 13 {
        return Err("version payload too short".to_string());
    }
    let protocol_version = u32::from_le_bytes(payload[0..4].try_into().expect("pv"));
    let tx_relay = payload[4] == 1;
    let pruned_below_height = u64::from_le_bytes(payload[5..13].try_into().expect("pruned"));

    if payload.len() < 17 {
        return Ok(VersionPayloadV1 {
            protocol_version,
            tx_relay,
            pruned_below_height,
            da_mempool_size: 0,
        });
    }
    let da_mempool_size = u32::from_le_bytes(payload[13..17].try_into().expect("da"));
    Ok(VersionPayloadV1 {
        protocol_version,
        tx_relay,
        pruned_below_height,
        da_mempool_size,
    })
}

fn build_envelope_header(magic: [u8; 4], command: &str, payload: &[u8]) -> Result<[u8; WIRE_HEADER_SIZE], String> {
    let command_bytes = encode_wire_command(command)?;
    let mut header = [0u8; WIRE_HEADER_SIZE];
    header[0..4].copy_from_slice(&magic);
    header[4..16].copy_from_slice(&command_bytes);
    let len = u32::try_from(payload.len()).map_err(|_| "payload length overflow".to_string())?;
    header[16..20].copy_from_slice(&len.to_le_bytes());
    let sum = wire_checksum(payload);
    header[20..24].copy_from_slice(&sum);
    Ok(header)
}

fn wire_checksum(payload: &[u8]) -> [u8; 4] {
    let mut h = Sha3_256::new();
    h.update(payload);
    let out = h.finalize();
    [out[0], out[1], out[2], out[3]]
}

fn encode_wire_command(command: &str) -> Result<[u8; WIRE_COMMAND_SIZE], String> {
    let bytes = command.as_bytes();
    if bytes.is_empty() || bytes.len() > WIRE_COMMAND_SIZE {
        return Err("invalid command length".to_string());
    }
    for &ch in bytes {
        if !is_printable_ascii_byte(ch) {
            return Err("command is not ASCII printable".to_string());
        }
    }
    let mut out = [0u8; WIRE_COMMAND_SIZE];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

fn decode_wire_command(raw: &[u8]) -> Result<String, String> {
    if raw.len() != WIRE_COMMAND_SIZE {
        return Err("invalid command width".to_string());
    }
    let mut end = WIRE_COMMAND_SIZE;
    for (i, &b) in raw.iter().enumerate() {
        if b == 0 {
            end = i;
            break;
        }
    }
    if end == 0 {
        return Err("empty command".to_string());
    }
    for &b in &raw[end..] {
        if b != 0 {
            return Err("invalid NUL padding in command".to_string());
        }
    }
    for &b in &raw[..end] {
        if !is_printable_ascii_byte(b) {
            return Err("command is not ASCII printable".to_string());
        }
    }
    let s = std::str::from_utf8(&raw[..end]).map_err(|_| "invalid command".to_string())?;
    Ok(s.to_string())
}

fn is_printable_ascii_byte(ch: u8) -> bool {
    ch >= 0x21 && ch <= 0x7e
}

fn normalize_peer_runtime_config(mut cfg: PeerRuntimeConfig) -> PeerRuntimeConfig {
    if cfg.max_peers == 0 {
        cfg.max_peers = 64;
    }
    if cfg.read_deadline == Duration::from_secs(0) {
        cfg.read_deadline = DEFAULT_READ_DEADLINE;
    }
    if cfg.write_deadline == Duration::from_secs(0) {
        cfg.write_deadline = DEFAULT_WRITE_DEADLINE;
    }
    if cfg.ban_threshold <= 0 {
        cfg.ban_threshold = DEFAULT_BAN_THRESHOLD;
    }
    cfg
}

fn network_magic(network: &str) -> [u8; 4] {
    match network {
        "mainnet" => *b"RBMN",
        "testnet" => *b"RBTN",
        "devnet" | "" => *b"RBDV",
        _ => *b"RBOP",
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use super::*;

    #[test]
    fn p2p_version_handshake_bidirectional_ok() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream
                .set_nodelay(true)
                .expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = VersionPayloadV1 {
                protocol_version: 1,
                tx_relay: true,
                pruned_below_height: 0,
                da_mempool_size: 0,
            };
            perform_version_handshake(stream, cfg, local).expect("server handshake")
        });

        let client = thread::spawn(move || {
            let stream = TcpStream::connect(addr).expect("connect");
            stream
                .set_nodelay(true)
                .expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = VersionPayloadV1 {
                protocol_version: 1,
                tx_relay: true,
                pruned_below_height: 0,
                da_mempool_size: 0,
            };
            perform_version_handshake(stream, cfg, local).expect("client handshake")
        });

        let a = server.join().expect("server join");
        let b = client.join().expect("client join");
        assert!(a.handshake_complete);
        assert!(b.handshake_complete);
        assert_eq!(a.remote_version.protocol_version, 1);
        assert_eq!(b.remote_version.protocol_version, 1);
    }

    #[test]
    fn p2p_invalid_magic_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let mut session = PeerSession::new(stream.try_clone().expect("clone"), cfg).expect("session");
            let err = session.read_message().unwrap_err();
            assert_eq!(err, "invalid envelope magic");
        });

        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream
                .set_nodelay(true)
                .expect("set_nodelay");
            let payload = marshal_version_payload_v1(VersionPayloadV1 {
                protocol_version: 1,
                tx_relay: true,
                pruned_below_height: 0,
                da_mempool_size: 0,
            });
            let header = build_envelope_header(network_magic("mainnet"), "version", &payload).expect("header");
            stream.write_all(&header).expect("write header");
            stream.write_all(&payload).expect("write payload");
            stream.flush().expect("flush");
        });

        client.join().expect("client join");
        server.join().expect("server join");
    }
}
