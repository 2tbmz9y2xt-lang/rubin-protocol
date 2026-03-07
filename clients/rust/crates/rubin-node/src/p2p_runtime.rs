use std::collections::HashMap;
use std::io::{self, Read, Write};
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
    pub chain_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub best_height: u64,
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

    pub fn read_message(&mut self) -> io::Result<WireMessage> {
        self.stream
            .set_read_timeout(Some(self.cfg.read_deadline))
            .map_err(io::Error::other)?;

        let mut header = [0u8; WIRE_HEADER_SIZE];
        self.stream.read_exact(&mut header)?;
        let envelope = parse_envelope_header(&header, network_magic(&self.cfg.network), MAX_RELAY_MSG_BYTES)?;
        let mut payload = vec![0u8; envelope.payload_len];
        let checksum = envelope.checksum;
        if envelope.payload_len > 0 {
            self.stream.read_exact(&mut payload)?;
        }
        let actual_checksum = wire_checksum(&payload);
        if checksum != actual_checksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid envelope checksum",
            ));
        }
        Ok(WireMessage {
            command: envelope.command,
            payload,
        })
    }

    pub fn write_message(&mut self, msg: &WireMessage) -> io::Result<()> {
        self.stream
            .set_write_timeout(Some(self.cfg.write_deadline))
            .map_err(io::Error::other)?;
        let raw = marshal_wire_message(msg, network_magic(&self.cfg.network), MAX_RELAY_MSG_BYTES)?;
        self.stream.write_all(&raw)?;
        self.stream.flush()?;
        Ok(())
    }

    fn bump_ban(&mut self, delta: i32, reason: &str) {
        self.peer.ban_score = self.peer.ban_score.saturating_add(delta);
        self.peer.last_error = reason.to_string();
    }

    pub fn run_message_loop(&mut self) -> io::Result<()> {
        loop {
            let msg = match self.read_message() {
                Ok(m) => m,
                Err(err) => {
                    if matches!(
                        err.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) {
                        continue;
                    }
                    if err.kind() == io::ErrorKind::UnexpectedEof {
                        return Ok(());
                    }
                    return Err(err);
                }
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
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "peer banned",
                        ));
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
    expected_chain_id: [u8; 32],
    expected_genesis_hash: [u8; 32],
) -> io::Result<PeerSession> {
    let mut session = PeerSession::new(stream, cfg).map_err(io::Error::other)?;
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
                validate_remote_version(
                    remote,
                    local.protocol_version,
                    expected_chain_id,
                    expected_genesis_hash,
                )?;
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
            _other => {
                session.bump_ban(10, "unexpected pre-handshake command");
                if session.peer.ban_score >= session.cfg.ban_threshold {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "peer banned during handshake",
                    ));
                }
            }
        }

        let completed =
            session.peer.version_received && session.peer.verack_received && sent_verack;
        if completed {
            session.peer.handshake_complete = true;
            return Ok(session);
        }
    }
}

fn validate_remote_version(
    remote: VersionPayloadV1,
    local_protocol_version: u32,
    expected_chain_id: [u8; 32],
    expected_genesis_hash: [u8; 32],
) -> io::Result<()> {
    if remote.protocol_version == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid protocol_version",
        ));
    }
    if !protocol_versions_compatible(local_protocol_version, remote.protocol_version) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "protocol_version mismatch: local={} remote={}",
                local_protocol_version, remote.protocol_version
            ),
        ));
    }
    if remote.chain_id != expected_chain_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chain_id mismatch",
        ));
    }
    if remote.genesis_hash != expected_genesis_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "genesis_hash mismatch",
        ));
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
    let mut payload = vec![0u8; 89];
    payload[0..4].copy_from_slice(&v.protocol_version.to_le_bytes());
    payload[4] = if v.tx_relay { 1 } else { 0 };
    payload[5..13].copy_from_slice(&v.pruned_below_height.to_le_bytes());
    payload[13..17].copy_from_slice(&v.da_mempool_size.to_le_bytes());
    payload[17..49].copy_from_slice(&v.chain_id);
    payload[49..81].copy_from_slice(&v.genesis_hash);
    payload[81..89].copy_from_slice(&v.best_height.to_le_bytes());
    payload
}

fn unmarshal_version_payload_v1(payload: &[u8]) -> io::Result<VersionPayloadV1> {
    if payload.len() != 89 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            if payload.len() < 89 {
                "version payload too short"
            } else {
                "trailing bytes in version payload"
            },
        ));
    }
    let protocol_version = u32::from_le_bytes(payload[0..4].try_into().expect("pv"));
    let tx_relay = payload[4] == 1;
    let pruned_below_height = u64::from_le_bytes(payload[5..13].try_into().expect("pruned"));
    let da_mempool_size = u32::from_le_bytes(payload[13..17].try_into().expect("da"));
    let mut chain_id = [0u8; 32];
    chain_id.copy_from_slice(&payload[17..49]);
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&payload[49..81]);
    let best_height = u64::from_le_bytes(payload[81..89].try_into().expect("best_height"));
    Ok(VersionPayloadV1 {
        protocol_version,
        tx_relay,
        pruned_below_height,
        da_mempool_size,
        chain_id,
        genesis_hash,
        best_height,
    })
}

fn build_envelope_header(
    magic: [u8; 4],
    command: &str,
    payload: &[u8],
) -> io::Result<[u8; WIRE_HEADER_SIZE]> {
    let command_bytes = encode_wire_command(command)?;
    let mut header = [0u8; WIRE_HEADER_SIZE];
    header[0..4].copy_from_slice(&magic);
    header[4..16].copy_from_slice(&command_bytes);
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "payload length overflow"))?;
    header[16..20].copy_from_slice(&len.to_le_bytes());
    let sum = wire_checksum(payload);
    header[20..24].copy_from_slice(&sum);
    Ok(header)
}

fn marshal_wire_message(
    msg: &WireMessage,
    magic: [u8; 4],
    max_message_size: u64,
) -> io::Result<Vec<u8>> {
    if msg.payload.len() as u64 > max_message_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message exceeds cap: {}", msg.payload.len()),
        ));
    }
    let header = build_envelope_header(magic, &msg.command, &msg.payload)?;
    let mut raw = Vec::with_capacity(WIRE_HEADER_SIZE + msg.payload.len());
    raw.extend_from_slice(&header);
    raw.extend_from_slice(&msg.payload);
    Ok(raw)
}

#[cfg(test)]
fn unmarshal_wire_message(
    raw: &[u8],
    expected_magic: [u8; 4],
    max_message_size: u64,
) -> io::Result<WireMessage> {
    if raw.len() < WIRE_HEADER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short envelope header",
        ));
    }
    let header = raw[..WIRE_HEADER_SIZE].try_into().expect("wire header");
    let envelope = parse_envelope_header(&header, expected_magic, max_message_size)?;
    let total_len = WIRE_HEADER_SIZE + envelope.payload_len;
    if raw.len() < total_len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short envelope payload",
        ));
    }
    let payload = raw[WIRE_HEADER_SIZE..total_len].to_vec();
    let checksum = wire_checksum(&payload);
    if envelope.checksum != checksum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid envelope checksum",
        ));
    }
    Ok(WireMessage {
        command: envelope.command,
        payload,
    })
}

struct ParsedEnvelopeHeader {
    command: String,
    payload_len: usize,
    checksum: [u8; 4],
}

fn parse_envelope_header(
    header: &[u8; WIRE_HEADER_SIZE],
    expected_magic: [u8; 4],
    max_message_size: u64,
) -> io::Result<ParsedEnvelopeHeader> {
    if header[0..4] != expected_magic {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid envelope magic",
        ));
    }
    let command = decode_wire_command(&header[4..4 + WIRE_COMMAND_SIZE])?;
    let payload_len = u32::from_le_bytes(header[16..20].try_into().expect("len"));
    if payload_len as u64 > max_message_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message exceeds cap",
        ));
    }
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&header[20..24]);
    Ok(ParsedEnvelopeHeader {
        command,
        payload_len: payload_len as usize,
        checksum,
    })
}

fn wire_checksum(payload: &[u8]) -> [u8; 4] {
    let mut h = Sha3_256::new();
    h.update(payload);
    let out = h.finalize();
    [out[0], out[1], out[2], out[3]]
}

fn encode_wire_command(command: &str) -> io::Result<[u8; WIRE_COMMAND_SIZE]> {
    let bytes = command.as_bytes();
    if bytes.is_empty() || bytes.len() > WIRE_COMMAND_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid command length",
        ));
    }
    for &ch in bytes {
        if !is_printable_ascii_byte(ch) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "command is not ASCII printable",
            ));
        }
    }
    let mut out = [0u8; WIRE_COMMAND_SIZE];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

fn decode_wire_command(raw: &[u8]) -> io::Result<String> {
    if raw.len() != WIRE_COMMAND_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid command width",
        ));
    }
    let mut end = WIRE_COMMAND_SIZE;
    for (i, &b) in raw.iter().enumerate() {
        if b == 0 {
            end = i;
            break;
        }
    }
    if end == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty command"));
    }
    for &b in &raw[end..] {
        if b != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid NUL padding in command",
            ));
        }
    }
    for &b in &raw[..end] {
        if !is_printable_ascii_byte(b) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "command is not ASCII printable",
            ));
        }
    }
    let s = std::str::from_utf8(&raw[..end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid command"))?;
    Ok(s.to_string())
}

fn is_printable_ascii_byte(ch: u8) -> bool {
    (0x21..=0x7e).contains(&ch)
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
    use std::fs;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::genesis::{devnet_genesis_block_bytes, devnet_genesis_chain_id};
    use rubin_consensus::block_hash;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct SharedRuntimeVectors {
        version_payload_v1: SharedVersionPayloadV1,
        frames: Vec<SharedFrameVector>,
        version_validation: Vec<SharedVersionValidation>,
    }

    #[derive(Deserialize)]
    struct SharedVersionPayloadV1 {
        hex: String,
        protocol_version: u32,
        tx_relay: bool,
        pruned_below_height: u64,
        da_mempool_size: u32,
        chain_id_hex: String,
        genesis_hash_hex: String,
        best_height: u64,
    }

    #[derive(Deserialize)]
    struct SharedFrameVector {
        id: String,
        network: String,
        max_message_size: u64,
        hex: String,
        expect_command: Option<String>,
        expect_payload_hex: Option<String>,
        expect_err: Option<String>,
    }

    #[derive(Deserialize)]
    struct SharedVersionValidation {
        id: String,
        local_protocol_version: u32,
        remote_protocol_version: u32,
        tx_relay: bool,
        pruned_below_height: u64,
        da_mempool_size: u32,
        chain_id_hex: String,
        genesis_hash_hex: String,
        best_height: u64,
        #[serde(default)]
        expect_ok: bool,
        #[serde(default)]
        expect_err: Option<String>,
    }

    fn test_version_payload(best_height: u64) -> VersionPayloadV1 {
        let genesis_bytes = devnet_genesis_block_bytes();
        let genesis_hash = block_hash(&genesis_bytes[..116]).expect("genesis hash");
        VersionPayloadV1 {
            protocol_version: 1,
            tx_relay: true,
            pruned_below_height: 0,
            da_mempool_size: 0,
            chain_id: devnet_genesis_chain_id(),
            genesis_hash,
            best_height,
        }
    }

    fn load_shared_runtime_vectors() -> SharedRuntimeVectors {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../../p2p/testdata/runtime_vectors.json");
        let raw = fs::read_to_string(&path).expect("read runtime_vectors.json");
        serde_json::from_str(&raw).expect("parse runtime_vectors.json")
    }

    fn decode_hex32(raw: &str) -> [u8; 32] {
        let bytes = hex::decode(raw).expect("hex32");
        assert_eq!(bytes.len(), 32, "hex32 len");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn shared_version_payload(v: &SharedVersionPayloadV1) -> VersionPayloadV1 {
        VersionPayloadV1 {
            protocol_version: v.protocol_version,
            tx_relay: v.tx_relay,
            pruned_below_height: v.pruned_below_height,
            da_mempool_size: v.da_mempool_size,
            chain_id: decode_hex32(&v.chain_id_hex),
            genesis_hash: decode_hex32(&v.genesis_hash_hex),
            best_height: v.best_height,
        }
    }

    #[test]
    fn p2p_version_handshake_bidirectional_ok() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = test_version_payload(0);
            perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                .expect("server handshake")
                .state()
        });

        let client = thread::spawn(move || {
            let stream = TcpStream::connect(addr).expect("connect");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let local = test_version_payload(0);
            perform_version_handshake(stream, cfg, local, local.chain_id, local.genesis_hash)
                .expect("client handshake")
                .state()
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
            let mut session =
                PeerSession::new(stream.try_clone().expect("clone"), cfg).expect("session");
            let err = session.read_message().unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "invalid envelope magic");
        });

        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream.set_nodelay(true).expect("set_nodelay");
            let payload = marshal_version_payload_v1(test_version_payload(0));
            let header = build_envelope_header(network_magic("mainnet"), "version", &payload)
                .expect("header");
            stream.write_all(&header).expect("write header");
            stream.write_all(&payload).expect("write payload");
            stream.flush().expect("flush");
        });

        client.join().expect("client join");
        server.join().expect("server join");
    }

    #[test]
    fn p2p_read_message_rejects_oversize_before_payload_read() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut cfg = default_peer_runtime_config("devnet", 8);
            cfg.read_deadline = Duration::from_secs(2);
            cfg.write_deadline = Duration::from_secs(2);
            let mut session =
                PeerSession::new(stream.try_clone().expect("clone"), cfg).expect("session");
            let err = session.read_message().unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "message exceeds cap");
        });

        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream.set_nodelay(true).expect("set_nodelay");
            let mut header = [0u8; WIRE_HEADER_SIZE];
            header[0..4].copy_from_slice(&network_magic("devnet"));
            header[4..16]
                .copy_from_slice(&encode_wire_command("tx").expect("command"));
            let oversize = (MAX_RELAY_MSG_BYTES + 1) as u32;
            header[16..20].copy_from_slice(&oversize.to_le_bytes());
            stream.write_all(&header).expect("write header");
            stream.flush().expect("flush");
        });

        client.join().expect("client join");
        server.join().expect("server join");
    }

    #[test]
    fn shared_runtime_vectors_version_payload_v1() {
        let vectors = load_shared_runtime_vectors();
        let expected = shared_version_payload(&vectors.version_payload_v1);
        let want = hex::decode(&vectors.version_payload_v1.hex).expect("payload hex");
        let encoded = marshal_version_payload_v1(expected);
        assert_eq!(encoded, want);
        let decoded = unmarshal_version_payload_v1(&want).expect("decode payload");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn shared_runtime_vectors_frames() {
        let vectors = load_shared_runtime_vectors();
        for frame in vectors.frames {
            let raw = hex::decode(&frame.hex).expect("frame hex");
            let decoded =
                unmarshal_wire_message(&raw, network_magic(&frame.network), frame.max_message_size);
            if let Some(expect_err) = frame.expect_err {
                let err = decoded.expect_err(&frame.id);
                assert_eq!(err.to_string(), expect_err, "{}", frame.id);
                continue;
            }
            let decoded = decoded.expect(&frame.id);
            assert_eq!(
                decoded.command,
                frame.expect_command.expect("command"),
                "{}",
                frame.id
            );
            assert_eq!(
                decoded.payload,
                hex::decode(frame.expect_payload_hex.expect("payload")).expect("payload hex"),
                "{}",
                frame.id
            );
            let reencoded = marshal_wire_message(
                &decoded,
                network_magic(&frame.network),
                frame.max_message_size,
            )
            .expect("marshal");
            assert_eq!(reencoded, raw, "{}", frame.id);
        }
    }

    #[test]
    fn shared_runtime_vectors_version_validation() {
        let vectors = load_shared_runtime_vectors();
        let expected = shared_version_payload(&vectors.version_payload_v1);
        for tc in vectors.version_validation {
            let remote = VersionPayloadV1 {
                protocol_version: tc.remote_protocol_version,
                tx_relay: tc.tx_relay,
                pruned_below_height: tc.pruned_below_height,
                da_mempool_size: tc.da_mempool_size,
                chain_id: decode_hex32(&tc.chain_id_hex),
                genesis_hash: decode_hex32(&tc.genesis_hash_hex),
                best_height: tc.best_height,
            };
            let got = validate_remote_version(
                remote,
                tc.local_protocol_version,
                expected.chain_id,
                expected.genesis_hash,
            );
            if let Some(expect_err) = tc.expect_err {
                let err = got.expect_err(&tc.id);
                assert_eq!(err.to_string(), expect_err, "{}", tc.id);
                continue;
            }
            assert!(tc.expect_ok, "{} should be marked expect_ok", tc.id);
            got.expect(&tc.id);
        }
    }
}
