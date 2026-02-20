use crate::envelope::{read_message, write_message};
use crate::reject::{encode_reject_payload, RejectPayload, REJECT_INVALID};
use crate::version::{
    decode_version_payload, encode_version_payload, VersionPayload, PROTOCOL_VERSION_V1,
};
use rubin_crypto::CryptoProvider;
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const CMD_VERSION: &str = "version";
pub const CMD_VERACK: &str = "verack";
pub const CMD_REJECT: &str = "reject";

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct HandshakeResult {
    pub peer_version: VersionPayload,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

pub fn handshake_outbound(
    stream: &mut TcpStream,
    crypto: &dyn CryptoProvider,
    magic: u32,
    local_chain_id: [u8; 32],
    mut our: VersionPayload,
) -> Result<HandshakeResult, String> {
    our.protocol_version = PROTOCOL_VERSION_V1;
    our.chain_id = local_chain_id;
    our.timestamp = now_unix();

    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|e| e.to_string())?;

    let payload = encode_version_payload(&our)?;
    write_message(stream, crypto, magic, CMD_VERSION, &payload)?;

    let peer = read_until_version(stream, crypto, magic, local_chain_id)?;

    // Send verack.
    write_message(stream, crypto, magic, CMD_VERACK, &[])?;

    // Wait for verack.
    read_until_verack(stream, crypto, magic)?;
    stream.set_read_timeout(None).map_err(|e| e.to_string())?;
    Ok(HandshakeResult { peer_version: peer })
}

pub fn handshake_inbound_server(
    stream: &mut TcpStream,
    crypto: &dyn CryptoProvider,
    magic: u32,
    local_chain_id: [u8; 32],
    mut our: VersionPayload,
) -> Result<HandshakeResult, String> {
    our.protocol_version = PROTOCOL_VERSION_V1;
    our.chain_id = local_chain_id;
    our.timestamp = now_unix();

    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|e| e.to_string())?;

    // Receive peer version first (so we can reject chain_id mismatch before verack).
    let peer = match read_until_version(stream, crypto, magic, local_chain_id) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    // Send our version.
    let payload = encode_version_payload(&our)?;
    write_message(stream, crypto, magic, CMD_VERSION, &payload)?;

    // Send verack.
    write_message(stream, crypto, magic, CMD_VERACK, &[])?;

    // Wait for peer verack.
    read_until_verack(stream, crypto, magic)?;
    stream.set_read_timeout(None).map_err(|e| e.to_string())?;
    Ok(HandshakeResult { peer_version: peer })
}

fn read_until_version(
    stream: &mut TcpStream,
    crypto: &dyn CryptoProvider,
    magic: u32,
    local_chain_id: [u8; 32],
) -> Result<VersionPayload, String> {
    loop {
        let msg = read_message(stream, crypto, magic).map_err(|e| e.err)?;
        if msg.command == CMD_VERSION {
            let v = decode_version_payload(&msg.payload)?;
            if v.chain_id != local_chain_id {
                let rp = RejectPayload {
                    message: CMD_VERSION.to_string(),
                    ccode: REJECT_INVALID,
                    reason: "chain_id mismatch".to_string(),
                };
                if let Ok(payload) = encode_reject_payload(&rp) {
                    let _ = write_message(stream, crypto, magic, CMD_REJECT, &payload);
                }
                return Err("p2p: handshake: chain_id mismatch".into());
            }
            if v.protocol_version != PROTOCOL_VERSION_V1 {
                return Err("p2p: handshake: unsupported protocol_version".into());
            }
            return Ok(v);
        }
        if msg.command == CMD_VERACK {
            // Early verack ignored.
            continue;
        }
        // Unknown/unsolicited ignored in INIT.
    }
}

fn read_until_verack(
    stream: &mut TcpStream,
    crypto: &dyn CryptoProvider,
    magic: u32,
) -> Result<(), String> {
    loop {
        let msg = read_message(stream, crypto, magic).map_err(|e| e.err)?;
        if msg.command == CMD_VERACK {
            if !msg.payload.is_empty() {
                return Err("p2p: handshake: verack payload must be empty".into());
            }
            return Ok(());
        }
        if msg.command == CMD_VERSION {
            return Err("p2p: handshake: duplicate version".into());
        }
        // ignore
    }
}
