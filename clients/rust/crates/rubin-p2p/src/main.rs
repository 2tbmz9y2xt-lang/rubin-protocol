use rubin_crypto::DevStdCryptoProvider;
use rubin_p2p::handshake::{handshake_inbound_server, HANDSHAKE_TIMEOUT};
use rubin_p2p::version::VersionPayload;
use std::env;
use std::io::{self, Write};
use std::net::TcpListener;

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let b = hex::decode(s).map_err(|e| e.to_string())?;
    if b.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", b.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

fn parse_u32(s: &str) -> Result<u32, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16)
        .or_else(|_| s.parse::<u32>())
        .map_err(|e| e.to_string())
}

fn main() -> Result<(), String> {
    // Minimal CLI (no extra deps):
    //   rubin-p2p listen-handshake --chain-id-hex <64hex> --magic <u32|0x..>
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(
            "usage: rubin-p2p listen-handshake --chain-id-hex <hex> --magic <u32|0x..>".into(),
        );
    }
    if args[1] != "listen-handshake" {
        return Err("unknown command".into());
    }
    let mut chain_hex: Option<String> = None;
    let mut magic: Option<u32> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--chain-id-hex" => {
                i += 1;
                chain_hex = args.get(i).cloned();
            }
            "--magic" => {
                i += 1;
                let v = args.get(i).ok_or("missing --magic value")?;
                magic = Some(parse_u32(v)?);
            }
            _ => return Err(format!("unknown arg: {}", args[i])),
        }
        i += 1;
    }
    let chain_id = parse_hex32(chain_hex.as_deref().ok_or("missing --chain-id-hex")?)?;
    let magic = magic.ok_or("missing --magic")?;

    let ln = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let addr = ln.local_addr().map_err(|e| e.to_string())?;
    println!("LISTEN {}", addr);
    io::stdout().flush().ok();

    let (mut stream, _) = ln.accept().map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|e| e.to_string())?;

    let crypto = DevStdCryptoProvider;
    let our = VersionPayload {
        protocol_version: 1,
        chain_id,
        peer_services: 0,
        timestamp: 0,
        nonce: 1,
        user_agent: "/rubin-p2p/0.1.0".to_string(),
        start_height: 0,
        relay: 0,
    };

    // If chain_id mismatch occurs, we still exit 0 (interop harness asserts behavior on the wire).
    let _ = handshake_inbound_server(&mut stream, &crypto, magic, chain_id, our);
    Ok(())
}
