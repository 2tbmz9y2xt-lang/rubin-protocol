use rubin_crypto::CryptoProvider;
use std::io::{Read, Write};

pub const TRANSPORT_PREFIX_BYTES: usize = 24;
pub const COMMAND_BYTES: usize = 12;
pub const MAX_RELAY_MSG_BYTES: usize = 8_388_608;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub magic: u32,
    pub command: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ReadError {
    pub err: String,
    pub ban_score_delta: i32,
    pub disconnect: bool,
}

fn checksum4(p: &dyn CryptoProvider, payload: &[u8]) -> Result<[u8; 4], String> {
    let d = p.sha3_256(payload)?;
    Ok([d[0], d[1], d[2], d[3]])
}

fn encode_command(cmd: &str) -> Result<[u8; COMMAND_BYTES], String> {
    if cmd.is_empty() {
        return Err("p2p: empty command".into());
    }
    if cmd.len() > COMMAND_BYTES {
        return Err("p2p: command too long".into());
    }
    let mut out = [0u8; COMMAND_BYTES];
    for (i, b) in cmd.as_bytes().iter().enumerate() {
        if *b == 0 || *b >= 0x80 {
            return Err("p2p: command must be ASCII".into());
        }
        out[i] = *b;
    }
    Ok(out)
}

fn decode_command(cmd: [u8; COMMAND_BYTES]) -> Result<String, String> {
    let mut n = COMMAND_BYTES;
    for i in 0..COMMAND_BYTES {
        if cmd[i] == 0 {
            n = i;
            break;
        }
    }
    for i in n..COMMAND_BYTES {
        if cmd[i] != 0 {
            return Err("p2p: command not NUL-right-padded".into());
        }
    }
    if n == 0 {
        return Err("p2p: empty command".into());
    }
    let s = std::str::from_utf8(&cmd[..n]).map_err(|_| "p2p: command not utf8".to_string())?;
    Ok(s.to_string())
}

pub fn write_message(
    w: &mut dyn Write,
    p: &dyn CryptoProvider,
    magic: u32,
    command: &str,
    payload: &[u8],
) -> Result<(), String> {
    let cmd12 = encode_command(command)?;
    if payload.len() > MAX_RELAY_MSG_BYTES {
        return Err("p2p: payload too large".into());
    }
    let c4 = checksum4(p, payload)?;

    let mut hdr = [0u8; TRANSPORT_PREFIX_BYTES];
    hdr[0..4].copy_from_slice(&magic.to_be_bytes());
    hdr[4..16].copy_from_slice(&cmd12);
    hdr[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    hdr[20..24].copy_from_slice(&c4);

    w.write_all(&hdr).map_err(|e| e.to_string())?;
    if !payload.is_empty() {
        w.write_all(payload).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn read_message(
    r: &mut dyn Read,
    p: &dyn CryptoProvider,
    expected_magic: u32,
) -> Result<Message, ReadError> {
    let mut hdr = [0u8; TRANSPORT_PREFIX_BYTES];
    if let Err(e) = r.read_exact(&mut hdr) {
        return Err(ReadError {
            err: e.to_string(),
            ban_score_delta: 0,
            disconnect: true,
        });
    }

    let magic = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    if magic != expected_magic {
        return Err(ReadError {
            err: "p2p: magic mismatch".into(),
            ban_score_delta: 0,
            disconnect: true,
        });
    }

    let mut cmd = [0u8; COMMAND_BYTES];
    cmd.copy_from_slice(&hdr[4..16]);
    let command = match decode_command(cmd) {
        Ok(c) => c,
        Err(e) => {
            return Err(ReadError {
                err: e,
                ban_score_delta: 10,
                disconnect: false,
            })
        }
    };

    let payload_len = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]) as usize;
    if payload_len > MAX_RELAY_MSG_BYTES {
        return Err(ReadError {
            err: "p2p: payload_length exceeds MAX_RELAY_MSG_BYTES".into(),
            ban_score_delta: 0,
            disconnect: true,
        });
    }

    let expected_c4 = [hdr[20], hdr[21], hdr[22], hdr[23]];
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        if let Err(e) = r.read_exact(&mut payload) {
            return Err(ReadError {
                err: e.to_string(),
                ban_score_delta: 20,
                disconnect: true,
            });
        }
    }

    let computed_c4 = match checksum4(p, &payload) {
        Ok(c4) => c4,
        Err(e) => {
            return Err(ReadError {
                err: e,
                ban_score_delta: 0,
                disconnect: true,
            })
        }
    };
    if expected_c4 != computed_c4 {
        return Err(ReadError {
            err: "p2p: checksum mismatch".into(),
            ban_score_delta: 10,
            disconnect: false,
        });
    }

    Ok(Message {
        magic,
        command,
        payload,
    })
}
