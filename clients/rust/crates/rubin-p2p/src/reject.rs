use crate::compactsize;

pub const REJECT_MALFORMED: u8 = 0x01;
pub const REJECT_INVALID: u8 = 0x10;
pub const REJECT_OBSOLETE: u8 = 0x11;
pub const REJECT_DUPLICATE: u8 = 0x12;
pub const REJECT_NONSTANDARD: u8 = 0x40;
pub const REJECT_DUST: u8 = 0x41;
pub const REJECT_INSUFFICIENTFEE: u8 = 0x42;
pub const REJECT_CHECKPOINT: u8 = 0x43;

pub const MAX_REJECT_REASON_BYTES: usize = 111;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectPayload {
    pub message: String,
    pub ccode: u8,
    pub reason: String,
}

pub fn encode_reject_payload(r: &RejectPayload) -> Result<Vec<u8>, String> {
    let msg = r.message.as_bytes();
    let reason = r.reason.as_bytes();
    if reason.len() > MAX_REJECT_REASON_BYTES {
        return Err("p2p: reject: reason too long".into());
    }
    // Note: message is a command string; we only require it be non-empty and <=12 in our impl.
    if msg.is_empty() || msg.len() > 12 {
        return Err("p2p: reject: invalid message".into());
    }
    let mut out = Vec::with_capacity(9 + msg.len() + 1 + 9 + reason.len());
    out.extend_from_slice(&compactsize::encode(msg.len() as u64));
    out.extend_from_slice(msg);
    out.push(r.ccode);
    out.extend_from_slice(&compactsize::encode(reason.len() as u64));
    out.extend_from_slice(reason);
    Ok(out)
}

pub fn decode_reject_payload(b: &[u8]) -> Result<RejectPayload, String> {
    let (msg_len, used1) = compactsize::decode(b)?;
    let msg_len = msg_len as usize;
    let off1 = used1;
    if b.len() < off1 + msg_len + 1 {
        return Err("p2p: reject: short payload".into());
    }
    let message = std::str::from_utf8(&b[off1..off1 + msg_len])
        .map_err(|_| "p2p: reject: message not utf8".to_string())?
        .to_string();
    let ccode = b[off1 + msg_len];
    let (reason_len, used2) = compactsize::decode(&b[off1 + msg_len + 1..])?;
    let reason_len = reason_len as usize;
    if reason_len > MAX_REJECT_REASON_BYTES {
        return Err("p2p: reject: reason too long".into());
    }
    let off2 = off1 + msg_len + 1 + used2;
    if b.len() != off2 + reason_len {
        return Err("p2p: reject: length mismatch".into());
    }
    let reason = std::str::from_utf8(&b[off2..off2 + reason_len])
        .map_err(|_| "p2p: reject: reason not utf8".to_string())?
        .to_string();
    Ok(RejectPayload {
        message,
        ccode,
        reason,
    })
}
