use crate::compactsize;

pub const PROTOCOL_VERSION_V1: u32 = 1;
pub const MAX_USER_AGENT_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionPayload {
    pub protocol_version: u32,
    pub chain_id: [u8; 32],
    pub peer_services: u64,
    pub timestamp: u64,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: u32,
    pub relay: u8, // 0 or 1
}

pub fn encode_version_payload(v: &VersionPayload) -> Result<Vec<u8>, String> {
    let ua = v.user_agent.as_bytes();
    if ua.len() > MAX_USER_AGENT_BYTES {
        return Err("p2p: version: user_agent too long".into());
    }
    if v.relay != 0 && v.relay != 1 {
        return Err("p2p: version: relay must be 0 or 1".into());
    }

    let mut out = Vec::with_capacity(4 + 32 + 8 + 8 + 8 + 9 + ua.len() + 4 + 1);
    out.extend_from_slice(&v.protocol_version.to_le_bytes());
    out.extend_from_slice(&v.chain_id);
    out.extend_from_slice(&v.peer_services.to_le_bytes());
    out.extend_from_slice(&v.timestamp.to_le_bytes());
    out.extend_from_slice(&v.nonce.to_le_bytes());
    out.extend_from_slice(&compactsize::encode(ua.len() as u64));
    out.extend_from_slice(ua);
    out.extend_from_slice(&v.start_height.to_le_bytes());
    out.push(v.relay);
    Ok(out)
}

pub fn decode_version_payload(b: &[u8]) -> Result<VersionPayload, String> {
    if b.len() < 4 + 32 + 8 + 8 + 8 + 1 + 4 + 1 {
        return Err("p2p: version: short payload".into());
    }
    let protocol_version = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let mut chain_id = [0u8; 32];
    chain_id.copy_from_slice(&b[4..36]);
    let peer_services = u64::from_le_bytes(b[36..44].try_into().unwrap());
    let timestamp = u64::from_le_bytes(b[44..52].try_into().unwrap());
    let nonce = u64::from_le_bytes(b[52..60].try_into().unwrap());

    let (ua_len, used) = compactsize::decode(&b[60..])?;
    if ua_len as usize > MAX_USER_AGENT_BYTES {
        return Err("p2p: version: user_agent_len exceeds MAX_USER_AGENT_BYTES".into());
    }
    let ua_len_usize = ua_len as usize;
    let off = 60 + used;
    let need = off + ua_len_usize + 4 + 1;
    if b.len() != need {
        return Err("p2p: version: length mismatch".into());
    }
    let ua_bytes = &b[off..off + ua_len_usize];
    let user_agent = std::str::from_utf8(ua_bytes)
        .map_err(|_| "p2p: version: user_agent not utf8".to_string())?
        .to_string();
    let start_height = u32::from_le_bytes(
        b[off + ua_len_usize..off + ua_len_usize + 4]
            .try_into()
            .unwrap(),
    );
    let relay = b[need - 1];
    if relay != 0 && relay != 1 {
        return Err("p2p: version: relay must be 0 or 1".into());
    }

    Ok(VersionPayload {
        protocol_version,
        chain_id,
        peer_services,
        timestamp,
        nonce,
        user_agent,
        start_height,
        relay,
    })
}
