use crate::compactsize;
use rubin_consensus::{
    block_header_bytes, parse_block_header_bytes, parse_tx_bytes, parse_tx_bytes_prefix,
    BlockHeader,
};
use rubin_crypto::CryptoProvider;
use siphasher::sip::SipHasher24;
use std::hash::Hasher;

pub const CMD_SENDCMPCT: &str = "sendcmpct";
pub const CMD_CMPCTBLOCK: &str = "cmpctblock";
pub const CMD_GETBLOCKTXN: &str = "getblocktxn";
pub const CMD_BLOCKTXN: &str = "blocktxn";

pub const SHORTID_BYTES: usize = 6;
const KEY_DOMAIN: &[u8] = b"RUBIN-CMPCT-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendCmpctPayload {
    pub announce: u8,
    pub shortid_wtxid: u8, // MUST be 1 in RUBIN
    pub protocol_version: u32,
}

pub fn encode_sendcmpct(p: &SendCmpctPayload) -> Result<Vec<u8>, String> {
    if p.shortid_wtxid != 1 {
        return Err("p2p: sendcmpct: shortid_wtxid must be 1".into());
    }
    let mut out = Vec::with_capacity(6);
    out.push(p.announce);
    out.push(p.shortid_wtxid);
    out.extend_from_slice(&p.protocol_version.to_le_bytes());
    Ok(out)
}

pub fn decode_sendcmpct(b: &[u8]) -> Result<SendCmpctPayload, String> {
    if b.len() != 6 {
        return Err("p2p: sendcmpct: length mismatch".into());
    }
    let announce = b[0];
    let shortid_wtxid = b[1];
    if shortid_wtxid != 1 {
        return Err("p2p: sendcmpct: shortid_wtxid must be 1".into());
    }
    let mut tmp4 = [0u8; 4];
    tmp4.copy_from_slice(&b[2..6]);
    let protocol_version = u32::from_le_bytes(tmp4);
    Ok(SendCmpctPayload {
        announce,
        shortid_wtxid,
        protocol_version,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefilledTx {
    pub index: u64,
    pub tx_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CmpctBlockPayload {
    pub header: BlockHeader,
    pub nonce: u64,
    pub tx_count: u64,
    pub shortids: Vec<[u8; SHORTID_BYTES]>,
    pub prefilled: Vec<PrefilledTx>,
}

pub fn encode_cmpctblock(p: &CmpctBlockPayload) -> Result<Vec<u8>, String> {
    if p.tx_count == 0 {
        return Err("p2p: cmpctblock: tx_count must be >= 1".into());
    }
    if (p.shortids.len() as u64) + (p.prefilled.len() as u64) != p.tx_count {
        return Err("p2p: cmpctblock: shortid_count+prefilled_count must equal tx_count".into());
    }

    let hb = block_header_bytes(&p.header);
    let mut out = Vec::new();
    out.extend_from_slice(&hb);
    out.extend_from_slice(&p.nonce.to_le_bytes());
    out.extend_from_slice(&compactsize::encode(p.tx_count));
    out.extend_from_slice(&compactsize::encode(p.shortids.len() as u64));
    for sid in &p.shortids {
        out.extend_from_slice(sid);
    }
    out.extend_from_slice(&compactsize::encode(p.prefilled.len() as u64));

    let mut prev_idx: u64 = 0;
    for (i, pf) in p.prefilled.iter().enumerate() {
        if pf.index >= p.tx_count {
            return Err("p2p: cmpctblock: prefilled index out of range".into());
        }
        if i == 0 {
            out.extend_from_slice(&compactsize::encode(pf.index));
        } else {
            if pf.index <= prev_idx {
                return Err("p2p: cmpctblock: prefilled indices not strictly increasing".into());
            }
            out.extend_from_slice(&compactsize::encode(pf.index - prev_idx - 1));
        }
        prev_idx = pf.index;
        // Ensure bytes are parseable to avoid ambiguity.
        let _ = parse_tx_bytes(&pf.tx_bytes)?;
        out.extend_from_slice(&pf.tx_bytes);
    }
    Ok(out)
}

pub fn decode_cmpctblock(b: &[u8]) -> Result<CmpctBlockPayload, String> {
    if b.len() < 116 + 8 + 1 {
        return Err("p2p: cmpctblock: short payload".into());
    }
    let mut off = 0usize;
    let header = parse_block_header_bytes(&b[0..116])?;
    off += 116;
    let mut tmp8 = [0u8; 8];
    tmp8.copy_from_slice(&b[off..off + 8]);
    let nonce = u64::from_le_bytes(tmp8);
    off += 8;

    let (tx_count, used) = compactsize::decode(&b[off..])?;
    off += used;
    if tx_count < 1 {
        return Err("p2p: cmpctblock: tx_count must be >= 1".into());
    }

    let (shortid_count, used) = compactsize::decode(&b[off..])?;
    off += used;
    if shortid_count > tx_count {
        return Err("p2p: cmpctblock: shortid_count exceeds tx_count".into());
    }
    let need_sids = (shortid_count as usize)
        .checked_mul(SHORTID_BYTES)
        .ok_or_else(|| "p2p: cmpctblock: shortid_count overflow".to_string())?;
    if b.len() < off + need_sids {
        return Err("p2p: cmpctblock: shortids truncated".into());
    }
    let mut shortids = Vec::with_capacity(shortid_count as usize);
    for _ in 0..(shortid_count as usize) {
        let mut sid = [0u8; SHORTID_BYTES];
        sid.copy_from_slice(&b[off..off + SHORTID_BYTES]);
        off += SHORTID_BYTES;
        shortids.push(sid);
    }

    let (prefilled_count, used) = compactsize::decode(&b[off..])?;
    off += used;
    if prefilled_count > tx_count {
        return Err("p2p: cmpctblock: prefilled_count exceeds tx_count".into());
    }
    if prefilled_count + shortid_count != tx_count {
        return Err("p2p: cmpctblock: shortid_count+prefilled_count must equal tx_count".into());
    }

    let mut prefilled = Vec::with_capacity(prefilled_count as usize);
    let mut prev_idx: u64 = 0;
    for i in 0..(prefilled_count as usize) {
        let (delta, u) = compactsize::decode(&b[off..])?;
        off += u;
        let idx = if i == 0 { delta } else { prev_idx + 1 + delta };
        if idx >= tx_count {
            return Err("p2p: cmpctblock: prefilled index out of range".into());
        }
        if i > 0 && idx <= prev_idx {
            return Err("p2p: cmpctblock: prefilled indices not strictly increasing".into());
        }
        prev_idx = idx;

        let (_tx, used_bytes) = parse_tx_bytes_prefix(&b[off..])?;
        let tx_bytes = b[off..off + used_bytes].to_vec();
        off += used_bytes;
        prefilled.push(PrefilledTx {
            index: idx,
            tx_bytes,
        });
    }

    if off != b.len() {
        return Err("p2p: cmpctblock: trailing bytes".into());
    }

    Ok(CmpctBlockPayload {
        header,
        nonce,
        tx_count,
        shortids,
        prefilled,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetBlockTxnPayload {
    pub block_hash: [u8; 32],
    pub indices: Vec<u64>,
}

pub fn encode_getblocktxn(p: &GetBlockTxnPayload) -> Result<Vec<u8>, String> {
    if p.indices.is_empty() {
        return Err("p2p: getblocktxn: empty indices".into());
    }
    let mut out = Vec::new();
    out.extend_from_slice(&p.block_hash);
    out.extend_from_slice(&compactsize::encode(p.indices.len() as u64));
    let mut prev = 0u64;
    for (i, idx) in p.indices.iter().enumerate() {
        if i == 0 {
            out.extend_from_slice(&compactsize::encode(*idx));
        } else {
            if *idx <= prev {
                return Err("p2p: getblocktxn: indices not strictly increasing".into());
            }
            out.extend_from_slice(&compactsize::encode(*idx - prev - 1));
        }
        prev = *idx;
    }
    Ok(out)
}

pub fn decode_getblocktxn(b: &[u8]) -> Result<GetBlockTxnPayload, String> {
    if b.len() < 32 + 1 {
        return Err("p2p: getblocktxn: short payload".into());
    }
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&b[0..32]);
    let mut off = 32usize;
    let (n, used) = compactsize::decode(&b[off..])?;
    off += used;
    if n == 0 {
        return Err("p2p: getblocktxn: empty indices".into());
    }
    let mut indices = Vec::with_capacity(n as usize);
    let mut prev = 0u64;
    for i in 0..(n as usize) {
        let (delta, u) = compactsize::decode(&b[off..])?;
        off += u;
        let idx = if i == 0 { delta } else { prev + 1 + delta };
        if i > 0 && idx <= prev {
            return Err("p2p: getblocktxn: indices not strictly increasing".into());
        }
        prev = idx;
        indices.push(idx);
    }
    if off != b.len() {
        return Err("p2p: getblocktxn: trailing bytes".into());
    }
    Ok(GetBlockTxnPayload {
        block_hash,
        indices,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockTxnPayload {
    pub block_hash: [u8; 32],
    pub txs: Vec<Vec<u8>>,
}

pub fn encode_blocktxn(p: &BlockTxnPayload) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(&p.block_hash);
    out.extend_from_slice(&compactsize::encode(p.txs.len() as u64));
    for txb in &p.txs {
        let _ = parse_tx_bytes(txb)?;
        out.extend_from_slice(txb);
    }
    Ok(out)
}

pub fn decode_blocktxn(b: &[u8]) -> Result<BlockTxnPayload, String> {
    if b.len() < 32 + 1 {
        return Err("p2p: blocktxn: short payload".into());
    }
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&b[0..32]);
    let mut off = 32usize;
    let (n, used) = compactsize::decode(&b[off..])?;
    off += used;
    let mut txs = Vec::with_capacity(n as usize);
    for _ in 0..(n as usize) {
        let (_tx, used_bytes) = parse_tx_bytes_prefix(&b[off..])?;
        txs.push(b[off..off + used_bytes].to_vec());
        off += used_bytes;
    }
    if off != b.len() {
        return Err("p2p: blocktxn: trailing bytes".into());
    }
    Ok(BlockTxnPayload { block_hash, txs })
}

fn cmpct_keys(
    provider: &dyn CryptoProvider,
    header: &BlockHeader,
    nonce: u64,
) -> Result<(u64, u64), String> {
    let hb = block_header_bytes(header);
    let mut buf = Vec::with_capacity(KEY_DOMAIN.len() + hb.len() + 8);
    buf.extend_from_slice(KEY_DOMAIN);
    buf.extend_from_slice(&hb);
    buf.extend_from_slice(&nonce.to_le_bytes());
    let km = provider.sha3_256(&buf)?;
    let mut a = [0u8; 8];
    let mut b8 = [0u8; 8];
    a.copy_from_slice(&km[0..8]);
    b8.copy_from_slice(&km[8..16]);
    Ok((u64::from_le_bytes(a), u64::from_le_bytes(b8)))
}

pub fn shortid(
    provider: &dyn CryptoProvider,
    header: &BlockHeader,
    nonce: u64,
    tx_bytes: &[u8],
) -> Result<[u8; SHORTID_BYTES], String> {
    let (k0, k1) = cmpct_keys(provider, header, nonce)?;
    let wtxid = provider.sha3_256(tx_bytes)?;
    let mut hasher = SipHasher24::new_with_keys(k0, k1);
    hasher.write(&wtxid);
    let s64 = hasher.finish();
    let le = s64.to_le_bytes();
    let mut out = [0u8; SHORTID_BYTES];
    out.copy_from_slice(&le[0..SHORTID_BYTES]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rubin_consensus::{
        tx_bytes, Tx, TxInput, TxOutput, WitnessSection, TX_KIND_STANDARD, TX_VERSION_V2,
    };
    use rubin_crypto::DevStdCryptoProvider;

    #[test]
    fn sendcmpct_roundtrip() {
        let p = SendCmpctPayload {
            announce: 1,
            shortid_wtxid: 1,
            protocol_version: 1,
        };
        let raw = encode_sendcmpct(&p).unwrap();
        let dec = decode_sendcmpct(&raw).unwrap();
        assert_eq!(p, dec);
    }

    #[test]
    fn cmpctblock_roundtrip() {
        let header = BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1,
            target: [0u8; 32],
            nonce: 2,
        };
        let tx = Tx {
            version: TX_VERSION_V2,
            tx_kind: TX_KIND_STANDARD,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 0,
                covenant_type: 0,
                covenant_data: vec![],
            }],
            locktime: 0,
            da_commit: None,
            da_chunk: None,
            da_payload: vec![],
            witness: WitnessSection { witnesses: vec![] },
        };
        let txb = tx_bytes(&tx);
        let payload = CmpctBlockPayload {
            header,
            nonce: 42,
            tx_count: 2,
            shortids: vec![[1, 2, 3, 4, 5, 6]],
            prefilled: vec![PrefilledTx {
                index: 0,
                tx_bytes: txb.clone(),
            }],
        };
        let raw = encode_cmpctblock(&payload).unwrap();
        let dec = decode_cmpctblock(&raw).unwrap();
        assert_eq!(dec.tx_count, 2);
        assert_eq!(dec.shortids.len(), 1);
        assert_eq!(dec.prefilled.len(), 1);
        assert_eq!(dec.prefilled[0].tx_bytes, txb);
    }

    #[test]
    fn shortid_is_deterministic() {
        let provider = DevStdCryptoProvider;
        let header = BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1,
            target: [0u8; 32],
            nonce: 2,
        };
        let tx = Tx {
            version: TX_VERSION_V2,
            tx_kind: TX_KIND_STANDARD,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 0,
                covenant_type: 0,
                covenant_data: vec![],
            }],
            locktime: 0,
            da_commit: None,
            da_chunk: None,
            da_payload: vec![],
            witness: WitnessSection { witnesses: vec![] },
        };
        let txb = tx_bytes(&tx);
        let a = shortid(&provider, &header, 123, &txb).unwrap();
        let b = shortid(&provider, &header, 123, &txb).unwrap();
        assert_eq!(a, b);
    }
}
