//! RUBIN consensus library (wire, hashing domains, validation).
//!
//! This crate MUST implement consensus exactly as defined in:
//! - spec/RUBIN_L1_CANONICAL_v1.1.md
//!
//! Non-consensus policy MUST NOT be implemented here.

use rubin_crypto::CryptoProvider;

pub const CONSENSUS_REVISION: &str = "v1.1";

pub fn compact_size_encode(n: u64) -> Vec<u8> {
    if n < 253 {
        return vec![n as u8];
    }
    if n <= 0xffff {
        let mut out = vec![0xfd];
        out.extend_from_slice(&(n as u16).to_le_bytes());
        return out;
    }
    if n <= 0xffff_ffff {
        let mut out = vec![0xfe];
        out.extend_from_slice(&(n as u32).to_le_bytes());
        return out;
    }
    let mut out = vec![0xff];
    out.extend_from_slice(&n.to_le_bytes());
    out
}

pub fn compact_size_decode(bytes: &[u8]) -> Result<(u64, usize), String> {
    if bytes.is_empty() {
        return Err("compactsize: empty".into());
    }
    let tag = bytes[0];
    if tag < 0xfd {
        return Ok((tag as u64, 1));
    }
    if tag == 0xfd {
        if bytes.len() < 3 {
            return Err("compactsize: truncated u16".into());
        }
        let n = u16::from_le_bytes([bytes[1], bytes[2]]) as u64;
        if n < 253 {
            return Err("compactsize: non-minimal u16".into());
        }
        return Ok((n, 3));
    }
    if tag == 0xfe {
        if bytes.len() < 5 {
            return Err("compactsize: truncated u32".into());
        }
        let n = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64;
        if n < 0x1_0000 {
            return Err("compactsize: non-minimal u32".into());
        }
        return Ok((n, 5));
    }
    if bytes.len() < 9 {
        return Err("compactsize: truncated u64".into());
    }
    let n = u64::from_le_bytes([
        bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
    ]);
    if n < 0x1_0000_0000 {
        return Err("compactsize: non-minimal u64".into());
    }
    Ok((n, 9))
}

pub fn hex_decode_strict(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.split_whitespace().collect();
    hex::decode(cleaned).map_err(|e| format!("hex decode error: {e}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub version: u32,
    pub tx_nonce: u64,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub locktime: u32,
    pub witness: WitnessSection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInput {
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutput {
    pub value: u64,
    pub covenant_type: u16,
    pub covenant_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessSection {
    pub witnesses: Vec<WitnessItem>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessItem {
    pub suite_id: u8,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.remaining() < len {
            return Err("parse: truncated".into());
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.bytes[start..start + len])
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16le(&mut self) -> Result<u16, String> {
        let b = self.read_exact(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u32le(&mut self) -> Result<u32, String> {
        let b = self.read_exact(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64le(&mut self) -> Result<u64, String> {
        let b = self.read_exact(8)?;
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    fn read_compact_size(&mut self) -> Result<u64, String> {
        let (n, consumed) = compact_size_decode(&self.bytes[self.pos..])?;
        self.pos += consumed;
        Ok(n)
    }
}

pub fn parse_tx_bytes(bytes: &[u8]) -> Result<Tx, String> {
    let mut cursor = Cursor::new(bytes);

    let version = cursor.read_u32le()?;
    let tx_nonce = cursor.read_u64le()?;

    let input_count_u64 = cursor.read_compact_size()?;
    let input_count: usize = input_count_u64
        .try_into()
        .map_err(|_| "parse: input_count overflows usize".to_string())?;
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let prev_txid_slice = cursor.read_exact(32)?;
        let mut prev_txid = [0u8; 32];
        prev_txid.copy_from_slice(prev_txid_slice);
        let prev_vout = cursor.read_u32le()?;

        let script_sig_len_u64 = cursor.read_compact_size()?;
        let script_sig_len: usize = script_sig_len_u64
            .try_into()
            .map_err(|_| "parse: script_sig_len overflows usize".to_string())?;
        let script_sig = cursor.read_exact(script_sig_len)?.to_vec();
        let sequence = cursor.read_u32le()?;

        inputs.push(TxInput {
            prev_txid,
            prev_vout,
            script_sig,
            sequence,
        });
    }

    let output_count_u64 = cursor.read_compact_size()?;
    let output_count: usize = output_count_u64
        .try_into()
        .map_err(|_| "parse: output_count overflows usize".to_string())?;
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let value = cursor.read_u64le()?;
        let covenant_type = cursor.read_u16le()?;

        let covenant_data_len_u64 = cursor.read_compact_size()?;
        let covenant_data_len: usize = covenant_data_len_u64
            .try_into()
            .map_err(|_| "parse: covenant_data_len overflows usize".to_string())?;
        let covenant_data = cursor.read_exact(covenant_data_len)?.to_vec();

        outputs.push(TxOutput {
            value,
            covenant_type,
            covenant_data,
        });
    }

    let locktime = cursor.read_u32le()?;

    let witness_count_u64 = cursor.read_compact_size()?;
    let witness_count: usize = witness_count_u64
        .try_into()
        .map_err(|_| "parse: witness_count overflows usize".to_string())?;
    let mut witnesses = Vec::with_capacity(witness_count);
    for _ in 0..witness_count {
        let suite_id = cursor.read_u8()?;

        let pubkey_len_u64 = cursor.read_compact_size()?;
        let pubkey_len: usize = pubkey_len_u64
            .try_into()
            .map_err(|_| "parse: pubkey_len overflows usize".to_string())?;
        let pubkey = cursor.read_exact(pubkey_len)?.to_vec();

        let sig_len_u64 = cursor.read_compact_size()?;
        let sig_len: usize = sig_len_u64
            .try_into()
            .map_err(|_| "parse: sig_len overflows usize".to_string())?;
        let signature = cursor.read_exact(sig_len)?.to_vec();

        witnesses.push(WitnessItem {
            suite_id,
            pubkey,
            signature,
        });
    }

    if cursor.pos != bytes.len() {
        return Err("parse: trailing bytes".into());
    }

    Ok(Tx {
        version,
        tx_nonce,
        inputs,
        outputs,
        locktime,
        witness: WitnessSection { witnesses },
    })
}

pub fn tx_no_witness_bytes(tx: &Tx) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version.to_le_bytes());
    out.extend_from_slice(&tx.tx_nonce.to_le_bytes());
    out.extend_from_slice(&compact_size_encode(tx.inputs.len() as u64));
    for input in &tx.inputs {
        out.extend_from_slice(&input.prev_txid);
        out.extend_from_slice(&input.prev_vout.to_le_bytes());
        out.extend_from_slice(&compact_size_encode(input.script_sig.len() as u64));
        out.extend_from_slice(&input.script_sig);
        out.extend_from_slice(&input.sequence.to_le_bytes());
    }
    out.extend_from_slice(&compact_size_encode(tx.outputs.len() as u64));
    for output in &tx.outputs {
        out.extend_from_slice(&tx_output_bytes(output));
    }
    out.extend_from_slice(&tx.locktime.to_le_bytes());
    out
}

pub fn witness_bytes(w: &WitnessSection) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&compact_size_encode(w.witnesses.len() as u64));
    for item in &w.witnesses {
        out.extend_from_slice(&witness_item_bytes(item));
    }
    out
}

pub fn tx_bytes(tx: &Tx) -> Vec<u8> {
    let mut out = tx_no_witness_bytes(tx);
    out.extend_from_slice(&witness_bytes(&tx.witness));
    out
}

pub fn tx_output_bytes(output: &TxOutput) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&output.value.to_le_bytes());
    out.extend_from_slice(&output.covenant_type.to_le_bytes());
    out.extend_from_slice(&compact_size_encode(output.covenant_data.len() as u64));
    out.extend_from_slice(&output.covenant_data);
    out
}

pub fn witness_item_bytes(item: &WitnessItem) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(item.suite_id);
    out.extend_from_slice(&compact_size_encode(item.pubkey.len() as u64));
    out.extend_from_slice(&item.pubkey);
    out.extend_from_slice(&compact_size_encode(item.signature.len() as u64));
    out.extend_from_slice(&item.signature);
    out
}

pub fn txid(provider: &dyn CryptoProvider, tx: &Tx) -> Result<[u8; 32], String> {
    provider.sha3_256(&tx_no_witness_bytes(tx))
}

pub fn sighash_v1_digest(
    provider: &dyn CryptoProvider,
    chain_id: &[u8; 32],
    tx: &Tx,
    input_index: u32,
    input_value: u64,
) -> Result<[u8; 32], String> {
    let input_index_usize: usize = input_index
        .try_into()
        .map_err(|_| "sighash: input_index overflows usize".to_string())?;
    if input_index_usize >= tx.inputs.len() {
        return Err("sighash: input_index out of bounds".into());
    }

    let mut prevouts = Vec::new();
    for input in &tx.inputs {
        prevouts.extend_from_slice(&input.prev_txid);
        prevouts.extend_from_slice(&input.prev_vout.to_le_bytes());
    }
    let hash_of_all_prevouts = provider.sha3_256(&prevouts)?;

    let mut sequences = Vec::new();
    for input in &tx.inputs {
        sequences.extend_from_slice(&input.sequence.to_le_bytes());
    }
    let hash_of_all_sequences = provider.sha3_256(&sequences)?;

    let mut outputs_bytes = Vec::new();
    for output in &tx.outputs {
        outputs_bytes.extend_from_slice(&tx_output_bytes(output));
    }
    let hash_of_all_outputs = provider.sha3_256(&outputs_bytes)?;

    let input = &tx.inputs[input_index_usize];

    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"RUBINv1-sighash/");
    preimage.extend_from_slice(chain_id);
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    preimage.extend_from_slice(&tx.tx_nonce.to_le_bytes());
    preimage.extend_from_slice(&hash_of_all_prevouts);
    preimage.extend_from_slice(&hash_of_all_sequences);
    preimage.extend_from_slice(&input_index.to_le_bytes());
    preimage.extend_from_slice(&input.prev_txid);
    preimage.extend_from_slice(&input.prev_vout.to_le_bytes());
    preimage.extend_from_slice(&input_value.to_le_bytes());
    preimage.extend_from_slice(&input.sequence.to_le_bytes());
    preimage.extend_from_slice(&hash_of_all_outputs);
    preimage.extend_from_slice(&tx.locktime.to_le_bytes());

    Ok(provider.sha3_256(&preimage)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_roundtrip_boundaries() {
        let cases = [
            0u64,
            1,
            252,
            253,
            65535,
            65536,
            305_419_896,
            4_294_967_296,
            u64::MAX,
        ];
        for n in cases {
            let enc = compact_size_encode(n);
            let (dec, used) = compact_size_decode(&enc).expect("decode");
            assert_eq!(dec, n);
            assert_eq!(used, enc.len());
        }
    }

    #[test]
    fn compact_size_rejects_non_minimal() {
        let (n, used) = compact_size_decode(&[0xfc]).expect("decode");
        assert_eq!(n, 252);
        assert_eq!(used, 1);

        assert!(compact_size_decode(&[0xfd, 0x01, 0x00]).is_err());
        assert!(compact_size_decode(&[0xfe, 0xff, 0x00, 0x00, 0x00]).is_err());
        assert!(compact_size_decode(&[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00]).is_err());
    }
}
