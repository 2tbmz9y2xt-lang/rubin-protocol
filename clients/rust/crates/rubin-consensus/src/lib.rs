//! RUBIN consensus library (wire, hashing domains, validation).
//!
//! This crate MUST implement consensus exactly as defined in:
//! - spec/RUBIN_L1_CANONICAL_v1.1.md
//!
//! Non-consensus policy MUST NOT be implemented here.

use rubin_crypto::CryptoProvider;
use std::collections::{HashMap, HashSet};

pub const CONSENSUS_REVISION: &str = "v1.1";

pub const CORE_P2PK: u16 = 0x0000;
pub const CORE_TIMELOCK_V1: u16 = 0x0001;
pub const CORE_ANCHOR: u16 = 0x0002;
pub const CORE_HTLC_V1: u16 = 0x0100;
pub const CORE_VAULT_V1: u16 = 0x0101;
pub const CORE_HTLC_V2: u16 = 0x0102;
pub const CORE_RESERVED_FUTURE: u16 = 0x00ff;

pub const SUITE_ID_SENTINEL: u8 = 0x00;
pub const SUITE_ID_ML_DSA: u8 = 0x01;
pub const SUITE_ID_SLH_DSA: u8 = 0x02;

pub const ML_DSA_PUBKEY_BYTES: usize = 2_592;
pub const SLH_DSA_PUBKEY_BYTES: usize = 64;
pub const ML_DSA_SIG_BYTES: usize = 4_627;
pub const SLH_DSA_SIG_MAX_BYTES: usize = 49_856;
pub const MAX_TX_INPUTS: usize = 1_024;
pub const MAX_TX_OUTPUTS: usize = 1_024;
pub const MAX_WITNESS_ITEMS: usize = 1_024;
pub const MAX_WITNESS_BYTES_PER_TX: usize = 100_000;

pub const TIMELOCK_MODE_HEIGHT: u8 = 0x00;
pub const TIMELOCK_MODE_TIMESTAMP: u8 = 0x01;

// Block-level consensus constants (v1.1).
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
pub const MAX_ANCHOR_BYTES_PER_BLOCK: u64 = 131_072;
pub const MAX_ANCHOR_PAYLOAD_SIZE: usize = 65_536;
pub const WINDOW_SIZE: u64 = 2_016;
pub const TARGET_BLOCK_INTERVAL: u64 = 600;
pub const MAX_FUTURE_DRIFT: u64 = 7_200;
pub const COINBASE_MATURITY: u64 = 100;

// Signature verification cost model (consensus weight accounting) — must match spec + Go client.
pub const VERIFY_COST_ML_DSA: u64 = 8;
pub const VERIFY_COST_SLH_DSA: u64 = 64;

// Tx-level replay / sequence constraints.
pub const TX_NONCE_ZERO: u64 = 0;
pub const TX_MAX_SEQUENCE: u32 = 0x7fffffff;
pub const TX_COINBASE_PREVOUT_VOUT: u32 = u32::MAX;

pub const BLOCK_ERR_PARSE: &str = "BLOCK_ERR_PARSE";
pub const BLOCK_ERR_LINKAGE_INVALID: &str = "BLOCK_ERR_LINKAGE_INVALID";
pub const BLOCK_ERR_POW_INVALID: &str = "BLOCK_ERR_POW_INVALID";
pub const BLOCK_ERR_TARGET_INVALID: &str = "BLOCK_ERR_TARGET_INVALID";
pub const BLOCK_ERR_MERKLE_INVALID: &str = "BLOCK_ERR_MERKLE_INVALID";
pub const BLOCK_ERR_WEIGHT_EXCEEDED: &str = "BLOCK_ERR_WEIGHT_EXCEEDED";
pub const BLOCK_ERR_COINBASE_INVALID: &str = "BLOCK_ERR_COINBASE_INVALID";
pub const BLOCK_ERR_SUBSIDY_EXCEEDED: &str = "BLOCK_ERR_SUBSIDY_EXCEEDED";
pub const BLOCK_ERR_TIMESTAMP_OLD: &str = "BLOCK_ERR_TIMESTAMP_OLD";
pub const BLOCK_ERR_TIMESTAMP_FUTURE: &str = "BLOCK_ERR_TIMESTAMP_FUTURE";
pub const BLOCK_ERR_ANCHOR_BYTES_EXCEEDED: &str = "BLOCK_ERR_ANCHOR_BYTES_EXCEEDED";

pub const TX_ERR_NONCE_REPLAY: &str = "TX_ERR_NONCE_REPLAY";
pub const TX_ERR_TX_NONCE_INVALID: &str = "TX_ERR_TX_NONCE_INVALID";
pub const TX_ERR_SEQUENCE_INVALID: &str = "TX_ERR_SEQUENCE_INVALID";
pub const TX_ERR_COINBASE_IMMATURE: &str = "TX_ERR_COINBASE_IMMATURE";
pub const TX_ERR_WITNESS_OVERFLOW: &str = "TX_ERR_WITNESS_OVERFLOW";

// MAX_TARGET is the maximum allowed PoW target. This implementation treats it as all-ones.
pub const MAX_TARGET: [u8; 32] = [0xffu8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u64,
    pub target: [u8; 32],
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Tx>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockValidationContext {
    pub height: u64,
    pub ancestor_headers: Vec<BlockHeader>, // ordered from oldest to newest, parent is last
    pub local_time: u64,
    pub local_time_set: bool,
    pub suite_id_02_active: bool,
    pub htlc_v2_active: bool,
}

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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TxOutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoEntry {
    pub output: TxOutput,
    pub creation_height: u64,
    pub created_by_coinbase: bool,
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
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn read_compact_size(&mut self) -> Result<u64, String> {
        let (n, consumed) = compact_size_decode(&self.bytes[self.pos..])?;
        self.pos += consumed;
        Ok(n)
    }
}

pub fn parse_tx_bytes(bytes: &[u8]) -> Result<Tx, String> {
    let mut cursor = Cursor::new(bytes);
    let tx = parse_tx_from_cursor(&mut cursor)?;
    if cursor.pos != bytes.len() {
        return Err("parse: trailing bytes".into());
    }
    Ok(tx)
}

fn parse_tx_from_cursor(cursor: &mut Cursor<'_>) -> Result<Tx, String> {
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

pub fn compute_key_id(provider: &dyn CryptoProvider, pubkey: &[u8]) -> Result<[u8; 32], String> {
    provider.sha3_256(pubkey)
}

fn parse_u64_le(bytes: &[u8], start: usize, name: &str) -> Result<u64, String> {
    if bytes.len() < start + 8 {
        return Err(format!("parse: {name} truncated"));
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&bytes[start..start + 8]);
    Ok(u64::from_le_bytes(v))
}

fn is_script_sig_zero_len(item_name: &str, script_sig_len: usize) -> Result<(), String> {
    if script_sig_len != 0 {
        return Err(format!("parse: {item_name} script_sig must be empty"));
    }
    Ok(())
}

fn validate_htlc_script_sig_len(script_sig_len: usize) -> Result<(), String> {
    match script_sig_len {
        0 | 32 => Ok(()),
        _ => Err("TX_ERR_PARSE".into()),
    }
}

fn check_witness_format(
    item: &WitnessItem,
    suite_activation_slh_active: bool,
) -> Result<(), String> {
    if item.suite_id == SUITE_ID_SENTINEL {
        if !item.pubkey.is_empty() || !item.signature.is_empty() {
            return Err("TX_ERR_PARSE".into());
        }
        return Ok(());
    }
    if item.suite_id == SUITE_ID_ML_DSA {
        if item.pubkey.len() != ML_DSA_PUBKEY_BYTES || item.signature.len() != ML_DSA_SIG_BYTES {
            return Err("TX_ERR_SIG_NONCANONICAL".into());
        }
        return Ok(());
    }
    if item.suite_id == SUITE_ID_SLH_DSA {
        if !suite_activation_slh_active {
            return Err("TX_ERR_DEPLOYMENT_INACTIVE".into());
        }
        if item.pubkey.len() != SLH_DSA_PUBKEY_BYTES
            || item.signature.is_empty()
            || item.signature.len() > SLH_DSA_SIG_MAX_BYTES
        {
            return Err("TX_ERR_SIG_NONCANONICAL".into());
        }
        return Ok(());
    }
    Err("TX_ERR_SIG_ALG_INVALID".into())
}

fn satisfy_lock(lock_mode: u8, lock_value: u64, height: u64, timestamp: u64) -> Result<(), String> {
    match lock_mode {
        TIMELOCK_MODE_HEIGHT => {
            if height >= lock_value {
                Ok(())
            } else {
                Err("TX_ERR_TIMELOCK_NOT_MET".into())
            }
        }
        TIMELOCK_MODE_TIMESTAMP => {
            if timestamp >= lock_value {
                Ok(())
            } else {
                Err("TX_ERR_TIMELOCK_NOT_MET".into())
            }
        }
        _ => Err("TX_ERR_PARSE".into()),
    }
}

fn add_u64(a: u64, b: u64) -> Result<u64, String> {
    match a.checked_add(b) {
        Some(v) => Ok(v),
        None => Err("TX_ERR_PARSE".to_string()),
    }
}

fn sub_u64(a: u64, b: u64) -> Result<u64, String> {
    if b > a {
        return Err("TX_ERR_VALUE_CONSERVATION".into());
    }
    Ok(a - b)
}

fn is_zero_outpoint(txid: &[u8; 32], vout: u32) -> bool {
    txid == &[0u8; 32] && vout == TX_COINBASE_PREVOUT_VOUT
}

fn is_coinbase_tx(tx: &Tx, block_height: u64) -> bool {
    if tx.inputs.len() != 1 {
        return false;
    }
    if tx.locktime as u64 != block_height {
        return false;
    }
    if tx.tx_nonce != 0 {
        return false;
    }
    if !tx.witness.witnesses.is_empty() {
        return false;
    }
    let txin = &tx.inputs[0];
    is_zero_outpoint(&txin.prev_txid, txin.prev_vout)
        && txin.sequence == TX_COINBASE_PREVOUT_VOUT
        && txin.script_sig.is_empty()
}

fn validate_coinbase_tx_inputs(tx: &Tx) -> Result<(), String> {
    if tx.tx_nonce != 0 {
        return Err(BLOCK_ERR_COINBASE_INVALID.into());
    }
    if tx.inputs.len() != 1 {
        return Err(BLOCK_ERR_COINBASE_INVALID.into());
    }
    let input = &tx.inputs[0];
    if input.sequence != TX_COINBASE_PREVOUT_VOUT {
        return Err(BLOCK_ERR_COINBASE_INVALID.into());
    }
    if !is_zero_outpoint(&input.prev_txid, input.prev_vout) {
        return Err(BLOCK_ERR_COINBASE_INVALID.into());
    }
    if !input.script_sig.is_empty() {
        return Err(BLOCK_ERR_COINBASE_INVALID.into());
    }
    if !tx.witness.witnesses.is_empty() {
        return Err(BLOCK_ERR_COINBASE_INVALID.into());
    }
    Ok(())
}

fn validate_output_covenant_constraints(output: &TxOutput) -> Result<(), String> {
    match output.covenant_type {
        CORE_P2PK => {
            if output.covenant_data.len() != 33 {
                return Err("TX_ERR_PARSE".into());
            }
        }
        CORE_TIMELOCK_V1 => {
            if output.covenant_data.len() != 9 {
                return Err("TX_ERR_PARSE".into());
            }
        }
        CORE_ANCHOR => {
            if output.value != 0 {
                return Err("TX_ERR_COVENANT_TYPE_INVALID".into());
            }
            if output.covenant_data.is_empty()
                || output.covenant_data.len() > MAX_ANCHOR_PAYLOAD_SIZE
            {
                return Err("TX_ERR_COVENANT_TYPE_INVALID".into());
            }
        }
        CORE_HTLC_V1 => {
            if output.covenant_data.len() != 105 {
                return Err("TX_ERR_PARSE".into());
            }
        }
        CORE_HTLC_V2 => {
            // Deployment gate checked at spend time, not output creation time.
            // Output-level constraint: same covenant_data layout as HTLC_V1.
            if output.covenant_data.len() != 105 {
                return Err("TX_ERR_PARSE".into());
            }
            let claim_key_id = &output.covenant_data[41..73];
            let refund_key_id = &output.covenant_data[73..105];
            if claim_key_id == refund_key_id {
                return Err("TX_ERR_PARSE".into());
            }
        }
        CORE_VAULT_V1 => {
            if output.covenant_data.len() != 73 && output.covenant_data.len() != 81 {
                return Err("TX_ERR_PARSE".into());
            }
        }
        CORE_RESERVED_FUTURE => return Err("TX_ERR_COVENANT_TYPE_INVALID".into()),
        _ => return Err("TX_ERR_COVENANT_TYPE_INVALID".into()),
    }
    Ok(())
}

pub fn tx_weight(tx: &Tx) -> Result<u64, String> {
    let base = tx_no_witness_bytes(tx).len();
    let witness = witness_bytes(&tx.witness).len();
    let mut sig_cost: u64 = 0;
    for (i, item) in tx.witness.witnesses.iter().enumerate() {
        if i < tx.inputs.len() {
            match item.suite_id {
                SUITE_ID_ML_DSA => sig_cost = sig_cost.saturating_add(VERIFY_COST_ML_DSA as u64),
                SUITE_ID_SLH_DSA => sig_cost = sig_cost.saturating_add(VERIFY_COST_SLH_DSA as u64),
                _ => {}
            }
        }
    }
    let base_weight = (base as u64)
        .checked_mul(4)
        .ok_or_else(|| "TX_ERR_PARSE".to_string())?;
    add_u64(add_u64(base_weight, witness as u64)?, sig_cost)
}

pub fn block_header_bytes(h: &BlockHeader) -> [u8; 116] {
    let mut out = [0u8; 116];
    out[0..4].copy_from_slice(&h.version.to_le_bytes());
    out[4..36].copy_from_slice(&h.prev_block_hash);
    out[36..68].copy_from_slice(&h.merkle_root);
    out[68..76].copy_from_slice(&h.timestamp.to_le_bytes());
    out[76..108].copy_from_slice(&h.target);
    out[108..116].copy_from_slice(&h.nonce.to_le_bytes());
    out
}

pub fn block_header_hash(
    provider: &dyn CryptoProvider,
    h: &BlockHeader,
) -> Result<[u8; 32], String> {
    provider.sha3_256(&block_header_bytes(h))
}

fn parse_block_header_from_cursor(cursor: &mut Cursor<'_>) -> Result<BlockHeader, String> {
    let version = cursor.read_u32le()?;
    let prev_block_hash_slice = cursor.read_exact(32)?;
    let mut prev_block_hash = [0u8; 32];
    prev_block_hash.copy_from_slice(prev_block_hash_slice);
    let merkle_root_slice = cursor.read_exact(32)?;
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(merkle_root_slice);
    let timestamp = cursor.read_u64le()?;
    let target_slice = cursor.read_exact(32)?;
    let mut target = [0u8; 32];
    target.copy_from_slice(target_slice);
    let nonce = cursor.read_u64le()?;
    Ok(BlockHeader {
        version,
        prev_block_hash,
        merkle_root,
        timestamp,
        target,
        nonce,
    })
}

pub fn parse_block_bytes(bytes: &[u8]) -> Result<Block, String> {
    let mut cursor = Cursor::new(bytes);
    let header = parse_block_header_from_cursor(&mut cursor)?;
    let tx_count_u64 = cursor.read_compact_size()?;
    let tx_count: usize = tx_count_u64
        .try_into()
        .map_err(|_| "parse: tx_count overflows usize".to_string())?;
    let mut txs = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        let tx = parse_tx_from_cursor(&mut cursor)?;
        txs.push(tx);
    }
    if cursor.pos != bytes.len() {
        return Err("parse: trailing bytes".into());
    }
    Ok(Block {
        header,
        transactions: txs,
    })
}

fn merkle_root_txids(provider: &dyn CryptoProvider, txs: &[Tx]) -> Result<[u8; 32], String> {
    if txs.is_empty() {
        return Err(BLOCK_ERR_MERKLE_INVALID.into());
    }
    let mut level: Vec<[u8; 32]> = Vec::with_capacity(txs.len());
    for tx in txs {
        let txid = txid(provider, tx)?;
        let mut leaf = Vec::with_capacity(1 + 32);
        leaf.push(0x00);
        leaf.extend_from_slice(&txid);
        level.push(provider.sha3_256(&leaf)?);
    }
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            if i + 1 == level.len() {
                next.push(level[i]);
                i += 1;
                continue;
            }
            let mut concat = Vec::with_capacity(1 + 32 + 32);
            concat.push(0x01);
            concat.extend_from_slice(&level[i]);
            concat.extend_from_slice(&level[i + 1]);
            next.push(provider.sha3_256(&concat)?);
            i += 2;
        }
        level = next;
    }
    Ok(level[0])
}

fn median_past_timestamp(headers: &[BlockHeader], height: u64) -> Result<u64, String> {
    if height == 0 || headers.is_empty() {
        return Err(BLOCK_ERR_TIMESTAMP_OLD.into());
    }
    let mut k = 11u64;
    if height < k {
        k = height;
    }
    let mut limit = k as usize;
    if headers.len() < limit {
        limit = headers.len();
    }
    let mut timestamps = Vec::with_capacity(limit);
    for i in 0..limit {
        timestamps.push(headers[headers.len() - 1 - i].timestamp);
    }
    timestamps.sort_unstable();
    Ok(timestamps[(timestamps.len() - 1) / 2])
}

fn u256_from_be_bytes32(b: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let start = i * 8;
        limbs[i] = u64::from_be_bytes([
            b[start],
            b[start + 1],
            b[start + 2],
            b[start + 3],
            b[start + 4],
            b[start + 5],
            b[start + 6],
            b[start + 7],
        ]);
    }
    limbs
}

fn u256_to_be_bytes32(limbs: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&limbs[i].to_be_bytes());
    }
    out
}

fn u256_cmp(a: &[u64; 4], b: &[u64; 4]) -> core::cmp::Ordering {
    for i in 0..4 {
        if a[i] < b[i] {
            return core::cmp::Ordering::Less;
        }
        if a[i] > b[i] {
            return core::cmp::Ordering::Greater;
        }
    }
    core::cmp::Ordering::Equal
}

fn u256_is_zero(a: &[u64; 4]) -> bool {
    a.iter().all(|v| *v == 0)
}

fn u256_shr2(a: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry: u64 = 0;
    for i in 0..4 {
        let v = a[i];
        out[i] = (carry << 62) | (v >> 2);
        carry = v & 0x3;
    }
    out
}

fn u256_shl2_saturating(a: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry: u64 = 0;
    for i in (0..4).rev() {
        let v = a[i];
        out[i] = (v << 2) | carry;
        carry = v >> 62;
    }
    if carry != 0 {
        // overflow => saturate
        return u256_from_be_bytes32(&MAX_TARGET);
    }
    out
}

fn u256_mul_u64_to_u320(a: &[u64; 4], m: u64) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut carry: u128 = 0;
    for i in (0..4).rev() {
        let prod = (a[i] as u128) * (m as u128) + carry;
        out[i + 1] = (prod & 0xffff_ffff_ffff_ffff) as u64;
        carry = prod >> 64;
    }
    out[0] = carry as u64;
    out
}

fn u320_div_u64_to_u256(n: &[u64; 5], d: u64) -> Result<[u64; 4], String> {
    if d == 0 {
        return Err(BLOCK_ERR_TARGET_INVALID.into());
    }
    let mut q = [0u64; 4];
    let mut rem: u128 = 0;
    for i in 0..5 {
        let limb = n[i] as u128;
        let cur = (rem << 64) | limb;
        let q_limb = cur / (d as u128);
        rem = cur % (d as u128);
        if i > 0 {
            q[i - 1] = q_limb as u64;
        } else if q_limb != 0 {
            // quotient exceeds 256-bit; saturate
            return Ok(u256_from_be_bytes32(&MAX_TARGET));
        }
    }
    Ok(q)
}

fn block_expected_target(
    headers: &[BlockHeader],
    height: u64,
    target_in: &[u8; 32],
) -> Result<[u8; 32], String> {
    if height == 0 {
        return Ok(*target_in);
    }
    if headers.is_empty() {
        return Err(BLOCK_ERR_TARGET_INVALID.into());
    }

    let target_old = u256_from_be_bytes32(&headers[headers.len() - 1].target);
    if (height % WINDOW_SIZE) != 0 {
        return Ok(u256_to_be_bytes32(&target_old));
    }

    let window = WINDOW_SIZE as usize;
    if headers.len() < window {
        return Err(BLOCK_ERR_TARGET_INVALID.into());
    }

    let first_ts = headers[headers.len() - window].timestamp;
    let last_ts = headers[headers.len() - 1].timestamp;
    let t_actual = if last_ts >= first_ts {
        last_ts - first_ts
    } else {
        1
    };
    let t_expected = TARGET_BLOCK_INTERVAL * WINDOW_SIZE;

    let n320 = u256_mul_u64_to_u320(&target_old, t_actual);
    let mut target_new = u320_div_u64_to_u256(&n320, t_expected)?;

    // clamp to [target_old/4, target_old*4]
    let mut min_target = u256_shr2(&target_old);
    if u256_is_zero(&min_target) {
        min_target = [0, 0, 0, 1];
    }
    let max_target = u256_shl2_saturating(&target_old);

    if u256_cmp(&target_new, &min_target) == core::cmp::Ordering::Less {
        target_new = min_target;
    }
    if u256_cmp(&target_new, &max_target) == core::cmp::Ordering::Greater {
        target_new = max_target;
    }

    Ok(u256_to_be_bytes32(&target_new))
}

fn block_reward_for_height(height: u64) -> u64 {
    // v1.1 consensus constants (linear emission; no halving; no tail).
    const SUBSIDY_TOTAL_MINED: u64 = 9_900_000_000_000_000; // 99,000,000 RBN @ 1e8 base units
    const SUBSIDY_DURATION_BLOCKS: u64 = 1_314_900; // fixed schedule in blocks

    if height >= SUBSIDY_DURATION_BLOCKS {
        return 0;
    }

    let base = SUBSIDY_TOTAL_MINED / SUBSIDY_DURATION_BLOCKS;
    let rem = SUBSIDY_TOTAL_MINED % SUBSIDY_DURATION_BLOCKS;
    if height < rem {
        base + 1
    } else {
        base
    }
}

fn tx_sums(tx: &Tx, utxo: &HashMap<TxOutPoint, UtxoEntry>) -> Result<(u64, u64), String> {
    let mut input_sum = 0u64;
    let mut output_sum = 0u64;
    for input in &tx.inputs {
        let prev = TxOutPoint {
            txid: input.prev_txid,
            vout: input.prev_vout,
        };
        let entry = utxo
            .get(&prev)
            .ok_or_else(|| "TX_ERR_MISSING_UTXO".to_string())?;
        input_sum = add_u64(input_sum, entry.output.value)?;
    }
    for output in &tx.outputs {
        output_sum = add_u64(output_sum, output.value)?;
    }
    Ok((input_sum, output_sum))
}

pub fn apply_block(
    provider: &dyn CryptoProvider,
    chain_id: &[u8; 32],
    block: &Block,
    utxo: &mut HashMap<TxOutPoint, UtxoEntry>,
    ctx: &BlockValidationContext,
) -> Result<(), String> {
    if block.transactions.is_empty() {
        return Err(BLOCK_ERR_COINBASE_INVALID.into());
    }

    if ctx.height > 0 && ctx.ancestor_headers.is_empty() {
        return Err(BLOCK_ERR_LINKAGE_INVALID.into());
    }

    if ctx.height == 0 {
        if block.header.prev_block_hash != [0u8; 32] {
            return Err(BLOCK_ERR_LINKAGE_INVALID.into());
        }
    } else {
        let parent = ctx
            .ancestor_headers
            .last()
            .ok_or_else(|| BLOCK_ERR_LINKAGE_INVALID.to_string())?;
        let parent_hash = block_header_hash(provider, parent)?;
        if block.header.prev_block_hash != parent_hash {
            return Err(BLOCK_ERR_LINKAGE_INVALID.into());
        }
    }

    let expected_target =
        block_expected_target(&ctx.ancestor_headers, ctx.height, &block.header.target)?;
    if expected_target != block.header.target {
        return Err(BLOCK_ERR_TARGET_INVALID.into());
    }

    let bhash = block_header_hash(provider, &block.header)?;
    if bhash.as_slice() >= block.header.target.as_slice() {
        return Err(BLOCK_ERR_POW_INVALID.into());
    }

    let merkle = merkle_root_txids(provider, &block.transactions)?;
    if merkle != block.header.merkle_root {
        return Err(BLOCK_ERR_MERKLE_INVALID.into());
    }

    if ctx.height > 0 {
        let median_ts = median_past_timestamp(&ctx.ancestor_headers, ctx.height)?;
        if block.header.timestamp <= median_ts {
            return Err(BLOCK_ERR_TIMESTAMP_OLD.into());
        }
        if ctx.local_time_set && block.header.timestamp > ctx.local_time + MAX_FUTURE_DRIFT {
            return Err(BLOCK_ERR_TIMESTAMP_FUTURE.into());
        }
    }

    let mut coinbase_count = 0u64;
    for (i, tx) in block.transactions.iter().enumerate() {
        if is_coinbase_tx(tx, ctx.height) {
            coinbase_count += 1;
            if i != 0 {
                return Err(BLOCK_ERR_COINBASE_INVALID.into());
            }
        }
    }
    if coinbase_count != 1 {
        return Err(BLOCK_ERR_COINBASE_INVALID.into());
    }

    let mut working_utxo = utxo.clone();
    let mut total_weight = 0u64;
    let mut total_anchor_bytes = 0u64;
    let mut total_fees = 0u64;
    let mut seen_nonces: HashSet<u64> = HashSet::with_capacity(block.transactions.len());

    for tx in &block.transactions {
        total_weight = add_u64(total_weight, tx_weight(tx)?)?;

        let is_coinbase = is_coinbase_tx(tx, ctx.height);
        if !is_coinbase {
            if seen_nonces.contains(&tx.tx_nonce) {
                return Err(TX_ERR_NONCE_REPLAY.into());
            }
            seen_nonces.insert(tx.tx_nonce);
        }

        apply_tx(
            provider,
            chain_id,
            tx,
            &working_utxo,
            ctx.height,
            block.header.timestamp,
            ctx.htlc_v2_active,
            ctx.suite_id_02_active,
        )?;

        if !is_coinbase {
            let (in_sum, out_sum) = tx_sums(tx, &working_utxo)?;
            let fee = sub_u64(in_sum, out_sum)?;
            total_fees = add_u64(total_fees, fee)?;

            for input in &tx.inputs {
                working_utxo.remove(&TxOutPoint {
                    txid: input.prev_txid,
                    vout: input.prev_vout,
                });
            }
        }

        let txid_v = txid(provider, tx)?;
        for (vout, out) in tx.outputs.iter().enumerate() {
            if out.covenant_type == CORE_ANCHOR {
                total_anchor_bytes = add_u64(total_anchor_bytes, out.covenant_data.len() as u64)?;
                continue;
            }
            working_utxo.insert(
                TxOutPoint {
                    txid: txid_v,
                    vout: vout as u32,
                },
                UtxoEntry {
                    output: out.clone(),
                    creation_height: ctx.height,
                    created_by_coinbase: is_coinbase,
                },
            );
        }
    }

    if total_weight > MAX_BLOCK_WEIGHT {
        return Err(BLOCK_ERR_WEIGHT_EXCEEDED.into());
    }
    if total_anchor_bytes > MAX_ANCHOR_BYTES_PER_BLOCK {
        return Err(BLOCK_ERR_ANCHOR_BYTES_EXCEEDED.into());
    }

    let mut coinbase_value = 0u64;
    for out in &block.transactions[0].outputs {
        coinbase_value = add_u64(coinbase_value, out.value)?;
    }
    if ctx.height != 0 {
        let max_coinbase = add_u64(block_reward_for_height(ctx.height), total_fees)?;
        if coinbase_value > max_coinbase {
            return Err(BLOCK_ERR_SUBSIDY_EXCEEDED.into());
        }
    }

    utxo.clear();
    for (k, v) in working_utxo {
        utxo.insert(k, v);
    }
    Ok(())
}

pub fn validate_input_authorization(
    provider: &dyn CryptoProvider,
    chain_id: &[u8; 32],
    tx: &Tx,
    input_index: usize,
    prev_value: u64,
    prevout: &TxOutput,
    prev_creation_height: u64,
    chain_height: u64,
    chain_timestamp: u64,
    htlc_v2_active: bool,
    suite_id_02_active: bool,
) -> Result<(), String> {
    if tx.inputs.is_empty() || input_index >= tx.inputs.len() {
        return Err("TX_ERR_PARSE".into());
    }
    if input_index >= tx.witness.witnesses.len() {
        return Err("TX_ERR_PARSE".into());
    }
    let input = &tx.inputs[input_index];
    let witness = &tx.witness.witnesses[input_index];

    match prevout.covenant_type {
        CORE_P2PK => {
            is_script_sig_zero_len("CORE_P2PK", input.script_sig.len())?;
            if witness.suite_id == SUITE_ID_SENTINEL {
                return Err("TX_ERR_SIG_ALG_INVALID".into());
            }
            check_witness_format(witness, suite_id_02_active)?;

            if prevout.covenant_data.len() != 33 {
                return Err("TX_ERR_PARSE".into());
            }
            let suite_id = prevout.covenant_data[0];
            if suite_id != witness.suite_id {
                return Err("TX_ERR_SIG_INVALID".into());
            }
            let expected_key_id = &prevout.covenant_data[1..33];
            let actual_key_id = compute_key_id(provider, &witness.pubkey)?;
            if actual_key_id.as_slice() != expected_key_id {
                return Err("TX_ERR_SIG_INVALID".into());
            }
        }
        CORE_TIMELOCK_V1 => {
            is_script_sig_zero_len("CORE_TIMELOCK_V1", input.script_sig.len())?;
            if witness.suite_id != SUITE_ID_SENTINEL {
                return Err("TX_ERR_SIG_ALG_INVALID".into());
            }
            if prevout.covenant_data.len() != 9 {
                return Err("TX_ERR_PARSE".into());
            }
            let lock_mode = prevout.covenant_data[0];
            let lock_value = parse_u64_le(&prevout.covenant_data, 1, "covenant_lock_value")?;
            satisfy_lock(lock_mode, lock_value, chain_height, chain_timestamp)?;
            return Ok(());
        }
        CORE_HTLC_V1 => {
            validate_htlc_script_sig_len(input.script_sig.len())?;
            if witness.suite_id == SUITE_ID_SENTINEL {
                return Err("TX_ERR_SIG_ALG_INVALID".into());
            }
            check_witness_format(witness, suite_id_02_active)?;

            if prevout.covenant_data.len() != 105 {
                return Err("TX_ERR_PARSE".into());
            }
            let lock_mode = prevout.covenant_data[32];
            let lock_value = parse_u64_le(&prevout.covenant_data, 33, "htlc_lock_value")?;
            if input.script_sig.len() == 32 {
                let expected_hash = &prevout.covenant_data[0..32];
                let script_hash = provider.sha3_256(&input.script_sig)?;
                if script_hash.as_slice() != expected_hash {
                    return Err("TX_ERR_SIG_INVALID".into());
                }
                let expected_claim_key_id = &prevout.covenant_data[41..73];
                let actual_key_id = compute_key_id(provider, &witness.pubkey)?;
                if actual_key_id.as_slice() != expected_claim_key_id {
                    return Err("TX_ERR_SIG_INVALID".into());
                }
            } else {
                let expected_refund_key_id = &prevout.covenant_data[73..105];
                let actual_key_id = compute_key_id(provider, &witness.pubkey)?;
                if actual_key_id.as_slice() != expected_refund_key_id {
                    return Err("TX_ERR_SIG_INVALID".into());
                }
                satisfy_lock(lock_mode, lock_value, chain_height, chain_timestamp)?;
            }
        }
        CORE_HTLC_V2 => {
            // Deployment gate (spend-time only).
            if !htlc_v2_active {
                return Err("TX_ERR_DEPLOYMENT_INACTIVE".into());
            }
            if input.script_sig.len() != 0 {
                return Err("TX_ERR_PARSE".into());
            }
            if witness.suite_id == SUITE_ID_SENTINEL {
                return Err("TX_ERR_SIG_ALG_INVALID".into());
            }
            check_witness_format(witness, suite_id_02_active)?;

            if prevout.covenant_data.len() != 105 {
                return Err("TX_ERR_PARSE".into());
            }
            let claim_key_id = &prevout.covenant_data[41..73];
            let refund_key_id = &prevout.covenant_data[73..105];
            if claim_key_id == refund_key_id {
                return Err("TX_ERR_PARSE".into());
            }

            let expected_hash = &prevout.covenant_data[0..32];
            let lock_mode = prevout.covenant_data[32];
            let lock_value = parse_u64_le(&prevout.covenant_data, 33, "htlc2_lock_value")?;

            // Scan ANCHOR outputs for matching HTLC_V2 envelope
            // prefix = ASCII("RUBINv1-htlc-preimage/") — 22 bytes, total envelope = 54 bytes
            const HTLC_V2_PREFIX: &[u8] = b"RUBINv1-htlc-preimage/";
            const HTLC_V2_ENVELOPE_LEN: usize = 54;

            let mut matching_anchors = 0usize;
            let mut matching_anchor: Option<&[u8]> = None;
            for out in &tx.outputs {
                if out.covenant_type != CORE_ANCHOR {
                    continue;
                }
                if out.covenant_data.len() != HTLC_V2_ENVELOPE_LEN {
                    continue;
                }
                if &out.covenant_data[0..HTLC_V2_PREFIX.len()] != HTLC_V2_PREFIX {
                    continue;
                }
                matching_anchors += 1;
                matching_anchor = Some(&out.covenant_data);
                if matching_anchors >= 2 {
                    break;
                }
            }

            match matching_anchors {
                0 => {
                    // Refund path
                    let actual_key_id = compute_key_id(provider, &witness.pubkey)?;
                    if actual_key_id.as_slice() != refund_key_id {
                        return Err("TX_ERR_SIG_INVALID".into());
                    }
                    satisfy_lock(lock_mode, lock_value, chain_height, chain_timestamp)?;
                }
                1 => {
                    // Claim path
                    let env = matching_anchor.ok_or_else(|| "TX_ERR_PARSE".to_string())?;
                    let preimage32 = &env[HTLC_V2_PREFIX.len()..];
                    let preimage_hash = provider.sha3_256(preimage32)?;
                    if preimage_hash.as_slice() != expected_hash {
                        return Err("TX_ERR_SIG_INVALID".into());
                    }
                    let actual_key_id = compute_key_id(provider, &witness.pubkey)?;
                    if actual_key_id.as_slice() != claim_key_id {
                        return Err("TX_ERR_SIG_INVALID".into());
                    }
                }
                _ => {
                    // Two or more matching envelopes — non-deterministic, reject
                    return Err("TX_ERR_PARSE".into());
                }
            }
        }
        CORE_VAULT_V1 => {
            is_script_sig_zero_len("CORE_VAULT_V1", input.script_sig.len())?;
            if witness.suite_id == SUITE_ID_SENTINEL {
                return Err("TX_ERR_SIG_ALG_INVALID".into());
            }
            check_witness_format(witness, suite_id_02_active)?;

            let (owner_key_id, spend_delay, lock_mode, lock_value, recovery_key_id) = match prevout
                .covenant_data
                .len()
            {
                73 => {
                    let owner_key_id = &prevout.covenant_data[0..32];
                    let lock_mode = prevout.covenant_data[32];
                    let lock_value = parse_u64_le(&prevout.covenant_data, 33, "vault_lock_value")?;
                    let recovery_key_id = &prevout.covenant_data[41..73];
                    (owner_key_id, 0u64, lock_mode, lock_value, recovery_key_id)
                }
                81 => {
                    let owner_key_id = &prevout.covenant_data[0..32];
                    let spend_delay =
                        parse_u64_le(&prevout.covenant_data, 32, "vault_spend_delay")?;
                    let lock_mode = prevout.covenant_data[40];
                    let lock_value = parse_u64_le(&prevout.covenant_data, 41, "vault_lock_value")?;
                    let recovery_key_id = &prevout.covenant_data[49..81];
                    (
                        owner_key_id,
                        spend_delay,
                        lock_mode,
                        lock_value,
                        recovery_key_id,
                    )
                }
                _ => return Err("TX_ERR_PARSE".into()),
            };
            if lock_mode != TIMELOCK_MODE_HEIGHT && lock_mode != TIMELOCK_MODE_TIMESTAMP {
                return Err("TX_ERR_PARSE".into());
            }
            if owner_key_id == recovery_key_id {
                return Err("TX_ERR_PARSE".into());
            }
            let actual_key_id = compute_key_id(provider, &witness.pubkey)?;

            if actual_key_id.as_slice() != owner_key_id
                && actual_key_id.as_slice() != recovery_key_id
            {
                return Err("TX_ERR_SIG_INVALID".into());
            }
            if actual_key_id.as_slice() == owner_key_id && spend_delay > 0 {
                if chain_height < prev_creation_height + spend_delay {
                    return Err("TX_ERR_TIMELOCK_NOT_MET".into());
                }
            }
            if actual_key_id.as_slice() == recovery_key_id {
                satisfy_lock(lock_mode, lock_value, chain_height, chain_timestamp)?;
            }
        }
        CORE_ANCHOR => return Err("TX_ERR_MISSING_UTXO".into()),
        CORE_RESERVED_FUTURE => return Err("TX_ERR_COVENANT_TYPE_INVALID".into()),
        _ => return Err("TX_ERR_COVENANT_TYPE_INVALID".into()),
    };

    let digest = sighash_v1_digest(provider, chain_id, tx, input_index as u32, prev_value)?;
    match witness.suite_id {
        SUITE_ID_ML_DSA => {
            let valid = provider
                .verify_mldsa87(&witness.pubkey, &witness.signature, &digest)
                .map_err(|_| "TX_ERR_SIG_INVALID".to_string())?;
            if valid {
                Ok(())
            } else {
                Err("TX_ERR_SIG_INVALID".into())
            }
        }
        SUITE_ID_SLH_DSA => {
            let valid = provider
                .verify_slhdsa_shake_256f(&witness.pubkey, &witness.signature, &digest)
                .map_err(|_| "TX_ERR_SIG_INVALID".to_string())?;
            if valid {
                Ok(())
            } else {
                Err("TX_ERR_SIG_INVALID".into())
            }
        }
        SUITE_ID_SENTINEL => {
            // Timelock-only covenants use empty witness and are already validated above.
            Ok(())
        }
        _ => Err("TX_ERR_SIG_ALG_INVALID".into()),
    }
}

pub fn apply_tx(
    provider: &dyn CryptoProvider,
    chain_id: &[u8; 32],
    tx: &Tx,
    utxo: &HashMap<TxOutPoint, UtxoEntry>,
    chain_height: u64,
    chain_timestamp: u64,
    htlc_v2_active: bool,
    suite_id_02_active: bool,
) -> Result<(), String> {
    if tx.inputs.len() > MAX_TX_INPUTS || tx.outputs.len() > MAX_TX_OUTPUTS {
        return Err("TX_ERR_PARSE".to_string());
    }
    if tx.witness.witnesses.len() > MAX_WITNESS_ITEMS {
        return Err(TX_ERR_WITNESS_OVERFLOW.to_string());
    }
    if witness_bytes(&tx.witness).len() > MAX_WITNESS_BYTES_PER_TX {
        return Err(TX_ERR_WITNESS_OVERFLOW.to_string());
    }
    if is_coinbase_tx(tx, chain_height) {
        validate_coinbase_tx_inputs(tx)?;
        for out in &tx.outputs {
            validate_output_covenant_constraints(out)?;
        }
        return Ok(());
    }

    if tx.tx_nonce == TX_NONCE_ZERO {
        return Err(TX_ERR_TX_NONCE_INVALID.to_string());
    }
    if tx.inputs.len() != tx.witness.witnesses.len() {
        return Err("TX_ERR_PARSE".to_string());
    }
    for out in &tx.outputs {
        validate_output_covenant_constraints(out)?;
    }

    let mut seen = HashSet::with_capacity(tx.inputs.len());
    let mut total_inputs = 0u64;
    let mut total_outputs = 0u64;

    for (input_index, input) in tx.inputs.iter().enumerate() {
        if input.sequence == TX_COINBASE_PREVOUT_VOUT || input.sequence > TX_MAX_SEQUENCE {
            return Err(TX_ERR_SEQUENCE_INVALID.to_string());
        }
        let prevout = TxOutPoint {
            txid: input.prev_txid,
            vout: input.prev_vout,
        };
        if is_zero_outpoint(&prevout.txid, prevout.vout) {
            return Err("TX_ERR_PARSE".to_string());
        }
        if !seen.insert(prevout.clone()) {
            return Err("TX_ERR_PARSE".to_string());
        }

        let prev = utxo
            .get(&prevout)
            .ok_or_else(|| "TX_ERR_MISSING_UTXO".to_string())?;

        validate_input_authorization(
            provider,
            chain_id,
            tx,
            input_index,
            prev.output.value,
            &prev.output,
            prev.creation_height,
            chain_height,
            chain_timestamp,
            htlc_v2_active,
            suite_id_02_active,
        )?;

        if prev.created_by_coinbase && chain_height < prev.creation_height + COINBASE_MATURITY {
            return Err(TX_ERR_COINBASE_IMMATURE.to_string());
        }

        total_inputs = add_u64(total_inputs, prev.output.value)?;
    }

    for output in &tx.outputs {
        total_outputs = add_u64(total_outputs, output.value)?;
    }

    if total_outputs > total_inputs {
        return Err("TX_ERR_VALUE_CONSERVATION".into());
    }
    Ok(())
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
    use std::collections::HashMap;

    struct TestProvider;

    impl TestProvider {
        fn simple_hash(input: &[u8]) -> [u8; 32] {
            let mut out = [0u8; 32];
            for (i, byte) in input.iter().enumerate() {
                out[i % 32] = out[i % 32].wrapping_add(*byte).wrapping_add(i as u8);
            }
            out
        }
    }

    impl CryptoProvider for TestProvider {
        fn sha3_256(&self, input: &[u8]) -> Result<[u8; 32], String> {
            Ok(Self::simple_hash(input))
        }

        fn verify_mldsa87(
            &self,
            _pubkey: &[u8],
            _sig: &[u8],
            _digest32: &[u8; 32],
        ) -> Result<bool, String> {
            Ok(true)
        }

        fn verify_slhdsa_shake_256f(
            &self,
            _pubkey: &[u8],
            _sig: &[u8],
            _digest32: &[u8; 32],
        ) -> Result<bool, String> {
            Ok(true)
        }
    }

    fn make_htlc_output(
        preimage: &[u8; 32],
        lock_height: u64,
        claim_key_id: [u8; 32],
        refund_key_id: [u8; 32],
    ) -> TxOutput {
        let mut covenant_data = Vec::with_capacity(105);
        covenant_data.extend_from_slice(&TestProvider::simple_hash(preimage));
        covenant_data.push(TIMELOCK_MODE_HEIGHT);
        covenant_data.extend_from_slice(&lock_height.to_le_bytes());
        covenant_data.extend_from_slice(&claim_key_id);
        covenant_data.extend_from_slice(&refund_key_id);
        TxOutput {
            value: 100,
            covenant_type: CORE_HTLC_V1,
            covenant_data,
        }
    }

    fn make_vault_output(
        owner_key_id: [u8; 32],
        lock_height: u64,
        recovery_key_id: [u8; 32],
    ) -> TxOutput {
        let mut covenant_data = Vec::with_capacity(73);
        covenant_data.extend_from_slice(&owner_key_id);
        covenant_data.push(TIMELOCK_MODE_HEIGHT);
        covenant_data.extend_from_slice(&lock_height.to_le_bytes());
        covenant_data.extend_from_slice(&recovery_key_id);
        TxOutput {
            value: 100,
            covenant_type: CORE_VAULT_V1,
            covenant_data,
        }
    }

    fn make_input(script_sig: Vec<u8>, sequence: u32) -> TxInput {
        TxInput {
            prev_txid: [0u8; 32],
            prev_vout: 0,
            script_sig,
            sequence,
        }
    }

    fn make_input_witness(suite_id: u8, pubkey: Vec<u8>, sig: Vec<u8>) -> WitnessItem {
        WitnessItem {
            suite_id,
            pubkey,
            signature: sig,
        }
    }

    fn make_tx(input: TxInput, witness: WitnessItem) -> Tx {
        Tx {
            version: 1,
            tx_nonce: 1,
            inputs: vec![input],
            outputs: vec![],
            locktime: 0,
            witness: WitnessSection {
                witnesses: vec![witness],
            },
        }
    }

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
        assert!(
            compact_size_decode(&[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00]).is_err()
        );
    }

    #[test]
    fn validate_htlc_rejects_bad_script_sig_len() {
        let p = TestProvider;
        let preimage = [0x11u8; 32];
        let claim_key = TestProvider::simple_hash(b"claim-key");
        let refund_key = TestProvider::simple_hash(b"refund-key");
        let prevout = make_htlc_output(&preimage, 20, claim_key, refund_key);

        let tx = make_tx(
            make_input(vec![1u8; 16], 1),
            make_input_witness(
                SUITE_ID_ML_DSA,
                vec![7u8; ML_DSA_PUBKEY_BYTES],
                vec![7u8; ML_DSA_SIG_BYTES],
            ),
        );

        let chain_id = [0u8; 32];
        let err = validate_input_authorization(
            &p, &chain_id, &tx, 0, 100, &prevout, 0, 0, 0, true, false,
        )
        .unwrap_err();
        assert_eq!(err, "TX_ERR_PARSE");
    }

    #[test]
    fn validate_htlc_refund_requires_lock() {
        let p = TestProvider;
        let preimage = [0x33u8; 32];
        let pubkey = vec![0x22u8; ML_DSA_PUBKEY_BYTES];
        let refund_pubkey_id = p.sha3_256(&pubkey).expect("hash");
        let claim_key = [0u8; 32];
        let prevout = make_htlc_output(&preimage, 100, claim_key, refund_pubkey_id);

        let tx = make_tx(
            make_input(vec![], 1),
            make_input_witness(SUITE_ID_ML_DSA, pubkey, vec![9u8; ML_DSA_SIG_BYTES]),
        );

        let chain_id = [0u8; 32];
        let err = validate_input_authorization(
            &p, &chain_id, &tx, 0, 100, &prevout, 0, 10, 0, true, false,
        )
        .unwrap_err();
        assert_eq!(err, "TX_ERR_TIMELOCK_NOT_MET");
    }

    #[test]
    fn validate_vault_owner_bypasses_lock() {
        let p = TestProvider;
        let owner_pubkey = vec![0x44u8; ML_DSA_PUBKEY_BYTES];
        let recovery_pubkey = vec![0x55u8; ML_DSA_PUBKEY_BYTES];
        let owner_key_id = p.sha3_256(&owner_pubkey).expect("hash");
        let recovery_key_id = p.sha3_256(&recovery_pubkey).expect("hash");
        let prevout = make_vault_output(owner_key_id, 1000, recovery_key_id);

        let tx = make_tx(
            make_input(vec![], 1),
            make_input_witness(SUITE_ID_ML_DSA, owner_pubkey, vec![1u8; ML_DSA_SIG_BYTES]),
        );

        let chain_id = [0u8; 32];
        let ok = validate_input_authorization(
            &p, &chain_id, &tx, 0, 100, &prevout, 0, 10, 0, true, false,
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn validate_vault_recovery_respects_lock() {
        let p = TestProvider;
        let owner_pubkey = vec![0x44u8; ML_DSA_PUBKEY_BYTES];
        let recovery_pubkey = vec![0x55u8; ML_DSA_PUBKEY_BYTES];
        let owner_key_id = p.sha3_256(&owner_pubkey).expect("hash");
        let recovery_key_id = p.sha3_256(&recovery_pubkey).expect("hash");
        let prevout = make_vault_output(owner_key_id, 1000, recovery_key_id);

        let tx = make_tx(
            make_input(vec![], 1),
            make_input_witness(
                SUITE_ID_ML_DSA,
                recovery_pubkey,
                vec![2u8; ML_DSA_SIG_BYTES],
            ),
        );

        let chain_id = [0u8; 32];
        let err = validate_input_authorization(
            &p, &chain_id, &tx, 0, 100, &prevout, 0, 10, 0, true, false,
        )
        .unwrap_err();
        assert_eq!(err, "TX_ERR_TIMELOCK_NOT_MET");
    }

    fn make_apply_tx_prevout(value: u64, covenant_type: u16, covenant_data: Vec<u8>) -> TxOutput {
        TxOutput {
            value,
            covenant_type,
            covenant_data,
        }
    }

    fn make_apply_tx_input(txid: [u8; 32], vout: u32) -> TxInput {
        TxInput {
            prev_txid: txid,
            prev_vout: vout,
            script_sig: Vec::new(),
            sequence: 0,
        }
    }

    fn make_apply_tx_tx(
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        witness: Vec<WitnessItem>,
    ) -> Tx {
        Tx {
            version: 1,
            tx_nonce: 1,
            inputs,
            outputs,
            locktime: 0,
            witness: WitnessSection { witnesses: witness },
        }
    }

    #[test]
    fn apply_tx_rejects_missing_utxo() {
        let p = TestProvider;
        // Use a valid 33-byte P2PK covenant_data for the output so output
        // covenant validation passes; the UTXO lookup should fail first.
        let dummy_key_id = p.sha3_256(&vec![0x11u8; ML_DSA_PUBKEY_BYTES]).unwrap();
        let valid_p2pk_data = [vec![SUITE_ID_ML_DSA], dummy_key_id.to_vec()].concat();
        let tx = make_apply_tx_tx(
            vec![make_apply_tx_input([1u8; 32], 0)],
            vec![TxOutput {
                value: 10,
                covenant_type: CORE_P2PK,
                covenant_data: valid_p2pk_data,
            }],
            vec![WitnessItem {
                suite_id: SUITE_ID_ML_DSA,
                pubkey: vec![0x11u8; ML_DSA_PUBKEY_BYTES],
                signature: vec![0x22u8; ML_DSA_SIG_BYTES],
            }],
        );

        let err = apply_tx(
            &p,
            &[0u8; 32],
            &tx,
            &HashMap::<TxOutPoint, UtxoEntry>::new(),
            0,
            0,
            true,
            false,
        )
        .unwrap_err();
        assert_eq!(err, "TX_ERR_MISSING_UTXO");
    }

    #[test]
    fn apply_tx_rejects_duplicate_prevout() {
        let p = TestProvider;
        let txid = [2u8; 32];
        let key_id = p.sha3_256(&[0x11u8; ML_DSA_PUBKEY_BYTES]).unwrap();
        let prevout = make_apply_tx_prevout(
            200,
            CORE_P2PK,
            [vec![SUITE_ID_ML_DSA], key_id.to_vec()].concat(),
        );
        let witness = vec![
            WitnessItem {
                suite_id: SUITE_ID_ML_DSA,
                pubkey: vec![0x11u8; ML_DSA_PUBKEY_BYTES],
                signature: vec![0x22u8; ML_DSA_SIG_BYTES],
            },
            WitnessItem {
                suite_id: SUITE_ID_ML_DSA,
                pubkey: vec![0x11u8; ML_DSA_PUBKEY_BYTES],
                signature: vec![0x22u8; ML_DSA_SIG_BYTES],
            },
        ];
        let tx = make_apply_tx_tx(
            vec![make_apply_tx_input(txid, 0), make_apply_tx_input(txid, 0)],
            vec![TxOutput {
                value: 100,
                covenant_type: CORE_P2PK,
                covenant_data: Vec::new(),
            }],
            witness,
        );

        let mut utxo = HashMap::new();
        utxo.insert(
            TxOutPoint { txid, vout: 0 },
            UtxoEntry {
                output: prevout,
                creation_height: 0,
                created_by_coinbase: false,
            },
        );

        let err = apply_tx(&p, &[0u8; 32], &tx, &utxo, 0, 0, true, false).unwrap_err();
        assert_eq!(err, "TX_ERR_PARSE");
    }

    #[test]
    fn apply_tx_rejects_value_conservation_violation() {
        let p = TestProvider;
        let txid = [3u8; 32];
        let key_id = p.sha3_256(&[0x33u8; ML_DSA_PUBKEY_BYTES]).unwrap();
        let prevout = make_apply_tx_prevout(
            100,
            CORE_P2PK,
            [vec![SUITE_ID_ML_DSA], key_id.to_vec()].concat(),
        );
        // Output value > input: value_conservation must fire.
        // Use a valid P2PK covenant_data so output validation passes first.
        let out_key_id = p.sha3_256(&[0x33u8; ML_DSA_PUBKEY_BYTES]).unwrap();
        let valid_out_data = [vec![SUITE_ID_ML_DSA], out_key_id.to_vec()].concat();
        let tx = make_apply_tx_tx(
            vec![make_apply_tx_input(txid, 0)],
            vec![TxOutput {
                value: 101,
                covenant_type: CORE_P2PK,
                covenant_data: valid_out_data,
            }],
            vec![WitnessItem {
                suite_id: SUITE_ID_ML_DSA,
                pubkey: vec![0x33u8; ML_DSA_PUBKEY_BYTES],
                signature: vec![0x44u8; ML_DSA_SIG_BYTES],
            }],
        );

        let mut utxo = HashMap::new();
        utxo.insert(
            TxOutPoint { txid, vout: 0 },
            UtxoEntry {
                output: prevout,
                creation_height: 0,
                created_by_coinbase: false,
            },
        );

        let err = apply_tx(&p, &[0u8; 32], &tx, &utxo, 0, 0, true, false).unwrap_err();
        assert_eq!(err, "TX_ERR_VALUE_CONSERVATION");
    }

    #[test]
    fn apply_tx_accepts_valid_p2pk_spend() {
        let p = TestProvider;
        let txid = [4u8; 32];
        let pubkey = vec![0x55u8; ML_DSA_PUBKEY_BYTES];
        let key_id = p.sha3_256(&pubkey).unwrap();
        let prevout = TxOutput {
            value: 100,
            covenant_type: CORE_P2PK,
            covenant_data: [vec![SUITE_ID_ML_DSA], key_id.to_vec()].concat(),
        };
        // Output needs valid 33-byte P2PK covenant_data
        let out_key_id = p.sha3_256(&vec![0x55u8; ML_DSA_PUBKEY_BYTES]).unwrap();
        let valid_out_data = [vec![SUITE_ID_ML_DSA], out_key_id.to_vec()].concat();
        let tx = make_apply_tx_tx(
            vec![make_apply_tx_input(txid, 0)],
            vec![TxOutput {
                value: 90,
                covenant_type: CORE_P2PK,
                covenant_data: valid_out_data,
            }],
            vec![WitnessItem {
                suite_id: SUITE_ID_ML_DSA,
                pubkey: pubkey.clone(),
                signature: vec![0x66u8; ML_DSA_SIG_BYTES],
            }],
        );

        let mut utxo = HashMap::new();
        utxo.insert(
            TxOutPoint { txid, vout: 0 },
            UtxoEntry {
                output: prevout,
                creation_height: 0,
                created_by_coinbase: false,
            },
        );

        apply_tx(&p, &[0u8; 32], &tx, &utxo, 0, 0, true, false).unwrap();
    }
}
