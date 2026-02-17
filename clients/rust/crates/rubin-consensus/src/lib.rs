//! RUBIN consensus library (wire, hashing domains, validation).
//!
//! This crate MUST implement consensus exactly as defined in:
//! - spec/RUBIN_L1_CANONICAL_v1.1.md
//!
//! Non-consensus policy MUST NOT be implemented here.

use rubin_crypto::CryptoProvider;

pub const CONSENSUS_REVISION: &str = "v1.1";

pub const CORE_P2PK: u16 = 0x0000;
pub const CORE_TIMELOCK_V1: u16 = 0x0001;
pub const CORE_ANCHOR: u16 = 0x0002;
pub const CORE_HTLC_V1: u16 = 0x0100;
pub const CORE_VAULT_V1: u16 = 0x0101;
pub const CORE_RESERVED_FUTURE: u16 = 0x00ff;

pub const SUITE_ID_SENTINEL: u8 = 0x00;
pub const SUITE_ID_ML_DSA: u8 = 0x01;
pub const SUITE_ID_SLH_DSA: u8 = 0x02;

pub const ML_DSA_PUBKEY_BYTES: usize = 2_592;
pub const SLH_DSA_PUBKEY_BYTES: usize = 64;
pub const ML_DSA_SIG_BYTES: usize = 4_627;
pub const SLH_DSA_SIG_MAX_BYTES: usize = 49_856;

pub const TIMELOCK_MODE_HEIGHT: u8 = 0x00;
pub const TIMELOCK_MODE_TIMESTAMP: u8 = 0x01;

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

pub fn validate_input_authorization(
    provider: &dyn CryptoProvider,
    chain_id: &[u8; 32],
    tx: &Tx,
    input_index: usize,
    prev_value: u64,
    prevout: &TxOutput,
    chain_height: u64,
    chain_timestamp: u64,
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
        CORE_VAULT_V1 => {
            is_script_sig_zero_len("CORE_VAULT_V1", input.script_sig.len())?;
            check_witness_format(witness, suite_id_02_active)?;

            if prevout.covenant_data.len() != 73 {
                return Err("TX_ERR_PARSE".into());
            }
            let lock_mode = prevout.covenant_data[32];
            let lock_value = parse_u64_le(&prevout.covenant_data, 33, "vault_lock_value")?;
            let owner_key_id = &prevout.covenant_data[0..32];
            let recovery_key_id = &prevout.covenant_data[41..73];
            let actual_key_id = compute_key_id(provider, &witness.pubkey)?;

            if actual_key_id.as_slice() != owner_key_id
                && actual_key_id.as_slice() != recovery_key_id
            {
                return Err("TX_ERR_SIG_INVALID".into());
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
        let err = validate_input_authorization(&p, &chain_id, &tx, 0, 100, &prevout, 0, 0, false)
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
        let err = validate_input_authorization(&p, &chain_id, &tx, 0, 100, &prevout, 10, 0, false)
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
        let ok = validate_input_authorization(&p, &chain_id, &tx, 0, 100, &prevout, 10, 0, false);
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
        let err = validate_input_authorization(&p, &chain_id, &tx, 0, 100, &prevout, 10, 0, false)
            .unwrap_err();
        assert_eq!(err, "TX_ERR_TIMELOCK_NOT_MET");
    }
}
