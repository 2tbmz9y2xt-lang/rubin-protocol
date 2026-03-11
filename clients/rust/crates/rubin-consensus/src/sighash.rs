use std::collections::HashMap;

use crate::compactsize::encode_compact_size;
use crate::constants::{SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::tx::{da_core_fields_bytes, Tx};

pub struct SighashV1PrehashCache<'a> {
    tx: &'a Tx,
    hash_of_da_core_fields: [u8; 32],
    hash_all_prevouts: [u8; 32],
    hash_all_sequences: [u8; 32],
    hash_all_outputs: [u8; 32],
    single_outputs: HashMap<u32, [u8; 32]>,
}

pub fn is_valid_sighash_type(sighash_type: u8) -> bool {
    sighash_type == SIGHASH_ALL
        || sighash_type == SIGHASH_NONE
        || sighash_type == SIGHASH_SINGLE
        || sighash_type == (SIGHASH_ALL | SIGHASH_ANYONECANPAY)
        || sighash_type == (SIGHASH_NONE | SIGHASH_ANYONECANPAY)
        || sighash_type == (SIGHASH_SINGLE | SIGHASH_ANYONECANPAY)
}

pub fn sighash_v1_digest(
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
) -> Result<[u8; 32], TxError> {
    sighash_v1_digest_with_type(tx, input_index, input_value, chain_id, SIGHASH_ALL)
}

pub fn sighash_v1_digest_with_type(
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    sighash_type: u8,
) -> Result<[u8; 32], TxError> {
    let mut cache = SighashV1PrehashCache::new(tx)?;
    sighash_v1_digest_with_cache(&mut cache, input_index, input_value, chain_id, sighash_type)
}

impl<'a> SighashV1PrehashCache<'a> {
    pub fn new(tx: &'a Tx) -> Result<Self, TxError> {
        let hash_of_da_core_fields = sha3_256(&da_core_fields_bytes(tx)?);

        let mut prevouts = Vec::with_capacity(tx.inputs.len() * (32 + 4));
        let mut sequences = Vec::with_capacity(tx.inputs.len() * 4);
        for tx_in in &tx.inputs {
            prevouts.extend_from_slice(&tx_in.prev_txid);
            prevouts.extend_from_slice(&tx_in.prev_vout.to_le_bytes());
            sequences.extend_from_slice(&tx_in.sequence.to_le_bytes());
        }

        let mut outputs_bytes = Vec::with_capacity(tx.outputs.len() * 64);
        for o in &tx.outputs {
            outputs_bytes.extend_from_slice(&o.value.to_le_bytes());
            outputs_bytes.extend_from_slice(&o.covenant_type.to_le_bytes());
            encode_compact_size(o.covenant_data.len() as u64, &mut outputs_bytes);
            outputs_bytes.extend_from_slice(&o.covenant_data);
        }

        Ok(Self {
            tx,
            hash_of_da_core_fields,
            hash_all_prevouts: sha3_256(&prevouts),
            hash_all_sequences: sha3_256(&sequences),
            hash_all_outputs: sha3_256(&outputs_bytes),
            single_outputs: HashMap::new(),
        })
    }

    fn single_output_hash(&mut self, input_index: u32) -> [u8; 32] {
        if let Some(hash) = self.single_outputs.get(&input_index) {
            return *hash;
        }

        let idx = input_index as usize;
        let hash = if idx < self.tx.outputs.len() {
            let o = &self.tx.outputs[idx];
            let mut output_bytes = Vec::with_capacity(64);
            output_bytes.extend_from_slice(&o.value.to_le_bytes());
            output_bytes.extend_from_slice(&o.covenant_type.to_le_bytes());
            encode_compact_size(o.covenant_data.len() as u64, &mut output_bytes);
            output_bytes.extend_from_slice(&o.covenant_data);
            sha3_256(&output_bytes)
        } else {
            sha3_256(&[])
        };
        self.single_outputs.insert(input_index, hash);
        hash
    }
}

pub fn sighash_v1_digest_with_cache(
    cache: &mut SighashV1PrehashCache<'_>,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    sighash_type: u8,
) -> Result<[u8; 32], TxError> {
    let tx = cache.tx;
    let idx = input_index as usize;
    if idx >= tx.inputs.len() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "sighash: input_index out of bounds",
        ));
    }
    if !is_valid_sighash_type(sighash_type) {
        return Err(TxError::new(
            ErrorCode::TxErrSighashTypeInvalid,
            "sighash: invalid sighash_type",
        ));
    }

    let base_type = sighash_type & 0x1f;
    let anyone_can_pay = (sighash_type & SIGHASH_ANYONECANPAY) != 0;
    let i = &tx.inputs[idx];

    let hash_prevouts = if anyone_can_pay {
        let mut prevouts = Vec::with_capacity(32 + 4);
        prevouts.extend_from_slice(&i.prev_txid);
        prevouts.extend_from_slice(&i.prev_vout.to_le_bytes());
        sha3_256(&prevouts)
    } else {
        cache.hash_all_prevouts
    };

    let hash_sequences = if anyone_can_pay {
        let mut sequences = Vec::with_capacity(4);
        sequences.extend_from_slice(&i.sequence.to_le_bytes());
        sha3_256(&sequences)
    } else {
        cache.hash_all_sequences
    };

    let hash_outputs = match base_type {
        SIGHASH_ALL => cache.hash_all_outputs,
        SIGHASH_NONE => sha3_256(&[]),
        SIGHASH_SINGLE => cache.single_output_hash(input_index),
        _ => {
            return Err(TxError::new(
                ErrorCode::TxErrSighashTypeInvalid,
                "sighash: invalid base_type",
            ))
        }
    };

    let mut preimage = Vec::with_capacity(256);
    preimage.extend_from_slice(b"RUBINv1-sighash/");
    preimage.extend_from_slice(&chain_id);
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    preimage.push(tx.tx_kind);
    preimage.extend_from_slice(&tx.tx_nonce.to_le_bytes());
    preimage.extend_from_slice(&cache.hash_of_da_core_fields);
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequences);
    preimage.extend_from_slice(&input_index.to_le_bytes());
    preimage.extend_from_slice(&i.prev_txid);
    preimage.extend_from_slice(&i.prev_vout.to_le_bytes());
    preimage.extend_from_slice(&input_value.to_le_bytes());
    preimage.extend_from_slice(&i.sequence.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&tx.locktime.to_le_bytes());
    preimage.push(sighash_type);

    Ok(sha3_256(&preimage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{TxInput, TxOutput};

    fn test_tx() -> Tx {
        Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: 7,
            inputs: vec![
                TxInput {
                    prev_txid: [0x11; 32],
                    prev_vout: 0,
                    script_sig: vec![],
                    sequence: 1,
                },
                TxInput {
                    prev_txid: [0x22; 32],
                    prev_vout: 1,
                    script_sig: vec![],
                    sequence: 2,
                },
            ],
            outputs: vec![
                TxOutput {
                    value: 5,
                    covenant_type: 0x0000,
                    covenant_data: vec![0x01; 33],
                },
                TxOutput {
                    value: 7,
                    covenant_type: 0x0000,
                    covenant_data: vec![0x02; 33],
                },
            ],
            locktime: 0,
            witness: vec![],
            da_payload: vec![],
            da_commit_core: None,
            da_chunk_core: None,
        }
    }

    #[test]
    fn sighash_cache_matches_wrapper_digest() {
        let tx = test_tx();
        let chain_id = [0x55; 32];
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");

        let direct =
            sighash_v1_digest_with_type(&tx, 0, 10, chain_id, SIGHASH_ALL).expect("direct");
        let cached =
            sighash_v1_digest_with_cache(&mut cache, 0, 10, chain_id, SIGHASH_ALL).expect("cached");
        assert_eq!(direct, cached);
    }

    #[test]
    fn sighash_cache_reuses_single_output_hash() {
        let tx = test_tx();
        let chain_id = [0x66; 32];
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");

        let first = sighash_v1_digest_with_cache(&mut cache, 1, 10, chain_id, SIGHASH_SINGLE)
            .expect("first");
        assert_eq!(cache.single_outputs.len(), 1);
        let second = sighash_v1_digest_with_cache(&mut cache, 1, 10, chain_id, SIGHASH_SINGLE)
            .expect("second");
        assert_eq!(cache.single_outputs.len(), 1);
        assert_eq!(first, second);
    }
}
