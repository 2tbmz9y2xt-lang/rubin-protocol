use crate::compactsize::encode_compact_size;
use crate::constants::{SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::tx::{da_core_fields_bytes, Tx};

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
    let hash_of_da_core_fields = sha3_256(&da_core_fields_bytes(tx)?);
    let i = &tx.inputs[idx];

    let hash_prevouts = if anyone_can_pay {
        let mut prevouts = Vec::with_capacity(32 + 4);
        prevouts.extend_from_slice(&i.prev_txid);
        prevouts.extend_from_slice(&i.prev_vout.to_le_bytes());
        sha3_256(&prevouts)
    } else {
        let mut prevouts = Vec::with_capacity(tx.inputs.len() * (32 + 4));
        for tx_in in &tx.inputs {
            prevouts.extend_from_slice(&tx_in.prev_txid);
            prevouts.extend_from_slice(&tx_in.prev_vout.to_le_bytes());
        }
        sha3_256(&prevouts)
    };

    let hash_sequences = if anyone_can_pay {
        let mut sequences = Vec::with_capacity(4);
        sequences.extend_from_slice(&i.sequence.to_le_bytes());
        sha3_256(&sequences)
    } else {
        let mut sequences = Vec::with_capacity(tx.inputs.len() * 4);
        for tx_in in &tx.inputs {
            sequences.extend_from_slice(&tx_in.sequence.to_le_bytes());
        }
        sha3_256(&sequences)
    };

    let hash_outputs = match base_type {
        SIGHASH_ALL => {
            let mut outputs_bytes = Vec::with_capacity(tx.outputs.len() * 64);
            for o in &tx.outputs {
                outputs_bytes.extend_from_slice(&o.value.to_le_bytes());
                outputs_bytes.extend_from_slice(&o.covenant_type.to_le_bytes());
                encode_compact_size(o.covenant_data.len() as u64, &mut outputs_bytes);
                outputs_bytes.extend_from_slice(&o.covenant_data);
            }
            sha3_256(&outputs_bytes)
        }
        SIGHASH_NONE => sha3_256(&[]),
        SIGHASH_SINGLE => {
            if idx < tx.outputs.len() {
                let o = &tx.outputs[idx];
                let mut output_bytes = Vec::with_capacity(64);
                output_bytes.extend_from_slice(&o.value.to_le_bytes());
                output_bytes.extend_from_slice(&o.covenant_type.to_le_bytes());
                encode_compact_size(o.covenant_data.len() as u64, &mut output_bytes);
                output_bytes.extend_from_slice(&o.covenant_data);
                sha3_256(&output_bytes)
            } else {
                sha3_256(&[])
            }
        }
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
    preimage.extend_from_slice(&hash_of_da_core_fields);
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
