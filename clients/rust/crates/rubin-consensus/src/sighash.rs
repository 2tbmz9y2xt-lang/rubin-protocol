use crate::compactsize::encode_compact_size;
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::tx::Tx;

pub fn sighash_v1_digest(
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
) -> Result<[u8; 32], TxError> {
    let idx = input_index as usize;
    if idx >= tx.inputs.len() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "sighash: input_index out of bounds",
        ));
    }

    let hash_of_da_core_fields = sha3_256(&[]);

    let mut prevouts = Vec::with_capacity(tx.inputs.len() * (32 + 4));
    for i in &tx.inputs {
        prevouts.extend_from_slice(&i.prev_txid);
        prevouts.extend_from_slice(&i.prev_vout.to_le_bytes());
    }
    let hash_of_all_prevouts = sha3_256(&prevouts);

    let mut sequences = Vec::with_capacity(tx.inputs.len() * 4);
    for i in &tx.inputs {
        sequences.extend_from_slice(&i.sequence.to_le_bytes());
    }
    let hash_of_all_sequences = sha3_256(&sequences);

    let mut outputs_bytes = Vec::with_capacity(tx.outputs.len() * 64);
    for o in &tx.outputs {
        outputs_bytes.extend_from_slice(&o.value.to_le_bytes());
        outputs_bytes.extend_from_slice(&o.covenant_type.to_le_bytes());
        encode_compact_size(o.covenant_data.len() as u64, &mut outputs_bytes);
        outputs_bytes.extend_from_slice(&o.covenant_data);
    }
    let hash_of_all_outputs = sha3_256(&outputs_bytes);

    let i = &tx.inputs[idx];

    let mut preimage = Vec::with_capacity(256);
    preimage.extend_from_slice(b"RUBINv1-sighash/");
    preimage.extend_from_slice(&chain_id);
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    preimage.push(tx.tx_kind);
    preimage.extend_from_slice(&tx.tx_nonce.to_le_bytes());
    preimage.extend_from_slice(&hash_of_da_core_fields);
    preimage.extend_from_slice(&hash_of_all_prevouts);
    preimage.extend_from_slice(&hash_of_all_sequences);
    preimage.extend_from_slice(&input_index.to_le_bytes());
    preimage.extend_from_slice(&i.prev_txid);
    preimage.extend_from_slice(&i.prev_vout.to_le_bytes());
    preimage.extend_from_slice(&input_value.to_le_bytes());
    preimage.extend_from_slice(&i.sequence.to_le_bytes());
    preimage.extend_from_slice(&hash_of_all_outputs);
    preimage.extend_from_slice(&tx.locktime.to_le_bytes());

    Ok(sha3_256(&preimage))
}
