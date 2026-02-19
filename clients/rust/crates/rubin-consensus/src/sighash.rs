use crate::Tx;
use crate::encode::tx_output_bytes;
use rubin_crypto::CryptoProvider;

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

    provider.sha3_256(&preimage)
}
