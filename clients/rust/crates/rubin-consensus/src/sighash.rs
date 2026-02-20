use crate::encode::tx_output_bytes;
use crate::{
    compact_size_encode, Tx, TX_KIND_DA_CHUNK, TX_KIND_DA_COMMIT, TX_KIND_STANDARD,
};
use rubin_crypto::CryptoProvider;

fn da_core_fields_bytes(tx: &Tx) -> Result<Vec<u8>, String> {
    match tx.tx_kind {
        TX_KIND_STANDARD => Ok(Vec::new()),
        TX_KIND_DA_COMMIT => {
            let f = tx.da_commit.as_ref().ok_or("sighash: missing da_commit")?;
            let mut out = Vec::new();
            out.extend_from_slice(&f.da_id);
            out.extend_from_slice(&f.chunk_count.to_le_bytes());
            out.extend_from_slice(&f.retl_domain_id);
            out.extend_from_slice(&f.batch_number.to_le_bytes());
            out.extend_from_slice(&f.tx_data_root);
            out.extend_from_slice(&f.state_root);
            out.extend_from_slice(&f.withdrawals_root);
            out.push(f.batch_sig_suite);
            out.extend_from_slice(&compact_size_encode(f.batch_sig.len() as u64));
            out.extend_from_slice(&f.batch_sig);
            Ok(out)
        }
        TX_KIND_DA_CHUNK => {
            let f = tx.da_chunk.as_ref().ok_or("sighash: missing da_chunk")?;
            let mut out = Vec::new();
            out.extend_from_slice(&f.da_id);
            out.extend_from_slice(&f.chunk_index.to_le_bytes());
            out.extend_from_slice(&f.chunk_hash);
            Ok(out)
        }
        _ => Err("sighash: unknown tx_kind".into()),
    }
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

    let hash_of_da_core_fields = provider.sha3_256(&da_core_fields_bytes(tx)?)?;

    let input = &tx.inputs[input_index_usize];

    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"RUBINv2-sighash/");
    preimage.extend_from_slice(chain_id);
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    preimage.push(tx.tx_kind);
    preimage.extend_from_slice(&tx.tx_nonce.to_le_bytes());
    preimage.extend_from_slice(&hash_of_da_core_fields);
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
