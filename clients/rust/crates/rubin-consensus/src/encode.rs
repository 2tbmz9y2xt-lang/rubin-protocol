use crate::{
    compact_size_encode, BlockHeader, DAChunkFields, DACommitFields, Tx, TxOutput, WitnessItem,
    WitnessSection, TX_KIND_DA_CHUNK, TX_KIND_DA_COMMIT, TX_KIND_STANDARD,
};

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

pub fn witness_bytes(w: &WitnessSection) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&compact_size_encode(w.witnesses.len() as u64));
    for item in &w.witnesses {
        out.extend_from_slice(&witness_item_bytes(item));
    }
    out
}

fn da_core_fields_bytes(tx: &Tx) -> Vec<u8> {
    match tx.tx_kind {
        TX_KIND_STANDARD => Vec::new(),
        TX_KIND_DA_COMMIT => {
            let f: &DACommitFields = tx
                .da_commit
                .as_ref()
                .expect("DA_COMMIT tx_kind requires da_commit");
            assert!(tx.da_chunk.is_none());
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
            out
        }
        TX_KIND_DA_CHUNK => {
            let f: &DAChunkFields = tx
                .da_chunk
                .as_ref()
                .expect("DA_CHUNK tx_kind requires da_chunk");
            assert!(tx.da_commit.is_none());
            let mut out = Vec::new();
            out.extend_from_slice(&f.da_id);
            out.extend_from_slice(&f.chunk_index.to_le_bytes());
            out.extend_from_slice(&f.chunk_hash);
            out
        }
        _ => panic!("unknown tx_kind"),
    }
}

pub fn tx_no_witness_bytes(tx: &Tx) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version.to_le_bytes());
    out.push(tx.tx_kind);
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
    out.extend_from_slice(&da_core_fields_bytes(tx));
    out
}

pub fn tx_bytes(tx: &Tx) -> Vec<u8> {
    let mut out = tx_no_witness_bytes(tx);
    out.extend_from_slice(&witness_bytes(&tx.witness));
    out.extend_from_slice(&compact_size_encode(tx.da_payload.len() as u64));
    out.extend_from_slice(&tx.da_payload);
    out
}
