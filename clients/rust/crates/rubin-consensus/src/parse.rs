use crate::wire::Cursor;
use crate::{
    Block, BlockHeader, Tx, TxInput, TxOutput, WitnessItem, WitnessSection, BLOCK_ERR_PARSE,
};

pub fn parse_tx_bytes(bytes: &[u8]) -> Result<Tx, String> {
    let mut cursor = Cursor::new(bytes);
    let tx = parse_tx_from_cursor(&mut cursor)?;
    if cursor.pos != bytes.len() {
        return Err("parse: trailing bytes".into());
    }
    Ok(tx)
}

pub(crate) fn parse_tx_from_cursor(cursor: &mut Cursor<'_>) -> Result<Tx, String> {
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
        return Err(BLOCK_ERR_PARSE.into());
    }
    Ok(Block {
        header,
        transactions: txs,
    })
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
