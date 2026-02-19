use crate::{BLOCK_ERR_COINBASE_INVALID, TX_COINBASE_PREVOUT_VOUT};

pub(crate) fn add_u64(a: u64, b: u64) -> Result<u64, String> {
    match a.checked_add(b) {
        Some(v) => Ok(v),
        None => Err("TX_ERR_PARSE".to_string()),
    }
}

pub(crate) fn sub_u64(a: u64, b: u64) -> Result<u64, String> {
    if b > a {
        return Err("TX_ERR_VALUE_CONSERVATION".into());
    }
    Ok(a - b)
}

pub(crate) fn parse_u64_le(bytes: &[u8], start: usize, name: &str) -> Result<u64, String> {
    if bytes.len() < start + 8 {
        return Err(format!("parse: {name} truncated"));
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&bytes[start..start + 8]);
    Ok(u64::from_le_bytes(v))
}

pub(crate) fn is_zero_outpoint(txid: &[u8; 32], vout: u32) -> bool {
    txid == &[0u8; 32] && vout == TX_COINBASE_PREVOUT_VOUT
}

pub(crate) fn is_coinbase_tx(tx: &crate::Tx, block_height: u64) -> bool {
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

pub(crate) fn is_script_sig_zero_len(item_name: &str, script_sig_len: usize) -> Result<(), String> {
    if script_sig_len != 0 {
        return Err(format!("parse: {item_name} script_sig must be empty"));
    }
    Ok(())
}

pub(crate) fn validate_htlc_script_sig_len(script_sig_len: usize) -> Result<(), String> {
    match script_sig_len {
        0 | 32 => Ok(()),
        _ => Err("TX_ERR_PARSE".into()),
    }
}

pub(crate) fn validate_coinbase_tx_inputs(tx: &crate::Tx) -> Result<(), String> {
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
