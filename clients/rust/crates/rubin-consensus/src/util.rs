use crate::{BLOCK_ERR_COINBASE_INVALID, TX_COINBASE_PREVOUT_VOUT};

/// Add two integers with overflow detection.
///
/// # Returns
///
/// `Ok(sum)` containing the sum if addition does not overflow, `Err("TX_ERR_PARSE")` if an overflow occurs.
///
/// # Examples
///
/// ```
/// let sum = super::add_u64(1, 2).unwrap();
/// assert_eq!(sum, 3);
/// assert_eq!(super::add_u64(u64::MAX, 1).unwrap_err(), "TX_ERR_PARSE");
/// ```
pub(crate) fn add_u64(a: u64, b: u64) -> Result<u64, String> {
    match a.checked_add(b) {
        Some(v) => Ok(v),
        None => Err("TX_ERR_PARSE".to_string()),
    }
}

/// Subtracts b from a and returns an error if the subtraction would underflow.
///
/// Returns `Ok(a - b)` if `b` is less than or equal to `a`, `Err("TX_ERR_VALUE_CONSERVATION")` otherwise.
///
/// # Examples
///
/// ```
/// assert_eq!(sub_u64(10, 3).unwrap(), 7);
/// assert!(sub_u64(3, 5).is_err());
/// ```
pub(crate) fn sub_u64(a: u64, b: u64) -> Result<u64, String> {
    if b > a {
        return Err("TX_ERR_VALUE_CONSERVATION".into());
    }
    Ok(a - b)
}

/// Parse an 8-byte little-endian unsigned integer from a byte slice at the given offset.
///
/// Returns `Ok(u64)` containing the parsed value. Returns `Err(String)` with message
/// `parse: {name} truncated` if there are fewer than 8 bytes available starting at `start`.
///
/// # Examples
///
/// ```
/// let bytes = [1u8, 0, 0, 0, 0, 0, 0, 0,  2, 0, 0, 0, 0, 0, 0, 0];
/// let v = crate::util::parse_u64_le(&bytes, 0, "field").unwrap();
/// assert_eq!(v, 1);
/// let v2 = crate::util::parse_u64_le(&bytes, 8, "field2").unwrap();
/// assert_eq!(v2, 2);
/// ```
pub(crate) fn parse_u64_le(bytes: &[u8], start: usize, name: &str) -> Result<u64, String> {
    if bytes.len() < start + 8 {
        return Err(format!("parse: {name} truncated"));
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&bytes[start..start + 8]);
    Ok(u64::from_le_bytes(v))
}

/// Determine if an outpoint refers to the all-zero txid and the coinbase prevout index.
///
/// # Returns
///
/// `true` if `txid` is 32 zero bytes and `vout` equals `TX_COINBASE_PREVOUT_VOUT`, `false` otherwise.
///
/// # Examples
///
/// ```
/// let txid = [0u8; 32];
/// assert!(is_zero_outpoint(&txid, TX_COINBASE_PREVOUT_VOUT));
/// ```
pub(crate) fn is_zero_outpoint(txid: &[u8; 32], vout: u32) -> bool {
    txid == &[0u8; 32] && vout == TX_COINBASE_PREVOUT_VOUT
}

/// Determine whether a transaction is a coinbase transaction for the given block height.
///
/// The transaction is considered coinbase only if it:
/// - has exactly one input;
/// - has locktime equal to `block_height`;
/// - has `tx_nonce == 0`;
/// - has no witness data;
/// - and its sole input has a zero prevout with `vout` and `sequence` equal to `TX_COINBASE_PREVOUT_VOUT` and an empty `script_sig`.
///
/// # Returns
///
/// `true` if the transaction is a coinbase transaction for the given block height, `false` otherwise.
///
/// # Examples
///
/// ```
/// // Given a transaction `tx` and block height `height`, call:
/// let _is_coinbase = is_coinbase_tx(&tx, height);
/// ```
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

/// Validate that a parsed item's scriptSig has zero length.
///
/// # Parameters
/// - `item_name`: name of the item being validated (used in the error message).
/// - `script_sig_len`: length of the scriptSig to validate.
///
/// # Returns
/// `Ok(())` if `script_sig_len` is zero, `Err(String)` with message `"parse: {item_name} script_sig must be empty"` otherwise.
///
/// # Examples
///
/// ```
/// assert!(is_script_sig_zero_len("input", 0).is_ok());
/// assert_eq!(
///     is_script_sig_zero_len("input", 1).unwrap_err(),
///     "parse: input script_sig must be empty"
/// );
/// ```
pub(crate) fn is_script_sig_zero_len(item_name: &str, script_sig_len: usize) -> Result<(), String> {
    if script_sig_len != 0 {
        return Err(format!("parse: {item_name} script_sig must be empty"));
    }
    Ok(())
}

/// Validate that an HTLC `scriptSig` length is allowed.
///
/// Accepts only lengths of 0 or 32 bytes.
///
/// # Returns
///
/// `Ok(())` if `script_sig_len` is 0 or 32, `Err("TX_ERR_PARSE")` otherwise.
///
/// # Examples
///
/// ```
/// assert!(validate_htlc_script_sig_len(0).is_ok());
/// assert!(validate_htlc_script_sig_len(32).is_ok());
/// assert_eq!(validate_htlc_script_sig_len(1).unwrap_err(), "TX_ERR_PARSE");
/// ```
pub(crate) fn validate_htlc_script_sig_len(script_sig_len: usize) -> Result<(), String> {
    match script_sig_len {
        0 | 32 => Ok(()),
        _ => Err("TX_ERR_PARSE".into()),
    }
}

/// Validate that a transaction's inputs conform to coinbase requirements.
///
/// Checks performed:
/// - `tx.tx_nonce` equals 0.
/// - exactly one input is present.
/// - the input's `sequence` equals `TX_COINBASE_PREVOUT_VOUT`.
/// - the input's previous outpoint is all-zero and `prev_vout` equals `TX_COINBASE_PREVOUT_VOUT`.
/// - the input's `script_sig` is empty.
/// - the transaction has no witnesses.
///
/// # Parameters
///
/// - `tx` — transaction to validate.
///
/// # Returns
///
/// `Ok(())` if all coinbase input invariants hold, `Err(BLOCK_ERR_COINBASE_INVALID)` otherwise.
///
/// # Examples
///
/// ```
/// // Construct or obtain a `crate::Tx` representing a coinbase transaction, then:
/// // let tx = /* coinbase tx */ ;
/// // assert!(validate_coinbase_tx_inputs(&tx).is_ok());
/// ```
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
