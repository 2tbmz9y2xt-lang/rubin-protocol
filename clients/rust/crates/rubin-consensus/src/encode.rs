use crate::{BlockHeader, Tx, TxOutput, WitnessItem, WitnessSection, compact_size_encode};

/// Serialize a BlockHeader into its 116-byte canonical header representation.
///
/// The returned array contains, in order:
/// - version as little-endian (bytes 0..4)
/// - previous block hash (bytes 4..36)
/// - merkle root (bytes 36..68)
/// - timestamp as little-endian (bytes 68..76)
/// - target (bytes 76..108)
/// - nonce as little-endian (bytes 108..116)
///
/// # Examples
///
/// ```
/// let header = BlockHeader {
///     version: 1,
///     prev_block_hash: [0u8; 32],
///     merkle_root: [0u8; 32],
///     timestamp: 0u64,
///     target: [0u8; 32],
///     nonce: 0u64,
/// };
/// let bytes = block_header_bytes(&header);
/// assert_eq!(bytes.len(), 116);
/// assert_eq!(&bytes[4..36], &header.prev_block_hash);
/// ```
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

/// Serialize a transaction output including its covenant data into a byte vector.
///
/// The resulting byte vector contains, in order:
/// 1. `value` as little-endian bytes,
/// 2. `covenant_type` as little-endian bytes,
/// 3. the compact-size-encoded length of `covenant_data`,
/// 4. the raw `covenant_data` bytes.
///
/// # Examples
///
/// ```
/// use crate::{TxOutput, tx_output_bytes};
///
/// let output = TxOutput {
///     value: 1u64,
///     covenant_type: 2u32,
///     covenant_data: vec![0xAA, 0xBB],
/// };
///
/// let bytes = tx_output_bytes(&output);
/// assert_eq!(&bytes[0..8], &1u64.to_le_bytes());
/// ```
pub fn tx_output_bytes(output: &TxOutput) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&output.value.to_le_bytes());
    out.extend_from_slice(&output.covenant_type.to_le_bytes());
    out.extend_from_slice(&compact_size_encode(output.covenant_data.len() as u64));
    out.extend_from_slice(&output.covenant_data);
    out
}

/// Serializes a witness item into a length-prefixed byte sequence.
///
/// The output contains, in order: the single-byte `suite_id`, the compact-size-encoded
/// length of `pubkey` followed by `pubkey` bytes, then the compact-size-encoded length
/// of `signature` followed by `signature` bytes.
///
/// # Parameters
///
/// - `item`: the witness item to serialize.
///
/// # Returns
///
/// A `Vec<u8>` containing the serialized witness item.
///
/// # Examples
///
/// ```
/// let item = WitnessItem {
///     suite_id: 1,
///     pubkey: vec![0x02, 0x03, 0x04],
///     signature: vec![0xaa, 0xbb],
/// };
/// let bytes = witness_item_bytes(&item);
/// // suite_id
/// assert_eq!(bytes[0], 1);
/// // pubkey length (compact size) then pubkey bytes
/// assert!(bytes.windows(3).any(|w| w == [0x03, 0x02, 0x03] ) || bytes.contains(&0x02));
/// ```
pub fn witness_item_bytes(item: &WitnessItem) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(item.suite_id);
    out.extend_from_slice(&compact_size_encode(item.pubkey.len() as u64));
    out.extend_from_slice(&item.pubkey);
    out.extend_from_slice(&compact_size_encode(item.signature.len() as u64));
    out.extend_from_slice(&item.signature);
    out
}

/// Serializes a witness section into bytes.
///
/// The output is the compact-size encoding of the number of witness items followed by each
/// witness item serialized in order.
///
/// # Examples
///
/// ```
/// let w = WitnessSection { witnesses: vec![] };
/// let bytes = witness_bytes(&w);
/// assert_eq!(bytes, compact_size_encode(0));
/// ```
pub fn witness_bytes(w: &WitnessSection) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&compact_size_encode(w.witnesses.len() as u64));
    for item in &w.witnesses {
        out.extend_from_slice(&witness_item_bytes(item));
    }
    out
}

/// Serialize a transaction excluding its witness section.
///
/// Produces the canonical byte serialization consisting of: version, tx_nonce,
/// compact-size-prefixed inputs (each as prev_txid, prev_vout, script_sig length + script_sig, sequence),
/// compact-size-prefixed outputs (each serialized via `tx_output_bytes`), and locktime.
///
/// # Returns
///
/// A byte vector containing the transaction serialization without witness data.
///
/// # Examples
///
/// ```no_run
/// // Build or obtain a `Tx` value named `tx`, then:
/// let bytes = tx_no_witness_bytes(&tx);
/// assert!(bytes.len() >= 8); // at least version and tx_nonce
/// ```
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

/// Serialize a transaction into a byte vector including its witness section.
///
/// # Returns
///
/// A `Vec<u8>` containing the complete serialized transaction (no-witness serialization followed by witness data).
///
/// # Examples
///
/// ```
/// let bytes = tx_bytes(&tx); // `tx` is a `Tx`
/// assert!(bytes.len() > 0);
/// ```
pub fn tx_bytes(tx: &Tx) -> Vec<u8> {
    let mut out = tx_no_witness_bytes(tx);
    out.extend_from_slice(&witness_bytes(&tx.witness));
    out
}
