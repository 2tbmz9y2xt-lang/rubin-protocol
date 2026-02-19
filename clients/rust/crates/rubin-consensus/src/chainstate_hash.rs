use crate::{TxOutPoint, UtxoEntry, compact_size_encode};
use rubin_crypto::CryptoProvider;
use std::collections::HashMap;

pub const UTXO_SET_HASH_DST: &[u8] = b"RUBINv1-utxo-set-hash/";

/// Canonical Phase 1 UTXO-set hash used for cross-client chainstate comparability.
///
/// See operational/RUBIN_CHAINSTATE_SNAPSHOT_HASH_v1.1.md.
pub fn utxo_set_hash(
    provider: &dyn CryptoProvider,
    utxo: &HashMap<TxOutPoint, UtxoEntry>,
) -> Result<[u8; 32], String> {
    let mut items: Vec<([u8; 36], &UtxoEntry)> = Vec::with_capacity(utxo.len());
    for (point, entry) in utxo {
        let mut key = [0u8; 36];
        key[0..32].copy_from_slice(&point.txid);
        key[32..36].copy_from_slice(&point.vout.to_le_bytes());
        items.push((key, entry));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));

    // NOTE: This allocates a full message buffer for hashing. Phase 1 conformance workloads are small.
    let mut buf: Vec<u8> = Vec::with_capacity(64 + items.len() * 64);
    buf.extend_from_slice(UTXO_SET_HASH_DST);
    buf.extend_from_slice(&(items.len() as u64).to_le_bytes());

    for (outpoint_key, entry) in items {
        buf.extend_from_slice(&outpoint_key);
        buf.extend_from_slice(&entry.output.value.to_le_bytes());
        buf.extend_from_slice(&entry.output.covenant_type.to_le_bytes());
        buf.extend_from_slice(&compact_size_encode(entry.output.covenant_data.len() as u64));
        buf.extend_from_slice(&entry.output.covenant_data);
        buf.extend_from_slice(&entry.creation_height.to_le_bytes());
        buf.push(if entry.created_by_coinbase {
            0x01
        } else {
            0x00
        });
    }

    provider.sha3_256(&buf)
}
