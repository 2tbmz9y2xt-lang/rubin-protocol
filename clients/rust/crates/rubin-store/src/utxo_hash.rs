//! Canonical utxo_set_hash computation.
//!
//! Spec (from user tech spec / operational Q-076):
//!   DST = "RUBINv1-utxo-set-hash/"
//!   utxo_set_hash = SHA3-256( DST || N_le[8] || pair_0 || pair_1 || ... )
//!   pair_i = outpoint_key_bytes || utxo_entry_bytes
//! Pairs ordered lexicographically by outpoint_key_bytes.

use rubin_crypto::CryptoProvider;

use crate::db::Store;
use crate::keys::decode_utxo_entry;

const DST: &[u8] = b"RUBINv1-utxo-set-hash/";

/// Compute utxo_set_hash by iterating the UTXO table in lex order.
pub fn utxo_set_hash(store: &Store, provider: &dyn CryptoProvider) -> Result<[u8; 32], String> {
    let count = store.utxo_count()?;

    // Build preimage: DST || N_le[8] || pairs...
    let mut preimage = Vec::new();
    preimage.extend_from_slice(DST);
    preimage.extend_from_slice(&count.to_le_bytes());

    store.iter_utxos(|key_bytes, value_bytes| -> Result<(), String> {
        // Canonical pair encoding MUST match Go `consensus.UtxoSetHash` byte-for-byte.
        // pair = outpoint_key_bytes || utxo_entry_canonical_bytes
        //
        // utxo_entry_canonical_bytes =
        //   value[8] || covenant_type[2] || covenant_data_len[compactsize] || covenant_data[var] ||
        //   creation_height[8] || coinbase_flag[1]
        preimage.extend_from_slice(key_bytes);

        // Decode DB encoding to consensus fields, then re-encode canonically for hashing.
        // This keeps DB storage layout an internal detail while the hash remains protocol-stable.
        let entry = decode_utxo_entry(value_bytes)
            .map_err(|e| format!("decode utxo entry for hash: {e}"))?;

        preimage.extend_from_slice(&entry.output.value.to_le_bytes());
        preimage.extend_from_slice(&entry.output.covenant_type.to_le_bytes());
        preimage.extend_from_slice(&rubin_consensus::compact_size_encode(
            entry.output.covenant_data.len() as u64,
        ));
        preimage.extend_from_slice(&entry.output.covenant_data);
        preimage.extend_from_slice(&entry.creation_height.to_le_bytes());
        preimage.push(if entry.created_by_coinbase { 1 } else { 0 });
        Ok(())
    })?;

    provider.sha3_256(&preimage)
}
