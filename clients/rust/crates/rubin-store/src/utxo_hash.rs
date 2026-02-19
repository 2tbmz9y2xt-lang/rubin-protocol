//! Canonical utxo_set_hash computation.
//!
//! Spec (from user ТЗ / operational Q-076):
//!   DST = "RUBINv1-utxo-set-hash/"
//!   utxo_set_hash = SHA3-256( DST || N_le[8] || pair_0 || pair_1 || ... )
//!   pair_i = outpoint_key_bytes || utxo_entry_bytes
//! Pairs ordered lexicographically by outpoint_key_bytes.

use rubin_crypto::CryptoProvider;

use crate::db::Store;

const DST: &[u8] = b"RUBINv1-utxo-set-hash/";

/// Compute utxo_set_hash by iterating the UTXO table in lex order.
pub fn utxo_set_hash(store: &Store, provider: &dyn CryptoProvider) -> Result<[u8; 32], String> {
    let count = store.utxo_count()?;

    // Build preimage: DST || N_le[8] || pairs...
    let mut preimage = Vec::new();
    preimage.extend_from_slice(DST);
    preimage.extend_from_slice(&count.to_le_bytes());

    store.iter_utxos(|key_bytes, value_bytes| {
        preimage.extend_from_slice(key_bytes);
        preimage.extend_from_slice(value_bytes);
    })?;

    provider.sha3_256(&preimage)
}
