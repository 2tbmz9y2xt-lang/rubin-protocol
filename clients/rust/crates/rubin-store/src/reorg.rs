//! Reorg: disconnect/connect with undo logs.
//!
//! See `operational/RUBIN_REORG_DISCONNECT_CONNECT_v1.1.md`.

use std::path::Path;

use rubin_crypto::CryptoProvider;

use crate::db::Store;
use crate::keys::BlockIndexEntry;
use crate::manifest::{hex_encode, Manifest};
use crate::pipeline;

// ---------------------------------------------------------------------------
// Fork-point discovery (§4)
// ---------------------------------------------------------------------------

/// Find the common ancestor of `old_tip` and `new_tip` by walking back
/// via `prev_hash` links in the block index.
pub fn find_fork_point(
    store: &Store,
    old_tip: &[u8; 32],
    new_tip: &[u8; 32],
) -> Result<[u8; 32], String> {
    let mut a = *old_tip;
    let mut b = *new_tip;

    let get_index = |hash: &[u8; 32]| -> Result<BlockIndexEntry, String> {
        store
            .get_block_index(hash)?
            .ok_or_else(|| format!("REORG_ERR_INDEX_MISSING: {}", hex_encode(hash)))
    };

    let mut a_idx = get_index(&a)?;
    let mut b_idx = get_index(&b)?;

    // Equalize heights.
    while a_idx.height > b_idx.height {
        a = a_idx.prev_hash;
        a_idx = get_index(&a)?;
    }
    while b_idx.height > a_idx.height {
        b = b_idx.prev_hash;
        b_idx = get_index(&b)?;
    }

    // Walk both back until they meet.
    while a != b {
        a = a_idx.prev_hash;
        b = b_idx.prev_hash;
        a_idx = get_index(&a)?;
        b_idx = get_index(&b)?;
    }

    Ok(a)
}

// ---------------------------------------------------------------------------
// Disconnect (§7)
// ---------------------------------------------------------------------------

/// Disconnect one block: revert UTXO changes using its undo record.
/// Updates the manifest to the parent after successful revert.
fn disconnect_block(
    store: &Store,
    manifest: &mut Manifest,
    manifest_path: &Path,
    block_hash: &[u8; 32],
) -> Result<(), String> {
    let undo = store
        .get_undo(block_hash)?
        .ok_or_else(|| format!("REORG_ERR_UNDO_MISSING: {}", hex_encode(block_hash)))?;

    let idx = store
        .get_block_index(block_hash)?
        .ok_or_else(|| format!("REORG_ERR_INDEX_MISSING: {}", hex_encode(block_hash)))?;

    let wb = store.begin_write()?;

    // Delete created UTXOs.
    for outpoint in &undo.created {
        wb.delete_utxo(outpoint)?;
    }

    // Restore spent UTXOs.
    for item in &undo.spent {
        wb.put_utxo(&item.outpoint, &item.restored_entry)?;
    }

    wb.commit()?;

    // Compute parent's cumulative work.
    let parent_idx = store.get_block_index(&idx.prev_hash)?;
    let parent_work = parent_idx.map(|p| p.cumulative_work).unwrap_or(0);
    let parent_height = if idx.height > 0 { idx.height - 1 } else { 0 };

    // Update manifest to parent.
    manifest.update_tip(&hex_encode(&idx.prev_hash), parent_height, parent_work);
    manifest.save_atomic(manifest_path)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Execute reorg (§5)
// ---------------------------------------------------------------------------

/// Execute a full reorg from current tip to new_tip.
/// 1. Find fork point.
/// 2. Disconnect from old tip down to fork point.
/// 3. Connect from fork point up to new_tip.
pub fn execute_reorg(
    store: &Store,
    manifest: &mut Manifest,
    manifest_path: &Path,
    provider: &dyn CryptoProvider,
    chain_id: &[u8; 32],
    new_tip_hash: &[u8; 32],
) -> Result<(), String> {
    let old_tip = manifest.tip_hash_bytes()?;

    let fork_point = find_fork_point(store, &old_tip, new_tip_hash)?;

    // Collect blocks to disconnect (old_tip → fork_point, exclusive of fork).
    let mut disconnect_hashes = Vec::new();
    {
        let mut cursor = old_tip;
        while cursor != fork_point {
            disconnect_hashes.push(cursor);
            let idx = store
                .get_block_index(&cursor)?
                .ok_or_else(|| format!("REORG_ERR_INDEX_MISSING: {}", hex_encode(&cursor)))?;
            cursor = idx.prev_hash;
        }
    }

    // Collect blocks to connect (fork_point → new_tip, exclusive of fork).
    let mut connect_hashes = Vec::new();
    {
        let mut cursor = *new_tip_hash;
        while cursor != fork_point {
            connect_hashes.push(cursor);
            let idx = store
                .get_block_index(&cursor)?
                .ok_or_else(|| format!("REORG_ERR_INDEX_MISSING: {}", hex_encode(&cursor)))?;
            cursor = idx.prev_hash;
        }
        connect_hashes.reverse(); // ascending height order
    }

    // Disconnect in descending order (already in descending order from tip).
    for hash in &disconnect_hashes {
        disconnect_block(store, manifest, manifest_path, hash)?;
    }

    // Connect in ascending order.
    for hash in &connect_hashes {
        let block_bytes = store
            .get_block_bytes(hash)?
            .ok_or_else(|| format!("REORG_ERR_BLOCK_MISSING: {}", hex_encode(hash)))?;
        let block = rubin_consensus::parse_block_bytes(&block_bytes)
            .map_err(|e| format!("REORG_ERR_PARSE: {e}"))?;
        let block_hash_computed = provider.sha3_256(&rubin_consensus::block_header_bytes(&block.header))?;

        let idx = store
            .get_block_index(hash)?
            .ok_or_else(|| format!("REORG_ERR_INDEX_MISSING: {}", hex_encode(hash)))?;

        pipeline::connect_block(
            store,
            manifest,
            manifest_path,
            provider,
            chain_id,
            &block,
            &block_hash_computed,
            &block_bytes,
            idx.height,
            idx.cumulative_work,
        )?;
    }

    Ok(())
}
