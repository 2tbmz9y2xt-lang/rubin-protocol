//! Block import pipeline (Stages 0–5).
//!
//! See `operational/RUBIN_BLOCK_IMPORT_PIPELINE_v1.1.md`.

use std::collections::HashMap;
use std::path::Path;

use rubin_consensus::{
    Block, BlockHeader, BlockValidationContext, CORE_ANCHOR, TxOutPoint, UtxoEntry,
    block_header_bytes, parse_block_bytes,
};
use rubin_crypto::CryptoProvider;

use crate::db::Store;
use crate::keys::{BlockIndexEntry, BlockStatus, UndoEntry, UndoRecord, header_work};
use crate::manifest::{Manifest, hex_encode};
use crate::reorg;

// ---------------------------------------------------------------------------
// ImportResult
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum ImportResult {
    AcceptedNewTip {
        height: u64,
        block_hash: [u8; 32],
    },
    StoredNotSelected {
        height: u64,
        block_hash: [u8; 32],
    },
    Orphaned {
        block_hash: [u8; 32],
    },
    Rejected {
        block_hash: [u8; 32],
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// import_block — main entry point
// ---------------------------------------------------------------------------

pub fn import_block(
    store: &Store,
    manifest: &mut Manifest,
    manifest_path: &Path,
    provider: &dyn CryptoProvider,
    chain_id: &[u8; 32],
    block_bytes: &[u8],
) -> Result<ImportResult, String> {
    // ── Stage 0: Decode ─────────────────────────────────────────────
    let block = parse_block_bytes(block_bytes).map_err(|e| format!("BLOCK_ERR_PARSE: {e}"))?;
    let block_hash = provider.sha3_256(&block_header_bytes(&block.header))?;

    // Check if already known.
    if let Some(idx) = store.get_block_index(&block_hash)? {
        if idx.status == BlockStatus::Valid {
            return Ok(ImportResult::StoredNotSelected {
                height: idx.height,
                block_hash,
            });
        }
        if idx.status == BlockStatus::Invalid {
            return Ok(ImportResult::Rejected {
                block_hash,
                reason: "already marked INVALID".into(),
            });
        }
    }

    // Store block bytes and header early (Stage 0 persist).
    {
        let wb = store.begin_write()?;
        wb.put_header(&block_hash, &block.header)?;
        wb.put_block_bytes(&block_hash, block_bytes)?;
        wb.commit()?;
    }

    // ── Stage 1: Header-level validation (stateless) ────────────────
    // PoW check: block_hash must be ≤ target (byte comparison, big-endian).
    if !hash_meets_target(&block_hash, &block.header.target) {
        mark_invalid(store, &block_hash, &block.header, 0, BlockStatus::Invalid)?;
        return Ok(ImportResult::Rejected {
            block_hash,
            reason: "BLOCK_ERR_POW_INVALID".into(),
        });
    }

    // ── Stage 2: Prev-link / ancestry checks ────────────────────────
    let parent_hash = block.header.prev_block_hash;
    let is_genesis = parent_hash == [0u8; 32];

    let (parent_height, parent_work) = if is_genesis {
        (u64::MAX, 0u128) // height wraps to 0 when +1
    } else {
        match store.get_block_index(&parent_hash)? {
            None => {
                // Parent unknown → orphan. Store index as ORPHANED.
                let this_work = header_work(&block.header.target);
                let idx_entry = BlockIndexEntry {
                    height: 0, // unknown
                    prev_hash: parent_hash,
                    cumulative_work: this_work,
                    status: BlockStatus::Orphaned,
                };
                let wb = store.begin_write()?;
                wb.put_block_index(&block_hash, &idx_entry)?;
                wb.commit()?;
                return Ok(ImportResult::Orphaned { block_hash });
            }
            Some(parent_idx) => {
                if parent_idx.status == BlockStatus::Invalid {
                    mark_invalid(
                        store,
                        &block_hash,
                        &block.header,
                        parent_idx.height + 1,
                        BlockStatus::Invalid,
                    )?;
                    return Ok(ImportResult::Rejected {
                        block_hash,
                        reason: "INVALID_ANCESTRY".into(),
                    });
                }
                (parent_idx.height, parent_idx.cumulative_work)
            }
        }
    };

    let candidate_height = if is_genesis { 0 } else { parent_height + 1 };
    let this_work = header_work(&block.header.target);
    let candidate_work = parent_work + this_work;

    // ── Stage 3: Fork-choice ────────────────────────────────────────
    let current_tip_work = manifest.tip_cumulative_work_u128()?;
    let current_tip_hash = manifest.tip_hash_bytes()?;

    let is_better = candidate_work > current_tip_work
        || (candidate_work == current_tip_work && block_hash < current_tip_hash);

    // Store index entry regardless.
    {
        let wb = store.begin_write()?;
        wb.put_block_index(
            &block_hash,
            &BlockIndexEntry {
                height: candidate_height,
                prev_hash: parent_hash,
                cumulative_work: candidate_work,
                status: BlockStatus::Valid,
            },
        )?;
        wb.commit()?;
    }

    if !is_better {
        return Ok(ImportResult::StoredNotSelected {
            height: candidate_height,
            block_hash,
        });
    }

    // If we need to reorg (current tip is not our parent), do it first.
    if current_tip_hash != parent_hash && manifest.tip_height > 0 {
        reorg::execute_reorg(
            store,
            manifest,
            manifest_path,
            provider,
            chain_id,
            &block_hash,
        )?;
        // After reorg, the manifest tip should be our parent.
        // Now connect this block.
    }

    // ── Stage 4 + 5: Full validation and apply ──────────────────────
    connect_block(
        store,
        manifest,
        manifest_path,
        provider,
        chain_id,
        &block,
        &block_hash,
        block_bytes,
        candidate_height,
        candidate_work,
    )?;

    Ok(ImportResult::AcceptedNewTip {
        height: candidate_height,
        block_hash,
    })
}

// ---------------------------------------------------------------------------
// connect_block — Stage 4 (validate) + Stage 5 (apply)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub(crate) fn connect_block(
    store: &Store,
    manifest: &mut Manifest,
    manifest_path: &Path,
    provider: &dyn CryptoProvider,
    chain_id: &[u8; 32],
    block: &Block,
    block_hash: &[u8; 32],
    block_bytes: &[u8],
    height: u64,
    cumulative_work: u128,
) -> Result<(), String> {
    // Load UTXOs needed by this block's inputs.
    let mut utxo_map = load_utxos_for_block(store, block)?;
    let utxo_before = utxo_map.clone();

    // Build ancestor headers for consensus validation.
    let ancestors = load_ancestor_headers(store, &block.header.prev_block_hash, height)?;

    let ctx = BlockValidationContext {
        height,
        ancestor_headers: ancestors,
        local_time: 0,
        local_time_set: false,
        suite_id_02_active: false,
        htlc_v2_active: false,
    };

    // Stage 4: Full validation.
    rubin_consensus::apply_block(provider, chain_id, block, &mut utxo_map, &ctx)?;

    // Stage 5: Compute undo and apply atomically.
    let undo = compute_undo(&utxo_before, &utxo_map, block, provider)?;

    let wb = store.begin_write()?;

    // Persist undo record.
    wb.put_undo(block_hash, &undo)?;

    // Persist block bytes (may already exist from Stage 0, but ensure it's there).
    wb.put_block_bytes(block_hash, block_bytes)?;

    // Update UTXO set: delete consumed, insert created.
    for entry in &undo.spent {
        wb.delete_utxo(&entry.outpoint)?;
    }
    for outpoint in &undo.created {
        if let Some(new_entry) = utxo_map.get(outpoint) {
            wb.put_utxo(outpoint, new_entry)?;
        }
    }

    // Update block index.
    wb.put_block_index(
        block_hash,
        &BlockIndexEntry {
            height,
            prev_hash: block.header.prev_block_hash,
            cumulative_work,
            status: BlockStatus::Valid,
        },
    )?;

    wb.put_header(block_hash, &block.header)?;

    wb.commit()?;

    // Update manifest (commit point).
    manifest.update_tip(&hex_encode(block_hash), height, cumulative_work);
    manifest.save_atomic(manifest_path)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load UTXOs referenced by the block's transaction inputs.
fn load_utxos_for_block(
    store: &Store,
    block: &Block,
) -> Result<HashMap<TxOutPoint, UtxoEntry>, String> {
    let mut utxo_map = HashMap::new();
    for tx in &block.transactions {
        for input in &tx.inputs {
            let outpoint = TxOutPoint {
                txid: input.prev_txid,
                vout: input.prev_vout,
            };
            // Skip coinbase null input.
            if outpoint.txid == [0u8; 32] && outpoint.vout == u32::MAX {
                continue;
            }
            if utxo_map.contains_key(&outpoint) {
                continue;
            }
            if let Some(entry) = store.get_utxo(&outpoint)? {
                utxo_map.insert(outpoint, entry);
            }
        }
    }
    Ok(utxo_map)
}

/// Load ancestor headers from store for consensus validation context.
/// The consensus engine expects ancestors ordered oldest-to-newest, parent last.
fn load_ancestor_headers(
    store: &Store,
    parent_hash: &[u8; 32],
    height: u64,
) -> Result<Vec<BlockHeader>, String> {
    if height == 0 {
        return Ok(vec![]);
    }

    // Need up to 11 ancestors (for median-time and retarget).
    let needed = std::cmp::min(height, 11) as usize;
    let mut headers = Vec::with_capacity(needed);
    let mut current_hash = *parent_hash;

    for _ in 0..needed {
        match store.get_header(&current_hash)? {
            Some(h) => {
                let prev = h.prev_block_hash;
                headers.push(h);
                current_hash = prev;
            }
            None => break,
        }
    }

    // Reverse: we collected newest-first, consensus wants oldest-first.
    headers.reverse();
    Ok(headers)
}

/// Compute the undo record by diffing utxo_before vs utxo_after.
fn compute_undo(
    utxo_before: &HashMap<TxOutPoint, UtxoEntry>,
    utxo_after: &HashMap<TxOutPoint, UtxoEntry>,
    block: &Block,
    provider: &dyn CryptoProvider,
) -> Result<UndoRecord, String> {
    let mut spent = Vec::new();
    let mut created = Vec::new();

    for tx in &block.transactions {
        // Spent: inputs that existed in utxo_before and are gone from utxo_after.
        for input in &tx.inputs {
            let outpoint = TxOutPoint {
                txid: input.prev_txid,
                vout: input.prev_vout,
            };
            // Skip coinbase null input.
            if outpoint.txid == [0u8; 32] && outpoint.vout == u32::MAX {
                continue;
            }
            if let Some(old_entry) = utxo_before.get(&outpoint)
                && !utxo_after.contains_key(&outpoint)
            {
                spent.push(UndoEntry {
                    outpoint,
                    restored_entry: old_entry.clone(),
                });
            }
        }

        // Created: outputs that are in utxo_after but not in utxo_before.
        let txid = rubin_consensus::txid(provider, tx)?;
        for (vout_idx, output) in tx.outputs.iter().enumerate() {
            // Skip non-spendable outputs (CORE_ANCHOR).
            if output.covenant_type == CORE_ANCHOR {
                continue;
            }
            let outpoint = TxOutPoint {
                txid,
                vout: vout_idx as u32,
            };
            if utxo_after.contains_key(&outpoint) && !utxo_before.contains_key(&outpoint) {
                created.push(outpoint);
            }
        }
    }

    Ok(UndoRecord { spent, created })
}

/// Check if block_hash (big-endian) is ≤ target (big-endian).
fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in 0..32 {
        if hash[i] < target[i] {
            return true;
        }
        if hash[i] > target[i] {
            return false;
        }
    }
    true // equal
}

/// Mark a block as invalid in the index.
fn mark_invalid(
    store: &Store,
    block_hash: &[u8; 32],
    header: &BlockHeader,
    height: u64,
    status: BlockStatus,
) -> Result<(), String> {
    let wb = store.begin_write()?;
    wb.put_block_index(
        block_hash,
        &BlockIndexEntry {
            height,
            prev_hash: header.prev_block_hash,
            cumulative_work: 0,
            status,
        },
    )?;
    wb.commit()
}
