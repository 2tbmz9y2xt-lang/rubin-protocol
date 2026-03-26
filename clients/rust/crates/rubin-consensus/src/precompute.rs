use std::collections::{HashMap, HashSet};

use crate::block_basic::ParsedBlock;
use crate::constants::{COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT};
use crate::error::{ErrorCode, TxError};
use crate::utxo_basic::{Outpoint, UtxoEntry};
use crate::vault::witness_slots;

/// Immutable, precomputed context for a single non-coinbase transaction within
/// a block. Computed once against the block-start UTXO snapshot and passed to
/// read-only validation workers.
///
/// Fields are intentionally owned types to prevent accidental aliasing of
/// mutable consensus state. The sighash cache is NOT stored here because
/// [`SighashV1PrehashCache`] borrows `&Tx`; workers construct it on demand
/// from `parsed_block.txs[tx_block_idx]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecomputedTxContext {
    /// 1-based position in the block (coinbase is index 0).
    pub tx_index: usize,
    /// Index into `ParsedBlock.txs` — workers use this to access the full `Tx`.
    pub tx_block_idx: usize,
    /// Canonical transaction identifier.
    pub txid: [u8; 32],
    /// Resolved UTXO entry for each input, in input order. Snapshot values;
    /// workers MUST NOT mutate these.
    pub resolved_inputs: Vec<UtxoEntry>,
    /// Starting index into `tx.witness` for this transaction's witness data.
    pub witness_start: usize,
    /// Exclusive end index into `tx.witness`.
    pub witness_end: usize,
    /// Input outpoints in input order, for dependency tracking.
    pub input_outpoints: Vec<Outpoint>,
    /// Transaction fee (sum_inputs − sum_outputs), validated during precompute.
    pub fee: u64,
}

/// Build an immutable [`PrecomputedTxContext`] slice for all non-coinbase
/// transactions in a parsed block.
///
/// Resolves inputs against the provided block-start UTXO snapshot, computes
/// witness slice boundaries using the deterministic sequential cursor model,
/// and validates value conservation.
///
/// The `utxo_snapshot` is **not** modified. Same-block output creation is
/// tracked internally to support parent-child dependencies.
///
/// Error behavior matches the sequential path exactly.
pub fn precompute_tx_contexts(
    pb: &ParsedBlock,
    utxo_snapshot: &HashMap<Outpoint, UtxoEntry>,
    block_height: u64,
) -> Result<Vec<PrecomputedTxContext>, TxError> {
    if pb.txs.is_empty() {
        return Err(TxError::new(
            ErrorCode::BlockErrParse,
            "nil or empty parsed block",
        ));
    }

    let tx_count = pb.txs.len() - 1; // exclude coinbase
    if tx_count == 0 {
        return Ok(Vec::new()); // coinbase-only block
    }

    // Working UTXO overlay: starts from immutable snapshot, tracks same-block
    // produced outputs. The original snapshot is never modified.
    let mut overlay: HashMap<Outpoint, UtxoEntry> =
        HashMap::with_capacity(utxo_snapshot.len());
    for (k, v) in utxo_snapshot {
        overlay.insert(k.clone(), v.clone());
    }

    let mut results = Vec::with_capacity(tx_count);
    let zero_txid = [0u8; 32];

    for i in 1..pb.txs.len() {
        let tx = &pb.txs[i];
        let txid = pb.txids[i];

        if tx.inputs.is_empty() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "non-coinbase must have at least one input",
            ));
        }

        // Resolve inputs and compute witness boundaries.
        let mut resolved_inputs = Vec::with_capacity(tx.inputs.len());
        let mut input_outpoints = Vec::with_capacity(tx.inputs.len());
        let mut seen_inputs: HashSet<Outpoint> = HashSet::with_capacity(tx.inputs.len());
        let mut total_witness_slots: usize = 0;
        let mut sum_in: u128 = 0;

        for input in &tx.inputs {
            // Coinbase prevout encoding forbidden in non-coinbase.
            if input.prev_vout == 0xffff_ffff && input.prev_txid == zero_txid {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "coinbase prevout encoding forbidden in non-coinbase",
                ));
            }

            let op = Outpoint {
                txid: input.prev_txid,
                vout: input.prev_vout,
            };

            if !seen_inputs.insert(op.clone()) {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "duplicate input outpoint",
                ));
            }

            let entry = overlay.get(&op).cloned().ok_or_else(|| {
                TxError::new(ErrorCode::TxErrMissingUtxo, "utxo not found")
            })?;

            if entry.covenant_type == COV_TYPE_ANCHOR
                || entry.covenant_type == COV_TYPE_DA_COMMIT
            {
                return Err(TxError::new(
                    ErrorCode::TxErrMissingUtxo,
                    "attempt to spend non-spendable covenant",
                ));
            }

            let slots = witness_slots(entry.covenant_type, &entry.covenant_data)?;
            if slots == 0 {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "invalid witness slots",
                ));
            }
            total_witness_slots += slots;

            sum_in = sum_in
                .checked_add(u128::from(entry.value))
                .ok_or_else(|| {
                    TxError::new(ErrorCode::TxErrValueConservation, "input sum overflow")
                })?;

            resolved_inputs.push(entry);
            input_outpoints.push(op);
        }

        // Witness boundary check. Cursor is per-tx (reset to 0 for each tx),
        // matching the sequential path.
        let witness_start: usize = 0;
        let witness_end = total_witness_slots;
        if witness_end > tx.witness.len() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "witness underflow",
            ));
        }
        if witness_end != tx.witness.len() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "witness_count mismatch",
            ));
        }

        // Fee = sum_in − sum_out, matching sequential value conservation.
        let mut sum_out: u128 = 0;
        for output in &tx.outputs {
            sum_out = sum_out
                .checked_add(u128::from(output.value))
                .ok_or_else(|| {
                    TxError::new(ErrorCode::TxErrValueConservation, "output sum overflow")
                })?;
        }
        if sum_in < sum_out {
            return Err(TxError::new(
                ErrorCode::TxErrValueConservation,
                "outputs exceed inputs",
            ));
        }
        let fee_big = sum_in - sum_out;
        if fee_big > u128::from(u64::MAX) {
            return Err(TxError::new(
                ErrorCode::TxErrValueConservation,
                "fee overflow u64",
            ));
        }
        let fee = fee_big as u64;

        results.push(PrecomputedTxContext {
            tx_index: i,
            tx_block_idx: i,
            txid,
            resolved_inputs,
            witness_start,
            witness_end,
            input_outpoints: input_outpoints.clone(),
            fee,
        });

        // Track same-block outputs: remove spent UTXOs, add created outputs.
        for op in &input_outpoints {
            overlay.remove(op);
        }
        for (j, output) in tx.outputs.iter().enumerate() {
            if output.covenant_type == COV_TYPE_ANCHOR
                || output.covenant_type == COV_TYPE_DA_COMMIT
            {
                continue;
            }
            let op = Outpoint {
                txid,
                vout: j as u32,
            };
            overlay.insert(
                op,
                UtxoEntry {
                    value: output.value,
                    covenant_type: output.covenant_type,
                    covenant_data: output.covenant_data.clone(),
                    creation_height: block_height,
                    created_by_coinbase: false,
                },
            );
        }
    }

    Ok(results)
}
