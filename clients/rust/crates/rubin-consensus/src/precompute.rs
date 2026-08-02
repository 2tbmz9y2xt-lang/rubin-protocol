use std::collections::{HashMap, HashSet};

use crate::block_basic::ParsedBlock;
use crate::constants::{
    COINBASE_MATURITY, COV_TYPE_ANCHOR, COV_TYPE_CORE_SIMPLICITY, COV_TYPE_DA_COMMIT,
};
use crate::covenant_genesis::validate_tx_covenants_genesis;
use crate::error::{ErrorCode, TxError};
use crate::simplicity_covenant::reject_core_simplicity_spend;
use crate::tx::{Tx, TxInput, TxOutput};
use crate::utxo_basic::{validate_non_coinbase_input_encoding, Outpoint, UtxoEntry};
use crate::vault::witness_slots;

/// Immutable, precomputed context for a single non-coinbase transaction within
/// a block. The caller must provide a `ParsedBlock` that completed canonical
/// connect preflight, including coinbase structure and locktime. The context
/// covers the block-start UTXO snapshot plus the current coinbase and earlier
/// transactions and is intended for read-only worker validation;
/// [`precompute_tx_contexts`] currently has no production caller.
/// `ParsedBlock` and its `Tx` objects remain caller-owned and must stay
/// immutable for the lifetime of returned contexts.
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
    /// Resolved UTXO entry for each input, in input order. Its UTXO bytes are
    /// detached from the caller snapshot, which the caller may mutate after
    /// return. Workers MUST NOT mutate these values.
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

/// Overflow-safe witness slot accumulator. Returns the new total or an error
/// if the addition would overflow `usize`.
pub(crate) fn add_witness_slots(total: usize, slots: usize) -> Result<usize, TxError> {
    total
        .checked_add(slots)
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "witness slot count overflow"))
}

struct CollectedPrecomputeInputs {
    resolved_inputs: Vec<UtxoEntry>,
    input_outpoints: Vec<Outpoint>,
    total_witness_slots: usize,
    sum_in: u128,
    stopped_at_core_simplicity: bool,
}

/// Build an immutable [`PrecomputedTxContext`] slice for all non-coinbase
/// transactions in a parsed block.
///
/// Resolves inputs against the provided block-start UTXO snapshot, computes
/// witness slice boundaries using the deterministic sequential cursor model,
/// and validates value conservation.
/// Precondition: `pb` completed canonical connect preflight, including coinbase
/// structure and locktime.
///
/// During this call, the caller retains read-only ownership of `utxo_snapshot`.
/// A local overlay adds the current coinbase and earlier same-block outputs to
/// support parent-child dependencies. `ParsedBlock` and its `Tx` objects remain
/// caller-owned and must stay immutable for the lifetime of returned contexts.
/// Resolved UTXO bytes are detached, so the caller may mutate `utxo_snapshot`
/// after return. This API repeats the connect path's non-coinbase coinbase-like,
/// nonce, and replay checks and validates output creation. Contexts are intended
/// for read-only workers, which validate resolved inputs; this exported API
/// currently has no production caller. Default chain and rotation context match
/// the standalone path.
///
/// With the default chain and rotation context, errors owned by this precompute
/// path (non-coinbase coinbase-like, nonce, and replay checks; output creation;
/// input resolution; witness boundaries; and value conservation) preserve the
/// corresponding sequential first-error order.
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

    if pb.txids.len() != pb.txs.len() {
        return Err(TxError::new(
            ErrorCode::BlockErrParse,
            "txids/txs length mismatch",
        ));
    }

    // Working UTXO overlay: starts from immutable snapshot, tracks same-block
    // produced outputs. The original snapshot is never modified.
    let mut overlay = utxo_snapshot.clone();
    pb.apply_coinbase_outputs(&mut overlay, block_height, None)?;
    if pb.txs.len() == 1 {
        return Ok(Vec::new());
    }
    precompute_non_coinbase_contexts(pb, &mut overlay, block_height)
}

fn precompute_non_coinbase_contexts(
    pb: &ParsedBlock,
    overlay: &mut HashMap<Outpoint, UtxoEntry>,
    block_height: u64,
) -> Result<Vec<PrecomputedTxContext>, TxError> {
    let tx_count = pb.txs.len() - 1;
    let mut results = Vec::with_capacity(tx_count);
    let mut seen_nonces = HashSet::with_capacity(tx_count);

    for i in 1..pb.txs.len() {
        let tx = &pb.txs[i];
        let txid = pb.txids[i];

        ParsedBlock::validate_non_coinbase_block_tx(tx, &mut seen_nonces)?;
        let (context, input_outpoints) = precompute_tx_context(i, tx, txid, overlay, block_height)?;
        results.push(context);
        update_precompute_overlay(overlay, tx, txid, &input_outpoints, block_height)?;
    }
    Ok(results)
}

fn precompute_tx_context(
    tx_index: usize,
    tx: &Tx,
    txid: [u8; 32],
    overlay: &HashMap<Outpoint, UtxoEntry>,
    block_height: u64,
) -> Result<(PrecomputedTxContext, Vec<Outpoint>), TxError> {
    if tx.tx_nonce == 0 {
        return Err(TxError::new(
            ErrorCode::TxErrTxNonceInvalid,
            "tx_nonce must be >= 1 for non-coinbase",
        ));
    }
    if tx.inputs.is_empty() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "non-coinbase must have at least one input",
        ));
    }
    validate_tx_covenants_genesis(tx, block_height, None)?;
    let inputs = collect_precompute_inputs(tx, overlay, block_height)?;
    let (witness_start, witness_end) = precompute_witness_bounds(
        tx,
        inputs.total_witness_slots,
        inputs.stopped_at_core_simplicity,
    )?;
    if inputs.stopped_at_core_simplicity {
        return Err(reject_core_simplicity_spend());
    }
    let fee = compute_precompute_fee(inputs.sum_in, &tx.outputs)?;
    let input_outpoints = inputs.input_outpoints;
    let context = PrecomputedTxContext {
        tx_index,
        tx_block_idx: tx_index,
        txid,
        resolved_inputs: inputs.resolved_inputs,
        witness_start,
        witness_end,
        input_outpoints: input_outpoints.clone(),
        fee,
    };
    Ok((context, input_outpoints))
}

fn collect_precompute_inputs(
    tx: &Tx,
    overlay: &HashMap<Outpoint, UtxoEntry>,
    block_height: u64,
) -> Result<CollectedPrecomputeInputs, TxError> {
    let mut out = CollectedPrecomputeInputs {
        resolved_inputs: Vec::with_capacity(tx.inputs.len()),
        input_outpoints: Vec::with_capacity(tx.inputs.len()),
        total_witness_slots: 0,
        sum_in: 0,
        stopped_at_core_simplicity: false,
    };
    let mut seen_inputs = HashSet::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        let (entry, op) = resolve_precompute_input(input, &mut seen_inputs, overlay, block_height)?;
        if entry.covenant_type == COV_TYPE_CORE_SIMPLICITY {
            // Standalone precompute is reject-only for 0x0106 under the default
            // context. Stop before trailing inputs and defer the dedicated
            // reject until after relaxed witness bounds. Active CORE_SIMPLICITY
            // parity is outside this boundary.
            out.stopped_at_core_simplicity = true;
            out.resolved_inputs.push(entry);
            out.input_outpoints.push(op);
            break;
        }
        let slots = precompute_witness_slots(&entry)?;
        out.total_witness_slots = add_witness_slots(out.total_witness_slots, slots)?;
        out.sum_in = out
            .sum_in
            .checked_add(u128::from(entry.value))
            .ok_or_else(|| TxError::new(ErrorCode::TxErrValueConservation, "input sum overflow"))?;
        out.resolved_inputs.push(entry);
        out.input_outpoints.push(op);
    }
    Ok(out)
}

fn resolve_precompute_input(
    input: &TxInput,
    seen_inputs: &mut HashSet<Outpoint>,
    overlay: &HashMap<Outpoint, UtxoEntry>,
    block_height: u64,
) -> Result<(UtxoEntry, Outpoint), TxError> {
    validate_non_coinbase_input_encoding(input)?;
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
    let entry = overlay
        .get(&op)
        .cloned()
        .ok_or_else(|| TxError::new(ErrorCode::TxErrMissingUtxo, "utxo not found"))?;
    validate_precompute_entry(&entry, block_height)?;
    Ok((entry, op))
}

fn validate_precompute_entry(entry: &UtxoEntry, block_height: u64) -> Result<(), TxError> {
    if matches!(entry.covenant_type, COV_TYPE_ANCHOR | COV_TYPE_DA_COMMIT) {
        return Err(TxError::new(
            ErrorCode::TxErrMissingUtxo,
            "attempt to spend non-spendable covenant",
        ));
    }
    if entry.created_by_coinbase
        && (block_height < entry.creation_height
            || block_height - entry.creation_height < COINBASE_MATURITY)
    {
        return Err(TxError::new(
            ErrorCode::TxErrCoinbaseImmature,
            "coinbase immature",
        ));
    }
    Ok(())
}

fn precompute_witness_slots(entry: &UtxoEntry) -> Result<usize, TxError> {
    let slots = witness_slots(entry.covenant_type, &entry.covenant_data)?;
    if slots == 0 {
        return Err(TxError::new(ErrorCode::TxErrParse, "invalid witness slots"));
    }
    Ok(slots)
}

fn precompute_witness_bounds(
    tx: &Tx,
    total_witness_slots: usize,
    stopped_at_core_simplicity: bool,
) -> Result<(usize, usize), TxError> {
    let witness_start = 0;
    let witness_end = total_witness_slots;
    if witness_end > tx.witness.len() {
        return Err(TxError::new(ErrorCode::TxErrParse, "witness underflow"));
    }
    if !stopped_at_core_simplicity && witness_end != tx.witness.len() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "witness_count mismatch",
        ));
    }
    Ok((witness_start, witness_end))
}

fn compute_precompute_fee(sum_in: u128, outputs: &[TxOutput]) -> Result<u64, TxError> {
    let mut sum_out = 0u128;
    for output in outputs {
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
    let fee = sum_in - sum_out;
    if fee > u128::from(u64::MAX) {
        return Err(TxError::new(
            ErrorCode::TxErrValueConservation,
            "fee overflow u64",
        ));
    }
    u64::try_from(fee)
        .map_err(|_| TxError::new(ErrorCode::TxErrValueConservation, "fee overflow u64"))
}

fn update_precompute_overlay(
    overlay: &mut HashMap<Outpoint, UtxoEntry>,
    tx: &Tx,
    txid: [u8; 32],
    input_outpoints: &[Outpoint],
    block_height: u64,
) -> Result<(), TxError> {
    for op in input_outpoints {
        overlay.remove(op);
    }
    for (index, output) in tx.outputs.iter().enumerate() {
        if matches!(output.covenant_type, COV_TYPE_ANCHOR | COV_TYPE_DA_COMMIT) {
            continue;
        }
        let vout = u32::try_from(index)
            .map_err(|_| TxError::new(ErrorCode::TxErrParse, "output index exceeds u32"))?;
        overlay.insert(
            Outpoint { txid, vout },
            UtxoEntry {
                value: output.value,
                covenant_type: output.covenant_type,
                covenant_data: output.covenant_data.clone(),
                creation_height: block_height,
                created_by_coinbase: false,
            },
        );
    }
    Ok(())
}
