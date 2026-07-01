//! CORE_SIMPLICITY (0x0106) transaction-context construction — Rust mirror of the
//! merged Go reference `simplicity_txcontext.go`. Base + IO views + self view
//! (RUB-500); same-CMR group views (8/8 + symmetric B-1 + atomic overflow
//! discard), the DA view, and the output covenant reject (RUB-501). Descriptor-hash
//! accessors and spend dispatch are later slices (RUB-503 / RUB-505).

use std::collections::BTreeMap;

use crate::constants::{
    COV_TYPE_CORE_SIMPLICITY, MAX_DA_CHUNK_COUNT, MAX_DA_MANIFEST_BYTES_PER_TX, MAX_TX_INPUTS,
    MAX_TX_OUTPUTS, SIMPLICITY_MAX_GROUP_INPUTS,
};
use crate::error::{ErrorCode, TxError};
use crate::simplicity_covenant::parse_core_simplicity_covenant_data;
use crate::tx::{DaCommitCore, Tx, TxOutput};
use crate::txcontext::Uint128;
use crate::utxo_basic::UtxoEntry;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimplicityTxContextBase {
    pub chain_id: [u8; 32],
    pub total_in: Uint128,
    pub total_out: Uint128,
    pub height: u64,
    pub tx_nonce: u64,
    pub locktime: u32,
    pub input_count: u16,
    pub output_count: u16,
    pub tx_kind: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimplicityTxContextIoView {
    pub value: u64,
    pub covenant_type: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimplicityTxContextGroupEntry {
    pub state: Vec<u8>,
    pub value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimplicityTxContextSameCmrView {
    pub program_cmr: [u8; 32],
    pub inputs: Vec<SimplicityTxContextGroupEntry>,
    pub outputs: Vec<SimplicityTxContextGroupEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SimplicityTxContextDaViewKind {
    #[default]
    Absent,
    Commit,
    Chunk,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SimplicityTxContextDaCommitView {
    pub da_id: [u8; 32],
    pub retl_domain_id: [u8; 32],
    pub tx_data_root: [u8; 32],
    pub state_root: [u8; 32],
    pub withdrawals_root: [u8; 32],
    pub batch_number: u64,
    pub chunk_count: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SimplicityTxContextDaChunkView {
    pub da_id: [u8; 32],
    pub chunk_hash: [u8; 32],
    pub chunk_index: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SimplicityTxContextDaView {
    pub commit: SimplicityTxContextDaCommitView,
    pub chunk: SimplicityTxContextDaChunkView,
    pub kind: SimplicityTxContextDaViewKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimplicityTxContextSelfView {
    pub self_program_cmr: [u8; 32],
    pub digest32: [u8; 32],
    pub self_state: Vec<u8>,
    pub self_value: u64,
    pub input_index: u16,
    pub sighash_type: u8,
}

// Index-aligned with the resolved inputs; only CORE_SIMPLICITY inputs carry a
// meaningful source, others keep a fail-closed placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SimplicityTxContextSelfSource {
    program_cmr: [u8; 32],
    state: Vec<u8>,
    value: u64,
    is_core_simplicity: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimplicityTxContext {
    pub base: SimplicityTxContextBase,
    input_views: Vec<SimplicityTxContextIoView>,
    output_views: Vec<SimplicityTxContextIoView>,
    self_sources: Vec<SimplicityTxContextSelfSource>,
    // Keyed by program_cmr; the per-key Vec preserves ascending input/output
    // order. BTreeMap keeps the structure iteration-order-free (determinism).
    group_inputs: BTreeMap<[u8; 32], Vec<SimplicityTxContextGroupEntry>>,
    group_outputs: BTreeMap<[u8; 32], Vec<SimplicityTxContextGroupEntry>>,
    da_view: SimplicityTxContextDaView,
}

fn parse_err(msg: &'static str) -> TxError {
    TxError::new(ErrorCode::TxErrParse, msg)
}

/// Returns `Ok(None)` when no resolved input spends a CORE_SIMPLICITY output
/// (mirrors the Go reference's `(nil, nil)`); otherwise builds the context
/// fail-closed. Crypto-free.
pub fn build_simplicity_tx_context(
    tx: &Tx,
    resolved_inputs: &[UtxoEntry],
    block_height: u64,
    chain_id: [u8; 32],
) -> Result<Option<SimplicityTxContext>, TxError> {
    if tx.inputs.len() != resolved_inputs.len() {
        return Err(parse_err(
            "simplicity txcontext resolved input count mismatch",
        ));
    }
    if tx.inputs.len() as u64 > MAX_TX_INPUTS {
        return Err(parse_err("simplicity txcontext input_count overflow"));
    }
    if tx.outputs.len() as u64 > MAX_TX_OUTPUTS {
        return Err(parse_err("simplicity txcontext output_count overflow"));
    }
    if !resolved_inputs
        .iter()
        .any(|entry| entry.covenant_type == COV_TYPE_CORE_SIMPLICITY)
    {
        return Ok(None);
    }

    #[allow(clippy::cast_possible_truncation)] // counts guarded len <= 1024 < u16::MAX
    let base = SimplicityTxContextBase {
        chain_id,
        total_in: sum_values(resolved_inputs.iter().map(|entry| entry.value))?,
        total_out: sum_values(tx.outputs.iter().map(|out| out.value))?,
        height: block_height,
        tx_nonce: tx.tx_nonce,
        locktime: tx.locktime,
        input_count: tx.inputs.len() as u16,
        output_count: tx.outputs.len() as u16,
        tx_kind: tx.tx_kind,
    };

    let mut ctx = SimplicityTxContext {
        base,
        input_views: Vec::with_capacity(resolved_inputs.len()),
        output_views: Vec::with_capacity(tx.outputs.len()),
        self_sources: Vec::with_capacity(resolved_inputs.len()),
        group_inputs: BTreeMap::new(),
        group_outputs: BTreeMap::new(),
        da_view: SimplicityTxContextDaView::default(),
    };
    populate_simplicity_tx_context_views(&mut ctx, tx, resolved_inputs)?;
    Ok(Some(ctx))
}

/// Fills input/output views, per-input self sources, same-CMR group views, and
/// the DA view. Mirrors Go `populateSimplicityTxContextViews`, the decomposition
/// `Build` delegates to.
fn populate_simplicity_tx_context_views(
    ctx: &mut SimplicityTxContext,
    tx: &Tx,
    resolved_inputs: &[UtxoEntry],
) -> Result<(), TxError> {
    populate_simplicity_tx_context_input_views(ctx, resolved_inputs)?;
    populate_simplicity_tx_context_output_views(ctx, &tx.outputs)?;
    ctx.da_view = build_simplicity_tx_context_da_view(tx)?;
    Ok(())
}

/// Input views + per-input self sources + same-CMR input groups. A same-CMR input
/// group exceeding `SIMPLICITY_MAX_GROUP_INPUTS` fails closed (atomic discard: the
/// error unwinds the whole build). Mirrors Go `populateSimplicityTxContextInputViews`.
fn populate_simplicity_tx_context_input_views(
    ctx: &mut SimplicityTxContext,
    resolved_inputs: &[UtxoEntry],
) -> Result<(), TxError> {
    for entry in resolved_inputs {
        ctx.input_views.push(SimplicityTxContextIoView {
            value: entry.value,
            covenant_type: entry.covenant_type,
        });
        if entry.covenant_type != COV_TYPE_CORE_SIMPLICITY {
            ctx.self_sources.push(SimplicityTxContextSelfSource {
                program_cmr: [0u8; 32],
                state: Vec::new(),
                value: 0,
                is_core_simplicity: false,
            });
            continue;
        }
        let (program_cmr, state) =
            parse_core_simplicity_covenant_data(entry.value, &entry.covenant_data)?;
        ctx.self_sources.push(SimplicityTxContextSelfSource {
            program_cmr,
            state: state.to_vec(),
            value: entry.value,
            is_core_simplicity: true,
        });
        let group = ctx.group_inputs.entry(program_cmr).or_default();
        group.push(SimplicityTxContextGroupEntry {
            value: entry.value,
            state: state.to_vec(),
        });
        if group.len() > SIMPLICITY_MAX_GROUP_INPUTS {
            return Err(TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "CORE_SIMPLICITY same-cmr input group exceeds limit",
            ));
        }
    }
    Ok(())
}

/// Output views + same-CMR output groups. A CORE_SIMPLICITY output whose value is 0
/// or whose covenant_data is malformed fails closed via the shared parse (the reject
/// RUB-500 core deferred here). Mirrors Go `populateSimplicityTxContextOutputViews`.
fn populate_simplicity_tx_context_output_views(
    ctx: &mut SimplicityTxContext,
    outputs: &[TxOutput],
) -> Result<(), TxError> {
    for out in outputs {
        ctx.output_views.push(SimplicityTxContextIoView {
            value: out.value,
            covenant_type: out.covenant_type,
        });
        if out.covenant_type != COV_TYPE_CORE_SIMPLICITY {
            continue;
        }
        let (program_cmr, state) =
            parse_core_simplicity_covenant_data(out.value, &out.covenant_data)?;
        ctx.group_outputs
            .entry(program_cmr)
            .or_default()
            .push(SimplicityTxContextGroupEntry {
                value: out.value,
                state: state.to_vec(),
            });
    }
    Ok(())
}

/// Builds the DA view from `tx_kind`: 0x00 absent, 0x01 commit (validated), 0x02
/// chunk (validated), any other rejected. Mirrors Go `buildSimplicityTxContextDAView`;
/// re-validates the DA cores since the builder may take a directly-constructed tx.
fn build_simplicity_tx_context_da_view(tx: &Tx) -> Result<SimplicityTxContextDaView, TxError> {
    let mut view = SimplicityTxContextDaView::default();
    match tx.tx_kind {
        0x00 => view.kind = SimplicityTxContextDaViewKind::Absent,
        0x01 => {
            let core = validate_simplicity_tx_context_da_commit_core(tx.da_commit_core.as_ref())?;
            view.kind = SimplicityTxContextDaViewKind::Commit;
            view.commit = SimplicityTxContextDaCommitView {
                da_id: core.da_id,
                chunk_count: core.chunk_count,
                retl_domain_id: core.retl_domain_id,
                batch_number: core.batch_number,
                tx_data_root: core.tx_data_root,
                state_root: core.state_root,
                withdrawals_root: core.withdrawals_root,
            };
        }
        0x02 => {
            let core = tx
                .da_chunk_core
                .as_ref()
                .ok_or_else(|| parse_err("missing da_chunk_core for tx_kind=0x02"))?;
            if u64::from(core.chunk_index) >= MAX_DA_CHUNK_COUNT {
                return Err(parse_err("chunk_index out of range for tx_kind=0x02"));
            }
            view.kind = SimplicityTxContextDaViewKind::Chunk;
            view.chunk = SimplicityTxContextDaChunkView {
                da_id: core.da_id,
                chunk_index: core.chunk_index,
                chunk_hash: core.chunk_hash,
            };
        }
        _ => return Err(parse_err("unsupported tx_kind")),
    }
    Ok(view)
}

/// Fail-closed DA commit-core validation for tx_kind=0x01: rejects a missing core, a
/// zero/over-limit chunk_count, or an oversized batch_sig — all with the single Go
/// message. Mirrors Go `validateSimplicityTxContextDACommitCore`.
fn validate_simplicity_tx_context_da_commit_core(
    core: Option<&DaCommitCore>,
) -> Result<&DaCommitCore, TxError> {
    match core {
        Some(core)
            if core.chunk_count != 0
                && u64::from(core.chunk_count) <= MAX_DA_CHUNK_COUNT
                && core.batch_sig.len() as u64 <= MAX_DA_MANIFEST_BYTES_PER_TX =>
        {
            Ok(core)
        }
        _ => Err(parse_err("invalid da_commit_core for tx_kind=0x01")),
    }
}

// u128-widened checked add: no truncation, and keeps Go's fail-closed overflow corner.
fn sum_values(values: impl Iterator<Item = u64>) -> Result<Uint128, TxError> {
    let mut total: u128 = 0;
    for value in values {
        total = total
            .checked_add(u128::from(value))
            .ok_or_else(|| parse_err("u128 overflow"))?;
    }
    Ok(Uint128::from_native(total))
}

impl SimplicityTxContext {
    pub fn input_views(&self) -> Vec<SimplicityTxContextIoView> {
        self.input_views.clone()
    }

    pub fn output_views(&self) -> Vec<SimplicityTxContextIoView> {
        self.output_views.clone()
    }

    pub fn self_view(
        &self,
        input_index: u16,
        sighash_type: u8,
        digest32: [u8; 32],
    ) -> Result<SimplicityTxContextSelfView, TxError> {
        let source = self
            .self_sources
            .get(input_index as usize)
            .ok_or_else(|| parse_err("simplicity txcontext self input index out of range"))?;
        if !source.is_core_simplicity {
            return Err(TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "simplicity txcontext self input is not CORE_SIMPLICITY",
            ));
        }
        Ok(SimplicityTxContextSelfView {
            self_program_cmr: source.program_cmr,
            digest32,
            self_state: source.state.clone(),
            self_value: source.value,
            input_index,
            sighash_type,
        })
    }

    /// The same-CMR group projection for `input_index`: every input AND output
    /// carrying this input's program_cmr, in ascending index order, as fresh clones
    /// (projection isolation). Fails closed on a non-CORE_SIMPLICITY or out-of-range
    /// index. Mirrors Go `SameCMRView`.
    pub fn same_cmr_view(
        &self,
        input_index: u16,
    ) -> Result<SimplicityTxContextSameCmrView, TxError> {
        let source = self
            .self_sources
            .get(input_index as usize)
            .ok_or_else(|| parse_err("simplicity txcontext self input index out of range"))?;
        if !source.is_core_simplicity {
            return Err(TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "simplicity txcontext self input is not CORE_SIMPLICITY",
            ));
        }
        Ok(SimplicityTxContextSameCmrView {
            program_cmr: source.program_cmr,
            inputs: self
                .group_inputs
                .get(&source.program_cmr)
                .cloned()
                .unwrap_or_default(),
            outputs: self
                .group_outputs
                .get(&source.program_cmr)
                .cloned()
                .unwrap_or_default(),
        })
    }
}

#[cfg(test)]
#[path = "tests/simplicity_txcontext.rs"]
mod tests;
