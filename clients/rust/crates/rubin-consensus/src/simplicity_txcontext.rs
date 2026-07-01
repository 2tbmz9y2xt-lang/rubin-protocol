//! CORE_SIMPLICITY (0x0106) transaction-context core construction — Rust mirror
//! of the merged Go reference `simplicity_txcontext.go` (RUB-498). Crypto-free
//! base + input/output views + per-input self view; group/DA views and spend
//! dispatch are later slices (RUB-501 / RUB-459D / RUB-505).

use crate::constants::{COV_TYPE_CORE_SIMPLICITY, MAX_TX_INPUTS, MAX_TX_OUTPUTS};
use crate::error::{ErrorCode, TxError};
use crate::simplicity_covenant::parse_core_simplicity_covenant_data;
use crate::tx::Tx;
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

    let total_in = sum_values(resolved_inputs.iter().map(|entry| entry.value))?;
    let total_out = sum_values(tx.outputs.iter().map(|out| out.value))?;

    // Counts are bounded by MAX_TX_INPUTS/MAX_TX_OUTPUTS above, so the u16
    // narrowing below cannot truncate.
    let base = SimplicityTxContextBase {
        chain_id,
        total_in,
        total_out,
        height: block_height,
        tx_nonce: tx.tx_nonce,
        locktime: tx.locktime,
        input_count: tx.inputs.len() as u16,
        output_count: tx.outputs.len() as u16,
        tx_kind: tx.tx_kind,
    };

    let mut input_views = Vec::with_capacity(resolved_inputs.len());
    let mut self_sources = Vec::with_capacity(resolved_inputs.len());
    for entry in resolved_inputs {
        input_views.push(SimplicityTxContextIoView {
            value: entry.value,
            covenant_type: entry.covenant_type,
        });
        if entry.covenant_type != COV_TYPE_CORE_SIMPLICITY {
            self_sources.push(SimplicityTxContextSelfSource {
                program_cmr: [0u8; 32],
                state: Vec::new(),
                value: 0,
                is_core_simplicity: false,
            });
            continue;
        }
        let (program_cmr, state) = parse_core_simplicity_covenant_data(&entry.covenant_data)?;
        self_sources.push(SimplicityTxContextSelfSource {
            program_cmr,
            state,
            value: entry.value,
            is_core_simplicity: true,
        });
    }

    let output_views = tx
        .outputs
        .iter()
        .map(|out| SimplicityTxContextIoView {
            value: out.value,
            covenant_type: out.covenant_type,
        })
        .collect();

    Ok(Some(SimplicityTxContext {
        base,
        input_views,
        output_views,
        self_sources,
    }))
}

// Widening each u64 to u128 before the add avoids truncation; the checked add
// keeps the Go reference's fail-closed overflow corner (unreachable for the
// wire-bounded counts).
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
}

#[cfg(test)]
#[path = "tests/simplicity_txcontext.rs"]
mod tests;
