//! CORE_SIMPLICITY (0x0106) covenant rules.
//!
//! Rust mirror of the merged Go reference (`clients/go/consensus/simplicity_covenant.go`):
//! the creation-side `covenant_data` structure validation plus the
//! deployment-active gate (RUB-494/590), and the spend-side fail-closed reject
//! (RUB-591). Creation is accepted only when the rotation provider reports the
//! Simplicity deployment active at the block height; otherwise it is rejected
//! ("deployment not active"), the default (fail-closed) for any provider that
//! does not wire a deployment. Spending a 0x0106 output is rejected with the
//! dedicated "spend evaluation not enabled" message ahead of generic
//! covenant/witness errors; actual spend evaluation is a later slice (RUB-505).

use crate::compactsize::read_compact_size;
use crate::constants::{COV_TYPE_CORE_SIMPLICITY, MAX_SIMPLICITY_STATE_BYTES};
use crate::error::{ErrorCode, TxError};
use crate::suite_registry::RotationProvider;
use crate::utxo_basic::UtxoEntry;
use crate::wire_read::Reader;

/// Rejects CORE_SIMPLICITY creation unless the rotation provider reports the
/// Simplicity deployment active at `height`. Mirrors Go
/// `validateCoreSimplicityDeploymentActive`: a provider that does not wire a
/// deployment (the default) yields "deployment not active".
pub(crate) fn validate_core_simplicity_deployment_active(
    height: u64,
    rotation: &dyn RotationProvider,
) -> Result<(), TxError> {
    if rotation.simplicity_active_at_height(height) {
        Ok(())
    } else {
        Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_SIMPLICITY deployment not active",
        ))
    }
}

/// The dedicated fail-closed reject for spending a CORE_SIMPLICITY (0x0106)
/// output. Mirrors Go `rejectCoreSimplicitySpend`: spend evaluation is not yet
/// enabled, so any 0x0106 spend is rejected with this exact code+message, ahead
/// of generic covenant/witness errors.
pub(crate) fn reject_core_simplicity_spend() -> TxError {
    TxError::new(
        ErrorCode::TxErrCovenantTypeInvalid,
        "CORE_SIMPLICITY spend evaluation not enabled",
    )
}

/// Rejects if any resolved input spends a CORE_SIMPLICITY (0x0106) output.
/// Mirrors Go `rejectCoreSimplicitySpendIfPresent`.
pub(crate) fn reject_core_simplicity_spend_if_present(inputs: &[UtxoEntry]) -> Result<(), TxError> {
    if inputs
        .iter()
        .any(|input| input.covenant_type == COV_TYPE_CORE_SIMPLICITY)
    {
        return Err(reject_core_simplicity_spend());
    }
    Ok(())
}

/// Parses a CORE_SIMPLICITY covenant blob: rejects `value == 0`, then
/// `program_cmr:bytes32 || state_len:CompactSize || state` (no trailing bytes,
/// `state_len <= MAX_SIMPLICITY_STATE_BYTES`), returning the CMR and a borrowed
/// `state` slice (callers copy only when they need ownership). Mirrors Go
/// `parseCoreSimplicityCovenantData` (returns a slice; `Build` copies).
pub(crate) fn parse_core_simplicity_covenant_data(
    value: u64,
    covenant_data: &[u8],
) -> Result<([u8; 32], &[u8]), TxError> {
    if value == 0 {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_SIMPLICITY value must be > 0",
        ));
    }
    let mut r = Reader::new(covenant_data);
    let cmr_bytes = r.read_bytes(32).map_err(|_| {
        TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_SIMPLICITY program_cmr parse failure",
        )
    })?;
    let mut program_cmr = [0u8; 32];
    program_cmr.copy_from_slice(cmr_bytes);

    let (state_len_u64, state_len_varint_bytes) = read_compact_size(&mut r).map_err(|_| {
        TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_SIMPLICITY state_len parse failure",
        )
    })?;
    if state_len_u64 > MAX_SIMPLICITY_STATE_BYTES {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_SIMPLICITY state_len too large",
        ));
    }
    let state_len = state_len_u64 as usize;

    let state = r.read_bytes(state_len).map_err(|_| {
        TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_SIMPLICITY state parse failure",
        )
    })?;
    if covenant_data.len() != 32 + state_len_varint_bytes + state_len {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_SIMPLICITY covenant_data length mismatch",
        ));
    }
    Ok((program_cmr, state))
}

/// Validates a CORE_SIMPLICITY creation output's `covenant_data`: `value > 0`
/// and the structure parses exactly. Mirrors Go
/// `validateCoreSimplicityCovenantData`.
pub(crate) fn validate_core_simplicity_covenant_data(
    value: u64,
    covenant_data: &[u8],
) -> Result<(), TxError> {
    parse_core_simplicity_covenant_data(value, covenant_data)?;
    Ok(())
}

#[cfg(test)]
#[path = "tests/simplicity_covenant.rs"]
mod tests;
