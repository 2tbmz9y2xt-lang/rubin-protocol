//! CORE_SIMPLICITY (0x0106) creation-side covenant rules.
//!
//! Rust mirror of the merged Go reference (`clients/go/consensus/simplicity_covenant.go`,
//! RUB-494): the creation-side `covenant_data` structure validation plus the
//! deployment-active gate. Creation is accepted only when the rotation provider
//! reports the Simplicity deployment active at the block height; otherwise it is
//! rejected ("deployment not active"), which is the default (fail-closed) for any
//! provider that does not wire a deployment. Spend-side handling (witness_slots,
//! spend reject, apply/precompute error-priority) lands in RUB-591.

use crate::compactsize::read_compact_size;
use crate::constants::MAX_SIMPLICITY_STATE_BYTES;
use crate::error::{ErrorCode, TxError};
use crate::suite_registry::RotationProvider;
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

/// Validates a CORE_SIMPLICITY creation output's `covenant_data`:
/// `program_cmr:bytes32 || state_len:CompactSize || state`, with
/// `value > 0`, `state_len <= MAX_SIMPLICITY_STATE_BYTES`, and the total
/// length matching exactly (no trailing bytes). Mirrors Go
/// `validateCoreSimplicityCovenantData`.
pub(crate) fn validate_core_simplicity_covenant_data(
    value: u64,
    covenant_data: &[u8],
) -> Result<(), TxError> {
    if value == 0 {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_SIMPLICITY value must be > 0",
        ));
    }

    let mut r = Reader::new(covenant_data);
    if r.read_bytes(32).is_err() {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_SIMPLICITY program_cmr parse failure",
        ));
    }

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

    if r.read_bytes(state_len).is_err() {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_SIMPLICITY state parse failure",
        ));
    }
    if covenant_data.len() != 32 + state_len_varint_bytes + state_len {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_SIMPLICITY covenant_data length mismatch",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/simplicity_covenant.rs"]
mod tests;
