use std::collections::HashMap;

use crate::constants::{
    COV_TYPE_ANCHOR, COV_TYPE_CORE_SIMPLICITY, COV_TYPE_CORE_STEALTH, COV_TYPE_DA_COMMIT,
    COV_TYPE_HTLC, COV_TYPE_MULTISIG, COV_TYPE_P2PK, COV_TYPE_RESERVED_FUTURE, COV_TYPE_VAULT,
    MAX_ANCHOR_PAYLOAD_SIZE, MAX_COVENANT_DATA_PER_OUTPUT, MAX_P2PK_COVENANT_DATA,
    SIMPLICITY_MAX_GROUP_OUTPUTS,
};
use crate::error::{ErrorCode, TxError};
use crate::htlc::parse_htlc_covenant_data;
use crate::simplicity_covenant::{
    validate_core_simplicity_covenant_data, validate_core_simplicity_deployment_active,
};
use crate::stealth::parse_stealth_covenant_data;
use crate::suite_registry::{DefaultRotationProvider, RotationProvider};
use crate::tx::{Tx, TxOutput};
use crate::vault::{parse_multisig_covenant_data, parse_vault_covenant_data};

/// Validates covenant structure at creation time. The `rotation` parameter
/// controls which signature suites are valid for native covenant creation
/// at the given block height. Pass `None` for the default pre-rotation
/// behaviour ({ML-DSA-87} only).
pub fn validate_tx_covenants_genesis(
    tx: &Tx,
    block_height: u64,
    rotation: Option<&dyn RotationProvider>,
) -> Result<(), TxError> {
    let default_rp = DefaultRotationProvider;
    let rp: &dyn RotationProvider = rotation.unwrap_or(&default_rp);

    fn validate_p2pk_anchor(
        out: &TxOutput,
        block_height: u64,
        rp: &dyn RotationProvider,
    ) -> Result<bool, TxError> {
        match out.covenant_type {
            COV_TYPE_P2PK => {
                if out.value == 0 {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "CORE_P2PK value must be > 0",
                    ));
                }
                if out.covenant_data.len() as u64 != MAX_P2PK_COVENANT_DATA {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "invalid CORE_P2PK covenant_data length",
                    ));
                }
                let suite_id = out.covenant_data[0];
                if !rp.native_create_suites(block_height).contains(suite_id) {
                    return Err(TxError::new(
                        ErrorCode::TxErrSigAlgInvalid,
                        "CORE_P2PK suite not in native create set",
                    ));
                }
            }
            COV_TYPE_ANCHOR => {
                if out.value != 0 {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "CORE_ANCHOR value must be 0",
                    ));
                }
                let cov_len = out.covenant_data.len() as u64;
                if cov_len == 0 || cov_len > MAX_ANCHOR_PAYLOAD_SIZE {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "invalid CORE_ANCHOR covenant_data length",
                    ));
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn validate_vault_multisig_htlc(out: &TxOutput) -> Result<bool, TxError> {
        match out.covenant_type {
            COV_TYPE_VAULT => {
                if out.value == 0 {
                    return Err(TxError::new(
                        ErrorCode::TxErrVaultParamsInvalid,
                        "CORE_VAULT value must be > 0",
                    ));
                }
                parse_vault_covenant_data(&out.covenant_data)?;
            }
            COV_TYPE_MULTISIG => {
                if out.value == 0 {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "CORE_MULTISIG value must be > 0",
                    ));
                }
                parse_multisig_covenant_data(&out.covenant_data)?;
            }
            COV_TYPE_HTLC => {
                parse_htlc_covenant_data(&out.covenant_data)?;
                if out.value == 0 {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "CORE_HTLC value must be > 0",
                    ));
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn validate_stealth_da(out: &TxOutput, tx_kind: u8) -> Result<bool, TxError> {
        match out.covenant_type {
            COV_TYPE_CORE_STEALTH => {
                if out.value == 0 {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "CORE_STEALTH value must be > 0",
                    ));
                }
                if out.covenant_data.len() as u64 > MAX_COVENANT_DATA_PER_OUTPUT {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "CORE_STEALTH covenant_data length exceeds MAX_COVENANT_DATA_PER_OUTPUT",
                    ));
                }
                let _ = parse_stealth_covenant_data(&out.covenant_data)?;
            }
            COV_TYPE_DA_COMMIT => {
                if tx_kind != 0x01 {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "CORE_DA_COMMIT allowed only in tx_kind=0x01",
                    ));
                }
                if out.value != 0 {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "CORE_DA_COMMIT value must be 0",
                    ));
                }
                if out.covenant_data.len() != 32 {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "invalid CORE_DA_COMMIT covenant_data length",
                    ));
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn validate_core_simplicity_genesis_output(
        out: &TxOutput,
        block_height: u64,
        rp: &dyn RotationProvider,
    ) -> Result<[u8; 32], TxError> {
        // Deployment activation must precede covenant_data parsing.
        validate_core_simplicity_deployment_active(block_height, rp)
            .and_then(|_| validate_core_simplicity_covenant_data(out.value, &out.covenant_data))
            .and_then(|_| {
                out.covenant_data
                    .first_chunk::<32>()
                    .copied()
                    .ok_or(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "CORE_SIMPLICITY program_cmr parse failure",
                    ))
            })
    }

    // Complete per-output validation in wire order before applying the
    // transaction-level same-program_cmr cap, so a later creation error wins.
    let mut simplicity_output_cmrs = Vec::new();
    tx.outputs
        .iter()
        .try_for_each(|out| match out.covenant_type {
            COV_TYPE_P2PK | COV_TYPE_ANCHOR => {
                validate_p2pk_anchor(out, block_height, rp).map(|_| ())
            }
            COV_TYPE_VAULT | COV_TYPE_MULTISIG | COV_TYPE_HTLC => {
                validate_vault_multisig_htlc(out).map(|_| ())
            }
            COV_TYPE_CORE_STEALTH | COV_TYPE_DA_COMMIT => {
                validate_stealth_da(out, tx.tx_kind).map(|_| ())
            }
            COV_TYPE_CORE_SIMPLICITY => {
                validate_core_simplicity_genesis_output(out, block_height, rp).map(|program_cmr| {
                    simplicity_output_cmrs.push(program_cmr);
                })
            }
            COV_TYPE_RESERVED_FUTURE => Err(TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "reserved covenant_type",
            )),
            _ => Err(TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "unknown covenant_type",
            )),
        })?;

    validate_simplicity_output_group_cap(&simplicity_output_cmrs)
}

/// Validates one output with the existing creation validator and returns a
/// CORE_SIMPLICITY CMR for the caller's coinbase transaction-wide cap accounting.
pub(crate) fn validate_tx_output_covenant_genesis(
    tx_kind: u8,
    out: &TxOutput,
    block_height: u64,
    rotation: &dyn RotationProvider,
) -> Result<Option<[u8; 32]>, TxError> {
    let tx = Tx {
        version: 1,
        tx_kind,
        tx_nonce: 0,
        inputs: Vec::new(),
        outputs: vec![out.clone()],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: Vec::new(),
    };
    validate_tx_covenants_genesis(&tx, block_height, Some(rotation))?;
    if out.covenant_type != COV_TYPE_CORE_SIMPLICITY {
        return Ok(None);
    }
    out.covenant_data
        .first_chunk::<32>()
        .copied()
        .map(Some)
        .ok_or_else(|| {
            TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "CORE_SIMPLICITY program_cmr parse failure",
            )
        })
}

pub(crate) fn validate_simplicity_output_group_cap(
    simplicity_output_cmrs: &[[u8; 32]],
) -> Result<(), TxError> {
    let mut groups = HashMap::with_capacity(simplicity_output_cmrs.len());
    simplicity_output_cmrs.iter().try_for_each(|program_cmr| {
        let count = groups.entry(*program_cmr).or_insert(0usize);
        *count += 1;
        if *count > SIMPLICITY_MAX_GROUP_OUTPUTS {
            return Err(TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "CORE_SIMPLICITY same-cmr output group exceeds limit",
            ));
        }
        Ok(())
    })
}
