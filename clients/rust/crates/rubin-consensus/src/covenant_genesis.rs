use crate::constants::{
    COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT, COV_TYPE_HTLC, COV_TYPE_P2PK, COV_TYPE_RESERVED_FUTURE,
    COV_TYPE_TIMELOCK, COV_TYPE_VAULT, MAX_ANCHOR_PAYLOAD_SIZE, MAX_P2PK_COVENANT_DATA,
    MAX_TIMELOCK_COVENANT_DATA, SUITE_ID_ML_DSA_87,
};
use crate::error::{ErrorCode, TxError};
use crate::tx::Tx;

pub fn validate_tx_covenants_genesis(tx: &Tx) -> Result<(), TxError> {
    for out in &tx.outputs {
        match out.covenant_type {
            COV_TYPE_P2PK => {
                if out.covenant_data.len() as u64 != MAX_P2PK_COVENANT_DATA {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "invalid CORE_P2PK covenant_data length",
                    ));
                }
                if out.covenant_data[0] != SUITE_ID_ML_DSA_87 {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "invalid CORE_P2PK suite_id",
                    ));
                }
            }
            COV_TYPE_TIMELOCK => {
                if out.covenant_data.len() as u64 != MAX_TIMELOCK_COVENANT_DATA {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "invalid CORE_TIMELOCK covenant_data length",
                    ));
                }
                let lock_mode = out.covenant_data[0];
                if lock_mode != 0x00 && lock_mode != 0x01 {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "invalid CORE_TIMELOCK lock_mode",
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
            COV_TYPE_VAULT => {
                // Q-V01 pending: until vault semantics are ratified, reject 0x0101.
                return Err(TxError::new(
                    ErrorCode::TxErrCovenantTypeInvalid,
                    "CORE_VAULT semantics pending",
                ));
            }
            COV_TYPE_RESERVED_FUTURE | COV_TYPE_HTLC | COV_TYPE_DA_COMMIT => {
                return Err(TxError::new(
                    ErrorCode::TxErrCovenantTypeInvalid,
                    "reserved or unsupported covenant_type",
                ));
            }
            _ => {
                return Err(TxError::new(
                    ErrorCode::TxErrCovenantTypeInvalid,
                    "unknown covenant_type",
                ));
            }
        }
    }

    Ok(())
}
