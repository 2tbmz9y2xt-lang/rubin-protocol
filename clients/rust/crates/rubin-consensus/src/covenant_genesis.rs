use crate::constants::{
    COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT, COV_TYPE_EXT, COV_TYPE_HTLC, COV_TYPE_MULTISIG,
    COV_TYPE_P2PK, COV_TYPE_RESERVED_FUTURE, COV_TYPE_VAULT, MAX_ANCHOR_PAYLOAD_SIZE,
    MAX_P2PK_COVENANT_DATA, SLH_DSA_ACTIVATION_HEIGHT, SUITE_ID_ML_DSA_87,
    SUITE_ID_SLH_DSA_SHAKE_256F,
};
use crate::error::{ErrorCode, TxError};
use crate::ext::parse_core_ext_covenant_data;
use crate::htlc::parse_htlc_covenant_data;
use crate::tx::Tx;
use crate::vault::{parse_multisig_covenant_data, parse_vault_covenant_data};

pub fn validate_tx_covenants_genesis(tx: &Tx, block_height: u64) -> Result<(), TxError> {
    for out in &tx.outputs {
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
                if suite_id != SUITE_ID_ML_DSA_87 && suite_id != SUITE_ID_SLH_DSA_SHAKE_256F {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "invalid CORE_P2PK suite_id",
                    ));
                }
                if suite_id == SUITE_ID_SLH_DSA_SHAKE_256F
                    && block_height < SLH_DSA_ACTIVATION_HEIGHT
                {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "CORE_P2PK SLH-DSA suite inactive at this height",
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
                if out.value == 0 {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "CORE_HTLC value must be > 0",
                    ));
                }
                parse_htlc_covenant_data(&out.covenant_data)?;
            }
            COV_TYPE_EXT => {
                if out.value == 0 {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        "CORE_EXT value must be > 0",
                    ));
                }
                parse_core_ext_covenant_data(&out.covenant_data)?;
            }
            COV_TYPE_DA_COMMIT => {
                if tx.tx_kind != 0x01 {
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
            COV_TYPE_RESERVED_FUTURE => {
                return Err(TxError::new(
                    ErrorCode::TxErrCovenantTypeInvalid,
                    "reserved covenant_type",
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
