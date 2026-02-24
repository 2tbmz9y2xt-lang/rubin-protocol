use crate::constants::{
    LOCK_MODE_HEIGHT, LOCK_MODE_TIMESTAMP, MAX_HTLC_COVENANT_DATA, MAX_HTLC_PREIMAGE_BYTES,
    MAX_SLH_DSA_SIG_BYTES, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SLH_DSA_ACTIVATION_HEIGHT,
    SLH_DSA_SHAKE_256F_PUBKEY_BYTES, SUITE_ID_ML_DSA_87, SUITE_ID_SENTINEL,
    SUITE_ID_SLH_DSA_SHAKE_256F,
};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::tx::WitnessItem;
use crate::utxo_basic::UtxoEntry;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcCovenant {
    pub hash: [u8; 32],
    pub lock_mode: u8,
    pub lock_value: u64,
    pub claim_key_id: [u8; 32],
    pub refund_key_id: [u8; 32],
}

pub fn parse_htlc_covenant_data(cov_data: &[u8]) -> Result<HtlcCovenant, TxError> {
    if cov_data.len() as u64 != MAX_HTLC_COVENANT_DATA {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_HTLC covenant_data length mismatch",
        ));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&cov_data[0..32]);
    let lock_mode = cov_data[32];
    let lock_value = u64::from_le_bytes(
        cov_data[33..41]
            .try_into()
            .map_err(|_| TxError::new(ErrorCode::TxErrParse, "bad CORE_HTLC lock_value"))?,
    );
    let mut claim_key_id = [0u8; 32];
    claim_key_id.copy_from_slice(&cov_data[41..73]);
    let mut refund_key_id = [0u8; 32];
    refund_key_id.copy_from_slice(&cov_data[73..105]);

    if lock_mode != LOCK_MODE_HEIGHT && lock_mode != LOCK_MODE_TIMESTAMP {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_HTLC lock_mode invalid",
        ));
    }
    if lock_value == 0 {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_HTLC lock_value must be > 0",
        ));
    }
    if claim_key_id == refund_key_id {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "CORE_HTLC claim/refund key_id must differ",
        ));
    }

    Ok(HtlcCovenant {
        hash,
        lock_mode,
        lock_value,
        claim_key_id,
        refund_key_id,
    })
}

pub fn validate_htlc_spend(
    entry: &UtxoEntry,
    path_item: &WitnessItem,
    sig_item: &WitnessItem,
    block_height: u64,
    block_timestamp: u64,
) -> Result<(), TxError> {
    let cov = parse_htlc_covenant_data(&entry.covenant_data)?;

    if path_item.suite_id != SUITE_ID_SENTINEL {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "CORE_HTLC selector suite_id invalid",
        ));
    }
    if path_item.pubkey.len() != 32 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "CORE_HTLC selector key_id length invalid",
        ));
    }
    if path_item.signature.is_empty() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "CORE_HTLC selector payload too short",
        ));
    }

    let mut selector_key_id = [0u8; 32];
    selector_key_id.copy_from_slice(&path_item.pubkey);

    let path_id = path_item.signature[0];
    let expected_key_id = match path_id {
        0x00 => {
            // Claim path.
            if selector_key_id != cov.claim_key_id {
                return Err(TxError::new(
                    ErrorCode::TxErrSigInvalid,
                    "CORE_HTLC claim key_id mismatch",
                ));
            }
            if path_item.signature.len() < 3 {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "CORE_HTLC claim payload too short",
                ));
            }
            let pre_len =
                u16::from_le_bytes(path_item.signature[1..3].try_into().map_err(|_| {
                    TxError::new(ErrorCode::TxErrParse, "bad CORE_HTLC preimage_len")
                })?) as usize;
            if pre_len == 0 {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "CORE_HTLC preimage_len must be > 0",
                ));
            }
            if pre_len as u64 > MAX_HTLC_PREIMAGE_BYTES {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "CORE_HTLC preimage length overflow",
                ));
            }
            if path_item.signature.len() != 3 + pre_len {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "CORE_HTLC claim payload length mismatch",
                ));
            }
            let preimage = &path_item.signature[3..];
            if sha3_256(preimage) != cov.hash {
                return Err(TxError::new(
                    ErrorCode::TxErrSigInvalid,
                    "CORE_HTLC claim preimage hash mismatch",
                ));
            }
            cov.claim_key_id
        }
        0x01 => {
            // Refund path.
            if selector_key_id != cov.refund_key_id {
                return Err(TxError::new(
                    ErrorCode::TxErrSigInvalid,
                    "CORE_HTLC refund key_id mismatch",
                ));
            }
            if path_item.signature.len() != 1 {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "CORE_HTLC refund payload length mismatch",
                ));
            }
            if cov.lock_mode == LOCK_MODE_HEIGHT {
                if block_height < cov.lock_value {
                    return Err(TxError::new(
                        ErrorCode::TxErrTimelockNotMet,
                        "CORE_HTLC height lock not met",
                    ));
                }
            } else if block_timestamp < cov.lock_value {
                return Err(TxError::new(
                    ErrorCode::TxErrTimelockNotMet,
                    "CORE_HTLC timestamp lock not met",
                ));
            }
            cov.refund_key_id
        }
        _ => {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "CORE_HTLC unknown spend path",
            ));
        }
    };

    match sig_item.suite_id {
        SUITE_ID_ML_DSA_87 => {
            if sig_item.pubkey.len() as u64 != ML_DSA_87_PUBKEY_BYTES
                || sig_item.signature.len() as u64 != ML_DSA_87_SIG_BYTES
            {
                return Err(TxError::new(
                    ErrorCode::TxErrSigNoncanonical,
                    "non-canonical ML-DSA witness item lengths",
                ));
            }
        }
        SUITE_ID_SLH_DSA_SHAKE_256F => {
            if block_height < SLH_DSA_ACTIVATION_HEIGHT {
                return Err(TxError::new(
                    ErrorCode::TxErrSigAlgInvalid,
                    "SLH-DSA suite inactive at this height",
                ));
            }
            if sig_item.pubkey.len() as u64 != SLH_DSA_SHAKE_256F_PUBKEY_BYTES
                || sig_item.signature.is_empty()
                || sig_item.signature.len() as u64 > MAX_SLH_DSA_SIG_BYTES
            {
                return Err(TxError::new(
                    ErrorCode::TxErrSigNoncanonical,
                    "non-canonical SLH-DSA witness item lengths",
                ));
            }
        }
        _ => {
            return Err(TxError::new(
                ErrorCode::TxErrSigAlgInvalid,
                "CORE_HTLC sig_item suite invalid",
            ));
        }
    }

    if sha3_256(&sig_item.pubkey) != expected_key_id {
        return Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "CORE_HTLC signature key binding mismatch",
        ));
    }

    Ok(())
}
