use crate::constants::{
    MAX_P2PK_COVENANT_DATA, MAX_SLH_DSA_SIG_BYTES, SLH_DSA_ACTIVATION_HEIGHT,
    SLH_DSA_SHAKE_256F_PUBKEY_BYTES, SUITE_ID_ML_DSA_87, SUITE_ID_SENTINEL,
    SUITE_ID_SLH_DSA_SHAKE_256F,
};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::tx::WitnessItem;
use crate::utxo_basic::UtxoEntry;
use crate::verify_sig_openssl::verify_sig;

/// Q-CF-18: validates SLH-DSA-SHAKE-256f witness-item byte lengths.
/// Returns Ok(()) for non-SLH suite IDs. Must be called after the activation check.
pub(crate) fn check_slh_canonical(w: &WitnessItem) -> Result<(), TxError> {
    if w.suite_id != SUITE_ID_SLH_DSA_SHAKE_256F {
        return Ok(());
    }
    if w.pubkey.len() as u64 != SLH_DSA_SHAKE_256F_PUBKEY_BYTES
        || w.signature.len() as u64 != MAX_SLH_DSA_SIG_BYTES
    {
        return Err(TxError::new(
            ErrorCode::TxErrSigNoncanonical,
            "non-canonical SLH-DSA witness item lengths",
        ));
    }
    Ok(())
}

pub(crate) fn validate_p2pk_spend(
    entry: &UtxoEntry,
    w: &WitnessItem,
    digest: &[u8; 32],
    block_height: u64,
) -> Result<(), TxError> {
    if w.suite_id != SUITE_ID_ML_DSA_87 && w.suite_id != SUITE_ID_SLH_DSA_SHAKE_256F {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_P2PK suite invalid",
        ));
    }
    if w.suite_id == SUITE_ID_SLH_DSA_SHAKE_256F && block_height < SLH_DSA_ACTIVATION_HEIGHT {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "SLH-DSA suite inactive at this height",
        ));
    }
    check_slh_canonical(w)?;
    if entry.covenant_data.len() as u64 != MAX_P2PK_COVENANT_DATA
        || entry.covenant_data[0] != w.suite_id
    {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_P2PK covenant_data invalid",
        ));
    }
    let mut key_id = [0u8; 32];
    key_id.copy_from_slice(&entry.covenant_data[1..33]);
    if sha3_256(&w.pubkey) != key_id {
        return Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "CORE_P2PK key binding mismatch",
        ));
    }

    let ok = verify_sig(w.suite_id, &w.pubkey, &w.signature, digest)?;
    if !ok {
        return Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "CORE_P2PK signature invalid",
        ));
    }
    Ok(())
}

pub(crate) fn validate_threshold_sig_spend(
    keys: &[[u8; 32]],
    threshold: u8,
    ws: &[WitnessItem],
    digest: &[u8; 32],
    block_height: u64,
    context: &'static str,
) -> Result<(), TxError> {
    if ws.len() != keys.len() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "witness slot assignment mismatch",
        ));
    }

    let mut valid: u8 = 0;
    for i in 0..keys.len() {
        let w = &ws[i];
        match w.suite_id {
            SUITE_ID_SENTINEL => continue,
            SUITE_ID_ML_DSA_87 | SUITE_ID_SLH_DSA_SHAKE_256F => {
                if w.suite_id == SUITE_ID_SLH_DSA_SHAKE_256F
                    && block_height < SLH_DSA_ACTIVATION_HEIGHT
                {
                    return Err(TxError::new(
                        ErrorCode::TxErrSigAlgInvalid,
                        "SLH-DSA suite inactive at this height",
                    ));
                }
                check_slh_canonical(w)?;
                if sha3_256(&w.pubkey) != keys[i] {
                    return Err(TxError::new(ErrorCode::TxErrSigInvalid, context));
                }
                let ok = verify_sig(w.suite_id, &w.pubkey, &w.signature, digest)?;
                if !ok {
                    return Err(TxError::new(ErrorCode::TxErrSigInvalid, context));
                }
                valid = valid.saturating_add(1);
            }
            _ => return Err(TxError::new(ErrorCode::TxErrSigAlgInvalid, context)),
        }
    }
    if valid < threshold {
        return Err(TxError::new(ErrorCode::TxErrSigInvalid, context));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        COV_TYPE_P2PK, SLH_DSA_ACTIVATION_HEIGHT, SLH_DSA_SHAKE_256F_PUBKEY_BYTES,
        SUITE_ID_SLH_DSA_SHAKE_256F,
    };

    fn dummy_entry() -> UtxoEntry {
        UtxoEntry {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: vec![0u8; 100],
            creation_height: 0,
            created_by_coinbase: false,
        }
    }

    #[test]
    fn slh_noncanonical_pubkey_p2pk() {
        let entry = dummy_entry();
        let w = WitnessItem {
            suite_id: SUITE_ID_SLH_DSA_SHAKE_256F,
            pubkey: vec![0x01], // wrong length
            signature: vec![0x01],
        };
        let err =
            validate_p2pk_spend(&entry, &w, &[0u8; 32], SLH_DSA_ACTIVATION_HEIGHT).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
    }

    #[test]
    fn slh_noncanonical_empty_sig_p2pk() {
        let entry = dummy_entry();
        let w = WitnessItem {
            suite_id: SUITE_ID_SLH_DSA_SHAKE_256F,
            pubkey: vec![0u8; SLH_DSA_SHAKE_256F_PUBKEY_BYTES as usize],
            signature: vec![],
        };
        let err =
            validate_p2pk_spend(&entry, &w, &[0u8; 32], SLH_DSA_ACTIVATION_HEIGHT).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
    }

    #[test]
    fn slh_noncanonical_short_sig_p2pk() {
        let entry = dummy_entry();
        let w = WitnessItem {
            suite_id: SUITE_ID_SLH_DSA_SHAKE_256F,
            pubkey: vec![0u8; SLH_DSA_SHAKE_256F_PUBKEY_BYTES as usize],
            signature: vec![0x01],
        };
        let err =
            validate_p2pk_spend(&entry, &w, &[0u8; 32], SLH_DSA_ACTIVATION_HEIGHT).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
    }

    #[test]
    fn slh_inactive_threshold() {
        let keys = vec![[0x01u8; 32]];
        let ws = vec![WitnessItem {
            suite_id: SUITE_ID_SLH_DSA_SHAKE_256F,
            pubkey: vec![0x01],
            signature: vec![0x01],
        }];
        let err = validate_threshold_sig_spend(
            &keys,
            1,
            &ws,
            &[0u8; 32],
            SLH_DSA_ACTIVATION_HEIGHT - 1,
            "ctx",
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn slh_noncanonical_threshold() {
        let keys = vec![[0x01u8; 32]];
        let ws = vec![WitnessItem {
            suite_id: SUITE_ID_SLH_DSA_SHAKE_256F,
            pubkey: vec![0x01], // wrong length
            signature: vec![0x01],
        }];
        let err = validate_threshold_sig_spend(
            &keys,
            1,
            &ws,
            &[0u8; 32],
            SLH_DSA_ACTIVATION_HEIGHT,
            "ctx",
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
    }
}
