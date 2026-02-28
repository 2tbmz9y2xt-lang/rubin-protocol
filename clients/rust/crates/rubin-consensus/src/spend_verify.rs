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
    if w.suite_id == SUITE_ID_SLH_DSA_SHAKE_256F
        && (w.pubkey.len() as u64 != SLH_DSA_SHAKE_256F_PUBKEY_BYTES
            || w.signature.is_empty()
            || w.signature.len() as u64 > MAX_SLH_DSA_SIG_BYTES)
    {
        return Err(TxError::new(
            ErrorCode::TxErrSigNoncanonical,
            "non-canonical SLH-DSA witness item lengths",
        ));
    }
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
                if w.suite_id == SUITE_ID_SLH_DSA_SHAKE_256F
                    && (w.pubkey.len() as u64 != SLH_DSA_SHAKE_256F_PUBKEY_BYTES
                        || w.signature.is_empty()
                        || w.signature.len() as u64 > MAX_SLH_DSA_SIG_BYTES)
                {
                    return Err(TxError::new(
                        ErrorCode::TxErrSigNoncanonical,
                        "non-canonical SLH-DSA witness item lengths",
                    ));
                }
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
