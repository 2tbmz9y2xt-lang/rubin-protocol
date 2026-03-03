use crate::constants::{
    MAX_SLH_DSA_SIG_BYTES, MAX_STEALTH_COVENANT_DATA, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES,
    ML_KEM_1024_CT_BYTES, SLH_DSA_ACTIVATION_HEIGHT, SLH_DSA_SHAKE_256F_PUBKEY_BYTES,
    SUITE_ID_ML_DSA_87, SUITE_ID_SLH_DSA_SHAKE_256F,
};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::sighash::{is_valid_sighash_type, sighash_v1_digest_with_type};
use crate::tx::{Tx, WitnessItem};
use crate::utxo_basic::UtxoEntry;
use crate::verify_sig_openssl::verify_sig;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StealthCovenant {
    pub ciphertext: Vec<u8>,
    pub one_time_key_id: [u8; 32],
}

pub fn parse_stealth_covenant_data(cov_data: &[u8]) -> Result<StealthCovenant, TxError> {
    if cov_data.len() as u64 != MAX_STEALTH_COVENANT_DATA {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_STEALTH covenant_data length mismatch",
        ));
    }
    if ML_KEM_1024_CT_BYTES + 32 != MAX_STEALTH_COVENANT_DATA {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "CORE_STEALTH constants mismatch",
        ));
    }
    let mut one_time_key_id = [0u8; 32];
    one_time_key_id.copy_from_slice(
        &cov_data[ML_KEM_1024_CT_BYTES as usize..MAX_STEALTH_COVENANT_DATA as usize],
    );
    Ok(StealthCovenant {
        ciphertext: cov_data[..ML_KEM_1024_CT_BYTES as usize].to_vec(),
        one_time_key_id,
    })
}

pub fn validate_stealth_spend(
    entry: &UtxoEntry,
    w: &WitnessItem,
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
) -> Result<(), TxError> {
    let cov = parse_stealth_covenant_data(&entry.covenant_data)?;
    let _ = cov.ciphertext;

    if w.suite_id != SUITE_ID_ML_DSA_87 && w.suite_id != SUITE_ID_SLH_DSA_SHAKE_256F {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_STEALTH suite invalid",
        ));
    }
    if w.suite_id == SUITE_ID_SLH_DSA_SHAKE_256F && block_height < SLH_DSA_ACTIVATION_HEIGHT {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "SLH-DSA suite inactive at this height",
        ));
    }

    match w.suite_id {
        SUITE_ID_ML_DSA_87 => {
            if w.pubkey.len() as u64 != ML_DSA_87_PUBKEY_BYTES
                || w.signature.len() as u64 != ML_DSA_87_SIG_BYTES + 1
            {
                return Err(TxError::new(
                    ErrorCode::TxErrSigNoncanonical,
                    "non-canonical ML-DSA witness item lengths",
                ));
            }
        }
        SUITE_ID_SLH_DSA_SHAKE_256F => {
            if w.pubkey.len() as u64 != SLH_DSA_SHAKE_256F_PUBKEY_BYTES
                || w.signature.len() as u64 != MAX_SLH_DSA_SIG_BYTES + 1
            {
                return Err(TxError::new(
                    ErrorCode::TxErrSigNoncanonical,
                    "non-canonical SLH-DSA witness item lengths",
                ));
            }
        }
        _ => {}
    }

    if sha3_256(&w.pubkey) != cov.one_time_key_id {
        return Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "CORE_STEALTH key binding mismatch",
        ));
    }

    let Some((&sighash_type, crypto_sig)) = w.signature.split_last() else {
        return Err(TxError::new(
            ErrorCode::TxErrSighashTypeInvalid,
            "missing sighash_type byte",
        ));
    };
    if !is_valid_sighash_type(sighash_type) {
        return Err(TxError::new(
            ErrorCode::TxErrSighashTypeInvalid,
            "invalid sighash_type",
        ));
    }
    let digest = sighash_v1_digest_with_type(tx, input_index, input_value, chain_id, sighash_type)?;
    let ok = verify_sig(w.suite_id, &w.pubkey, crypto_sig, &digest)?;
    if !ok {
        return Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "CORE_STEALTH signature invalid",
        ));
    }
    Ok(())
}
