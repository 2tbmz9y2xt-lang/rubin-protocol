use crate::constants::{MAX_P2PK_COVENANT_DATA, SUITE_ID_SENTINEL};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::sighash::{is_valid_sighash_type, sighash_v1_digest_with_cache, SighashV1PrehashCache};
use crate::suite_registry::{DefaultRotationProvider, RotationProvider, SuiteRegistry};
use crate::tx::Tx;
use crate::tx::WitnessItem;
use crate::utxo_basic::UtxoEntry;
use crate::verify_sig_openssl::verify_sig_with_registry;

fn extract_crypto_sig_and_sighash(w: &WitnessItem) -> Result<(&[u8], u8), TxError> {
    let Some((&sighash_type, crypto_sig)) = w.signature.split_last() else {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "missing sighash_type byte",
        ));
    };
    if !is_valid_sighash_type(sighash_type) {
        return Err(TxError::new(
            ErrorCode::TxErrSighashTypeInvalid,
            "invalid sighash_type",
        ));
    }
    Ok((crypto_sig, sighash_type))
}

#[allow(dead_code)]
pub(crate) fn validate_p2pk_spend(
    entry: &UtxoEntry,
    w: &WitnessItem,
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
) -> Result<(), TxError> {
    let mut cache = SighashV1PrehashCache::new(tx)?;
    validate_p2pk_spend_with_cache(
        entry,
        w,
        tx,
        input_index,
        input_value,
        chain_id,
        block_height,
        &mut cache,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_p2pk_spend_with_cache(
    entry: &UtxoEntry,
    w: &WitnessItem,
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    cache: &mut SighashV1PrehashCache<'_>,
) -> Result<(), TxError> {
    validate_p2pk_spend_at_height(
        entry,
        w,
        tx,
        input_index,
        input_value,
        chain_id,
        block_height,
        cache,
        None,
        None,
    )
}

/// Rotation-aware P2PK spend validation. When rotation or registry is None,
/// uses defaults (ML-DSA-87 genesis set). Parity with Go `validateP2PKSpendAtHeight`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_p2pk_spend_at_height(
    entry: &UtxoEntry,
    w: &WitnessItem,
    _tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    cache: &mut SighashV1PrehashCache<'_>,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
) -> Result<(), TxError> {
    let default_rp = DefaultRotationProvider;
    let default_reg = SuiteRegistry::default_registry();
    let rp: &dyn RotationProvider = rotation.unwrap_or(&default_rp);
    let reg = registry.unwrap_or(&default_reg);

    let native_spend = rp.native_spend_suites(block_height);
    if !native_spend.contains(w.suite_id) {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_P2PK suite not in native spend set",
        ));
    }

    let params = reg.lookup(w.suite_id).ok_or_else(|| {
        TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_P2PK suite not registered",
        )
    })?;

    if w.pubkey.len() as u64 != params.pubkey_len
        || w.signature.len() as u64 != params.sig_len + 1
    {
        return Err(TxError::new(
            ErrorCode::TxErrSigNoncanonical,
            "non-canonical witness item lengths",
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
    let (crypto_sig, sighash_type) = extract_crypto_sig_and_sighash(w)?;
    let digest =
        sighash_v1_digest_with_cache(cache, input_index, input_value, chain_id, sighash_type)?;
    let ok = verify_sig_with_registry(w.suite_id, &w.pubkey, crypto_sig, &digest, Some(reg))?;
    if !ok {
        return Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "CORE_P2PK signature invalid",
        ));
    }
    Ok(())
}

#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_threshold_sig_spend(
    keys: &[[u8; 32]],
    threshold: u8,
    ws: &[WitnessItem],
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    context: &'static str,
) -> Result<(), TxError> {
    let mut cache = SighashV1PrehashCache::new(tx)?;
    validate_threshold_sig_spend_with_cache(
        keys,
        threshold,
        ws,
        tx,
        input_index,
        input_value,
        chain_id,
        block_height,
        context,
        &mut cache,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_threshold_sig_spend_with_cache(
    keys: &[[u8; 32]],
    threshold: u8,
    ws: &[WitnessItem],
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    context: &'static str,
    cache: &mut SighashV1PrehashCache<'_>,
) -> Result<(), TxError> {
    validate_threshold_sig_spend_at_height(
        keys,
        threshold,
        ws,
        tx,
        input_index,
        input_value,
        chain_id,
        block_height,
        context,
        cache,
        None,
        None,
    )
}

/// Rotation-aware threshold-sig spend validation. When rotation or registry
/// is None, uses defaults (ML-DSA-87 genesis set). Parity with Go
/// `validateThresholdSigSpendAtHeight`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_threshold_sig_spend_at_height(
    keys: &[[u8; 32]],
    threshold: u8,
    ws: &[WitnessItem],
    _tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    context: &'static str,
    cache: &mut SighashV1PrehashCache<'_>,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
) -> Result<(), TxError> {
    let default_rp = DefaultRotationProvider;
    let default_reg = SuiteRegistry::default_registry();
    let rp: &dyn RotationProvider = rotation.unwrap_or(&default_rp);
    let reg = registry.unwrap_or(&default_reg);

    if ws.len() != keys.len() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "witness slot assignment mismatch",
        ));
    }

    let native_spend = rp.native_spend_suites(block_height);
    let mut valid: u8 = 0;

    for i in 0..keys.len() {
        let w = &ws[i];
        if w.suite_id == SUITE_ID_SENTINEL {
            if !w.pubkey.is_empty() || !w.signature.is_empty() {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "SENTINEL witness must be keyless",
                ));
            }
            continue;
        }

        if !native_spend.contains(w.suite_id) {
            return Err(TxError::new(ErrorCode::TxErrSigAlgInvalid, context));
        }

        let params = reg.lookup(w.suite_id).ok_or_else(|| {
            TxError::new(ErrorCode::TxErrSigAlgInvalid, context)
        })?;

        if w.pubkey.len() as u64 != params.pubkey_len
            || w.signature.len() as u64 != params.sig_len + 1
        {
            return Err(TxError::new(
                ErrorCode::TxErrSigNoncanonical,
                "non-canonical witness item lengths",
            ));
        }

        if sha3_256(&w.pubkey) != keys[i] {
            return Err(TxError::new(ErrorCode::TxErrSigInvalid, context));
        }
        let (crypto_sig, sighash_type) = extract_crypto_sig_and_sighash(w)?;
        let digest = sighash_v1_digest_with_cache(
            cache,
            input_index,
            input_value,
            chain_id,
            sighash_type,
        )?;
        let ok = verify_sig_with_registry(w.suite_id, &w.pubkey, crypto_sig, &digest, Some(reg))?;
        if !ok {
            return Err(TxError::new(ErrorCode::TxErrSigInvalid, context));
        }
        valid = valid.saturating_add(1);
    }
    if valid < threshold {
        return Err(TxError::new(ErrorCode::TxErrSigInvalid, context));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::COV_TYPE_P2PK;
    use crate::tx::{Tx, TxInput, TxOutput};

    fn dummy_entry() -> UtxoEntry {
        UtxoEntry {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: vec![0u8; 100],
            creation_height: 0,
            created_by_coinbase: false,
        }
    }

    fn dummy_tx_ctx() -> (Tx, u32, u64, [u8; 32]) {
        let mut prev = [0u8; 32];
        prev[0] = 0x42;
        let mut chain_id = [0u8; 32];
        chain_id[0] = 0x11;
        (
            Tx {
                version: 1,
                tx_kind: 0x00,
                tx_nonce: 7,
                inputs: vec![TxInput {
                    prev_txid: prev,
                    prev_vout: 0,
                    script_sig: vec![],
                    sequence: 0,
                }],
                outputs: vec![TxOutput {
                    value: 1,
                    covenant_type: COV_TYPE_P2PK,
                    covenant_data: vec![0u8; 33],
                }],
                locktime: 0,
                witness: vec![],
                da_payload: vec![],
                da_commit_core: None,
                da_chunk_core: None,
            },
            0,
            1,
            chain_id,
        )
    }

    #[test]
    fn p2pk_suite_invalid_rejected_sig_alg_invalid() {
        let entry = dummy_entry();
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = WitnessItem {
            suite_id: 0x02, // non-native / unknown suite
            pubkey: vec![0x01],
            signature: vec![0x01],
        };
        let err = validate_p2pk_spend(&entry, &w, &tx, input_index, input_value, chain_id, 0)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }
}
