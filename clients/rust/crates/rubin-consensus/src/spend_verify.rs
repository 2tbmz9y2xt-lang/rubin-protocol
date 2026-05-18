use crate::constants::{MAX_P2PK_COVENANT_DATA, SUITE_ID_SENTINEL};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::sig_queue::{queue_or_verify_signature, SigCheckQueue};
use crate::sighash::{is_valid_sighash_type, sighash_v1_digest_with_cache, SighashV1PrehashCache};
use crate::suite_registry::{
    DefaultRotationProvider, NativeSuiteSet, RotationProvider, SuiteParams, SuiteRegistry,
};
use crate::tx::Tx;
use crate::tx::WitnessItem;
use crate::utxo_basic::UtxoEntry;

pub(crate) fn extract_crypto_sig_and_sighash(w: &WitnessItem) -> Result<(&[u8], u8), TxError> {
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
    validate_p2pk_spend_q(
        entry,
        w,
        input_index,
        input_value,
        chain_id,
        block_height,
        cache,
        None,
        rotation,
        registry,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_p2pk_spend_q(
    entry: &UtxoEntry,
    w: &WitnessItem,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    cache: &mut SighashV1PrehashCache<'_>,
    sig_queue: Option<&mut SigCheckQueue>,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
) -> Result<(), TxError> {
    let default_rp = DefaultRotationProvider;
    let default_reg = SuiteRegistry::default_registry();
    let rp: &dyn RotationProvider = rotation.unwrap_or(&default_rp);
    let reg = registry.unwrap_or(&default_reg);
    let native_spend = rp.native_spend_suites(block_height);
    let params = spend_suite_params(
        w,
        &native_spend,
        reg,
        "CORE_P2PK suite not in native spend set",
        "CORE_P2PK suite not registered",
    )?;
    validate_witness_item_lengths(w, params)?;
    let key_id = p2pk_covenant_key_id(entry, w.suite_id)?;
    let mut sig_queue = sig_queue;
    verify_mldsa_key_and_sig_q(
        w,
        key_id,
        input_index,
        input_value,
        chain_id,
        cache,
        reg,
        &mut sig_queue,
        TxError::new(ErrorCode::TxErrSigInvalid, "CORE_P2PK key binding mismatch"),
        TxError::new(ErrorCode::TxErrSigInvalid, "CORE_P2PK signature invalid"),
    )
}

fn spend_suite_params<'a>(
    w: &WitnessItem,
    native_spend: &NativeSuiteSet,
    registry: &'a SuiteRegistry,
    suite_not_native_message: &'static str,
    suite_not_registered_message: &'static str,
) -> Result<&'a SuiteParams, TxError> {
    if !native_spend.contains(w.suite_id) {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            suite_not_native_message,
        ));
    }
    registry
        .lookup(w.suite_id)
        .ok_or_else(|| TxError::new(ErrorCode::TxErrSigAlgInvalid, suite_not_registered_message))
}

fn validate_witness_item_lengths(w: &WitnessItem, params: &SuiteParams) -> Result<(), TxError> {
    if w.pubkey.len() as u64 == params.pubkey_len && w.signature.len() as u64 == params.sig_len + 1
    {
        return Ok(());
    }
    Err(TxError::new(
        ErrorCode::TxErrSigNoncanonical,
        "non-canonical witness item lengths",
    ))
}

fn p2pk_covenant_key_id(entry: &UtxoEntry, suite_id: u8) -> Result<[u8; 32], TxError> {
    if entry.covenant_data.len() as u64 != MAX_P2PK_COVENANT_DATA
        || entry.covenant_data[0] != suite_id
    {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_P2PK covenant_data invalid",
        ));
    }
    let mut key_id = [0u8; 32];
    key_id.copy_from_slice(&entry.covenant_data[1..33]);
    Ok(key_id)
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
    validate_threshold_sig_spend_q(
        keys,
        threshold,
        ws,
        input_index,
        input_value,
        chain_id,
        block_height,
        context,
        cache,
        None,
        rotation,
        registry,
    )
}

#[derive(Clone, Copy)]
enum ThresholdSigErrorDetail {
    SuiteNotInNativeSpendSet,
    SuiteNotRegistered,
    KeyBindingMismatch,
    SignatureInvalid,
    ThresholdNotMet,
}

fn threshold_sig_error_message(
    context: &'static str,
    detail: ThresholdSigErrorDetail,
) -> &'static str {
    match (context, detail) {
        ("CORE_MULTISIG", ThresholdSigErrorDetail::SuiteNotInNativeSpendSet) => {
            "CORE_MULTISIG suite not in native spend set"
        }
        ("CORE_MULTISIG", ThresholdSigErrorDetail::SuiteNotRegistered) => {
            "CORE_MULTISIG suite not registered"
        }
        ("CORE_MULTISIG", ThresholdSigErrorDetail::KeyBindingMismatch) => {
            "CORE_MULTISIG key binding mismatch"
        }
        ("CORE_MULTISIG", ThresholdSigErrorDetail::SignatureInvalid) => {
            "CORE_MULTISIG signature invalid"
        }
        ("CORE_MULTISIG", ThresholdSigErrorDetail::ThresholdNotMet) => {
            "CORE_MULTISIG threshold not met"
        }
        ("CORE_VAULT", ThresholdSigErrorDetail::SuiteNotInNativeSpendSet) => {
            "CORE_VAULT suite not in native spend set"
        }
        ("CORE_VAULT", ThresholdSigErrorDetail::SuiteNotRegistered) => {
            "CORE_VAULT suite not registered"
        }
        ("CORE_VAULT", ThresholdSigErrorDetail::KeyBindingMismatch) => {
            "CORE_VAULT key binding mismatch"
        }
        ("CORE_VAULT", ThresholdSigErrorDetail::SignatureInvalid) => "CORE_VAULT signature invalid",
        ("CORE_VAULT", ThresholdSigErrorDetail::ThresholdNotMet) => "CORE_VAULT threshold not met",
        _ => context,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_threshold_sig_spend_q(
    keys: &[[u8; 32]],
    threshold: u8,
    ws: &[WitnessItem],
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    context: &'static str,
    cache: &mut SighashV1PrehashCache<'_>,
    sig_queue: Option<&mut SigCheckQueue>,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
) -> Result<(), TxError> {
    let default_rp = DefaultRotationProvider;
    let default_reg = SuiteRegistry::default_registry();
    let rp: &dyn RotationProvider = rotation.unwrap_or(&default_rp);
    let reg = registry.unwrap_or(&default_reg);
    let mut sig_queue = sig_queue;

    if ws.len() != keys.len() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "witness slot assignment mismatch",
        ));
    }

    let native_spend = rp.native_spend_suites(block_height);
    let mut valid: u8 = 0;
    let queue_mark = sig_queue.as_ref().map(|queue| queue.mark());

    let result = (|| -> Result<(), TxError> {
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

            let params = spend_suite_params(
                w,
                &native_spend,
                reg,
                threshold_sig_error_message(
                    context,
                    ThresholdSigErrorDetail::SuiteNotInNativeSpendSet,
                ),
                threshold_sig_error_message(context, ThresholdSigErrorDetail::SuiteNotRegistered),
            )?;
            validate_witness_item_lengths(w, params)?;

            verify_mldsa_key_and_sig_q(
                w,
                keys[i],
                input_index,
                input_value,
                chain_id,
                cache,
                reg,
                &mut sig_queue,
                TxError::new(
                    ErrorCode::TxErrSigInvalid,
                    threshold_sig_error_message(
                        context,
                        ThresholdSigErrorDetail::KeyBindingMismatch,
                    ),
                ),
                TxError::new(
                    ErrorCode::TxErrSigInvalid,
                    threshold_sig_error_message(context, ThresholdSigErrorDetail::SignatureInvalid),
                ),
            )?;
            valid = valid.saturating_add(1);
        }
        if valid < threshold {
            return Err(TxError::new(
                ErrorCode::TxErrSigInvalid,
                threshold_sig_error_message(context, ThresholdSigErrorDetail::ThresholdNotMet),
            ));
        }
        Ok(())
    })();

    match result {
        Ok(()) => Ok(()),
        Err(err) => {
            if let (Some(mark), Some(queue)) = (queue_mark, sig_queue) {
                queue.rollback_to(mark);
            }
            Err(err)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_mldsa_key_and_sig_q(
    w: &WitnessItem,
    expected_key_id: [u8; 32],
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    cache: &mut SighashV1PrehashCache<'_>,
    registry: &SuiteRegistry,
    sig_queue: &mut Option<&mut SigCheckQueue>,
    key_binding_error: TxError,
    invalid_sig_error: TxError,
) -> Result<(), TxError> {
    if sha3_256(&w.pubkey) != expected_key_id {
        return Err(key_binding_error);
    }
    let (crypto_sig, sighash_type) = extract_crypto_sig_and_sighash(w)?;
    let digest =
        sighash_v1_digest_with_cache(cache, input_index, input_value, chain_id, sighash_type)?;
    queue_or_verify_signature(
        w.suite_id,
        &w.pubkey,
        crypto_sig,
        digest,
        registry,
        sig_queue,
        invalid_sig_error,
    )
}

#[cfg(test)]
#[path = "spend_verify_tests/mod.rs"]
mod spend_verify_tests;
