use crate::constants::{
    LOCK_MODE_HEIGHT, LOCK_MODE_TIMESTAMP, MAX_HTLC_COVENANT_DATA, MAX_HTLC_PREIMAGE_BYTES,
    MIN_HTLC_PREIMAGE_BYTES, SUITE_ID_SENTINEL,
};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::sighash::{is_valid_sighash_type, sighash_v1_digest_with_cache, SighashV1PrehashCache};
use crate::suite_registry::{DefaultRotationProvider, RotationProvider, SuiteRegistry};
use crate::tx::{Tx, WitnessItem};
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

#[allow(clippy::too_many_arguments)]
pub fn validate_htlc_spend(
    entry: &UtxoEntry,
    path_item: &WitnessItem,
    sig_item: &WitnessItem,
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    block_mtp: u64,
) -> Result<(), TxError> {
    let mut cache = SighashV1PrehashCache::new(tx)?;
    validate_htlc_spend_with_cache(
        entry,
        path_item,
        sig_item,
        tx,
        input_index,
        input_value,
        chain_id,
        block_height,
        block_mtp,
        &mut cache,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_htlc_spend_with_cache(
    entry: &UtxoEntry,
    path_item: &WitnessItem,
    sig_item: &WitnessItem,
    _tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    block_mtp: u64,
    cache: &mut SighashV1PrehashCache<'_>,
) -> Result<(), TxError> {
    validate_htlc_spend_at_height(
        entry,
        path_item,
        sig_item,
        _tx,
        input_index,
        input_value,
        chain_id,
        block_height,
        block_mtp,
        cache,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_htlc_spend_at_height(
    entry: &UtxoEntry,
    path_item: &WitnessItem,
    sig_item: &WitnessItem,
    _tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    block_mtp: u64,
    cache: &mut SighashV1PrehashCache<'_>,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
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
            if (pre_len as u64) < MIN_HTLC_PREIMAGE_BYTES {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "CORE_HTLC preimage_len must be >= 16",
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
            } else if block_mtp < cov.lock_value {
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

    let default_rp = DefaultRotationProvider;
    let default_reg = SuiteRegistry::default_registry();
    let rp: &dyn RotationProvider = rotation.unwrap_or(&default_rp);
    let reg = registry.unwrap_or(&default_reg);

    let native_spend = rp.native_spend_suites(block_height);
    if !native_spend.contains(sig_item.suite_id) {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_HTLC suite not in native spend set",
        ));
    }

    let params = reg.lookup(sig_item.suite_id).ok_or_else(|| {
        TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_HTLC suite not registered",
        )
    })?;

    if sig_item.pubkey.len() as u64 != params.pubkey_len
        || sig_item.signature.len() as u64 != params.sig_len + 1
    {
        return Err(TxError::new(
            ErrorCode::TxErrSigNoncanonical,
            "non-canonical witness item lengths",
        ));
    }

    if sha3_256(&sig_item.pubkey) != expected_key_id {
        return Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "CORE_HTLC signature key binding mismatch",
        ));
    }

    let Some((&sighash_type, crypto_sig)) = sig_item.signature.split_last() else {
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
    let digest32 =
        sighash_v1_digest_with_cache(cache, input_index, input_value, chain_id, sighash_type)?;

    let ok = crate::verify_sig_openssl::verify_sig_with_registry(
        sig_item.suite_id,
        &sig_item.pubkey,
        crypto_sig,
        &digest32,
        Some(reg),
    )?;
    if !ok {
        return Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "CORE_HTLC signature invalid",
        ));
    }

    Ok(())
}
