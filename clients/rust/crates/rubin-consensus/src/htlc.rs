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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        COV_TYPE_HTLC, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87,
        VERIFY_COST_ML_DSA_87,
    };
    use crate::suite_registry::{
        CryptoRotationDescriptor, DescriptorRotationProvider, NativeSuiteSet, SuiteParams,
    };
    use crate::tx::{Tx, TxInput, TxOutput};

    fn make_htlc_covenant_data(
        hash: [u8; 32],
        lock_mode: u8,
        lock_value: u64,
        claim_key_id: [u8; 32],
        refund_key_id: [u8; 32],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
        out.extend_from_slice(&hash);
        out.push(lock_mode);
        out.extend_from_slice(&lock_value.to_le_bytes());
        out.extend_from_slice(&claim_key_id);
        out.extend_from_slice(&refund_key_id);
        out
    }

    fn make_htlc_entry(claim_key_id: [u8; 32], refund_key_id: [u8; 32]) -> UtxoEntry {
        UtxoEntry {
            value: 1000,
            covenant_type: COV_TYPE_HTLC,
            covenant_data: make_htlc_covenant_data(
                sha3_256(b"rotation-test"),
                LOCK_MODE_HEIGHT,
                1,
                claim_key_id,
                refund_key_id,
            ),
            creation_height: 0,
            created_by_coinbase: false,
        }
    }

    fn dummy_tx() -> Tx {
        Tx {
            version: 1,
            tx_kind: 0,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid: [0xee; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 900,
                covenant_type: crate::constants::COV_TYPE_P2PK,
                covenant_data: vec![0u8; 33],
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![],
            da_payload: vec![],
        }
    }

    fn sunset_rotation() -> (DescriptorRotationProvider, SuiteRegistry) {
        use std::collections::BTreeMap;
        let mut suites = BTreeMap::new();
        suites.insert(
            SUITE_ID_ML_DSA_87,
            SuiteParams {
                suite_id: SUITE_ID_ML_DSA_87,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: VERIFY_COST_ML_DSA_87,
                openssl_alg: "ML-DSA-87",
            },
        );
        suites.insert(
            0x02,
            SuiteParams {
                suite_id: 0x02,
                pubkey_len: 32,
                sig_len: 64,
                verify_cost: 100,
                openssl_alg: "TEST-SUITE",
            },
        );
        let registry = SuiteRegistry::with_suites(suites);
        let desc = CryptoRotationDescriptor {
            name: "test-htlc-sunset".to_string(),
            old_suite_id: SUITE_ID_ML_DSA_87,
            new_suite_id: 0x02,
            create_height: 1,
            spend_height: 5,
            sunset_height: 10,
        };
        desc.validate(&registry).expect("descriptor valid");
        (DescriptorRotationProvider { descriptor: desc }, registry)
    }

    #[test]
    fn test_htlc_spend_rotated_suite_rejected() {
        let claim_key_id = sha3_256(b"claim-key-rotation");
        let refund_key_id = sha3_256(b"refund-key-rotation");
        let entry = make_htlc_entry(claim_key_id, refund_key_id);

        let path_item = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: refund_key_id.to_vec(),
            signature: vec![0x01], // refund path selector
        };
        let sig_item = WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0u8; (ML_DSA_87_SIG_BYTES + 1) as usize],
        };

        let tx = dummy_tx();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let (rotation, registry) = sunset_rotation();

        // At height 15 (after sunset=10), ML-DSA-87 NOT in spend set
        let err = validate_htlc_spend_at_height(
            &entry,
            &path_item,
            &sig_item,
            &tx,
            0,
            1000,
            [0u8; 32],
            15,
            0,
            &mut cache,
            Some(&rotation),
            Some(&registry),
        );
        let err = err.expect_err("should reject sunset suite");
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
        assert!(
            err.to_string()
                .contains("CORE_HTLC suite not in native spend set"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_htlc_spend_active_suite_accepted() {
        let claim_key_id = sha3_256(b"claim-key-active");
        let refund_key_id = sha3_256(b"refund-key-active");
        let entry = make_htlc_entry(claim_key_id, refund_key_id);

        let path_item = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: refund_key_id.to_vec(),
            signature: vec![0x01], // refund path
        };
        let sig_item = WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0u8; (ML_DSA_87_SIG_BYTES + 1) as usize],
        };

        let tx = dummy_tx();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let (rotation, registry) = sunset_rotation();

        // At height 3 (before sunset=10), ML-DSA-87 IS in spend set
        let err = validate_htlc_spend_at_height(
            &entry,
            &path_item,
            &sig_item,
            &tx,
            0,
            1000,
            [0u8; 32],
            3,
            0,
            &mut cache,
            Some(&rotation),
            Some(&registry),
        );
        // Should pass suite check, fail on sig verify (fake sig)
        match err {
            Ok(()) => {} // unlikely with fake sig but acceptable
            Err(e) => {
                // Must NOT be TxErrSigAlgInvalid — that would mean suite check failed
                assert_ne!(
                    e.code,
                    ErrorCode::TxErrSigAlgInvalid,
                    "should NOT fail on suite check at height 3: {e}"
                );
            }
        }
    }
}
