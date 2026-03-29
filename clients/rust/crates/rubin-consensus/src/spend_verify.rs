use crate::constants::{MAX_P2PK_COVENANT_DATA, SUITE_ID_SENTINEL};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::sig_queue::{queue_or_verify_signature, SigCheckQueue};
use crate::sighash::{is_valid_sighash_type, sighash_v1_digest_with_cache, SighashV1PrehashCache};
use crate::suite_registry::{DefaultRotationProvider, RotationProvider, SuiteRegistry};
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

    if w.pubkey.len() as u64 != params.pubkey_len || w.signature.len() as u64 != params.sig_len + 1
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

            if !native_spend.contains(w.suite_id) {
                return Err(TxError::new(ErrorCode::TxErrSigAlgInvalid, context));
            }

            let params = reg
                .lookup(w.suite_id)
                .ok_or_else(|| TxError::new(ErrorCode::TxErrSigAlgInvalid, context))?;

            if w.pubkey.len() as u64 != params.pubkey_len
                || w.signature.len() as u64 != params.sig_len + 1
            {
                return Err(TxError::new(
                    ErrorCode::TxErrSigNoncanonical,
                    "non-canonical witness item lengths",
                ));
            }

            verify_mldsa_key_and_sig_q(
                w,
                keys[i],
                input_index,
                input_value,
                chain_id,
                cache,
                reg,
                &mut sig_queue,
                TxError::new(ErrorCode::TxErrSigInvalid, context),
                TxError::new(ErrorCode::TxErrSigInvalid, context),
            )?;
            valid = valid.saturating_add(1);
        }
        if valid < threshold {
            return Err(TxError::new(ErrorCode::TxErrSigInvalid, context));
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
mod tests {
    use super::*;
    use crate::constants::{
        COV_TYPE_P2PK, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SIGHASH_ALL,
        SUITE_ID_ML_DSA_87, SUITE_ID_SENTINEL,
    };
    use crate::hash::sha3_256;
    use crate::sighash_v1_digest_with_cache;
    use crate::suite_registry::{SuiteParams, SuiteRegistry};
    use crate::tx::{Tx, TxInput, TxOutput, WitnessItem};
    use crate::verify_sig_openssl::Mldsa87Keypair;
    use crate::SighashV1PrehashCache;
    use std::collections::BTreeMap;

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

    fn sign_witness(
        keypair: &Mldsa87Keypair,
        tx: &Tx,
        input_index: u32,
        input_value: u64,
        chain_id: [u8; 32],
    ) -> WitnessItem {
        let mut cache = SighashV1PrehashCache::new(tx).expect("cache");
        let digest = sighash_v1_digest_with_cache(
            &mut cache,
            input_index,
            input_value,
            chain_id,
            SIGHASH_ALL,
        )
        .expect("digest");
        let mut signature = keypair.sign_digest32(digest).expect("sign");
        signature.push(SIGHASH_ALL);
        WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: keypair.pubkey_bytes(),
            signature,
        }
    }

    fn make_p2pk_entry(pubkey: &[u8]) -> UtxoEntry {
        let pubkey_hash = sha3_256(pubkey);
        let mut covenant_data = vec![SUITE_ID_ML_DSA_87];
        covenant_data.extend_from_slice(&pubkey_hash);
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data,
            creation_height: 0,
            created_by_coinbase: false,
        }
    }

    // ======== Registry & Lookup Tests (8) ========

    #[test]
    fn verify_sig_with_registry_nil_falls_back_to_legacy() {
        // When registry is None, verify_sig_with_registry should fall back to verify_sig
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let pubkey = keypair.pubkey_bytes();
        let digest = [0x42; 32];
        let sig = keypair.sign_digest32(digest).expect("sign");

        let result = crate::verify_sig_openssl::verify_sig_with_registry(
            SUITE_ID_ML_DSA_87,
            &pubkey,
            &sig,
            &digest,
            None,
        )
        .expect("verify");

        assert!(result, "valid signature should verify");
    }

    #[test]
    fn verify_sig_with_registry_unknown_suite_returns_error() {
        // Suite 0xFF not in registry
        let registry = SuiteRegistry::default_registry();
        let pubkey = vec![0x01; ML_DSA_87_PUBKEY_BYTES as usize];
        let sig = vec![0x02; ML_DSA_87_SIG_BYTES as usize];
        let digest = [0x42; 32];

        let err = crate::verify_sig_openssl::verify_sig_with_registry(
            0xFF,
            &pubkey,
            &sig,
            &digest,
            Some(&registry),
        )
        .expect_err("unknown suite should error");

        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn verify_sig_with_registry_known_suite_wrong_lengths() {
        // Suite registered but pubkey/sig lengths mismatch
        let registry = SuiteRegistry::default_registry();
        let pubkey = vec![0x01; 10]; // wrong length
        let sig = vec![0x02; 10]; // wrong length
        let digest = [0x42; 32];

        let result = crate::verify_sig_openssl::verify_sig_with_registry(
            SUITE_ID_ML_DSA_87,
            &pubkey,
            &sig,
            &digest,
            Some(&registry),
        )
        .expect("should not error on length check");

        assert!(!result, "wrong lengths should return false, not error");
    }

    #[test]
    fn verify_sig_with_registry_known_suite_correct_lengths() {
        // Valid suite with correct lengths passes through to OpenSSL
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let pubkey = keypair.pubkey_bytes();
        let digest = [0x42; 32];
        let sig = keypair.sign_digest32(digest).expect("sign");
        let registry = SuiteRegistry::default_registry();

        let result = crate::verify_sig_openssl::verify_sig_with_registry(
            SUITE_ID_ML_DSA_87,
            &pubkey,
            &sig,
            &digest,
            Some(&registry),
        )
        .expect("verify with registry");

        assert!(result, "valid signature with registry should verify");
    }

    #[test]
    fn verify_sig_with_registry_custom_suite() {
        // Custom registry entry with different suite ID
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let pubkey = keypair.pubkey_bytes();
        let digest = [0x42; 32];
        let sig = keypair.sign_digest32(digest).expect("sign");

        let mut suites = BTreeMap::new();
        suites.insert(
            0x05,
            SuiteParams {
                suite_id: 0x05,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: 8,
                openssl_alg: "ML-DSA-87",
            },
        );
        let registry = SuiteRegistry::with_suites(suites);

        let result = crate::verify_sig_openssl::verify_sig_with_registry(
            0x05,
            &pubkey,
            &sig,
            &digest,
            Some(&registry),
        )
        .expect("verify custom suite");

        assert!(result, "custom suite entry should verify");
    }

    #[test]
    fn verify_sig_with_registry_consensus_init_error() {
        // Empty inputs should trigger OpenSSL parse error
        let registry = SuiteRegistry::default_registry();
        let digest = [0x42; 32];

        let result = crate::verify_sig_openssl::verify_sig_with_registry(
            SUITE_ID_ML_DSA_87,
            &[],
            &[],
            &digest,
            Some(&registry),
        );

        // Empty inputs return false, not an error (length check happens first)
        let ok = result.expect("should not error");
        assert!(!ok, "empty inputs should fail verification");
    }

    #[test]
    fn verify_sig_with_registry_openssl_error() {
        // Corrupted signature should fail verification
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let pubkey = keypair.pubkey_bytes();
        let digest = [0x42; 32];
        let mut sig = keypair.sign_digest32(digest).expect("sign");
        sig[0] ^= 0xFF; // corrupt first byte
        let registry = SuiteRegistry::default_registry();

        let result = crate::verify_sig_openssl::verify_sig_with_registry(
            SUITE_ID_ML_DSA_87,
            &pubkey,
            &sig,
            &digest,
            Some(&registry),
        )
        .expect("verify");

        assert!(!result, "corrupted signature should not verify");
    }

    #[test]
    fn verify_sig_with_registry_verify_returns_false() {
        // Valid signature over different digest should fail
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let pubkey = keypair.pubkey_bytes();
        let digest1 = [0x42; 32];
        let sig = keypair.sign_digest32(digest1).expect("sign");
        let mut digest2 = digest1;
        digest2[0] ^= 0xFF;
        let registry = SuiteRegistry::default_registry();

        let result = crate::verify_sig_openssl::verify_sig_with_registry(
            SUITE_ID_ML_DSA_87,
            &pubkey,
            &sig,
            &digest2,
            Some(&registry),
        )
        .expect("verify");

        assert!(!result, "signature over different digest should not verify");
    }

    // ======== P2PK Spend at Height Tests (7) ========

    #[test]
    fn p2pk_at_height_nil_providers_falls_back() {
        // No rotation, no registry -> use defaults (ML-DSA-87)
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let entry = make_p2pk_entry(&keypair.pubkey_bytes());
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let result = validate_p2pk_spend_at_height(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            &mut cache,
            None,
            None,
        );

        assert!(result.is_ok(), "default fallback should verify valid P2PK");
    }

    #[test]
    fn p2pk_at_height_suite_not_in_spend_set() {
        // Suite 0xFF not in native spend set at height
        let entry = dummy_entry();
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = WitnessItem {
            suite_id: 0xFF,
            pubkey: vec![0x01; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0x02; ML_DSA_87_SIG_BYTES as usize + 1],
        };

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_p2pk_spend_at_height(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            &mut cache,
            None,
            None,
        )
        .expect_err("unknown suite");

        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn p2pk_at_height_wrong_lengths() {
        // Correct suite, wrong pubkey/sig lengths
        let entry = dummy_entry();
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![0x01; 10], // wrong length
            signature: vec![0x02; 10],
        };

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_p2pk_spend_at_height(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            &mut cache,
            None,
            None,
        )
        .expect_err("wrong lengths");

        assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
    }

    #[test]
    fn p2pk_at_height_valid_sig_success() {
        // Full valid P2PK spend path
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let entry = make_p2pk_entry(&keypair.pubkey_bytes());
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let result = validate_p2pk_spend_at_height(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            &mut cache,
            None,
            None,
        );

        assert!(result.is_ok(), "valid P2PK should verify");
    }

    #[test]
    fn p2pk_at_height_bad_covenant_data() {
        // Malformed covenant_data
        let entry = UtxoEntry {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: vec![0x99; 10], // too short
            creation_height: 0,
            created_by_coinbase: false,
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![0x01; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0x02; ML_DSA_87_SIG_BYTES as usize + 1],
        };

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_p2pk_spend_at_height(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            &mut cache,
            None,
            None,
        )
        .expect_err("bad covenant");

        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    #[test]
    fn p2pk_at_height_suite_not_registered() {
        // Suite in spend set but not in registry
        let mut covenant_data = vec![0xAA];
        covenant_data.extend_from_slice(&[0x11; 32]);
        let entry = UtxoEntry {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
            covenant_data,
            creation_height: 0,
            created_by_coinbase: false,
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();

        // Create custom registry with only SUITE_ID_ML_DSA_87
        let mut suites = BTreeMap::new();
        suites.insert(
            SUITE_ID_ML_DSA_87,
            SuiteParams {
                suite_id: SUITE_ID_ML_DSA_87,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: 8,
                openssl_alg: "ML-DSA-87",
            },
        );
        let registry = SuiteRegistry::with_suites(suites);

        let w = WitnessItem {
            suite_id: 0xAA, // suite in covenant but not registered
            pubkey: vec![0x01; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0x02; ML_DSA_87_SIG_BYTES as usize + 1],
        };

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_p2pk_spend_at_height(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            &mut cache,
            None,
            Some(&registry),
        )
        .expect_err("unregistered suite");

        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn p2pk_at_height_key_binding_mismatch() {
        // sha3(pubkey) != covenant key_id
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let mut covenant_data = vec![SUITE_ID_ML_DSA_87];
        covenant_data.extend_from_slice(&[0xFF; 32]); // wrong key_id
        let entry = UtxoEntry {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
            covenant_data,
            creation_height: 0,
            created_by_coinbase: false,
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_p2pk_spend_at_height(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            &mut cache,
            None,
            None,
        )
        .expect_err("key binding mismatch");

        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    // ======== Threshold Sig at Height Tests (10) ========

    #[test]
    fn threshold_at_height_nil_providers_falls_back() {
        // No rotation, no registry -> defaults
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let key_id = sha3_256(&keypair.pubkey_bytes());
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let result = validate_threshold_sig_spend_at_height(
            &[key_id],
            1,
            &[w],
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            "test",
            &mut cache,
            None,
            None,
        );

        assert!(result.is_ok(), "1-of-1 valid threshold should verify");
    }

    #[test]
    fn threshold_at_height_sentinel_passthrough() {
        // SENTINEL suite should be skipped (keyless)
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let key_id = sha3_256(&keypair.pubkey_bytes());
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w1 = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![],
            signature: vec![],
        };
        let w2 = sign_witness(&keypair, &tx, input_index, input_value, chain_id);

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let result = validate_threshold_sig_spend_at_height(
            &[key_id, key_id],
            1,
            &[w1, w2],
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            "test",
            &mut cache,
            None,
            None,
        );

        assert!(result.is_ok(), "sentinel should be skipped");
    }

    #[test]
    fn threshold_at_height_non_native_suite_rejects() {
        // Suite 0xFF not in native spend set
        let key_id = [0x11; 32];
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = WitnessItem {
            suite_id: 0xFF,
            pubkey: vec![0x01; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0x02; ML_DSA_87_SIG_BYTES as usize + 1],
        };

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_threshold_sig_spend_at_height(
            &[key_id],
            1,
            &[w],
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            "test",
            &mut cache,
            None,
            None,
        )
        .expect_err("bad suite");

        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn threshold_at_height_slot_count_mismatch() {
        // Different number of witnesses vs keys
        let key_id = [0x11; 32];
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_threshold_sig_spend_at_height(
            &[key_id, key_id], // 2 keys
            1,
            &[], // 0 witnesses
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            "test",
            &mut cache,
            None,
            None,
        )
        .expect_err("mismatch");

        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn threshold_at_height_valid_sigs_meets_threshold() {
        // 1-of-2 threshold with one valid signature
        let keypair1 = Mldsa87Keypair::generate().expect("keypair1");
        let keypair2 = Mldsa87Keypair::generate().expect("keypair2");
        let key_id1 = sha3_256(&keypair1.pubkey_bytes());
        let key_id2 = sha3_256(&keypair2.pubkey_bytes());
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w1 = sign_witness(&keypair1, &tx, input_index, input_value, chain_id);
        let w2 = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![],
            signature: vec![],
        };

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let result = validate_threshold_sig_spend_at_height(
            &[key_id1, key_id2],
            1,
            &[w1, w2],
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            "test",
            &mut cache,
            None,
            None,
        );

        assert!(result.is_ok(), "1-of-2 with one valid should pass");
    }

    #[test]
    fn threshold_at_height_threshold_not_met() {
        // Threshold 2 but only 1 valid signature
        let keypair1 = Mldsa87Keypair::generate().expect("keypair1");
        let keypair2 = Mldsa87Keypair::generate().expect("keypair2");
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let mut bad_sig = sign_witness(&keypair1, &tx, input_index, input_value, chain_id);
        bad_sig.signature[0] ^= 0xFF; // corrupt signature
        let w2 = sign_witness(&keypair2, &tx, input_index, input_value, chain_id);

        let key_id1 = sha3_256(&keypair1.pubkey_bytes());
        let key_id2 = sha3_256(&keypair2.pubkey_bytes());

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_threshold_sig_spend_at_height(
            &[key_id1, key_id2],
            2,
            &[bad_sig, w2],
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            "test",
            &mut cache,
            None,
            None,
        )
        .expect_err("threshold not met");

        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn threshold_at_height_sentinel_with_payload_rejects() {
        // SENTINEL suite with non-empty pubkey/signature
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![0x01], // sentinel must be keyless
            signature: vec![],
        };

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_threshold_sig_spend_at_height(
            &[[0x11; 32]],
            1,
            &[w],
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            "test",
            &mut cache,
            None,
            None,
        )
        .expect_err("sentinel payload");

        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn threshold_at_height_wrong_lengths() {
        // Non-canonical witness item lengths
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![0x01; 10], // wrong length
            signature: vec![0x02; 10],
        };

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_threshold_sig_spend_at_height(
            &[[0x11; 32]],
            1,
            &[w],
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            "test",
            &mut cache,
            None,
            None,
        )
        .expect_err("wrong lengths");

        assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
    }

    #[test]
    fn threshold_at_height_not_registered() {
        // Suite not in registry
        let mut suites = BTreeMap::new();
        suites.insert(
            SUITE_ID_ML_DSA_87,
            SuiteParams {
                suite_id: SUITE_ID_ML_DSA_87,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: 8,
                openssl_alg: "ML-DSA-87",
            },
        );
        let registry = SuiteRegistry::with_suites(suites);

        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = WitnessItem {
            suite_id: 0xBB, // not in registry
            pubkey: vec![0x01; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0x02; ML_DSA_87_SIG_BYTES as usize + 1],
        };

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_threshold_sig_spend_at_height(
            &[[0x11; 32]],
            1,
            &[w],
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            "test",
            &mut cache,
            None,
            Some(&registry),
        )
        .expect_err("unregistered suite");

        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn threshold_at_height_sig_verify_error() {
        // Corrupted signature should fail verification
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let key_id = sha3_256(&keypair.pubkey_bytes());
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let mut w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);
        w.signature[0] ^= 0xFF; // corrupt

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let err = validate_threshold_sig_spend_at_height(
            &[key_id],
            1,
            &[w],
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            "test",
            &mut cache,
            None,
            None,
        )
        .expect_err("bad signature");

        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    // ======== Key & Sig with Registry Cache Tests (5) ========

    #[test]
    fn verify_key_sig_registry_cache_key_mismatch() {
        // sha3(pubkey) != expected_key_id
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let wrong_key_id = [0xFF; 32];
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let registry = SuiteRegistry::default_registry();
        let err = verify_mldsa_key_and_sig_q(
            &w,
            wrong_key_id,
            input_index,
            input_value,
            chain_id,
            &mut cache,
            &registry,
            &mut None,
            TxError::new(ErrorCode::TxErrSigInvalid, "key mismatch"),
            TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
        )
        .expect_err("key mismatch");

        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn verify_key_sig_registry_cache_sig_invalid() {
        // Valid key but bad signature
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let key_id = sha3_256(&keypair.pubkey_bytes());
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let mut w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);
        w.signature[0] ^= 0xFF; // corrupt signature

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let registry = SuiteRegistry::default_registry();
        let err = verify_mldsa_key_and_sig_q(
            &w,
            key_id,
            input_index,
            input_value,
            chain_id,
            &mut cache,
            &registry,
            &mut None,
            TxError::new(ErrorCode::TxErrSigInvalid, "key mismatch"),
            TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
        )
        .expect_err("bad sig");

        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn verify_key_sig_registry_cache_openssl_error() {
        // Empty pubkey should trigger key binding mismatch (sha3 of empty != key_id)
        let key_id = [0x11; 32];
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![],
            signature: vec![SIGHASH_ALL],
        };

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let registry = SuiteRegistry::default_registry();
        let err = verify_mldsa_key_and_sig_q(
            &w,
            key_id,
            input_index,
            input_value,
            chain_id,
            &mut cache,
            &registry,
            &mut None,
            TxError::new(ErrorCode::TxErrSigInvalid, "key mismatch"),
            TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
        )
        .expect_err("key binding mismatch on empty pubkey");

        // Empty pubkey SHA3 won't match [0x11; 32], so we get key mismatch error
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn verify_key_sig_registry_cache_bad_sighash() {
        // Invalid sighash_type byte
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let key_id = sha3_256(&keypair.pubkey_bytes());
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let mut w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);
        let last_idx = w.signature.len() - 1;
        w.signature[last_idx] = 0xFF; // invalid sighash_type

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let registry = SuiteRegistry::default_registry();
        let err = verify_mldsa_key_and_sig_q(
            &w,
            key_id,
            input_index,
            input_value,
            chain_id,
            &mut cache,
            &registry,
            &mut None,
            TxError::new(ErrorCode::TxErrSigInvalid, "key mismatch"),
            TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
        )
        .expect_err("bad sighash");

        assert_eq!(err.code, ErrorCode::TxErrSighashTypeInvalid);
    }

    #[test]
    fn verify_key_sig_registry_cache_success() {
        // Full valid roundtrip: correct key, valid signature
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let key_id = sha3_256(&keypair.pubkey_bytes());
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let w = sign_witness(&keypair, &tx, input_index, input_value, chain_id);

        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let registry = SuiteRegistry::default_registry();
        let result = verify_mldsa_key_and_sig_q(
            &w,
            key_id,
            input_index,
            input_value,
            chain_id,
            &mut cache,
            &registry,
            &mut None,
            TxError::new(ErrorCode::TxErrSigInvalid, "key mismatch"),
            TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
        );

        assert!(result.is_ok(), "valid key and sig should verify");
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
