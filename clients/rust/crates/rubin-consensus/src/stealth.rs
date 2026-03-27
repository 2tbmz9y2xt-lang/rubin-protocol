use crate::constants::{MAX_STEALTH_COVENANT_DATA, ML_KEM_1024_CT_BYTES};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::sig_queue::{queue_or_verify_signature, SigCheckQueue};
use crate::sighash::{sighash_v1_digest_with_cache, SighashV1PrehashCache};
use crate::spend_verify::extract_crypto_sig_and_sighash;
use crate::suite_registry::{DefaultRotationProvider, RotationProvider, SuiteRegistry};
use crate::tx::{Tx, WitnessItem};
use crate::utxo_basic::UtxoEntry;

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
    let mut cache = SighashV1PrehashCache::new(tx)?;
    validate_stealth_spend_with_cache(
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
pub(crate) fn validate_stealth_spend_with_cache(
    entry: &UtxoEntry,
    w: &WitnessItem,
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    cache: &mut SighashV1PrehashCache<'_>,
) -> Result<(), TxError> {
    validate_stealth_spend_at_height(
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

/// Rotation-aware CORE_STEALTH spend validation. When rotation or registry
/// is None, uses defaults (ML-DSA-87 genesis set). Parity with Go
/// `validateCoreStealthSpendAtHeight`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_stealth_spend_at_height(
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
    validate_stealth_spend_q(
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
pub(crate) fn validate_stealth_spend_q(
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
    let mut sig_queue = sig_queue;

    let cov = parse_stealth_covenant_data(&entry.covenant_data)?;
    let _ = cov.ciphertext;

    let native_spend = rp.native_spend_suites(block_height);
    if !native_spend.contains(w.suite_id) {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_STEALTH suite not in native spend set",
        ));
    }

    let params = reg.lookup(w.suite_id).ok_or_else(|| {
        TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_STEALTH suite not registered",
        )
    })?;

    if w.pubkey.len() as u64 != params.pubkey_len || w.signature.len() as u64 != params.sig_len + 1
    {
        return Err(TxError::new(
            ErrorCode::TxErrSigNoncanonical,
            "non-canonical witness item lengths",
        ));
    }

    if sha3_256(&w.pubkey) != cov.one_time_key_id {
        return Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "CORE_STEALTH key binding mismatch",
        ));
    }

    let (crypto_sig, sighash_type) = extract_crypto_sig_and_sighash(w)?;
    let digest =
        sighash_v1_digest_with_cache(cache, input_index, input_value, chain_id, sighash_type)?;
    queue_or_verify_signature(
        w.suite_id,
        &w.pubkey,
        crypto_sig,
        digest,
        reg,
        &mut sig_queue,
        TxError::new(ErrorCode::TxErrSigInvalid, "CORE_STEALTH signature invalid"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        COV_TYPE_STEALTH, MAX_STEALTH_COVENANT_DATA, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES,
        SUITE_ID_ML_DSA_87,
    };
    use crate::tx::{TxInput, TxOutput};

    fn stealth_cov_data(one_time_key_id: [u8; 32]) -> Vec<u8> {
        let mut out = vec![0u8; MAX_STEALTH_COVENANT_DATA as usize];
        out[ML_KEM_1024_CT_BYTES as usize..MAX_STEALTH_COVENANT_DATA as usize]
            .copy_from_slice(&one_time_key_id);
        out
    }

    fn dummy_entry(one_time_key_id: [u8; 32]) -> UtxoEntry {
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_STEALTH,
            covenant_data: stealth_cov_data(one_time_key_id),
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
                    value: 90,
                    covenant_type: crate::constants::COV_TYPE_P2PK,
                    covenant_data: vec![0u8; 33],
                }],
                locktime: 0,
                witness: vec![],
                da_payload: vec![],
                da_commit_core: None,
                da_chunk_core: None,
            },
            0,
            100,
            chain_id,
        )
    }

    #[test]
    fn parse_stealth_covenant_data_len_mismatch() {
        let err = parse_stealth_covenant_data(&vec![0u8; (MAX_STEALTH_COVENANT_DATA - 1) as usize])
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    #[test]
    fn parse_stealth_covenant_data_valid() {
        let mut key = [0u8; 32];
        key[0] = 0xaa;
        key[31] = 0x55;
        let cov = parse_stealth_covenant_data(&stealth_cov_data(key)).expect("parse");
        assert_eq!(cov.ciphertext.len() as u64, ML_KEM_1024_CT_BYTES);
        assert_eq!(cov.one_time_key_id, key);
    }

    #[test]
    fn validate_stealth_spend_suite_invalid() {
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let entry = dummy_entry([0u8; 32]);
        let w = WitnessItem {
            suite_id: 0x03,
            pubkey: vec![],
            signature: vec![],
        };
        let err = validate_stealth_spend(&entry, &w, &tx, input_index, input_value, chain_id, 200)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn validate_stealth_spend_key_binding_mismatch() {
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let entry = dummy_entry([0u8; 32]);
        let w = WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![0x11; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0x00; (ML_DSA_87_SIG_BYTES + 1) as usize],
        };
        let err = validate_stealth_spend(&entry, &w, &tx, input_index, input_value, chain_id, 200)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn validate_stealth_spend_non_native_suite_rejected_sig_alg_invalid() {
        let (tx, input_index, input_value, chain_id) = dummy_tx_ctx();
        let entry = dummy_entry([0u8; 32]);
        let w = WitnessItem {
            suite_id: 0x02, // non-native / unknown suite
            pubkey: vec![],
            signature: vec![],
        };
        let err = validate_stealth_spend(&entry, &w, &tx, input_index, input_value, chain_id, 0)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn verify_parse_stealth_covenant_data_accepts_exact_length() {
        let cov_data = [0x5au8; MAX_STEALTH_COVENANT_DATA as usize];
        let parsed = parse_stealth_covenant_data(&cov_data).expect("exact-length stealth covenant");
        assert_eq!(
            parsed.ciphertext,
            cov_data[..ML_KEM_1024_CT_BYTES as usize].to_vec()
        );
        assert_eq!(
            parsed.one_time_key_id,
            <[u8; 32]>::try_from(&cov_data[ML_KEM_1024_CT_BYTES as usize..]).expect("key slice")
        );
    }

    #[kani::proof]
    fn verify_parse_stealth_covenant_data_rejects_short_length() {
        let cov_data: [u8; (MAX_STEALTH_COVENANT_DATA as usize) - 1] = kani::any();
        let err = parse_stealth_covenant_data(&cov_data).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }
}
