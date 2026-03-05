use crate::compactsize::read_compact_size_bytes;
use crate::constants::{
    ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87, SUITE_ID_SENTINEL,
};
use crate::error::{ErrorCode, TxError};
use crate::sighash::{is_valid_sighash_type, sighash_v1_digest_with_type};
use crate::tx::Tx;
use crate::tx::WitnessItem;
use crate::utxo_basic::UtxoEntry;
use crate::verify_sig_openssl::verify_sig;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreExtCovenant<'a> {
    pub ext_id: u16,
    pub ext_payload: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreExtVerificationBinding {
    /// Verify via native `verify_sig` dispatch.
    NativeVerifySig,
    /// Deterministic test binding: `verify_sig_ext` accepts.
    VerifySigExtAccept,
    /// Deterministic test binding: `verify_sig_ext` returns false.
    VerifySigExtReject,
    /// Deterministic test binding: `verify_sig_ext` errors.
    VerifySigExtError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreExtActiveProfile {
    pub ext_id: u16,
    pub allowed_suite_ids: Vec<u8>,
    pub verification_binding: CoreExtVerificationBinding,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoreExtProfiles {
    pub active: Vec<CoreExtActiveProfile>,
}

impl CoreExtProfiles {
    pub fn empty() -> Self {
        Self { active: Vec::new() }
    }

    fn lookup_active_profile(&self, ext_id: u16) -> Result<Option<&CoreExtActiveProfile>, TxError> {
        let mut found: Option<&CoreExtActiveProfile> = None;
        for p in &self.active {
            if p.ext_id != ext_id {
                continue;
            }
            if found.is_some() {
                return Err(TxError::new(
                    ErrorCode::TxErrCovenantTypeInvalid,
                    "CORE_EXT multiple ACTIVE profiles for ext_id",
                ));
            }
            found = Some(p);
        }
        Ok(found)
    }
}

pub fn parse_core_ext_covenant_data(cov_data: &[u8]) -> Result<CoreExtCovenant<'_>, TxError> {
    if cov_data.len() < 2 {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_EXT covenant_data too short",
        ));
    }
    let ext_id = u16::from_le_bytes(
        cov_data[0..2]
            .try_into()
            .expect("cov_data[0..2] is 2 bytes"),
    );

    let (ext_payload_len_u64, varint_bytes) =
        read_compact_size_bytes(&cov_data[2..]).map_err(|_| {
            TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "CORE_EXT ext_payload_len CompactSize invalid",
            )
        })?;
    if ext_payload_len_u64 > usize::MAX as u64 {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_EXT ext_payload_len overflows usize",
        ));
    }
    let ext_payload_len = ext_payload_len_u64 as usize;
    let expected_len = 2usize
        .checked_add(varint_bytes)
        .and_then(|v| v.checked_add(ext_payload_len))
        .ok_or_else(|| {
            TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "CORE_EXT length overflow",
            )
        })?;
    if cov_data.len() != expected_len {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_EXT covenant_data length mismatch",
        ));
    }
    let payload_start = 2 + varint_bytes;
    let ext_payload = &cov_data[payload_start..payload_start + ext_payload_len];

    Ok(CoreExtCovenant {
        ext_id,
        ext_payload,
    })
}

pub fn validate_core_ext_spend(
    entry: &UtxoEntry,
    w: &WitnessItem,
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    profiles_at_height: &CoreExtProfiles,
) -> Result<(), TxError> {
    let cov = parse_core_ext_covenant_data(&entry.covenant_data)?;
    let _ = cov.ext_payload;

    let active_profile = profiles_at_height.lookup_active_profile(cov.ext_id)?;
    if active_profile.is_none() {
        return Ok(());
    }
    let p = active_profile.expect("active_profile is Some");

    if !p.allowed_suite_ids.contains(&w.suite_id) {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_EXT suite disallowed under ACTIVE profile",
        ));
    }
    if w.suite_id == SUITE_ID_SENTINEL {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_EXT sentinel suite forbidden under ACTIVE profile",
        ));
    }

    if w.suite_id == SUITE_ID_ML_DSA_87 {
        if w.pubkey.len() as u64 != ML_DSA_87_PUBKEY_BYTES
            || w.signature.len() as u64 != ML_DSA_87_SIG_BYTES + 1
        {
            return Err(TxError::new(
                ErrorCode::TxErrSigNoncanonical,
                "non-canonical ML-DSA witness item lengths",
            ));
        }
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
        let digest32 = sighash_v1_digest_with_type(
            tx,
            input_index,
            input_value,
            chain_id,
            sighash_type,
        )?;
        let ok = verify_sig(w.suite_id, &w.pubkey, crypto_sig, &digest32)?;
        if !ok {
            return Err(TxError::new(
                ErrorCode::TxErrSigInvalid,
                "CORE_EXT signature invalid",
            ));
        }
        return Ok(());
    }

    let Some((&sighash_type, _crypto_sig)) = w.signature.split_last() else {
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
    let _digest32 = sighash_v1_digest_with_type(tx, input_index, input_value, chain_id, sighash_type)?;

    match p.verification_binding {
        CoreExtVerificationBinding::NativeVerifySig => Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_EXT non-native verifier binding unsupported",
        )),
        CoreExtVerificationBinding::VerifySigExtAccept => Ok(()),
        CoreExtVerificationBinding::VerifySigExtReject => Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "CORE_EXT signature invalid",
        )),
        CoreExtVerificationBinding::VerifySigExtError => Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_EXT verify_sig_ext error",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compactsize::encode_compact_size;
    use crate::constants::{COV_TYPE_EXT, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES};
    use crate::tx::{Tx, TxInput, TxOutput};

    fn core_ext_covdata(ext_id: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ext_id.to_le_bytes());
        encode_compact_size(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }

    fn dummy_entry(ext_id: u16) -> UtxoEntry {
        UtxoEntry {
            value: 1,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(ext_id, b""),
            creation_height: 0,
            created_by_coinbase: false,
        }
    }

    fn dummy_tx() -> (Tx, u32, u64, [u8; 32]) {
        let mut prev = [0u8; 32];
        prev[0] = 0x11;
        let mut chain_id = [0u8; 32];
        chain_id[0] = 0x22;
        (
            Tx {
                version: 1,
                tx_kind: 0x00,
                tx_nonce: 1,
                inputs: vec![TxInput {
                    prev_txid: prev,
                    prev_vout: 0,
                    script_sig: vec![],
                    sequence: 0,
                }],
                outputs: vec![TxOutput {
                    value: 1,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: vec![],
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
    fn core_ext_pre_active_keyless_sentinel_ok() {
        let entry = dummy_entry(7);
        let w = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![],
            signature: vec![],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &CoreExtProfiles::empty(),
        )
        .unwrap();
    }

    #[test]
    fn core_ext_pre_active_non_keyless_sentinel_ok() {
        let entry = dummy_entry(7);
        let w = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![0u8; 32],
            signature: vec![0x01],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &CoreExtProfiles::empty(),
        )
        .unwrap();
    }

    #[test]
    fn core_ext_pre_active_non_sentinel_ok() {
        let entry = dummy_entry(7);
        let w = WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0u8; (ML_DSA_87_SIG_BYTES as usize) + 1],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &CoreExtProfiles::empty(),
        )
        .unwrap();
    }

    #[test]
    fn core_ext_active_disallowed_suite_rejected_sig_alg_invalid() {
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                allowed_suite_ids: vec![SUITE_ID_ML_DSA_87],
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
            }],
        };
        let w = WitnessItem {
            suite_id: 0x02,
            pubkey: vec![0u8; 1],
            signature: vec![0u8; 1],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let err = validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn core_ext_active_unknown_suite_allowed_but_unsupported_binding_rejected_sig_alg_invalid() {
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                allowed_suite_ids: vec![0x03],
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
            }],
        };
        let w = WitnessItem {
            suite_id: 0x03,
            pubkey: vec![0x01],
            signature: vec![0x02],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let err = validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn core_ext_active_verify_sig_ext_accept_allows_non_native_suite() {
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                allowed_suite_ids: vec![0x03],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
            }],
        };
        let w = WitnessItem {
            suite_id: 0x03,
            pubkey: vec![0x11],
            signature: vec![0x01],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap();
    }

    #[test]
    fn core_ext_active_verify_sig_ext_reject_maps_to_sig_invalid() {
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                allowed_suite_ids: vec![0x03],
                verification_binding: CoreExtVerificationBinding::VerifySigExtReject,
            }],
        };
        let w = WitnessItem {
            suite_id: 0x03,
            pubkey: vec![0x11],
            signature: vec![0x01],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let err = validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn core_ext_active_verify_sig_ext_error_maps_to_sig_alg_invalid() {
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                allowed_suite_ids: vec![0x03],
                verification_binding: CoreExtVerificationBinding::VerifySigExtError,
            }],
        };
        let w = WitnessItem {
            suite_id: 0x03,
            pubkey: vec![0x11],
            signature: vec![0x01],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let err = validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn core_ext_active_verify_sig_ext_accept_invalid_sighash_rejected() {
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                allowed_suite_ids: vec![0x03],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
            }],
        };
        let w = WitnessItem {
            suite_id: 0x03,
            pubkey: vec![0x11],
            signature: vec![0x00],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let err = validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSighashTypeInvalid);
    }

    #[test]
    fn core_ext_active_native_suite_invalid_signature_maps_to_sig_invalid() {
        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                allowed_suite_ids: vec![SUITE_ID_ML_DSA_87],
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
            }],
        };
        let mut sig = vec![0u8; (ML_DSA_87_SIG_BYTES as usize) + 1];
        sig[ML_DSA_87_SIG_BYTES as usize] = 0x01; // SIGHASH_ALL
        let w = WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: sig,
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let err = validate_core_ext_spend(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            &profiles,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }
}
