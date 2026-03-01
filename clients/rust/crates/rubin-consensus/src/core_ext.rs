use crate::compactsize::read_compact_size_bytes;
use crate::constants::{
    SLH_DSA_ACTIVATION_HEIGHT, SUITE_ID_ML_DSA_87, SUITE_ID_SENTINEL, SUITE_ID_SLH_DSA_SHAKE_256F,
};
use crate::error::{ErrorCode, TxError};
use crate::tx::WitnessItem;
use crate::utxo_basic::UtxoEntry;
use crate::verify_sig_openssl::verify_sig;

fn check_slh_canonical(w: &WitnessItem) -> Result<(), TxError> {
    use crate::constants::{MAX_SLH_DSA_SIG_BYTES, SLH_DSA_SHAKE_256F_PUBKEY_BYTES};
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreExtCovenant<'a> {
    pub ext_id: u16,
    pub ext_payload: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreExtVerificationBinding {
    /// Only native suites (0x01/0x02) are supported; non-native suites are rejected even if listed.
    NativeVerifySig,
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
    digest: &[u8; 32],
    block_height: u64,
    profiles_at_height: &CoreExtProfiles,
) -> Result<(), TxError> {
    let cov = parse_core_ext_covenant_data(&entry.covenant_data)?;
    let _ = cov.ext_payload;

    let active_profile = profiles_at_height.lookup_active_profile(cov.ext_id)?;
    if active_profile.is_none() {
        if w.suite_id != SUITE_ID_SENTINEL || !w.pubkey.is_empty() || !w.signature.is_empty() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "CORE_EXT pre-ACTIVE requires keyless sentinel witness",
            ));
        }
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
    if w.suite_id == SUITE_ID_SLH_DSA_SHAKE_256F && block_height < SLH_DSA_ACTIVATION_HEIGHT {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "SLH-DSA suite inactive at this height",
        ));
    }

    match p.verification_binding {
        CoreExtVerificationBinding::NativeVerifySig => match w.suite_id {
            SUITE_ID_ML_DSA_87 | SUITE_ID_SLH_DSA_SHAKE_256F => {
                check_slh_canonical(w)?;
                let ok = verify_sig(w.suite_id, &w.pubkey, &w.signature, digest)?;
                if !ok {
                    return Err(TxError::new(
                        ErrorCode::TxErrSigInvalid,
                        "CORE_EXT signature invalid",
                    ));
                }
                Ok(())
            }
            _ => Err(TxError::new(
                ErrorCode::TxErrSigAlgInvalid,
                "CORE_EXT non-native verifier binding unsupported",
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compactsize::encode_compact_size;
    use crate::constants::{COV_TYPE_EXT, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES};

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

    #[test]
    fn core_ext_pre_active_keyless_sentinel_ok() {
        let entry = dummy_entry(7);
        let w = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![],
            signature: vec![],
        };
        validate_core_ext_spend(&entry, &w, &[0u8; 32], 0, &CoreExtProfiles::empty()).unwrap();
    }

    #[test]
    fn core_ext_pre_active_non_keyless_sentinel_rejected_parse() {
        let entry = dummy_entry(7);
        let w = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![0u8; 32],
            signature: vec![0x01],
        };
        let err = validate_core_ext_spend(&entry, &w, &[0u8; 32], 0, &CoreExtProfiles::empty())
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn core_ext_pre_active_non_sentinel_rejected_parse() {
        let entry = dummy_entry(7);
        let w = WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0u8; ML_DSA_87_SIG_BYTES as usize],
        };
        let err = validate_core_ext_spend(&entry, &w, &[0u8; 32], 0, &CoreExtProfiles::empty())
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrParse);
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
            suite_id: SUITE_ID_SLH_DSA_SHAKE_256F,
            pubkey: vec![0u8; 64],
            signature: vec![0u8; 49_856],
        };
        let err =
            validate_core_ext_spend(&entry, &w, &[0u8; 32], SLH_DSA_ACTIVATION_HEIGHT, &profiles)
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
        let err = validate_core_ext_spend(&entry, &w, &[0u8; 32], 0, &profiles).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
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
        let w = WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0u8; ML_DSA_87_SIG_BYTES as usize],
        };
        let err = validate_core_ext_spend(&entry, &w, &[0u8; 32], 0, &profiles).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }
}
