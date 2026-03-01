use crate::compactsize::read_compact_size;
use crate::constants::{SUITE_ID_ML_DSA_87, SUITE_ID_SLH_DSA_SHAKE_256F};
use crate::error::{ErrorCode, TxError};
use crate::tx::WitnessItem;
use crate::verify_sig_openssl::verify_sig;
use crate::wire_read::Reader;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreExtCovenant {
    pub ext_id: u16,
    pub ext_payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreExtProfile {
    pub ext_id: u16,
    pub activation_height: u64,
    pub allowed_suite_ids: Vec<u8>,
}

const CORE_EXT_DEPLOYMENT_PROFILES: &[CoreExtProfile] = &[];

pub fn parse_core_ext_covenant_data(cov_data: &[u8]) -> Result<CoreExtCovenant, TxError> {
    if cov_data.len() < 3 {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_EXT covenant_data too short",
        ));
    }

    let mut reader = Reader::new(cov_data);
    let ext_id = reader.read_u16_le().map_err(|_| {
        TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_EXT missing ext_id",
        )
    })?;
    let (ext_payload_len_u64, _) = read_compact_size(&mut reader).map_err(|_| {
        TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_EXT malformed ext_payload_len",
        )
    })?;
    if ext_payload_len_u64 > usize::MAX as u64 {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_EXT ext_payload_len overflows usize",
        ));
    }
    let ext_payload_len = ext_payload_len_u64 as usize;
    if reader.offset() + ext_payload_len != cov_data.len() {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_EXT covenant_data length mismatch",
        ));
    }
    let ext_payload = reader
        .read_bytes(ext_payload_len)
        .map_err(|_| {
            TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "CORE_EXT truncated ext_payload",
            )
        })?
        .to_vec();

    Ok(CoreExtCovenant {
        ext_id,
        ext_payload,
    })
}

pub fn active_core_ext_profile_with_profiles(
    ext_id: u16,
    block_height: u64,
    profiles_override: Option<&[CoreExtProfile]>,
) -> Result<Option<CoreExtProfile>, TxError> {
    let profiles: &[CoreExtProfile] = profiles_override.unwrap_or(CORE_EXT_DEPLOYMENT_PROFILES);
    let mut active: Option<CoreExtProfile> = None;
    for profile in profiles {
        if profile.ext_id != ext_id || block_height < profile.activation_height {
            continue;
        }
        if active.is_some() {
            return Err(TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "multiple active CORE_EXT profiles for ext_id",
            ));
        }
        active = Some(profile.clone());
    }
    Ok(active)
}

pub fn core_ext_suite_allowed(profile: Option<&CoreExtProfile>, suite_id: u8) -> bool {
    profile
        .map(|p| p.allowed_suite_ids.contains(&suite_id))
        .unwrap_or(false)
}

pub fn verify_sig_ext(
    profile: Option<&CoreExtProfile>,
    ext: &CoreExtCovenant,
    witness: &WitnessItem,
    digest32: &[u8; 32],
) -> Result<bool, TxError> {
    if profile.is_none() {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_EXT verifier binding missing",
        ));
    }
    let _ = ext;
    match witness.suite_id {
        SUITE_ID_ML_DSA_87 | SUITE_ID_SLH_DSA_SHAKE_256F => verify_sig(
            witness.suite_id,
            &witness.pubkey,
            &witness.signature,
            digest32,
        ),
        _ => Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_EXT verifier binding unsupported for non-native suite",
        )),
    }
}
