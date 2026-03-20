use crate::compactsize::{encode_compact_size, read_compact_size_bytes};
use crate::constants::SUITE_ID_SENTINEL;
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::sighash::{is_valid_sighash_type, sighash_v1_digest_with_cache, SighashV1PrehashCache};
use crate::suite_registry::{DefaultRotationProvider, RotationProvider, SuiteRegistry};
use crate::tx::Tx;
use crate::tx::WitnessItem;
use crate::utxo_basic::UtxoEntry;
use crate::verify_sig_openssl::verify_sig_with_registry;
use std::sync::OnceLock;

pub const CORE_EXT_BINDING_KIND_NATIVE_ONLY: u8 = 0x01;
pub const CORE_EXT_BINDING_KIND_VERIFY_SIG_EXT: u8 = 0x02;

fn default_suite_registry() -> &'static SuiteRegistry {
    static DEFAULT_SUITE_REGISTRY: OnceLock<SuiteRegistry> = OnceLock::new();
    DEFAULT_SUITE_REGISTRY.get_or_init(SuiteRegistry::default_registry)
}

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
    pub binding_descriptor: Vec<u8>,
    pub ext_payload_schema: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoreExtProfiles {
    pub active: Vec<CoreExtActiveProfile>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreExtDeploymentProfile {
    pub ext_id: u16,
    pub activation_height: u64,
    pub allowed_suite_ids: Vec<u8>,
    pub verification_binding: CoreExtVerificationBinding,
    pub binding_descriptor: Vec<u8>,
    pub ext_payload_schema: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoreExtDeploymentProfiles {
    pub deployments: Vec<CoreExtDeploymentProfile>,
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

impl CoreExtDeploymentProfiles {
    pub fn empty() -> Self {
        Self {
            deployments: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        for deployment in &self.deployments {
            if deployment.allowed_suite_ids.is_empty() {
                return Err(format!(
                    "core_ext deployment for ext_id={} must have non-empty allowed_suite_ids",
                    deployment.ext_id
                ));
            }
        }
        Ok(())
    }

    pub fn active_profiles_at_height(&self, height: u64) -> Result<CoreExtProfiles, TxError> {
        self.validate().map_err(|_| {
            TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "CORE_EXT active profile must have non-empty allowed_suite_ids",
            )
        })?;
        let mut active = Vec::new();
        for deployment in &self.deployments {
            if height < deployment.activation_height {
                continue;
            }
            if active
                .iter()
                .any(|profile: &CoreExtActiveProfile| profile.ext_id == deployment.ext_id)
            {
                return Err(TxError::new(
                    ErrorCode::TxErrCovenantTypeInvalid,
                    "CORE_EXT multiple ACTIVE profiles for ext_id",
                ));
            }
            active.push(CoreExtActiveProfile {
                ext_id: deployment.ext_id,
                allowed_suite_ids: deployment.allowed_suite_ids.clone(),
                verification_binding: deployment.verification_binding.clone(),
                binding_descriptor: deployment.binding_descriptor.clone(),
                ext_payload_schema: deployment.ext_payload_schema.clone(),
            });
        }
        Ok(CoreExtProfiles { active })
    }
}

fn normalized_allowed_suite_ids(ids: &[u8]) -> Vec<u8> {
    let mut out = ids.to_vec();
    out.sort_unstable();
    out.dedup();
    out
}

fn core_ext_binding_kind(profile: &CoreExtDeploymentProfile) -> Result<u8, String> {
    match profile.verification_binding {
        CoreExtVerificationBinding::NativeVerifySig => {
            if !profile.binding_descriptor.is_empty() {
                return Err(format!(
                    "core_ext profile ext_id={} native-only profile must not carry binding_descriptor",
                    profile.ext_id
                ));
            }
            Ok(CORE_EXT_BINDING_KIND_NATIVE_ONLY)
        }
        _ => {
            if profile.binding_descriptor.is_empty() {
                return Err(format!(
                    "core_ext profile ext_id={} verify_sig_ext profile must carry binding_descriptor",
                    profile.ext_id
                ));
            }
            Ok(CORE_EXT_BINDING_KIND_VERIFY_SIG_EXT)
        }
    }
}

pub fn core_ext_profile_bytes_v1(profile: &CoreExtDeploymentProfile) -> Result<Vec<u8>, String> {
    let allowed_suite_ids = normalized_allowed_suite_ids(&profile.allowed_suite_ids);
    if allowed_suite_ids.is_empty() {
        return Err(format!(
            "core_ext profile ext_id={} must have non-empty allowed_suite_ids",
            profile.ext_id
        ));
    }
    if profile.ext_payload_schema.is_empty() {
        return Err(format!(
            "core_ext profile ext_id={} must carry ext_payload_schema",
            profile.ext_id
        ));
    }
    let binding_kind = core_ext_binding_kind(profile)?;

    let mut out = b"RUBIN-CORE-EXT-PROFILE-v1".to_vec();
    out.extend_from_slice(&profile.ext_id.to_le_bytes());
    out.extend_from_slice(&profile.activation_height.to_le_bytes());
    encode_compact_size(allowed_suite_ids.len() as u64, &mut out);
    out.extend_from_slice(&allowed_suite_ids);
    out.push(binding_kind);
    encode_compact_size(profile.binding_descriptor.len() as u64, &mut out);
    out.extend_from_slice(&profile.binding_descriptor);
    encode_compact_size(profile.ext_payload_schema.len() as u64, &mut out);
    out.extend_from_slice(&profile.ext_payload_schema);
    Ok(out)
}

pub fn core_ext_profile_anchor_v1(profile: &CoreExtDeploymentProfile) -> Result<[u8; 32], String> {
    let mut preimage = b"RUBIN-CORE-EXT-PROFILE-ANCHOR-v1".to_vec();
    preimage.extend_from_slice(&core_ext_profile_bytes_v1(profile)?);
    Ok(sha3_256(&preimage))
}

pub fn core_ext_profile_set_anchor_v1(
    chain_id: [u8; 32],
    deployments: &[CoreExtDeploymentProfile],
) -> Result<[u8; 32], String> {
    let mut anchors = Vec::with_capacity(deployments.len());
    for deployment in deployments {
        anchors.push(core_ext_profile_anchor_v1(deployment)?);
    }
    anchors.sort_unstable();

    let mut preimage = b"RUBIN-CORE-EXT-PROFILE-SET-v1".to_vec();
    preimage.extend_from_slice(&chain_id);
    encode_compact_size(anchors.len() as u64, &mut preimage);
    for anchor in anchors {
        preimage.extend_from_slice(&anchor);
    }
    Ok(sha3_256(&preimage))
}

pub fn core_ext_verification_binding_from_name(
    binding_name: &str,
) -> Result<CoreExtVerificationBinding, String> {
    match binding_name.trim() {
        "" | "native_verify_sig" => Ok(CoreExtVerificationBinding::NativeVerifySig),
        "verify_sig_ext_accept" => Ok(CoreExtVerificationBinding::VerifySigExtAccept),
        "verify_sig_ext_reject" => Ok(CoreExtVerificationBinding::VerifySigExtReject),
        "verify_sig_ext_error" => Ok(CoreExtVerificationBinding::VerifySigExtError),
        _ => Err(format!("unsupported core_ext binding: {binding_name}")),
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
    let mut cache = SighashV1PrehashCache::new(tx)?;
    validate_core_ext_spend_with_cache_and_suite_context(
        entry,
        w,
        tx,
        input_index,
        input_value,
        chain_id,
        0,
        profiles_at_height,
        None,
        None,
        &mut cache,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn validate_core_ext_spend_at_height(
    entry: &UtxoEntry,
    w: &WitnessItem,
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    profiles_at_height: &CoreExtProfiles,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
) -> Result<(), TxError> {
    let mut cache = SighashV1PrehashCache::new(tx)?;
    validate_core_ext_spend_with_cache_and_suite_context(
        entry,
        w,
        tx,
        input_index,
        input_value,
        chain_id,
        block_height,
        profiles_at_height,
        rotation,
        registry,
        &mut cache,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_core_ext_spend_with_cache_and_suite_context(
    entry: &UtxoEntry,
    w: &WitnessItem,
    _tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    profiles_at_height: &CoreExtProfiles,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
    cache: &mut SighashV1PrehashCache<'_>,
) -> Result<(), TxError> {
    let default_rotation = DefaultRotationProvider;
    let rotation = rotation.unwrap_or(&default_rotation);
    let registry = match registry {
        Some(registry) => registry,
        None => default_suite_registry(),
    };

    validate_core_ext_spend_with_cache_impl(
        entry,
        w,
        input_index,
        input_value,
        chain_id,
        block_height,
        profiles_at_height,
        rotation,
        registry,
        cache,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_core_ext_spend_with_cache_impl(
    entry: &UtxoEntry,
    w: &WitnessItem,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    profiles_at_height: &CoreExtProfiles,
    rotation: &dyn RotationProvider,
    registry: &SuiteRegistry,
    cache: &mut SighashV1PrehashCache<'_>,
) -> Result<(), TxError> {
    let cov = parse_core_ext_covenant_data(&entry.covenant_data)?;

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

    let native_spend_suites = rotation.native_spend_suites(block_height);
    let native_params = registry.lookup(w.suite_id);

    // Per CANONICAL §12.5 / §23.2.2, registry-known native suites stay on the
    // native path only while currently spend-permitted at this height; suites
    // outside the current native spend set reject here and never fall through
    // to verify_sig_ext.
    if let Some(params) = native_params {
        if !native_spend_suites.contains(w.suite_id) {
            return Err(TxError::new(
                ErrorCode::TxErrSigAlgInvalid,
                "CORE_EXT registered native suite not spend-permitted at this height",
            ));
        }
        if w.pubkey.len() as u64 != params.pubkey_len
            || w.signature.len() as u64 != params.sig_len + 1
        {
            return Err(TxError::new(
                ErrorCode::TxErrSigNoncanonical,
                "non-canonical CORE_EXT native witness item lengths",
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
        let digest32 =
            sighash_v1_digest_with_cache(cache, input_index, input_value, chain_id, sighash_type)?;
        let ok =
            verify_sig_with_registry(w.suite_id, &w.pubkey, crypto_sig, &digest32, Some(registry))?;
        if !ok {
            return Err(TxError::new(
                ErrorCode::TxErrSigInvalid,
                "CORE_EXT signature invalid",
            ));
        }
        return Ok(());
    }
    if native_spend_suites.contains(w.suite_id) {
        return Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "CORE_EXT registered native suite missing from registry",
        ));
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
    let _digest32 =
        sighash_v1_digest_with_cache(cache, input_index, input_value, chain_id, sighash_type)?;

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
    use crate::constants::{
        COV_TYPE_EXT, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87,
        VERIFY_COST_ML_DSA_87,
    };
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
                binding_descriptor: Vec::new(),
                ext_payload_schema: Vec::new(),
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
                binding_descriptor: Vec::new(),
                ext_payload_schema: Vec::new(),
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
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
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
                binding_descriptor: b"reject".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
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
                binding_descriptor: b"error".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
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
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
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
                binding_descriptor: Vec::new(),
                ext_payload_schema: Vec::new(),
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

    #[test]
    fn core_ext_deployments_activate_at_height() {
        let deployments = CoreExtDeploymentProfiles {
            deployments: vec![CoreExtDeploymentProfile {
                ext_id: 7,
                activation_height: 10,
                allowed_suite_ids: vec![0x03],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };

        let before = deployments.active_profiles_at_height(9).unwrap();
        assert!(before.active.is_empty());

        let active = deployments.active_profiles_at_height(10).unwrap();
        assert_eq!(active.active.len(), 1);
        assert_eq!(active.active[0].ext_id, 7);
    }

    #[test]
    fn core_ext_deployments_empty_allowed_suite_ids_rejected_at_activation_lookup() {
        let deployments = CoreExtDeploymentProfiles {
            deployments: vec![CoreExtDeploymentProfile {
                ext_id: 7,
                activation_height: 10,
                allowed_suite_ids: Vec::new(),
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
                binding_descriptor: Vec::new(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };

        let err = deployments.active_profiles_at_height(10).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    #[test]
    fn core_ext_deployments_duplicate_active_rejected() {
        let deployments = CoreExtDeploymentProfiles {
            deployments: vec![
                CoreExtDeploymentProfile {
                    ext_id: 7,
                    activation_height: 0,
                    allowed_suite_ids: vec![0x03],
                    verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                    binding_descriptor: b"accept".to_vec(),
                    ext_payload_schema: b"schema-a".to_vec(),
                },
                CoreExtDeploymentProfile {
                    ext_id: 7,
                    activation_height: 0,
                    allowed_suite_ids: vec![0x04],
                    verification_binding: CoreExtVerificationBinding::VerifySigExtReject,
                    binding_descriptor: b"reject".to_vec(),
                    ext_payload_schema: b"schema-b".to_vec(),
                },
            ],
        };

        let err = deployments.active_profiles_at_height(0).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    #[test]
    fn core_ext_profile_set_anchor_changes_with_payload_schema() {
        let chain_id = [0x42; 32];
        let mut base = CoreExtDeploymentProfile {
            ext_id: 7,
            activation_height: 1,
            allowed_suite_ids: vec![3],
            verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
            binding_descriptor: b"accept".to_vec(),
            ext_payload_schema: b"schema-a".to_vec(),
        };
        let base_anchor =
            core_ext_profile_set_anchor_v1(chain_id, &[base.clone()]).expect("base anchor");
        base.ext_payload_schema = b"schema-b".to_vec();
        let changed_anchor =
            core_ext_profile_set_anchor_v1(chain_id, &[base]).expect("changed anchor");
        assert_ne!(base_anchor, changed_anchor);
    }

    #[test]
    fn core_ext_profile_set_anchor_changes_with_activation_height() {
        let chain_id = [0x42; 32];
        let mut base = CoreExtDeploymentProfile {
            ext_id: 7,
            activation_height: 1,
            allowed_suite_ids: vec![3],
            verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
            binding_descriptor: b"accept".to_vec(),
            ext_payload_schema: b"schema-a".to_vec(),
        };
        let base_anchor =
            core_ext_profile_set_anchor_v1(chain_id, &[base.clone()]).expect("base anchor");
        base.activation_height = 2;
        let changed_anchor =
            core_ext_profile_set_anchor_v1(chain_id, &[base]).expect("changed anchor");
        assert_ne!(base_anchor, changed_anchor);
    }

    #[test]
    fn core_ext_profile_bytes_v1_native_binding_succeeds_without_descriptor() {
        let profile = CoreExtDeploymentProfile {
            ext_id: 7,
            activation_height: 1,
            allowed_suite_ids: vec![3],
            verification_binding: CoreExtVerificationBinding::NativeVerifySig,
            binding_descriptor: Vec::new(),
            ext_payload_schema: b"schema-a".to_vec(),
        };

        let bytes = core_ext_profile_bytes_v1(&profile).expect("native profile bytes");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn core_ext_profile_bytes_v1_rejects_invalid_profiles() {
        let err = core_ext_profile_bytes_v1(&CoreExtDeploymentProfile {
            ext_id: 7,
            activation_height: 1,
            allowed_suite_ids: Vec::new(),
            verification_binding: CoreExtVerificationBinding::NativeVerifySig,
            binding_descriptor: Vec::new(),
            ext_payload_schema: b"schema-a".to_vec(),
        })
        .unwrap_err();
        assert!(err.contains("must have non-empty allowed_suite_ids"));

        let err = core_ext_profile_bytes_v1(&CoreExtDeploymentProfile {
            ext_id: 7,
            activation_height: 1,
            allowed_suite_ids: vec![3],
            verification_binding: CoreExtVerificationBinding::NativeVerifySig,
            binding_descriptor: vec![0xa1],
            ext_payload_schema: b"schema-a".to_vec(),
        })
        .unwrap_err();
        assert!(err.contains("native-only profile must not carry binding_descriptor"));

        let err = core_ext_profile_bytes_v1(&CoreExtDeploymentProfile {
            ext_id: 7,
            activation_height: 1,
            allowed_suite_ids: vec![3],
            verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
            binding_descriptor: Vec::new(),
            ext_payload_schema: b"schema-a".to_vec(),
        })
        .unwrap_err();
        assert!(err.contains("verify_sig_ext profile must carry binding_descriptor"));
    }

    #[test]
    fn core_ext_rotated_native_suite_uses_registry_path() {
        use crate::suite_registry::{NativeSuiteSet, RotationProvider, SuiteParams, SuiteRegistry};
        use std::collections::BTreeMap;

        struct RotatedSpend;
        impl RotationProvider for RotatedSpend {
            fn native_create_suites(&self, _height: u64) -> NativeSuiteSet {
                NativeSuiteSet::new(&[SUITE_ID_ML_DSA_87, 0x02])
            }

            fn native_spend_suites(&self, _height: u64) -> NativeSuiteSet {
                NativeSuiteSet::new(&[SUITE_ID_ML_DSA_87, 0x02])
            }
        }

        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                allowed_suite_ids: vec![0x02],
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
                binding_descriptor: Vec::new(),
                ext_payload_schema: Vec::new(),
            }],
        };
        let mut sig = vec![0u8; (ML_DSA_87_SIG_BYTES as usize) + 1];
        sig[ML_DSA_87_SIG_BYTES as usize] = 0x01;
        let w = WitnessItem {
            suite_id: 0x02,
            pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: sig,
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let mut suites = BTreeMap::new();
        suites.insert(
            0x02,
            SuiteParams {
                suite_id: 0x02,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: VERIFY_COST_ML_DSA_87,
                openssl_alg: "ML-DSA-87",
            },
        );
        let reg = SuiteRegistry::with_suites(suites);
        let err = validate_core_ext_spend_at_height(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            &profiles,
            Some(&RotatedSpend),
            Some(&reg),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn core_ext_registered_native_suite_outside_spend_set_rejected() {
        use crate::suite_registry::{NativeSuiteSet, RotationProvider, SuiteParams, SuiteRegistry};
        use std::collections::BTreeMap;

        struct SunsetSpend;
        impl RotationProvider for SunsetSpend {
            fn native_create_suites(&self, _height: u64) -> NativeSuiteSet {
                NativeSuiteSet::new(&[SUITE_ID_ML_DSA_87, 0x02])
            }

            fn native_spend_suites(&self, _height: u64) -> NativeSuiteSet {
                NativeSuiteSet::new(&[SUITE_ID_ML_DSA_87])
            }
        }

        let entry = dummy_entry(7);
        let profiles = CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id: 7,
                allowed_suite_ids: vec![0x02],
                verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            }],
        };
        let w = WitnessItem {
            suite_id: 0x02,
            pubkey: vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize],
            signature: vec![0u8; (ML_DSA_87_SIG_BYTES as usize) + 1],
        };
        let (tx, input_index, input_value, chain_id) = dummy_tx();
        let mut suites = BTreeMap::new();
        suites.insert(
            0x02,
            SuiteParams {
                suite_id: 0x02,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: VERIFY_COST_ML_DSA_87,
                openssl_alg: "ML-DSA-87",
            },
        );
        let reg = SuiteRegistry::with_suites(suites);
        let err = validate_core_ext_spend_at_height(
            &entry,
            &w,
            &tx,
            input_index,
            input_value,
            chain_id,
            0,
            &profiles,
            Some(&SunsetSpend),
            Some(&reg),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
        assert_eq!(
            err.msg,
            "CORE_EXT registered native suite not spend-permitted at this height"
        );
    }
}
