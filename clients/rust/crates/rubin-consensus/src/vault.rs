use crate::compactsize::encode_compact_size;
use crate::constants::{
    CORE_STEALTH_WITNESS_SLOTS, COV_TYPE_EXT, COV_TYPE_HTLC, COV_TYPE_MULTISIG, COV_TYPE_P2PK,
    COV_TYPE_STEALTH, COV_TYPE_VAULT, MAX_MULTISIG_KEYS, MAX_VAULT_KEYS,
    MAX_VAULT_WHITELIST_ENTRIES,
};
use crate::error::{ErrorCode, TxError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultCovenant {
    pub owner_lock_id: [u8; 32],
    pub threshold: u8,
    pub key_count: u8,
    pub keys: Vec<[u8; 32]>,
    pub whitelist_count: u16,
    pub whitelist: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigCovenant {
    pub threshold: u8,
    pub key_count: u8,
    pub keys: Vec<[u8; 32]>,
}

pub fn parse_vault_covenant_data(covenant_data: &[u8]) -> Result<VaultCovenant, TxError> {
    parse_vault_covenant_data_inner(covenant_data, true)
}

pub fn parse_vault_covenant_data_for_spend(covenant_data: &[u8]) -> Result<VaultCovenant, TxError> {
    parse_vault_covenant_data_inner(covenant_data, false)
}

fn parse_vault_covenant_data_inner(
    covenant_data: &[u8],
    enforce_whitelist_canonical: bool,
) -> Result<VaultCovenant, TxError> {
    if covenant_data.len() < 34 {
        return Err(TxError::new(
            ErrorCode::TxErrVaultMalformed,
            "CORE_VAULT covenant_data too short",
        ));
    }

    let mut owner_lock_id = [0u8; 32];
    owner_lock_id.copy_from_slice(&covenant_data[0..32]);
    let threshold = covenant_data[32];
    let key_count = covenant_data[33];
    if key_count == 0 || key_count > MAX_VAULT_KEYS {
        return Err(TxError::new(
            ErrorCode::TxErrVaultParamsInvalid,
            "CORE_VAULT key_count out of range",
        ));
    }
    if threshold == 0 || threshold > key_count {
        return Err(TxError::new(
            ErrorCode::TxErrVaultParamsInvalid,
            "CORE_VAULT threshold out of range",
        ));
    }

    let mut offset = 34usize;
    let mut keys = Vec::with_capacity(key_count as usize);
    for _ in 0..key_count {
        if offset + 32 > covenant_data.len() {
            return Err(TxError::new(
                ErrorCode::TxErrVaultMalformed,
                "CORE_VAULT truncated keys",
            ));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&covenant_data[offset..offset + 32]);
        offset += 32;
        keys.push(k);
    }
    if !strictly_sorted_unique_32(&keys) {
        return Err(TxError::new(
            ErrorCode::TxErrVaultKeysNotCanonical,
            "CORE_VAULT keys not strictly sorted",
        ));
    }

    if offset + 2 > covenant_data.len() {
        return Err(TxError::new(
            ErrorCode::TxErrVaultMalformed,
            "CORE_VAULT missing whitelist_count",
        ));
    }
    let whitelist_count = u16::from_le_bytes([covenant_data[offset], covenant_data[offset + 1]]);
    offset += 2;
    if whitelist_count == 0 || whitelist_count > MAX_VAULT_WHITELIST_ENTRIES {
        return Err(TxError::new(
            ErrorCode::TxErrVaultParamsInvalid,
            "CORE_VAULT whitelist_count out of range",
        ));
    }

    let expected_len = 32 + 1 + 1 + (key_count as usize) * 32 + 2 + (whitelist_count as usize) * 32;
    if covenant_data.len() != expected_len {
        return Err(TxError::new(
            ErrorCode::TxErrVaultMalformed,
            "CORE_VAULT covenant_data length mismatch",
        ));
    }

    let mut whitelist = Vec::with_capacity(whitelist_count as usize);
    for _ in 0..whitelist_count {
        let mut h = [0u8; 32];
        h.copy_from_slice(&covenant_data[offset..offset + 32]);
        offset += 32;
        whitelist.push(h);
    }
    if enforce_whitelist_canonical {
        if !strictly_sorted_unique_32(&whitelist) {
            return Err(TxError::new(
                ErrorCode::TxErrVaultWhitelistNotCanonical,
                "CORE_VAULT whitelist not strictly sorted",
            ));
        }
        if hash_in_sorted_32(&whitelist, &owner_lock_id) {
            return Err(TxError::new(
                ErrorCode::TxErrVaultOwnerDestinationForbidden,
                "CORE_VAULT whitelist contains owner_lock_id",
            ));
        }
    }

    Ok(VaultCovenant {
        owner_lock_id,
        threshold,
        key_count,
        keys,
        whitelist_count,
        whitelist,
    })
}

pub fn parse_multisig_covenant_data(covenant_data: &[u8]) -> Result<MultisigCovenant, TxError> {
    if covenant_data.len() < 34 {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_MULTISIG covenant_data too short",
        ));
    }

    let threshold = covenant_data[0];
    let key_count = covenant_data[1];
    if key_count == 0 || key_count > MAX_MULTISIG_KEYS {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_MULTISIG key_count out of range",
        ));
    }
    if threshold == 0 || threshold > key_count {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_MULTISIG threshold out of range",
        ));
    }

    let expected_len = 2 + (key_count as usize) * 32;
    if covenant_data.len() != expected_len {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_MULTISIG covenant_data length mismatch",
        ));
    }

    let mut keys = Vec::with_capacity(key_count as usize);
    let mut offset = 2usize;
    for _ in 0..key_count {
        let mut k = [0u8; 32];
        k.copy_from_slice(&covenant_data[offset..offset + 32]);
        offset += 32;
        keys.push(k);
    }
    if !strictly_sorted_unique_32(&keys) {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_MULTISIG keys not strictly sorted",
        ));
    }

    Ok(MultisigCovenant {
        threshold,
        key_count,
        keys,
    })
}

pub fn output_descriptor_bytes(covenant_type: u16, covenant_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 9 + covenant_data.len());
    out.extend_from_slice(&covenant_type.to_le_bytes());
    encode_compact_size(covenant_data.len() as u64, &mut out);
    out.extend_from_slice(covenant_data);
    out
}

pub fn witness_slots(covenant_type: u16, covenant_data: &[u8]) -> Result<usize, TxError> {
    match covenant_type {
        COV_TYPE_P2PK => Ok(1),
        COV_TYPE_EXT => Ok(1),
        COV_TYPE_STEALTH => Ok(CORE_STEALTH_WITNESS_SLOTS as usize),
        COV_TYPE_MULTISIG => Ok(covenant_data.get(1).copied().unwrap_or(1) as usize),
        // CORE_VAULT: owner_lock_id[32] || threshold[1] || key_count[1] || ...
        COV_TYPE_VAULT => Ok(covenant_data.get(33).copied().unwrap_or(1) as usize),
        COV_TYPE_HTLC => Ok(2),
        _ => Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "unsupported covenant in witness_slots",
        )),
    }
}

pub fn hash_in_sorted_32(list: &[[u8; 32]], target: &[u8; 32]) -> bool {
    list.binary_search(target).is_ok()
}

fn strictly_sorted_unique_32(xs: &[[u8; 32]]) -> bool {
    xs.windows(2).all(|w| w[0] < w[1])
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn verify_parse_vault_covenant_data_accepts_minimal_canonical_shape() {
        let owner_lock_id = [1u8; 32];
        let key = [2u8; 32];
        let whitelist_entry = [3u8; 32];

        let mut covenant_data = Vec::with_capacity(32 + 1 + 1 + 32 + 2 + 32);
        covenant_data.extend_from_slice(&owner_lock_id);
        covenant_data.push(1); // threshold
        covenant_data.push(1); // key_count
        covenant_data.extend_from_slice(&key);
        covenant_data.extend_from_slice(&1u16.to_le_bytes()); // whitelist_count
        covenant_data.extend_from_slice(&whitelist_entry);

        let parsed = parse_vault_covenant_data(&covenant_data);
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else {
            return;
        };
        assert_eq!(parsed.owner_lock_id, owner_lock_id);
        assert_eq!(parsed.threshold, 1);
        assert_eq!(parsed.key_count, 1);
        assert_eq!(parsed.keys, vec![key]);
        assert_eq!(parsed.whitelist_count, 1);
        assert_eq!(parsed.whitelist, vec![whitelist_entry]);
    }

    #[kani::proof]
    fn verify_parse_vault_covenant_data_rejects_zero_key_count() {
        let owner_lock_id = [0u8; 32];
        let mut covenant_data = Vec::with_capacity(34);
        covenant_data.extend_from_slice(&owner_lock_id);
        covenant_data.push(1); // threshold
        covenant_data.push(0); // key_count

        let parsed = parse_vault_covenant_data(&covenant_data);
        assert!(parsed.is_err());
        let Err(err) = parsed else {
            return;
        };
        assert_eq!(err.code, ErrorCode::TxErrVaultParamsInvalid);
    }

    #[kani::proof]
    fn verify_parse_multisig_covenant_data_accepts_minimal_canonical_shape() {
        let key = [4u8; 32];
        let mut covenant_data = Vec::with_capacity(2 + 32);
        covenant_data.push(1); // threshold
        covenant_data.push(1); // key_count
        covenant_data.extend_from_slice(&key);

        let parsed = parse_multisig_covenant_data(&covenant_data);
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else {
            return;
        };
        assert_eq!(parsed.threshold, 1);
        assert_eq!(parsed.key_count, 1);
        assert_eq!(parsed.keys, vec![key]);
    }

    #[kani::proof]
    fn verify_parse_multisig_covenant_data_rejects_zero_key_count() {
        let mut covenant_data = Vec::with_capacity(2);
        covenant_data.push(1); // threshold
        covenant_data.push(0); // key_count

        let parsed = parse_multisig_covenant_data(&covenant_data);
        assert!(parsed.is_err());
        let Err(err) = parsed else {
            return;
        };
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }
}
