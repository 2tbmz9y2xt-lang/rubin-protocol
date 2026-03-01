use crate::compactsize::encode_compact_size;
use crate::constants::{
    COV_TYPE_EXT, COV_TYPE_HTLC, COV_TYPE_MULTISIG, COV_TYPE_P2PK, COV_TYPE_VAULT,
    MAX_MULTISIG_KEYS, MAX_VAULT_KEYS, MAX_VAULT_WHITELIST_ENTRIES,
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
