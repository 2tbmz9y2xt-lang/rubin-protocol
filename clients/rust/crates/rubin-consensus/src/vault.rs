use crate::constants::{MAX_VAULT_COVENANT_DATA, MAX_VAULT_COVENANT_LEGACY, MIN_VAULT_SPEND_DELAY};
use crate::error::{ErrorCode, TxError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultCovenant {
    pub owner_key_id: [u8; 32],
    pub recovery_key_id: [u8; 32],
    pub spend_delay: u64,
    pub lock_mode: u8,
    pub lock_value: u64,
}

pub fn parse_vault_covenant_data(covenant_data: &[u8]) -> Result<VaultCovenant, TxError> {
    let mut owner = [0u8; 32];
    let mut recovery = [0u8; 32];

    let (spend_delay, lock_mode, lock_value) = match covenant_data.len() as u64 {
        MAX_VAULT_COVENANT_LEGACY => {
            owner.copy_from_slice(&covenant_data[0..32]);
            recovery.copy_from_slice(&covenant_data[41..73]);
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&covenant_data[33..41]);
            (0u64, covenant_data[32], u64::from_le_bytes(raw))
        }
        MAX_VAULT_COVENANT_DATA => {
            owner.copy_from_slice(&covenant_data[0..32]);
            recovery.copy_from_slice(&covenant_data[49..81]);

            let mut delay_raw = [0u8; 8];
            delay_raw.copy_from_slice(&covenant_data[32..40]);
            let spend_delay = u64::from_le_bytes(delay_raw);
            if spend_delay < MIN_VAULT_SPEND_DELAY {
                return Err(TxError::new(
                    ErrorCode::TxErrCovenantTypeInvalid,
                    "CORE_VAULT spend_delay below minimum",
                ));
            }

            let mut lock_raw = [0u8; 8];
            lock_raw.copy_from_slice(&covenant_data[41..49]);
            (spend_delay, covenant_data[40], u64::from_le_bytes(lock_raw))
        }
        _ => {
            return Err(TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "invalid CORE_VAULT covenant_data length",
            ))
        }
    };

    if lock_mode != 0x00 && lock_mode != 0x01 {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "invalid CORE_VAULT lock_mode",
        ));
    }
    if owner == recovery {
        return Err(TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "CORE_VAULT owner_key_id equals recovery_key_id",
        ));
    }

    Ok(VaultCovenant {
        owner_key_id: owner,
        recovery_key_id: recovery,
        spend_delay,
        lock_mode,
        lock_value,
    })
}
