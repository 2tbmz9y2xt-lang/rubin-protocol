package consensus

import "encoding/binary"

type VaultCovenant struct {
	OwnerKeyID    [32]byte
	RecoveryKeyID [32]byte
	SpendDelay    uint64
	LockMode      byte
	LockValue     uint64
}

func ParseVaultCovenantData(covData []byte) (*VaultCovenant, error) {
	if covData == nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "nil CORE_VAULT covenant_data")
	}

	var v VaultCovenant
	switch len(covData) {
	case MAX_VAULT_COVENANT_LEGACY:
		copy(v.OwnerKeyID[:], covData[:32])
		v.SpendDelay = 0
		v.LockMode = covData[32]
		v.LockValue = binary.LittleEndian.Uint64(covData[33:41])
		copy(v.RecoveryKeyID[:], covData[41:73])
	case MAX_VAULT_COVENANT_DATA:
		copy(v.OwnerKeyID[:], covData[:32])
		v.SpendDelay = binary.LittleEndian.Uint64(covData[32:40])
		v.LockMode = covData[40]
		v.LockValue = binary.LittleEndian.Uint64(covData[41:49])
		copy(v.RecoveryKeyID[:], covData[49:81])
		if v.SpendDelay < MIN_VAULT_SPEND_DELAY {
			return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_VAULT spend_delay below minimum")
		}
	default:
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "invalid CORE_VAULT covenant_data length")
	}

	if v.LockMode != 0x00 && v.LockMode != 0x01 {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "invalid CORE_VAULT lock_mode")
	}
	if v.OwnerKeyID == v.RecoveryKeyID {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_VAULT owner_key_id equals recovery_key_id")
	}
	return &v, nil
}
