package consensus

import (
	"bytes"
	"encoding/binary"
	"sort"
)

type VaultCovenant struct {
	Keys           [][32]byte
	Whitelist      [][32]byte
	WhitelistCount uint16
	OwnerLockID    [32]byte
	Threshold      uint8
	KeyCount       uint8
}

type MultisigCovenant struct {
	Keys      [][32]byte
	Threshold uint8
	KeyCount  uint8
}

func ParseVaultCovenantData(covData []byte) (*VaultCovenant, error) {
	return parseVaultCovenantData(covData, true)
}

func ParseVaultCovenantDataForSpend(covData []byte) (*VaultCovenant, error) {
	return parseVaultCovenantData(covData, false)
}

func parseVaultCovenantData(covData []byte, enforceWhitelistCanonical bool) (*VaultCovenant, error) {
	v, offset, err := parseVaultHeader(covData)
	if err != nil {
		return nil, err
	}

	v.Keys, offset, err = parseVaultKeys(covData, offset, v.KeyCount)
	if err != nil {
		return nil, err
	}
	if !strictlySortedUnique32(v.Keys) {
		return nil, txerr(TX_ERR_VAULT_KEYS_NOT_CANONICAL, "CORE_VAULT keys not strictly sorted")
	}

	v.Whitelist, v.WhitelistCount, err = parseVaultWhitelist(covData, offset, v.KeyCount)
	if err != nil {
		return nil, err
	}
	if err := validateVaultWhitelist(v, enforceWhitelistCanonical); err != nil {
		return nil, err
	}
	return v, nil
}

func parseVaultHeader(covData []byte) (*VaultCovenant, int, error) {
	if len(covData) < 34 {
		return nil, 0, txerr(TX_ERR_VAULT_MALFORMED, "CORE_VAULT covenant_data too short")
	}

	var v VaultCovenant
	copy(v.OwnerLockID[:], covData[0:32])
	v.Threshold = covData[32]
	v.KeyCount = covData[33]
	if v.KeyCount < 1 || v.KeyCount > MAX_VAULT_KEYS {
		return nil, 0, txerr(TX_ERR_VAULT_PARAMS_INVALID, "CORE_VAULT key_count out of range")
	}
	if v.Threshold < 1 || v.Threshold > v.KeyCount {
		return nil, 0, txerr(TX_ERR_VAULT_PARAMS_INVALID, "CORE_VAULT threshold out of range")
	}
	return &v, 34, nil
}

func parseVaultKeys(covData []byte, offset int, keyCount uint8) ([][32]byte, int, error) {
	keys := make([][32]byte, int(keyCount))
	for i := 0; i < int(keyCount); i++ {
		if offset+32 > len(covData) {
			return nil, 0, txerr(TX_ERR_VAULT_MALFORMED, "CORE_VAULT truncated keys")
		}
		copy(keys[i][:], covData[offset:offset+32])
		offset += 32
	}
	return keys, offset, nil
}

func parseVaultWhitelist(covData []byte, offset int, keyCount uint8) ([][32]byte, uint16, error) {
	if offset+2 > len(covData) {
		return nil, 0, txerr(TX_ERR_VAULT_MALFORMED, "CORE_VAULT missing whitelist_count")
	}
	whitelistCount := binary.LittleEndian.Uint16(covData[offset : offset+2])
	offset += 2
	if whitelistCount < 1 || whitelistCount > MAX_VAULT_WHITELIST_ENTRIES {
		return nil, 0, txerr(TX_ERR_VAULT_PARAMS_INVALID, "CORE_VAULT whitelist_count out of range")
	}

	expectedLen := 32 + 1 + 1 + int(keyCount)*32 + 2 + int(whitelistCount)*32
	if len(covData) != expectedLen {
		return nil, 0, txerr(TX_ERR_VAULT_MALFORMED, "CORE_VAULT covenant_data length mismatch")
	}

	whitelist := make([][32]byte, int(whitelistCount))
	for i := 0; i < int(whitelistCount); i++ {
		copy(whitelist[i][:], covData[offset:offset+32])
		offset += 32
	}
	return whitelist, whitelistCount, nil
}

func validateVaultWhitelist(v *VaultCovenant, enforceWhitelistCanonical bool) error {
	if !enforceWhitelistCanonical {
		return nil
	}
	if !strictlySortedUnique32(v.Whitelist) {
		return txerr(TX_ERR_VAULT_WHITELIST_NOT_CANONICAL, "CORE_VAULT whitelist not strictly sorted")
	}
	if HashInSorted32(v.Whitelist, v.OwnerLockID) {
		return txerr(TX_ERR_VAULT_OWNER_DESTINATION_FORBIDDEN, "CORE_VAULT whitelist contains owner_lock_id")
	}
	return nil
}

func ParseMultisigCovenantData(covData []byte) (*MultisigCovenant, error) {
	m, err := parseMultisigHeader(covData)
	if err != nil {
		return nil, err
	}

	m.Keys = copyFixed32List(covData, 2, int(m.KeyCount))
	if !strictlySortedUnique32(m.Keys) {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_MULTISIG keys not strictly sorted")
	}
	return m, nil
}

func parseMultisigHeader(covData []byte) (*MultisigCovenant, error) {
	if len(covData) < 34 {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_MULTISIG covenant_data too short")
	}

	var m MultisigCovenant
	m.Threshold = covData[0]
	m.KeyCount = covData[1]
	if m.KeyCount < 1 || m.KeyCount > MAX_MULTISIG_KEYS {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_MULTISIG key_count out of range")
	}
	if m.Threshold < 1 || m.Threshold > m.KeyCount {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_MULTISIG threshold out of range")
	}
	expectedLen := 2 + int(m.KeyCount)*32
	if len(covData) != expectedLen {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_MULTISIG covenant_data length mismatch")
	}
	return &m, nil
}

func copyFixed32List(data []byte, offset int, count int) [][32]byte {
	items := make([][32]byte, count)
	for i := 0; i < count; i++ {
		copy(items[i][:], data[offset:offset+32])
		offset += 32
	}
	return items
}

// OutputDescriptorBytes returns canonical output serialization used for CORE_VAULT whitelist hashing.
func OutputDescriptorBytes(covenantType uint16, covenantData []byte) []byte {
	out := make([]byte, 0, 2+9+len(covenantData))
	out = AppendU16le(out, covenantType)
	out = AppendCompactSize(out, uint64(len(covenantData)))
	out = append(out, covenantData...)
	return out
}

// WitnessSlots returns the number of WitnessItems consumed by an input spending this covenant.
// Returns an error for unsupported/unknown covenant types (parity with Rust witness_slots).
func WitnessSlots(covenantType uint16, covenantData []byte) (int, error) {
	switch covenantType {
	case COV_TYPE_P2PK:
		return 1, nil
	case COV_TYPE_MULTISIG:
		return multisigWitnessSlots(covenantData), nil
	case COV_TYPE_VAULT:
		return vaultWitnessSlots(covenantData), nil
	case COV_TYPE_HTLC:
		return 2, nil
	case COV_TYPE_CORE_STEALTH:
		return CORE_STEALTH_WITNESS_SLOTS, nil
	case COV_TYPE_CORE_SIMPLICITY:
		return SIMPLICITY_WITNESS_SLOTS, nil
	default:
		return 0, txerr(TX_ERR_COVENANT_TYPE_INVALID, "unsupported covenant in witness_slots")
	}
}

func multisigWitnessSlots(covenantData []byte) int {
	if len(covenantData) >= 2 {
		return int(covenantData[1])
	}
	return 1
}

func vaultWitnessSlots(covenantData []byte) int {
	// CORE_VAULT: owner_lock_id[32] || threshold[1] || key_count[1] || ...
	if len(covenantData) >= 34 {
		return int(covenantData[33])
	}
	return 1
}

func HashInSorted32(list [][32]byte, target [32]byte) bool {
	i := sort.Search(len(list), func(i int) bool {
		return bytes.Compare(list[i][:], target[:]) >= 0
	})
	return i < len(list) && list[i] == target
}

func strictlySortedUnique32(xs [][32]byte) bool {
	for i := 1; i < len(xs); i++ {
		if bytes.Compare(xs[i-1][:], xs[i][:]) >= 0 {
			return false
		}
	}
	return true
}
