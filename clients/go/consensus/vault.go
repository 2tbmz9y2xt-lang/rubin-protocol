package consensus

import (
	"bytes"
	"encoding/binary"
	"sort"
)

type VaultCovenant struct {
	Threshold      uint8
	KeyCount       uint8
	Keys           [][32]byte
	WhitelistCount uint16
	Whitelist      [][32]byte
}

type MultisigCovenant struct {
	Threshold uint8
	KeyCount  uint8
	Keys      [][32]byte
}

func ParseVaultCovenantData(covData []byte) (*VaultCovenant, error) {
	if covData == nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "nil CORE_VAULT covenant_data")
	}
	if len(covData) < 68 {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_VAULT covenant_data too short")
	}

	var v VaultCovenant
	v.Threshold = covData[0]
	v.KeyCount = covData[1]
	if v.KeyCount < 1 || v.KeyCount > MAX_VAULT_KEYS {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_VAULT key_count out of range")
	}
	if v.Threshold < 1 || v.Threshold > v.KeyCount {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_VAULT threshold out of range")
	}

	offset := 2
	v.Keys = make([][32]byte, int(v.KeyCount))
	for i := 0; i < int(v.KeyCount); i++ {
		if offset+32 > len(covData) {
			return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_VAULT truncated keys")
		}
		copy(v.Keys[i][:], covData[offset:offset+32])
		offset += 32
	}
	if !strictlySortedUnique32(v.Keys) {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_VAULT keys not strictly sorted")
	}

	if offset+2 > len(covData) {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_VAULT missing whitelist_count")
	}
	v.WhitelistCount = binary.LittleEndian.Uint16(covData[offset : offset+2])
	offset += 2
	if v.WhitelistCount < 1 || v.WhitelistCount > MAX_VAULT_WHITELIST_ENTRIES {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_VAULT whitelist_count out of range")
	}

	expectedLen := 2 + int(v.KeyCount)*32 + 2 + int(v.WhitelistCount)*32
	if len(covData) != expectedLen {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_VAULT covenant_data length mismatch")
	}

	v.Whitelist = make([][32]byte, int(v.WhitelistCount))
	for i := 0; i < int(v.WhitelistCount); i++ {
		copy(v.Whitelist[i][:], covData[offset:offset+32])
		offset += 32
	}
	if !strictlySortedUnique32(v.Whitelist) {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_VAULT whitelist not strictly sorted")
	}
	return &v, nil
}

func ParseMultisigCovenantData(covData []byte) (*MultisigCovenant, error) {
	if covData == nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "nil CORE_MULTISIG covenant_data")
	}
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

	m.Keys = make([][32]byte, int(m.KeyCount))
	offset := 2
	for i := 0; i < int(m.KeyCount); i++ {
		copy(m.Keys[i][:], covData[offset:offset+32])
		offset += 32
	}
	if !strictlySortedUnique32(m.Keys) {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_MULTISIG keys not strictly sorted")
	}
	return &m, nil
}

// OutputDescriptorBytes returns canonical output serialization used for CORE_VAULT whitelist hashing.
func OutputDescriptorBytes(covenantType uint16, covenantData []byte) []byte {
	out := make([]byte, 0, 2+9+len(covenantData))
	out = appendU16le(out, covenantType)
	out = appendCompactSize(out, uint64(len(covenantData)))
	out = append(out, covenantData...)
	return out
}

// WitnessSlots returns the number of WitnessItems consumed by an input spending this covenant.
func WitnessSlots(covenantType uint16, covenantData []byte) int {
	switch covenantType {
	case COV_TYPE_VAULT, COV_TYPE_MULTISIG:
		if len(covenantData) >= 2 {
			return int(covenantData[1])
		}
		return 1
	case COV_TYPE_HTLC:
		return 2
	default:
		return 1
	}
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
