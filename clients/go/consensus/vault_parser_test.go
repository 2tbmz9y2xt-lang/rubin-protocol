package consensus

import "testing"

func TestParseVaultCovenantDataRejectsNilAndShapeErrors(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		_, err := ParseVaultCovenantData(nil)
		if err == nil {
			t.Fatal("expected nil covenant_data to fail")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_MALFORMED {
			t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_MALFORMED)
		}
	})

	t.Run("truncated_keys", func(t *testing.T) {
		var ownerLockID [32]byte
		keys := makeKeys(1, 0x11)
		covData := append(ownerLockID[:], 0x01, 0x01)
		covData = append(covData, keys[0][:16]...)

		_, err := ParseVaultCovenantData(covData)
		if err == nil {
			t.Fatal("expected truncated keys to fail")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_MALFORMED {
			t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_MALFORMED)
		}
	})

	t.Run("missing_whitelist_count", func(t *testing.T) {
		var ownerLockID [32]byte
		keys := makeKeys(1, 0x21)
		covData := append(ownerLockID[:], 0x01, 0x01)
		covData = append(covData, keys[0][:]...)

		_, err := ParseVaultCovenantData(covData)
		if err == nil {
			t.Fatal("expected missing whitelist_count to fail")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_MALFORMED {
			t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_MALFORMED)
		}
	})

	t.Run("key_count_out_of_range", func(t *testing.T) {
		covData := make([]byte, 34)
		covData[32] = 1
		covData[33] = 0

		_, err := ParseVaultCovenantData(covData)
		if err == nil {
			t.Fatal("expected out-of-range key_count to fail")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_PARAMS_INVALID {
			t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_PARAMS_INVALID)
		}
	})

	t.Run("length_mismatch_after_whitelist_count", func(t *testing.T) {
		var ownerLockID [32]byte
		keys := makeKeys(1, 0x21)
		whitelist := makeKeys(1, 0x41)
		covData := encodeVaultCovenantData(ownerLockID, 1, keys, whitelist)
		covData = append(covData, 0x99)

		_, err := ParseVaultCovenantData(covData)
		if err == nil {
			t.Fatal("expected covenant_data length mismatch to fail")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_MALFORMED {
			t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_MALFORMED)
		}
	})
}

func TestParseVaultCovenantDataForSpendAllowsNonCanonicalWhitelist(t *testing.T) {
	keys := makeKeys(1, 0x31)
	ownerLockID := makeKeys(1, 0x51)[0]
	otherWhitelist := makeKeys(1, 0x61)[0]
	whitelist := [][32]byte{otherWhitelist, ownerLockID}
	covData := encodeVaultCovenantData(ownerLockID, 1, keys, whitelist)

	v, err := ParseVaultCovenantDataForSpend(covData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.WhitelistCount != uint16(len(whitelist)) {
		t.Fatalf("whitelist_count=%d, want %d", v.WhitelistCount, len(whitelist))
	}
	if len(v.Whitelist) != len(whitelist) {
		t.Fatalf("len(whitelist)=%d, want %d", len(v.Whitelist), len(whitelist))
	}
	if v.Whitelist[0] != whitelist[0] || v.Whitelist[1] != whitelist[1] {
		t.Fatal("spend-mode parser must preserve non-canonical whitelist entries")
	}

	_, err = ParseVaultCovenantData(covData)
	if err == nil {
		t.Fatal("expected creation-mode parser to reject non-canonical whitelist")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_WHITELIST_NOT_CANONICAL {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_WHITELIST_NOT_CANONICAL)
	}
}

func TestParseVaultCovenantDataRejectsOwnerDestinationInCanonicalWhitelist(t *testing.T) {
	keys := makeKeys(1, 0x71)
	ownerLockID := makeKeys(1, 0x11)[0]
	otherWhitelist := makeKeys(1, 0x21)[0]
	covData := encodeVaultCovenantData(ownerLockID, 1, keys, [][32]byte{ownerLockID, otherWhitelist})

	_, err := ParseVaultCovenantData(covData)
	if err == nil {
		t.Fatal("expected owner_lock_id in canonical whitelist to fail")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_OWNER_DESTINATION_FORBIDDEN {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_OWNER_DESTINATION_FORBIDDEN)
	}

	if _, err := ParseVaultCovenantDataForSpend(covData); err != nil {
		t.Fatalf("spend-mode parser must allow owner_lock_id in whitelist: %v", err)
	}
}

func TestParseMultisigCovenantDataRejectsMalformedInputs(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		_, err := ParseMultisigCovenantData(nil)
		if err == nil {
			t.Fatal("expected nil multisig covenant_data to fail")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
			t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
		}
	})

	t.Run("length_mismatch", func(t *testing.T) {
		keys := makeKeys(1, 0x41)
		covData := encodeMultisigCovenantData(1, keys)
		covData = append(covData, 0x99)

		_, err := ParseMultisigCovenantData(covData)
		if err == nil {
			t.Fatal("expected multisig length mismatch to fail")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
			t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
		}
	})

	t.Run("key_count_out_of_range", func(t *testing.T) {
		covData := make([]byte, 34)
		covData[0] = 1
		covData[1] = 0

		_, err := ParseMultisigCovenantData(covData)
		if err == nil {
			t.Fatal("expected out-of-range multisig key_count to fail")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
			t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
		}
	})
}
