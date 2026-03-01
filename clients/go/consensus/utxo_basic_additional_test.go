package consensus

import "testing"

func TestU128Helpers_SubUnderflowAndToU64Overflow(t *testing.T) {
	// subU128 underflow
	_, err := subU128(u128{hi: 0, lo: 0}, u128{hi: 0, lo: 1})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}

	// u128ToU64 overflow
	_, err = u128ToU64(u128{hi: 1, lo: 0})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestCheckSpendCovenant_SupportedTypes(t *testing.T) {
	if err := checkSpendCovenant(COV_TYPE_P2PK, nil); err != nil {
		t.Fatalf("CORE_P2PK: %v", err)
	}

	if err := checkSpendCovenant(COV_TYPE_VAULT, validVaultCovenantDataForP2PKOutput()); err != nil {
		t.Fatalf("CORE_VAULT: %v", err)
	}

	msKeyID := filled32(0x33)
	if err := checkSpendCovenant(COV_TYPE_MULTISIG, encodeMultisigCovenantData(1, [][32]byte{msKeyID})); err != nil {
		t.Fatalf("CORE_MULTISIG: %v", err)
	}

	claimKeyID := filled32(0x44)
	refundKeyID := filled32(0x45)
	htlcData := encodeHTLCCovenantData(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)
	if err := checkSpendCovenant(COV_TYPE_HTLC, htlcData); err != nil {
		t.Fatalf("CORE_HTLC: %v", err)
	}

	coreExtData := AppendU16le(nil, 1)
	coreExtData = AppendCompactSize(coreExtData, 0)
	if err := checkSpendCovenant(COV_TYPE_CORE_EXT, coreExtData); err != nil {
		t.Fatalf("CORE_EXT: %v", err)
	}
}

func TestCheckSpendCovenant_Errors(t *testing.T) {
	if err := checkSpendCovenant(COV_TYPE_VAULT, nil); err == nil {
		t.Fatalf("expected error for invalid CORE_VAULT covenant_data")
	}
	if err := checkSpendCovenant(COV_TYPE_MULTISIG, nil); err == nil {
		t.Fatalf("expected error for invalid CORE_MULTISIG covenant_data")
	}
	if err := checkSpendCovenant(COV_TYPE_HTLC, nil); err == nil {
		t.Fatalf("expected error for invalid CORE_HTLC covenant_data")
	}
	if err := checkSpendCovenant(COV_TYPE_CORE_EXT, nil); err == nil {
		t.Fatalf("expected error for invalid CORE_EXT covenant_data")
	}

	err := checkSpendCovenant(0x9999, []byte{0x01})
	if err == nil {
		t.Fatalf("expected error for unknown covenant type")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}
