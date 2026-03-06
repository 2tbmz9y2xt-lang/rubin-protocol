package consensus

import (
	"math/big"
	"testing"
)

func TestCoverage_ParseCoreExtCovenantData(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		if _, err := ParseCoreExtCovenantData([]byte{0x01}); err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("payload overflow int", func(t *testing.T) {
		tooBig := []byte{0x01, 0x00, 0xff}
		for i := 0; i < 7; i++ {
			tooBig = append(tooBig, 0xff)
		}
		if _, err := ParseCoreExtCovenantData(tooBig); err == nil {
			t.Fatalf("expected overflow error")
		}
	})

	t.Run("payload parse failure", func(t *testing.T) {
		if _, err := ParseCoreExtCovenantData([]byte{0x34, 0x12, 0x04, 0xaa}); err == nil {
			t.Fatalf("expected payload parse failure")
		}
	})

	t.Run("length mismatch", func(t *testing.T) {
		if _, err := ParseCoreExtCovenantData([]byte{0x34, 0x12, 0x01, 0xaa, 0xbb}); err == nil {
			t.Fatalf("expected length mismatch")
		}
	})

	t.Run("success", func(t *testing.T) {
		got, err := ParseCoreExtCovenantData([]byte{0x34, 0x12, 0x02, 0xaa, 0xbb})
		if err != nil {
			t.Fatalf("ParseCoreExtCovenantData: %v", err)
		}
		if got.ExtID != 0x1234 {
			t.Fatalf("ext_id=%x", got.ExtID)
		}
		if len(got.ExtPayload) != 2 || got.ExtPayload[0] != 0xaa || got.ExtPayload[1] != 0xbb {
			t.Fatalf("unexpected payload=%x", got.ExtPayload)
		}
	})
}

func TestCoverage_HasSuiteAndBigIntToUint64(t *testing.T) {
	if hasSuite(nil, SUITE_ID_ML_DSA_87) {
		t.Fatalf("nil allowed set must reject")
	}
	if hasSuite(map[uint8]struct{}{}, SUITE_ID_ML_DSA_87) {
		t.Fatalf("empty allowed set must reject")
	}
	if !hasSuite(map[uint8]struct{}{SUITE_ID_ML_DSA_87: {}}, SUITE_ID_ML_DSA_87) {
		t.Fatalf("expected suite present")
	}

	if got, err := bigIntToUint64(nil); err != nil || got != 0 {
		t.Fatalf("bigIntToUint64(nil)=%d,%v want 0,nil", got, err)
	}
	if _, err := bigIntToUint64(big.NewInt(-1)); err == nil {
		t.Fatalf("expected negative big.Int rejection")
	}
	if _, err := bigIntToUint64(new(big.Int).Lsh(big.NewInt(1), 65)); err == nil {
		t.Fatalf("expected overflow rejection")
	}
}

func TestCoverage_ConnectBlockBasicInMemoryAtHeightGuards(t *testing.T) {
	var target = POW_LIMIT
	if _, err := ConnectBlockBasicInMemoryAtHeight(nil, nil, &target, 0, nil, nil, [32]byte{}); err == nil {
		t.Fatalf("expected nil state rejection")
	}

	state := &InMemoryChainState{AlreadyGenerated: big.NewInt(-1)}
	if _, err := ConnectBlockBasicInMemoryAtHeight(nil, nil, &target, 0, nil, state, [32]byte{}); err == nil {
		t.Fatalf("expected unsigned already_generated guard")
	}
}

func TestCoverage_SighashBranches(t *testing.T) {
	if _, err := SighashV1DigestWithType(nil, 0, 0, [32]byte{}, SIGHASH_ALL); err == nil {
		t.Fatalf("expected nil tx rejection")
	}

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 7,
		Inputs: []TxInput{{
			PrevTxid: [32]byte{0x11},
			PrevVout: 2,
			Sequence: 3,
		}},
		Outputs: []TxOutput{{
			Value:        9,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: []byte{0x01},
		}},
	}

	if _, err := SighashV1DigestWithType(tx, 1, 9, [32]byte{}, SIGHASH_ALL); err == nil {
		t.Fatalf("expected input index rejection")
	}
	if _, err := SighashV1DigestWithType(tx, 0, 9, [32]byte{}, 0x7f); err == nil {
		t.Fatalf("expected invalid sighash type rejection")
	}
	if _, err := SighashV1DigestWithType(tx, 0, 9, [32]byte{}, SIGHASH_SINGLE|SIGHASH_ANYONECANPAY); err != nil {
		t.Fatalf("SighashV1DigestWithType(anyonecanpay): %v", err)
	}
	tx.Outputs = nil
	if _, err := SighashV1DigestWithType(tx, 0, 9, [32]byte{}, SIGHASH_SINGLE); err != nil {
		t.Fatalf("SighashV1DigestWithType(single no output): %v", err)
	}
}

func TestCoverage_SpendVerifyBranches(t *testing.T) {
	if _, _, err := extractCryptoSigAndSighash(WitnessItem{}); err == nil {
		t.Fatalf("expected empty signature rejection")
	}
	if _, _, err := extractCryptoSigAndSighash(WitnessItem{Signature: []byte{0x7f}}); err == nil {
		t.Fatalf("expected invalid sighash rejection")
	}

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: [32]byte{0x44}, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: make([]byte, 33)}},
	}

	keys := [][32]byte{{0x01}, {0x02}}
	ws := []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}
	if err := validateThresholdSigSpend(keys, 1, ws, tx, 0, 1, [32]byte{}, 0, "ctx"); err == nil {
		t.Fatalf("expected witness slot mismatch")
	}

	ws = []WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL, Pubkey: []byte{0x01}},
		{SuiteID: SUITE_ID_SENTINEL},
	}
	if err := validateThresholdSigSpend(keys, 1, ws, tx, 0, 1, [32]byte{}, 0, "ctx"); err == nil {
		t.Fatalf("expected sentinel keyless guard")
	}

	ws = []WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL},
		{SuiteID: 0x99},
	}
	if err := validateThresholdSigSpend(keys, 1, ws, tx, 0, 1, [32]byte{}, 0, "ctx"); err == nil {
		t.Fatalf("expected unknown suite rejection")
	}
}

func TestCoverage_StealthBranches(t *testing.T) {
	if _, err := ParseStealthCovenantData(nil); err == nil {
		t.Fatalf("expected nil covenant_data rejection")
	}
	if _, err := ParseStealthCovenantData(make([]byte, MAX_STEALTH_COVENANT_DATA-1)); err == nil {
		t.Fatalf("expected length mismatch")
	}

	entry := UtxoEntry{
		Value:        1,
		CovenantType: COV_TYPE_CORE_STEALTH,
		CovenantData: make([]byte, MAX_STEALTH_COVENANT_DATA),
	}
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: [32]byte{0x55}, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: make([]byte, 33)}},
	}

	w := WitnessItem{SuiteID: 0x99}
	if err := validateCoreStealthSpend(entry, w, tx, 0, 1, [32]byte{}, 0); err == nil {
		t.Fatalf("expected suite invalid")
	}

	w = WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    make([]byte, ML_DSA_87_PUBKEY_BYTES),
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}
	if err := validateCoreStealthSpend(entry, w, tx, 0, 1, [32]byte{}, 0); err == nil {
		t.Fatalf("expected key binding mismatch")
	}

	w = WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    make([]byte, 1),
		Signature: make([]byte, 1),
	}
	if err := validateCoreStealthSpend(entry, w, tx, 0, 1, [32]byte{}, 0); err == nil {
		t.Fatalf("expected noncanonical witness rejection")
	}
}
