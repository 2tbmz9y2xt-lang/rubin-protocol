package consensus

import (
	"errors"
	"math/big"
	"testing"
)

func TestCoverage_HasSuiteAndBigIntToUint64(t *testing.T) {
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
	env := testSpendSigEnv{tx: tx, inputValue: 1, context: "ctx"}
	ws := []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}
	if err := validateThresholdSigSpend(testThresholdSigSpendCheck(keys, 1, ws, env)); err == nil {
		t.Fatalf("expected witness slot mismatch")
	}

	ws = []WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL, Pubkey: []byte{0x01}},
		{SuiteID: SUITE_ID_SENTINEL},
	}
	if err := validateThresholdSigSpend(testThresholdSigSpendCheck(keys, 1, ws, env)); err == nil {
		t.Fatalf("expected sentinel keyless guard")
	}

	ws = []WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL},
		{SuiteID: 0x99},
	}
	if err := validateThresholdSigSpend(testThresholdSigSpendCheck(keys, 1, ws, env)); err == nil {
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

func TestCoverage_NilCovenantDataUsesGenericMalformedContext(t *testing.T) {
	cases := []struct {
		name    string
		parse   func([]byte) error
		code    ErrorCode
		message string
	}{
		{
			name: "htlc",
			parse: func(covData []byte) error {
				_, err := ParseHTLCCovenantData(covData)
				return err
			},
			code:    TX_ERR_COVENANT_TYPE_INVALID,
			message: "CORE_HTLC covenant_data length mismatch",
		},
		{
			name: "vault",
			parse: func(covData []byte) error {
				_, err := ParseVaultCovenantData(covData)
				return err
			},
			code:    TX_ERR_VAULT_MALFORMED,
			message: "CORE_VAULT covenant_data too short",
		},
		{
			name: "stealth",
			parse: func(covData []byte) error {
				_, err := ParseStealthCovenantData(covData)
				return err
			},
			code:    TX_ERR_COVENANT_TYPE_INVALID,
			message: "CORE_STEALTH covenant_data length mismatch",
		},
		{
			name: "multisig",
			parse: func(covData []byte) error {
				_, err := ParseMultisigCovenantData(covData)
				return err
			},
			code:    TX_ERR_COVENANT_TYPE_INVALID,
			message: "CORE_MULTISIG covenant_data too short",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/nil", func(t *testing.T) {
			assertTxErrCodeMsg(t, tc.parse(nil), tc.code, tc.message)
		})
		t.Run(tc.name+"/empty", func(t *testing.T) {
			assertTxErrCodeMsg(t, tc.parse([]byte{}), tc.code, tc.message)
		})
	}
}

func TestCoverage_CoreExtRetirementAndValueContextBranches(t *testing.T) {
	entry := wcCoreExtEntry(1, 1)
	good := nonCoinbaseResolvedInput{entry: entry, witness: []WitnessItem{{}}}
	if err := (&nonCoinbaseApplyContext{}).validateInputSpend(0, good); err != nil {
		t.Fatalf("validateInputSpend(CORE_EXT): %v", err)
	}
	bad := good
	bad.witness = nil
	assertTxErrCodeMsg(t, (&nonCoinbaseApplyContext{}).validateInputSpend(0, bad), TX_ERR_PARSE, "CORE_EXT witness_slots must be 1")
	check := txInputSpendCheck{entry: entry, assigned: []WitnessItem{{}}}
	if err := validateInputSpendQ(check, txValidationWorkerEnv{}); err != nil {
		t.Fatalf("validateInputSpendQ(CORE_EXT): %v", err)
	}
	check.assigned = nil
	assertTxErrCodeMsg(t, validateInputSpendQ(check, txValidationWorkerEnv{}), TX_ERR_PARSE, "CORE_EXT witness_slots must be 1")
	check.assigned = []WitnessItem{{}}
	check.entry.CovenantData = []byte{0x01}
	assertTxErrCodeMsg(t, validateInputSpendQ(check, txValidationWorkerEnv{}), TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT covenant_data too short")
	if got := CheckValueConservationTxWide(nil, false, Uint128{}); got == nil || got.Code != TX_ERR_PARSE {
		t.Fatalf("nil txcontext base code=%v, want %s", got, TX_ERR_PARSE)
	}
	max := u128{lo: ^uint64(0), hi: ^uint64(0)}
	if _, err := sumTxContextInputValues([]UtxoEntry{{Value: 1}}, max); err == nil {
		t.Fatalf("expected input total overflow")
	}
	if _, err := sumTxContextOutputValues([]TxOutput{{Value: 1}}, max); err == nil {
		t.Fatalf("expected output total overflow")
	}
}

func assertTxErrCodeMsg(t *testing.T, err error, code ErrorCode, message string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error")
	}
	var te *TxError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TxError, got %T: %v", err, err)
	}
	if te.Code != code {
		t.Fatalf("code=%s, want %s", te.Code, code)
	}
	if te.Msg != message {
		t.Fatalf("msg=%q, want %q", te.Msg, message)
	}
}
