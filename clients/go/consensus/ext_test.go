package consensus

import "testing"

func encodeCoreExtCovenantData(extID uint16, payload []byte) []byte {
	out := make([]byte, 0, 2+9+len(payload))
	out = AppendU16le(out, extID)
	out = AppendCompactSize(out, uint64(len(payload)))
	out = append(out, payload...)
	return out
}

func TestParseCoreExtCovenantData_ValidAndMalformed(t *testing.T) {
	valid := encodeCoreExtCovenantData(0x0101, []byte{0xaa, 0xbb, 0xcc})
	ext, err := ParseCoreExtCovenantData(valid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ext.ExtID != 0x0101 {
		t.Fatalf("ext_id=%d, want %d", ext.ExtID, 0x0101)
	}
	if got := len(ext.ExtPayload); got != 3 {
		t.Fatalf("payload_len=%d, want 3", got)
	}

	malformed := append([]byte{}, valid...)
	malformed = malformed[:len(malformed)-1]
	if err := checkSpendCovenant(COV_TYPE_EXT, malformed); err == nil {
		t.Fatal("expected malformed CORE_EXT covenant_data to be rejected")
	}
}

func TestWitnessSlots_CORE_EXT(t *testing.T) {
	got, err := WitnessSlots(COV_TYPE_EXT, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != CORE_EXT_WITNESS_SLOTS {
		t.Fatalf("slots=%d, want %d", got, CORE_EXT_WITNESS_SLOTS)
	}
}

func TestValidateTxCovenantsGenesis_CORE_EXT(t *testing.T) {
	tx := &Tx{
		TxKind: 0x00,
		Outputs: []TxOutput{
			{
				Value:        1,
				CovenantType: COV_TYPE_EXT,
				CovenantData: encodeCoreExtCovenantData(0x0011, []byte{0x01}),
			},
		},
	}
	if err := ValidateTxCovenantsGenesis(tx, 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tx.Outputs[0].Value = 0
	err := ValidateTxCovenantsGenesis(tx, 0)
	if err == nil {
		t.Fatal("expected CORE_EXT value=0 reject")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_PreActivationSentinelRule(t *testing.T) {
	var chainID [32]byte
	var prevTxid [32]byte
	var txid [32]byte
	prevTxid[0] = 0x42
	txid[0] = 0x43

	destKP := mustMLDSA87Keypair(t)
	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
	extCovData := encodeCoreExtCovenantData(0x0077, []byte{0x10, 0x20})

	baseTx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{
				PrevTxid: prevTxid,
				PrevVout: 0,
			},
		},
		Outputs: []TxOutput{
			{
				Value:        90,
				CovenantType: COV_TYPE_P2PK,
				CovenantData: destCovData,
			},
		},
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_EXT,
			CovenantData: extCovData,
		},
	}

	sentinelTx := *baseTx
	sentinelTx.Witness = []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}
	s, err := ApplyNonCoinbaseTxBasic(&sentinelTx, txid, utxos, 100, 1000, chainID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Fee != 10 {
		t.Fatalf("fee=%d, want 10", s.Fee)
	}

	nonSentinelTx := *baseTx
	nonSentinelTx.Witness = []WitnessItem{{SuiteID: SUITE_ID_ML_DSA_87}}
	_, err = ApplyNonCoinbaseTxBasic(&nonSentinelTx, txid, utxos, 100, 1000, chainID)
	if err == nil {
		t.Fatal("expected non-sentinel pre-activation reject")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_ProfileActivationEnforced(t *testing.T) {
	var chainID [32]byte
	var prevTxid [32]byte
	var txid [32]byte
	prevTxid[0] = 0x51
	txid[0] = 0x52

	destKP := mustMLDSA87Keypair(t)
	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
	extCovData := encodeCoreExtCovenantData(0x0077, []byte{0xaa})

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevTxid, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{
				Value:        90,
				CovenantType: COV_TYPE_P2PK,
				CovenantData: destCovData,
			},
		},
		Witness: []WitnessItem{
			{SuiteID: 0x03, Pubkey: []byte{}, Signature: []byte{}},
		},
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_EXT,
			CovenantData: extCovData,
		},
	}

	profiles := []CoreExtProfile{
		{
			ExtID:            0x0077,
			ActivationHeight: 1_000,
			AllowedSuiteIDs:  []uint8{SUITE_ID_ML_DSA_87},
		},
	}
	_, _, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndProfiles(tx, txid, utxos, 1_000, 1000, 1000, chainID, profiles)
	if err == nil {
		t.Fatal("expected disallowed suite reject under active profile")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
}
