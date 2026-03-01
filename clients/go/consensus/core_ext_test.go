package consensus

import "testing"

type staticCoreExtProfiles map[uint16]CoreExtProfile

func (m staticCoreExtProfiles) LookupCoreExtProfile(extID uint16, _ uint64) (CoreExtProfile, bool, error) {
	p, ok := m[extID]
	return p, ok, nil
}

func coreExtCovenantData(extID uint16, payload []byte) []byte {
	out := AppendU16le(nil, extID)
	out = AppendCompactSize(out, uint64(len(payload)))
	out = append(out, payload...)
	return out
}

func TestParseTx_UnknownSuiteAcceptedAndCharged(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xaa

	sentinelTxBytes := txWithOneInputOneOutputWithWitness(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData(), []WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL},
	})
	sentinelTx, _, _, _, err := ParseTx(sentinelTxBytes)
	if err != nil {
		t.Fatalf("ParseTx(sentinel): %v", err)
	}
	wSentinel, _, _, err := TxWeightAndStats(sentinelTx)
	if err != nil {
		t.Fatalf("TxWeightAndStats(sentinel): %v", err)
	}

	unknownTxBytes := txWithOneInputOneOutputWithWitness(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData(), []WitnessItem{
		{SuiteID: 0x09},
	})
	unknownTx, _, _, _, err := ParseTx(unknownTxBytes)
	if err != nil {
		t.Fatalf("ParseTx(unknown): %v", err)
	}
	if got := len(unknownTx.Witness); got != 1 || unknownTx.Witness[0].SuiteID != 0x09 {
		t.Fatalf("witness=%v, want suite_id=0x09", unknownTx.Witness)
	}
	wUnknown, _, _, err := TxWeightAndStats(unknownTx)
	if err != nil {
		t.Fatalf("TxWeightAndStats(unknown): %v", err)
	}
	if wUnknown != wSentinel+VERIFY_COST_UNKNOWN_SUITE {
		t.Fatalf("weight_unknown=%d, want %d", wUnknown, wSentinel+VERIFY_COST_UNKNOWN_SUITE)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_PreActiveKeylessSentinelOnly(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa1

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(1, nil),
		},
	}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 0, 0, chainID); err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicUpdate: %v", err)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_PreActiveRejectsNonKeylessSentinel(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa2

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_SENTINEL, Pubkey: make([]byte, 32), Signature: []byte{0x01}}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(1, nil),
		},
	}
	_, _, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 0, 0, chainID)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_DeterministicCovenantDataParseFirst(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa3

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_SENTINEL, Pubkey: make([]byte, 32), Signature: []byte{0x01}}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: []byte{0x01}, // malformed, must map to TX_ERR_COVENANT_TYPE_INVALID before witness checks
		},
	}
	_, _, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 0, 0, chainID)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_ActiveSuiteRulesAndVerifySig(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa4

	kp := mustMLDSA87Keypair(t)

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, []byte{0x01}),
		},
	}

	profiles := staticCoreExtProfiles{
		7: {
			Active: true,
			AllowedSuites: map[uint8]struct{}{
				SUITE_ID_SENTINEL:  {},
				SUITE_ID_ML_DSA_87: {},
			},
		},
	}

	// Sentinel is explicitly forbidden under ACTIVE.
	_, _, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(tx, txid, utxos, 0, 0, 0, chainID, profiles)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}

	// Valid ML-DSA signature succeeds under ACTIVE.
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, chainID, kp)}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(tx, txid, utxos, 0, 0, 0, chainID, profiles); err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(valid sig): %v", err)
	}

	// Same-length mutated signature must deterministically reject as TX_ERR_SIG_INVALID.
	bad := tx.Witness[0]
	bad.Signature = append([]byte(nil), bad.Signature...)
	bad.Signature[len(bad.Signature)-1] ^= 0x01
	tx.Witness = []WitnessItem{bad}
	_, _, err = ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(tx, txid, utxos, 0, 0, 0, chainID, profiles)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}
