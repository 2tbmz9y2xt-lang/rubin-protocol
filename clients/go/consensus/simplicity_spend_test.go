package consensus

import "testing"

var coreSimplicityAcceptCMR = [32]byte{0xc4, 0x0a, 0x10, 0x26, 0x3f, 0x74, 0x36, 0xb4, 0x16, 0x0a, 0xcb, 0xef, 0x1c, 0x36, 0xfb, 0xa4, 0xbe, 0x4d, 0x95, 0xdf, 0x18, 0x1a, 0x96, 0x8a, 0xfe, 0xab, 0x5e, 0xac, 0x24, 0x7a, 0xdf, 0xf7}

func coreSimplicityAcceptEntry(value uint64) UtxoEntry {
	return UtxoEntry{Value: value, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: encodeSimplicityCovenantData(coreSimplicityAcceptCMR, nil)}
}

func coreSimplicityAcceptWitness() WitnessItem {
	return WitnessItem{SuiteID: SUITE_ID_SIMPLICITY_ENVELOPE, Signature: simplicityEnvelopeSignature([]byte{0x24}, nil, SIGHASH_ALL)}
}

func TestCoreSimplicitySpendDispatchSequentialQueueAndWorker(t *testing.T) {
	prev := hashWithPrefix(0x61)
	tx, txid := mustParseTxForUtxo(t, txWithOneInputOneOutputWithWitness(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData(), []WitnessItem{coreSimplicityAcceptWitness()}))
	utxos := map[Outpoint]UtxoEntry{{Txid: prev, Vout: 0}: coreSimplicityAcceptEntry(100)}

	_, summary, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 1, 0, [32]byte{})
	if err != nil || summary == nil || summary.Fee != 10 {
		t.Fatalf("sequential spend err=%v summary=%#v", err, summary)
	}

	q := NewSigCheckQueue(1)
	_, feeQ, err := applyNonCoinbaseTxBasicWorkQ(tx, txid, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
	if err != nil || feeQ != 10 || q.Len() != 0 {
		t.Fatalf("queued spend err=%v fee/sigs=%d/%d", err, feeQ, q.Len())
	}

	result := ValidateTxLocal(TxValidationContext{
		TxIndex:        1,
		Tx:             tx,
		ResolvedInputs: []UtxoEntry{coreSimplicityAcceptEntry(100)},
		WitnessStart:   0,
		WitnessEnd:     1,
		Fee:            10,
	}, [32]byte{}, 1, 0, nil, nil)
	if !result.Valid || result.Err != nil || result.SigCount != 0 {
		t.Fatalf("worker result = %#v", result)
	}
}

func TestCoreSimplicitySpendDispatchErrors(t *testing.T) {
	tx := &Tx{Version: TX_WIRE_VERSION, Inputs: []TxInput{{}}, Witness: []WitnessItem{coreSimplicityAcceptWitness()}}
	baseEntry := coreSimplicityAcceptEntry(1)
	baseWitness := coreSimplicityAcceptWitness()
	for _, tc := range []struct {
		name string
		edit func(*UtxoEntry, *WitnessItem)
		code ErrorCode
	}{
		{"wrong_suite", func(_ *UtxoEntry, w *WitnessItem) { *w = WitnessItem{SuiteID: SUITE_ID_SENTINEL} }, TX_ERR_SIG_ALG_INVALID},
		{"envelope_parse", func(_ *UtxoEntry, w *WitnessItem) { w.Signature = []byte{SIGHASH_ALL} }, TX_ERR_PARSE},
		{"covenant_parse", func(e *UtxoEntry, _ *WitnessItem) { e.CovenantData = nil }, TX_ERR_COVENANT_TYPE_INVALID},
		{"cmr_mismatch", func(e *UtxoEntry, _ *WitnessItem) {
			e.CovenantData = encodeSimplicityCovenantData([32]byte{0x99}, nil)
		}, TX_ERR_SIMPLICITY_CMR_MISMATCH},
		{"program_decode", func(_ *UtxoEntry, w *WitnessItem) {
			w.Signature = simplicityEnvelopeSignature([]byte{0x25}, nil, SIGHASH_ALL)
		}, TX_ERR_SIMPLICITY_DECODE},
		{"jet_disallowed", func(e *UtxoEntry, w *WitnessItem) {
			e.CovenantData = encodeSimplicityCovenantData([32]byte{0x39, 0x99, 0x88, 0x9b, 0xdf, 0x18, 0xd0, 0x7c, 0x6c, 0x38, 0xb7, 0xaa, 0xcb, 0x89, 0xf6, 0xc2, 0xbd, 0xd3, 0xc6, 0xa5, 0xc3, 0xc9, 0x3c, 0xe7, 0x9d, 0x19, 0x02, 0xa5, 0x67, 0xb1, 0xe6, 0x37}, nil)
			w.Signature = simplicityEnvelopeSignature([]byte{0x60}, nil, SIGHASH_ALL)
		}, TX_ERR_SIMPLICITY_JET_DISALLOWED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry, witness := baseEntry, baseWitness
			tc.edit(&entry, &witness)
			assertTxErrCode(t, validateCoreSimplicitySpend(entry, witness, tx, 1, [32]byte{}, []UtxoEntry{entry}), tc.code)
		})
	}
}

func TestParseSimplicityEnvelopeSignatureRejectsMalformed(t *testing.T) {
	for _, sig := range [][]byte{{0x01, 0xff}, {0x01, 0x01, SIGHASH_ALL}, {0x01, 0x00, SIGHASH_ALL}, {0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, SIGHASH_ALL}} {
		if _, err := parseSimplicityEnvelopeSignature(sig); err == nil {
			t.Fatalf("parseSimplicityEnvelopeSignature(%x) succeeded", sig)
		}
	}
}
