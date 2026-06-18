package consensus

import (
	"errors"
	"testing"
)

var coreSimplicityAcceptCMR = [32]byte{0xc4, 0x0a, 0x10, 0x26, 0x3f, 0x74, 0x36, 0xb4, 0x16, 0x0a, 0xcb, 0xef, 0x1c, 0x36, 0xfb, 0xa4, 0xbe, 0x4d, 0x95, 0xdf, 0x18, 0x1a, 0x96, 0x8a, 0xfe, 0xab, 0x5e, 0xac, 0x24, 0x7a, 0xdf, 0xf7}

func coreSimplicityAcceptEntry(value uint64) UtxoEntry {
	return UtxoEntry{Value: value, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: encodeSimplicityCovenantData(coreSimplicityAcceptCMR, nil)}
}

func coreSimplicityAcceptWitness() WitnessItem {
	return WitnessItem{SuiteID: SUITE_ID_SIMPLICITY_ENVELOPE, Signature: simplicityEnvelopeSignature([]byte{0x24}, nil, SIGHASH_ALL)}
}

func TestValidateCoreSimplicitySpendErrors(t *testing.T) {
	baseEntry := coreSimplicityAcceptEntry(1)
	baseWitness := coreSimplicityAcceptWitness()
	validTxContext := func() (*SimplicityTxContext, error) { return &SimplicityTxContext{}, nil }
	for _, tc := range []struct {
		name string
		edit func(*UtxoEntry, *WitnessItem)
		code ErrorCode
	}{
		{"wrong_suite", func(_ *UtxoEntry, w *WitnessItem) { *w = WitnessItem{SuiteID: SUITE_ID_SENTINEL} }, TX_ERR_SIG_ALG_INVALID},
		{"nonzero_pubkey", func(_ *UtxoEntry, w *WitnessItem) { w.Pubkey = []byte{0x01} }, TX_ERR_PARSE},
		{"envelope_parse", func(_ *UtxoEntry, w *WitnessItem) { w.Signature = []byte{SIGHASH_ALL} }, TX_ERR_PARSE},
		{"invalid_sighash", func(_ *UtxoEntry, w *WitnessItem) { w.Signature[len(w.Signature)-1] = 0x7f }, TX_ERR_SIGHASH_TYPE_INVALID},
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
			entry := baseEntry
			witness := WitnessItem{
				SuiteID:   baseWitness.SuiteID,
				Pubkey:    append([]byte(nil), baseWitness.Pubkey...),
				Signature: append([]byte(nil), baseWitness.Signature...),
			}
			tc.edit(&entry, &witness)
			assertTxErrCode(t, validateCoreSimplicitySpend(entry, witness, validTxContext), tc.code)
		})
	}
}

func TestValidateCoreSimplicitySpendRequiresTxContext(t *testing.T) {
	entry := coreSimplicityAcceptEntry(1)
	witness := coreSimplicityAcceptWitness()

	assertTxErrCode(t, validateCoreSimplicitySpend(entry, witness, nil), TX_ERR_PARSE)
	assertTxErrCode(t, validateCoreSimplicitySpend(entry, witness, func() (*SimplicityTxContext, error) {
		return nil, nil
	}), TX_ERR_PARSE)
	assertTxErrCode(t, validateCoreSimplicitySpend(entry, witness, func() (*SimplicityTxContext, error) {
		return nil, txerr(TX_ERR_PARSE, "txcontext fixture error")
	}), TX_ERR_PARSE)
}

func TestSimplicityEvalErrorPreservesGenericErrors(t *testing.T) {
	errSentinel := errors.New("sentinel")
	if err := simplicityEvalError(errSentinel); !errors.Is(err, errSentinel) {
		t.Fatalf("simplicityEvalError() = %v, want sentinel", err)
	}
}

func TestSimplicityEvalErrorUsesCodeOnlyMessage(t *testing.T) {
	entry := coreSimplicityAcceptEntry(1)
	witness := coreSimplicityAcceptWitness()
	witness.Signature = simplicityEnvelopeSignature([]byte{0x25}, nil, SIGHASH_ALL)

	err := validateCoreSimplicitySpend(entry, witness, func() (*SimplicityTxContext, error) {
		return &SimplicityTxContext{}, nil
	})
	assertTxErrCodeMsg(t, err, TX_ERR_SIMPLICITY_DECODE, "")
	if err.Error() != string(TX_ERR_SIMPLICITY_DECODE) {
		t.Fatalf("Error()=%q, want %q", err.Error(), TX_ERR_SIMPLICITY_DECODE)
	}
}

func TestParseSimplicityEnvelopeSignatureRejectsMalformed(t *testing.T) {
	for _, sig := range [][]byte{{0x01, 0xff}, {0x01, 0x01, SIGHASH_ALL}, {0x01, 0x00, SIGHASH_ALL}, {0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, SIGHASH_ALL}} {
		if _, err := parseSimplicityEnvelopeSignature(sig); err == nil {
			t.Fatalf("parseSimplicityEnvelopeSignature(%x) succeeded", sig)
		}
	}
}
