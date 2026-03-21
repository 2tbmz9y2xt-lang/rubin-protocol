package main

import (
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func testTxctxProfile(extID uint16) TxctxProfileJSON {
	return TxctxProfileJSON{
		ExtID:              extID,
		ActivationHeight:   100,
		TxContextEnabled:   1,
		AllowedSuiteIDs:    []uint8{16},
		AllowedSighashSet:  1,
		MaxExtPayloadBytes: 48,
		BindingKind:        consensus.CoreExtBindingKindVerifySigExt,
		SuiteCount:         1,
		SuiteID:            16,
	}
}

func TestTxctxProfileErrorRejectsOversizedContinuingOutput(t *testing.T) {
	tc := &TxctxCaseJSON{
		Height:   200,
		Profiles: []TxctxProfileJSON{testTxctxProfile(0x0FFF)},
		Inputs: []TxctxInputJSON{{
			ExtID:       0x0FFF,
			SighashType: 1,
		}},
		Outputs: []TxctxOutputJSON{{
			CovenantType:  "CORE_EXT",
			ExtID:         0x0FFF,
			Value:         1,
			ExtPayloadHex: strings.Repeat("00", 52),
		}},
	}
	if got := txctxProfileError(tc); got != string(consensus.TX_ERR_COVENANT_TYPE_INVALID) {
		t.Fatalf("got %q want %q", got, consensus.TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestTxctxProfileErrorRejectsNonMinimalRawCompactSize(t *testing.T) {
	tc := &TxctxCaseJSON{
		Height:   200,
		Profiles: []TxctxProfileJSON{testTxctxProfile(0x0FFE)},
		Inputs: []TxctxInputJSON{{
			ExtID:            0x0FFE,
			SighashType:      1,
			RawExtPayloadHex: "ff08000000000000004142434445464748",
		}},
	}
	if got := txctxProfileError(tc); got != string(consensus.TX_ERR_COVENANT_TYPE_INVALID) {
		t.Fatalf("got %q want %q", got, consensus.TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestTxctxBuildHarnessArtifactsRejectsUnsupportedNonCoreExtOutputWithoutRawData(t *testing.T) {
	tc := &TxctxCaseJSON{
		Height: 200,
		Outputs: []TxctxOutputJSON{{
			CovenantType: "CORE_VAULT",
			Value:        1,
		}},
	}

	_, _, _, _, _, _, err := txctxBuildHarnessArtifacts(tc, &txctxDiagnosticsRecorder{})
	if err == nil || !strings.Contains(err.Error(), "unsupported harness covenant_type=") {
		t.Fatalf("expected unsupported covenant error, got %v", err)
	}
}

func TestRunTxctxSpendVectorScopesMissingContinuingToRequestedExtID(t *testing.T) {
	profile := testTxctxProfile(0x0FFE)
	tc := &TxctxCaseJSON{
		Height:   200,
		Profiles: []TxctxProfileJSON{profile},
		Inputs: []TxctxInputJSON{{
			CovenantType:   "CORE_EXT",
			ExtID:          0x0FFE,
			UtxoValue:      5,
			SelfInputValue: 5,
			SuiteID:        0x10,
			SighashType:    consensus.SIGHASH_ALL,
			PubkeyLength:   2592,
		}},
		Outputs: []TxctxOutputJSON{{
			CovenantType: "CORE_EXT",
			ExtID:        0x0FFE,
			Value:        5,
		}},
		ForceMissingCtxContinuingExt: 0x0FFF,
	}

	resp := runTxctxSpendVector(Request{TxctxCase: tc})
	if !resp.Ok {
		t.Fatalf("expected scoped missing-continuing injection to be ignored, got ok=%v err=%q", resp.Ok, resp.Err)
	}
}
