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
