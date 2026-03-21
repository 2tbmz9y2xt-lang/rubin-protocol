package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func testTxctxGovernanceChecklist(extID uint16, maxExtPayloadBytes int) TxctxDependencyChecklistJSON {
	return TxctxDependencyChecklistJSON{
		ProfileExtID:         "0x" + hex.EncodeToString([]byte{byte(extID >> 8), byte(extID)}),
		SpecDocument:         "SPEC-TXCTX-01.md",
		SighashTypesRequired: []string{"SIGHASH_ALL"},
		MaxExtPayloadBytes:   maxExtPayloadBytes,
		VerifierSideEffects:  "none",
		Reviewer:             "gpt5",
	}
}

func testTxctxGovernanceProfile() CoreExtProfileJSON {
	return CoreExtProfileJSON{
		ExtID:              0x0feb,
		ActivationHeight:   100,
		TxContextEnabled:   1,
		AllowedSuiteIDs:    []uint8{0x10},
		MaxExtPayloadBytes: 48,
		Binding:            "native_verify_sig",
	}
}

func TestRunTxctxGovernanceVectorRejectsDuplicateAllowedSuiteIDs(t *testing.T) {
	profile := testTxctxGovernanceProfile()
	profile.AllowedSuiteIDs = []uint8{0x10, 0x10}
	resp := runTxctxGovernanceVector(
		Request{
			TransitionHeight:     uint64Ptr(100),
			DependencyChecklists: []TxctxDependencyChecklistJSON{testTxctxGovernanceChecklist(profile.ExtID, 48)},
		},
		[]CoreExtProfileJSON{profile},
	)
	if resp.Ok {
		t.Fatalf("expected duplicate allowed suite rejection")
	}
	if resp.Err != txctxGovernanceErrDuplicateAllowedSuiteID {
		t.Fatalf("unexpected err: %q", resp.Err)
	}
}

func TestRunTxctxGovernanceVectorRejectsActivationBelowTransition(t *testing.T) {
	profile := testTxctxGovernanceProfile()
	profile.ActivationHeight = 99
	resp := runTxctxGovernanceVector(
		Request{
			TransitionHeight:     uint64Ptr(100),
			DependencyChecklists: []TxctxDependencyChecklistJSON{testTxctxGovernanceChecklist(profile.ExtID, 48)},
		},
		[]CoreExtProfileJSON{profile},
	)
	if resp.Ok {
		t.Fatalf("expected activation gate rejection")
	}
	if resp.Err != txctxGovernanceErrActivationBelowTransition {
		t.Fatalf("unexpected err: %q", resp.Err)
	}
}

func TestRunTxctxGovernanceVectorRejectsArtifactHashMismatch(t *testing.T) {
	profile := testTxctxGovernanceProfile()
	artifact := []byte("txctx-governance-artifact")
	hash := sha256.Sum256(artifact)
	hash[0] ^= 0xff
	resp := runTxctxGovernanceVector(
		Request{
			ArtifactHex:          hex.EncodeToString(artifact),
			ExpectedArtifactHash: hex.EncodeToString(hash[:]),
			TransitionHeight:     uint64Ptr(100),
			DependencyChecklists: []TxctxDependencyChecklistJSON{testTxctxGovernanceChecklist(profile.ExtID, 48)},
		},
		[]CoreExtProfileJSON{profile},
	)
	if resp.Ok {
		t.Fatalf("expected artifact hash mismatch")
	}
	if resp.Err != txctxGovernanceErrArtifactHashMismatch {
		t.Fatalf("unexpected err: %q", resp.Err)
	}
}

func TestRunTxctxGovernanceVectorRejectsMissingChecklist(t *testing.T) {
	resp := runTxctxGovernanceVector(
		Request{
			TransitionHeight: uint64Ptr(100),
		},
		[]CoreExtProfileJSON{testTxctxGovernanceProfile()},
	)
	if resp.Ok {
		t.Fatalf("expected missing checklist rejection")
	}
	if resp.Err != txctxGovernanceErrMissingChecklist {
		t.Fatalf("unexpected err: %q", resp.Err)
	}
}

func TestRunTxctxGovernanceVectorRejectsLargePayloadWithoutMempoolGate(t *testing.T) {
	profile := testTxctxGovernanceProfile()
	profile.MaxExtPayloadBytes = 300
	resp := runTxctxGovernanceVector(
		Request{
			TransitionHeight:     uint64Ptr(100),
			DependencyChecklists: []TxctxDependencyChecklistJSON{testTxctxGovernanceChecklist(profile.ExtID, 300)},
		},
		[]CoreExtProfileJSON{profile},
	)
	if resp.Ok {
		t.Fatalf("expected mempool gate rejection")
	}
	if resp.Err != txctxGovernanceErrMempoolGateRequired {
		t.Fatalf("unexpected err: %q", resp.Err)
	}
}

func TestRunTxctxGovernanceVectorRejectsExtraChecklist(t *testing.T) {
	profile := testTxctxGovernanceProfile()
	resp := runTxctxGovernanceVector(
		Request{
			TransitionHeight: uint64Ptr(100),
			DependencyChecklists: []TxctxDependencyChecklistJSON{
				testTxctxGovernanceChecklist(profile.ExtID, 48),
				testTxctxGovernanceChecklist(0x0fed, 48),
			},
		},
		[]CoreExtProfileJSON{profile},
	)
	if resp.Ok {
		t.Fatalf("expected extra checklist rejection")
	}
	if resp.Err != txctxGovernanceErrInvalidChecklist {
		t.Fatalf("unexpected err: %q", resp.Err)
	}
}

func TestRunTxctxGovernanceVectorRejectsNonCanonicalChecklistExtID(t *testing.T) {
	profile := testTxctxGovernanceProfile()
	checklist := testTxctxGovernanceChecklist(profile.ExtID, 48)
	checklist.ProfileExtID = "0x1"
	resp := runTxctxGovernanceVector(
		Request{
			TransitionHeight:     uint64Ptr(100),
			DependencyChecklists: []TxctxDependencyChecklistJSON{checklist},
		},
		[]CoreExtProfileJSON{profile},
	)
	if resp.Ok {
		t.Fatalf("expected non-canonical ext id rejection")
	}
	if resp.Err != txctxGovernanceErrInvalidChecklist {
		t.Fatalf("unexpected err: %q", resp.Err)
	}
}

func TestRunTxctxGovernanceVectorRejectsNegativePayloadLimit(t *testing.T) {
	profile := testTxctxGovernanceProfile()
	profile.MaxExtPayloadBytes = -1
	resp := runTxctxGovernanceVector(
		Request{
			TransitionHeight:     uint64Ptr(100),
			DependencyChecklists: []TxctxDependencyChecklistJSON{testTxctxGovernanceChecklist(profile.ExtID, -1)},
		},
		[]CoreExtProfileJSON{profile},
	)
	if resp.Ok {
		t.Fatalf("expected negative payload limit rejection")
	}
	if resp.Err != txctxGovernanceErrInvalidChecklist {
		t.Fatalf("unexpected err: %q", resp.Err)
	}
}

func TestRunTxctxGovernanceVectorRejectsNonBooleanTxContextEnabled(t *testing.T) {
	profile := testTxctxGovernanceProfile()
	profile.TxContextEnabled = 2
	resp := runTxctxGovernanceVector(
		Request{
			TransitionHeight:     uint64Ptr(100),
			DependencyChecklists: []TxctxDependencyChecklistJSON{testTxctxGovernanceChecklist(profile.ExtID, 48)},
		},
		[]CoreExtProfileJSON{profile},
	)
	if resp.Ok {
		t.Fatalf("expected invalid tx_context_enabled rejection")
	}
	if resp.Err != txctxGovernanceErrInvalidChecklist {
		t.Fatalf("unexpected err: %q", resp.Err)
	}
}

func TestCoreExtProfileJSONRejectsNonBooleanTxContextEnabledJSON(t *testing.T) {
	var profile CoreExtProfileJSON
	err := json.Unmarshal([]byte(`{"tx_context_enabled":2}`), &profile)
	if err == nil {
		t.Fatalf("expected tx_context_enabled unmarshal failure")
	}
}

func TestRunTxctxGovernanceVectorAcceptsValidRequest(t *testing.T) {
	profile := testTxctxGovernanceProfile()
	artifact := []byte("txctx-governance-artifact")
	hash := sha256.Sum256(artifact)
	mempoolConfirmed := true
	resp := runTxctxGovernanceVector(
		Request{
			ArtifactHex:           hex.EncodeToString(artifact),
			ExpectedArtifactHash:  hex.EncodeToString(hash[:]),
			TransitionHeight:      uint64Ptr(100),
			MempoolTxctxConfirmed: &mempoolConfirmed,
			DependencyChecklists:  []TxctxDependencyChecklistJSON{testTxctxGovernanceChecklist(profile.ExtID, 48)},
		},
		[]CoreExtProfileJSON{profile},
	)
	if !resp.Ok {
		t.Fatalf("expected valid governance request, got err=%q", resp.Err)
	}
	if got := resp.Diagnostics["derived_transition_height"]; got != uint64(100) {
		t.Fatalf("derived_transition_height=%v", got)
	}
}

func uint64Ptr(value uint64) *uint64 {
	return &value
}
