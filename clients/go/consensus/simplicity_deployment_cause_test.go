package consensus

import (
	"errors"
	"fmt"
	"testing"
)

// This file is the CONSENSUS CAUSE CORPUS for the CORE_SIMPLICITY deployment
// gate: it drives validateCoreSimplicityDeploymentActive and the real
// ValidateTxCovenantsGenesis entry for every same-read deployment state and
// pins, per row, the exact public ErrorCode, the exact message, and the typed
// cause read through errors.As plus Cause().
//
// The cause is NOT observable through the node's relay surface (that publishes
// a rendered string), so the relay corpus can only prove it INDIRECTLY through
// the disposition it selects. The exact cause per state is proven HERE.

var errCauseCorpusLookup = errors.New("deployment store offline")

// causeRotation is a live RotationProvider whose deployment surface publishes
// exactly one same-read state, so a row can drive the REAL production entry
// (ValidateTxCovenantsGenesis -> validateCoreSimplicityGenesisOutput -> the
// gate) and not only the gate helper.
type causeRotation struct {
	DefaultRotationProvider
	deployments SimplicityDeploymentProvider
}

func (r causeRotation) PublishedSimplicityDeployments() ([]SimplicityDeploymentDescriptor, [32]byte, bool, error) {
	return r.deployments.PublishedSimplicityDeployments()
}

// countingDeploymentProvider answers differently on the FIRST read than on any
// later one, and counts reads. It is the executable proof that the gate takes
// exactly ONE observation and classifies from that one.
type countingDeploymentProvider struct {
	reads  *int
	first  stubDeploymentProvider
	later  stubDeploymentProvider
	single bool // true => every read answers `first`
}

func (p countingDeploymentProvider) PublishedSimplicityDeployments() ([]SimplicityDeploymentDescriptor, [32]byte, bool, error) {
	*p.reads++
	if p.single || *p.reads == 1 {
		return p.first.PublishedSimplicityDeployments()
	}
	return p.later.PublishedSimplicityDeployments()
}

// deploymentCauseRow is one row of the required classification matrix: the
// same-read state, the unchanged public result, the typed cause it must carry,
// and the exported SimplicityActiveAtHeight baseline for the same state.
type deploymentCauseRow struct {
	name           string
	provider       SimplicityDeploymentProvider // nil => no provider configured
	wantErr        bool
	wantMessage    string
	wantCause      TxErrorCause
	wantActive     bool
	wantLookupFail bool
}

// deploymentCauseMatrix builds every same-read state at the pinned height.
func deploymentCauseMatrix(t *testing.T, chainID [32]byte, height uint64) []deploymentCauseRow {
	t.Helper()
	anchorOf := func(set []SimplicityDeploymentDescriptor) [32]byte {
		t.Helper()
		anchor, err := SimplicityDeploymentSetAnchor(chainID, set)
		if err != nil {
			t.Fatalf("SimplicityDeploymentSetAnchor: %v", err)
		}
		return anchor
	}

	governing := []SimplicityDeploymentDescriptor{liveValidDescriptor(chainID, height)}
	governingAnchor := anchorOf(governing)

	// A complete, anchor-valid set whose only descriptor activates above the
	// candidate height: state known, and known inactive here.
	future := []SimplicityDeploymentDescriptor{liveValidDescriptor(chainID, height+1)}
	futureAnchor := anchorOf(future)

	// Self-consistent descriptors paired with a mismatched anchor.
	mismatched := governingAnchor
	mismatched[0] ^= 0xFF

	// Duplicate anchors: the set anchor cannot even be computed, so the failure
	// arrives from SimplicityDeploymentSetAnchor, not from the compare.
	duplicate := []SimplicityDeploymentDescriptor{governing[0], governing[0]}

	const notActive = "CORE_SIMPLICITY deployment not active"
	const lookupFailure = "CORE_SIMPLICITY deployment lookup failure"

	// The ok=false row carries a NON-EMPTY partial set on purpose: those
	// descriptors must not be read as evidence of anything.
	return []deploymentCauseRow{
		{name: "no provider configured", provider: nil,
			wantErr: true, wantMessage: notActive, wantCause: TxErrorCauseSimplicityDeploymentInactiveFrozen},
		{name: "provider returns an I/O error", provider: stubDeploymentProvider{err: errCauseCorpusLookup},
			wantErr: true, wantMessage: lookupFailure, wantCause: TxErrorCauseSimplicityDeploymentUnavailable, wantLookupFail: true},
		{name: "provider returns ok=false with partial descriptors", provider: stubDeploymentProvider{set: governing, setAnchor: governingAnchor, ok: false},
			wantErr: true, wantMessage: notActive, wantCause: TxErrorCauseSimplicityDeploymentUnavailable},
		{name: "set anchor mismatch", provider: stubDeploymentProvider{set: governing, setAnchor: mismatched, ok: true},
			wantErr: true, wantMessage: notActive, wantCause: TxErrorCauseSimplicityDeploymentEvidenceInvalid},
		{name: "duplicate descriptor anchors", provider: stubDeploymentProvider{set: duplicate, setAnchor: governingAnchor, ok: true},
			wantErr: true, wantMessage: notActive, wantCause: TxErrorCauseSimplicityDeploymentEvidenceInvalid},
		{name: "complete anchor-valid set with no governing descriptor", provider: stubDeploymentProvider{set: future, setAnchor: futureAnchor, ok: true},
			wantErr: true, wantMessage: notActive, wantCause: TxErrorCauseSimplicityDeploymentInactiveProvider},
		{name: "governing descriptor active", provider: stubDeploymentProvider{set: governing, setAnchor: governingAnchor, ok: true},
			wantCause: TxErrorCauseUnspecified, wantActive: true},
	}
}

// assertDeploymentCause pins the exact public code, the exact message and the
// typed cause, all read through the public accessors a consumer would use.
func assertDeploymentCause(t *testing.T, err error, row deploymentCauseRow) {
	t.Helper()
	if !row.wantErr {
		if err != nil {
			t.Fatalf("active deployment produced %v, want nil", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("want error %q, got nil", row.wantMessage)
	}
	var txErr *TxError
	if !errors.As(err, &txErr) {
		t.Fatalf("error %v is not a *TxError", err)
	}
	if txErr.Code != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want the unchanged %s", txErr.Code, TX_ERR_COVENANT_TYPE_INVALID)
	}
	if txErr.Msg != row.wantMessage {
		t.Fatalf("msg=%q, want the unchanged %q", txErr.Msg, row.wantMessage)
	}
	if want := fmt.Sprintf("%s: %s", TX_ERR_COVENANT_TYPE_INVALID, row.wantMessage); txErr.Error() != want {
		t.Fatalf("Error()=%q, want the unchanged %q", txErr.Error(), want)
	}
	if got := txErr.Cause(); got != row.wantCause {
		t.Fatalf("Cause()=%d, want %d", got, row.wantCause)
	}
}

// TestSimplicityDeploymentCauseMatrix drives the gate directly for every
// same-read state: the public result is byte-identical to the pre-cause
// baseline and the typed cause is one-to-one with the state.
func TestSimplicityDeploymentCauseMatrix(t *testing.T) {
	chainID := bytes32(0xAB)
	const height = 10
	for _, row := range deploymentCauseMatrix(t, chainID, height) {
		t.Run(row.name, func(t *testing.T) {
			assertDeploymentCause(t, validateCoreSimplicityDeploymentActive(chainID, height, row.provider), row)
		})
	}
}

// TestSimplicityDeploymentCauseThroughProductionEntry is the dataflow proof:
// candidate BYTES -> ParseTx -> ValidateTxCovenantsGenesis -> the deployment
// gate. Each row's trigger is reached from a real CORE_SIMPLICITY creation
// output, not by calling the gate helper, so the matrix rows are proven over
// the trigger set production actually produces.
func TestSimplicityDeploymentCauseThroughProductionEntry(t *testing.T) {
	chainID := bytes32(0xAB)
	const height = 10
	var cmr [32]byte
	cmr[0] = 0xa5
	tx := &Tx{Outputs: []TxOutput{{
		Value:        1,
		CovenantType: COV_TYPE_CORE_SIMPLICITY,
		CovenantData: encodeSimplicityCovenantData(cmr, []byte{0x01, 0x02}),
	}}}

	for _, row := range deploymentCauseMatrix(t, chainID, height) {
		t.Run(row.name, func(t *testing.T) {
			var rotation RotationProvider = DefaultRotationProvider{}
			if row.provider != nil {
				rotation = causeRotation{deployments: row.provider}
			}
			assertDeploymentCause(t, ValidateTxCovenantsGenesis(tx, chainID, height, rotation), row)
		})
	}
}

// TestSimplicityActiveAtHeightBaselineUnchanged is the COMPATIBILITY CORPUS for
// the exported accessor: nil provider -> (false,nil); provider error -> the
// provider's OWN error value; ok=false -> (false,nil); invalid set/anchor ->
// (false,nil); verified inactive -> (false,nil); active -> (true,nil).
func TestSimplicityActiveAtHeightBaselineUnchanged(t *testing.T) {
	// Dynamic-type / signature dimension: the exported symbol still has exactly
	// the baseline function type, so no caller's assignment or call shape moves.
	var _ func([32]byte, uint64, SimplicityDeploymentProvider) (bool, error) = SimplicityActiveAtHeight

	chainID := bytes32(0xAB)
	const height = 10
	for _, row := range deploymentCauseMatrix(t, chainID, height) {
		t.Run(row.name, func(t *testing.T) {
			active, err := SimplicityActiveAtHeight(chainID, height, row.provider)
			if active != row.wantActive {
				t.Fatalf("active=%v, want %v", active, row.wantActive)
			}
			if !row.wantLookupFail {
				if err != nil {
					t.Fatalf("err=%v, want nil", err)
				}
				return
			}
			// The provider's own error value is returned unwrapped and untyped:
			// the exported surface never converts it into a *TxError.
			if !errors.Is(err, errCauseCorpusLookup) {
				t.Fatalf("err=%v, want the provider's own %v", err, errCauseCorpusLookup)
			}
			var txErr *TxError
			if errors.As(err, &txErr) {
				t.Fatalf("exported accessor converted the provider error into %v", txErr)
			}
		})
	}
}

// TestSimplicityDeploymentSameReadEvidence proves the classification comes from
// ONE observation. A provider that fails the FIRST read and would succeed on a
// hypothetical second must still classify as UNAVAILABLE and must be read
// exactly once; the mirrored case pins that a set inactive now and active at a
// greater height is read once per gate call too.
func TestSimplicityDeploymentSameReadEvidence(t *testing.T) {
	chainID := bytes32(0xAB)
	const height = 10
	governing := []SimplicityDeploymentDescriptor{liveValidDescriptor(chainID, height)}
	anchor, err := SimplicityDeploymentSetAnchor(chainID, governing)
	if err != nil {
		t.Fatalf("SimplicityDeploymentSetAnchor: %v", err)
	}
	active := stubDeploymentProvider{set: governing, setAnchor: anchor, ok: true}

	t.Run("a failing first read is never rescued by a later one", func(t *testing.T) {
		reads := 0
		provider := countingDeploymentProvider{
			reads: &reads,
			first: stubDeploymentProvider{err: errCauseCorpusLookup},
			later: active,
		}
		gotErr := validateCoreSimplicityDeploymentActive(chainID, height, provider)
		var txErr *TxError
		if !errors.As(gotErr, &txErr) {
			t.Fatalf("err=%v, want a *TxError", gotErr)
		}
		if txErr.Msg != "CORE_SIMPLICITY deployment lookup failure" {
			t.Fatalf("msg=%q, want the first read's failure", txErr.Msg)
		}
		if txErr.Cause() != TxErrorCauseSimplicityDeploymentUnavailable {
			t.Fatalf("cause=%d, want UNAVAILABLE from the first read", txErr.Cause())
		}
		if reads != 1 {
			t.Fatalf("provider reads=%d, want exactly 1 (a second read is a different observation)", reads)
		}
	})

	t.Run("one read per gate call on the affirmative row", func(t *testing.T) {
		reads := 0
		provider := countingDeploymentProvider{reads: &reads, first: active, single: true}
		if err := validateCoreSimplicityDeploymentActive(chainID, height, provider); err != nil {
			t.Fatalf("active gate: %v", err)
		}
		if reads != 1 {
			t.Fatalf("provider reads=%d, want exactly 1", reads)
		}
	})

	t.Run("the same complete set is inactive below its activation height", func(t *testing.T) {
		reads := 0
		provider := countingDeploymentProvider{reads: &reads, first: active, single: true}
		gotErr := validateCoreSimplicityDeploymentActive(chainID, height-1, provider)
		var txErr *TxError
		if !errors.As(gotErr, &txErr) {
			t.Fatalf("err=%v, want a *TxError", gotErr)
		}
		if txErr.Cause() != TxErrorCauseSimplicityDeploymentInactiveProvider {
			t.Fatalf("cause=%d, want INACTIVE_PROVIDER for a complete verified set", txErr.Cause())
		}
		if reads != 1 {
			t.Fatalf("provider reads=%d, want exactly 1", reads)
		}
	})
}

// TestSimplicityDeploymentCauseSurvivesWrappers pins BOTH directions of the
// wrapper contract: an outer %w wrapper preserves the cause the producing
// branch selected, and a wrapper around an UNCAUSED error never invents one.
func TestSimplicityDeploymentCauseSurvivesWrappers(t *testing.T) {
	chainID := bytes32(0xAB)
	inner := validateCoreSimplicityDeploymentActive(chainID, 10, stubDeploymentProvider{err: errCauseCorpusLookup})

	wrapped := fmt.Errorf("CORE_SIMPLICITY deployment lookup failure: %w", inner)
	var txErr *TxError
	if !errors.As(wrapped, &txErr) {
		t.Fatalf("wrapped error lost its *TxError: %v", wrapped)
	}
	if txErr.Cause() != TxErrorCauseSimplicityDeploymentUnavailable {
		t.Fatalf("wrapped cause=%d, want UNAVAILABLE preserved", txErr.Cause())
	}
	// Double wrapping is still lossless.
	if !errors.As(fmt.Errorf("outer: %w", wrapped), &txErr) || txErr.Cause() != TxErrorCauseSimplicityDeploymentUnavailable {
		t.Fatal("a second wrapper erased the cause")
	}

	// The uncaused direction: a baseline txerr wrapped the same way stays
	// UNSPECIFIED, so no wrapper can manufacture a deployment cause.
	uncaused := txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY deployment not active")
	if !errors.As(fmt.Errorf("outer: %w", uncaused), &txErr) {
		t.Fatalf("wrapped baseline error lost its *TxError: %v", uncaused)
	}
	if txErr.Cause() != TxErrorCauseUnspecified {
		t.Fatalf("wrapper invented cause=%d on an uncaused error", txErr.Cause())
	}
}

// TestSimplicityDeploymentCauseLegacyValuesAreBaseline pins that the values a
// caller can build outside this package — the zero TxError, a keyed literal, a
// value copy — stay panic-free and cause-UNSPECIFIED.
func TestSimplicityDeploymentCauseLegacyValuesAreBaseline(t *testing.T) {
	var zero TxError
	if zero.Cause() != TxErrorCauseUnspecified {
		t.Fatalf("zero TxError cause=%d", zero.Cause())
	}
	var nilErr *TxError
	if nilErr.Cause() != TxErrorCauseUnspecified || nilErr.Error() != "<nil>" {
		t.Fatalf("nil *TxError is not baseline: cause=%d error=%q", nilErr.Cause(), nilErr.Error())
	}
	legacy := TxError{Code: TX_ERR_COVENANT_TYPE_INVALID, Msg: "CORE_SIMPLICITY deployment not active"}
	if legacy.Cause() != TxErrorCauseUnspecified {
		t.Fatalf("keyed legacy literal cause=%d", legacy.Cause())
	}

	// Value-copy dimension: copying a caused error carries the cause with it and
	// comparison over the copies still agrees.
	caused := validateCoreSimplicityDeploymentActive(bytes32(0xAB), 10, nil)
	var txErr *TxError
	if !errors.As(caused, &txErr) {
		t.Fatalf("no *TxError: %v", caused)
	}
	copied := *txErr
	if copied.Cause() != TxErrorCauseSimplicityDeploymentInactiveFrozen {
		t.Fatalf("value copy cause=%d, want INACTIVE_FROZEN", copied.Cause())
	}
	if copied != *txErr {
		t.Fatal("value copies of the same TxError compare unequal")
	}
}

var _ SimplicityDeploymentProvider = causeRotation{}
var _ SimplicityDeploymentProvider = countingDeploymentProvider{}
