package node

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// relayHarness is one signed-P2PK admission fixture: a spendable chainstate, a
// mempool bound to it, and the keys needed to build candidates against it.
type relayHarness struct {
	t         *testing.T
	fromKey   *consensus.MLDSA87Keypair
	fromAddr  []byte
	toAddr    []byte
	st        *ChainState
	outpoints []consensus.Outpoint
	mp        *Mempool
}

func newRelayHarness(t *testing.T, cfg *MempoolConfig, values ...uint64) *relayHarness {
	t.Helper()
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	h := &relayHarness{
		t:        t,
		fromKey:  fromKey,
		fromAddr: consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes()),
		toAddr:   consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes()),
	}
	h.st, h.outpoints = testSpendableChainState(h.fromAddr, values)
	var err error
	if cfg == nil {
		h.mp, err = NewMempool(h.st, nil, devnetGenesisChainID)
	} else {
		h.mp, err = NewMempoolWithConfig(h.st, nil, devnetGenesisChainID, *cfg)
	}
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	return h
}

func (h *relayHarness) tx(input int, amount, fee, nonce uint64) []byte {
	h.t.Helper()
	return mustBuildSignedTransferTx(h.t, h.st.Utxos, []consensus.Outpoint{h.outpoints[input]}, amount, fee, nonce, h.fromKey, h.fromAddr, h.toAddr)
}

// context returns the owner's current exact admission context.
func (h *relayHarness) context() *PendingOutpointAdmissionContext {
	h.t.Helper()
	ctx, ok := h.mp.PendingOutpointOwner().AdmissionContext()
	if !ok {
		h.t.Fatal("owner admission context unavailable")
	}
	return &ctx
}

// advanceOwnerGeneration commits a transition back onto the SAME stable tip, so
// the tip compares equal while the generation the owner is bound to has moved
// past every context observed before this call.
func (h *relayHarness) advanceOwnerGeneration() {
	h.t.Helper()
	owner := h.mp.PendingOutpointOwner()
	if _, err := owner.beginTransition(); err != nil {
		h.t.Fatalf("beginTransition: %v", err)
	}
	if err := owner.commitStableTip(pendingOutpointTipOf(h.st)); err != nil {
		h.t.Fatalf("commitStableTip: %v", err)
	}
}

func mustSnapshot(t *testing.T, mp *Mempool) mempoolSnapshot {
	t.Helper()
	snap, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshotMempool: %v", err)
	}
	return snap
}

func admitKind(t *testing.T, err error) TxAdmitErrorKind {
	t.Helper()
	var admitErr *TxAdmitError
	if !errors.As(err, &admitErr) {
		t.Fatalf("expected *TxAdmitError, got %T: %v", err, err)
	}
	return admitErr.Kind
}

// TestRelayAdmissionDispositionCorpus drives ONE candidate per branch of the
// closed classifier through the live public relay entry point and pins the
// disposition its originating branch selected, the unchanged public admission
// kind, and whether cache-authorizing context evidence was published.
//
// The rows deliberately include inputs whose public TxAdmitErrorKind is
// ambiguous — TxAdmitConflict carries both DUPLICATE and CONFLICT,
// TxAdmitUnavailable carries ROLLING_FLOOR, CAPACITY, ADMISSION_SEQUENCE and
// UNAVAILABLE — so a classifier that read the kind instead of the branch would
// fail here.
func TestRelayAdmissionDispositionCorpus(t *testing.T) {
	cases := []struct {
		name string
		// build returns the mempool, the candidate bytes, and the caller's
		// expected admission context (nil for the legacy-equivalent shape).
		build       func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext)
		want        RelayAdmissionDisposition
		wantKind    TxAdmitErrorKind
		wantNilErr  bool
		wantContext bool
		wantTxID    bool
	}{
		{
			name: "retained without expected context",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, nil, 1_000_000)
				return h.mp, h.tx(0, 100_000, 100_000, 1), nil
			},
			want:       RelayAdmissionRetained,
			wantNilErr: true,
			wantTxID:   true,
		},
		{
			name: "retained with the exact stable context carries no cache authority",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, nil, 1_000_000)
				return h.mp, h.tx(0, 100_000, 100_000, 1), h.context()
			},
			want:       RelayAdmissionRetained,
			wantNilErr: true,
			wantTxID:   true,
		},
		{
			name: "stable terminal reject: unparseable bytes",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, nil, 1_000_000)
				return h.mp, []byte{0xFF, 0x00, 0x13, 0x37}, h.context()
			},
			want:        RelayAdmissionStableTerminalReject,
			wantKind:    TxAdmitRejected,
			wantContext: true,
		},
		{
			name: "stable terminal reject: trailing bytes after canonical tx",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, nil, 1_000_000)
				return h.mp, append(h.tx(0, 100_000, 100_000, 1), 0x00), h.context()
			},
			want:        RelayAdmissionStableTerminalReject,
			wantKind:    TxAdmitRejected,
			wantContext: true,
		},
		{
			name: "stable terminal reject: consensus-invalid signature",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, nil, 1_000_000)
				return h.mp, corruptFirstWitnessSignature(t, h.tx(0, 100_000, 100_000, 1)), h.context()
			},
			want:        RelayAdmissionStableTerminalReject,
			wantKind:    TxAdmitRejected,
			wantContext: true,
			wantTxID:    true,
		},
		{
			name: "stable terminal reject: static anchor-output policy",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, &MempoolConfig{
					MaxTransactions:                      10,
					MaxBytes:                             1 << 20,
					PolicyRejectNonCoinbaseAnchorOutputs: true,
				}, 1_000_000)
				// A CORE_ANCHOR output of value 0 is CONSENSUS-valid
				// (clients/go/consensus/covenant_genesis.go
				// validateAnchorGenesisOutput), so the candidate reaches the
				// static-policy lane this row is named for and is rejected by
				// applyPolicyAgainstState — the branch that must select the tag.
				raw := mustBuildSignedAnchorOutputTx(t, h.st.Utxos, h.outpoints[0], 0, 100_000, 1, h.fromKey, h.fromAddr)
				return h.mp, raw, h.context()
			},
			want:        RelayAdmissionStableTerminalReject,
			wantKind:    TxAdmitRejected,
			wantContext: true,
			wantTxID:    true,
		},
		{
			name: "missing dependency never carries cache authority",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, nil, 1_000_000, 1_000_000)
				raw := h.tx(1, 100_000, 100_000, 1)
				delete(h.st.Utxos, h.outpoints[1])
				return h.mp, raw, h.context()
			},
			want:     RelayAdmissionMissingDependency,
			wantKind: TxAdmitRejected,
			wantTxID: true,
		},
		{
			name: "duplicate resident txid keeps the conflict kind",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, nil, 1_000_000)
				raw := h.tx(0, 100_000, 100_000, 1)
				if err := h.mp.AddRemoteTx(raw); err != nil {
					t.Fatalf("seed AddRemoteTx: %v", err)
				}
				return h.mp, raw, h.context()
			},
			want:     RelayAdmissionDuplicate,
			wantKind: TxAdmitConflict,
			wantTxID: true,
		},
		{
			name: "pending-outpoint owner conflict keeps the conflict kind",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, nil, 1_000_000)
				if err := h.mp.AddRemoteTx(h.tx(0, 100_000, 100_000, 1)); err != nil {
					t.Fatalf("seed AddRemoteTx: %v", err)
				}
				return h.mp, h.tx(0, 100_000, 200_000, 2), h.context()
			},
			want:     RelayAdmissionConflict,
			wantKind: TxAdmitConflict,
			wantTxID: true,
		},
		{
			// The cheap-precheck floor authority: a single-input plain P2PK
			// shape is fast-rejected at mempool_precheck.go's precheck wrap
			// before any signature verification.
			name: "rolling floor: cheap precheck authority",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, nil, 1_000_000)
				raw := h.tx(0, 100_000, 100_000, 1)
				h.mp.SetCurrentMinFeeRateForTest(1 << 40)
				return h.mp, raw, h.context()
			},
			want:     RelayAdmissionRollingFloor,
			wantKind: TxAdmitUnavailable,
			wantTxID: true,
		},
		{
			// The LOCKED floor authority (validateFeeFloorLockedWithFloor, the
			// max(snappedFloor, live) re-check). Two inputs mean two witness
			// items, which disqualifies feePrecheckP2PKInputValue, so the cheap
			// precheck defers and the locked check owns the outcome.
			name: "rolling floor: locked max(snapped,live) authority",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, nil, 1_000_000, 1_000_000)
				raw := mustBuildSignedTransferTx(t, h.st.Utxos, h.outpoints, 100_000, 100_000, 1, h.fromKey, h.fromAddr, h.toAddr)
				h.mp.SetCurrentMinFeeRateForTest(1 << 40)
				return h.mp, raw, h.context()
			},
			want:     RelayAdmissionRollingFloor,
			wantKind: TxAdmitUnavailable,
			wantTxID: true,
		},
		{
			name: "capacity: candidate is the worst under byte pressure",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, nil, 1_000_000, 1_000_000)
				rich := h.tx(0, 100_000, 200_000, 1)
				poor := h.tx(1, 100_000, 100_000, 2)
				mp, err := NewMempoolWithConfig(h.st, nil, devnetGenesisChainID, MempoolConfig{
					MaxTransactions: 10,
					MaxBytes:        len(rich) + len(poor) - 1,
				})
				if err != nil {
					t.Fatalf("new mempool: %v", err)
				}
				if err := mp.AddRemoteTx(rich); err != nil {
					t.Fatalf("seed AddRemoteTx: %v", err)
				}
				ctx, ok := mp.PendingOutpointOwner().AdmissionContext()
				if !ok {
					t.Fatal("owner admission context unavailable")
				}
				return mp, poor, &ctx
			},
			want:     RelayAdmissionCapacity,
			wantKind: TxAdmitUnavailable,
			wantTxID: true,
		},
		{
			name: "admission sequence exhausted",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, nil, 1_000_000)
				raw := h.tx(0, 100_000, 100_000, 1)
				h.mp.mu.Lock()
				h.mp.lastAdmissionSeq = ^uint64(0)
				h.mp.mu.Unlock()
				return h.mp, raw, h.context()
			},
			want:     RelayAdmissionAdmissionSequence,
			wantKind: TxAdmitUnavailable,
			wantTxID: true,
		},
		{
			name: "unavailable: absent chainstate",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				return &Mempool{}, []byte{0x01}, nil
			},
			want:     RelayAdmissionUnavailable,
			wantKind: TxAdmitUnavailable,
		},
		{
			name: "unavailable: superseded expected context at the owner seam",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, nil, 1_000_000)
				raw := h.tx(0, 100_000, 100_000, 1)
				stale := h.context()
				h.advanceOwnerGeneration()
				return h.mp, raw, stale
			},
			want:     RelayAdmissionUnavailable,
			wantKind: TxAdmitUnavailable,
			wantTxID: true,
		},
		{
			name: "unavailable: owner transition in progress",
			build: func(t *testing.T) (*Mempool, []byte, *PendingOutpointAdmissionContext) {
				h := newRelayHarness(t, nil, 1_000_000)
				raw := h.tx(0, 100_000, 100_000, 1)
				expected := h.context()
				if _, err := h.mp.PendingOutpointOwner().beginTransition(); err != nil {
					t.Fatalf("beginTransition: %v", err)
				}
				return h.mp, raw, expected
			},
			want:     RelayAdmissionUnavailable,
			wantKind: TxAdmitUnavailable,
			wantTxID: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mp, raw, expected := tc.build(t)
			got := mp.AddRemoteTxForRelay(raw, expected)

			if got.Disposition != tc.want {
				t.Fatalf("disposition=%v, want %v (err=%v)", got.Disposition, tc.want, got.Err)
			}
			if got.Disposition == RelayAdmissionCancelled {
				t.Fatal("no production branch may select CANCELLED")
			}
			if tc.wantNilErr {
				if got.Err != nil {
					t.Fatalf("err=%v, want nil", got.Err)
				}
			} else {
				if got.Err == nil {
					t.Fatal("err=nil, want a public admission error")
				}
				if kind := admitKind(t, got.Err); kind != tc.wantKind {
					t.Fatalf("TxAdmitErrorKind=%q, want %q", kind, tc.wantKind)
				}
			}
			if got.HasAdmissionContext != tc.wantContext {
				t.Fatalf("HasAdmissionContext=%v, want %v", got.HasAdmissionContext, tc.wantContext)
			}
			if got.HasAdmissionContext {
				if got.Disposition != RelayAdmissionStableTerminalReject {
					t.Fatalf("disposition %v published cache-authorizing context", got.Disposition)
				}
				if got.AdmissionContext != *expected {
					t.Fatalf("AdmissionContext=%+v, want the exact expected context %+v", got.AdmissionContext, *expected)
				}
			} else if got.AdmissionContext != (PendingOutpointAdmissionContext{}) {
				t.Fatalf("AdmissionContext=%+v published without HasAdmissionContext", got.AdmissionContext)
			}
			if hasTxID := got.TxID != ([32]byte{}); hasTxID != tc.wantTxID {
				t.Fatalf("TxID present=%v (%x), want present=%v", hasTxID, got.TxID, tc.wantTxID)
			}
			if tc.wantTxID {
				if want := txID(t, raw); got.TxID != want {
					t.Fatalf("TxID=%x, want the producer-parsed %x", got.TxID, want)
				}
				if got.WTxID == ([32]byte{}) {
					t.Fatalf("WTxID is zero for a parsed candidate")
				}
			}
		})
	}
}

// TestRelayAdmissionDispositionNeverInfersFromTheErrorSurface proves the
// classification is READ from the producing branch's own selection and is never
// reconstructed from the compatibility kind, the message text, or a default.
func TestRelayAdmissionDispositionNeverInfersFromTheErrorSurface(t *testing.T) {
	// An error no branch classified is INTERNAL, never stable-terminal — even
	// when its kind and message look exactly like a stable rejection.
	untagged := []error{
		txAdmitRejected("TX_ERR_SIG_INVALID: signature invalid"),
		txAdmitConflict("tx already in mempool"),
		txAdmitUnavailable("mempool fee below rolling minimum: fee=0 weight=1 min_fee_rate=9"),
		errors.New("not an admission error"),
	}
	for _, err := range untagged {
		if got := relayDispositionOf(err); got != RelayAdmissionInternal {
			t.Fatalf("relayDispositionOf(%v)=%v, want INTERNAL", err, got)
		}
	}

	// The FIRST selection wins: an outer class tag cannot overwrite the precise
	// disposition an inner branch already selected.
	inner := txAdmitConflict("tx already in mempool")
	tagged := selectRelayDisposition(inner, RelayAdmissionDuplicate)
	tagged = selectRelayDisposition(tagged, RelayAdmissionInternal)
	if got := relayDispositionOf(tagged); got != RelayAdmissionDuplicate {
		t.Fatalf("disposition=%v after an outer tag, want the inner DUPLICATE", got)
	}

	// Tagging changes no public surface.
	if inner.Kind != TxAdmitConflict || inner.Error() != "tx already in mempool" {
		t.Fatalf("tagging mutated the public error surface: kind=%q message=%q", inner.Kind, inner.Error())
	}

	// Pass-through shapes.
	if selectRelayDisposition(nil, RelayAdmissionRetained) != nil {
		t.Fatal("selectRelayDisposition(nil) must stay nil")
	}
	plain := errors.New("plain")
	if selectRelayDisposition(plain, RelayAdmissionCapacity) != plain {
		t.Fatal("selectRelayDisposition must return a non-admission error unchanged")
	}
}

// TestRelayAdmissionDispositionEnumIsClosed pins the eleven-value taxonomy and
// the deliberately-unselected zero value.
func TestRelayAdmissionDispositionEnumIsClosed(t *testing.T) {
	want := map[RelayAdmissionDisposition]string{
		RelayAdmissionRetained:             "RETAINED",
		RelayAdmissionStableTerminalReject: "STABLE_TERMINAL_REJECT",
		RelayAdmissionDuplicate:            "DUPLICATE",
		RelayAdmissionConflict:             "CONFLICT",
		RelayAdmissionMissingDependency:    "MISSING_DEPENDENCY",
		RelayAdmissionRollingFloor:         "ROLLING_FLOOR",
		RelayAdmissionCapacity:             "CAPACITY",
		RelayAdmissionAdmissionSequence:    "ADMISSION_SEQUENCE",
		RelayAdmissionUnavailable:          "UNAVAILABLE",
		RelayAdmissionInternal:             "INTERNAL",
		RelayAdmissionCancelled:            "CANCELLED",
	}
	if len(want) != 11 {
		t.Fatalf("taxonomy has %d values, want exactly 11", len(want))
	}
	seen := make(map[RelayAdmissionDisposition]struct{}, len(want))
	for value, name := range want {
		if value == 0 {
			t.Fatalf("%s must not be the zero value", name)
		}
		if _, dup := seen[value]; dup {
			t.Fatalf("%s duplicates another enum value", name)
		}
		seen[value] = struct{}{}
		if got := value.String(); got != name {
			t.Fatalf("String()=%q, want %q", got, name)
		}
	}
	for _, outside := range []RelayAdmissionDisposition{0, 12, 255} {
		if got := outside.String(); got != "UNSELECTED" {
			t.Fatalf("String() for %d = %q, want UNSELECTED", outside, got)
		}
	}
}

// TestRelayAdmissionDispositionTypedProducerMappings pins the two producer
// mappings that read a TYPED code from the failing producer rather than any
// rendered text, including the retryable-dependency class that must never be
// published as a stable terminal rejection.
func TestRelayAdmissionDispositionTypedProducerMappings(t *testing.T) {
	ownerCases := []struct {
		err  error
		want RelayAdmissionDisposition
	}{
		{&PendingOutpointError{Kind: PendingOutpointConflict, Msg: "mempool double-spend conflict with ab"}, RelayAdmissionConflict},
		{&PendingOutpointError{Kind: PendingOutpointUnavailable, Msg: "pending-outpoint expected tip mismatch"}, RelayAdmissionUnavailable},
		{&PendingOutpointError{Kind: PendingOutpointInternal, Msg: "zero or foreign pending-outpoint token"}, RelayAdmissionInternal},
		{errors.New("not an owner error"), RelayAdmissionInternal},
	}
	for _, tc := range ownerCases {
		if got := relayDispositionForOwnerError(tc.err); got != tc.want {
			t.Fatalf("relayDispositionForOwnerError(%v)=%v, want %v", tc.err, got, tc.want)
		}
	}

	dependency := []consensus.ErrorCode{
		consensus.TX_ERR_MISSING_UTXO,
		consensus.TX_ERR_COINBASE_IMMATURE,
		consensus.TX_ERR_TIMELOCK_NOT_MET,
	}
	for _, code := range dependency {
		err := &consensus.TxError{Code: code, Msg: "input"}
		for _, nonDependency := range []RelayAdmissionDisposition{RelayAdmissionStableTerminalReject, RelayAdmissionInternal} {
			if got := relayDispositionForInputError(err, nonDependency); got != RelayAdmissionMissingDependency {
				t.Fatalf("relayDispositionForInputError(%s)=%v, want MISSING_DEPENDENCY", code, got)
			}
		}
	}
	stable := &consensus.TxError{Code: consensus.TX_ERR_SIG_INVALID, Msg: "bad signature"}
	if got := relayDispositionForInputError(stable, RelayAdmissionStableTerminalReject); got != RelayAdmissionStableTerminalReject {
		t.Fatalf("non-dependency consensus failure=%v, want STABLE_TERMINAL_REJECT", got)
	}
	if got := relayDispositionForInputError(errors.New("nil utxo set"), RelayAdmissionInternal); got != RelayAdmissionInternal {
		t.Fatalf("non-typed input failure=%v, want the branch's own INTERNAL", got)
	}
}

// TestRelayAdmissionDispositionRetainedProvesResidency pins RETAINED against the
// live index rather than against a nil error: a published record that is not the
// exact candidate is the retained-identity-mismatch invariant, i.e. INTERNAL.
func TestRelayAdmissionDispositionRetainedProvesResidency(t *testing.T) {
	entry := &mempoolEntry{txid: [32]byte{0x01}, wtxid: [32]byte{0x02}, weight: 1, size: 1}
	mp := &Mempool{txs: map[[32]byte]*mempoolEntry{entry.txid: entry}}

	probe := &relayAdmissionProbe{}
	mp.noteRetainedLocked(entry, probe)
	if probe.success != RelayAdmissionRetained {
		t.Fatalf("resident exact candidate selected %v, want RETAINED", probe.success)
	}
	if probe.txid != entry.txid || probe.wtxid != entry.wtxid {
		t.Fatalf("identity=(%x,%x), want the candidate's own (%x,%x)", probe.txid, probe.wtxid, entry.txid, entry.wtxid)
	}

	impostor := &mempoolEntry{txid: entry.txid, wtxid: entry.wtxid, weight: 1, size: 1}
	mismatch := &relayAdmissionProbe{}
	mp.noteRetainedLocked(impostor, mismatch)
	if mismatch.success != RelayAdmissionInternal {
		t.Fatalf("retained identity mismatch selected %v, want INTERNAL", mismatch.success)
	}

	missing := &relayAdmissionProbe{}
	(&Mempool{}).noteRetainedLocked(entry, missing)
	if missing.success != RelayAdmissionInternal {
		t.Fatalf("absent record selected %v, want INTERNAL", missing.success)
	}

	// A nil probe is the legacy path and must stay a no-op — including result,
	// which the type documents as nil-safe like every other method here.
	mp.noteRetainedLocked(entry, nil)
	var legacy *relayAdmissionProbe
	cause := txAdmitUnavailable("nil mempool")
	if got := legacy.result(selectRelayDisposition(cause, RelayAdmissionUnavailable)); got.Disposition != RelayAdmissionUnavailable || got.Err != error(cause) {
		t.Fatalf("nil probe result=%+v, want the producer's UNAVAILABLE and its error", got)
	}
	if got := legacy.result(nil); got.Disposition != RelayAdmissionInternal {
		t.Fatalf("nil probe with an unselected outcome=%v, want INTERNAL fail closed", got.Disposition)
	}
}

// TestRelayAdmissionDispositionDuplicateWtxidBranch covers the second duplicate
// branch: a candidate whose wtxid is already indexed under another txid. It is
// unreachable through two distinct signed candidates, so the index is seeded
// directly, exactly as the baseline wtxid test does.
func TestRelayAdmissionDispositionDuplicateWtxidBranch(t *testing.T) {
	h := newRelayHarness(t, nil, 1_000_000, 1_000_000)
	tx1 := h.tx(0, 100_000, 100_000, 1)
	if err := h.mp.AddRemoteTx(tx1); err != nil {
		t.Fatalf("seed AddRemoteTx: %v", err)
	}
	tx2 := h.tx(1, 100_000, 100_000, 2)
	_, tx2ID, tx2Wtxid, _, err := consensus.ParseTx(tx2)
	if err != nil {
		t.Fatalf("ParseTx(tx2): %v", err)
	}
	h.mp.mu.Lock()
	h.mp.wtxids[tx2Wtxid] = txID(t, tx1)
	h.mp.mu.Unlock()

	got := h.mp.AddRemoteTxForRelay(tx2, h.context())
	if got.Disposition != RelayAdmissionDuplicate {
		t.Fatalf("disposition=%v, want DUPLICATE (err=%v)", got.Disposition, got.Err)
	}
	if kind := admitKind(t, got.Err); kind != TxAdmitConflict {
		t.Fatalf("TxAdmitErrorKind=%q, want %q", kind, TxAdmitConflict)
	}
	if got.HasAdmissionContext {
		t.Fatal("a duplicate must never publish cache-authorizing context")
	}
	if got.TxID != tx2ID || got.WTxID != tx2Wtxid {
		t.Fatalf("identity=(%x,%x), want the producer-parsed (%x,%x)", got.TxID, got.WTxID, tx2ID, tx2Wtxid)
	}
	if h.mp.Contains(tx2ID) {
		t.Fatal("a duplicate candidate entered the mempool")
	}
}

// TestRelayAdmissionDispositionDuplicateTxidWithAlternateWtxid covers the mirror
// hostile row: a re-signed candidate carries the SAME txid under a different
// wtxid, and the resident-txid branch must keep winning over the wtxid branch.
func TestRelayAdmissionDispositionDuplicateTxidWithAlternateWtxid(t *testing.T) {
	h := newRelayHarness(t, nil, 1_000_000)
	first := h.tx(0, 100_000, 100_000, 1)
	second := h.tx(0, 100_000, 100_000, 1)
	if bytes.Equal(first, second) {
		t.Skip("signature backend is deterministic: no alternate witness representation available")
	}
	_, firstTxid, firstWtxid, _, err := consensus.ParseTx(first)
	if err != nil {
		t.Fatalf("ParseTx(first): %v", err)
	}
	_, secondTxid, secondWtxid, _, err := consensus.ParseTx(second)
	if err != nil {
		t.Fatalf("ParseTx(second): %v", err)
	}
	if firstTxid != secondTxid || firstWtxid == secondWtxid {
		t.Fatalf("fixture is not same-txid/alternate-wtxid: txids (%x,%x) wtxids (%x,%x)", firstTxid, secondTxid, firstWtxid, secondWtxid)
	}
	if err := h.mp.AddRemoteTx(first); err != nil {
		t.Fatalf("seed AddRemoteTx: %v", err)
	}

	got := h.mp.AddRemoteTxForRelay(second, h.context())
	if got.Disposition != RelayAdmissionDuplicate {
		t.Fatalf("disposition=%v, want DUPLICATE (err=%v)", got.Disposition, got.Err)
	}
	// The resident-txid branch owns this outcome, not the wtxid branch.
	if got.Err.Error() != "tx already in mempool" {
		t.Fatalf("message=%q, want the resident-txid branch's %q", got.Err.Error(), "tx already in mempool")
	}
	if kind := admitKind(t, got.Err); kind != TxAdmitConflict {
		t.Fatalf("TxAdmitErrorKind=%q, want %q", kind, TxAdmitConflict)
	}
	if got.WTxID != secondWtxid {
		t.Fatalf("WTxID=%x, want the producer-parsed %x", got.WTxID, secondWtxid)
	}
	if got.HasAdmissionContext {
		t.Fatal("a duplicate must never publish cache-authorizing context")
	}
}

// TestRelayAdmissionDispositionMixedViolations pins the disposition of
// candidates that violate TWO rules at once. The winner must be the branch the
// baseline validation order reaches first, unchanged by this surface.
func TestRelayAdmissionDispositionMixedViolations(t *testing.T) {
	t.Run("missing input plus malformed witness stays a dependency gap", func(t *testing.T) {
		h := newRelayHarness(t, nil, 1_000_000, 1_000_000)
		raw := corruptFirstWitnessSignature(t, h.tx(1, 100_000, 100_000, 1))
		delete(h.st.Utxos, h.outpoints[1])
		got := h.mp.AddRemoteTxForRelay(raw, h.context())
		if got.Disposition != RelayAdmissionMissingDependency {
			t.Fatalf("disposition=%v, want MISSING_DEPENDENCY (err=%v)", got.Disposition, got.Err)
		}
		if got.HasAdmissionContext {
			t.Fatal("a dependency gap must never publish cache-authorizing context")
		}
	})

	t.Run("below floor plus invalid signature keeps the cheap-floor precedence", func(t *testing.T) {
		h := newRelayHarness(t, nil, 1_000_000)
		raw := corruptFirstWitnessSignature(t, h.tx(0, 100_000, 100_000, 1))
		h.mp.SetCurrentMinFeeRateForTest(1 << 40)
		got := h.mp.AddRemoteTxForRelay(raw, h.context())
		if got.Disposition != RelayAdmissionRollingFloor {
			t.Fatalf("disposition=%v, want ROLLING_FLOOR (err=%v)", got.Disposition, got.Err)
		}
		if got.HasAdmissionContext {
			t.Fatal("a floor rejection must never publish cache-authorizing context")
		}
	})

	t.Run("below floor plus a shape the precheck defers on is stable terminal", func(t *testing.T) {
		h := newRelayHarness(t, nil, 1_000_000)
		// tx_nonce == 0 is a shape the cheap precheck refuses to decide, so the
		// slow path owns the outcome and reports terminal invalidity.
		raw := h.tx(0, 100_000, 100_000, 0)
		h.mp.SetCurrentMinFeeRateForTest(1 << 40)
		got := h.mp.AddRemoteTxForRelay(raw, h.context())
		if got.Disposition != RelayAdmissionStableTerminalReject {
			t.Fatalf("disposition=%v, want STABLE_TERMINAL_REJECT (err=%v)", got.Disposition, got.Err)
		}
		if !got.HasAdmissionContext {
			t.Fatal("a proven stable terminal rejection must publish its exact context")
		}
	})
}

// TestRelayAdmissionDispositionContextTransitionsNeverAuthorizeCaching walks the
// owner generations a tip comparison alone cannot see. An A-to-B-to-A reorg and
// an aborted transition both leave the stable tip equal and the generation past
// every earlier context, so a cached expected context must lose.
func TestRelayAdmissionDispositionContextTransitionsNeverAuthorizeCaching(t *testing.T) {
	t.Run("A to B to A with the same tip", func(t *testing.T) {
		h := newRelayHarness(t, nil, 1_000_000)
		raw := h.tx(0, 100_000, 100_000, 1)
		stale := h.context()

		owner := h.mp.PendingOutpointOwner()
		otherTip := PendingOutpointTip{HasTip: true, Height: 101, Hash: [32]byte{0x22}}
		if _, err := owner.beginTransition(); err != nil {
			t.Fatalf("beginTransition(B): %v", err)
		}
		if err := owner.commitStableTip(otherTip); err != nil {
			t.Fatalf("commitStableTip(B): %v", err)
		}
		if _, err := owner.beginTransition(); err != nil {
			t.Fatalf("beginTransition(A): %v", err)
		}
		if err := owner.commitStableTip(pendingOutpointTipOf(h.st)); err != nil {
			t.Fatalf("commitStableTip(A): %v", err)
		}

		current, ok := owner.AdmissionContext()
		if !ok {
			t.Fatal("owner admission context unavailable")
		}
		if current.StableTip != stale.StableTip {
			t.Fatalf("stable tip moved: got %+v, want the original %+v", current.StableTip, stale.StableTip)
		}
		if current.Generation == stale.Generation {
			t.Fatal("generation did not advance across the reorg")
		}

		before := mustSnapshot(t, h.mp)
		got := h.mp.AddRemoteTxForRelay(raw, stale)
		if got.Disposition != RelayAdmissionUnavailable {
			t.Fatalf("disposition=%v, want UNAVAILABLE (err=%v)", got.Disposition, got.Err)
		}
		if got.HasAdmissionContext {
			t.Fatal("a superseded context must never be published as cache authority")
		}
		// The owner refuses an unavailable binding before it scans for a
		// conflict and before it consumes a sequence: nothing moved at all.
		if after := mustSnapshot(t, h.mp); !reflect.DeepEqual(after, before) {
			t.Fatalf("superseded-context admission mutated state: before=%+v after=%+v", before, after)
		}
	})

	t.Run("superseded context loses to nothing at the conflict slot", func(t *testing.T) {
		h := newRelayHarness(t, nil, 1_000_000)
		if err := h.mp.AddRemoteTx(h.tx(0, 100_000, 100_000, 1)); err != nil {
			t.Fatalf("seed AddRemoteTx: %v", err)
		}
		conflicting := h.tx(0, 100_000, 200_000, 2)
		stale := h.context()
		h.advanceOwnerGeneration()

		// The SAME candidate is a live owner conflict. Availability is checked
		// first, so the superseded context wins over the conflict.
		got := h.mp.AddRemoteTxForRelay(conflicting, stale)
		if got.Disposition != RelayAdmissionUnavailable {
			t.Fatalf("disposition=%v, want UNAVAILABLE ahead of the conflict (err=%v)", got.Disposition, got.Err)
		}
		if got.HasAdmissionContext {
			t.Fatal("a superseded context must never be published as cache authority")
		}
		// With a current context the same candidate reaches the conflict.
		current := h.context()
		if again := h.mp.AddRemoteTxForRelay(conflicting, current); again.Disposition != RelayAdmissionConflict {
			t.Fatalf("disposition=%v with the current context, want CONFLICT (err=%v)", again.Disposition, again.Err)
		}
	})
}

// TestAddRemoteTxForRelayMatchesAddRemoteTxExactly proves the new entry point is
// a compatibility-preserving twin of AddRemoteTx: same public error kind and
// message, same residency, same admission counters, same rolling floor, same
// byte accounting, for accepted and rejected candidates alike.
func TestAddRemoteTxForRelayMatchesAddRemoteTxExactly(t *testing.T) {
	relay := newRelayHarness(t, nil, 1_000_000, 1_000_000)
	// The SAME candidate bytes drive both sides, so every public message —
	// including the ones that embed a conflicting txid — must compare equal.
	// testSpendableChainState is deterministic for a given address, so the
	// legacy twin starts from an identical, separately owned chainstate.
	legacySt, _ := testSpendableChainState(relay.fromAddr, []uint64{1_000_000, 1_000_000})
	legacyMp, err := NewMempool(legacySt, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new legacy mempool: %v", err)
	}

	accepted := relay.tx(0, 100_000, 100_000, 1)
	candidates := [][]byte{
		accepted,                         // accepted
		accepted,                         // duplicate txid
		relay.tx(0, 100_000, 200_000, 2), // owner conflict
		{0xFF, 0x00},                     // unparseable
		append(relay.tx(1, 100_000, 100_000, 3), 0x00),                    // trailing bytes
		corruptFirstWitnessSignature(t, relay.tx(1, 100_000, 100_000, 4)), // consensus-invalid
	}

	for i := range candidates {
		legacyErr := legacyMp.AddRemoteTx(candidates[i])
		result := relay.mp.AddRemoteTxForRelay(candidates[i], nil)

		switch {
		case legacyErr == nil && result.Err != nil:
			t.Fatalf("candidate %d: legacy accepted, relay returned %v", i, result.Err)
		case legacyErr != nil && result.Err == nil:
			t.Fatalf("candidate %d: legacy returned %v, relay accepted", i, legacyErr)
		case legacyErr != nil:
			if got, want := admitKind(t, result.Err), admitKind(t, legacyErr); got != want {
				t.Fatalf("candidate %d: relay kind=%q, want the legacy %q", i, got, want)
			}
			if got, want := result.Err.Error(), legacyErr.Error(); got != want {
				t.Fatalf("candidate %d: relay message=%q, want the legacy %q", i, got, want)
			}
		}
		if result.HasAdmissionContext {
			t.Fatalf("candidate %d: a nil expected context authorized caching", i)
		}
		if result.AdmissionContext != (PendingOutpointAdmissionContext{}) {
			t.Fatalf("candidate %d: a nil expected context published a context", i)
		}
	}

	if got, want := relay.mp.AdmissionCounts(), legacyMp.AdmissionCounts(); got != want {
		t.Fatalf("admission counters=%+v, want the legacy %+v", got, want)
	}
	if got, want := relay.mp.Stats(), legacyMp.Stats(); got != want {
		t.Fatalf("mempool stats=%+v, want the legacy %+v", got, want)
	}
	if got, want := relay.mp.Len(), legacyMp.Len(); got != want {
		t.Fatalf("mempool len=%d, want the legacy %d", got, want)
	}
	relay.mp.mu.RLock()
	relaySeq := relay.mp.lastAdmissionSeq
	relay.mp.mu.RUnlock()
	legacyMp.mu.RLock()
	legacySeq := legacyMp.lastAdmissionSeq
	legacyMp.mu.RUnlock()
	if relaySeq != legacySeq {
		t.Fatalf("lastAdmissionSeq=%d, want the legacy %d", relaySeq, legacySeq)
	}
}

// TestAddRemoteTxForRelayValidatesExpectedContextAtTheOwnerSeam pins the
// ordering clause: a supplied expected context is validated AT the owner seam
// and never earlier, so it cannot preempt the baseline parse or duplicate
// precedence — and validating it mutates nothing.
func TestAddRemoteTxForRelayValidatesExpectedContextAtTheOwnerSeam(t *testing.T) {
	t.Run("parse precedes the context check", func(t *testing.T) {
		h := newRelayHarness(t, nil, 1_000_000)
		stale := h.context()
		h.advanceOwnerGeneration()
		before := mustSnapshot(t, h.mp)

		got := h.mp.AddRemoteTxForRelay([]byte{0xFF, 0x00, 0x13, 0x37}, stale)
		if got.Disposition != RelayAdmissionStableTerminalReject {
			t.Fatalf("disposition=%v, want STABLE_TERMINAL_REJECT ahead of the context check (err=%v)", got.Disposition, got.Err)
		}
		if got.HasAdmissionContext {
			t.Fatal("a superseded context must not be published for the parse rejection")
		}
		if after := mustSnapshot(t, h.mp); !reflect.DeepEqual(after, before) {
			t.Fatalf("classification mutated state: before=%+v after=%+v", before, after)
		}
	})

	t.Run("the duplicate slot precedes the context check", func(t *testing.T) {
		h := newRelayHarness(t, nil, 1_000_000)
		raw := h.tx(0, 100_000, 100_000, 1)
		if err := h.mp.AddRemoteTx(raw); err != nil {
			t.Fatalf("seed AddRemoteTx: %v", err)
		}
		stale := h.context()
		h.advanceOwnerGeneration()

		got := h.mp.AddRemoteTxForRelay(raw, stale)
		if got.Disposition != RelayAdmissionDuplicate {
			t.Fatalf("disposition=%v, want DUPLICATE ahead of the context check (err=%v)", got.Disposition, got.Err)
		}
	})

	t.Run("an unavailable owner context is not proven and admits nothing", func(t *testing.T) {
		h := newRelayHarness(t, nil, 1_000_000)
		raw := h.tx(0, 100_000, 100_000, 1)
		expected := h.context()
		if _, err := h.mp.PendingOutpointOwner().beginTransition(); err != nil {
			t.Fatalf("beginTransition: %v", err)
		}
		got := h.mp.AddRemoteTxForRelay(raw, expected)
		if got.Disposition != RelayAdmissionUnavailable {
			t.Fatalf("disposition=%v, want UNAVAILABLE (err=%v)", got.Disposition, got.Err)
		}
		if got.HasAdmissionContext {
			t.Fatal("an active transition must never publish cache authority")
		}
		if h.mp.Len() != 0 {
			t.Fatal("a candidate entered the mempool during an active owner transition")
		}
	})

	t.Run("an input-less candidate still validates the supplied context", func(t *testing.T) {
		h := newRelayHarness(t, nil, 1_000_000)
		stale := h.context()
		h.advanceOwnerGeneration()

		entry := &mempoolEntry{txid: [32]byte{0x71}, wtxid: [32]byte{0x72}, weight: 1, size: 1}
		probe := &relayAdmissionProbe{expected: stale}
		h.mp.mu.Lock()
		err := h.mp.reserveEntryInputsLocked(entry, probe)
		h.mp.mu.Unlock()
		if err == nil {
			t.Fatal("a superseded context must not pass the input-less seam")
		}
		if got := relayDispositionOf(err); got != RelayAdmissionUnavailable {
			t.Fatalf("disposition=%v, want UNAVAILABLE", got)
		}
		if entry.token != (PendingOutpointToken{}) {
			t.Fatal("the input-less seam issued a token")
		}

		// The current context passes, and a nil probe keeps the baseline no-op.
		probe = &relayAdmissionProbe{expected: h.context()}
		h.mp.mu.Lock()
		err = h.mp.reserveEntryInputsLocked(entry, probe)
		if err == nil {
			err = h.mp.reserveEntryInputsLocked(entry, nil)
		}
		h.mp.mu.Unlock()
		if err != nil {
			t.Fatalf("input-less seam with the current context: %v", err)
		}
	})

	t.Run("the input-less seam refuses a nil owner exactly as the sibling does", func(t *testing.T) {
		// A bare Mempool value has no owner at all, so the owner's admission
		// context is unavailable — the same first check the input-bearing
		// sibling runs, and the shape a nil owner can only take.
		h := newRelayHarness(t, nil, 1_000_000)
		expected := h.context()
		bare := &Mempool{}
		entry := &mempoolEntry{txid: [32]byte{0x81}, wtxid: [32]byte{0x82}, weight: 1, size: 1}
		probe := &relayAdmissionProbe{expected: expected}
		bare.mu.Lock()
		err := bare.reserveEntryInputsLocked(entry, probe)
		bare.mu.Unlock()
		if err == nil {
			t.Fatal("a nil owner must not pass the input-less seam")
		}
		if got := relayDispositionOf(err); got != RelayAdmissionUnavailable {
			t.Fatalf("disposition=%v, want UNAVAILABLE", got)
		}
		if got, want := err.Error(), "pending-outpoint owner admission context unavailable"; got != want {
			t.Fatalf("message=%q, want the sibling's %q", got, want)
		}
		if bare.pendingOutpoints != nil {
			t.Fatal("classifying created an owner")
		}
	})

	t.Run("the input-less seam refuses an owner tip that left the guarded chainstate tip", func(t *testing.T) {
		// The input-bearing sibling refuses this shape (mempool_policy.go's
		// reserveEntryInputsLocked tip check); the input-less seam must refuse
		// it identically, or a candidate that claims no outpoint would pass
		// what every other candidate is held to.
		h := newRelayHarness(t, nil, 1_000_000)
		expected := h.context()
		h.st.Height = 101

		entry := &mempoolEntry{txid: [32]byte{0x91}, wtxid: [32]byte{0x92}, weight: 1, size: 1}
		probe := &relayAdmissionProbe{expected: expected}
		h.mp.mu.Lock()
		err := h.mp.reserveEntryInputsLocked(entry, probe)
		h.mp.mu.Unlock()
		if err == nil {
			t.Fatal("an owner tip behind the guarded chainstate tip must not pass the input-less seam")
		}
		if got := relayDispositionOf(err); got != RelayAdmissionUnavailable {
			t.Fatalf("disposition=%v, want UNAVAILABLE", got)
		}
		if got, want := err.Error(), "pending-outpoint owner tip does not match the guarded chainstate tip"; got != want {
			t.Fatalf("message=%q, want the sibling's %q", got, want)
		}
	})
}

// TestAddRemoteTxForRelayNilReceiverIsUnavailable pins the nil-receiver contract
// shared with every other exported Mempool accessor: a typed unavailable result,
// no panic, and no counter movement.
func TestAddRemoteTxForRelayNilReceiverIsUnavailable(t *testing.T) {
	var mp *Mempool
	got := mp.AddRemoteTxForRelay([]byte{0x01}, nil)
	if got.Disposition != RelayAdmissionUnavailable {
		t.Fatalf("disposition=%v, want UNAVAILABLE", got.Disposition)
	}
	if kind := admitKind(t, got.Err); kind != TxAdmitUnavailable {
		t.Fatalf("TxAdmitErrorKind=%q, want %q", kind, TxAdmitUnavailable)
	}
	if got.Err.Error() != "nil mempool" {
		t.Fatalf("message=%q, want the legacy %q", got.Err.Error(), "nil mempool")
	}
	if got.TxID != ([32]byte{}) || got.HasAdmissionContext {
		t.Fatalf("nil receiver published identity or context: %+v", got)
	}
	if counts := mp.AdmissionCounts(); counts != (MempoolAdmissionCounts{}) {
		t.Fatalf("nil receiver moved counters: %+v", counts)
	}
}
