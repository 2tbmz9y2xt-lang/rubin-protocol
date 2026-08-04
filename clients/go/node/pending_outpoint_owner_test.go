package node

import (
	"errors"
	"sync"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func testOutpoint(vout uint32) consensus.Outpoint {
	return consensus.Outpoint{Txid: [32]byte{0xaa}, Vout: vout}
}

func testOwnerKind(t *testing.T, err error) PendingOutpointErrorKind {
	t.Helper()
	var ownerErr *PendingOutpointError
	if !errors.As(err, &ownerErr) {
		t.Fatalf("error %v is not a *PendingOutpointError", err)
	}
	return ownerErr.Kind
}

func mustReserve(t *testing.T, o *PendingOutpointOwner, txid [32]byte, inputs ...consensus.Outpoint) PendingOutpointToken {
	t.Helper()
	token, err := o.Reserve(o.stableTip, PendingOutpointStandardMempool, txid, inputs)
	if err != nil {
		t.Fatalf("Reserve(%x): %v", txid, err)
	}
	return token
}

// TestPendingOutpointOwnerReserveInstallsCompleteClaim pins the accepted rows:
// one-input and many-input reservations install a complete claim preserving
// canonical input order and consume exactly one sequence each.
func TestPendingOutpointOwnerReserveInstallsCompleteClaim(t *testing.T) {
	owner := newPendingOutpointOwner(PendingOutpointTip{})
	inputs := []consensus.Outpoint{testOutpoint(3), testOutpoint(1), testOutpoint(2)}
	token := mustReserve(t, owner, [32]byte{0x01}, inputs...)
	if token.owner != owner || token.seq != 1 || owner.tokenHighWater != 1 {
		t.Fatalf("token seq=%d high_water=%d, want seq 1 from this owner", token.seq, owner.tokenHighWater)
	}
	claim := owner.byToken[token]
	if claim == nil || claim.finalized || claim.domain != PendingOutpointStandardMempool {
		t.Fatalf("claim=%+v, want a reserved standard claim", claim)
	}
	for i, op := range inputs {
		if claim.inputs[i] != op {
			t.Fatalf("claim input %d = %v, want caller order %v", i, claim.inputs[i], op)
		}
		if got, ok := owner.txidForOutpoint(op); !ok || got != claim.txid {
			t.Fatalf("index row for %v = (%x,%v), want txid %x", op, got, ok, claim.txid)
		}
	}
	if single := mustReserve(t, owner, [32]byte{0x02}, testOutpoint(9)); single.seq != 2 {
		t.Fatalf("second reservation seq=%d, want 2", single.seq)
	}
}

// TestPendingOutpointOwnerReserveRejectionsMutateNothing pins every rejected
// Reserve row, its error kind, and the no-mutation / no-sequence-consumed rule.
// Malformed requests are internal; a closed owner is unavailable.
func TestPendingOutpointOwnerReserveRejectionsMutateNothing(t *testing.T) {
	otherTip := PendingOutpointTip{HasTip: true, Height: 7, Hash: [32]byte{0x77}}
	cases := []struct {
		name   string
		setup  func(o *PendingOutpointOwner)
		tip    PendingOutpointTip
		domain PendingOutpointDomain
		txid   [32]byte
		inputs []consensus.Outpoint
		want   PendingOutpointErrorKind
	}{
		{"invalid domain", nil, PendingOutpointTip{}, PendingOutpointDomain(0), [32]byte{0x01}, []consensus.Outpoint{testOutpoint(1)}, PendingOutpointInternal},
		{"zero txid", nil, PendingOutpointTip{}, PendingOutpointStandardMempool, [32]byte{}, []consensus.Outpoint{testOutpoint(1)}, PendingOutpointInternal},
		{"empty input set", nil, PendingOutpointTip{}, PendingOutpointStandardMempool, [32]byte{0x01}, nil, PendingOutpointInternal},
		{"duplicate input", nil, PendingOutpointTip{}, PendingOutpointStandardMempool, [32]byte{0x01}, []consensus.Outpoint{testOutpoint(1), testOutpoint(1)}, PendingOutpointInternal},
		{"expected tip mismatch", nil, otherTip, PendingOutpointStandardMempool, [32]byte{0x01}, []consensus.Outpoint{testOutpoint(1)}, PendingOutpointUnavailable},
		{
			"active transition",
			func(o *PendingOutpointOwner) {
				if _, err := o.beginTransition(); err != nil {
					t.Fatalf("beginTransition: %v", err)
				}
			},
			PendingOutpointTip{},
			PendingOutpointStandardMempool,
			[32]byte{0x01},
			[]consensus.Outpoint{testOutpoint(1)},
			PendingOutpointUnavailable,
		},
		{
			"token sequence exhausted",
			func(o *PendingOutpointOwner) { o.tokenHighWater = ^uint64(0) },
			PendingOutpointTip{},
			PendingOutpointStandardMempool,
			[32]byte{0x01},
			[]consensus.Outpoint{testOutpoint(1)},
			PendingOutpointUnavailable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			owner := newPendingOutpointOwner(PendingOutpointTip{})
			if tc.setup != nil {
				tc.setup(owner)
			}
			highWater, generation := owner.tokenHighWater, owner.generation
			token, err := owner.Reserve(tc.tip, tc.domain, tc.txid, tc.inputs)
			if err == nil {
				t.Fatalf("Reserve accepted %s", tc.name)
			}
			if got := testOwnerKind(t, err); got != tc.want {
				t.Fatalf("kind=%d, want %d", got, tc.want)
			}
			if (token != PendingOutpointToken{}) || len(owner.byOutpoint) != 0 || len(owner.byToken) != 0 {
				t.Fatalf("rejected Reserve mutated owner state: outpoints=%d claims=%d", len(owner.byOutpoint), len(owner.byToken))
			}
			if owner.tokenHighWater != highWater || owner.generation != generation {
				t.Fatalf("high_water=%d gen=%d, want %d/%d", owner.tokenHighWater, owner.generation, highWater, generation)
			}
		})
	}
	t.Run("nil owner", func(t *testing.T) {
		var owner *PendingOutpointOwner
		_, err := owner.Reserve(PendingOutpointTip{}, PendingOutpointStandardMempool, [32]byte{0x01}, []consensus.Outpoint{testOutpoint(1)})
		if testOwnerKind(t, err) != PendingOutpointInternal {
			t.Fatalf("nil owner Reserve = %v, want internal", err)
		}
	})
}

// TestPendingOutpointOwnerConflictReportsFirstInputAndInstallsNothing pins the
// first-conflict rule: the scan follows the supplied slice order, reports that
// exact input index and the claiming txid, and leaves no partial claim behind
// even when the conflicting input is the last one.
func TestPendingOutpointOwnerConflictReportsFirstInputAndInstallsNothing(t *testing.T) {
	owner := newPendingOutpointOwner(PendingOutpointTip{})
	first := mustReserve(t, owner, [32]byte{0x01}, testOutpoint(5))
	highWater := owner.tokenHighWater

	_, err := owner.Reserve(PendingOutpointTip{}, PendingOutpointStandardMempool, [32]byte{0x02},
		[]consensus.Outpoint{testOutpoint(1), testOutpoint(2), testOutpoint(5)})
	var ownerErr *PendingOutpointError
	if !errors.As(err, &ownerErr) || ownerErr.Kind != PendingOutpointConflict {
		t.Fatalf("late-input conflict = %v, want conflict", err)
	}
	if ownerErr.InputIndex != 2 || ownerErr.Outpoint != testOutpoint(5) || ownerErr.ExistingTxid != [32]byte{0x01} {
		t.Fatalf("conflict evidence=%+v, want index 2 on outpoint 5 held by 0x01", ownerErr)
	}
	if len(owner.byOutpoint) != 1 || owner.tokenHighWater != highWater {
		t.Fatalf("conflict installed a partial claim: outpoints=%d high_water=%d", len(owner.byOutpoint), owner.tokenHighWater)
	}
	if _, taken := owner.txidForOutpoint(testOutpoint(1)); taken {
		t.Fatal("conflicting request claimed its earlier inputs")
	}
	if err := owner.Release(first); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := owner.Reserve(PendingOutpointTip{}, PendingOutpointStandardMempool, [32]byte{0x02},
		[]consensus.Outpoint{testOutpoint(1), testOutpoint(2), testOutpoint(5)}); err != nil {
		t.Fatalf("Reserve after release: %v", err)
	}
}

// TestPendingOutpointOwnerFinalizeAndReleaseSemantics pins the retry rows and
// every rejected token row for both terminal operations.
func TestPendingOutpointOwnerFinalizeAndReleaseSemantics(t *testing.T) {
	owner := newPendingOutpointOwner(PendingOutpointTip{})
	token := mustReserve(t, owner, [32]byte{0x01}, testOutpoint(1), testOutpoint(2))

	if err := owner.Finalize(token); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if err := owner.Finalize(token); err != nil {
		t.Fatalf("exact Finalize retry: %v", err)
	}
	if !owner.byToken[token].finalized || len(owner.byOutpoint) != 2 {
		t.Fatalf("Finalize retry mutated state: outpoints=%d", len(owner.byOutpoint))
	}

	foreign := newPendingOutpointOwner(PendingOutpointTip{})
	foreignToken := mustReserve(t, foreign, [32]byte{0x09}, testOutpoint(1))
	badTokens := map[string]PendingOutpointToken{
		"zero token":       {},
		"foreign owner":    foreignToken,
		"above high-water": {owner: owner, seq: owner.tokenHighWater + 1},
	}
	for name, bad := range badTokens {
		if got := testOwnerKind(t, owner.Finalize(bad)); got != PendingOutpointInternal {
			t.Fatalf("Finalize(%s) kind=%d, want internal", name, got)
		}
		if got := testOwnerKind(t, owner.Release(bad)); got != PendingOutpointInternal {
			t.Fatalf("Release(%s) kind=%d, want internal", name, got)
		}
	}

	// Partial live mismatch: one row was overwritten, so the release must
	// delete nothing at all.
	owner.byOutpoint[testOutpoint(2)] = pendingOutpointRow{token: PendingOutpointToken{owner: owner, seq: 2}, txid: [32]byte{0xff}}
	if got := testOwnerKind(t, owner.Release(token)); got != PendingOutpointInternal {
		t.Fatalf("partial-mismatch Release kind=%d, want internal", got)
	}
	if _, ok := owner.byOutpoint[testOutpoint(1)]; !ok {
		t.Fatal("partial-mismatch Release deleted a row")
	}
	owner.byOutpoint[testOutpoint(2)] = pendingOutpointRow{token: token, txid: [32]byte{0x01}}

	if err := owner.Release(token); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if err := owner.Release(token); err != nil {
		t.Fatalf("exact Release retry: %v", err)
	}
	if len(owner.byOutpoint) != 0 || len(owner.byToken) != 0 {
		t.Fatalf("release left state: outpoints=%d claims=%d", len(owner.byOutpoint), len(owner.byToken))
	}
	if got := testOwnerKind(t, owner.Finalize(token)); got != PendingOutpointUnavailable {
		t.Fatalf("Finalize after release kind=%d, want unavailable", got)
	}
}

// TestPendingOutpointOwnerTransitionClosesPublicationAndKeepsHighWaters pins
// the transition rows: Reserve and Finalize are unavailable while a transition
// is active, exact Release stays valid, an old-generation Finalize publishes
// nothing, and an abort keeps both high-waters advanced.
func TestPendingOutpointOwnerTransitionClosesPublicationAndKeepsHighWaters(t *testing.T) {
	owner := newPendingOutpointOwner(PendingOutpointTip{})
	reserved := mustReserve(t, owner, [32]byte{0x01}, testOutpoint(1))
	snapshot := owner.snapshot()

	generation, err := owner.beginTransition()
	if err != nil || generation != 1 {
		t.Fatalf("beginTransition=(%d,%v), want generation 1", generation, err)
	}
	if _, err := owner.beginTransition(); testOwnerKind(t, err) != PendingOutpointUnavailable {
		t.Fatalf("re-entrant beginTransition = %v, want unavailable", err)
	}
	if got := testOwnerKind(t, owner.Finalize(reserved)); got != PendingOutpointUnavailable {
		t.Fatalf("Finalize during transition kind=%d, want unavailable", got)
	}
	if owner.byToken[reserved].finalized {
		t.Fatal("Finalize during transition published the claim")
	}
	if err := owner.Release(reserved); err != nil {
		t.Fatalf("exact Release during transition: %v", err)
	}

	owner.mu.Lock()
	candidate, restoreErr := owner.buildRestoreLocked(snapshot)
	if restoreErr == nil {
		owner.publishRestoreLocked(snapshot, candidate)
	}
	owner.mu.Unlock()
	if restoreErr != nil {
		t.Fatalf("buildRestoreLocked: %v", restoreErr)
	}
	owner.endTransitionAborted()
	if owner.tokenHighWater != 1 || owner.generation != 1 {
		t.Fatalf("abort regressed high-waters: token=%d gen=%d", owner.tokenHighWater, owner.generation)
	}
	if got := testOwnerKind(t, owner.Finalize(reserved)); got != PendingOutpointUnavailable {
		t.Fatalf("old-generation Finalize kind=%d, want unavailable", got)
	}
	if owner.byToken[reserved].finalized {
		t.Fatal("old-generation Finalize published the claim")
	}
	next := mustReserve(t, owner, [32]byte{0x02}, testOutpoint(2))
	if next.seq != 2 {
		t.Fatalf("post-abort reservation seq=%d, want 2 (no sequence reuse)", next.seq)
	}
}

// TestPendingOutpointOwnerAdmissionContext pins the read-only downstream seam:
// the exact stable tip paired with the current generation while stable, and a
// fail-closed unavailable result for a nil owner, an active transition, or an
// exhausted generation space. It also pins the cache-validity property the seam
// exists for — the initial context and every begun transition carry distinct
// generations, and neither a commit back to an earlier tip (A->B->A) nor an
// aborted transition can reproduce an earlier context.
func TestPendingOutpointOwnerAdmissionContext(t *testing.T) {
	tipA := PendingOutpointTip{HasTip: true, Height: 4, Hash: [32]byte{0x0a}}
	tipB := PendingOutpointTip{HasTip: true, Height: 5, Hash: [32]byte{0x0b}}

	var nilOwner *PendingOutpointOwner
	if ctx, ok := nilOwner.AdmissionContext(); ok {
		t.Fatalf("nil owner reported %+v, want unavailable", ctx)
	}

	owner := newPendingOutpointOwner(tipA)
	initial, ok := owner.AdmissionContext()
	if !ok || initial != (PendingOutpointAdmissionContext{StableTip: tipA, Generation: 0}) {
		t.Fatalf("initial context=(%+v,%v), want stable tipA at generation 0", initial, ok)
	}
	// A reservation is not an observable canonical move: same context.
	token := mustReserve(t, owner, [32]byte{0x01}, testOutpoint(1))
	if again, ok := owner.AdmissionContext(); !ok || again != initial {
		t.Fatalf("context after Reserve=(%+v,%v), want %+v unchanged", again, ok, initial)
	}
	if err := owner.Finalize(token); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	// A->B: a begun transition is unavailable, and its commit publishes the new
	// tip on a fresh generation.
	if _, err := owner.beginTransition(); err != nil {
		t.Fatalf("beginTransition(A->B): %v", err)
	}
	if ctx, ok := owner.AdmissionContext(); ok {
		t.Fatalf("context during transition=%+v, want unavailable", ctx)
	}
	if err := owner.commitStableTip(tipB); err != nil {
		t.Fatalf("commitStableTip(B): %v", err)
	}
	atB, ok := owner.AdmissionContext()
	if !ok || atB != (PendingOutpointAdmissionContext{StableTip: tipB, Generation: 1}) {
		t.Fatalf("context at B=(%+v,%v), want tipB at generation 1", atB, ok)
	}

	// B->A: the tip is identical to the initial one, the generation is not, so a
	// generation-keyed cache cannot mistake this for the pre-reorg context.
	if _, err := owner.beginTransition(); err != nil {
		t.Fatalf("beginTransition(B->A): %v", err)
	}
	if err := owner.commitStableTip(tipA); err != nil {
		t.Fatalf("commitStableTip(A): %v", err)
	}
	backAtA, ok := owner.AdmissionContext()
	if !ok || backAtA.StableTip != tipA || backAtA.Generation != 2 {
		t.Fatalf("context back at A=(%+v,%v), want tipA at generation 2", backAtA, ok)
	}
	if backAtA == initial {
		t.Fatal("A->B->A reproduced the pre-reorg admission context")
	}

	// A failed transition keeps the tip and still advances the generation.
	if _, err := owner.beginTransition(); err != nil {
		t.Fatalf("beginTransition(failed): %v", err)
	}
	owner.endTransitionAborted()
	afterAbort, ok := owner.AdmissionContext()
	if !ok || afterAbort.StableTip != tipA || afterAbort.Generation != 3 {
		t.Fatalf("context after abort=(%+v,%v), want tipA at generation 3", afterAbort, ok)
	}

	// Generation exhaustion is fail-closed: no further transition can be
	// distinguished, so no context is reported at all.
	owner.mu.Lock()
	owner.generation = ^uint64(0)
	owner.mu.Unlock()
	if ctx, ok := owner.AdmissionContext(); ok {
		t.Fatalf("exhausted generation reported %+v, want unavailable", ctx)
	}
}

// TestPendingOutpointOwnerAdmissionContextRacingTransitionBeginIsNeverInconsistent
// pins the hostile row: a reader racing a transition begin observes either the
// prior stable context or unavailability, never a stable context paired with an
// active transition, and never the fresh generation before the transition ends.
func TestPendingOutpointOwnerAdmissionContextRacingTransitionBeginIsNeverInconsistent(t *testing.T) {
	tip := PendingOutpointTip{HasTip: true, Height: 9, Hash: [32]byte{0x09}}
	for round := 0; round < 64; round++ {
		owner := newPendingOutpointOwner(tip)
		var wg sync.WaitGroup
		wg.Add(2)
		var observed PendingOutpointAdmissionContext
		var available bool
		go func() { defer wg.Done(); observed, available = owner.AdmissionContext() }()
		go func() {
			defer wg.Done()
			if _, err := owner.beginTransition(); err != nil {
				t.Errorf("beginTransition: %v", err)
			}
		}()
		wg.Wait()
		if available && observed != (PendingOutpointAdmissionContext{StableTip: tip, Generation: 0}) {
			t.Fatalf("round %d: observed %+v, want the prior stable context or unavailable", round, observed)
		}
		// The transition is still active, so the reader is closed out now
		// regardless of which side won the race.
		if ctx, ok := owner.AdmissionContext(); ok {
			t.Fatalf("round %d: context %+v available during the active transition", round, ctx)
		}
	}
}

// TestPendingOutpointOwnerRestoreRejectsInconsistentSnapshots pins all three
// snapshot rejection rows — a foreign token, a duplicate outpoint, and a
// sequence above the snapshot's own high-water — and proves a refused restore
// publishes no map.
func TestPendingOutpointOwnerRestoreRejectsInconsistentSnapshots(t *testing.T) {
	owner := newPendingOutpointOwner(PendingOutpointTip{})
	foreign := newPendingOutpointOwner(PendingOutpointTip{})
	dup := testOutpoint(1)
	cases := map[string]pendingOutpointSnapshot{
		"foreign token": {
			claims:         []pendingOutpointClaim{{token: PendingOutpointToken{owner: foreign, seq: 1}, domain: PendingOutpointStandardMempool, txid: [32]byte{0x01}, inputs: []consensus.Outpoint{dup}}},
			tokenHighWater: 1,
		},
		"duplicate outpoint": {
			claims: []pendingOutpointClaim{
				{token: PendingOutpointToken{owner: owner, seq: 1}, domain: PendingOutpointStandardMempool, txid: [32]byte{0x01}, inputs: []consensus.Outpoint{dup}},
				{token: PendingOutpointToken{owner: owner, seq: 2}, domain: PendingOutpointStandardMempool, txid: [32]byte{0x02}, inputs: []consensus.Outpoint{dup}},
			},
			tokenHighWater: 2,
		},
		"sequence above snapshot high-water": {
			claims:         []pendingOutpointClaim{{token: PendingOutpointToken{owner: owner, seq: 4}, domain: PendingOutpointStandardMempool, txid: [32]byte{0x01}, inputs: []consensus.Outpoint{dup}}},
			tokenHighWater: 1,
		},
	}
	for name, snap := range cases {
		t.Run(name, func(t *testing.T) {
			owner.mu.Lock()
			_, err := owner.buildRestoreLocked(snap)
			owner.mu.Unlock()
			if testOwnerKind(t, err) != PendingOutpointInternal {
				t.Fatalf("buildRestoreLocked accepted %s: %v", name, err)
			}
			if len(owner.byOutpoint) != 0 {
				t.Fatalf("refused restore published %d rows", len(owner.byOutpoint))
			}
		})
	}
}

// TestPendingOutpointOwnerDomainsShareOneAuthority proves the DA domain value
// exists, reserves through the same single owner, and creates no separate DA
// record or index: a DA claim occupies the same by-outpoint authority a
// standard claim does, so the two can never both hold one outpoint.
func TestPendingOutpointOwnerDomainsShareOneAuthority(t *testing.T) {
	owner := newPendingOutpointOwner(PendingOutpointTip{})
	daToken, err := owner.Reserve(PendingOutpointTip{}, PendingOutpointDA, [32]byte{0xda}, []consensus.Outpoint{testOutpoint(1)})
	if err != nil {
		t.Fatalf("DA Reserve: %v", err)
	}
	if _, err := owner.Reserve(PendingOutpointTip{}, PendingOutpointStandardMempool, [32]byte{0x01}, []consensus.Outpoint{testOutpoint(1)}); testOwnerKind(t, err) != PendingOutpointConflict {
		t.Fatalf("standard Reserve over a DA claim = %v, want conflict", err)
	}
	// A DA claim is not a standard record: the standard binding check refuses
	// to bind it to a mempool entry.
	owner.mu.Lock()
	bindErr := owner.validateEntryClaimLocked([32]byte{0xda}, []consensus.Outpoint{testOutpoint(1)}, daToken, false)
	owner.mu.Unlock()
	if testOwnerKind(t, bindErr) != PendingOutpointInternal {
		t.Fatalf("DA claim bound as a standard record: %v", bindErr)
	}
}

// TestPendingOutpointOwnerConcurrentContendersProduceOneWinner runs the two
// concurrent-Reserve rows under -race: two contenders sharing an input in either
// schedule yield exactly one complete winner and one complete loser, and
// contenders over independent outpoints all admit.
func TestPendingOutpointOwnerConcurrentContendersProduceOneWinner(t *testing.T) {
	for round := 0; round < 64; round++ {
		owner := newPendingOutpointOwner(PendingOutpointTip{})
		shared := testOutpoint(1)
		var mu sync.Mutex
		winners := 0
		conflicts := 0
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				txid := [32]byte{byte(0x10 + i)}
				_, err := owner.Reserve(PendingOutpointTip{}, PendingOutpointStandardMempool, txid,
					[]consensus.Outpoint{shared, testOutpoint(uint32(100 + i))})
				var ownerErr *PendingOutpointError
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					winners++
				case errors.As(err, &ownerErr) && ownerErr.Kind == PendingOutpointConflict:
					conflicts++
				default:
					// t.Errorf, never t.Fatalf: runtime.Goexit from a spawned
					// goroutine would abandon the WaitGroup.
					t.Errorf("round %d: unexpected contender error: %v", round, err)
				}
			}(i)
		}
		wg.Wait()
		if winners != 1 || conflicts != 1 {
			t.Fatalf("round %d: winners=%d conflicts=%d, want exactly one of each", round, winners, conflicts)
		}
		// The loser installed nothing, so only the winner's two inputs are held.
		if len(owner.byOutpoint) != 2 || len(owner.byToken) != 1 {
			t.Fatalf("round %d: outpoints=%d claims=%d, want a single complete winner", round, len(owner.byOutpoint), len(owner.byToken))
		}
	}
	t.Run("independent outpoints admit concurrently", func(t *testing.T) {
		const contenders = 8
		owner := newPendingOutpointOwner(PendingOutpointTip{})
		var wg sync.WaitGroup
		for i := 0; i < contenders; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if _, err := owner.Reserve(PendingOutpointTip{}, PendingOutpointStandardMempool,
					[32]byte{byte(0x20 + i)}, []consensus.Outpoint{testOutpoint(uint32(200 + i))}); err != nil {
					t.Errorf("independent contender %d: %v", i, err)
				}
			}(i)
		}
		wg.Wait()
		if len(owner.byOutpoint) != contenders || len(owner.byToken) != contenders || owner.tokenHighWater != contenders {
			t.Fatalf("outpoints=%d claims=%d high_water=%d, want %d of each",
				len(owner.byOutpoint), len(owner.byToken), owner.tokenHighWater, contenders)
		}
	})
}

// TestPendingOutpointOwnerStaleReleaseCannotDeleteNewerClaim pins the hostile
// row from both directions: through the public API, where a release issued for
// an already-dropped claim races a newer claim over the same outpoint, and
// directly against the compare-delete guard that makes it safe.
func TestPendingOutpointOwnerStaleReleaseCannotDeleteNewerClaim(t *testing.T) {
	for round := 0; round < 64; round++ {
		owner := newPendingOutpointOwner(PendingOutpointTip{})
		shared := testOutpoint(1)
		stale := mustReserve(t, owner, [32]byte{0x01}, shared)
		if err := owner.Release(stale); err != nil {
			t.Fatalf("Release: %v", err)
		}
		newer := mustReserve(t, owner, [32]byte{0x02}, shared)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = owner.Release(stale) }()
		go func() { defer wg.Done(); _ = owner.Finalize(newer) }()
		wg.Wait()
		got, ok := owner.txidForOutpoint(shared)
		if !ok || got != [32]byte{0x02} {
			t.Fatalf("round %d: stale release deleted the newer claim (got %x ok=%v)", round, got, ok)
		}
	}

	// The loop above exits Release early: the stale claim is gone from byToken,
	// so claimForToken returns (nil, nil) and dropClaimLocked is never entered.
	// Its compare-delete guard is unreachable through the public API — Release's
	// own row check rejects a partially owned claim first — so it is pinned
	// directly. Deleting `row.token == token` fails this assertion.
	owner := newPendingOutpointOwner(PendingOutpointTip{})
	shared := testOutpoint(1)
	stale := mustReserve(t, owner, [32]byte{0x01}, shared)
	owner.mu.Lock()
	newer := PendingOutpointToken{owner: owner, seq: owner.tokenHighWater + 1}
	owner.byOutpoint[shared] = pendingOutpointRow{token: newer, txid: [32]byte{0x02}}
	owner.dropClaimLocked(stale)
	row, ok := owner.byOutpoint[shared]
	_, staleLive := owner.byToken[stale]
	owner.mu.Unlock()
	if !ok || row.token != newer {
		t.Fatalf("dropClaimLocked deleted a row owned by a newer token: row=%+v ok=%v", row, ok)
	}
	if staleLive {
		t.Fatal("dropClaimLocked left the stale claim live")
	}
}

// TestPendingOutpointOwnerFinalizeRacingTransitionBeginPublishesNothingStale
// pins the hostile row: a Finalize concurrent with a transition begin either
// wins before the generation advances or is refused; it never publishes a claim
// bound to the superseded generation.
func TestPendingOutpointOwnerFinalizeRacingTransitionBeginPublishesNothingStale(t *testing.T) {
	for round := 0; round < 64; round++ {
		owner := newPendingOutpointOwner(PendingOutpointTip{})
		token := mustReserve(t, owner, [32]byte{0x01}, testOutpoint(1))
		var wg sync.WaitGroup
		wg.Add(2)
		var finalizeErr error
		go func() { defer wg.Done(); finalizeErr = owner.Finalize(token) }()
		go func() {
			defer wg.Done()
			if _, err := owner.beginTransition(); err != nil {
				t.Errorf("beginTransition: %v", err)
			}
		}()
		wg.Wait()
		owner.mu.Lock()
		published := owner.byToken[token].finalized
		owner.mu.Unlock()
		if published != (finalizeErr == nil) {
			t.Fatalf("round %d: published=%v finalize_err=%v, want publication exactly on success", round, published, finalizeErr)
		}
		// The transition won the generation either way, so the claim is now
		// bound to the superseded one and can never be published later.
		if err := owner.Finalize(token); testOwnerKind(t, err) != PendingOutpointUnavailable {
			t.Fatalf("round %d: post-begin Finalize = %v, want unavailable", round, err)
		}
	}
}

// assertCandidateExactlyReleased pins the shared post-slot rule for a candidate
// a LATER admission check rejected: the original cause is returned unchanged,
// no entry is published, the entry's token is zeroed, no outpoint of the
// candidate is still claimed, and the issued sequence stays consumed.
func assertCandidateExactlyReleased(t *testing.T, mp *Mempool, entry *mempoolEntry, err error, wantKind TxAdmitErrorKind, wantMsg string) {
	t.Helper()
	// Each dimension reports independently so a regression shows every rule it
	// broke, not only the first one checked.
	var admitErr *TxAdmitError
	if !errors.As(err, &admitErr) || admitErr.Kind != wantKind || admitErr.Message != wantMsg {
		t.Errorf("admission error %v, want %s TxAdmitError %q", err, wantKind, wantMsg)
	}
	var zero PendingOutpointToken
	if entry.token != zero {
		t.Errorf("rejected candidate token=%+v, want the zero token after exact release", entry.token)
	}
	if len(mp.txs) != 0 {
		t.Errorf("rejected candidate published %d record(s), want none", len(mp.txs))
	}
	owner := mp.pendingOutpoints
	owner.mu.Lock()
	defer owner.mu.Unlock()
	for _, op := range entry.inputs {
		if row, ok := owner.byOutpoint[op]; ok {
			t.Errorf("outpoint %v still claimed by %+v after exact release", op, row)
		}
	}
	if len(owner.byToken) != 0 || len(owner.byOutpoint) != 0 {
		t.Errorf("owner holds claims=%d outpoints=%d after exact release, want none", len(owner.byToken), len(owner.byOutpoint))
	}
	if owner.tokenHighWater != 1 {
		t.Errorf("token high-water=%d, want the one issued sequence retained", owner.tokenHighWater)
	}
}

// TestMempoolPendingOutpointAdmissionSeqExhaustionReleasesReservation pins the
// first of the two post-slot release categories that no capacity-class test
// covers: validateAdmissionSeqLocked fires AFTER the conflict slot issued a
// token, so dropping its release would strand a claim over the candidate's
// outpoints with no record behind it. The 2^64-wide sequence space makes this
// row unreachable from AddTx, so the exhausted counter is set directly.
func TestMempoolPendingOutpointAdmissionSeqExhaustionReleasesReservation(t *testing.T) {
	entry := &mempoolEntry{
		txid:   [32]byte{0x0c},
		wtxid:  [32]byte{0x0d},
		inputs: []consensus.Outpoint{testOutpoint(1), testOutpoint(2)},
		fee:    1, weight: 1, size: 1,
	}
	mp := &Mempool{maxTxs: 10, maxBytes: 100, lastAdmissionSeq: ^uint64(0)}
	mp.mu.Lock()
	err := mp.addEntryLocked(entry)
	mp.mu.Unlock()
	assertCandidateExactlyReleased(t, mp, entry, err, TxAdmitUnavailable, "mempool admission sequence exhausted")
}

// TestMempoolPendingOutpointLiveFloorRecheckReleasesReservation pins the second
// uncovered post-slot release category: the live rolling-floor recheck inside
// validateCapacityAdmissionLocked. It is driven package-internally because the
// public path cannot reach it — addTxWithSource's cheap pre-slot precheck
// already rejects everything below the SNAPPED floor, and the locked recheck
// exists exactly for a floor RAISE between snap and lock. Passing the stale
// snapped floor against a raised live floor is that race, deterministically.
func TestMempoolPendingOutpointLiveFloorRecheckReleasesReservation(t *testing.T) {
	entry := &mempoolEntry{
		txid:   [32]byte{0x1c},
		wtxid:  [32]byte{0x1d},
		inputs: []consensus.Outpoint{testOutpoint(3)},
		fee:    DefaultMempoolMinFeeRate, weight: 1, size: 1,
	}
	// The snap admits this fee rate; the live floor raised past it does not.
	mp := &Mempool{maxTxs: 10, maxBytes: 100, currentMinFeeRate: DefaultMempoolMinFeeRate + 1}
	mp.mu.Lock()
	err := mp.addEntryLockedWithFloor(entry, DefaultMempoolMinFeeRate)
	mp.mu.Unlock()
	assertCandidateExactlyReleased(t, mp, entry, err, TxAdmitUnavailable,
		"mempool fee below rolling minimum: fee=1 weight=1 min_fee_rate=2")
}
