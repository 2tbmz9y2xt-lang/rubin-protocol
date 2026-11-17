package node

import (
	"crypto/sha3"
	"errors"
	"maps"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Literal RUBIN_NETWORK_PARAMS.md limits, never the production constants.
const perSource, global = uint64(100_000_000), uint64(1_600_000_000)

type daCompletionBudgetImage struct {
	present bool
	tip     daCompletionTip
	global  daCompletionUse
	sources map[string]daCompletionUse
}

func imageDACompletionBudget(b *daCompletionBudget) daCompletionBudgetImage {
	b.mu.Lock()
	defer b.mu.Unlock()
	return daCompletionBudgetImage{present: b.present, tip: b.tip, global: b.global, sources: maps.Clone(b.sources)}
}

func daBudgetContext(tipByte byte, height, generation uint64) PendingOutpointAdmissionContext {
	return PendingOutpointAdmissionContext{StableTip: PendingOutpointTip{HasTip: true, Height: height, Hash: [32]byte{tipByte}}, Generation: generation}
}

func daBudgetPeer(t *testing.T, quota string) DAProvenance {
	t.Helper()
	provenance, err := NewPeerDAProvenance("peer-"+quota, quota)
	if err != nil {
		t.Fatal(err)
	}
	return provenance
}

// daBudgetFiller is deliberately unparseable so a charge from it proves a
// lengths-only computation.
func daBudgetFiller(n int) []byte { return []byte(strings.Repeat("\xff", n)) }

func daBudgetChunk(raw, payload int) daRelayChunk {
	return daRelayChunk{txBytes: daBudgetFiller(raw), payload: daBudgetFiller(payload)}
}

func requireDABudgetDisposition(t *testing.T, err error, want RelayAdmissionDisposition, text string) {
	t.Helper()
	if err == nil || relayDispositionOf(err) != want || !strings.Contains(err.Error(), text) {
		t.Fatalf("err=%v disposition=%v want %v %q", err, relayDispositionOf(err), want, text)
	}
}

func seededDABudget(tipByte byte, height uint64, global daCompletionUse, sources map[string]daCompletionUse) *daCompletionBudget {
	return &daCompletionBudget{present: true, tip: daCompletionTip{hash: [32]byte{tipByte}, height: height}, global: global, sources: sources}
}

func TestDACompletionBudget(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T)
	}{
		{"charge_literals", func(t *testing.T) {
			stateB := &daCompleteSnapshot{}
			stateB.prior.commit = daRelayCommit{member: &daRelayMemberIdentity{}, txBytes: daBudgetFiller(200)}
			stateB.prior.chunks = map[uint16]daRelayChunk{0: daBudgetChunk(300, 1000), 1: daBudgetChunk(300, 1000)}
			stateB.candidate.member = daRelayOwnerReadyMember{locator: daRelayLocator{kind: daRelayLocatorChunk, chunkIndex: 2}, txBytes: daBudgetFiller(300), payload: daBudgetFiller(1000)}
			if got := daCompletionChargeOf(stateB); got != (daCompletionCharge{bytes: 4100}) {
				t.Fatalf("State B charge=%+v want 4100", got)
			}
			stateA := &daCompleteSnapshot{}
			// Index 9 is outside the incoming commit's chunk_count 2 and still counts.
			stateA.prior.chunks = map[uint16]daRelayChunk{0: daBudgetChunk(400, 2000), 1: daBudgetChunk(400, 2000), 9: daBudgetChunk(400, 2000)}
			stateA.candidate.member = daRelayOwnerReadyMember{locator: daRelayLocator{kind: daRelayLocatorCommit}, txBytes: daBudgetFiller(250), payload: daBudgetFiller(77)}
			stateA.candidate.chunkCount = 2
			if got := daCompletionChargeOf(stateA); got != (daCompletionCharge{bytes: 7450}) {
				t.Fatalf("State A charge=%+v want 7450", got)
			}
		}},
		{"global_equal", func(t *testing.T) {
			const c = uint64(5000)
			b := seededDABudget(1, 1, daCompletionUse{used: global - c - 7, reserved: 7}, map[string]daCompletionUse{"other": {used: global - c - 7, reserved: 7}})
			if _, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: c}); err != nil {
				t.Fatalf("exact global equality declined: %v", err)
			}
			b = seededDABudget(1, 1, daCompletionUse{used: global - c + 1}, nil)
			before := imageDACompletionBudget(b)
			for _, quota := range []string{"q", "fresh"} {
				_, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, quota), daCompletionCharge{bytes: c})
				requireDABudgetDisposition(t, err, RelayAdmissionUnavailable, "DA completion work budget unavailable")
			}
			if !reflect.DeepEqual(imageDACompletionBudget(b), before) {
				t.Fatal("global decline changed the budget")
			}
		}},
		{"source_equal", func(t *testing.T) {
			const c = uint64(3000)
			b := seededDABudget(1, 1, daCompletionUse{used: perSource}, map[string]daCompletionUse{"q": {used: perSource - c - 5, reserved: 5}})
			if _, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: c}); err != nil {
				t.Fatalf("exact source equality declined: %v", err)
			}
			if got := imageDACompletionBudget(b); got.global != (daCompletionUse{used: perSource, reserved: c}) || got.sources["q"] != (daCompletionUse{used: perSource - c - 5, reserved: 5 + c}) {
				t.Fatalf("reserved state=%+v", got)
			}
			b = seededDABudget(1, 1, daCompletionUse{used: perSource - c + 1}, map[string]daCompletionUse{"q": {used: perSource - c + 1}})
			before := imageDACompletionBudget(b)
			_, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: c})
			requireDABudgetDisposition(t, err, RelayAdmissionUnavailable, "DA completion work budget unavailable")
			if !reflect.DeepEqual(imageDACompletionBudget(b), before) {
				t.Fatal("source decline changed the budget")
			}
			if _, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "other"), daCompletionCharge{bytes: c}); err != nil {
				t.Fatalf("source exhaustion leaked to another quota_identity: %v", err)
			}
		}},
		{"settle_accepted_returns", func(t *testing.T) {
			b := seededDABudget(1, 1, daCompletionUse{used: 11}, map[string]daCompletionUse{"other": {used: 11}})
			reservation, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: 900})
			if err != nil || reservation != (daCompletionReservation{quota: "q", charge: 900}) {
				t.Fatalf("reservation=%+v err=%v", reservation, err)
			}
			b.settle(reservation, true)
			want := daCompletionBudgetImage{present: true, tip: daCompletionTip{hash: [32]byte{1}, height: 1}, global: daCompletionUse{used: 11}, sources: map[string]daCompletionUse{"other": {used: 11}}}
			if got := imageDACompletionBudget(b); !reflect.DeepEqual(got, want) {
				t.Fatalf("accepted settle=%+v want %+v", got, want)
			}
		}},
		{"settle_failed_converts", func(t *testing.T) {
			b := &daCompletionBudget{}
			reservation, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: 900})
			if err != nil {
				t.Fatal(err)
			}
			b.settle(reservation, false)
			want := daCompletionBudgetImage{present: true, tip: daCompletionTip{hash: [32]byte{1}, height: 1}, global: daCompletionUse{used: 900}, sources: map[string]daCompletionUse{"q": {used: 900}}}
			if got := imageDACompletionBudget(b); !reflect.DeepEqual(got, want) {
				t.Fatalf("failed settle=%+v want %+v", got, want)
			}
		}},
		{"renewal_changed_tip", func(t *testing.T) {
			b := seededDABudget(1, 1, daCompletionUse{used: global}, map[string]daCompletionUse{"q": {used: perSource}, "other": {used: 4}})
			if _, err := b.reserve(daBudgetContext(2, 2, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: 600}); err != nil {
				t.Fatal(err)
			}
			want := daCompletionBudgetImage{present: true, tip: daCompletionTip{hash: [32]byte{2}, height: 2}, global: daCompletionUse{reserved: 600}, sources: map[string]daCompletionUse{"q": {reserved: 600}}}
			if got := imageDACompletionBudget(b); !reflect.DeepEqual(got, want) {
				t.Fatalf("renewed=%+v want %+v", got, want)
			}
			// Same hash at another height is another identity; a decline keeps the renewal.
			b = seededDABudget(2, 2, daCompletionUse{used: 9}, map[string]daCompletionUse{"q": {used: 9}})
			_, err := b.reserve(daBudgetContext(2, 3, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: perSource + 1})
			requireDABudgetDisposition(t, err, RelayAdmissionUnavailable, "DA completion work budget unavailable")
			want = daCompletionBudgetImage{present: true, tip: daCompletionTip{hash: [32]byte{2}, height: 3}}
			if got := imageDACompletionBudget(b); !reflect.DeepEqual(got, want) {
				t.Fatalf("decline after renewal=%+v want %+v", got, want)
			}
		}},
		{"generation_unchanged", func(t *testing.T) {
			b := seededDABudget(1, 1, daCompletionUse{used: global - 100}, map[string]daCompletionUse{"q": {used: 50}})
			before := imageDACompletionBudget(b)
			_, err := b.reserve(daBudgetContext(1, 1, 99), daBudgetPeer(t, "q"), daCompletionCharge{bytes: 101})
			requireDABudgetDisposition(t, err, RelayAdmissionUnavailable, "DA completion work budget unavailable")
			if !reflect.DeepEqual(imageDACompletionBudget(b), before) {
				t.Fatal("generation change renewed the budget")
			}
			// HasTip does not participate either.
			noTip := &daCompletionBudget{}
			if _, err := noTip.reserve(PendingOutpointAdmissionContext{}, daBudgetPeer(t, "q"), daCompletionCharge{bytes: 120}); err != nil {
				t.Fatal(err)
			}
			if got := imageDACompletionBudget(noTip); !got.present || got.tip != (daCompletionTip{}) {
				t.Fatalf("no-tip identity=%+v", got)
			}
		}},
		{"reconnect_unchanged", func(t *testing.T) {
			relay, err := newDARelayState(nil, defaultDARelayCaps())
			if err != nil {
				t.Fatal(err)
			}
			if got := imageDACompletionBudget(&relay.completionBudget); !reflect.DeepEqual(got, daCompletionBudgetImage{}) {
				t.Fatalf("new owner budget=%+v", got)
			}
			first, err := relay.completionBudget.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: perSource})
			if err != nil {
				t.Fatal(err)
			}
			relay.completionBudget.settle(first, false)
			before := imageDACompletionBudget(&relay.completionBudget)
			reconnected, err := NewPeerDAProvenance("peer-q-reconnected", "q")
			if err != nil {
				t.Fatal(err)
			}
			_, err = relay.completionBudget.reserve(daBudgetContext(1, 1, 7), reconnected, daCompletionCharge{bytes: 120})
			requireDABudgetDisposition(t, err, RelayAdmissionUnavailable, "DA completion work budget unavailable")
			if !reflect.DeepEqual(imageDACompletionBudget(&relay.completionBudget), before) {
				t.Fatal("reconnect reset the budget")
			}
		}},
		{"image_excludes_budget", func(t *testing.T) {
			relay, err := newDARelayState(nil, defaultDARelayCaps())
			if err != nil {
				t.Fatal(err)
			}
			relay.completionBudget = daCompletionBudget{present: true, tip: daCompletionTip{height: 4}, global: daCompletionUse{used: 6}, sources: map[string]daCompletionUse{"q": {used: 6}}}
			seeded := imageDACompletionBudget(&relay.completionBudget)
			relay.mu.Lock()
			projected := relay.cloneForAtomicBatchLocked()
			cloned := imageDACompletionBudget(&projected.completionBudget)
			relay.publishAtomicBatchLocked(projected)
			relay.mu.Unlock()
			if !reflect.DeepEqual(cloned, daCompletionBudgetImage{}) || !reflect.DeepEqual(imageDACompletionBudget(&relay.completionBudget), seeded) {
				t.Fatalf("retained image copied=%+v live=%+v", cloned, imageDACompletionBudget(&relay.completionBudget))
			}
		}},
		{"overflow_no_effect", func(t *testing.T) {
			var charge daCompletionCharge
			charge.add(^uint64(0))
			charge.add(1)
			if !charge.overflow {
				t.Fatal("checked charge wrapped")
			}
			for _, b := range []*daCompletionBudget{
				seededDABudget(1, 1, daCompletionUse{used: 5}, map[string]daCompletionUse{"q": {used: 5}}),
				{},
			} {
				before := imageDACompletionBudget(b)
				_, err := b.reserve(daBudgetContext(2, 2, 0), daBudgetPeer(t, "q"), charge)
				requireDABudgetDisposition(t, err, RelayAdmissionInternal, errDARelayArithmeticOverflow.Error())
				if !reflect.DeepEqual(imageDACompletionBudget(b), before) {
					t.Fatal("charge overflow changed the budget")
				}
			}
			for _, b := range []*daCompletionBudget{
				seededDABudget(1, 1, daCompletionUse{used: ^uint64(0) - 1}, nil),
				seededDABudget(1, 1, daCompletionUse{}, map[string]daCompletionUse{"q": {used: ^uint64(0) - 1}}),
			} {
				before := imageDACompletionBudget(b)
				_, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: 2})
				requireDABudgetDisposition(t, err, RelayAdmissionInternal, errDARelayArithmeticOverflow.Error())
				if !reflect.DeepEqual(imageDACompletionBudget(b), before) {
					t.Fatal("test overflow changed the budget")
				}
			}
		}},
		{"renewal_with_reserved", func(t *testing.T) {
			b := seededDABudget(1, 1, daCompletionUse{used: 3, reserved: 4}, map[string]daCompletionUse{"q": {used: 3, reserved: 4}})
			before := imageDACompletionBudget(b)
			for _, tip := range []byte{2, 3} {
				_, err := b.reserve(daBudgetContext(tip, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: 120})
				requireDABudgetDisposition(t, err, RelayAdmissionInternal, errDARelayImageIncompatible.Error())
				if !reflect.DeepEqual(imageDACompletionBudget(b), before) {
					t.Fatal("renewal with reserved_global changed the budget")
				}
			}
			// Dual violation: nonzero reserved_global at a changed identity wins over charge overflow.
			_, err := b.reserve(daBudgetContext(2, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{overflow: true})
			requireDABudgetDisposition(t, err, RelayAdmissionInternal, errDARelayImageIncompatible.Error())
			if !reflect.DeepEqual(imageDACompletionBudget(b), before) {
				t.Fatal("dual violation changed the budget")
			}
		}},
	} {
		t.Run(tc.name, tc.run)
	}
	for _, tc := range daBudgetAdmissionCases() {
		t.Run(tc.name, tc.run)
	}
}

func BenchmarkDACompletionBudget(b *testing.B) {
	snapshot := &daCompleteSnapshot{}
	snapshot.prior.commit = daRelayCommit{member: &daRelayMemberIdentity{}, txBytes: daBudgetFiller(200)}
	snapshot.prior.chunks = map[uint16]daRelayChunk{0: daBudgetChunk(300, 1000), 1: daBudgetChunk(300, 1000)}
	snapshot.candidate.member = daRelayOwnerReadyMember{locator: daRelayLocator{kind: daRelayLocatorChunk}, txBytes: daBudgetFiller(300), payload: daBudgetFiller(1000)}
	provenance, err := NewPeerDAProvenance("peer", "q")
	if err != nil {
		b.Fatal(err)
	}
	budget := &daCompletionBudget{}
	context := daBudgetContext(1, 1, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reservation, err := budget.reserve(context, provenance, daCompletionChargeOf(snapshot))
		if err != nil {
			b.Fatal(err)
		}
		budget.settle(reservation, true)
	}
}

type daBudgetCase struct {
	name string
	run  func(t *testing.T)
}

type daBudgetAdmission struct {
	f      *daNonReplayFixture
	last   daNonReplayTx
	charge uint64
}

// newDABudgetAdmission retains every member but the last one of a one-chunk
// set; charge is computed from the raw member lengths and the chunk payload.
func newDABudgetAdmission(t *testing.T, commitLast, match bool) daBudgetAdmission {
	t.Helper()
	f := newDANonReplayFixture(t, 20)
	id, payload := [32]byte{1}, []byte("complete payload")
	commitment := sha3.Sum256(payload)
	if !match {
		commitment = [32]byte{99}
	}
	chunk := f.signed(daNonReplayTxSpec{kind: 2, daID: id, payload: payload, inputCount: 2})
	commit := f.signed(daNonReplayTxSpec{kind: 1, daID: id, chunkCount: 1, commitment: commitment, commitmentOutputs: 1})
	charge := uint64(len(commit.raw) + len(chunk.raw) + len(payload))
	if commitLast {
		f.admit(chunk, daNonReplayPeer("retained"))
		return daBudgetAdmission{f: f, last: commit, charge: charge}
	}
	f.admit(commit, DetachedReorgDAProvenance())
	return daBudgetAdmission{f: f, last: chunk, charge: charge}
}

func (a daBudgetAdmission) tip(t *testing.T) daCompletionTip {
	t.Helper()
	context, ok := a.f.mp.pendingOutpoints.AdmissionContext()
	if !ok {
		t.Fatal("admission context unavailable")
	}
	return daCompletionTip{hash: context.StableTip.Hash, height: context.StableTip.Height}
}

func (a daBudgetAdmission) seed(tip daCompletionTip, global daCompletionUse, sources map[string]daCompletionUse) {
	b := &a.f.relay.completionBudget
	b.present, b.tip, b.global, b.sources = true, tip, global, sources
}

func (a daBudgetAdmission) budget() daCompletionBudgetImage {
	return imageDACompletionBudget(&a.f.relay.completionBudget)
}

func (a daBudgetAdmission) requireUsed(t *testing.T, tip daCompletionTip) {
	t.Helper()
	want := daCompletionBudgetImage{present: true, tip: tip, global: daCompletionUse{used: a.charge}, sources: map[string]daCompletionUse{"q": {used: a.charge}}}
	if got := a.budget(); !reflect.DeepEqual(got, want) {
		t.Fatalf("budget=%+v want %+v", got, want)
	}
}

type daBudgetRejectImage struct {
	context PendingOutpointAdmissionContext
	adopted bool
	entries map[[32]byte]struct{}
	fifo    [][32]byte
	next    int
}

func daBudgetRejectCache(c *daRejectCache) daBudgetRejectImage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return daBudgetRejectImage{context: c.context, adopted: c.adopted, entries: maps.Clone(c.entries), fifo: slices.Clone(c.fifo), next: c.next}
}

// daBudgetPanicAdmission recovers the panic of one AdmitDA call.
func daBudgetPanicAdmission(a daBudgetAdmission, provenance DAProvenance) (recovered any) {
	defer func() { recovered = recover() }()
	_, _ = a.f.relay.AdmitDA(a.last.raw, provenance)
	return nil
}

func (o *PendingOutpointOwner) stableContextForBudgetTest(t *testing.T) PendingOutpointAdmissionContext {
	t.Helper()
	context, ok := o.AdmissionContext()
	if !ok {
		t.Fatal("admission context unavailable")
	}
	return context
}

func daBudgetWaitSettling(t *testing.T) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); runtime.Gosched() {
		if strings.Contains(string(buf[:runtime.Stack(buf, true)]), "(*daCompletionBudget).settle") {
			return
		}
	}
	t.Fatal("settlement never waited on the budget mutex")
}

func daBudgetAdmissionCases() []daBudgetCase {
	return []daBudgetCase{
		{"state_c_returns", func(t *testing.T) {
			a := newDABudgetAdmission(t, false, true)
			result, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
			if err != nil || result.Disposition != DAAdmissionRetained {
				t.Fatalf("State C=(%+v,%v)", result, err)
			}
			if got := a.budget(); !got.present || got.tip != a.tip(t) || got.global != (daCompletionUse{}) || len(got.sources) != 0 {
				t.Fatalf("accepted budget=%+v", got)
			}
		}},
		{"commit_last_mismatch", func(t *testing.T) {
			a := newDABudgetAdmission(t, true, false)
			result, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
			if err != nil || result.Disposition != DAAdmissionRetained {
				t.Fatalf("commit-last mismatch=(%+v,%v)", result, err)
			}
			if record := a.f.relay.relations.recordValue([32]byte{1}); record.state != daRelayStateStagedCommit {
				t.Fatalf("state=%v want State B", record.state)
			}
			a.requireUsed(t, a.tip(t))
		}},
		{"chunk_last_mismatch", func(t *testing.T) {
			a := newDABudgetAdmission(t, false, false)
			if _, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q")); !errors.Is(err, ErrDARelayPayloadCommitmentMismatch) {
				t.Fatalf("chunk-last mismatch err=%v", err)
			}
			a.requireUsed(t, a.tip(t))
		}},
		{"final_duplicate", func(t *testing.T) {
			a := newDABudgetAdmission(t, false, true)
			a.f.relay.completeHook = func(stage daCompleteStage, p *daCompleteCommitPlan) {
				if stage == daCompletePlanned {
					a.f.mutateRelay(func(s *DARelayState) { s.relations.putLocator(a.last.txid, p.source.candidate.member.locator) })
				}
			}
			result, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
			if err != nil || result.Disposition != DAAdmissionDuplicate {
				t.Fatalf("final duplicate=(%+v,%v)", result, err)
			}
			a.requireUsed(t, a.tip(t))
		}},
		{"target_drift", func(t *testing.T) {
			a := newDABudgetAdmission(t, false, true)
			a.f.relay.completeHook = func(stage daCompleteStage, _ *daCompleteCommitPlan) {
				if stage == daCompletePlanned {
					a.f.mutateRelay(func(s *DARelayState) {
						record := s.relations.recordValue([32]byte{1})
						record.revision++
						s.relations.putRecord(record.daID, record)
					})
				}
			}
			_, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
			requireDABudgetDisposition(t, err, RelayAdmissionUnavailable, "retained DA record moved")
			a.requireUsed(t, a.tip(t))
		}},
		{"panic_settlement", func(t *testing.T) {
			for _, stage := range []daCompleteStage{daCompletePlanned, daCompleteEffects} {
				a := newDABudgetAdmission(t, false, true)
				sentinel := &struct{ stage daCompleteStage }{stage}
				a.f.relay.completeHook = func(at daCompleteStage, _ *daCompleteCommitPlan) {
					if at == stage {
						panic(sentinel)
					}
				}
				if got := daBudgetPanicAdmission(a, daNonReplayPeer("q")); got != sentinel {
					t.Fatalf("stage %d panic=%v", stage, got)
				}
				a.requireUsed(t, a.tip(t))
				if !a.f.relay.mu.TryLock() || !a.f.mp.pendingOutpoints.mu.TryLock() || !a.f.state.admissionMu.TryLock() {
					t.Fatalf("stage %d leaked a lock", stage)
				}
			}
		}},
		{"settlement_lock_order", func(t *testing.T) {
			// Planned panics (step-3-side, guard only); effects returns and publishes.
			for _, stage := range []daCompleteStage{daCompletePlanned, daCompleteEffects} {
				a := newDABudgetAdmission(t, false, true)
				budget := &a.f.relay.completionBudget
				a.f.relay.completeHook = func(at daCompleteStage, _ *daCompleteCommitPlan) {
					if at != stage {
						return
					}
					budget.mu.Lock()
					if at == daCompletePlanned {
						panic("planned")
					}
				}
				done := make(chan any)
				go func() { done <- daBudgetPanicAdmission(a, daNonReplayPeer("q")) }()
				daBudgetWaitSettling(t)
				daFree := a.f.relay.mu.TryLock()
				if daFree {
					a.f.relay.mu.Unlock()
				}
				ownerFree := a.f.mp.pendingOutpoints.mu.TryLock()
				if ownerFree {
					a.f.mp.pendingOutpoints.mu.Unlock()
				}
				guardFree := a.f.state.admissionMu.TryLock()
				if guardFree {
					a.f.state.admissionMu.RWMutex.Unlock()
				}
				budget.mu.Unlock()
				<-done
				if !daFree || !ownerFree || guardFree {
					t.Fatalf("stage %d settlement locks: DA free=%v owner free=%v guard free=%v", stage, daFree, ownerFree, guardFree)
				}
			}
		}},
		{"before_step3", func(t *testing.T) {
			for _, full := range []bool{true, false} {
				a := newDABudgetAdmission(t, false, true)
				a.f.mutateRelay(func(s *DARelayState) {
					record := s.relations.recordValue([32]byte{1})
					record.commit.txBytes = daBudgetFiller(len(record.commit.txBytes))
					s.relations.putRecord(record.daID, record)
				})
				if full {
					a.seed(a.tip(t), daCompletionUse{used: global}, nil)
				}
				hooked := false
				a.f.relay.completeHook = func(daCompleteStage, *daCompleteCommitPlan) { hooked = true }
				_, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
				if full {
					requireDABudgetDisposition(t, err, RelayAdmissionUnavailable, "DA completion work budget unavailable")
				} else if err == nil || relayDispositionOf(err) == RelayAdmissionUnavailable {
					t.Fatalf("control step-3 parse err=%v", err)
				}
				if hooked {
					t.Fatal("step 3 completed")
				}
			}
		}},
		{"decline_zero_effect", func(t *testing.T) {
			a := newDABudgetAdmission(t, false, true)
			a.seed(a.tip(t), daCompletionUse{used: 7}, map[string]daCompletionUse{"q": {used: perSource - a.charge + 1}})
			relay, owner, budget := daRelayStateSnapshot(a.f.relay), cloneDAAdmissionOwner(a.f.mp.pendingOutpoints), a.budget()
			cache := daBudgetRejectCache(&a.f.relay.rejectCache)
			result, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
			if result != (DAAdmissionResult{}) {
				t.Fatalf("decline result=%+v", result)
			}
			requireDABudgetDisposition(t, err, RelayAdmissionUnavailable, "DA completion work budget unavailable")
			requireDANonReplayUnchanged(t, a.f.relay, a.f.mp.pendingOutpoints, relay, owner)
			if got := a.budget(); !reflect.DeepEqual(got, budget) {
				t.Fatalf("decline changed the budget: %+v want %+v", got, budget)
			}
			// Earlier miss reconciliation may adopt the context; no reject row is added.
			cache.context, cache.adopted = a.f.mp.pendingOutpoints.stableContextForBudgetTest(t), true
			if got := daBudgetRejectCache(&a.f.relay.rejectCache); !reflect.DeepEqual(got, cache) {
				t.Fatalf("decline changed the reject cache: %+v want %+v", got, cache)
			}
		}},
		{"repeated_refusal", func(t *testing.T) {
			// A13: repeated chunk-last mismatches exhaust one source, then decline before step 3.
			a := newDABudgetAdmission(t, false, false)
			tip := a.tip(t)
			a.seed(tip, daCompletionUse{used: perSource - 2*a.charge}, map[string]daCompletionUse{"q": {used: perSource - 2*a.charge}})
			for i := 0; i < 2; i++ {
				if _, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q")); !errors.Is(err, ErrDARelayPayloadCommitmentMismatch) {
					t.Fatalf("attempt %d err=%v", i, err)
				}
			}
			_, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
			requireDABudgetDisposition(t, err, RelayAdmissionUnavailable, "DA completion work budget unavailable")
			if got := a.budget(); got.global != (daCompletionUse{used: perSource}) || got.sources["q"] != (daCompletionUse{used: perSource}) {
				t.Fatalf("exhausted budget=%+v", got)
			}
		}},
		{"local_reorg_bypass", func(t *testing.T) {
			for _, provenance := range []DAProvenance{LocalDAProvenance(), DetachedReorgDAProvenance()} {
				a := newDABudgetAdmission(t, false, true)
				a.seed(daCompletionTip{height: 99}, daCompletionUse{used: global}, map[string]daCompletionUse{"q": {used: perSource}})
				before := a.budget()
				result, err := a.f.relay.AdmitDA(a.last.raw, provenance)
				if err != nil || result.Disposition != DAAdmissionRetained || !reflect.DeepEqual(a.budget(), before) {
					t.Fatalf("bypass=(%+v,%v) budget=%+v", result, err, a.budget())
				}
			}
		}},
		{"concurrent_reservations", func(t *testing.T) {
			const c = uint64(1000)
			b := seededDABudget(1, 1, daCompletionUse{used: global - 3*c}, nil)
			var start, done sync.WaitGroup
			start.Add(1)
			reserved := make([]bool, 8)
			for i := range reserved {
				done.Add(1)
				go func() {
					defer done.Done()
					start.Wait()
					provenance, _ := NewPeerDAProvenance("peer", string(rune('a'+i)))
					reservation, err := b.reserve(daBudgetContext(1, 1, 0), provenance, daCompletionCharge{bytes: c})
					if err == nil {
						reserved[i] = true
						b.settle(reservation, false)
					}
				}()
			}
			start.Done()
			done.Wait()
			count := 0
			for _, ok := range reserved {
				if ok {
					count++
				}
			}
			if got := imageDACompletionBudget(b); count != 3 || got.global != (daCompletionUse{used: global}) {
				t.Fatalf("reservations=%d budget=%+v", count, got)
			}
		}},
	}
}
