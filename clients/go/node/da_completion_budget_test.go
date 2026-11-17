package node

import (
	"maps"
	"reflect"
	"strings"
	"testing"
)

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
	const perSource, global = uint64(100_000_000), uint64(1_600_000_000)
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
