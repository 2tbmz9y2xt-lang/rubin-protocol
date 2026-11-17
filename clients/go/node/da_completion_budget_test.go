package node

import (
	"crypto/sha3"
	"errors"
	"fmt"
	"maps"
	"math"
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

func daBudgetChunk(index uint16, raw, payload int) daRelayChunk {
	return daRelayChunk{chunkIndex: index, txBytes: daBudgetFiller(raw), payload: daBudgetFiller(payload)}
}

func requireDABudgetDisposition(t *testing.T, err error, want RelayAdmissionDisposition, text string) {
	t.Helper()
	if err == nil || relayDispositionOf(err) != want || !strings.Contains(err.Error(), text) {
		t.Fatalf("err=%v disposition=%v want %v %q", err, relayDispositionOf(err), want, text)
	}
}

const daBudgetDeclineText = "DA completion work budget unavailable"

// isDABudgetDecline reports the real budget decline: err itself is the
// unwrapped *TxAdmitError of class TxAdmitUnavailable with its exact text, no
// cause, and disposition UNAVAILABLE.
func isDABudgetDecline(err error) bool {
	var admitErr *TxAdmitError
	return errors.As(err, &admitErr) && admitErr != nil && errors.Unwrap(err) == nil && errors.Is(admitErr, err) && admitErr.Kind == TxAdmitUnavailable &&
		admitErr.Message == daBudgetDeclineText && relayDispositionOf(err) == RelayAdmissionUnavailable
}

// requireDABudgetDecline requires the real budget decline (isDABudgetDecline).
func requireDABudgetDecline(t *testing.T, err error) {
	t.Helper()
	if !isDABudgetDecline(err) {
		t.Fatalf("err=%v (%T, unwrap=%v) disposition=%v want budget decline: err itself an unwrapped *TxAdmitError with no cause, kind TxAdmitUnavailable, message %q, disposition UNAVAILABLE", err, err, errors.Unwrap(err), relayDispositionOf(err), daBudgetDeclineText)
	}
}

// requireDABudgetInternal requires INTERNAL carrying cause for errors.Is.
func requireDABudgetInternal(t *testing.T, err error, cause error) {
	t.Helper()
	if !errors.Is(err, cause) || relayDispositionOf(err) != RelayAdmissionInternal {
		t.Fatalf("err=%v disposition=%v want INTERNAL with cause %v", err, relayDispositionOf(err), cause)
	}
}

// requireDABudgetRefused runs one refused reserve and requires the zero
// reservation; a nil cause requires the decline, otherwise INTERNAL with cause.
func requireDABudgetRefused(t *testing.T, b *daCompletionBudget, context PendingOutpointAdmissionContext, provenance DAProvenance, charge daCompletionCharge, cause error) {
	t.Helper()
	reservation, err := b.reserve(context, provenance, charge)
	if reservation != (daCompletionReservation{}) {
		t.Fatalf("refused reserve returned reservation %+v", reservation)
	}
	if cause == nil {
		requireDABudgetDecline(t, err)
		return
	}
	requireDABudgetInternal(t, err, cause)
}

func seededDABudget(tipByte byte, height uint64, global daCompletionUse, sources map[string]daCompletionUse) *daCompletionBudget {
	return &daCompletionBudget{present: true, tip: daCompletionTip{hash: [32]byte{tipByte}, height: height}, global: global, sources: sources}
}

func seededDABudgetFrom(tipByte byte, height, fill uint64, named map[string]daCompletionUse) *daCompletionBudget {
	global, sources := daBudgetSeed(fill, named)
	return seededDABudget(tipByte, height, global, sources)
}

// daBudgetSeed builds an owner-consistent pre-state: fill used bytes spread
// over "fill<i>" sources of at most perSource each, plus named, with global
// the sum of every source. A named key equal to a generated fill key panics.
func daBudgetSeed(fill uint64, named map[string]daCompletionUse) (daCompletionUse, map[string]daCompletionUse) {
	sum, sources := daCompletionUse{used: fill}, maps.Clone(named)
	if sources == nil {
		sources = map[string]daCompletionUse{}
	}
	for i := 0; fill > 0; i++ {
		n, key := min(fill, perSource), fmt.Sprintf("fill%d", i)
		if _, clash := sources[key]; clash {
			panic("seed named source collides with " + key)
		}
		sources[key], fill = daCompletionUse{used: n}, fill-n
	}
	for _, use := range named {
		sum.used, sum.reserved = sum.used+use.used, sum.reserved+use.reserved
		if use.used+use.reserved > perSource {
			panic("seed source above perSource")
		}
	}
	if sum.used+sum.reserved > global {
		panic("seed above global")
	}
	return sum, sources
}

// requireDABudgetSettled settles reservation and requires the exact image.
func requireDABudgetSettled(t *testing.T, b *daCompletionBudget, reservation daCompletionReservation, accepted bool, global daCompletionUse, sources map[string]daCompletionUse) {
	t.Helper()
	b.settle(reservation, accepted)
	want := daCompletionBudgetImage{present: true, tip: daCompletionTip{hash: [32]byte{1}, height: 1}, global: global, sources: sources}
	if got := imageDACompletionBudget(b); !reflect.DeepEqual(got, want) {
		t.Fatalf("settle %+v accepted=%v: %+v want %+v", reservation, accepted, got, want)
	}
}

func TestDACompletionBudget(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T)
	}{
		{"seed_named_fill_collision", func(t *testing.T) {
			defer func() {
				if r := recover(); r != "seed named source collides with fill0" {
					t.Fatalf("recover=%v", r)
				}
			}()
			daBudgetSeed(1, map[string]daCompletionUse{"fill0": {used: 1}})
		}},
		{"charge_literals", func(t *testing.T) {
			stateB := &daCompleteSnapshot{}
			stateB.prior.commit = daRelayCommit{member: &daRelayMemberIdentity{}, txBytes: daBudgetFiller(200)}
			stateB.prior.chunks = map[uint16]daRelayChunk{0: daBudgetChunk(0, 300, 1000), 1: daBudgetChunk(1, 300, 1000)}
			stateB.candidate.member = daRelayOwnerReadyMember{locator: daRelayLocator{kind: daRelayLocatorChunk, chunkIndex: 2}, txBytes: daBudgetFiller(300), payload: daBudgetFiller(1000)}
			if got := daCompletionChargeOf(stateB); got != (daCompletionCharge{bytes: 4100}) {
				t.Fatalf("State B charge=%+v want 4100", got)
			}
			stateA := &daCompleteSnapshot{}
			// Chunk 9 (map key and chunkIndex) is outside the incoming commit's
			// chunk_count 2 and still counts.
			stateA.prior.chunks = map[uint16]daRelayChunk{0: daBudgetChunk(0, 400, 2000), 1: daBudgetChunk(1, 400, 2000), 9: daBudgetChunk(9, 400, 2000)}
			stateA.candidate.member = daRelayOwnerReadyMember{locator: daRelayLocator{kind: daRelayLocatorCommit}, txBytes: daBudgetFiller(250), payload: daBudgetFiller(77)}
			stateA.candidate.chunkCount = 2
			if got := daCompletionChargeOf(stateA); got != (daCompletionCharge{bytes: 7450}) {
				t.Fatalf("State A charge=%+v want 7450", got)
			}
		}},
		{"global_equal", func(t *testing.T) {
			const c = uint64(5000)
			b := seededDABudgetFrom(1, 1, global-c-7, map[string]daCompletionUse{"other": {reserved: 7}})
			if _, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: c}); err != nil {
				t.Fatalf("exact global equality declined: %v", err)
			}
			if got := imageDACompletionBudget(b); got.global != (daCompletionUse{used: global - c - 7, reserved: 7 + c}) || got.sources["q"] != (daCompletionUse{reserved: c}) || got.sources["other"] != (daCompletionUse{reserved: 7}) {
				t.Fatalf("reserved state=%+v", got)
			}
			b = seededDABudgetFrom(1, 1, global-c+1-7, map[string]daCompletionUse{"other": {reserved: 7}})
			before := imageDACompletionBudget(b)
			for _, quota := range []string{"q", "fresh"} {
				requireDABudgetRefused(t, b, daBudgetContext(1, 1, 0), daBudgetPeer(t, quota), daCompletionCharge{bytes: c}, nil)
			}
			if !reflect.DeepEqual(imageDACompletionBudget(b), before) {
				t.Fatal("global decline changed the budget")
			}
		}},
		{"source_equal", func(t *testing.T) {
			const c = uint64(3000)
			b := seededDABudgetFrom(1, 1, 0, map[string]daCompletionUse{"q": {used: perSource - c - 5, reserved: 5}, "other": {used: 40, reserved: 9}})
			if _, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: c}); err != nil {
				t.Fatalf("exact source equality declined: %v", err)
			}
			if got := imageDACompletionBudget(b); got.global != (daCompletionUse{used: perSource - c - 5 + 40, reserved: 5 + 9 + c}) || got.sources["q"] != (daCompletionUse{used: perSource - c - 5, reserved: 5 + c}) {
				t.Fatalf("reserved state=%+v", got)
			}
			b = seededDABudgetFrom(1, 1, 0, map[string]daCompletionUse{"q": {used: perSource - c + 1 - 5, reserved: 5}})
			before := imageDACompletionBudget(b)
			requireDABudgetRefused(t, b, daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: c}, nil)
			if !reflect.DeepEqual(imageDACompletionBudget(b), before) {
				t.Fatal("source decline changed the budget")
			}
			if _, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "other"), daCompletionCharge{bytes: c}); err != nil {
				t.Fatalf("source exhaustion leaked to another quota_identity: %v", err)
			}
		}},
		{"settle_accepted_returns", func(t *testing.T) {
			// "other" holds a reservation, so returning q's charges must subtract
			// only them; the second return deletes the zero q entry.
			b := seededDABudgetFrom(1, 1, 0, map[string]daCompletionUse{"other": {used: 11, reserved: 13}})
			first, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: 900})
			if err != nil || first != (daCompletionReservation{quota: "q", charge: 900}) {
				t.Fatalf("reservation=%+v err=%v", first, err)
			}
			second, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: 50})
			if err != nil {
				t.Fatal(err)
			}
			requireDABudgetSettled(t, b, first, true, daCompletionUse{used: 11, reserved: 63}, map[string]daCompletionUse{"other": {used: 11, reserved: 13}, "q": {reserved: 50}})
			requireDABudgetSettled(t, b, second, true, daCompletionUse{used: 11, reserved: 13}, map[string]daCompletionUse{"other": {used: 11, reserved: 13}})
		}},
		{"settle_failed_converts", func(t *testing.T) {
			// q already has used bytes and "other" a reservation, so each
			// conversion must move only the settled charge.
			b := seededDABudgetFrom(1, 1, 0, map[string]daCompletionUse{"other": {used: 11, reserved: 13}, "q": {used: 3}})
			first, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: 900})
			if err != nil {
				t.Fatal(err)
			}
			second, err := b.reserve(daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: 50})
			if err != nil {
				t.Fatal(err)
			}
			requireDABudgetSettled(t, b, first, false, daCompletionUse{used: 914, reserved: 63}, map[string]daCompletionUse{"other": {used: 11, reserved: 13}, "q": {used: 903, reserved: 50}})
			requireDABudgetSettled(t, b, second, false, daCompletionUse{used: 964, reserved: 13}, map[string]daCompletionUse{"other": {used: 11, reserved: 13}, "q": {used: 953}})
		}},
		{"renewal_changed_tip", func(t *testing.T) {
			b := seededDABudgetFrom(1, 1, global-perSource, map[string]daCompletionUse{"q": {used: perSource}})
			if _, err := b.reserve(daBudgetContext(2, 2, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: 600}); err != nil {
				t.Fatal(err)
			}
			want := daCompletionBudgetImage{present: true, tip: daCompletionTip{hash: [32]byte{2}, height: 2}, global: daCompletionUse{reserved: 600}, sources: map[string]daCompletionUse{"q": {reserved: 600}}}
			if got := imageDACompletionBudget(b); !reflect.DeepEqual(got, want) {
				t.Fatalf("renewed=%+v want %+v", got, want)
			}
			// Same hash at another height is another identity; a decline keeps the renewal.
			b = seededDABudget(2, 2, daCompletionUse{used: 9}, map[string]daCompletionUse{"q": {used: 9}})
			requireDABudgetRefused(t, b, daBudgetContext(2, 3, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: perSource + 1}, nil)
			want = daCompletionBudgetImage{present: true, tip: daCompletionTip{hash: [32]byte{2}, height: 3}}
			if got := imageDACompletionBudget(b); !reflect.DeepEqual(got, want) {
				t.Fatalf("decline after renewal=%+v want %+v", got, want)
			}
		}},
		{"generation_unchanged", func(t *testing.T) {
			b := seededDABudgetFrom(1, 1, global-150, map[string]daCompletionUse{"q": {used: 50}})
			before := imageDACompletionBudget(b)
			requireDABudgetRefused(t, b, daBudgetContext(1, 1, 99), daBudgetPeer(t, "q"), daCompletionCharge{bytes: 101}, nil)
			if !reflect.DeepEqual(imageDACompletionBudget(b), before) {
				t.Fatal("generation change renewed the budget")
			}
			// HasTip does not participate: a stored no-tip identity (zero hash,
			// height 0) observed again from a zero context does not renew, so a
			// charge that fits only after renewal declines with no change.
			b = seededDABudgetFrom(0, 0, global-150, map[string]daCompletionUse{"q": {used: 50}})
			before = imageDACompletionBudget(b)
			requireDABudgetRefused(t, b, PendingOutpointAdmissionContext{}, daBudgetPeer(t, "q"), daCompletionCharge{bytes: 101}, nil)
			if !reflect.DeepEqual(imageDACompletionBudget(b), before) {
				t.Fatal("HasTip=false renewed a present no-tip identity")
			}
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
			// Same tip and generation: only the reconnect differs.
			requireDABudgetRefused(t, &relay.completionBudget, daBudgetContext(1, 1, 0), reconnected, daCompletionCharge{bytes: 120}, nil)
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
				// Same identity with zero counters: no renewal is involved.
				seededDABudget(2, 2, daCompletionUse{}, nil),
			} {
				before := imageDACompletionBudget(b)
				requireDABudgetRefused(t, b, daBudgetContext(2, 2, 0), daBudgetPeer(t, "q"), charge, errDARelayArithmeticOverflow)
				if !reflect.DeepEqual(imageDACompletionBudget(b), before) {
					t.Fatal("charge overflow changed the budget")
				}
			}
			for _, b := range []*daCompletionBudget{
				seededDABudget(1, 1, daCompletionUse{used: ^uint64(0) - 1}, nil),
				seededDABudget(1, 1, daCompletionUse{}, map[string]daCompletionUse{"q": {used: ^uint64(0) - 1}}),
			} {
				before := imageDACompletionBudget(b)
				requireDABudgetRefused(t, b, daBudgetContext(1, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: 2}, errDARelayArithmeticOverflow)
				if !reflect.DeepEqual(imageDACompletionBudget(b), before) {
					t.Fatal("test overflow changed the budget")
				}
			}
		}},
		{"renewal_with_reserved", func(t *testing.T) {
			b := seededDABudget(1, 1, daCompletionUse{used: 3, reserved: 4}, map[string]daCompletionUse{"q": {used: 3, reserved: 4}})
			before := imageDACompletionBudget(b)
			for _, tip := range []byte{2, 3} {
				requireDABudgetRefused(t, b, daBudgetContext(tip, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{bytes: 120}, errDARelayImageIncompatible)
				if !reflect.DeepEqual(imageDACompletionBudget(b), before) {
					t.Fatal("renewal with reserved_global changed the budget")
				}
			}
			// Both violations together: INTERNAL with no change; neither the spec
			// nor the contract orders the two errors, so no text is pinned.
			reservation, err := b.reserve(daBudgetContext(2, 1, 0), daBudgetPeer(t, "q"), daCompletionCharge{overflow: true})
			if reservation != (daCompletionReservation{}) || relayDispositionOf(err) != RelayAdmissionInternal || (!errors.Is(err, errDARelayImageIncompatible) && !errors.Is(err, errDARelayArithmeticOverflow)) {
				t.Fatalf("dual violation=(%+v,%v)", reservation, err)
			}
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

type daBudgetCase struct {
	name string
	run  func(t *testing.T)
}

type daBudgetAdmission struct {
	f             *daNonReplayFixture
	last          daNonReplayTx
	retainedChunk daNonReplayTx
	charge        uint64
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
		return daBudgetAdmission{f: f, last: commit, retainedChunk: chunk, charge: charge}
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

func (a daBudgetAdmission) seed(tip daCompletionTip, fill uint64, named map[string]daCompletionUse) {
	b := &a.f.relay.completionBudget
	b.present, b.tip = true, tip
	b.global, b.sources = daBudgetSeed(fill, named)
}

func (a daBudgetAdmission) budget() daCompletionBudgetImage {
	return imageDACompletionBudget(&a.f.relay.completionBudget)
}

// retained captures the retained DA image and owner claims; requireRetained
// compares the current ones with that capture.
func (a daBudgetAdmission) retained() (daRelayStateView, *PendingOutpointOwner) {
	return daRelayStateSnapshot(a.f.relay), cloneDAAdmissionOwner(a.f.mp.pendingOutpoints)
}

func (a daBudgetAdmission) requireRetained(t *testing.T, relay daRelayStateView, owner *PendingOutpointOwner) {
	t.Helper()
	requireDANonReplayUnchanged(t, a.f.relay, a.f.mp.pendingOutpoints, relay, owner)
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
	recovered, _ = daBudgetAttempt(a, provenance)
	return recovered
}

// daBudgetAttempt runs one AdmitDA call and returns its recovered panic and error.
func daBudgetAttempt(a daBudgetAdmission, provenance DAProvenance) (recovered any, err error) {
	defer func() { recovered = recover() }()
	_, err = a.f.relay.AdmitDA(a.last.raw, provenance)
	return nil, err
}

func (o *PendingOutpointOwner) stableContextForBudgetTest(t *testing.T) PendingOutpointAdmissionContext {
	t.Helper()
	context, ok := o.AdmissionContext()
	if !ok {
		t.Fatal("admission context unavailable")
	}
	return context
}

// daBudgetWaitFrame waits until some goroutine stack shows frame.
func daBudgetWaitFrame(t *testing.T, frame string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); runtime.Gosched() {
		if strings.Contains(string(buf[:runtime.Stack(buf, true)]), frame) {
			return
		}
	}
	t.Fatalf("no goroutine reached %s", frame)
}

// daBudgetLockProbe reports whether the DA, owner and ChainState admission
// locks are free, leaving each as it found it.
func daBudgetLockProbe(a daBudgetAdmission) (daFree, ownerFree, guardFree bool) {
	if daFree = a.f.relay.mu.TryLock(); daFree {
		a.f.relay.mu.Unlock()
	}
	if ownerFree = a.f.mp.pendingOutpoints.mu.TryLock(); ownerFree {
		a.f.mp.pendingOutpoints.mu.Unlock()
	}
	if guardFree = a.f.state.admissionMu.TryLock(); guardFree {
		a.f.state.admissionMu.RWMutex.Unlock()
	}
	return daFree, ownerFree, guardFree
}

// corruptDABudgetTarget makes step 3 fail on the retained commit bytes.
func corruptDABudgetTarget(a daBudgetAdmission) {
	a.f.mutateRelay(func(s *DARelayState) {
		record := s.relations.recordValue([32]byte{1})
		record.commit.txBytes = daBudgetFiller(len(record.commit.txBytes))
		s.relations.putRecord(record.daID, record)
	})
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
			record := a.f.relay.relations.recordValue([32]byte{1})
			// State B keeps the commit only: the mismatching chunk and its claims leave.
			if record.state != daRelayStateStagedCommit || len(record.chunks) != 0 {
				t.Fatalf("state=%v chunks=%d want State B with no chunk", record.state, len(record.chunks))
			}
			a.f.requireMember(t, record, a.last, 2, daNonReplayPeer("q"))
			owner := a.f.mp.pendingOutpoints
			for _, input := range a.retainedChunk.inputs {
				if txid, ok := owner.txidForOutpoint(input); ok {
					t.Fatalf("dropped chunk input still claimed by %x", txid)
				}
			}
			for _, input := range a.last.inputs {
				if txid, ok := owner.txidForOutpoint(input); !ok || txid != a.last.txid {
					t.Fatalf("commit input claim=(%x,%v)", txid, ok)
				}
			}
			a.requireUsed(t, a.tip(t))
		}},
		{"chunk_last_mismatch", func(t *testing.T) {
			a := newDABudgetAdmission(t, false, false)
			relay, owner := a.retained()
			if _, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q")); !errors.Is(err, ErrDARelayPayloadCommitmentMismatch) {
				t.Fatalf("chunk-last mismatch err=%v", err)
			}
			a.requireUsed(t, a.tip(t))
			a.requireRetained(t, relay, owner)
		}},
		{"final_duplicate", func(t *testing.T) {
			a := newDABudgetAdmission(t, false, true)
			var relay daRelayStateView
			var owner *PendingOutpointOwner
			a.f.relay.completeHook = func(stage daCompleteStage, p *daCompleteCommitPlan) {
				if stage == daCompletePlanned {
					a.f.mutateRelay(func(s *DARelayState) { s.relations.putLocator(a.last.txid, p.source.candidate.member.locator) })
					relay, owner = a.retained()
				}
			}
			result, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
			if err != nil || result.Disposition != DAAdmissionDuplicate {
				t.Fatalf("final duplicate=(%+v,%v)", result, err)
			}
			a.requireUsed(t, a.tip(t))
			a.requireRetained(t, relay, owner)
		}},
		{"target_drift", func(t *testing.T) {
			a := newDABudgetAdmission(t, false, true)
			var relay daRelayStateView
			var owner *PendingOutpointOwner
			a.f.relay.completeHook = func(stage daCompleteStage, _ *daCompleteCommitPlan) {
				if stage == daCompletePlanned {
					a.f.mutateRelay(func(s *DARelayState) {
						record := s.relations.recordValue([32]byte{1})
						record.revision++
						s.relations.putRecord(record.daID, record)
					})
					relay, owner = a.retained()
				}
			}
			_, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
			requireDABudgetDisposition(t, err, RelayAdmissionUnavailable, "retained DA record moved")
			a.requireUsed(t, a.tip(t))
			a.requireRetained(t, relay, owner)
		}},
		{"panic_settlement", func(t *testing.T) {
			for _, stage := range []daCompleteStage{daCompletePlanned, daCompleteEffects} {
				a := newDABudgetAdmission(t, false, true)
				sentinel := &struct{ stage daCompleteStage }{stage}
				var relay daRelayStateView
				var owner *PendingOutpointOwner
				a.f.relay.completeHook = func(at daCompleteStage, _ *daCompleteCommitPlan) {
					if at == daCompletePlanned {
						relay, owner = a.retained()
					}
					if at == stage {
						panic(sentinel)
					}
				}
				if got := daBudgetPanicAdmission(a, daNonReplayPeer("q")); got != sentinel {
					t.Fatalf("stage %d panic=%v", stage, got)
				}
				a.requireUsed(t, a.tip(t))
				a.requireRetained(t, relay, owner)
				if !a.f.relay.mu.TryLock() || !a.f.mp.pendingOutpoints.mu.TryLock() || !a.f.state.admissionMu.TryLock() {
					t.Fatalf("stage %d leaked a lock", stage)
				}
			}
		}},
		{"settlement_lock_order", func(t *testing.T) {
			// Settlement after the planned hook is step-3-side (guard only);
			// after the effects hook it is later (DA and owner released). Each
			// stage ends by ordinary return and by panic. On the planned ordinary
			// return the test hook unbinds the plan so applyDACompleteCommit returns
			// errDARelayImageIncompatible before the DA lock.
			for _, row := range []struct {
				stage  daCompleteStage
				panics bool
			}{{daCompletePlanned, false}, {daCompletePlanned, true}, {daCompleteEffects, false}, {daCompleteEffects, true}} {
				a := newDABudgetAdmission(t, false, true)
				budget := &a.f.relay.completionBudget
				sentinel := &struct{ stage daCompleteStage }{row.stage}
				a.f.relay.completeHook = func(at daCompleteStage, p *daCompleteCommitPlan) {
					if at != row.stage {
						return
					}
					budget.mu.Lock()
					if row.panics {
						panic(sentinel)
					}
					if at == daCompletePlanned {
						p.admission = nil
					}
				}
				type attempt struct {
					recovered any
					err       error
				}
				done := make(chan attempt)
				go func() {
					recovered, err := daBudgetAttempt(a, daNonReplayPeer("q"))
					done <- attempt{recovered, err}
				}()
				daBudgetWaitFrame(t, "(*daCompletionBudget).settle")
				daFree, ownerFree, guardFree := daBudgetLockProbe(a)
				budget.mu.Unlock()
				got := <-done
				if !daFree || !ownerFree || guardFree {
					t.Fatalf("%+v settlement locks: DA free=%v owner free=%v guard free=%v", row, daFree, ownerFree, guardFree)
				}
				if row.panics != (got.recovered == sentinel) || (!row.panics && got.recovered != nil) {
					t.Fatalf("%+v panic=%v", row, got.recovered)
				}
				planned := row.stage == daCompletePlanned && !row.panics
				if planned != errors.Is(got.err, errDARelayImageIncompatible) {
					t.Fatalf("%+v err=%v", row, got.err)
				}
				if row.panics || planned {
					a.requireUsed(t, a.tip(t))
				}
			}
		}},
		{"settlement_step3_return", func(t *testing.T) {
			// Step-3 parse error return: no hook runs, so once the attempt is
			// parked in reserve (step 2 has released DA) the test takes DA and
			// owner and holds them until the attempt returns (settlement must not
			// need them). The parked ChainState writer's read is an extra check
			// only; the deterministic guard-held observation of a guard-only
			// ordinary return is the planned row of settlement_lock_order.
			a := newDABudgetAdmission(t, false, true)
			corruptDABudgetTarget(a)
			budget, owner := &a.f.relay.completionBudget, a.f.mp.pendingOutpoints
			budget.mu.Lock()
			done := make(chan error, 1)
			go func() {
				_, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
				done <- err
			}()
			daBudgetWaitFrame(t, "(*daCompletionBudget).reserve")
			if !a.f.relay.mu.TryLock() {
				budget.mu.Unlock()
				t.Fatal("DA lock held at step 2a")
			}
			if !owner.mu.TryLock() {
				a.f.relay.mu.Unlock()
				budget.mu.Unlock()
				t.Fatal("owner lock held at step 2a")
			}
			afterGuard := make(chan daCompletionBudgetImage, 1)
			go func() {
				a.f.state.admissionMu.Lock()
				afterGuard <- imageDACompletionBudget(budget)
				a.f.state.admissionMu.RWMutex.Unlock()
			}()
			daBudgetWaitFrame(t, "(*RWMutex).Lock")
			budget.mu.Unlock()
			var err error
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("step-3 settlement waited on a DA or owner lock")
			}
			a.f.relay.mu.Unlock()
			owner.mu.Unlock()
			if err == nil || relayDispositionOf(err) == RelayAdmissionUnavailable {
				t.Fatalf("step-3 err=%v", err)
			}
			want := daCompletionBudgetImage{present: true, tip: a.tip(t), global: daCompletionUse{used: a.charge}, sources: map[string]daCompletionUse{"q": {used: a.charge}}}
			if got := <-afterGuard; !reflect.DeepEqual(got, want) {
				t.Fatalf("budget at guard release=%+v want %+v", got, want)
			}
		}},
		{"before_step3", func(t *testing.T) {
			// Each full row observes the decline instead of the step-3 refusal its
			// control gets from the same target, and that the planned hook did not
			// run. The corrupt target fails the commit parse; the mismatch target
			// parses and fails only the payload-commitment comparison. Neither counts
			// parse or hash calls, so step-3 work whose result is discarded is not
			// observed. The clean control shows the hook runs once step 3 completes.
			for _, row := range []struct{ full, corrupt, mismatch bool }{
				{true, true, false}, {false, true, false}, {true, false, true}, {false, false, true}, {false, false, false},
			} {
				a := newDABudgetAdmission(t, false, !row.mismatch)
				if row.corrupt {
					corruptDABudgetTarget(a)
				}
				if row.full {
					a.seed(a.tip(t), global, nil)
				}
				hooked := false
				a.f.relay.completeHook = func(daCompleteStage, *daCompleteCommitPlan) { hooked = true }
				result, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
				switch {
				case row.full:
					requireDABudgetDecline(t, err)
				case row.mismatch:
					if !errors.Is(err, ErrDARelayPayloadCommitmentMismatch) {
						t.Fatalf("control step-3 commitment err=%v", err)
					}
				case row.corrupt:
					if err == nil || relayDispositionOf(err) == RelayAdmissionUnavailable {
						t.Fatalf("control step-3 parse err=%v", err)
					}
				case err != nil || result.Disposition != DAAdmissionRetained:
					t.Fatalf("clean control=(%+v,%v)", result, err)
				}
				if want := !row.full && !row.corrupt && !row.mismatch; hooked != want {
					t.Fatalf("%+v hooked=%v want %v", row, hooked, want)
				}
			}
		}},
		{"decline_zero_effect", func(t *testing.T) {
			a := newDABudgetAdmission(t, false, true)
			a.seed(a.tip(t), 7, map[string]daCompletionUse{"q": {used: perSource - a.charge + 1}})
			relay, owner, budget := daRelayStateSnapshot(a.f.relay), cloneDAAdmissionOwner(a.f.mp.pendingOutpoints), a.budget()
			cache := daBudgetRejectCache(&a.f.relay.rejectCache)
			result, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
			if result != (DAAdmissionResult{}) {
				t.Fatalf("decline result=%+v", result)
			}
			requireDABudgetDecline(t, err)
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
			a.seed(tip, 0, map[string]daCompletionUse{"q": {used: perSource - 2*a.charge}})
			for i := 0; i < 2; i++ {
				if _, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q")); !errors.Is(err, ErrDARelayPayloadCommitmentMismatch) {
					t.Fatalf("attempt %d err=%v", i, err)
				}
			}
			_, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
			requireDABudgetDecline(t, err)
			if got := a.budget(); got.global != (daCompletionUse{used: perSource}) || got.sources["q"] != (daCompletionUse{used: perSource}) {
				t.Fatalf("exhausted budget=%+v", got)
			}
		}},
		{"local_reorg_bypass", func(t *testing.T) {
			for _, provenance := range []DAProvenance{LocalDAProvenance(), DetachedReorgDAProvenance()} {
				a := newDABudgetAdmission(t, false, true)
				a.seed(daCompletionTip{height: 99}, global-perSource, map[string]daCompletionUse{"q": {used: perSource}})
				before := a.budget()
				result, err := a.f.relay.AdmitDA(a.last.raw, provenance)
				if err != nil || result.Disposition != DAAdmissionRetained || !reflect.DeepEqual(a.budget(), before) {
					t.Fatalf("bypass=(%+v,%v) budget=%+v", result, err, a.budget())
				}
			}
		}},
		{"refusal_terminations", func(t *testing.T) {
			// A5: each refusal after a successful reservation converts it to used
			// and leaves retained state and claims as they were when step 3 ended.
			for _, row := range []struct {
				name     string
				arrange  func(a daBudgetAdmission)
				planned  func(t *testing.T, a daBudgetAdmission)
				effects  func(s *DARelayState)
				want     func(t *testing.T, err error)
				consumed bool
			}{
				{
					name: "capacity", arrange: func(a daBudgetAdmission) { daCompleteCommitFillCountLimit(a.f, 65536, 2_000_000) },
					want: func(t *testing.T, err error) {
						requireDABudgetDisposition(t, err, RelayAdmissionCapacity, "DA COMPLETE_SET capacity rejected")
					}, consumed: true,
				},
				{name: "reserve_conflict", planned: func(t *testing.T, a daBudgetAdmission) {
					mustReserve(t, a.f.mp.pendingOutpoints, [32]byte{80}, a.last.inputs[0])
				}, want: func(t *testing.T, err error) {
					requireDABudgetDisposition(t, err, RelayAdmissionConflict, fmt.Sprintf("mempool double-spend conflict with %x", [32]byte{80}))
				}},
				{name: "reserve_unavailable", planned: func(_ *testing.T, a daBudgetAdmission) {
					a.f.mp.pendingOutpoints.tokenHighWater = math.MaxUint64
				}, want: func(t *testing.T, err error) {
					requireDABudgetDisposition(t, err, RelayAdmissionUnavailable, "pending-outpoint token sequence exhausted")
				}},
				{
					name: "publication_preflight", effects: func(s *DARelayState) { s.orphanBytesByDAID = nil },
					want: func(t *testing.T, err error) {
						if !errors.Is(err, errDARelayImageIncompatible) || relayDispositionOf(err) != RelayAdmissionInternal {
							t.Fatalf("preflight err=%v", err)
						}
					},
				},
				{name: "internal", planned: func(_ *testing.T, a daBudgetAdmission) {
					a.f.mutateRelay(func(s *DARelayState) { s.nextReceivedTime = math.MaxUint64 })
				}, want: func(t *testing.T, err error) {
					if !errors.Is(err, errDARelayArithmeticOverflow) || relayDispositionOf(err) != RelayAdmissionInternal {
						t.Fatalf("internal err=%v", err)
					}
				}},
			} {
				t.Run(row.name, func(t *testing.T) {
					a := newDABudgetAdmission(t, false, true)
					if row.arrange != nil {
						row.arrange(a)
					}
					var relay daRelayStateView
					var owner *PendingOutpointOwner
					a.f.relay.completeHook = func(stage daCompleteStage, _ *daCompleteCommitPlan) {
						switch {
						case stage == daCompletePlanned:
							if row.planned != nil {
								row.planned(t, a)
							}
							relay, owner = a.retained()
						case row.effects != nil:
							row.effects(a.f.relay)
						}
					}
					result, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
					if result != (DAAdmissionResult{}) {
						t.Fatalf("refusal result=%+v", result)
					}
					row.want(t, err)
					a.requireUsed(t, a.tip(t))
					if row.effects != nil {
						relay.daIDBytes = nil
					}
					if row.consumed {
						owner.tokenHighWater++
					}
					a.requireRetained(t, relay, owner)
				})
			}
		}},
		{"repeated_reserve_refusal", func(t *testing.T) {
			// A13: repeated Reserve-refused matching completions exhaust one
			// source; the next attempt declines before step 3 until the test
			// rewrites the stored best-tip identity, after which step 2a renews.
			a := newDABudgetAdmission(t, false, true)
			tip := a.tip(t)
			a.seed(tip, 0, map[string]daCompletionUse{"q": {used: perSource - 2*a.charge}})
			steps := 0
			a.f.relay.completeHook = func(stage daCompleteStage, _ *daCompleteCommitPlan) {
				if stage == daCompletePlanned {
					steps++
					a.f.mp.pendingOutpoints.tokenHighWater = math.MaxUint64
				}
			}
			const exhausted = "pending-outpoint token sequence exhausted"
			for i := 0; i < 2; i++ {
				_, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
				requireDABudgetDisposition(t, err, RelayAdmissionUnavailable, exhausted)
			}
			for i := 0; i < 2; i++ {
				_, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
				requireDABudgetDecline(t, err)
			}
			if got := a.budget(); steps != 2 || got.global != (daCompletionUse{used: perSource}) || got.sources["q"] != (daCompletionUse{used: perSource}) {
				t.Fatalf("steps=%d exhausted budget=%+v", steps, got)
			}
			b := &a.f.relay.completionBudget
			b.mu.Lock()
			b.tip = daCompletionTip{hash: [32]byte{0xee}, height: tip.height + 1}
			b.mu.Unlock()
			_, err := a.f.relay.AdmitDA(a.last.raw, daNonReplayPeer("q"))
			requireDABudgetDisposition(t, err, RelayAdmissionUnavailable, exhausted)
			if steps != 3 {
				t.Fatalf("renewed attempt reached step 3 %d times", steps)
			}
			a.requireUsed(t, tip)
		}},
		{"no_step2a", func(t *testing.T) {
			// A1: noncompletions, an exact replay, a first-DA plan duplicate and
			// a failed first-DA snapshot (direct private call with a nil target)
			// run no step 2a: a stale stored identity would otherwise renew.
			f := newDANonReplayFixture(t, 20)
			b := &f.relay.completionBudget
			b.present, b.tip = true, daCompletionTip{hash: [32]byte{0xee}, height: 77}
			b.global, b.sources = daBudgetSeed(global-perSource, map[string]daCompletionUse{"q": {used: perSource}})
			before := imageDACompletionBudget(b)
			commit := f.signed(daNonReplayTxSpec{kind: 1, daID: [32]byte{5}, chunkCount: 2, commitment: [32]byte{9}, commitmentOutputs: 1})
			for _, want := range []DAAdmissionDisposition{DAAdmissionRetained, DAAdmissionDuplicate} {
				result, err := f.relay.AdmitDA(commit.raw, daNonReplayPeer("q"))
				if err != nil || result.Disposition != want || !reflect.DeepEqual(imageDACompletionBudget(b), before) {
					t.Fatalf("want %v: (%+v,%v) budget=%+v", want, result, err, imageDACompletionBudget(b))
				}
			}
			// Noncompleting chunk 0, then an occupied-index non-exact duplicate
			// that exits at the first-DA plan.
			for _, row := range []struct {
				payload string
				want    DAAdmissionDisposition
			}{{"a", DAAdmissionRetained}, {"b", DAAdmissionDuplicate}} {
				tx := f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{5}, payload: []byte(row.payload)})
				result, err := f.relay.AdmitDA(tx.raw, daNonReplayPeer("q"))
				if err != nil || result.Disposition != row.want || !reflect.DeepEqual(imageDACompletionBudget(b), before) {
					t.Fatalf("chunk %q: (%+v,%v) budget=%+v", row.payload, result, err, imageDACompletionBudget(b))
				}
			}
			chunk := f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{5}, chunkIndex: 1, payload: []byte("x")})
			admission := f.begin(chunk)
			defer admission.Close()
			if _, err := f.relay.admitDAComplete(admission, nil); err == nil || !reflect.DeepEqual(imageDACompletionBudget(b), before) {
				t.Fatalf("failed snapshot err=%v budget=%+v", err, imageDACompletionBudget(b))
			}
		}},
		{"reconnect_and_passive_tip", func(t *testing.T) {
			// A10/A7: the disconnect release (ReleasePeerQuotaKey), a reconnect
			// with the same quota_identity (AdmitDA), a best-tip change and the
			// block-connect TTL tick (AdvanceOrphanTTL) leave the budget
			// unchanged; the next step 2a (AdmitDA) observes the new tip and
			// renews. The best-tip change is simulated: the test writes the chain
			// state tip and sets the owner's stable tip with setRelaySource; no
			// production tip-change path runs.
			a := newDABudgetAdmission(t, false, true)
			other := a.f.signed(daNonReplayTxSpec{kind: 1, daID: [32]byte{7}, chunkCount: 2, commitment: [32]byte{9}, commitmentOutputs: 1})
			a.f.admit(other, daNonReplayPeer("q"))
			context := a.f.mp.pendingOutpoints.stableContextForBudgetTest(t)
			tip := a.tip(t)
			a.seed(tip, 0, map[string]daCompletionUse{"q": {used: perSource - a.charge + 1}})
			before := a.budget()
			if err := a.f.relay.ReleasePeerQuotaKey("q"); err != nil {
				t.Fatal(err)
			}
			if record := a.f.relay.relations.recordValue([32]byte{7}); record.commit.member != nil {
				t.Fatal("disconnect release kept the PEER q commit")
			}
			if got := a.budget(); !reflect.DeepEqual(got, before) {
				t.Fatalf("disconnect changed the budget: %+v want %+v", got, before)
			}
			reconnected, err := NewPeerDAProvenance("peer-q-reconnected", "q")
			if err != nil {
				t.Fatal(err)
			}
			_, err = a.f.relay.AdmitDA(a.last.raw, reconnected)
			requireDABudgetDecline(t, err)
			moved := PendingOutpointTip{HasTip: true, Height: tip.height + 1, Hash: [32]byte{0xab}}
			a.f.state.HasTip, a.f.state.Height, a.f.state.TipHash = true, moved.Height, moved.Hash
			setRelaySource(a.f.mp.pendingOutpoints, moved, context.Generation)
			if err := a.f.relay.AdvanceOrphanTTL(); err != nil {
				t.Fatal(err)
			}
			if got := a.budget(); !reflect.DeepEqual(got, before) {
				t.Fatalf("tip change without step 2a changed the budget: %+v want %+v", got, before)
			}
			result, err := a.f.relay.AdmitDA(a.last.raw, reconnected)
			if err != nil || result.Disposition != DAAdmissionRetained {
				t.Fatalf("renewed completion=(%+v,%v)", result, err)
			}
			want := daCompletionBudgetImage{present: true, tip: daCompletionTip{hash: moved.Hash, height: moved.Height}, sources: map[string]daCompletionUse{}}
			if got := a.budget(); !reflect.DeepEqual(got, want) {
				t.Fatalf("renewed budget=%+v want %+v", got, want)
			}
		}},
		{"concurrent_admissions", func(t *testing.T) {
			// A11 through AdmitDA: four chunk-last mismatches from distinct quota
			// identities race for room for exactly two charges.
			f := newDANonReplayFixture(t, 20)
			const n = 4
			raws, charge := make([][]byte, n), uint64(0)
			for i := range raws {
				id, payload := [32]byte{byte(10 + i)}, []byte("complete payload")
				chunk := f.signed(daNonReplayTxSpec{kind: 2, daID: id, payload: payload, inputCount: 2})
				commit := f.signed(daNonReplayTxSpec{kind: 1, daID: id, chunkCount: 1, commitment: [32]byte{99}, commitmentOutputs: 1})
				f.admit(commit, DetachedReorgDAProvenance())
				c := uint64(len(commit.raw) + len(chunk.raw) + len(payload))
				if i > 0 && c != charge {
					t.Fatalf("unequal charges %d %d", c, charge)
				}
				raws[i], charge = chunk.raw, c
			}
			context := f.mp.pendingOutpoints.stableContextForBudgetTest(t)
			tip := daCompletionTip{hash: context.StableTip.Hash, height: context.StableTip.Height}
			b := &f.relay.completionBudget
			b.present, b.tip = true, tip
			b.global, b.sources = daBudgetSeed(global-2*charge, nil)
			pre := maps.Clone(b.sources)
			errs := make([]error, n)
			var start, done sync.WaitGroup
			start.Add(1)
			for i := range raws {
				done.Add(1)
				go func() {
					defer done.Done()
					start.Wait()
					_, errs[i] = f.relay.AdmitDA(raws[i], daNonReplayPeer(string(rune('a'+i))))
				}()
			}
			start.Done()
			done.Wait()
			want := daCompletionBudgetImage{present: true, tip: tip, global: daCompletionUse{used: global}, sources: pre}
			declined := 0
			for i, err := range errs {
				switch {
				case errors.Is(err, ErrDARelayPayloadCommitmentMismatch):
					want.sources[string(rune('a'+i))] = daCompletionUse{used: charge}
				case isDABudgetDecline(err):
					declined++
				default:
					t.Fatalf("attempt %d err=%v", i, err)
				}
			}
			if got := imageDACompletionBudget(b); declined != 2 || !reflect.DeepEqual(got, want) {
				t.Fatalf("declined=%d budget=%+v want %+v", declined, got, want)
			}
		}},
		{"concurrent_reservations", func(t *testing.T) {
			const c = uint64(1000)
			b := seededDABudgetFrom(1, 1, global-3*c, nil)
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
					} else if reservation != (daCompletionReservation{}) {
						t.Errorf("declined reserve returned %+v", reservation)
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
