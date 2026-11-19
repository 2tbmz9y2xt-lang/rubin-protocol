package node

import (
	"crypto/sha3"
	"errors"
	"fmt"
	"go/ast"
	"maps"
	"math"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// runDATTLBodyInGuard runs advanceDATTLChecked under the held exclusive admission guard and fails after a 10 s wait.
func runDATTLBodyInGuard(t *testing.T, f *daNonReplayFixture) error {
	t.Helper()
	f.state.admissionMu.Lock()
	done := make(chan error, 1)
	body := goDone(func() { done <- advanceDATTLChecked(f.relay, f.mp.pendingOutpoints) })
	defer func() {
		f.state.admissionMu.Unlock()
		joinWithin(t, "the TTL body after the guard release", body)
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("TTL body blocked under the held exclusive admission guard")
	}
	return nil
}

// goDone runs fn on a new goroutine and returns a channel closed after fn returns or unwinds.
func goDone(fn func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	return done
}

// joinWithin waits up to 10 s for done to close and reports a timeout through t.Errorf, so an unwind continues.
func joinWithin(t *testing.T, label string, done ...<-chan struct{}) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for _, d := range done {
		select {
		case <-d:
		case <-deadline:
			t.Errorf("%s did not return within 10s", label)
			return
		}
	}
}

func requireDATTLOK(t *testing.T, err error, format string, args ...any) {
	t.Helper()
	if err != nil {
		t.Fatalf(format+": %v", append(args, err)...)
	}
}

// advanceDATTLInGuard runs advanceDATTLChecked under a bound relay's held exclusive admission guard, with its owner.
func advanceDATTLInGuard(s *DARelayState) error {
	var owner *PendingOutpointOwner
	if s.mempool != nil && s.mempool.chainState != nil {
		s.mempool.chainState.admissionMu.Lock()
		defer s.mempool.chainState.admissionMu.Unlock()
		owner = s.mempool.pendingOutpoints
	}
	return advanceDATTLChecked(s, owner)
}

// ownerReadyTTLSelector names the in-guard TTL body's arm in the shared owner-ready selector tables.
const ownerReadyTTLSelector = "ttl tick"

// requireDATTLSkipsStateC requires run to accept a State-C-only image carrying a defect and to change nothing.
func requireDATTLSkipsStateC(t *testing.T, f *daNonReplayFixture, run func(*DARelayState) error, label string) {
	t.Helper()
	before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	require(t, run(f.relay) == nil, "%s: the in-guard TTL body refused a State C defect it must not visit", label)
	requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
}

// productionDeclarations lists the non-test Go files under clients/go that declare or name name as an identifier.
func productionDeclarations(t *testing.T, name string) []string {
	t.Helper()
	var hits []string
	walkProductionGoFiles(t, "declaration census", func(path string, file *ast.File) {
		ast.Inspect(file, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok && ident.Name == name {
				hits = append(hits, path)
			}
			return true
		})
	})
	return hits
}

type daTTLCallbackRecords struct {
	stateAID, stateBID, stateCID [32]byte
	stateA, stateB               daNonReplayTx
	base, setup                  daRelayStateView
}

// newDATTLCallbackRecords admits State C, then State A (PEER chunk, prefetch reserved) and State B (LOCAL commit) at 3.
func newDATTLCallbackRecords(t *testing.T) (*daNonReplayFixture, daTTLCallbackRecords) {
	f := newDANonReplayFixture(t, 6)
	r := daTTLCallbackRecords{stateAID: [32]byte{0xa7}, stateBID: [32]byte{0xb7}, stateCID: [32]byte{0xc7}}
	f.completeReplayPinned(r.stateCID)
	r.base = daRelayStateSnapshot(f.relay)
	r.stateA = f.ownerReadyChunk(r.stateAID, 0, "ttl-a", daNonReplayPeer("ttl-peer"))
	r.stateB = f.ownerReadyCommit(r.stateBID, 1, LocalDAProvenance())
	f.setOwnerReadyTTL(r.stateAID, 3)
	f.setOwnerReadyTTL(r.stateBID, 3)
	f.relay.mu.Lock()
	f.relay.prefetch.ensureMaps()
	f.relay.prefetch.indexes[r.stateAID] = map[uint16]string{0: "ttl-peer"}
	f.relay.prefetch.expires[r.stateAID] = time.Now().Add(time.Hour)
	f.relay.mu.Unlock()
	r.setup = daRelayStateSnapshot(f.relay)
	return f, r
}

// daTTLImage is the DA image, the owner image (empty when no owner is given) and the owner's operation counts.
type daTTLImage struct {
	view   daRelayStateView
	owner  *PendingOutpointOwner
	counts [4]uint64
}

func daTTLSnapshot(relay *DARelayState, owner *PendingOutpointOwner) daTTLImage {
	image := daTTLImage{view: daRelayStateSnapshot(relay), owner: &PendingOutpointOwner{}}
	if owner != nil {
		image.owner, image.counts = cloneDAAdmissionOwner(owner), daObservationCounts(owner)
	}
	return image
}

// advanceDATTLChecked runs the in-guard TTL body and returns its error, or after a success daTTLOutsideErr.
func advanceDATTLChecked(relay *DARelayState, owner *PendingOutpointOwner) error {
	before := daTTLSnapshot(relay, owner)
	if err := relay.advanceOwnerReadyTTLInGuard(); err != nil {
		return err
	}
	return daTTLOutsideErr(before, daTTLSnapshot(relay, owner))
}

// daTTLOutsideErr requires after to equal before outside before's State A and B records, less the removed records'
// locator rows, charges, entries, claims and outpoint rows, with equal owner counts and one revision per survivor,
// and then requires daTTLSelectedErr of those records.
func daTTLOutsideErr(before, after daTTLImage) error {
	selected, removed := daTTLSelection(before.view, after.view)
	wantView, isView := daTTLExpectedView(before.view, selected, removed), daTTLWithoutSelected(after.view, selected)
	released := removed
	if before.view.mempool == nil { // an unbound relay has no claim domain
		released = nil
	}
	wantOwner := daTTLExpectedOwner(before.owner, released)
	survivors := uint64(len(selected) - len(removed))
	switch {
	case after.view.records != before.view.records+survivors:
		return fmt.Errorf("revision high-water %d -> %d, want one minted per surviving selected record (%d)", before.view.records, after.view.records, survivors)
	case !reflect.DeepEqual(wantView, isView): //nolint:govet // Complete private state-image equality requires structural comparison, error identities included.
		return fmt.Errorf("DA image outside the selected set changed: want %+v, got %+v", wantView, isView)
	case !reflect.DeepEqual(wantOwner, after.owner) || before.counts != after.counts:
		return fmt.Errorf("owner outside the selected set changed: want %+v %+v, got %+v %+v", wantOwner, before.counts, after.owner, after.counts)
	}
	return daTTLSelectedErr(before.view, after.view, selected)
}

// daTTLSelectedErr requires a selected record absent from after to have been at count 1, and a present one to equal
// its before record one count lower with a distinct revision minted above before's high-water (RUBIN_COMPACT_BLOCKS.md Section 5).
func daTTLSelectedErr(before, after daRelayStateView, selected map[[32]byte]daRelaySetRecord) error {
	minted := map[uint64]bool{}
	for daID, was := range selected {
		var err error
		if got, present := after.sets[daID]; present {
			err = daTTLSurvivorErr(was, got, before.records, after.records, minted)
		} else if was.ttlBlocksRemaining != 1 {
			err = fmt.Errorf("record %x removed at count %d, want removal at count 1", daID[:1], was.ttlBlocksRemaining)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// daTTLSurvivorErr requires got to equal was with the count one lower and a revision in (low, high] not yet in minted.
func daTTLSurvivorErr(was, got daRelaySetRecord, low, high uint64, minted map[uint64]bool) error {
	switch {
	case was.ttlBlocksRemaining < 2:
		return fmt.Errorf("record %x kept at count %d, want removal at count 1", was.daID[:1], was.ttlBlocksRemaining)
	case got.revision <= low || got.revision > high:
		return fmt.Errorf("surviving record %x revision %d, want one minted in (%d, %d]", was.daID[:1], got.revision, low, high)
	case minted[got.revision]:
		return fmt.Errorf("surviving record %x shares revision %d with another survivor, want one distinct revision per survivor", was.daID[:1], got.revision)
	}
	minted[got.revision] = true
	want := was
	want.ttlBlocksRemaining, want.revision = was.ttlBlocksRemaining-1, got.revision
	if !reflect.DeepEqual(want, got) {
		return fmt.Errorf("surviving record %x: want %+v, got %+v", was.daID[:1], want, got)
	}
	return nil
}

// daTTLSelection returns the State A and B records of before and the subset absent from after.
func daTTLSelection(before, after daRelayStateView) (selected, removed map[[32]byte]daRelaySetRecord) {
	selected, removed = map[[32]byte]daRelaySetRecord{}, map[[32]byte]daRelaySetRecord{}
	for daID, record := range before.sets {
		if record.state == daRelayStateCompleteSet {
			continue
		}
		selected[daID] = record
		if _, present := after.sets[daID]; !present {
			removed[daID] = record
		}
	}
	return selected, removed
}

// daTTLMembers visits each present member of record with its charge (RUBIN_COMPACT_BLOCKS.md Section 18.1).
func daTTLMembers(record daRelaySetRecord, visit func(member *daRelayMemberIdentity, charge uint64, commit bool)) {
	if record.commit.member != nil {
		visit(record.commit.member, uint64(len(record.commit.txBytes)), true)
	}
	for _, chunk := range record.chunks {
		if chunk.member != nil {
			visit(chunk.member, uint64(len(chunk.txBytes)+len(chunk.payload)), false)
		}
	}
}

// daTTLExpectedView is view without the selected records and high-water, less the removed records' rows, charges and entries.
func daTTLExpectedView(view daRelayStateView, selected, removed map[[32]byte]daRelaySetRecord) daRelayStateView {
	view = daTTLWithoutSelected(view, selected)
	for _, record := range removed {
		daTTLUncharge(&view, record)
	}
	maps.DeleteFunc(view.locators, func(_ [32]byte, locator daRelayLocator) bool {
		_, gone := removed[locator.daID]
		return gone
	})
	view.daIDBytes = daTTLWithout(view.daIDBytes, removed)
	view.prefetchIndexes, view.prefetchExpires = daTTLWithout(view.prefetchIndexes, removed), daTTLWithout(view.prefetchExpires, removed)
	return view
}

// daTTLUncharge subtracts record's member charges from view's counters and drops a peer entry its charges bring to 0.
func daTTLUncharge(view *daRelayStateView, record daRelaySetRecord) {
	staged := record.state == daRelayStateStagedCommit
	daTTLMembers(record, func(member *daRelayMemberIdentity, charge uint64, commit bool) {
		if commit {
			view.commitBytes -= charge
		}
		if staged {
			view.stagedBytes -= charge
			return
		}
		view.orphanBytes -= charge
		if member.provenance.kind == daProvenancePeer {
			key := member.provenance.quotaKey()
			if view.peerBytes[key] -= charge; view.peerBytes[key] == 0 {
				delete(view.peerBytes, key)
			}
		}
	})
}

// daTTLWithoutSelected is a copy of view's maps with the selected records and the high-water left out.
func daTTLWithoutSelected(view daRelayStateView, selected map[[32]byte]daRelaySetRecord) daRelayStateView {
	view.sets = daTTLWithout(view.sets, selected)
	view.peerBytes, view.locators = maps.Collect(maps.All(view.peerBytes)), maps.Collect(maps.All(view.locators))
	view.daIDBytes = maps.Collect(maps.All(view.daIDBytes))
	view.prefetchIndexes, view.prefetchExpires = maps.Collect(maps.All(view.prefetchIndexes)), maps.Collect(maps.All(view.prefetchExpires))
	view.records = 0
	return view
}

func daTTLWithout[V, S any](m map[[32]byte]V, selected map[[32]byte]S) map[[32]byte]V {
	kept := maps.Collect(maps.All(m))
	maps.DeleteFunc(kept, func(daID [32]byte, _ V) bool {
		_, drop := selected[daID]
		return drop
	})
	return kept
}

// daTTLExpectedOwner is a copy of before less the claims and outpoint rows of the removed records' member tokens.
func daTTLExpectedOwner(owner *PendingOutpointOwner, removed map[[32]byte]daRelaySetRecord) *PendingOutpointOwner {
	tokens := map[PendingOutpointToken]bool{}
	for _, record := range removed {
		daTTLMembers(record, func(member *daRelayMemberIdentity, _ uint64, _ bool) { tokens[member.token] = true })
	}
	expected := cloneDAAdmissionOwner(owner)
	maps.DeleteFunc(expected.byToken, func(token PendingOutpointToken, _ *pendingOutpointClaim) bool { return tokens[token] })
	maps.DeleteFunc(expected.byOutpoint, func(_ consensus.Outpoint, row pendingOutpointRow) bool { return tokens[row.token] })
	return expected
}

func requireDATTLCount(t *testing.T, view daRelayStateView, daID [32]byte, want uint64) {
	t.Helper()
	record, present := view.sets[daID]
	require(t, present && record.ttlBlocksRemaining == want, "record %x: present=%v ttl=%d, want ttl %d", daID[:1], present, record.ttlBlocksRemaining, want)
}

// TestDATTLCallbackBodyThreeCountedPublications: State A and B records at 3 go to 2, 1, then expire; State C stays.
func TestDATTLCallbackBodyThreeCountedPublications(t *testing.T) {
	f, r := newDATTLCallbackRecords(t)
	tokenA, tokenB := r.setup.sets[r.stateAID].chunks[0].member.token, r.setup.sets[r.stateBID].commit.member.token
	for call, want := range []uint64{2, 1} {
		requireDATTLOK(t, runDATTLBodyInGuard(t, f), "body call %d", call+1)
		view := daRelayStateSnapshot(f.relay)
		requireDATTLCount(t, view, r.stateAID, want)
		requireDATTLCount(t, view, r.stateBID, want)
		if wantRecords := r.setup.records + 2*uint64(call+1); view.records != wantRecords {
			t.Fatalf("body call %d: records=%d, want %d (one revision per decreased record)", call+1, view.records, wantRecords)
		}
		if _, held := view.prefetchIndexes[r.stateAID]; !held {
			t.Fatalf("body call %d released the prefetch reservation of a surviving record", call+1)
		}
	}
	requireDATTLOK(t, runDATTLBodyInGuard(t, f), "body call 3")
	after := daRelayStateSnapshot(f.relay)
	ownerReadyRecordAbsent(t, after, r.stateAID, r.stateA.txid)
	ownerReadyRecordAbsent(t, after, r.stateBID, r.stateB.txid)
	ownerReadyClaimGone(t, cloneDAAdmissionOwner(f.mp.pendingOutpoints), tokenA, r.stateA.inputs)
	ownerReadyClaimGone(t, cloneDAAdmissionOwner(f.mp.pendingOutpoints), tokenB, r.stateB.inputs)
	require(t, after.records == r.setup.records+4, "expiry minted a revision: records=%d, want %d", after.records, r.setup.records+4)
	if !reflect.DeepEqual(after.sets[r.stateCID], r.base.sets[r.stateCID]) || !reflect.DeepEqual(after.locators, r.base.locators) {
		t.Fatal("State C record or the locator image changed")
	}
	type counters struct{ staged, orphan, commit, complete, pinned uint64 }
	got := counters{after.stagedBytes, after.orphanBytes, after.commitBytes, after.completeBytes, after.pinnedPayloadBytes}
	want := counters{r.base.stagedBytes, r.base.orphanBytes, r.base.commitBytes, r.base.completeBytes, r.base.pinnedPayloadBytes}
	require(t, got == want && reflect.DeepEqual(after.peerBytes, r.base.peerBytes) && reflect.DeepEqual(after.daIDBytes, r.base.daIDBytes), "accounting after expiry: got=%+v peer=%v da=%v, want=%+v peer=%v da=%v", got, after.peerBytes, after.daIDBytes, want, r.base.peerBytes, r.base.daIDBytes)
}

// TestDATTLCallbackBodyRefusalChangesNothing: a refused record or member-token check leaves image and owner unchanged.
func TestDATTLCallbackBodyRefusalChangesNothing(t *testing.T) {
	for _, row := range []struct {
		name    string
		corrupt func(*daNonReplayFixture, daTTLCallbackRecords)
	}{
		{"inconsistent stored value", daTTLRelayEdit(func(s *DARelayState, r daTTLCallbackRecords) {
			mutateOwnerReadyRecord(s, r.stateBID, func(record *daRelaySetRecord) { record.wireBytes = 1 })
		})},
		{"unbound owner token", daTTLOwnerEdit(func(o *PendingOutpointOwner, r daTTLCallbackRecords) {
			o.byToken[r.setup.sets[r.stateAID].chunks[0].member.token].txid[0] ^= 0xff
		})},
		{"count above the configured orphan TTL", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.setOwnerReadyTTL(r.stateAID, f.relay.caps.orphanTTLBlocks+1)
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			f, r := newDATTLCallbackRecords(t)
			f.setOwnerReadyTTL(r.stateBID, 1) // one would-be expiry and one would-be decrease
			row.corrupt(f, r)
			before, ownerBefore := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
			indexBefore := daTTLIndexKeys(f.relay)
			if err := runDATTLBodyInGuard(t, f); !errors.Is(err, errDARelayImageIncompatible) {
				t.Fatalf("body: err=%v, want %v", err, errDARelayImageIncompatible)
			}
			requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, ownerBefore)
			requireDATTLIndexUnchanged(t, f.relay, indexBefore, true)
		})
	}
}

// daTTLIndexKeys reads the State A/B bucket in its link order.
func daTTLIndexKeys(relay *DARelayState) [][32]byte {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.relations.incompleteKeys()
}

// requireDATTLIndexUnchanged requires the State A/B bucket's pre-body link order, and exactness if it was exact.
func requireDATTLIndexUnchanged(t *testing.T, relay *DARelayState, before [][32]byte, exactBefore bool) {
	t.Helper()
	if after := daTTLIndexKeys(relay); !slices.Equal(after, before) {
		t.Fatalf("refusal changed the State A/B index: %x, want %x", after, before)
	}
	if exactBefore {
		requireDATTLIndexExact(t, relay)
	}
}

// requireDATTLIndexExact pins the State A/B bucket to exactly the present records that are not State C.
func requireDATTLIndexExact(t *testing.T, relay *DARelayState) {
	t.Helper()
	if msg := daTTLIndexMismatch(relay); msg != "" {
		t.Fatal(msg)
	}
}

func daTTLIndexMismatch(relay *DARelayState) string {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	want := map[[32]byte]bool{}
	for daID, record := range relay.relations.records() {
		if record.state != daRelayStateCompleteSet {
			want[daID] = true
		}
	}
	got := map[[32]byte]bool{}
	for _, daID := range relay.relations.incompleteKeys() {
		if got[daID] {
			return fmt.Sprintf("State A/B index lists %x twice", daID[:1])
		}
		got[daID] = true
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Sprintf("State A/B index=%v, want %v", got, want)
	}
	return ""
}

// TestDATTLCallbackBodyRefusalArms corrupts one stored value per check arm: the body's error, nothing changed.
func TestDATTLCallbackBodyRefusalArms(t *testing.T) {
	for _, row := range []struct {
		name    string
		corrupt func(*daNonReplayFixture, daTTLCallbackRecords)
		want    func(error) bool
	}{
		{"locator row moved", daTTLRelayEdit(func(s *DARelayState, r daTTLCallbackRecords) {
			s.relations.putLocator(r.stateA.txid, daRelayLocator{daID: r.stateAID, kind: daRelayLocatorChunk, chunkIndex: 1})
		}), daTTLIs(errDARelayLocatorMismatch)},
		{"survivor per-da_id entry differs", daTTLRelayEdit(func(s *DARelayState, r daTTLCallbackRecords) { s.orphanBytesByDAID[r.stateAID]++ }), daTTLIs(errDARelayImageIncompatible)},
		{"expiring per-da_id entry larger", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.setOwnerReadyTTL(r.stateAID, 1)
			f.mutateRelay(func(s *DARelayState) { s.orphanBytesByDAID[r.stateAID]++ })
		}, daTTLIs(errDARelayImageIncompatible)},
		{"State B carries a per-da_id entry", daTTLRelayEdit(func(s *DARelayState, r daTTLCallbackRecords) { s.orphanBytesByDAID[r.stateBID] = 5 }), daTTLIs(errDARelayImageIncompatible)},
		{"record stored under another da_id", daTTLRelayEdit(func(s *DARelayState, r daTTLCallbackRecords) {
			record := s.relations.recordValue(r.stateAID)
			record.daID = [32]byte{0xa8}
			s.relations.scalarRecord(r.stateAID, record)
		}), daTTLIs(errDARelayTTLRecordKeyMismatch)},
		{"victim claim not finalized", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.setOwnerReadyTTL(r.stateAID, 1)
			token := r.setup.sets[r.stateAID].chunks[0].member.token
			ownerReadyEditOwner(f, func(o *PendingOutpointOwner) { o.byToken[token].finalized = false })
		}, func(err error) bool { return err != nil && strings.Contains(err.Error(), "DA victim claim mismatch") }},
		// The same unfinalized claim on a survivor, which is no victim.
		{"survivor claim not finalized", daTTLOwnerEdit(func(o *PendingOutpointOwner, r daTTLCallbackRecords) {
			o.byToken[r.setup.sets[r.stateAID].chunks[0].member.token].finalized = false
		}), daTTLIs(errDARelayImageIncompatible)},
		// A survivor's input with its owner row missing or different.
		{"survivor outpoint row missing", daTTLOwnerEdit(func(o *PendingOutpointOwner, r daTTLCallbackRecords) { delete(o.byOutpoint, r.stateA.inputs[0]) }), daTTLIs(errDARelayImageIncompatible)},
		{"survivor outpoint row different", daTTLOwnerEdit(func(o *PendingOutpointOwner, r daTTLCallbackRecords) {
			row := o.byOutpoint[r.stateA.inputs[0]]
			row.txid[0] ^= 0xff
			o.byOutpoint[r.stateA.inputs[0]] = row
		}), daTTLIs(errDARelayImageIncompatible)},
		// The same owner-row edit on an expiring member, which is a victim.
		{"expiring outpoint row different", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.setOwnerReadyTTL(r.stateAID, 1)
			ownerReadyEditOwner(f, func(o *PendingOutpointOwner) {
				row := o.byOutpoint[r.stateA.inputs[0]]
				row.txid[0] ^= 0xff
				o.byOutpoint[r.stateA.inputs[0]] = row
			})
		}, func(err error) bool { return err != nil && strings.Contains(err.Error(), "DA victim input mismatch") }},
		{"revision above the high-water", daTTLRelayEdit(func(s *DARelayState, r daTTLCallbackRecords) {
			s.records = s.relations.recordValue(r.stateAID).revision - 1
		}), daTTLWrapped(errDARelayImageIncompatible, "revision")},
		{"received time above the high-water", daTTLRelayEdit(func(s *DARelayState, r daTTLCallbackRecords) {
			s.nextReceivedTime = s.relations.recordValue(r.stateAID).receivedTime - 1
		}), daTTLWrapped(errDARelayImageIncompatible, "received time")},
		{"survivor revision overflows", daTTLRelayEdit(func(s *DARelayState, _ daTTLCallbackRecords) { s.records = math.MaxUint64 }), daTTLIs(errDARelayArithmeticOverflow)},
		{"stored staged total differs", daTTLRelayEdit(func(s *DARelayState, _ daTTLCallbackRecords) { s.stagedBytes++ }), daTTLWrapped(errDARelayImageIncompatible, "staged retained bytes")},
		{"stored orphan total differs", daTTLRelayEdit(func(s *DARelayState, _ daTTLCallbackRecords) { s.orphanBytes-- }), daTTLWrapped(errDARelayImageIncompatible, "orphan pool bytes")},
		{"stored commit overhead total differs", daTTLRelayEdit(func(s *DARelayState, _ daTTLCallbackRecords) { s.orphanCommitOverheadBytes-- }), daTTLWrapped(errDARelayImageIncompatible, "orphan commit overhead bytes")},
		{"stored per-peer entry differs", daTTLRelayEdit(func(s *DARelayState, _ daTTLCallbackRecords) { s.orphanBytesByPeerQuotaKey["ttl-peer"]++ }), daTTLWrapped(errDARelayImageIncompatible, `per-peer orphan bytes for "ttl-peer"`)},
		{"selected peer key absent from the stored map", daTTLRelayEdit(func(s *DARelayState, _ daTTLCallbackRecords) { delete(s.orphanBytesByPeerQuotaKey, "ttl-peer") }), daTTLWrapped(errDARelayImageIncompatible, `per-peer orphan bytes for "ttl-peer"`)},
		{"extra stored per-peer entry", daTTLRelayEdit(func(s *DARelayState, _ daTTLCallbackRecords) { s.orphanBytesByPeerQuotaKey["ghost"] = 1 }), daTTLWrapped(errDARelayImageIncompatible, "per-peer orphan bytes: records imply")},
		{"extra stored per-da_id entry", daTTLRelayEdit(func(s *DARelayState, _ daTTLCallbackRecords) { s.orphanBytesByDAID[[32]byte{0xee}] = 1 }), daTTLWrapped(errDARelayImageIncompatible, "per-da_id orphan bytes: records imply")},
		{"index entry absent", daTTLRelayEdit(func(s *DARelayState, r daTTLCallbackRecords) { s.relations.sets[r.stateAID].present = false }), daTTLIs(errDARelayTTLRecordKeyMismatch)},
		{"index entry State C", daTTLRelayEdit(func(s *DARelayState, r daTTLCallbackRecords) {
			record := s.relations.recordValue(r.stateAID)
			record.state = daRelayStateCompleteSet
			s.relations.scalarRecord(r.stateAID, record)
		}), daTTLIs(errDARelayTTLRecordKeyMismatch)},
		// The next four rows corrupt a member token or input set and assert errDARelayImageIncompatible.
		{"zero member token", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			editDATTLChunkMember(f, r.stateAID, func(m *daRelayMemberIdentity) { m.token = PendingOutpointToken{} })
		}, daTTLIs(errDARelayImageIncompatible)},
		{"foreign member token", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			editDATTLChunkMember(f, r.stateAID, func(m *daRelayMemberIdentity) { m.token.owner = &PendingOutpointOwner{} })
		}, daTTLIs(errDARelayImageIncompatible)},
		{"member token held twice", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			token := r.setup.sets[r.stateBID].commit.member.token
			editDATTLChunkMember(f, r.stateAID, func(m *daRelayMemberIdentity) { m.token = token })
		}, daTTLIs(errDARelayImageIncompatible)},
		{"input claimed by two members", reuseDATTLInputInStateB, daTTLIs(errDARelayImageIncompatible)},
		// The State B commit member stores State A's txid, which its own parsed bytes contradict.
		{"commit member txid contradicts its parsed identity", daTTLRelayEdit(func(s *DARelayState, r daTTLCallbackRecords) {
			record := s.relations.recordValue(r.stateBID)
			member := *record.commit.member
			member.txid = r.stateA.txid
			record.commit.member = &member
			s.relations.putRecord(r.stateBID, record)
		}), func(err error) bool {
			var terminal *canonicalDATerminalError
			return errors.As(err, &terminal) && strings.Contains(err.Error(), "contradicts its parsed identity")
		}},
		// A zero count is an inconsistent stored value (underflow invalidates the plan); the rows assert the bare error.
		{"State A count zero", func(f *daNonReplayFixture, r daTTLCallbackRecords) { f.setOwnerReadyTTL(r.stateAID, 0) }, daTTLBareIncompatible},
		{"State B count zero", func(f *daNonReplayFixture, r daTTLCallbackRecords) { f.setOwnerReadyTTL(r.stateBID, 0) }, daTTLBareIncompatible},
		{"nil chainstate", daTTLRelayEdit(func(s *DARelayState, _ daTTLCallbackRecords) { s.mempool.chainState = nil }), func(err error) bool { return err != nil && strings.Contains(err.Error(), "nil chainstate") }},
		{"nil pending-outpoint owner", daTTLRelayEdit(func(s *DARelayState, _ daTTLCallbackRecords) { s.mempool.pendingOutpoints = nil }), func(err error) bool { return err != nil && strings.Contains(err.Error(), "nil pending-outpoint owner") }},
	} {
		t.Run(row.name, func(t *testing.T) {
			f, r := newDATTLCallbackRecords(t)
			owner := f.mp.pendingOutpoints
			row.corrupt(f, r)
			before, ownerBefore := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(owner)
			indexBefore, exactBefore := daTTLIndexKeys(f.relay), daTTLIndexMismatch(f.relay) == ""
			err := runDATTLBodyInGuard(t, f)
			require(t, row.want(err), "body: err=%v, want this arm's refusal", err)
			requireDANonReplayUnchanged(t, f.relay, owner, before, ownerBefore)
			requireDATTLIndexUnchanged(t, f.relay, indexBefore, exactBefore)
		})
	}
}

// TestDATTLCallbackBodyUnboundRelay: with no mempool the DA image is the whole change; a live owner stays untouched.
func TestDATTLCallbackBodyUnboundRelay(t *testing.T) {
	f, r := newDATTLCallbackRecords(t)
	owner := f.mp.pendingOutpoints
	ownerBefore := cloneDAAdmissionOwner(owner)
	f.mutateRelay(func(s *DARelayState) { s.mempool = nil })
	mustAtomic(t, runDATTLBodyInGuard(t, f))
	view := daRelayStateSnapshot(f.relay)
	requireDATTLCount(t, view, r.stateAID, 2)
	requireDATTLCount(t, view, r.stateBID, 2)
	if !reflect.DeepEqual(cloneDAAdmissionOwner(owner), ownerBefore) {
		t.Fatal("unbound body changed an owner it cannot reach")
	}
	mustAtomic(t, runDATTLBodyInGuard(t, f))
	mustAtomic(t, runDATTLBodyInGuard(t, f))
	require(t, reflect.DeepEqual(daRelayStateSnapshot(f.relay).sets, r.base.sets), "the third unbound body call left %v, want only the unchanged State C record", daRelayStateSnapshot(f.relay).sets)
}

// TestDATTLCallbackBodyWalksOnlyStateAB: a refusable State C record is not visited; the State A/B index stays exact.
func TestDATTLCallbackBodyWalksOnlyStateAB(t *testing.T) {
	f, r := newDATTLCallbackRecords(t)
	requireDATTLIndexExact(t, f.relay)
	mustAtomic(t, f.relay.ReleasePeerQuotaKey("unrelated-peer"))
	requireDATTLIndexExact(t, f.relay)
	f.mutateRelay(func(s *DARelayState) {
		mutateOwnerReadyRecord(s, r.stateCID, func(record *daRelaySetRecord) { record.wireBytes = 1 })
	})
	requireDATTLIndexExact(t, f.relay)
	requireDATTLOK(t, runDATTLBodyInGuard(t, f), "body visited State C")
	requireDATTLCount(t, daRelayStateSnapshot(f.relay), r.stateAID, 2)
	requireDATTLIndexExact(t, f.relay)
	for _, want := range []uint64{1, 0} {
		requireDATTLOK(t, runDATTLBodyInGuard(t, f), "body with a corrupt State C record")
		view := daRelayStateSnapshot(f.relay)
		if want != 0 {
			requireDATTLCount(t, view, r.stateAID, want)
		} else if _, present := view.sets[r.stateAID]; present {
			t.Fatal("State A survived its expiry after the clone swap")
		}
		requireDATTLIndexExact(t, f.relay)
	}
}

// daTTLBareIncompatible accepts only errDARelayImageIncompatible itself, as both zero-count arms return it.
func daTTLBareIncompatible(err error) bool {
	return errors.Is(err, errDARelayImageIncompatible) && reflect.TypeOf(err) == reflect.TypeOf(errDARelayImageIncompatible)
}

func daTTLWrapped(want error, detail string) func(error) bool {
	return func(err error) bool { return errors.Is(err, want) && strings.Contains(err.Error(), detail) }
}

func daTTLIs(want error) func(error) bool {
	return func(err error) bool { return errors.Is(err, want) }
}

// daTTLRelayEdit and daTTLOwnerEdit run edit on the relay or on the pending-outpoint owner under its mutex.
func daTTLRelayEdit(edit func(*DARelayState, daTTLCallbackRecords)) func(*daNonReplayFixture, daTTLCallbackRecords) {
	return func(f *daNonReplayFixture, r daTTLCallbackRecords) {
		f.mutateRelay(func(s *DARelayState) { edit(s, r) })
	}
}

func daTTLOwnerEdit(edit func(*PendingOutpointOwner, daTTLCallbackRecords)) func(*daNonReplayFixture, daTTLCallbackRecords) {
	return func(f *daNonReplayFixture, r daTTLCallbackRecords) {
		ownerReadyEditOwner(f, func(o *PendingOutpointOwner) { edit(o, r) })
	}
}

// editDATTLChunkMember replaces chunk 0's member of one record with an edited copy, keeping other identities.
func editDATTLChunkMember(f *daNonReplayFixture, daID [32]byte, edit func(*daRelayMemberIdentity)) {
	f.mutateRelay(func(s *DARelayState) {
		mutateOwnerReadyRecord(s, daID, func(record *daRelaySetRecord) {
			chunks := make(map[uint16]daRelayChunk, len(record.chunks))
			for index, chunk := range record.chunks {
				chunks[index] = chunk
			}
			chunk := chunks[0]
			member := *chunk.member
			edit(&member)
			chunk.member = &member
			chunks[0] = chunk
			record.chunks = chunks
		})
	})
}

// reuseDATTLInputInStateB re-signs State B's commit over State A's same-length input, so only the input set repeats.
func reuseDATTLInputInStateB(f *daNonReplayFixture, r daTTLCallbackRecords) {
	next := f.next
	f.next = slices.Index(f.outpoints, r.stateA.inputs[0])
	duplicate := f.signed(r.stateB.spec)
	f.next = next
	f.mutateRelay(func(s *DARelayState) {
		record := s.relations.recordValue(r.stateBID)
		member := *record.commit.member
		record.commit.member = &member
		replaceOwnerReadyMember(f, s, &member, &record.commit.txBytes, duplicate, daRelayLocator{daID: r.stateBID, kind: daRelayLocatorCommit})
		s.relations.putRecord(r.stateBID, record)
	})
}

// requireDATTLIndexStep pins the State A/B index after one production publication and runs one succeeding body call.
func requireDATTLIndexStep(t *testing.T, f *daNonReplayFixture, step string) {
	t.Helper()
	requireDATTLIndexExact(t, f.relay)
	requireDATTLOK(t, runDATTLBodyInGuard(t, f), "%s: body after the publication", step)
	requireDATTLIndexExact(t, f.relay)
}

// TestDATTLCallbackIndexProductionPaths pins the State A/B index across staging, completion and PEER quota cleanup.
func TestDATTLCallbackIndexProductionPaths(t *testing.T) {
	f := newDANonReplayFixture(t, 10)
	grown, staged, completed, released, late := [32]byte{0xd1}, [32]byte{0xd2}, [32]byte{0xd3}, [32]byte{0xd4}, [32]byte{0xd5}
	f.ownerReadyChunk(grown, 0, "grow-0", daNonReplayPeer("keep"))
	requireDATTLIndexStep(t, f, "State A created")
	f.ownerReadyChunk(grown, 1, "grow-1", daNonReplayPeer("keep"))
	requireDATTLIndexStep(t, f, "State A grown")
	f.ownerReadyChunk(staged, 0, "staged", daNonReplayPeer("keep"))
	f.ownerReadyCommit(staged, 2, daNonReplayPeer("keep"))
	requireDATTLState(t, f, staged, daRelayStateStagedCommit)
	requireDATTLIndexStep(t, f, "State A to State B")
	payload := []byte("complete")
	f.ownerReadyChunk(completed, 0, string(payload), daNonReplayPeer("keep"))
	commit := f.signed(daNonReplayTxSpec{kind: 0x01, daID: completed, chunkCount: 1, commitment: sha3.Sum256(payload), commitmentOutputs: 1})
	f.admit(commit, daNonReplayPeer("keep"))
	requireDATTLState(t, f, completed, daRelayStateCompleteSet)
	requireDATTLIndexStep(t, f, "State A to State C")
	f.admit(f.signed(daNonReplayTxSpec{kind: 0x01, daID: late, chunkCount: 1, commitment: sha3.Sum256(payload), commitmentOutputs: 1}), daNonReplayPeer("keep"))
	requireDATTLState(t, f, late, daRelayStateStagedCommit)
	requireDATTLIndexStep(t, f, "commit staged without chunks")
	f.ownerReadyChunk(late, 0, string(payload), daNonReplayPeer("keep"))
	requireDATTLState(t, f, late, daRelayStateCompleteSet)
	requireDATTLIndexStep(t, f, "State B to State C")
	f.ownerReadyChunk(released, 0, "released", daNonReplayPeer("drop"))
	requireDATTLIndexExact(t, f.relay)
	mustAtomic(t, f.relay.ReleasePeerQuotaKey("drop"))
	if _, present := daRelayStateSnapshot(f.relay).sets[released]; present {
		t.Fatal("PEER cleanup kept the released record")
	}
	requireDATTLIndexStep(t, f, "PEER cleanup removal")
}

// TestDATTLCallbackIndexD1Projection pins the index on the D1 projection: the State A survivor stays, the included
// State C record and the State B record whose input the final chain spent are removed; O1 is not published.
func TestDATTLCallbackIndexD1Projection(t *testing.T) {
	x := canonicalDAOwnerFixtureOver(t, newDANonReplayFixture(t, 10))
	x.stateC = daRelayTestID(0x33)
	x.admit("a0", daNonReplayTxSpec{kind: 0x02, daID: x.stateA, chunkIndex: 0, payload: []byte("d1 state-a")}, daNonReplayPeer("peer-a"))
	x.admit("commit", daNonReplayTxSpec{kind: 0x01, daID: x.stateB, chunkCount: 2, commitment: sha3.Sum256([]byte("d1 state-b")), commitmentOutputs: 1}, daNonReplayPeer("peer-b"))
	x.admit("b0", daNonReplayTxSpec{kind: 0x02, daID: x.stateB, chunkIndex: 0, payload: []byte("d1 state-b chunk")}, daNonReplayPeer("peer-b"))
	x.admit("c0", daNonReplayTxSpec{kind: 0x02, daID: x.stateC, chunkIndex: 0, payload: []byte("d1 state-c")}, LocalDAProvenance())
	x.admit("ccommit", daNonReplayTxSpec{kind: 0x01, daID: x.stateC, chunkCount: 1, commitment: sha3.Sum256([]byte("d1 state-c")), commitmentOutputs: 1}, LocalDAProvenance())
	x.capture()
	x.included = []canonicalDASetIdentity{x.identityOf(x.stateC, "ccommit", "c0")}
	x.spendInput("b0")
	requireDATTLD1Records(t, x, map[[32]byte]daRelaySetState{x.stateA: daRelayStateOrphanChunks, x.stateB: daRelayStateStagedCommit, x.stateC: daRelayStateCompleteSet})
	requireDATTLIndexExact(t, x.f.relay)
	pair := x.requirePair()
	(&preparedCanonicalDAImage{relay: x.f.relay, projected: pair.retained}).publish()
	requireDATTLD1Records(t, x, map[[32]byte]daRelaySetState{x.stateA: daRelayStateOrphanChunks})
	requireDATTLIndexStep(t, x.f, "D1 projection")
}

// requireDATTLD1Records pins the live record set to exactly these records in these states.
func requireDATTLD1Records(t *testing.T, x *canonicalDAOwnerFixture, want map[[32]byte]daRelaySetState) {
	t.Helper()
	got := map[[32]byte]daRelaySetState{}
	for daID, record := range daRelayStateSnapshot(x.f.relay).sets {
		got[daID] = record.state
	}
	require(t, reflect.DeepEqual(got, want), "records=%v, want %v", got, want)
}

func requireDATTLState(t *testing.T, f *daNonReplayFixture, daID [32]byte, want daRelaySetState) {
	t.Helper()
	if record, present := daRelayStateSnapshot(f.relay).sets[daID]; !present || record.state != want {
		t.Fatalf("record %x: present=%v state=%v, want %v", daID[:1], present, record.state, want)
	}
}

// TestDATTLCallbackEmptiedBucketDropped pins that removing the last State A/B record leaves no empty State A/B bucket.
func TestDATTLCallbackEmptiedBucketDropped(t *testing.T) {
	f, r := newDATTLCallbackRecords(t)
	f.setOwnerReadyTTL(r.stateAID, 1)
	f.setOwnerReadyTTL(r.stateBID, 1)
	mustAtomic(t, runDATTLBodyInGuard(t, f))
	f.relay.mu.Lock()
	defer f.relay.mu.Unlock()
	if bucket, present := f.relay.relations.buckets[daRelayIncompleteKey]; present {
		t.Fatalf("emptied State A/B bucket retained: %+v", bucket)
	}
}

// daTTLRecordingService runs beforeAttempt, records the attempt by name and, unless refused, runs decrease once.
type daTTLRecordingService struct {
	name          string
	attempts      *[]string
	refuse        error
	beforeAttempt func()
}

func (r *daTTLRecordingService) EnterDATTLMutation(decrease func() error) error {
	if r.beforeAttempt != nil {
		r.beforeAttempt()
	}
	*r.attempts = append(*r.attempts, r.name)
	if r.refuse != nil {
		return r.refuse
	}
	return decrease()
}

// TestDATTLCallbackBindingSelection: absent invokes nothing, the latest publication wins, a snapshot keeps its Service.
func TestDATTLCallbackBindingSelection(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	var attempts []string
	decreases := 0
	decrease := func() error { decreases++; return nil }
	s1 := &daTTLRecordingService{name: "S1", attempts: &attempts}
	s2 := &daTTLRecordingService{name: "S2", attempts: &attempts}
	require(t, f.engine.DATTLBindingService() == nil, "binding present before any publication")
	require(t, f.engine.enterSelectedDATTL(decrease) == nil && len(attempts) == 0 && decreases == 0, "absent binding invoked: attempts=%v decreases=%d", attempts, decreases)
	f.engine.PublishDATTLBinding(nil)
	require(t, f.engine.DATTLBindingService() == nil, "nil publication populated the binding")
	f.engine.PublishDATTLBinding(s1)
	require(t, f.engine.DATTLBindingService() == DATTLMutationService(s1), "identity read after S1 publication")
	f.engine.PublishDATTLBinding(nil)
	require(t, f.engine.DATTLBindingService() == DATTLMutationService(s1), "nil publication replaced S1")
	f.engine.PublishDATTLBinding(s2)
	require(t, f.engine.DATTLBindingService() == DATTLMutationService(s2), "identity read after S2 publication")
	f.engine.daRelay.mu.Lock()
	f.owner.mu.Lock()
	read := make(chan DATTLMutationService, 1)
	reader := goDone(func() { read <- f.engine.DATTLBindingService() })
	var got DATTLMutationService
	returned := false
	select {
	case got = <-read:
		returned = true
	case <-time.After(5 * time.Second):
	}
	f.owner.mu.Unlock()
	f.engine.daRelay.mu.Unlock()
	joinWithin(t, "the identity read after the DA locks were released", reader)
	require(t, returned, "identity read waited on the DA relay or owner mutex")
	require(t, got == DATTLMutationService(s2), "identity read under held DA locks=%v, want S2", got)
	require(t, f.engine.enterSelectedDATTL(decrease) == nil && slices.Equal(attempts, []string{"S2"}) && decreases == 1, "latest binding: attempts=%v decreases=%d", attempts, decreases)
	// S2 binds after the selection snapshot and before the registration attempt.
	attempts, decreases = nil, 0
	snapshotThenBind := &daTTLRecordingService{name: "S1", attempts: &attempts}
	snapshotThenBind.beforeAttempt = func() {
		require(t, len(attempts) == 0 && decreases == 0, "S2 published after registration: attempts=%v decreases=%d", attempts, decreases)
		f.engine.PublishDATTLBinding(s2)
	}
	f.engine.PublishDATTLBinding(snapshotThenBind)
	err := f.engine.enterSelectedDATTL(decrease)
	require(t, err == nil && slices.Equal(attempts, []string{"S1"}) && decreases == 1 && f.engine.DATTLBindingService() == DATTLMutationService(s2), "snapshot retarget: attempts=%v decreases=%d", attempts, decreases)
	// A refused registration is returned unchanged, runs no decrease, and falls back nowhere.
	attempts, decreases = nil, 0
	closed := errors.New("service already closed")
	refusing := &daTTLRecordingService{name: "closed", attempts: &attempts, refuse: closed}
	f.engine.PublishDATTLBinding(s1)
	f.engine.PublishDATTLBinding(refusing)
	err = f.engine.enterSelectedDATTL(decrease)
	require(t, errors.Is(err, closed) && reflect.TypeOf(err) == reflect.TypeOf(closed) && slices.Equal(attempts, []string{"closed"}) && decreases == 0, "refused registration: err=%v attempts=%v decreases=%d", err, attempts, decreases)
	var nilEngine *SyncEngine
	nilEngine.PublishDATTLBinding(s1)
	require(t, nilEngine.DATTLBindingService() == nil && nilEngine.enterSelectedDATTL(decrease) == nil && decreases == 0, "nil engine binding")
}

// TestDATTLCallbackBindingChangesNoDAState: claims, publication, identity read and selection change no DA state.
func TestDATTLCallbackBindingChangesNoDAState(t *testing.T) {
	f, r := newDATTLCallbackRecords(t)
	engine := &SyncEngine{chainState: f.state, daRelay: f.relay}
	requireDATTLCount(t, r.setup, r.stateAID, 3)
	requireDATTLCount(t, r.setup, r.stateBID, 3)
	beforeRelay, beforeOwner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	firstCalls := 0
	first := func([]byte) (func(bool), error) { firstCalls++; return func(bool) {}, nil }
	later := func([]byte) (func(bool), error) {
		t.Error("later claimant's hook installed")
		return func(bool) {}, nil
	}
	var attempts []string
	require(t, engine.enterSelectedDATTL(func() error { t.Error("absent binding ran decrease"); return nil }) == nil, "absent selection")
	for _, hook := range []func([]byte) (func(bool), error){first, later} {
		claimed, err := engine.ClaimDARelayState(f.relay, hook)
		require(t, err == nil && claimed == f.relay, "claim: claimed=%p err=%v", claimed, err)
	}
	engine.PublishDATTLBinding(&daTTLRecordingService{name: "S1", attempts: &attempts, refuse: errors.New("service already closed")})
	_ = engine.DATTLBindingService()
	err := engine.enterSelectedDATTL(func() error { t.Error("refused selection ran decrease"); return nil })
	require(t, err != nil && slices.Equal(attempts, []string{"S1"}), "refused selection err=%v attempts=%v", err, attempts)
	engine.PublishDATTLBinding(&daTTLRecordingService{name: "S2", attempts: &attempts})
	require(t, engine.enterSelectedDATTL(func() error { return nil }) == nil && slices.Equal(attempts, []string{"S1", "S2"}), "admitted selection attempts=%v", attempts)
	_, _ = engine.reorgDAAdmission(nil)
	require(t, firstCalls == 1, "later claim replaced the first claimant's hook: first calls=%d", firstCalls)
	requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, beforeRelay, beforeOwner)
	require(t, f.relay.mu.TryLock(), "DA relay mutex leaked")
	f.relay.mu.Unlock()
}

// TestDATTLCallbackBindingConcurrentPublications: a racing selection selects S_j, before <= j <= after+1 (-race).
func TestDATTLCallbackBindingConcurrentPublications(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	const publications = 400
	var recorded, selected atomic.Int64
	services := make([]*daTTLFuncService, publications)
	for i := range services {
		services[i] = &daTTLFuncService{enter: func(decrease func() error) error {
			selected.Store(int64(i))
			return decrease()
		}}
	}
	f.engine.PublishDATTLBinding(services[0])
	done := goDone(func() {
		for i := 1; i < publications; i++ {
			f.engine.PublishDATTLBinding(services[i])
			recorded.Store(int64(i))
		}
	})
	defer joinWithin(t, "the publisher goroutine", done)
	for range 2 * publications {
		before := recorded.Load()
		selected.Store(-1)
		require(t, f.engine.enterSelectedDATTL(func() error { return nil }) == nil, "selection error")
		after, got := recorded.Load(), selected.Load()
		require(t, before <= got && got <= after+1, "selected S_%d outside [S_%d, S_%d]", got, before, after+1)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the publisher goroutine did not finish")
	}
	require(t, f.engine.DATTLBindingService() == DATTLMutationService(services[publications-1]), "final binding is not the last publication")
}

// TestDATTLCallbackRunsInsideTheTransitionHold: writers started under the held guard run after it, on the decreased image.
func TestDATTLCallbackRunsInsideTheTransitionHold(t *testing.T) {
	f, r := newDATTLCallbackRecords(t)
	f.state.admissionMu.Lock()
	released := false
	var started []<-chan struct{}
	defer func() {
		if !released {
			f.state.admissionMu.Unlock()
		}
		joinWithin(t, "the parked writers and the body", started...)
	}()
	done := make(chan error, 2)
	started = append(started, goDone(func() { done <- f.relay.ReleasePeerQuotaKey("unrelated-peer") }))
	awaitCanonicalMOAdmissionRLock(t, "ReleasePeerQuotaKey", 1)
	freshID := [32]byte{0xa8}
	fresh := f.signed(daNonReplayTxSpec{kind: 0x02, daID: freshID, payload: []byte("ttl-fresh")})
	started = append(started, goDone(func() { _, err := f.tryAdmit(fresh, daNonReplayPeer("fresh-peer")); done <- err }))
	awaitCanonicalMOAdmissionRLock(t, "BeginDAAdmission", 1)
	body := make(chan error, 1)
	started = append(started, goDone(func() { body <- advanceDATTLChecked(f.relay, f.mp.pendingOutpoints) }))
	select {
	case err := <-body:
		require(t, err == nil, "in-guard TTL body: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("TTL body blocked under the held exclusive admission guard")
	}
	select {
	case err := <-done:
		t.Fatalf("a parked writer ran while the admission guard was held (err=%v)", err)
	default:
	}
	f.state.admissionMu.Unlock()
	released = true
	for range 2 {
		select {
		case err := <-done:
			require(t, err == nil, "parked writer after the guard release: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("a writer never proceeded after the guard release")
		}
	}
	after := daRelayStateSnapshot(f.relay)
	requireDATTLCount(t, after, r.stateAID, 2)
	requireDATTLCount(t, after, r.stateBID, 2)
	requireDATTLCount(t, after, freshID, 7) // the fixture's orphan TTL: created after the decrease
}

// TestDATTLCallbackDecrementReachability pins the production callers of the listed TTL count-lowering functions.
func TestDATTLCallbackDecrementReachability(t *testing.T) {
	want := map[string][]string{
		"addOwnerReadyTTLSurvivor":         {"planOwnerReadyTTLRecordLocked"},
		"planOwnerReadyTTLRecordLocked":    {"planOwnerReadyTTLLocked"},
		"planOwnerReadyTTLLocked":          {"advanceOwnerReadyTTLInGuard"},
		"commitOwnerReadyTTLPlanLocked":    {"advanceOwnerReadyTTLInGuard"},
		"applyOwnerReadyTTLPlanUnderOwner": {"commitOwnerReadyTTLPlanLocked"},
		"applyOwnerReadyTTLPlanLocked":     {"advanceOwnerReadyTTLInGuard", "applyOwnerReadyTTLPlanUnderOwner"},
		"advanceOwnerReadyTTLInGuard":      {"enterDATTL"},
		"advanceOrphanTTLLocked":           {"advanceOrphanTTL"},
	}
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	got := productionReferenceCensus(t, names...)
	require(t, reflect.DeepEqual(got, want), "TTL decrement reachability=%v, want %v", got, want)
}

// TestDATTLCallbackLatchedNewInvokesNothing: a TERMINAL_PERSISTENCE(new) publication makes no entry attempt.
func TestDATTLCallbackLatchedNewInvokesNothing(t *testing.T) {
	f := newPendingOutpointSyncFixture(t)
	require(t, f.engine.DARelayState() != nil, "fixture engine has no bound DA relay")
	var attempts []string
	f.engine.PublishDATTLBinding(&daTTLRecordingService{name: "S", attempts: &attempts})
	f.extendCanonical(t, 1, 400)
	require(t, slices.Equal(attempts, []string{"S"}), "ordinary ACCEPTED/NEW publication: attempts=%v, want one", attempts)
	prevWrite := writeFileAtomicFn
	t.Cleanup(func() { writeFileAtomicFn = prevWrite })
	injected := false
	writeFileAtomicFn = func(path string, data []byte, mode os.FileMode) error {
		if path != f.store.indexPath || injected {
			return prevWrite(path, data, mode)
		}
		injected = true
		if err := prevWrite(path, data, mode); err != nil {
			return err
		}
		return newAtomicWriteError(atomicWriteAfterNamespaceCommit, path, atomicWriteOverwrite, os.ErrPermission)
	}
	height := f.tipHeight + 1
	coinbase := reorgTestCoinbaseForAddress(t, height, consensus.BlockSubsidy(height, f.alreadyGenerated), f.sourceAddress)
	block := buildSingleTxBlock(t, f.tipHash, f.target, 401, coinbase)
	summary, err := f.engine.ApplyBlock(block, nil)
	require(t, injected && err != nil && summary != nil && summary.BlockHeight == height, "ApplyBlock=(%+v,%v) injected=%v, want the published NEW summary with a terminal error", summary, err, injected)
	require(t, f.engine.persistenceFaulted() && f.engine.chainState.view().tipHash == summary.BlockHash, "terminal NEW did not publish and latch")
	require(t, slices.Equal(attempts, []string{"S"}), "TERMINAL_PERSISTENCE(new) invoked the entry: attempts=%v", attempts)
}

// daTTLEngineRecords admits one State A chunk at count 3 and one State B commit at count 1 into f.engine's DA relay.
func daTTLEngineRecords(t *testing.T, f *pendingOutpointSyncFixture) (*daNonReplayFixture, [32]byte, [32]byte) {
	t.Helper()
	signer := mustNodeMLDSA87Keypair(t)
	address := consensus.P2PKCovenantDataForPubkey(signer.PubkeyBytes())
	outpoints := make([]consensus.Outpoint, 0, 2)
	for i := range 2 {
		op := consensus.Outpoint{Txid: [32]byte{0xd7, byte(i)}}
		f.engine.chainState.Utxos[op] = consensus.UtxoEntry{Value: 2_000_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), address...), CreationHeight: 1}
		outpoints = append(outpoints, op)
	}
	x := &daNonReplayFixture{t: t, signer: signer, address: address, state: f.engine.chainState, mp: f.mempool, relay: f.engine.DARelayState(), outpoints: outpoints}
	stateA, stateB := [32]byte{0xa9}, [32]byte{0xb9}
	x.ownerReadyChunk(stateA, 0, "ttl-e2e-a", daNonReplayPeer("ttl-e2e-peer"))
	x.ownerReadyCommit(stateB, 1, LocalDAProvenance())
	x.setOwnerReadyTTL(stateA, 3)
	x.setOwnerReadyTTL(stateB, 1)
	return x, stateA, stateB
}

// TestDATTLCallbackEndToEndBodyRefusalConsumed: a body refusal under the selection or the lease entry leaves the apply
// ACCEPTED/NEW with a nil error, the engine unlatched, one lease released and the image unchanged.
func TestDATTLCallbackEndToEndBodyRefusalConsumed(t *testing.T) {
	corruptions := map[string]func(*daNonReplayFixture, [32]byte, [32]byte){
		"inconsistent stored value": func(x *daNonReplayFixture, _, stateB [32]byte) {
			x.mutateRelay(func(s *DARelayState) {
				mutateOwnerReadyRecord(s, stateB, func(record *daRelaySetRecord) { record.wireBytes = 1 })
			})
		},
		"unbound owner token": func(x *daNonReplayFixture, stateA, _ [32]byte) {
			token := daRelayStateSnapshot(x.relay).sets[stateA].chunks[0].member.token
			ownerReadyEditOwner(x, func(o *PendingOutpointOwner) { o.byToken[token].txid[0] ^= 0xff })
		},
	}
	for name, corrupt := range corruptions {
		for _, leased := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/leased=%v", name, leased), func(t *testing.T) {
				requireDATTLBodyRefusalConsumed(t, corrupt, leased)
			})
		}
	}
}

func requireDATTLBodyRefusalConsumed(t *testing.T, corrupt func(*daNonReplayFixture, [32]byte, [32]byte), leased bool) {
	f := newPendingOutpointSyncFixture(t)
	x, stateA, stateB := daTTLEngineRecords(t, f)
	var results []error
	var before daRelayStateView
	var ownerBefore *PendingOutpointOwner
	entry := func(decrease func() error) error {
		corrupt(x, stateA, stateB)
		before, ownerBefore = daRelayStateSnapshot(x.relay), cloneDAAdmissionOwner(x.mp.pendingOutpoints)
		err := decrease()
		results = append(results, err)
		return err
	}
	height := f.tipHeight + 1
	coinbase := reorgTestCoinbaseForAddress(t, height, consensus.BlockSubsidy(height, f.alreadyGenerated), f.sourceAddress)
	block := buildSingleTxBlock(t, f.tipHash, f.target, 500, coinbase)
	var summary *ChainStateConnectSummary
	var err error
	var acquired, released int
	if leased {
		var finish func()
		summary, finish, err = f.engine.ApplyBlockWithReorgDeferredUnderLease(block, nil, entry)
		finish()
	} else {
		f.engine.PublishDATTLBinding(&daTTLFuncService{enter: func(decrease func() error) error {
			acquired++
			defer func() { released++ }()
			return entry(decrease)
		}})
		summary, err = f.engine.ApplyBlock(block, nil)
		require(t, acquired == 1 && released == 1, "no-lease leases acquired=%d released=%d, want 1 and 1", acquired, released)
	}
	require(t, err == nil && summary != nil && summary.BlockHeight == height, "apply=(%+v,%v), want ACCEPTED/NEW", summary, err)
	require(t, len(summary.CanonicalAppliedBlocks) == 1 && summary.CanonicalAppliedBlocks[0].Hash == summary.BlockHash, "relayed blocks=%+v, want the applied block", summary.CanonicalAppliedBlocks)
	require(t, len(results) == 1 && errors.Is(results[0], errDARelayImageIncompatible), "entry results=%v, want one %v", results, errDARelayImageIncompatible)
	require(t, !f.engine.TerminalFaulted(), "the consumed refusal latched the engine")
	requireDANonReplayUnchanged(t, x.relay, x.mp.pendingOutpoints, before, ownerBefore)
}

// daTTLFuncService is a binding whose entry is enter.
type daTTLFuncService struct{ enter func(func() error) error }

func (d *daTTLFuncService) EnterDATTLMutation(decrease func() error) error { return d.enter(decrease) }

// panicDATTLBodyAt runs the body under the held guard with a panic injected at stage and returns the recovered value.
func panicDATTLBodyAt(t *testing.T, f *daNonReplayFixture, stage daTTLStage) (recovered any) {
	t.Helper()
	f.relay.ttlHook = func(at daTTLStage) {
		if at == stage {
			panic(fmt.Sprintf("ttl panic at stage %d", stage))
		}
	}
	defer func() { f.relay.ttlHook = nil }()
	f.state.admissionMu.Lock()
	defer f.state.admissionMu.Unlock()
	defer func() { recovered = recover() }()
	_ = f.relay.advanceOwnerReadyTTLInGuard()
	return nil
}

// requireDATTLLocksFree fails by name when the body left the DA relay or owner mutex held.
func requireDATTLLocksFree(t *testing.T, relay *DARelayState, owner *PendingOutpointOwner) {
	t.Helper()
	require(t, relay.mu.TryLock(), "DA relay mutex held after unwind")
	relay.mu.Unlock()
	require(t, owner.mu.TryLock(), "owner mutex held after unwind")
	owner.mu.Unlock()
}

// requireDATTLAppliedImage requires A 3->2 with a fresh revision, B removed with claim and prefetch set, then A to 1.
func requireDATTLAppliedImage(t *testing.T, f *daNonReplayFixture, r daTTLCallbackRecords, image daTTLImage) {
	t.Helper()
	applied := daTTLSnapshot(f.relay, f.mp.pendingOutpoints)
	requireDATTLOK(t, daTTLOutsideErr(image, applied), "applied image")
	before, after, ownerAfter := image.view, applied.view, applied.owner
	requireDATTLCount(t, after, r.stateAID, 2)
	ownerReadyRecordAbsent(t, after, r.stateBID, r.stateB.txid)
	ownerReadyClaimGone(t, ownerAfter, before.sets[r.stateBID].commit.member.token, r.stateB.inputs)
	require(t, after.records == before.records+1, "records=%d after the applied decrease, want %d", after.records, before.records+1)
	wantIndexes, wantExpires := maps.Clone(before.prefetchIndexes), maps.Clone(before.prefetchExpires)
	delete(wantIndexes, r.stateBID)
	delete(wantExpires, r.stateBID)
	require(t, reflect.DeepEqual(after.prefetchIndexes, wantIndexes) && reflect.DeepEqual(after.prefetchExpires, wantExpires), "prefetch after the applied decrease=%v %v, want only the removed State B set released", after.prefetchIndexes, after.prefetchExpires)
	require(t, advanceDATTLInGuard(f.relay) == nil, "the next body call refused the applied image")
	requireDATTLCount(t, daRelayStateSnapshot(f.relay), r.stateAID, 1)
}

// TestDATTLCallbackBodyPanicKeepsWholeImage: a panic before the first or after the last mutation propagates with the
// DA and owner mutexes released and the complete old or applied image (RUBIN_COMPACT_BLOCKS.md Section 5).
func TestDATTLCallbackBodyPanicKeepsWholeImage(t *testing.T) {
	for _, stage := range []daTTLStage{daTTLPlanned, daTTLApplied} {
		t.Run(fmt.Sprintf("stage=%d", stage), func(t *testing.T) {
			f, r := newDATTLCallbackRecords(t)
			f.setOwnerReadyTTL(r.stateBID, 1)
			f.relay.prefetch.indexes[r.stateBID] = map[uint16]string{0: "ttl-peer"}
			f.relay.prefetch.expires[r.stateBID] = time.Now().Add(time.Hour)
			before := daTTLSnapshot(f.relay, f.mp.pendingOutpoints)
			got := panicDATTLBodyAt(t, f, stage)
			require(t, got == fmt.Sprintf("ttl panic at stage %d", stage), "recovered %v, want the injected panic", got)
			requireDATTLLocksFree(t, f.relay, f.mp.pendingOutpoints)
			if stage == daTTLPlanned {
				requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before.view, before.owner)
				return
			}
			requireDATTLAppliedImage(t, f, r, before)
		})
	}
}

// TestDATTLCallbackEndToEndBodyPanic: a body panic under ApplyBlock's selection propagates unrecovered, releases the
// entry's lease once and the DA mutexes, leaves the old or applied image, and the admission guard stays held.
func TestDATTLCallbackEndToEndBodyPanic(t *testing.T) {
	for _, stage := range []daTTLStage{daTTLPlanned, daTTLApplied} {
		t.Run(fmt.Sprintf("stage=%d", stage), func(t *testing.T) {
			f := newPendingOutpointSyncFixture(t)
			x, stateA, stateB := daTTLEngineRecords(t, f)
			// The entry mirrors the Service entry under no lease: one registered lease, one decrease, released by defer.
			var leases sync.WaitGroup
			var acquired, released atomic.Int32
			var before daTTLImage
			f.engine.PublishDATTLBinding(&daTTLFuncService{enter: func(decrease func() error) error {
				before = daTTLSnapshot(x.relay, x.mp.pendingOutpoints)
				leases.Add(1)
				acquired.Add(1)
				defer func() { released.Add(1); leases.Done() }()
				return decrease()
			}})
			want := fmt.Sprintf("e2e ttl panic at stage %d", stage)
			x.relay.ttlHook = func(at daTTLStage) {
				if at == stage {
					panic(want)
				}
			}
			height := f.tipHeight + 1
			coinbase := reorgTestCoinbaseForAddress(t, height, consensus.BlockSubsidy(height, f.alreadyGenerated), f.sourceAddress)
			block := buildSingleTxBlock(t, f.tipHash, f.target, 600, coinbase)
			got := func() (value any) {
				defer func() { value = recover() }()
				_, _ = f.engine.ApplyBlock(block, nil)
				return nil
			}()
			x.relay.ttlHook = nil
			require(t, got == want, "recovered %v, want the injected panic", got)
			require(t, acquired.Load() == 1 && released.Load() == 1, "leases acquired=%d released=%d, want 1 and 1", acquired.Load(), released.Load())
			waited := make(chan struct{})
			go func() { leases.Wait(); close(waited) }()
			select {
			case <-waited:
			case <-time.After(5 * time.Second):
				t.Fatal("a wait on the released lease is stranded")
			}
			requireDATTLLocksFree(t, x.relay, x.mp.pendingOutpoints)
			require(t, !f.engine.chainState.admissionMu.TryLock(), "admission guard released after the unwind")
			require(t, f.engine.mutationMu.TryLock(), "engine mutation lock held after the unwind")
			f.engine.mutationMu.Unlock()
			after := daRelayStateSnapshot(x.relay)
			if stage == daTTLPlanned {
				requireDANonReplayUnchanged(t, x.relay, x.mp.pendingOutpoints, before.view, before.owner)
				return
			}
			requireDATTLOK(t, daTTLOutsideErr(before, daTTLSnapshot(x.relay, x.mp.pendingOutpoints)), "applied image")
			requireDATTLCount(t, after, stateA, 2)
			_, present := after.sets[stateB]
			require(t, !present && after.records == before.view.records+1, "applied image: State B present=%v records=%d, want removed and %d", present, after.records, before.view.records+1)
		})
	}
}

// TestDATTLCallbackEndToEndGenesisBootstrap: genesis bootstrap attempts a bound entry once; unbound, it changes nothing.
func TestDATTLCallbackEndToEndGenesisBootstrap(t *testing.T) {
	for _, bound := range []bool{true, false} {
		t.Run(fmt.Sprintf("bound=%v", bound), func(t *testing.T) {
			engine := newGenesisIdentityTestEngine(t, DevnetGenesisChainID())
			mp, err := NewMempool(engine.chainState, engine.blockStore, devnetGenesisChainID)
			require(t, err == nil, "NewMempool: %v", err)
			engine.SetMempool(mp)
			relay := engine.DARelayState()
			require(t, relay != nil, "engine has no bound DA relay")
			var attempts []string
			var stages []daTTLStage
			relay.ttlHook = func(at daTTLStage) { stages = append(stages, at) }
			defer func() { relay.ttlHook = nil }()
			if bound {
				engine.PublishDATTLBinding(&daTTLRecordingService{name: "S", attempts: &attempts})
			}
			before := daRelayStateSnapshot(relay)
			require(t, engine.BootstrapCanonicalGenesisIfEmpty() == nil && engine.chainState.view().tipHash == DevnetGenesisBlockHash(), "genesis bootstrap did not publish the devnet genesis")
			if bound {
				require(t, slices.Equal(attempts, []string{"S"}) && slices.Equal(stages, []daTTLStage{daTTLPlanned, daTTLApplied}), "bound genesis bootstrap attempts=%v body stages=%v, want one attempt and one body run", attempts, stages)
				return
			}
			require(t, engine.DATTLBindingService() == nil && len(stages) == 0, "absent binding: binding=%v body stages=%v, want no body run", engine.DATTLBindingService(), stages)
			after := daRelayStateSnapshot(relay)
			require(t, reflect.DeepEqual(after.sets, before.sets) && reflect.DeepEqual(after.locators, before.locators) && after.records == before.records, "absent-binding genesis bootstrap changed the DA records")
		})
	}
}

// daTTLHoldRecord is one signed DA transaction of a guard-hold shape, admitted as PEER, and its booked charge.
type daTTLHoldRecord struct {
	raw    []byte
	quota  string
	charge uint64
}

// daTTLHoldShape: records admitted in order, then next, which the default caps refuse with capErr (E has neither).
type daTTLHoldShape struct {
	name    string
	records []daTTLHoldRecord
	next    *daTTLHoldRecord
	capErr  error
	sets    int
	members int
	charged uint64
}

// daTTLHoldInputs are the signed transactions of the pre-states; fill stops before the next exceeds a mempool cap.
type daTTLHoldInputs struct {
	kp       *consensus.MLDSA87Keypair
	address  []byte
	utxos    map[consensus.Outpoint]consensus.UtxoEntry
	fill     [][]byte
	fillNext []byte
	shapes   []daTTLHoldShape
}

const (
	daTTLHoldMempoolMaxTxs   = 65_536
	daTTLHoldMempoolMaxBytes = 256 << 20
)

// sign gives tx one fresh funding input worth fee+1000 and a last P2PK output of 1000.
func (in *daTTLHoldInputs) sign(b testing.TB, tx *consensus.Tx, fee uint64) []byte {
	b.Helper()
	n := len(in.utxos)
	op := consensus.Outpoint{Txid: [32]byte{0xd8, byte(n >> 16), byte(n >> 8), byte(n)}}
	in.utxos[op] = consensus.UtxoEntry{Value: fee + 1000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: in.address, CreationHeight: 1}
	tx.Version, tx.TxNonce = 1, uint64(n)+1
	tx.Inputs = []consensus.TxInput{{PrevTxid: op.Txid, PrevVout: op.Vout}}
	tx.Outputs = append(tx.Outputs, consensus.TxOutput{Value: 1000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: in.address})
	if err := consensus.SignTransaction(tx, in.utxos, devnetGenesisChainID, in.kp); err != nil {
		b.Fatalf("SignTransaction: %v", err)
	}
	raw, err := consensus.MarshalTx(tx)
	if err != nil {
		b.Fatalf("MarshalTx: %v", err)
	}
	return raw
}

// buildFill signs one-input one-output transfers until the next would exceed a mempool cap.
func (in *daTTLHoldInputs) buildFill(b testing.TB) {
	used := 0
	for {
		raw := in.sign(b, &consensus.Tx{}, 200_000)
		if used+len(raw) > daTTLHoldMempoolMaxBytes || len(in.fill) == daTTLHoldMempoolMaxTxs {
			in.fillNext = raw
			return
		}
		used += len(raw)
		in.fill = append(in.fill, raw)
	}
}

// commit signs a State B commit-only record (one CORE_DA_COMMIT output, chunk_count 1) charging its tx bytes.
func (in *daTTLHoldInputs) commit(b testing.TB, daID [32]byte, manifest, batchSig int) daTTLHoldRecord {
	b.Helper()
	commitment := sha3.Sum256(daID[:])
	tx := &consensus.Tx{
		TxKind:       0x01,
		Outputs:      []consensus.TxOutput{{CovenantType: consensus.COV_TYPE_DA_COMMIT, CovenantData: commitment[:]}},
		DaPayload:    make([]byte, manifest),
		DaCommitCore: &consensus.DaCommitCore{DaID: daID, ChunkCount: 1, BatchSig: make([]byte, batchSig)},
	}
	raw := in.sign(b, tx, 5_000_000)
	return daTTLHoldRecord{raw: raw, quota: "ttl-hold-b", charge: uint64(len(raw))}
}

// stateBShape builds one quota identity's commits up to DA_ORPHAN_POOL_SIZE and DA_ORPHAN_COMMIT_OVERHEAD_MAX.
func (in *daTTLHoldInputs) stateBShape(b testing.TB, name string, tag byte, manifest, batchSig int) daTTLHoldShape {
	caps := defaultDARelayCaps()
	shape := daTTLHoldShape{name: name, capErr: errDARelayOrphanCommitCapExceeded}
	for i := 0; ; i++ {
		rec := in.commit(b, [32]byte{tag, byte(i >> 8), byte(i)}, manifest, batchSig)
		if total := shape.charged + rec.charge; total > caps.orphanPoolBytes || total > caps.orphanCommitOverheadBytes {
			shape.next = &rec
			return shape
		}
		shape.charged += rec.charge
		shape.members++
		shape.sets++
		shape.records = append(shape.records, rec)
	}
}

// chunk signs a State A chunk of daID at index carrying payloadLen zero bytes; its charge is tx bytes plus payload.
func (in *daTTLHoldInputs) chunk(b testing.TB, daID [32]byte, index uint16, payloadLen int) daTTLHoldRecord {
	payload := make([]byte, payloadLen)
	tx := &consensus.Tx{TxKind: 0x02, DaPayload: payload, DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: index, ChunkHash: sha3.Sum256(payload)}}
	raw := in.sign(b, tx, 100_000_000)
	return daTTLHoldRecord{raw: raw, charge: uint64(len(raw) + payloadLen)}
}

// fullRecordPayloads gives the fewest chunk payloads charging at most DA_ORPHAN_POOL_PER_DA_ID_MAX for one record.
func (in *daTTLHoldInputs) fullRecordPayloads(b testing.TB) []int {
	full := in.chunk(b, [32]byte{0xaf}, 0, consensus.CHUNK_BYTES).charge
	n := daOrphanPoolPerDAIDMaxBytes / full
	rem := daOrphanPoolPerDAIDMaxBytes - n*full
	last := int((rem - (full - 2*consensus.CHUNK_BYTES)) / 2)
	if charge := in.chunk(b, [32]byte{0xaf}, 1, last).charge; last <= 0xffff || charge > rem || charge+2 <= rem {
		b.Fatalf("last payload %d charges %d, want the largest within %d", last, charge, rem)
	}
	return append(slices.Repeat([]int{consensus.CHUNK_BYTES}, int(n)), last)
}

// stateAShape builds records with the given chunk payloads up to DA_ORPHAN_POOL_SIZE under the per-peer cap.
func (in *daTTLHoldInputs) stateAShape(b testing.TB, name string, tag byte, payloads []int) daTTLHoldShape {
	shape := daTTLHoldShape{name: name, capErr: errDARelayOrphanPoolCapExceeded}
	identity, used := 0, uint64(0)
	assign := func(rec *daTTLHoldRecord) {
		if used+rec.charge > daOrphanPoolPerPeerMaxBytes {
			identity, used = identity+1, 0
		}
		used += rec.charge
		rec.quota = fmt.Sprintf("ttl-hold-%s-%d", name, identity)
	}
	for i := 0; ; i++ {
		var record []daTTLHoldRecord
		var charge uint64
		for index, payload := range payloads {
			rec := in.chunk(b, [32]byte{tag, byte(i >> 8), byte(i)}, uint16(index), payload)
			record, charge = append(record, rec), charge+rec.charge
		}
		if shape.charged+charge > daOrphanPoolSizeBytes {
			assign(&record[0])
			shape.next = &record[0]
			return shape
		}
		for j := range record {
			assign(&record[j])
		}
		shape.records = append(shape.records, record...)
		shape.charged += charge
		shape.members += len(record)
		shape.sets++
	}
}

func newDATTLHoldInputs(b testing.TB) *daTTLHoldInputs {
	b.Helper()
	kp, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		b.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	b.Cleanup(kp.Close)
	in := &daTTLHoldInputs{kp: kp, address: consensus.P2PKCovenantDataForPubkey(kp.PubkeyBytes()), utxos: map[consensus.Outpoint]consensus.UtxoEntry{}}
	in.shapes = []daTTLHoldShape{
		{name: "E"},
		in.stateAShape(b, "M-A", 0xa1, []int{1}),
		in.stateAShape(b, "F-A", 0xa2, in.fullRecordPayloads(b)),
		in.stateBShape(b, "M-B", 0xb1, 0, 0),
		in.stateBShape(b, "F-B", 0xb2, consensus.MAX_DA_MANIFEST_BYTES_PER_TX, consensus.MAX_DA_MANIFEST_BYTES_PER_TX),
	}
	in.buildFill(b)
	return in
}

// preState copies the template, funds inputs, sets the TTL, admits the shape, checks the cap refusal, then the fill.
func (in *daTTLHoldInputs) preState(b testing.TB, shape daTTLHoldShape, ttl uint64) *pendingOutpointSyncFixture {
	b.Helper()
	cfg := DefaultMempoolConfig()
	cfg.MaxTransactions, cfg.MaxBytes = daTTLHoldMempoolMaxTxs, daTTLHoldMempoolMaxBytes
	f := newPendingOutpointSyncFixtureWithMempool(b, cfg)
	maps.Copy(f.engine.chainState.Utxos, in.utxos)
	relay := f.engine.DARelayState()
	relay.caps.orphanTTLBlocks = ttl
	admit := func(rec daTTLHoldRecord) error {
		provenance, err := NewPeerDAProvenance(rec.quota, rec.quota)
		if err != nil {
			b.Fatalf("NewPeerDAProvenance: %v", err)
		}
		_, err = relay.AdmitDA(rec.raw, provenance)
		return err
	}
	for i, rec := range shape.records {
		if err := admit(rec); err != nil {
			b.Fatalf("%s record %d: AdmitDA: %v", shape.name, i, err)
		}
	}
	if shape.next != nil {
		if err := admit(*shape.next); !errors.Is(err, shape.capErr) {
			b.Fatalf("%s next record: AdmitDA=%v, want %v", shape.name, err, shape.capErr)
		}
	}
	view := daRelayStateSnapshot(relay)
	if len(view.sets) != shape.sets || view.commitBytes+view.orphanBytes != shape.charged {
		b.Fatalf("%s: retained %d records charging %d, want %d charging %d", shape.name, len(view.sets), view.commitBytes+view.orphanBytes, shape.sets, shape.charged)
	}
	for i, raw := range in.fill {
		if err := f.mempool.AddTx(raw); err != nil {
			b.Fatalf("fill %d: AddTx: %v", i, err)
		}
	}
	stats := f.mempool.Stats()
	if stats.TxCount != len(in.fill) || (stats.BytesUsed+len(in.fillNext) <= daTTLHoldMempoolMaxBytes && stats.TxCount < daTTLHoldMempoolMaxTxs) {
		b.Fatalf("mempool count=%d bytes=%d next=%d, want %d entries with the next over a cap", stats.TxCount, stats.BytesUsed, len(in.fillNext), len(in.fill))
	}
	return f
}

// requireDATTLHoldEffect: with the binding each record decreases once (removed at TTL 1), without it none changes.
func requireDATTLHoldEffect(b testing.TB, before, after daRelayStateView, ttl uint64, bound bool) {
	b.Helper()
	switch {
	case !bound:
		if !reflect.DeepEqual(before.sets, after.sets) {
			b.Fatal("the unbound apply changed a DA record")
		}
	case ttl == 1:
		if len(after.sets) != 0 {
			b.Fatalf("%d records left after the TTL 1 decrease, want 0", len(after.sets))
		}
	default:
		if len(after.sets) != len(before.sets) {
			b.Fatalf("%d records after the decrease, want %d", len(after.sets), len(before.sets))
		}
		for daID, record := range after.sets {
			if record.ttlBlocksRemaining != ttl-1 {
				b.Fatalf("record %x ttl=%d, want %d", daID[:3], record.ttlBlocksRemaining, ttl-1)
			}
		}
	}
}

func benchDATTLGuardHold(b *testing.B, in *daTTLHoldInputs, shape daTTLHoldShape, ttl uint64, bound bool) {
	b.StopTimer()
	b.ReportAllocs()
	quotas := map[string]struct{}{}
	for _, rec := range shape.records {
		quotas[rec.quota] = struct{}{}
	}
	b.ResetTimer()
	for range b.N {
		f := in.preState(b, shape, ttl)
		if bound {
			f.engine.PublishDATTLBinding(&daTTLFuncService{enter: func(decrease func() error) error { return decrease() }})
		}
		height := f.tipHeight + 1
		coinbase := reorgTestCoinbaseForAddress(b, height, consensus.BlockSubsidy(height, f.alreadyGenerated), f.sourceAddress)
		block := benchmarkBuildSingleTxBlock(b, f.tipHash, f.target, 500, coinbase)
		before := daRelayStateSnapshot(f.engine.DARelayState())
		b.StartTimer()
		summary, err := f.engine.ApplyBlock(block, nil)
		b.StopTimer()
		if err != nil || summary == nil || summary.BlockHeight != height {
			b.Fatalf("ApplyBlock=(%+v,%v), want ACCEPTED/NEW at %d", summary, err, height)
		}
		requireDATTLHoldEffect(b, before, daRelayStateSnapshot(f.engine.DARelayState()), ttl, bound)
	}
	b.ReportMetric(float64(shape.sets), "records")
	b.ReportMetric(float64(shape.members), "members")
	b.ReportMetric(float64(len(quotas)), "quotas")
	b.ReportMetric(float64(shape.charged), "charged-bytes")
	b.ReportMetric(float64(len(in.fill)), "fill-txs")
}

// BenchmarkDATTLCallbackGuardHold times one ACCEPTED/NEW ApplyBlock per shape with and without a decreasing binding.
func BenchmarkDATTLCallbackGuardHold(b *testing.B) {
	in := newDATTLHoldInputs(b)
	for _, shape := range in.shapes {
		for _, ttl := range []uint64{3, 1} {
			for _, bound := range []bool{true, false} {
				b.Run(fmt.Sprintf("%s/ttl=%d/bound=%v", shape.name, ttl, bound), func(b *testing.B) {
					benchDATTLGuardHold(b, in, shape, ttl, bound)
				})
			}
		}
	}
}
