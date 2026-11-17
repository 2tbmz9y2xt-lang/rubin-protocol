package node

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

// runDATTLBodyInGuard runs the in-guard TTL body while the test holds the ChainState admission
// guard EXCLUSIVELY, as the canonical transition does. A body that reacquired the guard would
// block on its own caller, so completion within the timeout is the H4 observation.
func runDATTLBodyInGuard(t *testing.T, f *daNonReplayFixture) error {
	t.Helper()
	f.state.admissionMu.Lock()
	defer f.state.admissionMu.Unlock()
	done := make(chan error, 1)
	go func() { done <- f.relay.advanceOwnerReadyTTLInGuard() }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("TTL body blocked under the held exclusive admission guard")
	}
	return nil
}

type daTTLCallbackRecords struct {
	stateAID, stateBID, stateCID [32]byte
	stateA, stateB               daNonReplayTx
	base, setup                  daRelayStateView
}

// newDATTLCallbackRecords admits State C first (the base image), then State A (PEER chunk with a
// prefetch reservation) and State B (LOCAL staged commit), both at count 3.
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

func requireDATTLCount(t *testing.T, view daRelayStateView, daID [32]byte, want uint64) {
	t.Helper()
	record, present := view.sets[daID]
	if !present || record.ttlBlocksRemaining != want {
		t.Fatalf("record %x: present=%v ttl=%d, want ttl %d", daID[:1], present, record.ttlBlocksRemaining, want)
	}
}

// TestDATTLCallbackBodyThreeCountedPublications is the body-level C10 row: one State A and one
// State B record created at 3 decrease to 2, then 1, and are removed with the owner-ready expiry
// effect at the third body call; State C is untouched; every counter returns to the base image.
func TestDATTLCallbackBodyThreeCountedPublications(t *testing.T) {
	f, r := newDATTLCallbackRecords(t)
	tokenA, tokenB := r.setup.sets[r.stateAID].chunks[0].member.token, r.setup.sets[r.stateBID].commit.member.token
	for call, want := range []uint64{2, 1} {
		if err := runDATTLBodyInGuard(t, f); err != nil {
			t.Fatalf("body call %d: %v", call+1, err)
		}
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
	if err := runDATTLBodyInGuard(t, f); err != nil {
		t.Fatalf("body call 3: %v", err)
	}
	after := daRelayStateSnapshot(f.relay)
	ownerReadyRecordAbsent(t, after, r.stateAID, r.stateA.txid)
	ownerReadyRecordAbsent(t, after, r.stateBID, r.stateB.txid)
	ownerReadyClaimGone(t, cloneDAAdmissionOwner(f.mp.pendingOutpoints), tokenA, r.stateA.inputs)
	ownerReadyClaimGone(t, cloneDAAdmissionOwner(f.mp.pendingOutpoints), tokenB, r.stateB.inputs)
	if after.records != r.setup.records+4 {
		t.Fatalf("expiry minted a revision: records=%d, want %d", after.records, r.setup.records+4)
	}
	if !reflect.DeepEqual(after.sets[r.stateCID], r.base.sets[r.stateCID]) || !reflect.DeepEqual(after.locators, r.base.locators) {
		t.Fatal("State C record or the locator image changed")
	}
	type counters struct{ staged, orphan, commit, complete, pinned uint64 }
	got := counters{after.stagedBytes, after.orphanBytes, after.commitBytes, after.completeBytes, after.pinnedPayloadBytes}
	want := counters{r.base.stagedBytes, r.base.orphanBytes, r.base.commitBytes, r.base.completeBytes, r.base.pinnedPayloadBytes}
	if got != want || !reflect.DeepEqual(after.peerBytes, r.base.peerBytes) || !reflect.DeepEqual(after.daIDBytes, r.base.daIDBytes) {
		t.Fatalf("accounting after expiry: got=%+v peer=%v da=%v, want=%+v peer=%v da=%v", got, after.peerBytes, after.daIDBytes, want, r.base.peerBytes, r.base.daIDBytes)
	}
}

// TestDATTLCallbackBodyRefusalChangesNothing is the body-level C11 row: a refused check on one
// selected record, or a selected member whose exact owner token is not bound, returns the
// body's own error and leaves the whole DA image and owner unchanged.
func TestDATTLCallbackBodyRefusalChangesNothing(t *testing.T) {
	for _, row := range []struct {
		name    string
		corrupt func(*daNonReplayFixture, daTTLCallbackRecords)
	}{
		{"inconsistent stored value", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) {
				mutateOwnerReadyRecord(s, r.stateBID, func(record *daRelaySetRecord) { record.wireBytes = 1 })
			})
		}},
		{"unbound owner token", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			token := r.setup.sets[r.stateAID].chunks[0].member.token
			ownerReadyEditOwner(f, func(o *PendingOutpointOwner) { o.byToken[token].txid[0] ^= 0xff })
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			f, r := newDATTLCallbackRecords(t)
			f.setOwnerReadyTTL(r.stateBID, 1) // one would-be expiry and one would-be decrease
			row.corrupt(f, r)
			before, ownerBefore := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
			if err := runDATTLBodyInGuard(t, f); !errors.Is(err, errDARelayImageIncompatible) {
				t.Fatalf("body: err=%v, want %v", err, errDARelayImageIncompatible)
			}
			requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, ownerBefore)
		})
	}
}
