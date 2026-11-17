package node

import (
	"crypto/sha3"
	"errors"
	"math"
	"reflect"
	"slices"
	"strings"
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

// TestDATTLCallbackBodySurvivorRevisions is the body-level C10 revision row: each body call
// gives every surviving record its own fresh revision, minted one by one above the stored
// high-water in ascending da_id order. The third record is admitted last with the smallest
// da_id, so admission order is not da_id order whichever end the State A/B bucket links at.
func TestDATTLCallbackBodySurvivorRevisions(t *testing.T) {
	f, r := newDATTLCallbackRecords(t)
	late := [32]byte{0x17}
	f.ownerReadyChunk(late, 0, "ttl-late", daNonReplayPeer("ttl-peer"))
	f.setOwnerReadyTTL(late, 3)
	ascending := [][32]byte{late, r.stateAID, r.stateBID}
	for call := range 2 {
		high := daRelayStateSnapshot(f.relay).records
		if err := runDATTLBodyInGuard(t, f); err != nil {
			t.Fatalf("body call %d: %v", call+1, err)
		}
		view := daRelayStateSnapshot(f.relay)
		for rank, daID := range ascending {
			if got, want := view.sets[daID].revision, high+uint64(rank)+1; got != want {
				t.Fatalf("body call %d: record %x revision=%d, want %d", call+1, daID[:1], got, want)
			}
		}
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

// requireDATTLIndexExact pins the relations' State A/B bucket to exactly the present records
// that are not State C, so the bounded walk can miss no State A or B record.
func requireDATTLIndexExact(t *testing.T, relay *DARelayState) {
	t.Helper()
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
			t.Fatalf("State A/B index lists %x twice", daID[:1])
		}
		got[daID] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("State A/B index=%v, want %v", got, want)
	}
}

// TestDATTLCallbackBodyRefusalArms is the body-level C11 row per refusal arm: each arm returns
// its own error and leaves the DA image and the owner unchanged; removing the arm lets the body
// apply and fails the row at its error assertion.
func TestDATTLCallbackBodyRefusalArms(t *testing.T) {
	for _, row := range []struct {
		name    string
		corrupt func(*daNonReplayFixture, daTTLCallbackRecords)
		want    func(error) bool
	}{
		{"locator row moved", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) {
				s.relations.putLocator(r.stateA.txid, daRelayLocator{daID: r.stateAID, kind: daRelayLocatorChunk, chunkIndex: 1})
			})
		}, func(err error) bool { return errors.Is(err, errDARelayLocatorMismatch) }},
		{"survivor per-da_id entry differs", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.orphanBytesByDAID[r.stateAID]++ })
		}, func(err error) bool { return errors.Is(err, errDARelayImageIncompatible) }},
		{"expiring per-da_id entry larger", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.setOwnerReadyTTL(r.stateAID, 1)
			f.mutateRelay(func(s *DARelayState) { s.orphanBytesByDAID[r.stateAID]++ })
		}, func(err error) bool { return errors.Is(err, errDARelayImageIncompatible) }},
		{"State B carries a per-da_id entry", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.orphanBytesByDAID[r.stateBID] = 5 })
		}, func(err error) bool { return errors.Is(err, errDARelayImageIncompatible) }},
		{"record stored under another da_id", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) {
				record := s.relations.recordValue(r.stateAID)
				record.daID = [32]byte{0xa8}
				s.relations.scalarRecord(r.stateAID, record)
			})
		}, func(err error) bool { return errors.Is(err, errDARelayTTLRecordKeyMismatch) }},
		{"victim claim not finalized", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.setOwnerReadyTTL(r.stateAID, 1)
			token := r.setup.sets[r.stateAID].chunks[0].member.token
			ownerReadyEditOwner(f, func(o *PendingOutpointOwner) { o.byToken[token].finalized = false })
		}, func(err error) bool { return err != nil && strings.Contains(err.Error(), "DA victim claim mismatch") }},
		// The same claim on a survivor is no victim, so the member proof is what refuses it; it
		// is also the check that refuses the row above once the victim preflight is removed.
		{"survivor claim not finalized", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			token := r.setup.sets[r.stateAID].chunks[0].member.token
			ownerReadyEditOwner(f, func(o *PendingOutpointOwner) { o.byToken[token].finalized = false })
		}, func(err error) bool { return errors.Is(err, errDARelayImageIncompatible) }},
		// A survivor is no victim, so only the member proof's outpoint-row comparison sees a
		// missing or different row for its input.
		{"survivor outpoint row missing", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			ownerReadyEditOwner(f, func(o *PendingOutpointOwner) { delete(o.byOutpoint, r.stateA.inputs[0]) })
		}, func(err error) bool { return errors.Is(err, errDARelayImageIncompatible) }},
		{"survivor outpoint row different", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			ownerReadyEditOwner(f, func(o *PendingOutpointOwner) {
				row := o.byOutpoint[r.stateA.inputs[0]]
				row.txid[0] ^= 0xff
				o.byOutpoint[r.stateA.inputs[0]] = row
			})
		}, func(err error) bool { return errors.Is(err, errDARelayImageIncompatible) }},
		// An expiring member is a victim, so the victim preflight's input match refuses the same
		// edit first.
		{"expiring outpoint row different", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.setOwnerReadyTTL(r.stateAID, 1)
			ownerReadyEditOwner(f, func(o *PendingOutpointOwner) {
				row := o.byOutpoint[r.stateA.inputs[0]]
				row.txid[0] ^= 0xff
				o.byOutpoint[r.stateA.inputs[0]] = row
			})
		}, func(err error) bool { return err != nil && strings.Contains(err.Error(), "DA victim input mismatch") }},
		{"revision above the high-water", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.records = s.relations.recordValue(r.stateAID).revision - 1 })
		}, daTTLWrapped(errDARelayImageIncompatible, "revision")},
		{"received time above the high-water", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.nextReceivedTime = s.relations.recordValue(r.stateAID).receivedTime - 1 })
		}, daTTLWrapped(errDARelayImageIncompatible, "received time")},
		{"survivor revision overflows", func(f *daNonReplayFixture, _ daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.records = math.MaxUint64 })
		}, func(err error) bool { return errors.Is(err, errDARelayArithmeticOverflow) }},
		{"stored staged total differs", func(f *daNonReplayFixture, _ daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.stagedBytes++ })
		}, daTTLWrapped(errDARelayImageIncompatible, "staged retained bytes")},
		{"stored orphan total differs", func(f *daNonReplayFixture, _ daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.orphanBytes-- })
		}, daTTLWrapped(errDARelayImageIncompatible, "orphan pool bytes")},
		{"stored commit overhead total differs", func(f *daNonReplayFixture, _ daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.orphanCommitOverheadBytes-- })
		}, daTTLWrapped(errDARelayImageIncompatible, "orphan commit overhead bytes")},
		{"stored per-peer entry differs", func(f *daNonReplayFixture, _ daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.orphanBytesByPeerQuotaKey["ttl-peer"]++ })
		}, daTTLWrapped(errDARelayImageIncompatible, `per-peer orphan bytes for "ttl-peer"`)},
		{"selected peer key absent from the stored map", func(f *daNonReplayFixture, _ daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { delete(s.orphanBytesByPeerQuotaKey, "ttl-peer") })
		}, daTTLWrapped(errDARelayImageIncompatible, `per-peer orphan bytes for "ttl-peer"`)},
		{"extra stored per-peer entry", func(f *daNonReplayFixture, _ daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.orphanBytesByPeerQuotaKey["ghost"] = 1 })
		}, daTTLWrapped(errDARelayImageIncompatible, "per-peer orphan bytes: records imply")},
		{"extra stored per-da_id entry", func(f *daNonReplayFixture, _ daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.orphanBytesByDAID[[32]byte{0xee}] = 1 })
		}, daTTLWrapped(errDARelayImageIncompatible, "per-da_id orphan bytes: records imply")},
		{"index entry absent", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.relations.sets[r.stateAID].present = false })
		}, func(err error) bool { return errors.Is(err, errDARelayTTLRecordKeyMismatch) }},
		{"index entry State C", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) {
				record := s.relations.recordValue(r.stateAID)
				record.state = daRelayStateCompleteSet
				s.relations.scalarRecord(r.stateAID, record)
			})
		}, func(err error) bool { return errors.Is(err, errDARelayTTLRecordKeyMismatch) }},
		{"zero member token", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			editDATTLChunkMember(f, r.stateAID, func(m *daRelayMemberIdentity) { m.token = PendingOutpointToken{} })
		}, func(err error) bool { return errors.Is(err, errDARelayImageIncompatible) }},
		{"foreign member token", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			editDATTLChunkMember(f, r.stateAID, func(m *daRelayMemberIdentity) { m.token.owner = &PendingOutpointOwner{} })
		}, func(err error) bool { return errors.Is(err, errDARelayImageIncompatible) }},
		{"member token held twice", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			token := r.setup.sets[r.stateBID].commit.member.token
			editDATTLChunkMember(f, r.stateAID, func(m *daRelayMemberIdentity) { m.token = token })
		}, func(err error) bool { return errors.Is(err, errDARelayImageIncompatible) }},
		{"input claimed by two members", reuseDATTLInputInStateB, func(err error) bool { return errors.Is(err, errDARelayImageIncompatible) }},
		// The State B commit member stores State A's txid, which its own parsed bytes contradict:
		// bindRetainedRecord's canonicalDARetainedBinding refuses it, reached from
		// checkOwnerReadyRetainedRecordLocked while the plan is built.
		{"commit member txid contradicts its parsed identity", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) {
				record := s.relations.recordValue(r.stateBID)
				member := *record.commit.member
				member.txid = r.stateA.txid
				record.commit.member = &member
				s.relations.putRecord(r.stateBID, record)
			})
		}, func(err error) bool {
			var terminal *canonicalDATerminalError
			return errors.As(err, &terminal) && strings.Contains(err.Error(), "contradicts its parsed identity")
		}},
		// A count of zero is an inconsistent stored value (ATOM: underflow invalidates the plan
		// before mutation). ownerReadyRemovalGateFails refuses it first; the survivor bound in
		// checkOwnerReadyRemovalSurvivor refuses the underflowed count when that clause is gone.
		{"State A count zero", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.setOwnerReadyTTL(r.stateAID, 0)
		}, daTTLBareIncompatible},
		{"State B count zero", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			f.setOwnerReadyTTL(r.stateBID, 0)
		}, daTTLBareIncompatible},
		{"nil chainstate", func(f *daNonReplayFixture, _ daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.mempool.chainState = nil })
		}, func(err error) bool { return err != nil && strings.Contains(err.Error(), "nil chainstate") }},
		{"nil pending-outpoint owner", func(f *daNonReplayFixture, _ daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.mempool.pendingOutpoints = nil })
		}, func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "nil pending-outpoint owner")
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			f, r := newDATTLCallbackRecords(t)
			owner := f.mp.pendingOutpoints
			row.corrupt(f, r)
			before, ownerBefore := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(owner)
			err := runDATTLBodyInGuard(t, f)
			t.Logf("refusal: %v", err)
			if !row.want(err) {
				t.Fatalf("body: err=%v, want this arm's refusal", err)
			}
			requireDANonReplayUnchanged(t, f.relay, owner, before, ownerBefore)
		})
	}
}

// TestDATTLCallbackBodyUnboundRelay is the unbound arm: a relay with no mempool reaches no claim
// domain, so the DA image is the whole change and a live owner it cannot see stays untouched.
func TestDATTLCallbackBodyUnboundRelay(t *testing.T) {
	f, r := newDATTLCallbackRecords(t)
	owner := f.mp.pendingOutpoints
	ownerBefore := cloneDAAdmissionOwner(owner)
	f.mutateRelay(func(s *DARelayState) { s.mempool = nil })
	if err := runDATTLBodyInGuard(t, f); err != nil {
		t.Fatalf("unbound body: %v", err)
	}
	view := daRelayStateSnapshot(f.relay)
	requireDATTLCount(t, view, r.stateAID, 2)
	requireDATTLCount(t, view, r.stateBID, 2)
	if !reflect.DeepEqual(cloneDAAdmissionOwner(owner), ownerBefore) {
		t.Fatal("unbound body changed an owner it cannot reach")
	}
}

// TestDATTLCallbackBodyWalksOnlyStateAB is the F2 row: a State C record that would fail every
// owner-ready check is never visited, and the State A/B index stays exact across admission,
// decrease, expiry and the whole-clone ReleasePeerQuotaKey swap.
func TestDATTLCallbackBodyWalksOnlyStateAB(t *testing.T) {
	f, r := newDATTLCallbackRecords(t)
	requireDATTLIndexExact(t, f.relay)
	if err := f.relay.ReleasePeerQuotaKey("unrelated-peer"); err != nil {
		t.Fatalf("ReleasePeerQuotaKey: %v", err)
	}
	requireDATTLIndexExact(t, f.relay)
	f.mutateRelay(func(s *DARelayState) {
		mutateOwnerReadyRecord(s, r.stateCID, func(record *daRelaySetRecord) { record.wireBytes = 1 })
	})
	requireDATTLIndexExact(t, f.relay)
	if err := runDATTLBodyInGuard(t, f); err != nil {
		t.Fatalf("body visited State C: %v", err)
	}
	requireDATTLCount(t, daRelayStateSnapshot(f.relay), r.stateAID, 2)
	requireDATTLIndexExact(t, f.relay)
	for _, want := range []uint64{1, 0} {
		if err := runDATTLBodyInGuard(t, f); err != nil {
			t.Fatalf("body with a corrupt State C record: %v", err)
		}
		view := daRelayStateSnapshot(f.relay)
		if want != 0 {
			requireDATTLCount(t, view, r.stateAID, want)
		} else if _, present := view.sets[r.stateAID]; present {
			t.Fatal("State A survived its expiry after the clone swap")
		}
		requireDATTLIndexExact(t, f.relay)
	}
}

// daTTLBareIncompatible accepts only the unwrapped errDARelayImageIncompatible, which both
// zero-count arms return; a refusal wrapped with a detail suffix fails it.
func daTTLBareIncompatible(err error) bool {
	return errors.Is(err, errDARelayImageIncompatible) && err.Error() == errDARelayImageIncompatible.Error()
}

func daTTLWrapped(want error, detail string) func(error) bool {
	return func(err error) bool { return errors.Is(err, want) && strings.Contains(err.Error(), detail) }
}

// editDATTLChunkMember replaces chunk 0's member of one record with an edited copy, so the
// owner and every other record keep their own identities.
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

// reuseDATTLInputInStateB re-signs State B's commit over State A's input, same length, so the
// retained bytes, locators and accounting stay consistent and only the input set repeats.
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

// requireDATTLIndexStep pins the State A/B index after one production publication and runs one
// body call that must succeed over it.
func requireDATTLIndexStep(t *testing.T, f *daNonReplayFixture, step string) {
	t.Helper()
	requireDATTLIndexExact(t, f.relay)
	if err := runDATTLBodyInGuard(t, f); err != nil {
		t.Fatalf("%s: body after the publication: %v", step, err)
	}
	requireDATTLIndexExact(t, f.relay)
}

// TestDATTLCallbackIndexProductionPaths is the F2 index row on these production paths that
// publish a record row: orphan-chunk staging (State A created and grown), commit staging
// (State A to State B), DA completion (State B to State C) and the PEER quota cleanup removal.
// It does not run the D1 projection's putRecord and removeRecord on its clone (sync_da_relay.go)
// or the capacity-victim removal of a DA complete commit (da_complete_commit.go).
func TestDATTLCallbackIndexProductionPaths(t *testing.T) {
	f := newDANonReplayFixture(t, 8)
	grown, staged, completed, released := [32]byte{0xd1}, [32]byte{0xd2}, [32]byte{0xd3}, [32]byte{0xd4}
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
	requireDATTLIndexStep(t, f, "State B to State C")
	f.ownerReadyChunk(released, 0, "released", daNonReplayPeer("drop"))
	requireDATTLIndexExact(t, f.relay)
	if err := f.relay.ReleasePeerQuotaKey("drop"); err != nil {
		t.Fatalf("ReleasePeerQuotaKey: %v", err)
	}
	if _, present := daRelayStateSnapshot(f.relay).sets[released]; present {
		t.Fatal("PEER cleanup kept the released record")
	}
	requireDATTLIndexStep(t, f, "PEER cleanup removal")
}

func requireDATTLState(t *testing.T, f *daNonReplayFixture, daID [32]byte, want daRelaySetState) {
	t.Helper()
	if record, present := daRelayStateSnapshot(f.relay).sets[daID]; !present || record.state != want {
		t.Fatalf("record %x: present=%v state=%v, want %v", daID[:1], present, record.state, want)
	}
}

// TestDATTLCallbackEmptiedBucketDropped is the P3 row: removing the last State A/B record leaves
// no empty State A/B bucket behind, like every member bucket.
func TestDATTLCallbackEmptiedBucketDropped(t *testing.T) {
	f, r := newDATTLCallbackRecords(t)
	f.setOwnerReadyTTL(r.stateAID, 1)
	f.setOwnerReadyTTL(r.stateBID, 1)
	if err := runDATTLBodyInGuard(t, f); err != nil {
		t.Fatalf("expiry: %v", err)
	}
	f.relay.mu.Lock()
	defer f.relay.mu.Unlock()
	if bucket, present := f.relay.relations.buckets[daRelayIncompleteKey]; present {
		t.Fatalf("emptied State A/B bucket retained: %+v", bucket)
	}
}
