package node

import (
	"crypto/sha3"
	"errors"
	"fmt"
	"go/ast"
	"maps"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// runDATTLBodyInGuard runs the in-guard TTL body while the test holds the ChainState admission guard EXCLUSIVELY, as
// the canonical transition does. A body that reacquired the guard would block on its own caller, so completion within
// the timeout shows the body never reacquires it.
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

// requireDATTLOK fails the test unless err is nil.
func requireDATTLOK(t *testing.T, err error, format string, args ...any) {
	t.Helper()
	if err != nil {
		t.Fatalf(format+": %v", append(args, err)...)
	}
}

// advanceDATTLInGuard runs the in-guard TTL body as the canonical transition does: with the bound ChainState admission
// guard held exclusively, or bare on an unbound relay, which has no guard.
func advanceDATTLInGuard(s *DARelayState) error {
	if s.mempool != nil && s.mempool.chainState != nil {
		s.mempool.chainState.admissionMu.Lock()
		defer s.mempool.chainState.admissionMu.Unlock()
	}
	return s.advanceOwnerReadyTTLInGuard()
}

// ownerReadyTTLSelector names the in-guard TTL body's arm in the shared owner-ready selector tables; rows whose premise
// is the clone path's whole-image check branch on it.
const ownerReadyTTLSelector = "ttl tick"

// requireDATTLSkipsStateC pins the State A and B walk on a State-C-only image: the in-guard TTL body walks only State A
// and State B, so a State C defect it never visits is neither refused nor changed.
func requireDATTLSkipsStateC(t *testing.T, f *daNonReplayFixture, run func(*DARelayState) error, label string) {
	t.Helper()
	before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	require(t, run(f.relay) == nil, "%s: the in-guard TTL body refused a State C defect it must not visit", label)
	requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
}

// productionDeclarations lists every non-test Go file under clients/go that declares or names name as an identifier, so
// a deleted function stays absent from production, method values included.
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

// newDATTLCallbackRecords admits State C first (the base image), then State A (PEER chunk with a prefetch reservation)
// and State B (LOCAL staged commit), both at count 3.
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

// requireDATTLOutsideSelectedUnchanged checks, outside the selected records: every other record, every locator of
// another record, and every owner claim and outpoint row whose token no selected member holds are unchanged.
func requireDATTLOutsideSelectedUnchanged(t *testing.T, before, after daRelayStateView, ownerBefore, ownerAfter *PendingOutpointOwner, selected ...[32]byte) {
	t.Helper()
	isSelected := map[[32]byte]bool{}
	tokens := map[PendingOutpointToken]bool{}
	for _, daID := range selected {
		isSelected[daID] = true
		record := before.sets[daID]
		if record.commit.member != nil {
			tokens[record.commit.member.token] = true
		}
		for _, chunk := range record.chunks {
			if chunk.member != nil {
				tokens[chunk.member.token] = true
			}
		}
	}
	for daID := range mergedKeys(before.sets, after.sets) {
		require(t, isSelected[daID] || reflect.DeepEqual(before.sets[daID], after.sets[daID]), "record %x outside the selected set changed", daID[:1])
	}
	for txid := range mergedKeys(before.locators, after.locators) {
		was, is := before.locators[txid], after.locators[txid]
		require(t, isSelected[was.daID] || was == is, "locator %x outside the selected set changed: %+v -> %+v", txid[:1], was, is)
	}
	for token := range mergedKeys(ownerBefore.byToken, ownerAfter.byToken) {
		require(t, tokens[token] || reflect.DeepEqual(ownerBefore.byToken[token], ownerAfter.byToken[token]), "owner claim %+v outside the selected set changed", token)
	}
	for op := range mergedKeys(ownerBefore.byOutpoint, ownerAfter.byOutpoint) {
		was, is := ownerBefore.byOutpoint[op], ownerAfter.byOutpoint[op]
		require(t, tokens[was.token] || was == is, "owner row %+v outside the selected set changed: %+v -> %+v", op, was, is)
	}
}

func mergedKeys[K comparable, V any](a, b map[K]V) map[K]struct{} {
	keys := make(map[K]struct{}, len(a)+len(b))
	for k := range a {
		keys[k] = struct{}{}
	}
	for k := range b {
		keys[k] = struct{}{}
	}
	return keys
}

func requireDATTLCount(t *testing.T, view daRelayStateView, daID [32]byte, want uint64) {
	t.Helper()
	record, present := view.sets[daID]
	require(t, present && record.ttlBlocksRemaining == want, "record %x: present=%v ttl=%d, want ttl %d", daID[:1], present, record.ttlBlocksRemaining, want)
}

// TestDATTLCallbackBodyThreeCountedPublications decreases over repeated body calls: one State A and one State B record
// created at 3 decrease to 2, then 1, and are removed with the owner-ready expiry effect at the third body call; State
// C is untouched; every counter returns to the base image.
func TestDATTLCallbackBodyThreeCountedPublications(t *testing.T) {
	f, r := newDATTLCallbackRecords(t)
	tokenA, tokenB := r.setup.sets[r.stateAID].chunks[0].member.token, r.setup.sets[r.stateBID].commit.member.token
	for call, want := range []uint64{2, 1} {
		before, ownerBefore := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
		requireDATTLOK(t, runDATTLBodyInGuard(t, f), "body call %d", call+1)
		view := daRelayStateSnapshot(f.relay)
		requireDATTLOutsideSelectedUnchanged(t, before, view, ownerBefore, cloneDAAdmissionOwner(f.mp.pendingOutpoints), r.stateAID, r.stateBID)
		requireDATTLCount(t, view, r.stateAID, want)
		requireDATTLCount(t, view, r.stateBID, want)
		if wantRecords := r.setup.records + 2*uint64(call+1); view.records != wantRecords {
			t.Fatalf("body call %d: records=%d, want %d (one revision per decreased record)", call+1, view.records, wantRecords)
		}
		if _, held := view.prefetchIndexes[r.stateAID]; !held {
			t.Fatalf("body call %d released the prefetch reservation of a surviving record", call+1)
		}
	}
	before, ownerBefore := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	requireDATTLOK(t, runDATTLBodyInGuard(t, f), "body call 3")
	after := daRelayStateSnapshot(f.relay)
	requireDATTLOutsideSelectedUnchanged(t, before, after, ownerBefore, cloneDAAdmissionOwner(f.mp.pendingOutpoints), r.stateAID, r.stateBID)
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

// TestDATTLCallbackBodySurvivorRevisions pins revisions over repeated body calls: each body call gives every surviving
// record its own fresh revision, minted one by one above the stored high-water in ascending da_id order. The third
// record is admitted last with the smallest da_id, so admission order is not da_id order whichever end the State A/B
// bucket links at.
func TestDATTLCallbackBodySurvivorRevisions(t *testing.T) {
	f, r := newDATTLCallbackRecords(t)
	late := [32]byte{0x17}
	f.ownerReadyChunk(late, 0, "ttl-late", daNonReplayPeer("ttl-peer"))
	f.setOwnerReadyTTL(late, 3)
	ascending := [][32]byte{late, r.stateAID, r.stateBID}
	for call := range 2 {
		high := daRelayStateSnapshot(f.relay).records
		requireDATTLOK(t, runDATTLBodyInGuard(t, f), "body call %d", call+1)
		view := daRelayStateSnapshot(f.relay)
		for rank, daID := range ascending {
			if got, want := view.sets[daID].revision, high+uint64(rank)+1; got != want {
				t.Fatalf("body call %d: record %x revision=%d, want %d", call+1, daID[:1], got, want)
			}
		}
	}
}

// TestDATTLCallbackBodyRefusalChangesNothing pins that a refused check on one selected record, or a selected member
// whose exact owner token is not bound, returns the body's own error and leaves the whole DA image and owner unchanged.
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

// requireDATTLIndexUnchanged pins the State A/B bucket after a refusal to its link order before the body, and to
// exactness whenever the row's corruption left it exact before the body.
func requireDATTLIndexUnchanged(t *testing.T, relay *DARelayState, before [][32]byte, exactBefore bool) {
	t.Helper()
	if after := daTTLIndexKeys(relay); !slices.Equal(after, before) {
		t.Fatalf("refusal changed the State A/B index: %x, want %x", after, before)
	}
	if exactBefore {
		requireDATTLIndexExact(t, relay)
	}
}

// requireDATTLIndexExact pins the relations' State A/B bucket to exactly the present records that are not State C, so
// the bounded walk can miss no State A or B record.
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

// TestDATTLCallbackBodyRefusalArms pins one refusal per check arm: each case corrupts one stored value, asserts the
// body's returned error, and asserts that the DA image, the owner and the State A/B index are unchanged (the index also
// exact whenever the corruption left it exact).
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
		// The same unfinalized claim on a survivor, which is no victim.
		{"survivor claim not finalized", func(f *daNonReplayFixture, r daTTLCallbackRecords) {
			token := r.setup.sets[r.stateAID].chunks[0].member.token
			ownerReadyEditOwner(f, func(o *PendingOutpointOwner) { o.byToken[token].finalized = false })
		}, func(err error) bool { return errors.Is(err, errDARelayImageIncompatible) }},
		// A survivor's input with its owner row missing or different.
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
		// The same owner-row edit on an expiring member, which is a victim.
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
		// The next four rows corrupt a member token or input set and assert
		// errDARelayImageIncompatible.
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
		// The State B commit member stores State A's txid, which its own parsed bytes contradict.
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
		// A count of zero is an inconsistent stored value (underflow invalidates the plan
		// before mutation); the rows assert the bare errDARelayImageIncompatible.
		{"State A count zero", func(f *daNonReplayFixture, r daTTLCallbackRecords) { f.setOwnerReadyTTL(r.stateAID, 0) }, daTTLBareIncompatible},
		{"State B count zero", func(f *daNonReplayFixture, r daTTLCallbackRecords) { f.setOwnerReadyTTL(r.stateBID, 0) }, daTTLBareIncompatible},
		{"nil chainstate", func(f *daNonReplayFixture, _ daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.mempool.chainState = nil })
		}, func(err error) bool { return err != nil && strings.Contains(err.Error(), "nil chainstate") }},
		{"nil pending-outpoint owner", func(f *daNonReplayFixture, _ daTTLCallbackRecords) {
			f.mutateRelay(func(s *DARelayState) { s.mempool.pendingOutpoints = nil })
		}, func(err error) bool { return err != nil && strings.Contains(err.Error(), "nil pending-outpoint owner") }},
	} {
		t.Run(row.name, func(t *testing.T) {
			f, r := newDATTLCallbackRecords(t)
			owner := f.mp.pendingOutpoints
			row.corrupt(f, r)
			before, ownerBefore := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(owner)
			indexBefore, exactBefore := daTTLIndexKeys(f.relay), daTTLIndexMismatch(f.relay) == ""
			err := runDATTLBodyInGuard(t, f)
			t.Logf("refusal: %v (index exact before the body: %v)", err, exactBefore)
			require(t, row.want(err), "body: err=%v, want this arm's refusal", err)
			requireDANonReplayUnchanged(t, f.relay, owner, before, ownerBefore)
			requireDATTLIndexUnchanged(t, f.relay, indexBefore, exactBefore)
		})
	}
}

// TestDATTLCallbackBodyUnboundRelay is the unbound arm: a relay with no mempool reaches no claim domain, so the DA
// image is the whole change and a live owner it cannot see stays untouched.
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
}

// TestDATTLCallbackBodyWalksOnlyStateAB pins the walk bound: a State C record whose stored value the owner-ready check
// refuses is never visited, and the State A/B index stays exact across admission, decrease, expiry and the whole-clone
// ReleasePeerQuotaKey swap.
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

// daTTLBareIncompatible accepts only the unwrapped errDARelayImageIncompatible, which both zero-count arms return; a
// refusal wrapped with a detail suffix fails it.
func daTTLBareIncompatible(err error) bool {
	return errors.Is(err, errDARelayImageIncompatible) && err.Error() == errDARelayImageIncompatible.Error()
}

func daTTLWrapped(want error, detail string) func(error) bool {
	return func(err error) bool { return errors.Is(err, want) && strings.Contains(err.Error(), detail) }
}

// editDATTLChunkMember replaces chunk 0's member of one record with an edited copy, so the owner and every other record
// keep their own identities.
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

// reuseDATTLInputInStateB re-signs State B's commit over State A's input, same length, so the retained bytes, locators
// and accounting stay consistent and only the input set repeats.
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

// requireDATTLIndexStep pins the State A/B index after one production publication and runs one body call that must
// succeed over it.
func requireDATTLIndexStep(t *testing.T, f *daNonReplayFixture, step string) {
	t.Helper()
	requireDATTLIndexExact(t, f.relay)
	requireDATTLOK(t, runDATTLBodyInGuard(t, f), "%s: body after the publication", step)
	requireDATTLIndexExact(t, f.relay)
}

// TestDATTLCallbackIndexProductionPaths pins the index across orphan-chunk staging (State A created and grown), commit
// staging (State A to State B), completion by the commit (State A to State C) and by the last chunk (State B to State
// C) and the PEER quota cleanup removal (D1 projection: TestDATTLCallbackIndexD1Projection); capacity-victim removal is
// not run.
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

// TestDATTLCallbackIndexD1Projection pins the index on the D1 projection: one buildCanonicalDAOwnerCandidates pass over
// a snapshot taken as capture() takes it re-puts the State A survivor, removes the included State C record and the
// State B record whose input the final chain spent, and D1 publishes that clone; the O1 half is not published. State C
// is completed through the real admission, which releases its admission reader.
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

// TestDATTLCallbackEmptiedBucketDropped pins that removing the last State A/B record leaves no empty State A/B bucket
// behind.
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

// daTTLRecordingService is a node-level DATTLMutationService that records each entry attempt by name and, unless
// refused, runs decrease once as an admitted registration would. beforeAttempt, when set, runs after the selection
// snapshot and before the attempt is recorded, the point a registration would linearize.
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

// TestDATTLCallbackBindingSelection pins the binding API: absent invokes nothing, the latest publication wins, a
// snapshot taken before a later publication keeps its Service, the identity read follows publications and returns while
// the DA relay and owner mutexes are held, a refusal is returned unchanged with no fallback, and a nil publication
// leaves the binding unchanged.
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
	go func() { read <- f.engine.DATTLBindingService() }()
	select {
	case got := <-read:
		require(t, got == DATTLMutationService(s2), "identity read under held DA locks=%v, want S2", got)
	case <-time.After(5 * time.Second):
		t.Fatal("identity read waited on the DA relay or owner mutex")
	}
	f.owner.mu.Unlock()
	f.engine.daRelay.mu.Unlock()
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
	require(t, errors.Is(err, closed) && slices.Equal(attempts, []string{"closed"}) && decreases == 0, "refused registration: err=%v attempts=%v decreases=%d", err, attempts, decreases)
	var nilEngine *SyncEngine
	nilEngine.PublishDATTLBinding(s1)
	require(t, nilEngine.DATTLBindingService() == nil && nilEngine.enterSelectedDATTL(decrease) == nil && decreases == 0, "nil engine binding")
}

// TestDATTLCallbackBindingChangesNoDAState pins that binding and selection change nothing over a populated relay (State
// A and B at nonzero counts with owner tokens and a prefetch reservation, State C): the first and a later
// ClaimDARelayState, publication, the identity read and an absent, refused or admitted selection whose decrease does
// nothing change no DA state, and the later claim keeps the first hook.
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

// TestDATTLCallbackBindingConcurrentPublications runs under -race: one publisher stores S_i in increasing i and then
// records i, while selections run concurrently. A selection reads the recorded index before and after it and must
// select an S_j with before <= j <= after+1 (S_after+1 may be published and not yet recorded), so a cached or stale
// binding fails.
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
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 1; i < publications; i++ {
			f.engine.PublishDATTLBinding(services[i])
			recorded.Store(int64(i))
		}
	}()
	for range 2 * publications {
		before := recorded.Load()
		selected.Store(-1)
		require(t, f.engine.enterSelectedDATTL(func() error { return nil }) == nil, "selection error")
		after, got := recorded.Load(), selected.Load()
		require(t, before <= got && got <= after+1, "selected S_%d outside [S_%d, S_%d]", got, before, after+1)
	}
	<-done
	require(t, f.engine.DATTLBindingService() == DATTLMutationService(services[publications-1]), "final binding is not the last publication")
}

// TestDATTLCallbackRunsInsideTheTransitionHold pins the in-guard TTL body under an admission guard the test holds
// exclusively: a ReleasePeerQuotaKey and a DA admission started first park on it, the body completes under that hold,
// neither writer runs before the release, and after it both run against the decreased image: the admitted record is
// created at the full orphan TTL and the decreased records keep count 2.
func TestDATTLCallbackRunsInsideTheTransitionHold(t *testing.T) {
	f, r := newDATTLCallbackRecords(t)
	f.state.admissionMu.Lock()
	released := false
	defer func() {
		if !released {
			f.state.admissionMu.Unlock()
		}
	}()
	done := make(chan error, 2)
	go func() { done <- f.relay.ReleasePeerQuotaKey("unrelated-peer") }()
	awaitCanonicalMOAdmissionRLock(t, "ReleasePeerQuotaKey", 1)
	freshID := [32]byte{0xa8}
	fresh := f.signed(daNonReplayTxSpec{kind: 0x02, daID: freshID, payload: []byte("ttl-fresh")})
	go func() { _, err := f.tryAdmit(fresh, daNonReplayPeer("fresh-peer")); done <- err }()
	awaitCanonicalMOAdmissionRLock(t, "BeginDAAdmission", 1)
	body := make(chan error, 1)
	go func() { body <- f.relay.advanceOwnerReadyTTLInGuard() }()
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

// TestDATTLCallbackDecrementReachability pins the callers of the listed TTL functions: the count-lowering helpers are
// reached only from advanceOwnerReadyTTLInGuard, and the in-guard body only from the canonical transition's enterDATTL;
// the legacy advanceOrphanTTLLocked keeps its one legacy caller.
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

// TestDATTLCallbackAcceptedMarkerCensus pins every production use of the transition's ACCEPTED marker: only the direct
// connect and preferred branch applies set it, to true, and only publishCanonicalTransition reads it, so no other
// initiator invokes a DA TTL entry.
func TestDATTLCallbackAcceptedMarkerCensus(t *testing.T) {
	var uses []string
	walkProductionGoFiles(t, "accepted marker census", func(path string, file *ast.File) {
		for _, decl := range file.Decls {
			enclosing := "package-level " + filepath.Base(path)
			if function, ok := decl.(*ast.FuncDecl); ok {
				enclosing = function.Name.Name
			}
			uses = append(uses, daTTLAcceptedMarkerUses(decl, enclosing)...)
		}
	})
	slices.Sort(uses)
	want := []string{"set applyCanonicalParsedBlockTracked true", "set applyPreferredBranch true", "use package-level sync_apply_helpers.go", "use publishCanonicalTransition"}
	require(t, reflect.DeepEqual(uses, want), "daTTLAccepted uses=%q, want %q", uses, want)
}

// daTTLAcceptedMarkerUses lists each daTTLAccepted identifier in decl: an assignment target as "set <enclosing>
// <right-hand identifier>", every other occurrence as "use <enclosing>".
func daTTLAcceptedMarkerUses(decl ast.Node, enclosing string) []string {
	var uses []string
	assigned := map[*ast.Ident]bool{}
	ast.Inspect(decl, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range n.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "daTTLAccepted" {
					assigned[sel.Sel] = true
					uses = append(uses, "set "+enclosing+" "+daTTLMarkerValue(n, i))
				}
			}
		case *ast.Ident:
			if n.Name == "daTTLAccepted" && !assigned[n] {
				uses = append(uses, "use "+enclosing)
			}
		}
		return true
	})
	return uses
}

func daTTLMarkerValue(assign *ast.AssignStmt, i int) string {
	if len(assign.Rhs) != len(assign.Lhs) {
		return "multi-value"
	}
	if value, ok := assign.Rhs[i].(*ast.Ident); ok {
		return value.Name
	}
	return "expression"
}

// TestDATTLCallbackLatchedNewInvokesNothing pins that a TERMINAL_PERSISTENCE(new) publication, which publishes the
// complete NEW image of an ACCEPTED apply and then latches, invokes no DA TTL entry (RUBIN_COMPACT_BLOCKS.md Section
// 5): the bound entry, attempted once by the preceding ordinary ACCEPTED/NEW publication on the same engine and DA
// relay, records no further attempt.
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

// daTTLEngineRecords retains one State A chunk at count 3 and one State B commit at count 1 in the DA relay bound to
// f.engine, through the real admission over fresh spendable outputs.
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

// TestDATTLCallbackEndToEndBodyRefusalConsumed drives one ACCEPTED/NEW publication through the real SyncEngine and DA
// relay, by the no-lease selection and by the lease entry; the entry gives one State B record an inconsistent stored
// value, or unbinds the exact owner token of the State A member, before it runs the in-guard body, which refuses with
// its own error. The apply still returns its ACCEPTED/NEW summary and a nil error, the engine is not latched, the
// no-lease lease is registered and released once, and the DA image and owner are unchanged (RUBIN_COMPACT_BLOCKS.md
// Section 5).
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

// panicDATTLBodyAt runs the in-guard TTL body under the held exclusive admission guard with a panic injected at stage
// and returns the recovered value; the test, not the body, recovers.
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

// requireDATTLAppliedImage requires the complete applied image of one decrease over State A at 3 and State B at 1: A at
// 2 with one fresh revision, B removed with its claim and prefetch set, nothing else changed; a following body call
// then accepts that image and decreases A to 1.
func requireDATTLAppliedImage(t *testing.T, f *daNonReplayFixture, r daTTLCallbackRecords, before daRelayStateView, ownerBefore *PendingOutpointOwner) {
	t.Helper()
	after, ownerAfter := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	requireDATTLOutsideSelectedUnchanged(t, before, after, ownerBefore, ownerAfter, r.stateAID, r.stateBID)
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

// TestDATTLCallbackBodyPanicKeepsWholeImage injects a panic into the in-guard body after the plan and every check,
// before the first mutation, and after the last apply mutation, before return: the panic reaches the caller
// unrecovered, the DA relay and owner mutexes are released, and the image is the complete old one or the complete
// applied one (RUBIN_COMPACT_BLOCKS.md Section 5).
func TestDATTLCallbackBodyPanicKeepsWholeImage(t *testing.T) {
	for _, stage := range []daTTLStage{daTTLPlanned, daTTLApplied} {
		t.Run(fmt.Sprintf("stage=%d", stage), func(t *testing.T) {
			f, r := newDATTLCallbackRecords(t)
			f.setOwnerReadyTTL(r.stateBID, 1)
			f.relay.prefetch.indexes[r.stateBID] = map[uint16]string{0: "ttl-peer"}
			f.relay.prefetch.expires[r.stateBID] = time.Now().Add(time.Hour)
			before, ownerBefore := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
			got := panicDATTLBodyAt(t, f, stage)
			require(t, got == fmt.Sprintf("ttl panic at stage %d", stage), "recovered %v, want the injected panic", got)
			requireDATTLLocksFree(t, f.relay, f.mp.pendingOutpoints)
			if stage == daTTLPlanned {
				requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, ownerBefore)
				return
			}
			requireDATTLAppliedImage(t, f, r, before, ownerBefore)
		})
	}
}

// TestDATTLCallbackEndToEndBodyPanic drives one ACCEPTED/NEW SyncEngine.ApplyBlock through the production selection
// into a package-test entry holding one registered lease and the real body, with a panic injected at each of the two
// body points: the panic reaches the apply caller unrecovered, the lease is released exactly once so a wait on that
// lease returns, the DA relay and owner mutexes are free, the image is the complete old or applied one, and the
// admission guard stays held by the transition's non-deferred release while the engine mutation lock is released.
func TestDATTLCallbackEndToEndBodyPanic(t *testing.T) {
	for _, stage := range []daTTLStage{daTTLPlanned, daTTLApplied} {
		t.Run(fmt.Sprintf("stage=%d", stage), func(t *testing.T) {
			f := newPendingOutpointSyncFixture(t)
			x, stateA, stateB := daTTLEngineRecords(t, f)
			// The entry mirrors the Service entry under no Service lease: one registered lease,
			// decrease run once, the lease released by defer, unwind included.
			var leases sync.WaitGroup
			var acquired, released atomic.Int32
			var before daRelayStateView
			var ownerBefore *PendingOutpointOwner
			f.engine.PublishDATTLBinding(&daTTLFuncService{enter: func(decrease func() error) error {
				before, ownerBefore = daRelayStateSnapshot(x.relay), cloneDAAdmissionOwner(x.mp.pendingOutpoints)
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
				requireDANonReplayUnchanged(t, x.relay, x.mp.pendingOutpoints, before, ownerBefore)
				return
			}
			requireDATTLOutsideSelectedUnchanged(t, before, after, ownerBefore, cloneDAAdmissionOwner(x.mp.pendingOutpoints), stateA, stateB)
			requireDATTLCount(t, after, stateA, 2)
			_, present := after.sets[stateB]
			require(t, !present && after.records == before.records+1, "applied image: State B present=%v records=%d, want removed and %d", present, after.records, before.records+1)
		})
	}
}

// TestDATTLCallbackEndToEndGenesisBootstrap drives bootstrapCanonicalGenesisIfEmpty on an empty devnet engine with a
// bound DA relay: genesis is an ACCEPTED/NEW publication, so a published binding is attempted exactly once, while under
// an absent binding the bootstrap invokes nothing, publishes no binding and leaves the DA image unchanged
// (RUBIN_COMPACT_BLOCKS.md Section 5).
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

// daTTLHoldRecord is one signed DA transaction of a guard-hold shape, admitted with PEER provenance under quota, and
// the charge the DA relay books for it.
type daTTLHoldRecord struct {
	raw    []byte
	quota  string
	charge uint64
}

// daTTLHoldShape is one retained DA image: records admitted in order, then next, which the default caps refuse with
// capErr. E has no records and no next.
type daTTLHoldShape struct {
	name    string
	records []daTTLHoldRecord
	next    *daTTLHoldRecord
	capErr  error
	sets    int
	members int
	charged uint64
}

// daTTLHoldInputs are the signed transactions of every pre-state: each spends its own one-output ML-DSA-87 P2PK funding
// output from utxos. fill stops before fillNext would exceed the standard mempool byte or count cap.
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

// commit signs a State B commit-only record: one CORE_DA_COMMIT output, chunk_count 1, batch_sig_suite 0, the given
// manifest and batch_sig lengths; its charge is its tx bytes.
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

// stateBShape builds commits for one quota identity until the next would exceed DA_ORPHAN_POOL_SIZE or
// DA_ORPHAN_COMMIT_OVERHEAD_MAX.
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

// chunk signs a State A chunk of daID at index carrying payloadLen zero bytes; its charge is its tx bytes plus its
// payload.
func (in *daTTLHoldInputs) chunk(b testing.TB, daID [32]byte, index uint16, payloadLen int) daTTLHoldRecord {
	payload := make([]byte, payloadLen)
	tx := &consensus.Tx{TxKind: 0x02, DaPayload: payload, DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: index, ChunkHash: sha3.Sum256(payload)}}
	raw := in.sign(b, tx, 100_000_000)
	return daTTLHoldRecord{raw: raw, charge: uint64(len(raw) + payloadLen)}
}

// fullRecordPayloads gives the fewest chunk payloads of one record charging at most DA_ORPHAN_POOL_PER_DA_ID_MAX:
// CHUNK_BYTES each, then the largest last payload that fits.
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

// stateAShape builds records of chunks with the given payload lengths under fresh da_ids until the next record would
// exceed DA_ORPHAN_POOL_SIZE; each PEER identity takes members in order until the next would exceed
// DA_ORPHAN_POOL_PER_PEER_MAX. next is the next record's first chunk.
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

// preState copies the template chain, funds every input, sets the orphan TTL, admits the shape through AdmitDA, checks
// that the caps refuse its next record, then admits the mempool fill.
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

// requireDATTLHoldEffect checks the timed block's DA effect: with the binding every record is decreased once (removed
// at TTL 1); without it no record changes.
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

// BenchmarkDATTLCallbackGuardHold times one ACCEPTED/NEW ApplyBlock over a full standard mempool and one retained DA
// shape, with a binding whose entry runs the decrease directly and with no binding; the difference is the guard hold
// the in-guard TTL decrease adds (RUBIN_COMPACT_BLOCKS.md Section 5).
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
