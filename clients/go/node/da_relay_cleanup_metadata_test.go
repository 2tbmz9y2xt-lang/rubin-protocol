package node

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestDACleanupIntrinsicMetadata(t *testing.T) {
	selectors := []struct {
		name string
		run  func(*DARelayState) error
	}{
		{"ttl tick", (*DARelayState).AdvanceOrphanTTL},
		{"peer commit", func(s *DARelayState) error { return s.ReleasePeerQuotaKey("commit") }},
		{"peer chunk", func(s *DARelayState) error { return s.ReleasePeerQuotaKey("chunk") }},
		{"peer release", func(s *DARelayState) error { return s.ReleasePeerQuotaKey("unrelated") }},
		{"peer empty", func(s *DARelayState) error { return s.ReleasePeerQuotaKey("") }},
	}
	for _, row := range []struct {
		name   string
		mutate func(*daCompleteCapacitySet)
	}{
		{"absent descriptor", func(x *daCompleteCapacitySet) { *x = daCompleteCapacitySet{} }},
		{"wrong da_id", func(x *daCompleteCapacitySet) { x.id[0] ^= 0xff }},
		{"wrong fee", func(x *daCompleteCapacitySet) { x.fee.Lo++ }},
		{"zero total bytes", func(x *daCompleteCapacitySet) { x.totalBytes = 0 }},
		{"wrong nonzero total bytes", func(x *daCompleteCapacitySet) { x.totalBytes++ }},
		{"wrong payload bytes", func(x *daCompleteCapacitySet) { x.payloadBytes++ }},
		{"wrong received sequence", func(x *daCompleteCapacitySet) { x.receivedSequence++ }},
	} {
		for _, selector := range selectors {
			t.Run(row.name+" on "+selector.name, func(t *testing.T) {
				f, id := newDANonReplayFixture(t, 2), [32]byte{0xd1}
				f.completeReplayPinned(id)
				clean, ownerClean := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
				f.mutateRelay(func(s *DARelayState) {
					record := s.sets[id]
					row.mutate(&record.completeIntrinsic)
					s.sets[id] = record
				})
				before, ownerBefore := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
				if err := selector.run(f.relay); !errors.Is(err, errDARelayImageIncompatible) {
					t.Fatalf("cleanup accepted inconsistent C metadata: err=%v, want %v", err, errDARelayImageIncompatible)
				}
				requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, ownerBefore)
				f.mutateRelay(func(s *DARelayState) { s.sets[id] = clean.sets[id] })
				if err := selector.run(f.relay); err != nil {
					t.Fatalf("State C cleanup ceased to be a successful no-op: corrected cleanup: %v", err)
				}
				requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, clean, ownerClean)
			})
		}
	}
	t.Run("mixed eligible removal is atomic with invalid C metadata", func(t *testing.T) {
		f, incompleteID, completeID := newDANonReplayFixture(t, 4), [32]byte{0xa1}, [32]byte{0xc1}
		incomplete := f.ownerReadyChunk(incompleteID, 0, "drop", daNonReplayPeer("drop"))
		f.completeReplayPinned(completeID)
		var descriptor daCompleteCapacitySet
		f.mutateRelay(func(s *DARelayState) {
			record := s.sets[completeID]
			descriptor = record.completeIntrinsic
			record.completeIntrinsic.fee.Lo++
			s.sets[completeID] = record
			s.prefetch.indexes = map[[32]byte]map[uint16]string{incompleteID: {1: "peer"}}
		})
		before, ownerBefore := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
		if err := f.relay.ReleasePeerQuotaKey("drop"); !errors.Is(err, errDARelayImageIncompatible) {
			t.Fatalf("cleanup accepted inconsistent C metadata: %v", err)
		}
		requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, ownerBefore)
		f.mutateRelay(func(s *DARelayState) {
			record := s.sets[completeID]
			record.completeIntrinsic = descriptor
			s.sets[completeID] = record
		})
		if err := f.relay.ReleasePeerQuotaKey("drop"); err != nil {
			t.Fatalf("corrected mixed cleanup: %v", err)
		}
		after := daRelayStateSnapshot(f.relay)
		ownerReadyRecordAbsent(t, after, incompleteID, incomplete.txid)
		ownerReadyClaimGone(t, cloneDAAdmissionOwner(f.mp.pendingOutpoints), before.sets[incompleteID].chunks[0].member.token, incomplete.inputs)
		if after.sets[completeID].completeIntrinsic != descriptor {
			t.Fatal("corrected mixed cleanup changed surviving C metadata")
		}
	})
}

func TestDACleanupCanonicalIsolation(t *testing.T) {
	f := newDANonReplayFixture(t, 4)
	earlier, later := [32]byte{0x31}, [32]byte{0x32}
	f.completeReplayPinned(earlier)
	f.completeReplayPinned(later)
	f.mutateRelay(func(s *DARelayState) {
		record := s.sets[earlier]
		chunk := record.chunks[0]
		chunk.txBytes = append([]byte(nil), chunk.txBytes...)
		chunk.txBytes[len(chunk.txBytes)-1] ^= 0xff
		record.chunks[0] = chunk
		s.sets[earlier] = record
	})
	before, ownerBefore := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	if err := f.relay.ReleasePeerQuotaKey("unrelated"); err != nil {
		t.Fatalf("metadata-valid cleanup read State C body: %v", err)
	}
	requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, ownerBefore)
	f.mutateRelay(func(s *DARelayState) {
		record := s.sets[later]
		record.commit.member = nil
		s.sets[later] = record
	})
	var terminal *canonicalDATerminalError
	if _, err := validateCanonicalDARetainedSnapshot(f.relay, f.mp.pendingOutpoints); !errors.As(err, &terminal) || !strings.Contains(err.Error(), errDARelayImageIncompatible.Error()) || !strings.Contains(err.Error(), fmt.Sprintf("retained DA record %x", earlier)) || strings.Contains(err.Error(), fmt.Sprintf("retained DA record %x", later)) {
		t.Fatalf("canonical C intrinsic first-error order changed: %v", err)
	}
}
