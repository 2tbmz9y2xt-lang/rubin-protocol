package node

import (
	"crypto/sha3"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
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
		mutate func(*daRelaySetRecord)
	}{
		{"absent descriptor", func(r *daRelaySetRecord) { r.completeIntrinsic = daCompleteCapacitySet{} }},
		{"wrong da_id", func(r *daRelaySetRecord) { r.completeIntrinsic.id[0] ^= 0xff }},
		{"wrong fee", func(r *daRelaySetRecord) { r.completeIntrinsic.fee.Lo++ }},
		{"zero total bytes", func(r *daRelaySetRecord) { r.completeIntrinsic.totalBytes = 0 }},
		{"wrong nonzero total bytes", func(r *daRelaySetRecord) { r.completeIntrinsic.totalBytes++ }},
		{"wrong payload bytes", func(r *daRelaySetRecord) { r.completeIntrinsic.payloadBytes++ }},
		{"payload exceeds total bytes", func(r *daRelaySetRecord) {
			r.payloadBytes, r.completeIntrinsic.payloadBytes = r.completeIntrinsic.totalBytes+1, r.completeIntrinsic.totalBytes+1
		}},
		{"wrong received sequence", func(r *daRelaySetRecord) { r.completeIntrinsic.receivedSequence++ }},
		{"member fee overflow", func(r *daRelaySetRecord) {
			*r = r.cloneOwnerReady()
			r.commit.member.fee, r.chunks[0].member.fee = consensus.Uint128{Hi: ^uint64(0), Lo: ^uint64(0)}, consensus.Uint128FromU64(1)
			r.completeIntrinsic.fee = consensus.Uint128{}
		}},
	} {
		for _, selector := range selectors {
			t.Run(row.name+" on "+selector.name, func(t *testing.T) {
				f, id := newDANonReplayFixture(t, 2), [32]byte{0xd1}
				f.completeReplayPinned(id)
				clean, ownerClean := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
				f.mutateRelay(func(s *DARelayState) {
					record := s.sets[id]
					row.mutate(&record)
					s.sets[id], s.pinnedPayloadBytes = record, record.payloadBytes
				})
				before, ownerBefore := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
				if err := selector.run(f.relay); !errors.Is(err, errDARelayImageIncompatible) {
					t.Fatalf("cleanup accepted inconsistent C metadata: err=%v, want %v", err, errDARelayImageIncompatible)
				}
				requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, ownerBefore)
				f.mutateRelay(func(s *DARelayState) { s.sets[id], s.pinnedPayloadBytes = clean.sets[id], clean.pinnedPayloadBytes })
				if err := selector.run(f.relay); err != nil {
					t.Fatalf("State C cleanup ceased to be a successful no-op: corrected cleanup: %v", err)
				}
				requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, clean, ownerClean)
			})
		}
	}
	buildMaxCount := func(t *testing.T) (*daNonReplayFixture, [32]byte, daRelayStateView, *PendingOutpointOwner) {
		count, id := uint16(consensus.MAX_DA_CHUNK_COUNT), [32]byte{0xd2}
		f, payloads := newDANonReplayFixture(t, int(count)+3), make([]byte, count)
		for index := uint16(0); index < count; index++ {
			payloads[index] = byte(index + 1)
			f.admit(f.signed(daNonReplayTxSpec{kind: 0x02, daID: id, chunkIndex: index, payload: payloads[index : index+1]}), LocalDAProvenance())
		}
		commit := f.signed(daNonReplayTxSpec{kind: 0x01, daID: id, chunkCount: count, commitment: sha3.Sum256(payloads), commitmentOutputs: 1})
		_, token := mustFinalizeDAAdmission(t, f.mp, commit.raw)
		f.mutateRelay(func(s *DARelayState) {
			record := s.sets[id]
			record.commit = daRelayCommit{daID: id, payloadCommitment: commit.spec.commitment, member: &daRelayMemberIdentity{txid: commit.txid, wtxid: commit.wtxid, fee: commit.spec.fee, inputs: commit.inputs, token: token, provenance: LocalDAProvenance()}, chunkCount: count, txBytes: commit.raw}
			record.markComplete(uint64(count))
			set, matches, err := parseDACompleteRecord(record)
			require(t, err == nil && matches, "maximum-count G1 fixture: matches=%v err=%v", matches, err)
			record.completeIntrinsic = set
			charge := s.orphanBytesByDAID[id]
			delete(s.orphanBytesByDAID, id)
			s.orphanBytes, s.completeBytes, s.completeCount, s.pinnedPayloadBytes = s.orphanBytes-charge, s.completeBytes+set.totalBytes, s.completeCount+1, s.pinnedPayloadBytes+set.payloadBytes
			s.locators[commit.txid], s.sets[id] = daRelayLocator{daID: id, kind: daRelayLocatorCommit}, record
		})
		clean, ownerClean := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
		return f, id, clean, ownerClean
	}
	for _, selector := range selectors {
		t.Run("excessive chunk count on "+selector.name, func(t *testing.T) {
			f, id, clean, ownerClean := buildMaxCount(t)
			require(t, selector.run(f.relay) == nil, "valid maximum chunk count failed on %s", selector.name)
			requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, clean, ownerClean)
			extra := f.signed(daNonReplayTxSpec{kind: 0x02, daID: id, payload: []byte("over")})
			_, extraToken := mustFinalizeDAAdmission(t, f.mp, extra.raw)
			// The over-MAX image uses signed/claimed bytes; only their R5 byte role differs from cached slot MAX.
			f.mutateRelay(func(s *DARelayState) {
				record, index := s.sets[id], uint16(consensus.MAX_DA_CHUNK_COUNT)
				member := &daRelayMemberIdentity{txid: extra.txid, wtxid: extra.wtxid, fee: extra.spec.fee, inputs: extra.inputs, token: extraToken, provenance: LocalDAProvenance()}
				record.commit.chunkCount, record.chunks[index] = index+1, daRelayChunk{daID: id, chunkHash: sha3.Sum256(extra.spec.payload), member: member, chunkIndex: index, txBytes: extra.raw}
				record.payloadBytes, record.completeIntrinsic.payloadBytes = record.payloadBytes+uint64(len(extra.spec.payload)), record.completeIntrinsic.payloadBytes+uint64(len(extra.spec.payload))
				record.completeIntrinsic.fee.Lo, record.completeIntrinsic.totalBytes = record.completeIntrinsic.fee.Lo+extra.spec.fee.Lo, record.completeIntrinsic.totalBytes+uint64(len(extra.raw))
				s.sets[id], s.completeBytes, s.pinnedPayloadBytes, s.locators[extra.txid] = record, s.completeBytes+uint64(len(extra.raw)), s.pinnedPayloadBytes+uint64(len(extra.spec.payload)), daRelayLocator{daID: id, kind: daRelayLocatorChunk, chunkIndex: index}
			})
			before, ownerBefore := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
			require(t, errors.Is(selector.run(f.relay), errDARelayImageIncompatible), "cleanup accepted excessive C chunk count")
			requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, ownerBefore)
			f.mutateRelay(func(s *DARelayState) {
				s.sets, s.locators, s.completeBytes, s.pinnedPayloadBytes = maps.Clone(clean.sets), maps.Clone(clean.locators), clean.completeBytes, clean.pinnedPayloadBytes
			})
			ownerReadyEditOwner(f, func(o *PendingOutpointOwner) {
				o.byToken, o.byOutpoint, o.tokenHighWater = maps.Clone(ownerClean.byToken), maps.Clone(ownerClean.byOutpoint), ownerClean.tokenHighWater
			})
			require(t, selector.run(f.relay) == nil, "corrected excessive chunk count failed on %s", selector.name)
			requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, clean, ownerClean)
		})
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
