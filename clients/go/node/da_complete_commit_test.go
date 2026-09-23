package node

import (
	"bytes"
	"crypto/sha3"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"math"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func daCompleteCommitTestPlan(t *testing.T, f *daNonReplayFixture, a *DAAdmission, c daRelayAdmissionCandidate) (*daCompleteCommitPlan, daCompletePreparation) {
	t.Helper()
	s := daCompleteTestCapture(t, f, c)
	r, err := prepareDACompleteSnapshot(s, daRelayAdmissionOutcome{})
	if err != nil {
		t.Fatal(err)
	}
	before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	p, err := f.relay.prepareDACompleteCommit(a, r)
	if err != nil {
		t.Fatal(err)
	}
	requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
	return p, r
}

func daCompleteCommitTestApply(t *testing.T, f *daNonReplayFixture, a *DAAdmission, p *daCompleteCommitPlan) {
	t.Helper()
	out, rejected, err := f.relay.applyDACompleteCommit(a, p)
	if err != nil || rejected || out != (daRelayAdmissionOutcome{daID: [32]byte{1}, disposition: 1}) {
		t.Fatalf("completion tuple: %+v %v %v", out, rejected, err)
	}
}

// Populate the closed C count boundary with owned scalar descriptors and live
// claims. The completion path must not parse these resident bytes.
func daCompleteCommitFillCountLimit(f *daNonReplayFixture, count int, fee uint64) {
	s, o := f.relay, f.mp.pendingOutpoints
	for i := 0; i < count; i++ {
		id := [32]byte{2, byte(i), byte(i >> 8)}
		r := daRelaySetRecord{daID: id, state: daRelayStateCompleteSet, revision: 1, receivedTime: 1, payloadBytes: 1, chunks: map[uint16]daRelayChunk{}}
		for j := 0; j < 2; j++ {
			txid := [32]byte{byte(3 + j), byte(i), byte(i >> 8)}
			input := consensus.Outpoint{Txid: txid}
			o.tokenHighWater++
			token := PendingOutpointToken{owner: o, seq: o.tokenHighWater}
			claim := &pendingOutpointClaim{domain: PendingOutpointDA, txid: txid, inputs: []consensus.Outpoint{input}, token: token, generation: o.generation, finalized: true}
			o.byToken[token] = claim
			o.byOutpoint[input] = pendingOutpointRow{token: token, txid: txid}
			m := &daRelayMemberIdentity{txid: txid, wtxid: txid, fee: consensus.Uint128{Lo: fee}, token: token, inputs: []consensus.Outpoint{input}, provenance: LocalDAProvenance()}
			if j == 0 {
				r.commit = daRelayCommit{daID: id, member: m, chunkCount: 1, txBytes: []byte{1}}
				s.locators[txid] = daRelayLocator{daID: id, kind: daRelayLocatorCommit}
			} else {
				r.chunks[0] = daRelayChunk{daID: id, member: m, txBytes: []byte{2}}
				s.locators[txid] = daRelayLocator{daID: id, kind: daRelayLocatorChunk}
			}
		}
		r.completeIntrinsic = daCompleteCapacitySet{id: id, fee: consensus.Uint128{Lo: 2 * fee}, totalBytes: 2, payloadBytes: 1, receivedSequence: 1}
		s.sets[id] = r
	}
	s.completeBytes += uint64(2 * count)
	s.completeCount += uint64(count)
	s.pinnedPayloadBytes += uint64(count)
}

func daCompleteCommitLocatorHistory(s *DARelayState, tombstone bool) {
	for i := byte(40); i < 72; i++ {
		s.locators[[32]byte{i}] = daRelayLocator{daID: [32]byte{i}, kind: daRelayLocatorChunk}
	}
	if tombstone {
		for i := byte(40); i < 56; i++ {
			delete(s.locators, [32]byte{i})
		}
	}
}

// Reconstruct the descriptor from retained transactions, without the completion parser.
func intrinsicFromRetainedOracle(t *testing.T, record daRelaySetRecord, id [32]byte, payloads [][]byte, first uint64) daCompleteCapacitySet {
	t.Helper()
	if record.daID != id || record.receivedTime != first {
		t.Fatal("retained DA identity or first accepted sequence")
	}
	commit, txid, wtxid, n, err := consensus.ParseTx(record.commit.txBytes)
	if err != nil || n != len(record.commit.txBytes) || commit.DaCommitCore == nil || commit.DaCommitCore.DaID != id || int(commit.DaCommitCore.ChunkCount) != len(payloads) || record.commit.member == nil || record.commit.member.txid != txid || record.commit.member.wtxid != wtxid || record.commit.member.fee != (consensus.Uint128{Lo: 600_000}) {
		t.Fatal("retained commit parse, identity or admission fee")
	}
	want := daCompleteCapacitySet{id: id, fee: consensus.Uint128{Lo: 600_000}, totalBytes: uint64(n), receivedSequence: first}
	for i, payload := range payloads {
		chunk := record.chunks[uint16(i)]
		tx, chunkID, chunkWID, used, parseErr := consensus.ParseTx(chunk.txBytes)
		if parseErr != nil || used != len(chunk.txBytes) || tx.DaChunkCore == nil || tx.DaChunkCore.DaID != id || tx.DaChunkCore.ChunkIndex != uint16(i) || !bytes.Equal(tx.DaPayload, payload) || sha3.Sum256(tx.DaPayload) != tx.DaChunkCore.ChunkHash || chunk.member == nil || chunk.member.txid != chunkID || chunk.member.wtxid != chunkWID || chunk.member.fee != (consensus.Uint128{Lo: 600_000}) {
			t.Fatalf("retained chunk %d parse, payload, identity or admission fee", i)
		}
		want.fee.Lo += 600_000
		want.totalBytes += uint64(used)
		want.payloadBytes += uint64(len(tx.DaPayload))
	}
	if len(record.chunks) != len(payloads) || record.commit.payloadCommitment != sha3.Sum256(bytes.Join(payloads, nil)) {
		t.Fatal("retained complete set shape or payload commitment")
	}
	return want
}

func requireDACompleteCommitReplayRejected(t *testing.T, f *daNonReplayFixture, a *DAAdmission, p *daCompleteCommitPlan, before daRelayStateView, owner *PendingOutpointOwner, wantState uint32) {
	if out, rejected, err := f.relay.applyDACompleteCommit(a, p); out != (daRelayAdmissionOutcome{}) || rejected || !daCompleteTestError(err, errDARelayImageIncompatible) || a.guard.state.Load() != wantState {
		t.Fatal("complete plan replay")
	}
	requireDANonReplayUnchanged(t, f.relay, a.guard.owner, before, owner)
}

func TestDACompleteCommitMatching(t *testing.T) {
	for _, commitLast := range []bool{true, false} {
		t.Run(fmt.Sprint(commitLast), func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, commitLast, 2, 0)
			before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
			old := before.sets[[32]byte{1}]
			p, _ := daCompleteCommitTestPlan(t, f, a, c)
			daCompleteCommitTestApply(t, f, a, p)
			got := daRelayStateSnapshot(f.relay)
			r := got.sets[[32]byte{1}]
			wantBytes := uint64(len(a.snapshot.TxBytes))
			if commitLast {
				wantBytes += uint64(len(old.chunks[0].txBytes))
			} else {
				wantBytes += uint64(len(old.commit.txBytes))
			}
			if got.stagedBytes != 0 {
				t.Fatal("staged credit")
			}
			if got.commitBytes != 0 {
				t.Fatal("prior B commit overhead")
			}
			if got.orphanBytes != 0 || len(got.peerBytes) != 0 || len(got.daIDBytes) != 0 {
				t.Fatal("old A peer DA orphan charge")
			}
			if got.completeBytes != wantBytes || got.completeCount != 1 || got.pinnedPayloadBytes != 16 {
				t.Fatal("C bytes count payload")
			}
			if got.records != before.records+1 || r.revision != before.records+1 || got.nextReceivedTime != before.nextReceivedTime+1 || r.receivedTime != old.receivedTime {
				t.Fatal("one revision sequence and first receivedTime")
			}
			if r.state != 2 || r.ttlBlocksRemaining != 0 || r.wireBytes != 0 || r.replaceableChunks != nil || r.chunks[0].payload != nil || len(r.chunks) != 1 {
				t.Fatal("exact C representation")
			}
			wantIntrinsic := intrinsicFromRetainedOracle(t, r, [32]byte{1}, [][]byte{[]byte("complete payload")}, 1)
			if r.completeIntrinsic != wantIntrinsic {
				t.Fatalf("State C intrinsic=%+v, want %+v", r.completeIntrinsic, wantIntrinsic)
			}
			if len(got.locators) != 2 || got.locators[c.member.member.txid] != c.member.locator {
				t.Fatal("candidate locator")
			}
			current := cloneDAAdmissionOwner(f.mp.pendingOutpoints)
			candidateToken := PendingOutpointToken{owner: f.mp.pendingOutpoints, seq: owner.tokenHighWater + 1}
			member, raw := r.commit.member, r.commit.txBytes
			survivor, oldSurvivor := r.chunks[0].member, old.chunks[0].member
			survivorRaw, oldRaw := r.chunks[0].txBytes, old.chunks[0].txBytes
			if !commitLast {
				member, raw = r.chunks[0].member, r.chunks[0].txBytes
				survivor, oldSurvivor = r.commit.member, old.commit.member
				survivorRaw, oldRaw = r.commit.txBytes, old.commit.txBytes
			}
			wantMember := c.member.member
			wantMember.token = candidateToken
			if !reflect.DeepEqual(member, &wantMember) || !bytes.Equal(raw, a.snapshot.TxBytes) || !reflect.DeepEqual(survivor, oldSurvivor) || !bytes.Equal(survivorRaw, oldRaw) {
				t.Fatal("exact retained candidate and survivor metadata bytes provenance")
			}
			claim := current.byToken[candidateToken]
			if claim == nil || !claim.finalized || claim.txid != a.snapshot.TxID || !slices.Equal(claim.inputs, a.snapshot.Inputs) || a.guard.state.Load() != 4 {
				t.Fatal("candidate finalized original admission guard consumed")
			}
			for token, oldClaim := range owner.byToken {
				_, survives := got.locators[oldClaim.txid]
				if survives && !reflect.DeepEqual(current.byToken[token], oldClaim) {
					t.Fatal("surviving token and metadata")
				}
				if !survives && current.byToken[token] != nil {
					t.Fatal("pruned victim deletion")
				}
				for _, input := range oldClaim.inputs {
					if _, present := current.byOutpoint[input]; !survives && present {
						t.Fatal("pruned input deletion")
					}
				}
			}
			for _, input := range a.snapshot.Inputs {
				if current.byOutpoint[input] != (pendingOutpointRow{token: candidateToken, txid: a.snapshot.TxID}) {
					t.Fatal("candidate exact input rows")
				}
			}
			if current.tokenHighWater != owner.tokenHighWater+1 || len(current.byToken) != 2 {
				t.Fatal("one completing token")
			}
		})
	}
	f, a, c, victims := daCompleteCommitPhysicalVictims(t, 1)
	f.relay.prefetch.indexes = map[[32]byte]map[uint16]string{{11}: {0: "victim"}}
	f.relay.prefetch.expires = map[[32]byte]time.Time{{11}: time.Unix(3, 0)}
	p, _ := daCompleteCommitTestPlan(t, f, a, c)
	daCompleteCommitTestApply(t, f, a, p)
	for _, record := range victims {
		if _, present := f.relay.prefetch.indexes[record.daID]; present {
			t.Fatal("exact victim prefetch index deletion")
		}
		if _, present := f.relay.prefetch.expires[record.daID]; present {
			t.Fatal("exact victim prefetch expiry deletion")
		}
		if _, present := f.relay.sets[record.daID]; present {
			t.Fatal("victim record deletion")
		}
		for _, member := range []*daRelayMemberIdentity{record.commit.member, record.chunks[0].member} {
			if _, present := f.relay.locators[member.txid]; present {
				t.Fatal("victim locator deletion")
			}
			if f.mp.pendingOutpoints.byToken[member.token] != nil {
				t.Fatal("victim claim deletion")
			}
		}
	}
	if f.relay.completeCount != 65536 || f.relay.pinnedPayloadBytes != 65535+16 || f.relay.completeBytes != 131070+uint64(len(a.snapshot.TxBytes)+len(p.source.prior.chunks[0].txBytes)) {
		t.Fatal("victim C bytes count payload")
	}

	// Scalar C pressure drives the real apply path; this is not canonical raw-byte provenance evidence.
	// Count pressure needs one victim; live payload pressure needs a second.
	f, a, c, victims = daCompleteCommitPhysicalVictims(t, 2)
	p, _ = daCompleteCommitTestPlan(t, f, a, c)
	pressureID, survivorID := [32]byte{2}, [32]byte{2, 1}
	pressure := f.relay.sets[pressureID]
	largePayload := uint64(96_000_000) - (f.relay.pinnedPayloadBytes - 1)
	largeChunk := pressure.chunks[0]
	largeChunk.txBytes = make([]byte, int(largePayload))
	largeChunk.member.fee = consensus.Uint128{Hi: 1}
	pressure.chunks[0] = largeChunk
	pressure.commit.member.fee = consensus.Uint128{Hi: 1}
	pressure.payloadBytes = largePayload
	pressure.completeIntrinsic.payloadBytes = largePayload
	pressure.completeIntrinsic.totalBytes = largePayload + 1
	pressure.completeIntrinsic.fee = consensus.Uint128{Hi: 2}
	f.relay.sets[pressureID] = pressure
	f.relay.completeBytes += largePayload - 1
	f.relay.pinnedPayloadBytes += largePayload - 1
	f.relay.prefetch.indexes = map[[32]byte]map[uint16]string{{11}: {0: "victim"}, {12}: {0: "victim"}, survivorID: {0: "survivor"}}
	f.relay.prefetch.expires = map[[32]byte]time.Time{{11}: time.Unix(3, 0), {12}: time.Unix(4, 0), survivorID: time.Unix(5, 0)}
	beforeBytes, beforeCount, beforePayload := f.relay.completeBytes, f.relay.completeCount, f.relay.pinnedPayloadBytes
	beforeRecords, beforeSequence := f.relay.records, f.relay.nextReceivedTime
	beforeLocators, beforeHigh := len(f.relay.locators), f.mp.pendingOutpoints.tokenHighWater
	survivor := f.relay.sets[survivorID]
	pressure = f.relay.sets[pressureID]
	survivingClaims := make(map[PendingOutpointToken]pendingOutpointClaim)
	for _, record := range []daRelaySetRecord{survivor, pressure} {
		for _, member := range []*daRelayMemberIdentity{record.commit.member, record.chunks[0].member} {
			claim := *f.mp.pendingOutpoints.byToken[member.token]
			claim.inputs = slices.Clone(claim.inputs)
			survivingClaims[member.token] = claim
		}
	}
	if beforePayload != 96_000_000 || p.result.prepared.set.payloadBytes != 16 {
		t.Fatal("two-victim payload precondition")
	}
	daCompleteCommitTestApply(t, f, a, p)
	if !slices.Equal(p.capacity.victims, [][32]byte{{11}, {12}}) {
		t.Fatal("source-first minimal two-victim prefix", p.capacity.victims)
	}
	removedBytes := victims[0].completeIntrinsic.totalBytes + victims[1].completeIntrinsic.totalBytes
	if f.relay.completeBytes != beforeBytes-removedBytes+p.result.prepared.set.totalBytes || f.relay.completeCount != beforeCount-1 || f.relay.pinnedPayloadBytes != beforePayload || f.relay.records != beforeRecords+1 || f.relay.nextReceivedTime != beforeSequence+1 {
		t.Fatal("exact two-victim C counters and accepted sequence")
	}
	if len(f.relay.sets) != 65535 || len(f.relay.locators) != beforeLocators-3 || f.relay.locators[c.member.member.txid] != c.member.locator || !reflect.DeepEqual(f.relay.sets[survivorID], survivor) || !reflect.DeepEqual(f.relay.sets[pressureID], pressure) {
		t.Fatal("sparse two-victim records and locators")
	}
	o := f.mp.pendingOutpoints
	candidateToken := PendingOutpointToken{owner: o, seq: beforeHigh + 1}
	if o.tokenHighWater != candidateToken.seq || o.byToken[candidateToken] == nil || !o.byToken[candidateToken].finalized || len(o.byToken) != 2*65535 {
		t.Fatal("exact candidate token and surviving C claims")
	}
	for _, input := range a.snapshot.Inputs {
		if o.byOutpoint[input] != (pendingOutpointRow{token: candidateToken, txid: a.snapshot.TxID}) {
			t.Fatal("candidate input was not claimed")
		}
	}
	for _, record := range victims {
		if _, present := f.relay.sets[record.daID]; present {
			t.Fatal("selected C victim survived")
		}
		if _, present := f.relay.prefetch.indexes[record.daID]; present {
			t.Fatal("selected C prefetch survived")
		}
		if _, present := f.relay.prefetch.expires[record.daID]; present {
			t.Fatal("selected C prefetch expiry survived")
		}
		for _, member := range []*daRelayMemberIdentity{record.commit.member, record.chunks[0].member} {
			if _, present := f.relay.locators[member.txid]; present || o.byToken[member.token] != nil {
				t.Fatal("selected C locator or claim survived")
			}
			for _, input := range member.inputs {
				if _, present := o.byOutpoint[input]; present {
					t.Fatal("selected C input survived")
				}
			}
		}
	}
	for _, record := range []daRelaySetRecord{survivor, pressure} {
		for _, member := range []*daRelayMemberIdentity{record.commit.member, record.chunks[0].member} {
			if o.byToken[member.token] == nil || !reflect.DeepEqual(*o.byToken[member.token], survivingClaims[member.token]) {
				t.Fatal("unselected C claim changed")
			}
			for _, input := range member.inputs {
				if o.byOutpoint[input] != (pendingOutpointRow{token: member.token, txid: member.txid}) {
					t.Fatal("unselected C input changed")
				}
			}
		}
	}
	if !reflect.DeepEqual(f.relay.prefetch.indexes[survivorID], map[uint16]string{0: "survivor"}) || f.relay.prefetch.expires[survivorID] != time.Unix(5, 0) {
		t.Fatal("unselected C prefetch changed")
	}
}

func TestDAStateCIntrinsicOwnership(t *testing.T) {
	for _, commitLast := range []bool{true, false} {
		t.Run(fmt.Sprint(commitLast), func(t *testing.T) {
			f := newDANonReplayFixture(t, 8)
			id, payload := [32]byte{1}, []byte("complete payload")
			chunk := f.signed(daNonReplayTxSpec{kind: 2, daID: id, payload: payload, inputCount: 2})
			commit := f.signed(daNonReplayTxSpec{kind: 1, daID: id, chunkCount: 1, commitment: sha3.Sum256(payload), commitmentOutputs: 1})
			last, survivor := chunk, commit
			if commitLast {
				f.admit(chunk, daNonReplayPeer("retained"))
				last, survivor = commit, chunk
			} else {
				f.admit(commit, DetachedReorgDAProvenance())
			}
			prior := f.relay.sets[id]
			if prior.completeIntrinsic != (daCompleteCapacitySet{}) {
				t.Fatal("State A/B carried a complete intrinsic descriptor")
			}
			wantCommitRaw, wantChunkRaw := slices.Clone(commit.raw), slices.Clone(chunk.raw)
			wantCommitInputs, wantChunkInputs := slices.Clone(commit.inputs), slices.Clone(chunk.inputs)
			a := f.begin(last)
			t.Cleanup(func() {
				if a.guard.state.Load() != daAdmissionClosed {
					a.Close()
				}
			})
			candidate, err := a.renderDARelayAdmissionCandidate(LocalDAProvenance())
			if err != nil {
				t.Fatal(err)
			}
			last.raw[0] ^= 1
			survivor.raw[0] ^= 1
			ownerHigh := f.mp.pendingOutpoints.tokenHighWater
			plan, result := daCompleteCommitTestPlan(t, f, a, candidate)
			candidate.member.txBytes[0] ^= 1
			candidate.member.member.inputs[0].Vout++
			result.prepared.image.next.commit.txBytes[0] ^= 1
			result.prepared.image.next.commit.member.inputs[0].Vout++
			imageChunk := result.prepared.image.next.chunks[0]
			imageChunk.txBytes[0] ^= 1
			imageChunk.member.inputs[0].Vout++
			result.prepared.image.next.chunks[0] = imageChunk
			daCompleteCommitTestApply(t, f, a, plan)

			record := f.relay.sets[id]
			wantIntrinsic := intrinsicFromRetainedOracle(t, record, id, [][]byte{payload}, 1)
			if record.completeIntrinsic != wantIntrinsic {
				t.Fatalf("published State C intrinsic=%+v, want %+v", record.completeIntrinsic, wantIntrinsic)
			}
			if !bytes.Equal(record.commit.txBytes, wantCommitRaw) || !bytes.Equal(record.chunks[0].txBytes, wantChunkRaw) || !slices.Equal(record.commit.member.inputs, wantCommitInputs) || !slices.Equal(record.chunks[0].member.inputs, wantChunkInputs) {
				t.Fatal("retained commit/chunk/input aliases changed through caller or source image")
			}
			candidateToken := PendingOutpointToken{owner: f.mp.pendingOutpoints, seq: ownerHigh + 1}
			if (commitLast && (record.commit.member.token != candidateToken || record.chunks[0].member.token != prior.chunks[0].member.token)) || (!commitLast && (record.chunks[0].member.token != candidateToken || record.commit.member.token != prior.commit.member.token)) {
				t.Fatal("State C owner tokens differ from reserved/surviving values")
			}

			provided := f.relay.CompleteSetCandidates(math.MaxUint64)
			if len(provided) != 1 || len(provided[0].Chunks) != 1 {
				t.Fatalf("provider snapshot=%+v", provided)
			}
			provided[0].CommitTx[0] ^= 1
			provided[0].Chunks[0].Tx[0] ^= 1
			provided[0].Chunks = nil
			again := f.relay.CompleteSetCandidates(math.MaxUint64)
			if len(again) != 1 || len(again[0].Chunks) != 1 || !bytes.Equal(again[0].CommitTx, wantCommitRaw) || !bytes.Equal(again[0].Chunks[0].Tx, wantChunkRaw) || f.relay.sets[id].completeIntrinsic != wantIntrinsic {
				t.Fatal("provider snapshot aliases retained State C")
			}
			a.Close()
			replay := last
			if commitLast {
				replay.raw = slices.Clone(wantCommitRaw)
			} else {
				replay.raw = slices.Clone(wantChunkRaw)
			}
			requireExactDADuplicate(t, f, replay)

			corrupt := record.cloneOwnerReady()
			corrupt.commit.txBytes[0] ^= 1
			if !daCompleteTestError(checkOwnerReadyRetainedRecordLocked(corrupt), errDARelayImageIncompatible) {
				t.Fatal("direct retained-byte corruption bypassed full validation")
			}
			corrupt = record.cloneOwnerReady()
			corrupt.completeIntrinsic.totalBytes++
			if !daCompleteTestError(checkOwnerReadyRetainedRecordLocked(corrupt), errDARelayImageIncompatible) {
				t.Fatal("descriptor mismatch bypassed owner-ready validation")
			}
			corrupt = record.cloneOwnerReady()
			corrupt.completeIntrinsic = daCompleteCapacitySet{}
			if !daCompleteTestError(checkOwnerReadyRetainedRecordLocked(corrupt), errDARelayImageIncompatible) {
				t.Fatal("legacy zero descriptor was promoted to owner-ready State C")
			}
		})
	}
}

func TestDACompleteCommitCapacity(t *testing.T) {
	f, a, c := daCompleteTestCandidate(t, true, 1, 0)
	p, _ := daCompleteCommitTestPlan(t, f, a, c)
	daCompleteCommitFillCountLimit(f, 65536, 2_000_000) // no C resident is strictly worse
	f.relay.records = math.MaxUint64
	o := f.mp.pendingOutpoints
	beforeSequence, beforeHigh, beforeRecords := f.relay.nextReceivedTime, o.tokenHighWater, f.relay.records
	beforeTarget := f.relay.sets[[32]byte{1}].cloneOwnerReady()
	firstC := f.relay.sets[[32]byte{2}]
	invalidC := firstC
	invalidC.completeIntrinsic.totalBytes++
	f.relay.sets[invalidC.daID] = invalidC
	requireDACompleteImageRefusal(t, f, a, p.result)
	f.relay.sets[firstC.daID] = firstC
	out, rejected, err := f.relay.applyDACompleteCommit(a, p)
	if out != (daRelayAdmissionOutcome{}) || !rejected || err != nil {
		t.Fatal("capacity rejection after Reserve", out, rejected, err)
	}
	if o.tokenHighWater != beforeHigh+1 || o.byToken[PendingOutpointToken{owner: o, seq: beforeHigh + 1}] != nil || f.relay.nextReceivedTime != beforeSequence || f.relay.records != beforeRecords || f.relay.completeCount != 65536 || f.relay.completeBytes != 131072 || f.relay.pinnedPayloadBytes != 65536 || !reflect.DeepEqual(f.relay.sets[[32]byte{1}], beforeTarget) || !reflect.DeepEqual(f.relay.sets[[32]byte{2}], firstC) || len(f.relay.sets) != 65537 {
		t.Fatal("capacity refusal changed DA image, old claims, or sequence")
	}
	if _, found := f.relay.locators[c.member.member.txid]; found || len(p.owner.commit.victims) != 0 || a.guard.state.Load() != daAdmissionResolved {
		t.Fatal("capacity refusal leaked candidate locator or token")
	}
}

func TestDACompleteCommitOwnerOrder(t *testing.T) {
	for _, shape := range []string{"zero txid", "empty inputs", "duplicate inputs"} {
		t.Run("invalid "+shape, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, true, 0, 0)
			p, _ := daCompleteCommitTestPlan(t, f, a, c)
			input := a.snapshot.Inputs[0]
			want := ""
			switch shape {
			case "zero txid":
				a.snapshot.TxID = [32]byte{}
				want = "zero pending-outpoint txid"
			case "empty inputs":
				a.snapshot.Inputs = nil
				want = "empty pending-outpoint input set"
			case "duplicate inputs":
				a.snapshot.Inputs = []consensus.Outpoint{input, input}
				want = fmt.Sprintf("duplicate pending-outpoint input txid=%x vout=%d", input.Txid, input.Vout)
			}
			before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
			out, rejected, err := f.relay.applyDACompleteCommit(a, p)
			if out != (daRelayAdmissionOutcome{}) || rejected || daAdmit(t, err, "unavailable").Message != want || relayDispositionOf(err) != RelayAdmissionInternal || a.guard.state.Load() != daAdmissionOpen {
				t.Fatal("invalid owner request before Reserve", shape, err)
			}
			requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
		})
	}
	for _, name := range []string{"transition", "tip", "generation", "exhaustion", "first input", "selected victim", "capacity conflict"} {
		t.Run(name, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, false, 0, 0)
			p, _ := daCompleteCommitTestPlan(t, f, a, c)
			o := f.mp.pendingOutpoints
			if name == "selected victim" || name == "capacity conflict" {
				fee := uint64(1)
				if name == "capacity conflict" {
					fee = 2_000_000
				}
				daCompleteCommitFillCountLimit(f, 65536, fee)
				if name == "capacity conflict" {
					low := f.relay.sets[[32]byte{2}]
					low.commit.member.fee = consensus.Uint128{Lo: 1}
					low.chunks[0].member.fee = consensus.Uint128{Lo: 1}
					low.completeIntrinsic.fee = consensus.Uint128{Lo: 2}
					f.relay.sets[low.daID] = low
					pressure := f.relay.sets[[32]byte{2, 1}]
					const size = 96_000_000 - 65_535
					// Scalar-only State C pressure isolates owner order; it is not a canonical raw-byte or resource fixture.
					chunk := pressure.chunks[0]
					chunk.txBytes = make([]byte, size)
					chunk.member.fee = consensus.Uint128{Lo: 1_000_000_000_000}
					pressure.chunks[0] = chunk
					pressure.commit.member.fee = chunk.member.fee
					pressure.payloadBytes, pressure.completeIntrinsic.payloadBytes = size, size
					pressure.completeIntrinsic.totalBytes, pressure.completeIntrinsic.fee = 1+size, consensus.Uint128{Lo: 2_000_000_000_000}
					f.relay.sets[pressure.daID] = pressure
					f.relay.completeBytes += size - 1
					f.relay.pinnedPayloadBytes += size - 1
					candidate := p.result.prepared.set
					if low.completeIntrinsic.fee.Lo*candidate.totalBytes >= candidate.fee.Lo*low.completeIntrinsic.totalBytes {
						t.Fatal("conflicting C must be strictly worse than candidate")
					}
					f.relay.mu.Lock()
					in, err := f.relay.capacityInput(p.source, p.result.prepared.set)
					plan, planErr := planDACompleteCapacity(in)
					f.relay.mu.Unlock()
					if err != nil || planErr != nil || plan.accepted || in.completePayload+in.candidate.payloadBytes-1 <= 96_000_000 {
						t.Fatal("low C prefix still cannot fit payload", err, planErr)
					}
				}
				victim := f.relay.sets[[32]byte{2}].commit.member
				claim := o.byToken[victim.token]
				delete(o.byOutpoint, claim.inputs[0])
				claim.inputs[0] = a.snapshot.Inputs[0]
				o.byOutpoint[claim.inputs[0]] = pendingOutpointRow{token: victim.token, txid: victim.txid}
				victim.inputs[0] = claim.inputs[0]
			}
			want, kind := "", TxAdmitErrorKind("unavailable")
			switch name {
			case "transition":
				o.inTransition = true
				o.generation++
				o.tokenHighWater = math.MaxUint64
				want = "pending-outpoint owner transition in progress"
			case "tip":
				o.stableTip.Height++
				o.generation++
				o.tokenHighWater = math.MaxUint64
				want = "pending-outpoint expected tip mismatch"
			case "generation":
				o.generation++
				o.tokenHighWater = math.MaxUint64
				want = "pending-outpoint expected generation mismatch"
			case "exhaustion":
				o.tokenHighWater = math.MaxUint64
				want = "pending-outpoint token sequence exhausted"
			case "selected victim", "capacity conflict":
				want, kind = fmt.Sprintf("mempool double-spend conflict with %x", f.relay.sets[[32]byte{2}].commit.member.txid), "conflict"
			default:
				mustReserve(t, o, [32]byte{81}, a.snapshot.Inputs[1])
				mustReserve(t, o, [32]byte{80}, a.snapshot.Inputs[0])
				want, kind = fmt.Sprintf("mempool double-spend conflict with %x", [32]byte{80}), "conflict"
			}
			before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(o)
			out, rejected, err := f.relay.applyDACompleteCommit(a, p)
			if out != (daRelayAdmissionOutcome{}) || rejected || daAdmit(t, err, kind).Message != want {
				t.Fatal("exact first-input owner-unavailable error tuple", err)
			}
			wantDisposition := RelayAdmissionUnavailable
			if kind == "conflict" {
				wantDisposition = RelayAdmissionConflict
			}
			if relayDispositionOf(err) != wantDisposition {
				t.Fatal("owner error disposition")
			}
			if a.guard.state.Load() != 4 {
				t.Fatal("failed-attempt resolution")
			}
			requireDANonReplayUnchanged(t, f.relay, o, before, owner)
		})
	}
}

func TestDACompleteCommitStale(t *testing.T) {
	for _, field := range []string{"target sequence high", "target revision high", "revision and sequence exhaustion"} {
		t.Run(field, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, true, 0, 0)
			s := daCompleteTestCapture(t, f, c)
			result, err := daCompleteTestPrepare(t, f, a, s)
			if err != nil {
				t.Fatal(err)
			}
			if field == "target sequence high" {
				f.relay.nextReceivedTime = s.prior.receivedTime - 1
			}
			if field != "target sequence high" {
				f.relay.records = s.prior.revision - 1
			}
			if field == "revision and sequence exhaustion" {
				f.relay.nextReceivedTime = math.MaxUint64
			}
			requireDACompleteImageRefusal(t, f, a, result)
		})
	}
	t.Run("matching sequence before invalid resident", func(t *testing.T) {
		f, a, c := daCompleteTestCandidate(t, true, 0, 1)
		p, _ := daCompleteCommitTestPlan(t, f, a, c)
		f.relay.nextReceivedTime = math.MaxUint64
		resident := f.relay.sets[[32]byte{11}]
		resident.completeIntrinsic.totalBytes++
		f.relay.sets[resident.daID] = resident
		before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
		out, rejected, err := f.relay.applyDACompleteCommit(a, p)
		if out != (daRelayAdmissionOutcome{}) || rejected || !daCompleteTestError(err, errDARelayArithmeticOverflow) || a.guard.state.Load() != daAdmissionOpen {
			t.Fatal("matching sequence must precede resident scan", err)
		}
		requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
	})
	t.Run("last usable accepted sequence", func(t *testing.T) {
		f, a, c := daCompleteTestCandidate(t, true, 0, 0)
		p, _ := daCompleteCommitTestPlan(t, f, a, c)
		f.relay.nextReceivedTime = math.MaxUint64 - 1
		beforeRecords, beforeHigh := f.relay.records, f.mp.pendingOutpoints.tokenHighWater
		daCompleteCommitTestApply(t, f, a, p)
		if f.relay.nextReceivedTime != math.MaxUint64 || f.relay.records != beforeRecords+1 || f.relay.sets[[32]byte{1}].receivedTime != 1 || f.mp.pendingOutpoints.tokenHighWater != beforeHigh+1 {
			t.Fatal("last accepted value or first received sequence")
		}
	})
	for _, field := range []string{"daID", "state", "revision", "receivedTime", "payloadBytes", "wireBytes", "replaceable nilness", "replaceable contents", "commit metadata", "chunk metadata", "member token", "member inputs", "member raw", "mempool", "owner", "locator", "extra locator"} {
		t.Run("target "+field, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, true, 0, 0)
			p, _ := daCompleteCommitTestPlan(t, f, a, c)
			r := f.relay.sets[[32]byte{1}].cloneOwnerReady()
			switch field {
			case "daID":
				r.daID[0]++
			case "state":
				r.state = 1
			case "revision":
				r.revision++
			case "receivedTime":
				r.receivedTime++
			case "payloadBytes":
				r.payloadBytes++
			case "wireBytes":
				r.wireBytes++
			case "replaceable nilness":
				r.replaceableChunks = map[uint16]bool{}
			case "replaceable contents":
				r.replaceableChunks = map[uint16]bool{3: true}
			case "commit metadata":
				r.commit.chunkCount++
			case "chunk metadata":
				ch := r.chunks[0]
				ch.chunkHash[0]++
				r.chunks[0] = ch
			case "member token":
				r.chunks[0].member.token.seq++
			case "member inputs":
				r.chunks[0].member.inputs[0].Vout++
			case "member raw":
				r.chunks[0].txBytes[0]++
			case "mempool":
				f.relay.mempool = &Mempool{pendingOutpoints: f.mp.pendingOutpoints}
			case "owner":
				f.mp.pendingOutpoints = &PendingOutpointOwner{}
			case "locator":
				delete(f.relay.locators, r.chunks[0].member.txid)
			case "extra locator":
				f.relay.locators[[32]byte{99}] = daRelayLocator{daID: [32]byte{1}, kind: daRelayLocatorChunk}
			}
			f.relay.sets[[32]byte{1}] = r
			o := a.guard.owner
			before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(o)
			out, rejected, err := f.relay.applyDACompleteCommit(a, p)
			if out != (daRelayAdmissionOutcome{}) || rejected || daAdmit(t, err, "unavailable").Message != "retained DA record moved while this admission was planned" {
				t.Fatal("target drift before Reserve", field, err)
			}
			requireDANonReplayUnchanged(t, f.relay, o, before, owner)
		})
	}
	for _, field := range []string{"complete", "complete count", "payload", "staged", "commit overhead"} {
		t.Run("live counter "+field, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, true, 1, 1)
			p, _ := daCompleteCommitTestPlan(t, f, a, c)
			switch field {
			case "complete":
				f.relay.completeBytes++
			case "complete count":
				f.relay.completeCount++
			case "payload":
				f.relay.pinnedPayloadBytes++
			case "staged":
				f.relay.stagedBytes++
			case "commit overhead":
				f.relay.orphanCommitOverheadBytes++
			}
			requireDACompleteImageRefusal(t, f, a, p.result)
		})
	}
	for _, field := range []string{"survivor token", "survivor input", "baseline before survivor", "victim before baseline"} {
		t.Run(field, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, true, 1, 0)
			p, _ := daCompleteCommitTestPlan(t, f, a, c)
			o := f.mp.pendingOutpoints
			member := f.relay.sets[[32]byte{1}].chunks[0].member
			want := "DA victim claim mismatch"
			if field == "survivor input" || field == "baseline before survivor" {
				delete(o.byOutpoint, member.inputs[0])
				want = "DA victim input mismatch"
			} else if field == "victim before baseline" {
				member = f.relay.sets[[32]byte{1}].chunks[3].member
				o.byToken[member.token].finalized = false
			} else {
				o.byToken[member.token].finalized = false
			}
			if field == "baseline before survivor" || field == "victim before baseline" {
				f.relay.records++
			}
			before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(o)
			out, rejected, err := f.relay.applyDACompleteCommit(a, p)
			if out != (daRelayAdmissionOutcome{}) || rejected || daAdmit(t, err, "unavailable").Message != want {
				t.Fatal("live target claims after Reserve", field, err)
			}
			owner.tokenHighWater++
			requireDANonReplayUnchanged(t, f.relay, o, before, owner)
		})
	}
	for _, field := range []string{"C survivor intrinsic", "C survivor payload nilness", "C survivor token", "C survivor input", "C victim claim before baseline", "C victim input"} {
		t.Run(field, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, true, 0, 2)
			if field == "C victim claim before baseline" || field == "C victim input" {
				f, a, c, _ = daCompleteCommitPhysicalVictims(t, 1)
			}
			p, _ := daCompleteCommitTestPlan(t, f, a, c)
			id := [32]byte{11}
			r := f.relay.sets[id].cloneOwnerReady()
			o := f.mp.pendingOutpoints
			switch field {
			case "C survivor intrinsic":
				r.completeIntrinsic.totalBytes++
			case "C survivor payload nilness":
				ch := r.chunks[0]
				ch.payload = []byte{}
				r.chunks[0] = ch
			case "C survivor token", "C victim claim before baseline":
				o.byToken[r.commit.member.token].finalized = false
			case "C survivor input", "C victim input":
				delete(o.byOutpoint, r.chunks[0].member.inputs[0])
			}
			if field == "C victim claim before baseline" {
				f.relay.records++
			}
			f.relay.sets[id] = r
			before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(o)
			out, rejected, err := f.relay.applyDACompleteCommit(a, p)
			if field == "C survivor intrinsic" || field == "C survivor payload nilness" {
				if out != (daRelayAdmissionOutcome{}) || rejected || !daCompleteTestError(err, errDARelayImageIncompatible) {
					t.Fatal("resident descriptor before Reserve", err)
				}
			} else {
				want := "DA victim claim mismatch"
				if field == "C survivor input" || field == "C victim input" {
					want = "DA victim input mismatch"
				}
				if out != (daRelayAdmissionOutcome{}) || rejected || daAdmit(t, err, "unavailable").Message != want {
					t.Fatal("C survivor claim after Reserve", err)
				}
				owner.tokenHighWater++
			}
			requireDANonReplayUnchanged(t, f.relay, o, before, owner)
		})
	}
	for _, field := range []string{"records", "sequence"} {
		t.Run("live "+field, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, true, 0, 0)
			p, _ := daCompleteCommitTestPlan(t, f, a, c)
			if field == "records" {
				f.relay.records++
			} else {
				f.relay.nextReceivedTime++
			}
			rev, seq := f.relay.records, f.relay.nextReceivedTime
			daCompleteCommitTestApply(t, f, a, p)
			if f.relay.records != rev+1 || f.relay.nextReceivedTime != seq+1 {
				t.Fatal("completion did not use current revision and sequence")
			}
		})
	}
}
func daCompleteCommitPhysicalVictims(t *testing.T, count int) (*daNonReplayFixture, *DAAdmission, daRelayAdmissionCandidate, []daRelaySetRecord) {
	t.Helper()
	f := newDANonReplayFixture(t, 12)
	var residents []daRelaySetRecord
	var total uint64
	for i := 0; i < count; i++ {
		id := [32]byte{byte(11 + i)}
		f.completeReplayPinned(id)
		r := f.relay.sets[id]
		r.wireBytes = 0
		f.relay.sets[id] = r
		residents = append(residents, r)
		total += uint64(len(r.commit.txBytes) + len(r.chunks[0].txBytes))
	}
	f.relay.completeBytes, f.relay.completeCount = total, uint64(count)
	chunk := f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{1}, payload: []byte("complete payload"), inputCount: 2, fee: consensus.Uint128{Lo: 1500000}})
	f.admit(chunk, LocalDAProvenance())
	last := f.signed(daNonReplayTxSpec{kind: 1, daID: [32]byte{1}, chunkCount: 1, commitment: sha3.Sum256(chunk.spec.payload), commitmentOutputs: 1, fee: consensus.Uint128{Lo: 1500000}})
	a := f.begin(last)
	t.Cleanup(a.Close)
	c, err := a.renderDARelayAdmissionCandidate(LocalDAProvenance())
	if err != nil {
		t.Fatal(err)
	}
	daCompleteCommitFillCountLimit(f, 65536-count, 3_000_000)
	return f, a, c, residents
}

func daCompleteCommitMismatchFixture(t *testing.T, commitLast bool) (*daNonReplayFixture, *DAAdmission, daRelayAdmissionCandidate) {
	t.Helper()
	f := newDANonReplayFixture(t, 10)
	commit := f.signed(daNonReplayTxSpec{kind: 1, daID: [32]byte{1}, chunkCount: 1, commitment: [32]byte{99}, commitmentOutputs: 1})
	chunk := f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{1}, payload: []byte("complete payload")})
	last := chunk
	if commitLast {
		f.admit(chunk, daNonReplayPeer("retained"))
		f.admit(f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{1}, chunkIndex: 3, payload: []byte{9}}), LocalDAProvenance())
		last = commit
	} else {
		f.admit(commit, DetachedReorgDAProvenance())
	}
	a := f.begin(last)
	t.Cleanup(a.Close)
	c, err := a.renderDARelayAdmissionCandidate(LocalDAProvenance())
	if err != nil {
		t.Fatal(err)
	}
	return f, a, c
}

func TestDACompleteCommitMismatch(t *testing.T) {
	f, a, c := daCompleteCommitMismatchFixture(t, true)
	before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	p, _ := daCompleteCommitTestPlan(t, f, a, c)
	daCompleteCommitTestApply(t, f, a, p)
	got := daRelayStateSnapshot(f.relay)
	r := got.sets[[32]byte{1}]
	if r.state != 1 || r.completeIntrinsic != (daCompleteCapacitySet{}) || len(r.chunks) != 0 || len(got.locators) != 1 || got.locators[a.snapshot.TxID] != c.member.locator {
		t.Fatal("exact removed-set includes in-range and out-of-range")
	}
	if got.stagedBytes != uint64(len(a.snapshot.TxBytes)) || got.commitBytes != uint64(len(a.snapshot.TxBytes)) || got.orphanBytes != 0 || len(got.peerBytes) != 0 || len(got.daIDBytes) != 0 || got.completeBytes != 0 || got.completeCount != 0 || got.pinnedPayloadBytes != 0 {
		t.Fatal("commit-only B charges")
	}
	if r.ttlBlocksRemaining != 7 || r.receivedTime != before.sets[[32]byte{1}].receivedTime || got.nextReceivedTime != before.nextReceivedTime+1 || got.records != before.records+1 {
		t.Fatal("mismatch TTL sequence revision")
	}
	current := cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	for token, claim := range owner.byToken {
		if current.byToken[token] != nil {
			t.Fatal("all mismatching claims removed")
		}
		for _, op := range claim.inputs {
			if _, ok := current.byOutpoint[op]; ok {
				t.Fatal("all mismatching input rows removed")
			}
		}
	}
	if len(current.byToken) != 1 || !current.byToken[r.commit.member.token].finalized {
		t.Fatal("mismatch candidate finalized")
	}
	f, a, c = daCompleteCommitMismatchFixture(t, false)
	f.relay.nextReceivedTime = math.MaxUint64
	s := daCompleteTestCapture(t, f, c)
	result, err := prepareDACompleteSnapshot(s, daRelayAdmissionOutcome{})
	if err != nil {
		t.Fatal(err)
	}
	before, owner = daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	plan, err := f.relay.prepareDACompleteCommit(a, result)
	if plan != nil || !daCompleteTestError(err, ErrDARelayPayloadCommitmentMismatch) || a.guard.state.Load() != 0 {
		t.Fatal("chunk mismatch without reserve or sequence")
	}
	requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
	t.Run("chunk-last retained sibling", func(t *testing.T) {
		f := newDANonReplayFixture(t, 4)
		id := [32]byte{42}
		commit := f.signed(daNonReplayTxSpec{kind: 1, daID: id, chunkCount: 2, commitment: [32]byte{99}, commitmentOutputs: 1})
		f.admit(commit, LocalDAProvenance())
		first := f.signed(daNonReplayTxSpec{kind: 2, daID: id, payload: []byte{1}})
		f.admit(first, LocalDAProvenance())
		last := f.signed(daNonReplayTxSpec{kind: 2, daID: id, chunkIndex: 1, payload: []byte{2}})
		a := f.begin(last)
		defer a.Close()
		candidate, err := a.renderDARelayAdmissionCandidate(LocalDAProvenance())
		if err != nil {
			t.Fatal(err)
		}
		source := daCompleteTestCapture(t, f, candidate)
		f.relay.nextReceivedTime = math.MaxUint64
		before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
		result, err := prepareDACompleteSnapshot(source, daRelayAdmissionOutcome{})
		if err != nil || result.mismatch == nil || result.prepared != nil || !reflect.DeepEqual(result.mismatch.image.next, source.prior) || len(result.mismatch.image.next.chunks) != 1 {
			t.Fatal("chunk-last mismatch must retain first chunk", err)
		}
		plan, err := f.relay.prepareDACompleteCommit(a, result)
		if plan != nil || !daCompleteTestError(err, ErrDARelayPayloadCommitmentMismatch) || a.guard.state.Load() != daAdmissionOpen {
			t.Fatal("chunk-last rejection before sequence and Reserve", err)
		}
		requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
		if !reflect.DeepEqual(f.relay.sets[id], before.sets[id]) || f.relay.locators[first.txid] != before.locators[first.txid] {
			t.Fatal("retained B sibling changed on chunk-last mismatch")
		}
	})
}

func TestDACompleteCommitMismatchOrder(t *testing.T) {
	for _, field := range []string{"DA-ID counter", "peer counter", "shared sum"} {
		t.Run("preflight "+field, func(t *testing.T) {
			f, a, c := daCompleteCommitMismatchFixture(t, true)
			p, _ := daCompleteCommitTestPlan(t, f, a, c)
			s, o := f.relay, f.mp.pendingOutpoints
			switch field {
			case "DA-ID counter":
				delete(s.orphanBytesByDAID, [32]byte{1})
			case "peer counter":
				delete(s.orphanBytesByPeerQuotaKey, "retained")
			case "shared sum":
				s.completeBytes = math.MaxUint64
			}
			o.inTransition = true // owner refusal would win if arithmetic were deferred past preflight
			before, owner := daRelayStateSnapshot(s), cloneDAAdmissionOwner(o)
			out, rejected, err := s.applyDACompleteCommit(a, p)
			if out != (daRelayAdmissionOutcome{}) || rejected || !daCompleteTestError(err, errDARelayArithmeticOverflow) || a.guard.state.Load() != daAdmissionOpen {
				t.Fatal("mismatch preflight must precede Reserve", field, err)
			}
			requireDANonReplayUnchanged(t, s, o, before, owner)
		})
	}
	for _, name := range []string{"stale A", "owner", "conflict", "post reserve", "shared", "commit", "sequence"} {
		t.Run(name, func(t *testing.T) {
			f, a, c := daCompleteCommitMismatchFixture(t, true)
			f.relay.nextReceivedTime = math.MaxUint64
			f.relay.caps.orphanCommitOverheadBytes = 1
			f.relay.stagedBytes = 536870912
			if name == "commit" || name == "sequence" {
				f.relay.stagedBytes = 0
			}
			if name == "sequence" {
				f.relay.caps.orphanCommitOverheadBytes = 8388608
			}
			p, _ := daCompleteCommitTestPlan(t, f, a, c)
			o := f.mp.pendingOutpoints
			want, reserve := "", true
			kind := TxAdmitErrorKind("unavailable")
			switch name {
			case "stale A":
				r := f.relay.sets[[32]byte{1}]
				r.ttlBlocksRemaining--
				f.relay.sets[r.daID] = r
				o.inTransition = true
				want, reserve = "retained DA record moved while this admission was planned", false
			case "owner":
				o.inTransition = true
				want, reserve = "pending-outpoint owner transition in progress", false
			case "conflict":
				mustReserve(t, o, [32]byte{80}, a.snapshot.Inputs[0])
				want, reserve, kind = fmt.Sprintf("mempool double-spend conflict with %x", [32]byte{80}), false, "conflict"
			case "post reserve":
				member := f.relay.sets[[32]byte{1}].chunks[0].member
				o.byToken[member.token].finalized = false
				want = "DA victim claim mismatch"
			}
			before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(o)
			out, rejected, err := f.relay.applyDACompleteCommit(a, p)
			if out != (daRelayAdmissionOutcome{}) || rejected {
				t.Fatal("mismatch error tuple")
			}
			if want != "" {
				if daAdmit(t, err, kind).Message != want {
					t.Fatal("mismatch error order", err)
				}
			} else {
				wantError := map[string]error{"shared": errDARelayOrphanPoolCapExceeded, "commit": errDARelayOrphanCommitCapExceeded, "sequence": errDARelayArithmeticOverflow}[name]
				if !daCompleteTestError(err, wantError) {
					t.Fatal("shared then commit then sequence", err)
				}
			}
			if reserve {
				owner.tokenHighWater++
			}
			requireDANonReplayUnchanged(t, f.relay, o, before, owner)
			if name == "stale A" {
				requireDACompleteCommitReplayRejected(t, f, a, p, before, owner, 0)
			}
		})
	}
}

func TestDACompleteCommitLifecycle(t *testing.T) {
	for _, final := range []bool{false, true} {
		f, a, c := daCompleteTestCandidate(t, true, 0, 0)
		var p *daCompleteCommitPlan
		if final {
			p, _ = daCompleteCommitTestPlan(t, f, a, c)
			target := f.relay.sets[[32]byte{1}]
			target.revision++
			f.relay.sets[target.daID] = target
		}
		f.relay.locators[c.member.member.txid] = c.member.locator
		if !final {
			source, duplicate, err := f.relay.captureDACompleteSnapshot(c)
			if err != nil {
				t.Fatal(err)
			}
			result, err := prepareDACompleteSnapshot(source, duplicate)
			if err != nil {
				t.Fatal(err)
			}
			p, err = f.relay.prepareDACompleteCommit(a, result)
			if err != nil {
				t.Fatal(err)
			}
		}
		before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
		out, rejected, err := f.relay.applyDACompleteCommit(a, p)
		if err != nil || rejected || out != (daRelayAdmissionOutcome{daID: [32]byte{1}, disposition: 2}) || a.guard.state.Load() != 0 {
			t.Fatal("duplicate leaves OPEN no CAS")
		}
		_ = a.Snapshot()
		requireDACompleteCommitReplayRejected(t, f, a, p, before, owner, 0)
	}
	f, a, c := daCompleteTestCandidate(t, true, 0, 0)
	p, _ := daCompleteCommitTestPlan(t, f, a, c)
	if !reflect.DeepEqual(a.Snapshot(), a.snapshot) {
		t.Fatal("OPEN preparation snapshot")
	}
	daCompleteCommitTestApply(t, f, a, p)
	if a.guard.state.Load() != 4 || p.owner.commit.guard != a.guard {
		t.Fatal("original admission guard consumed")
	}
	before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	requireDACompleteCommitReplayRejected(t, f, a, p, before, owner, 4)
	f, a, c = daCompleteTestCandidate(t, true, 0, 0)
	p, _ = daCompleteCommitTestPlan(t, f, a, c)
	o := f.mp.pendingOutpoints
	o.inTransition = true
	before, owner = daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(o)
	out, rejected, err := f.relay.applyDACompleteCommit(a, p)
	if out != (daRelayAdmissionOutcome{}) || rejected || daAdmit(t, err, "unavailable").Message != "pending-outpoint owner transition in progress" {
		t.Fatal("owner refusal lifecycle", err)
	}
	if a.guard.state.Load() != 4 || o.tokenHighWater != owner.tokenHighWater || len(o.byToken) != len(owner.byToken) {
		t.Fatal("failed attempt resolved without candidate claim")
	}
	requireDANonReplayUnchanged(t, f.relay, o, before, owner)
}

func TestDACompleteCommitPreparation(t *testing.T) {
	for _, shape := range []string{"missing candidate chunk", "nil completing chunk", "nil surviving commit", "nil mismatch commit"} {
		t.Run(shape, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, false, 0, 0)
			if shape == "nil mismatch commit" {
				f, a, c = daCompleteCommitMismatchFixture(t, true)
			}
			s := daCompleteTestCapture(t, f, c)
			result, err := prepareDACompleteSnapshot(s, daRelayAdmissionOutcome{})
			if err != nil {
				t.Fatal(err)
			}
			if result.prepared != nil {
				switch shape {
				case "missing candidate chunk":
					delete(result.prepared.image.next.chunks, c.member.locator.chunkIndex)
				case "nil completing chunk":
					ch := result.prepared.image.next.chunks[c.member.locator.chunkIndex]
					ch.member = nil
					result.prepared.image.next.chunks[c.member.locator.chunkIndex] = ch
				case "nil surviving commit":
					result.prepared.image.next.commit.member = nil
				}
			} else {
				result.mismatch.image.next.commit.member = nil
			}
			requireDACompleteImageRefusal(t, f, a, result)
		})
	}
	for _, name := range []string{"missing", "invalid duplicate", "duplicate prepared", "duplicate mismatch", "prepared mismatch", "all variants", "nil source", "image", "set", "txid", "wtxid", "bytes", "fee", "inputs", "owner"} {
		t.Run(name, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, false, 0, 0)
			s := daCompleteTestCapture(t, f, c)
			result, err := prepareDACompleteSnapshot(s, daRelayAdmissionOutcome{})
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "missing":
				result = daCompletePreparation{}
			case "invalid duplicate":
				result = daCompletePreparation{duplicate: &daRelayAdmissionOutcome{disposition: 1}}
			case "duplicate prepared":
				result.duplicate = &daRelayAdmissionOutcome{disposition: 2}
			case "duplicate mismatch":
				result = daCompletePreparation{duplicate: &daRelayAdmissionOutcome{disposition: 2}, mismatch: &daCompleteMismatch{}}
			case "prepared mismatch":
				result.mismatch = &daCompleteMismatch{}
			case "all variants":
				result.duplicate = &daRelayAdmissionOutcome{disposition: 2}
				result.mismatch = &daCompleteMismatch{}
			case "nil source":
				result.prepared.source = nil
			case "image":
				result.prepared.image.next.state = 1
			case "set":
				result.prepared.set.totalBytes++
			case "txid":
				s.candidate.member.member.txid[0]++
			case "wtxid":
				s.candidate.member.member.wtxid[0]++
			case "bytes":
				s.candidate.member.txBytes[0]++
			case "fee":
				s.candidate.member.member.fee.Lo++
			case "inputs":
				slices.Reverse(s.candidate.member.member.inputs)
			case "owner":
				s.owner = &PendingOutpointOwner{}
			}
			before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
			p, err := f.relay.prepareDACompleteCommit(a, result)
			if p != nil || !daCompleteTestError(err, errDARelayImageIncompatible) || a.guard.state.Load() != daAdmissionOpen {
				t.Fatal("closed preparation shape", name, err)
			}
			requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
		})
	}
	f, a, c := daCompleteTestCandidate(t, true, 1, 0)
	p, result := daCompleteCommitTestPlan(t, f, a, c)
	result.prepared.image.next.commit.txBytes[0] ^= 1
	result.prepared.image.next.commit.member.inputs[0].Vout++
	wantRaw, wantInputs := slices.Clone(a.snapshot.TxBytes), slices.Clone(a.snapshot.Inputs)
	daCompleteCommitTestApply(t, f, a, p)
	record := f.relay.sets[[32]byte{1}]
	if !bytes.Equal(record.commit.txBytes, wantRaw) || !slices.Equal(record.commit.member.inputs, wantInputs) {
		t.Fatal("prepared candidate aliased caller result")
	}
	for _, name := range []string{"nil source", "kind zero", "kind other", "wrong role", "missing image"} {
		f, a, c := daCompleteCommitMismatchFixture(t, true)
		s := daCompleteTestCapture(t, f, c)
		result, err := prepareDACompleteSnapshot(s, daRelayAdmissionOutcome{})
		if err != nil {
			t.Fatal(err)
		}
		switch name {
		case "nil source":
			result.mismatch.source = nil
		case "kind zero":
			result.mismatch.kind = 0
		case "kind other":
			result.mismatch.kind = 99
		case "wrong role":
			result.mismatch.kind = 2
		case "missing image":
			result.mismatch.image = daRelayRecordImage{}
		}
		if p, err := f.relay.prepareDACompleteCommit(a, result); p != nil || !daCompleteTestError(err, errDARelayImageIncompatible) {
			t.Fatal("closed mismatch shape", name, err)
		}
	}
	f, a, c = daCompleteTestCandidate(t, false, 0, 0)
	p, _ = daCompleteCommitTestPlan(t, f, a, c)
	f.relay.records = math.MaxUint64
	before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	out, rejected, err := f.relay.applyDACompleteCommit(a, p)
	if out != (daRelayAdmissionOutcome{}) || rejected || !daCompleteTestError(err, errDARelayArithmeticOverflow) {
		t.Fatal("current revision exhaustion before Reserve", err)
	}
	requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
}

func TestDACompleteCommitVictims(t *testing.T) {
	for _, count := range []int{1, 2, 65} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			set := daCompleteCapacitySet{id: [32]byte{1}, fee: consensus.Uint128{Lo: 1_200_000}, totalBytes: 256, payloadBytes: 16, receivedSequence: 1}
			input := daCompleteCapacityInput{byteCap: 536870912, stagedBytes: 536870912 - set.totalBytes - 1, candidate: set, completeBytes: uint64(2 * count), completeCount: uint64(count), completePayload: uint64(count)}
			var ids [][32]byte
			for i := 0; i < count; i++ {
				id := [32]byte{2, byte(i)}
				ids = append(ids, id)
				input.residents = append(input.residents, daCompleteCapacitySet{id: id, fee: consensus.Uint128{Lo: 2}, totalBytes: 2, payloadBytes: 1, receivedSequence: 1})
			}
			plan, err := planDACompleteCapacity(input)
			if err != nil || !plan.accepted || !slices.Equal(plan.victims, ids) || plan.completeCount != 1 || plan.payloadBytes != set.payloadBytes || plan.sharedBytes != input.stagedBytes+set.totalBytes {
				t.Fatal("exact minimal C victim prefix", count, plan, err)
			}
		})
	}
}

func TestDACompleteCommitUnrelatedState(t *testing.T) {
	for _, operation := range []string{"preserve", "insert A", "insert B", "delete A", "delete B", "replace A", "replace B", "TTL A", "TTL B", "locator"} {
		t.Run(operation, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, true, 0, 0)
			x := f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{40}, payload: []byte{1}})
			y := f.signed(daNonReplayTxSpec{kind: 1, daID: [32]byte{41}, chunkCount: 2, commitment: [32]byte{8}, commitmentOutputs: 1})
			f.admit(x, daNonReplayPeer("other"))
			f.admit(y, LocalDAProvenance())
			p, _ := daCompleteCommitTestPlan(t, f, a, c)
			id := x.spec.daID
			if strings.HasSuffix(operation, "B") {
				id = y.spec.daID
			}
			switch {
			case operation == "insert A":
				f.admit(f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{42}, payload: []byte{2}}), LocalDAProvenance())
			case operation == "insert B":
				f.admit(f.signed(daNonReplayTxSpec{kind: 1, daID: [32]byte{43}, chunkCount: 2, commitment: [32]byte{9}, commitmentOutputs: 1}), LocalDAProvenance())
			case strings.HasPrefix(operation, "delete"):
				r := f.relay.sets[id]
				f.relay.mu.Lock()
				victims, err := f.relay.removeOwnerReadyWholeRecordLocked(r)
				f.relay.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				o := f.mp.pendingOutpoints
				o.mu.Lock()
				for _, victim := range victims {
					o.dropClaimLocked(victim.Token)
				}
				o.mu.Unlock()
			case strings.HasPrefix(operation, "replace"):
				r := f.relay.sets[id].cloneOwnerReady()
				f.relay.records++
				r.revision = f.relay.records
				f.relay.sets[id] = r
			case strings.HasPrefix(operation, "TTL"):
				r := f.relay.sets[id]
				r.ttlBlocksRemaining--
				f.relay.sets[id] = r
			case operation == "locator":
				delete(f.relay.locators, x.txid)
			}
			f.relay.prefetch.indexes = map[[32]byte]map[uint16]string{{1}: {0: "candidate"}, {40}: {0: "live"}}
			f.relay.prefetch.expires = map[[32]byte]time.Time{{1}: time.Unix(3, 0), {40}: time.Unix(4, 0)}
			f.relay.rejectCache.entries = map[[32]byte]struct{}{{99}: {}}
			before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
			oldCharge, err := f.relay.sets[[32]byte{1}].ownerReadyAccounting()
			if err != nil {
				t.Fatal(err)
			}
			daCompleteCommitTestApply(t, f, a, p)
			got := daRelayStateSnapshot(f.relay)
			for key, record := range before.sets {
				if key != ([32]byte{1}) && !reflect.DeepEqual(got.sets[key], record) {
					t.Fatal("unrelated live record overwritten", operation, key)
				}
			}
			for txid, locator := range before.locators {
				if locator.daID != ([32]byte{1}) && got.locators[txid] != locator {
					t.Fatal("unrelated locator overwritten", operation, txid)
				}
			}
			if got.stagedBytes != before.stagedBytes || got.commitBytes != before.commitBytes || got.orphanBytes != before.orphanBytes-oldCharge.orphanBytes || got.peerBytes["other"] != before.peerBytes["other"] || got.daIDBytes[x.spec.daID] != before.daIDBytes[x.spec.daID] {
				t.Fatal("unrelated live counter overwritten", operation)
			}
			for token, claim := range owner.byToken {
				if !reflect.DeepEqual(f.mp.pendingOutpoints.byToken[token], claim) {
					t.Fatal("unrelated or surviving claim changed", operation)
				}
			}
			if !reflect.DeepEqual(got.prefetchIndexes, map[[32]byte]map[uint16]string{{40}: {0: "live"}}) || !reflect.DeepEqual(got.prefetchExpires, map[[32]byte]time.Time{{40}: time.Unix(4, 0)}) || !maps.Equal(f.relay.rejectCache.entries, map[[32]byte]struct{}{{99}: {}}) {
				t.Fatal("unrelated prefetch or reject cache changed", operation)
			}
		})
	}
}

func TestDACompleteLiveCapacity(t *testing.T) {
	t.Run("C removed between holds", func(t *testing.T) {
		f, a, c := daCompleteTestCandidate(t, true, 0, 0)
		id := [32]byte{11}
		f.completeReplayPinned(id)
		p, _ := daCompleteCommitTestPlan(t, f, a, c)
		r := f.relay.sets[id]
		for _, row := range r.locatorRows() {
			member := r.commit.member
			if row.locator.kind == daRelayLocatorChunk {
				member = r.chunks[row.locator.chunkIndex].member
			}
			f.mp.pendingOutpoints.dropClaimLocked(member.token)
			delete(f.relay.locators, row.txid)
		}
		delete(f.relay.sets, id)
		f.relay.completeBytes -= r.completeIntrinsic.totalBytes
		f.relay.completeCount--
		f.relay.pinnedPayloadBytes -= r.completeIntrinsic.payloadBytes
		daCompleteCommitTestApply(t, f, a, p)
		if f.relay.completeCount != 1 || len(p.capacity.victims) != 0 || f.relay.completeBytes != p.result.prepared.set.totalBytes || f.relay.pinnedPayloadBytes != 16 {
			t.Fatal("final plan used removed C resident")
		}
	})
	f, a, c := daCompleteTestCandidate(t, false, 0, 0)
	p, _ := daCompleteCommitTestPlan(t, f, a, c)
	x := f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{40}, payload: []byte{1}})
	y := f.signed(daNonReplayTxSpec{kind: 1, daID: [32]byte{41}, chunkCount: 2, commitment: [32]byte{8}, commitmentOutputs: 1})
	f.admit(x, LocalDAProvenance())
	f.admit(y, LocalDAProvenance())
	f.completeReplayPinned([32]byte{42})
	before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	daCompleteCommitTestApply(t, f, a, p)
	got := daRelayStateSnapshot(f.relay)
	if !reflect.DeepEqual(got.sets[x.spec.daID], before.sets[x.spec.daID]) || !reflect.DeepEqual(got.sets[y.spec.daID], before.sets[y.spec.daID]) || !reflect.DeepEqual(got.sets[[32]byte{42}], before.sets[[32]byte{42}]) || got.locators[x.txid] != before.locators[x.txid] || got.locators[y.txid] != before.locators[y.txid] {
		t.Fatal("live A/B/C state overwritten by first-lock image")
	}
	if got.stagedBytes != before.stagedBytes-uint64(len(before.sets[[32]byte{1}].commit.txBytes)) || got.completeCount != before.completeCount+1 || got.records != before.records+1 || got.nextReceivedTime != before.nextReceivedTime+1 {
		t.Fatal("final DA hold ignored live accounting or sequence")
	}
	for token, claim := range owner.byToken {
		if !reflect.DeepEqual(f.mp.pendingOutpoints.byToken[token], claim) {
			t.Fatal("live unrelated claim changed")
		}
	}
}

func TestDACompleteSparsePublication(t *testing.T) {
	t.Run("preflight failure", func(t *testing.T) {
		f, a, c := daCompleteTestCandidate(t, false, 0, 0)
		p, _ := daCompleteCommitTestPlan(t, f, a, c)
		f.relay.orphanBytesByPeerQuotaKey = nil
		requireDACompleteImageRefusal(t, f, a, p.result)
	})
	for _, shape := range []string{"full", "tombstone"} {
		for _, refusal := range []string{"owner", "post reserve claim", "guard CAS"} {
			t.Run(shape+" "+refusal, func(t *testing.T) {
				f, a, c := daCompleteTestCandidate(t, true, 0, 0)
				p, _ := daCompleteCommitTestPlan(t, f, a, c)
				s, o := f.relay, f.mp.pendingOutpoints
				s.mu.Lock()
				if err := p.prepareEffects(s, a); err != nil {
					s.mu.Unlock()
					t.Fatal(err)
				}
				// Populate before deletion: Go 1.26 small maps cannot retain tombstones.
				daCompleteCommitLocatorHistory(s, shape == "tombstone")
				for i := byte(60); i < 67; i++ {
					id := [32]byte{i}
					s.sets[id] = daRelaySetRecord{daID: id, state: daRelayStateOrphanChunks}
					s.orphanBytesByDAID[id] = 1
					s.orphanBytesByPeerQuotaKey[fmt.Sprint(i)] = 1
				}
				beforeLocators := maps.Clone(s.locators)
				beforeSets, beforeDAID, beforePeer := maps.Clone(s.sets), maps.Clone(s.orphanBytesByDAID), maps.Clone(s.orphanBytesByPeerQuotaKey)
				beforeRecord := s.sets[[32]byte{1}].cloneOwnerReady()
				beforeSequence, beforeRevision, beforeHigh := s.nextReceivedTime, s.records, o.tokenHighWater
				beforeCounters := [6]uint64{s.stagedBytes, s.orphanBytes, s.orphanCommitOverheadBytes, s.completeBytes, s.completeCount, s.pinnedPayloadBytes}
				if err := s.preflightDACompleteCommit(p); err != nil {
					s.mu.Unlock()
					t.Fatal(err)
				}
				if s.locators[c.member.member.txid] != c.member.locator {
					s.mu.Unlock()
					t.Fatal("missing provisional locator")
				}
				switch refusal {
				case "owner":
					o.inTransition = true
				case "guard CAS":
					a.guard.state.Store(daAdmissionResolved)
				default:
					member := s.sets[[32]byte{1}].chunks[0].member
					o.byToken[member.token].finalized = false
				}
				beforeOwner := cloneDAAdmissionOwner(o)
				out, rejected, err := s.reserveDACompleteCommit(a, p) // releases DA on every refusal
				want, high := "pending-outpoint owner transition in progress", beforeHigh
				if refusal == "post reserve claim" {
					want, high = "DA victim claim mismatch", beforeHigh+1
				}
				exactError := (refusal == "guard CAS" && daCompleteTestError(err, errDARelayImageIncompatible)) ||
					(refusal != "guard CAS" && daAdmit(t, err, "unavailable").Message == want)
				if out != (daRelayAdmissionOutcome{}) || rejected || !exactError || o.tokenHighWater != high || s.nextReceivedTime != beforeSequence || s.records != beforeRevision || a.guard.state.Load() != daAdmissionResolved {
					t.Fatal("post-provisional refusal tuple and high-water", shape, refusal, err)
				}
				if !maps.Equal(s.locators, beforeLocators) || !reflect.DeepEqual(s.sets, beforeSets) || !maps.Equal(s.orphanBytesByDAID, beforeDAID) || !maps.Equal(s.orphanBytesByPeerQuotaKey, beforePeer) || !reflect.DeepEqual(s.sets[[32]byte{1}], beforeRecord) || ([6]uint64{s.stagedBytes, s.orphanBytes, s.orphanCommitOverheadBytes, s.completeBytes, s.completeCount, s.pinnedPayloadBytes}) != beforeCounters || !reflect.DeepEqual(o.byToken, beforeOwner.byToken) || !reflect.DeepEqual(o.byOutpoint, beforeOwner.byOutpoint) || o.byToken[PendingOutpointToken{owner: o, seq: beforeHigh + 1}] != nil {
					t.Fatal("post-provisional refusal leaked locator, record or candidate claim")
				}
			})
		}
	}
}

func TestDACompleteTailAllocations(t *testing.T) {
	for _, shape := range []string{"small", "full", "tombstone"} {
		t.Run(shape, func(t *testing.T) {
			type tailFixture struct {
				f                       *daNonReplayFixture
				a                       *DAAdmission
				p                       *daCompleteCommitPlan
				commit                  *DACommit
				locators                map[[32]byte]daRelayLocator
				records, sequence, high uint64
				preflightErr            error
				out                     daRelayAdmissionOutcome
				rejected                bool
				err                     error
			}
			build := func() tailFixture {
				f, a, c := daCompleteTestCandidate(t, true, 0, 0)
				p, _ := daCompleteCommitTestPlan(t, f, a, c)
				s, o := f.relay, f.mp.pendingOutpoints
				s.mu.Lock()
				if err := p.prepareEffects(s, a); err != nil {
					s.mu.Unlock()
					t.Fatal(err)
				}
				// One full eight-slot small map per row isolates each same-value preflight write.
				for i := byte(60); i < 67; i++ {
					id := [32]byte{i}
					switch shape {
					case "small":
						s.sets[id] = daRelaySetRecord{daID: id, state: daRelayStateOrphanChunks}
					case "full":
						s.orphanBytesByDAID[id] = 1
					case "tombstone":
						s.orphanBytesByPeerQuotaKey[fmt.Sprint(i)] = 1
					}
				}
				if shape != "small" {
					daCompleteCommitLocatorHistory(s, shape == "tombstone")
				}
				// Counter keys are deleted in normal acceptance, so measure their preflight writes directly.
				_, affected := p.placement.peerBytes["retained"]
				shapeOK := (shape == "small" && len(s.sets) == 8 && len(s.locators) == 1) ||
					(shape == "full" && len(s.orphanBytesByDAID) == 8 && len(s.locators) == 33) ||
					(shape == "tombstone" && len(s.orphanBytesByPeerQuotaKey) == 8 && len(s.locators) == 17 && affected)
				if !shapeOK {
					s.mu.Unlock()
					t.Fatal("small/full/tombstone preflight shape", shape)
				}
				item := tailFixture{f: f, a: a, p: p, locators: maps.Clone(s.locators), records: s.records, sequence: s.nextReceivedTime, high: o.tokenHighWater}
				return item
			}
			// Go 1.26 AllocsPerRun first calls f once without measuring. Both calls consume distinct prepared states.
			items := []tailFixture{build(), build()}
			calls := 0
			preflightAllocs := testing.AllocsPerRun(1, func() {
				item := &items[calls]
				calls++
				item.preflightErr = item.f.relay.preflightDACompleteCommit(item.p)
			})
			if calls != len(items) || preflightAllocs == 0 {
				t.Fatalf("same-value %s preflight did not grow: calls=%d allocs=%v", shape, calls, preflightAllocs)
			}
			for i := range items {
				item := &items[i]
				s, o := item.f.relay, item.f.mp.pendingOutpoints
				if item.preflightErr != nil || s.locators[item.p.source.candidate.member.member.txid] != item.p.source.candidate.member.locator {
					t.Fatal("candidate locator not preflighted", item.preflightErr)
				}
				if !item.a.guard.state.CompareAndSwap(daAdmissionOpen, daAdmissionAttempting) {
					t.Fatal("admission was not open")
				}
				commit, failure, failed := reservePreparedDAAdmissionCommit(item.p.owner)
				if failed {
					t.Fatal("owner Reserve", failure)
				}
				if failure, failed := o.validateDAAdmissionVictimsLocked(item.p.original, commit.candidate); failed {
					commit.Abort()
					s.mu.Unlock()
					t.Fatal("live owner claims", failure)
				}
				item.commit = commit // holds owner and DA through the measured first successful tail
			}
			calls = 0
			allocs := testing.AllocsPerRun(1, func() {
				item := &items[calls]
				calls++
				item.out, item.rejected, item.err = item.f.relay.finishDACompleteCommit(item.p, item.commit)
			})
			if allocs != 0 || calls != len(items) {
				t.Fatalf("first successful tail allocations=%v calls=%d", allocs, calls)
			}
			for _, item := range items {
				s, o := item.f.relay, item.f.mp.pendingOutpoints
				token := PendingOutpointToken{owner: o, seq: item.high + 1}
				if item.err != nil || item.rejected || item.out != (daRelayAdmissionOutcome{daID: [32]byte{1}, disposition: daRelayAdmissionRetained}) || item.a.guard.state.Load() != daAdmissionResolved || o.tokenHighWater != token.seq || o.byToken[token] == nil || !o.byToken[token].finalized {
					t.Fatal("first successful tail did not finalize candidate", item.err)
				}
				if s.records != item.records+1 || s.nextReceivedTime != item.sequence+1 || s.completeCount != 1 || s.completeBytes != item.p.result.prepared.set.totalBytes || s.pinnedPayloadBytes != 16 || s.sets[[32]byte{1}].commit.member.token != token || s.locators[item.p.source.candidate.member.member.txid] != item.p.source.candidate.member.locator || len(s.locators) != len(item.locators)+1 {
					t.Fatal("first successful tail did not publish exact DA delta")
				}
				for txid, locator := range item.locators {
					if s.locators[txid] != locator {
						t.Fatal("preexisting locator changed")
					}
				}
				for _, input := range item.a.snapshot.Inputs {
					if o.byOutpoint[input] != (pendingOutpointRow{token: token, txid: item.a.snapshot.TxID}) {
						t.Fatal("first successful tail candidate input missing")
					}
				}
			}
		})
	}
}

func TestDACompleteCommitAtomicity(t *testing.T) {
	f, a, c := daCompleteTestCandidate(t, true, 1, 0)
	p, _ := daCompleteCommitTestPlan(t, f, a, c)
	o := f.mp.pendingOutpoints
	beforeSequence := f.relay.nextReceivedTime
	finished := make(chan struct{})
	// Holding the existing owner stops the writer at Reserve with DA held.
	o.mu.Lock()
	go func() {
		out, rejected, err := f.relay.applyDACompleteCommit(a, p)
		if err != nil || rejected || out.disposition != 1 {
			t.Error("atomic completion", err)
		}
		close(finished)
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	watchdog := func() {
		t.Helper()
		select {
		case <-deadline.C:
			o.mu.Unlock()
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
			}
			t.Fatal("atomicity boundary watchdog")
		default:
		}
	}
	for f.relay.mu.TryLock() {
		f.relay.mu.Unlock()
		watchdog()
		runtime.Gosched()
	}
	if a.guard.state.Load() != 1 {
		// DA acquisition precedes the CAS; wait only for the actual state boundary.
		for a.guard.state.Load() == 0 {
			watchdog()
			runtime.Gosched()
		}
	}
	if f.relay.mu.TryLock() {
		f.relay.mu.Unlock()
		t.Error("DA lock must remain held while Reserve waits for owner")
	}
	if len(o.byToken) != 2 {
		t.Error("owner before image")
	}
	readDA := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		close(readDA)
		f.relay.mu.Lock()
		defer f.relay.mu.Unlock()
		if f.relay.sets[[32]byte{1}].state != 2 || f.relay.nextReceivedTime != beforeSequence+1 || len(f.relay.locators) != 2 {
			t.Error("DA-only reader observed partial publication")
		}
	}()
	<-readDA
	o.mu.Unlock()
	<-finished
	wg.Wait()
	// Independent owner reader has no domain lock to hide early owner publication.
	o.mu.Lock()
	if len(o.byToken) != 2 || !o.byToken[p.member.token].finalized {
		t.Error("owner-only reader observed partial publication")
	}
	o.mu.Unlock()
	// Two original admissions share the input; both capture before either apply.
	f2, a1, c1 := daCompleteTestCandidate(t, true, 0, 0)
	a2 := mustDAAdmission(t, f2.mp, a1.snapshot.TxBytes)
	defer a2.Close()
	p1, _ := daCompleteCommitTestPlan(t, f2, a1, c1)
	p2, _ := daCompleteCommitTestPlan(t, f2, a2, c1)
	start := make(chan struct{})
	results := make(chan daRelayAdmissionDisposition, 2)
	for i, admission := range []*DAAdmission{a1, a2} {
		plan := []*daCompleteCommitPlan{p1, p2}[i]
		go func() {
			<-start
			out, rejected, err := f2.relay.applyDACompleteCommit(admission, plan)
			if err != nil || rejected {
				t.Error("same-input race error", err)
			}
			results <- out.disposition
		}()
	}
	close(start)
	first, second := <-results, <-results
	if ((first != 1 || second != 2) && (first != 2 || second != 1)) || len(f2.mp.pendingOutpoints.byToken) != 2 {
		t.Fatal("same-input race one winner no leaked claim")
	}
}

func TestDACompleteCommitStructure(t *testing.T) {
	declarations := map[string]*ast.FuncDecl{}
	for _, path := range []string{"da_complete_commit.go", "da_admission.go", "pending_outpoint_owner.go", "da_relay_state.go", "da_relay_mutation.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				declarations[fn.Name.Name] = fn
			}
		}
	}
	finish := declarations["finishDACompleteCommit"]
	if finish == nil {
		t.Fatal("missing private completion tail")
	}
	start := -1
	for i, stmt := range finish.Body.List {
		if branch, ok := stmt.(*ast.IfStmt); ok {
			ast.Inspect(branch, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Abort" {
					start = i + 1
				}
				return true
			})
		}
	}
	if start < 0 {
		t.Fatal("missing acceptance boundary")
	}
	var walk func(ast.Node, map[string]bool) bool
	walk = func(node ast.Node, seen map[string]bool) bool {
		valid := true
		ast.Inspect(node, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if star, ok := ast.Unparen(lhs).(*ast.StarExpr); ok {
						if id, ok := ast.Unparen(star.X).(*ast.Ident); ok && id.Name == "s" {
							valid = false
						}
					}
					if index, ok := ast.Unparen(lhs).(*ast.IndexExpr); ok {
						if sel, ok := ast.Unparen(index.X).(*ast.SelectorExpr); ok && sel.Sel.Name == "locators" {
							valid = false
						}
					}
					if sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr); ok && slices.Contains([]string{"sets", "locators", "orphanBytesByPeerQuotaKey", "orphanBytesByDAID", "prefetch"}, sel.Sel.Name) {
						valid = false
					}
				}
			case *ast.FuncLit, *ast.GoStmt, *ast.DeferStmt, *ast.SendStmt, *ast.SelectStmt:
				valid = false
			case *ast.CompositeLit:
				switch n.Type.(type) {
				case *ast.ArrayType, *ast.MapType:
					valid = false
				}
			case *ast.UnaryExpr:
				if _, composite := ast.Unparen(n.X).(*ast.CompositeLit); composite && n.Op == token.AND {
					valid = false
				}
			case *ast.CallExpr:
				name := ""
				switch fn := n.Fun.(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				}
				if slices.Contains([]string{"delete", "len", "panic", "Load", "Store", "CompareAndSwap", "Unlock"}, name) {
					break
				}
				decl := declarations[name]
				if decl == nil {
					valid = false
					break
				}
				if !seen[name] {
					seen[name] = true
					valid = walk(decl.Body, seen) && valid
				}
			}
			return valid
		})
		return valid
	}
	var terminal []string
	for _, stmt := range finish.Body.List[start:] {
		if !walk(stmt, map[string]bool{}) {
			t.Fatal("fallible preparation after acceptance")
		}
		ast.Inspect(stmt, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					terminal = append(terminal, sel.Sel.Name)
				}
			}
			return true
		})
	}
	if !slices.Equal(terminal, []string{"publishDACompleteLocked", "Commit", "Unlock"}) {
		t.Fatal("owner terminal precedes DA unlock")
	}
	for _, probe := range []struct {
		body  string
		valid bool
	}{
		{"x := make([]byte, 1); _ = x", false},
		{"x := append([]byte(nil), source...); _ = x", false},
		{"alias := prepareDAAdmissionCommit; alias(a, victims)", false},
		{"func() { make([]byte, 1) }()", false},
		{"p := projected; s.sets = (p.sets)", false},
		{"x := PendingOutpointToken{}; _ = x", true},
		{"p := projected; *s = (*p)", false},
		{"s.locators[x] = y", false},
		{"x := &DACommit{}; _ = x", false},
		{"x := &(DACommit{}); _ = x", false},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "probe.go", "package node\nfunc probe(){"+probe.body+"}", 0)
		if err != nil {
			t.Fatal(err)
		}
		if walk(file.Decls[0].(*ast.FuncDecl).Body, map[string]bool{}) != probe.valid {
			t.Fatal("fallible preparation after acceptance: alias/parenthesis/inert probe")
		}
	}
	// Preserve predecessor coverage, exact source literals, owner closure hash and public counts.
	requireDAAdmissionStructure(t)
	TestDAPreparedCommitStructure(t)
	for path, want := range map[string]map[string]int{
		"da_complete_snapshot.go": {"cloneForAtomicBatchLocked": 0},
		"da_complete_commit.go":   {"prepareDAAdmissionCommit": 1, "reservePreparedDAAdmissionCommit": 1, "validateDAAdmissionVictimsLocked": 1, "cloneForAtomicBatchLocked": 0, "applyDACompleteCommit": 0, "prepareDACompleteCommit": 0},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]int{}
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					got[fn.Name]++
				case *ast.SelectorExpr:
					got[fn.Sel.Name]++
				}
			}
			return true
		})
		for name, count := range want {
			if got[name] != count {
				t.Fatal("private consumer and snapshot bridge references", path, name, got[name])
			}
		}
	}
}
