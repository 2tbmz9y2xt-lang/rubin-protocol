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
	f, a, c, victims := daCompleteCommitPhysicalVictims(t, 2)
	f.relay.prefetch.indexes = map[[32]byte]map[uint16]string{{11}: {0: "victim"}, {12}: {0: "victim"}}
	f.relay.prefetch.expires = map[[32]byte]time.Time{{11}: time.Unix(3, 0), {12}: time.Unix(4, 0)}
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
	if f.relay.completeCount != 1 || f.relay.pinnedPayloadBytes != 16 || f.relay.completeBytes != uint64(len(a.snapshot.TxBytes)+len(p.source.prior.chunks[0].txBytes)) {
		t.Fatal("victim C bytes count payload")
	}
}

func TestDACompleteCommitCapacity(t *testing.T) {
	for _, individual := range []bool{false, true} {
		f, a, c := daCompleteTestCandidate(t, true, 1, 0)
		// Numerical owner-image boundary: fixed B occupancy, without allocating 512 MiB.
		f.relay.stagedBytes = 536870912
		s := daCompleteTestCapture(t, f, c)
		r, err := prepareDACompleteSnapshot(s, daRelayAdmissionOutcome{})
		if err != nil {
			t.Fatal(err)
		}
		if individual {
			r.prepared.input.candidate.totalBytes = 536870913
		}
		p, err := f.relay.prepareDACompleteCommit(a, r)
		if err != nil {
			t.Fatal(err)
		}
		before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
		out, rejected, err := f.relay.applyDACompleteCommit(a, p)
		if out != (daRelayAdmissionOutcome{}) || !rejected || err != nil {
			t.Fatal("capacity rejected tuple after reserve", out, rejected, err)
		}
		owner.tokenHighWater++
		requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
		if a.guard.state.Load() != 4 || len(p.owner.commit.victims) != 0 {
			t.Fatal("candidate release and other-claim image")
		}
	}
}

func TestDACompleteCommitOwnerOrder(t *testing.T) {
	for _, name := range []string{"transition", "tip", "generation", "exhaustion", "first input", "selected victim"} {
		t.Run(name, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, false, 0, 0)
			f.relay.stagedBytes = 536870912
			p, _ := daCompleteCommitTestPlan(t, f, a, c)
			o := f.mp.pendingOutpoints
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
			default:
				mustReserve(t, o, [32]byte{81}, a.snapshot.Inputs[1])
				mustReserve(t, o, [32]byte{80}, a.snapshot.Inputs[0])
				want, kind = fmt.Sprintf("mempool double-spend conflict with %x", [32]byte{80}), "conflict"
				if name == "selected victim" {
					p.owner.commit.victims = []DAAdmissionVictim{{TxID: [32]byte{80}, Token: o.byOutpoint[a.snapshot.Inputs[0]].token, Inputs: slices.Clone(a.snapshot.Inputs[:1])}}
				}
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
	for _, name := range []string{"target", "complete", "complete count", "payload", "staged", "orphan", "commit overhead", "peer", "DA map", "caps", "locator", "records", "sequence", "survivor token", "survivor input", "baseline before survivor", "stale capacity", "victim before baseline"} {
		t.Run(name, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, true, 1, 0)
			if name == "stale capacity" {
				f.relay.stagedBytes = 536870912
			}
			p, _ := daCompleteCommitTestPlan(t, f, a, c)
			o := f.mp.pendingOutpoints
			member := f.relay.sets[[32]byte{1}].chunks[0].member
			want := "retained DA record moved while this admission was planned"
			switch name {
			case "target":
				r := f.relay.sets[[32]byte{1}]
				r.ttlBlocksRemaining--
				f.relay.sets[r.daID] = r
			case "complete":
				f.relay.completeBytes++
			case "complete count":
				f.relay.completeCount++
			case "payload":
				f.relay.pinnedPayloadBytes++
			case "orphan":
				f.relay.orphanBytes++
			case "commit overhead":
				f.relay.orphanCommitOverheadBytes++
			case "peer":
				f.relay.orphanBytesByPeerQuotaKey["retained"]++
			case "DA map":
				f.relay.orphanBytesByDAID[[32]byte{1}]++
			case "caps":
				f.relay.caps.orphanTTLBlocks++
			case "staged", "stale capacity":
				f.relay.stagedBytes++
			case "locator":
				delete(f.relay.locators, member.txid)
			case "records":
				f.relay.records++
			case "sequence":
				f.relay.nextReceivedTime++
			case "survivor token":
				o.byToken[member.token].finalized = false
				want = "DA victim claim mismatch"
			case "survivor input":
				delete(o.byOutpoint, member.inputs[0])
				want = "DA victim input mismatch"
			case "baseline before survivor":
				f.relay.records++
				delete(o.byOutpoint, member.inputs[0])
			case "victim before baseline":
				f.relay.records++
				victim := f.relay.sets[[32]byte{1}].chunks[3].member
				o.byToken[victim.token].finalized = false
				want = "DA victim claim mismatch"
			}
			before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(o)
			out, rejected, err := f.relay.applyDACompleteCommit(a, p)
			if out != (daRelayAdmissionOutcome{}) || rejected || daAdmit(t, err, "unavailable").Message != want {
				t.Fatal("baseline mismatch precedes survivor mismatch", err)
			}
			if o.tokenHighWater != owner.tokenHighWater+1 {
				t.Fatal("post-reserve high-water")
			}
			owner.tokenHighWater++
			requireDANonReplayUnchanged(t, f.relay, o, before, owner)
			if a.guard.state.Load() != 4 {
				t.Fatal("candidate release and other-claim image")
			}
		})
	}
	for _, name := range []string{"C survivor record", "C survivor payload nilness", "C survivor token", "C survivor input", "C victim record", "C victim claim before baseline"} {
		t.Run(name, func(t *testing.T) {
			f, a, c, residents := daCompleteCommitPhysicalVictims(t, 2)
			f.relay.stagedBytes -= 2 // Select the first C record; the second survives.
			p, _ := daCompleteCommitTestPlan(t, f, a, c)
			chosen := residents[1]
			if strings.Contains(name, "victim") {
				chosen = residents[0]
			}
			want := "retained DA record moved while this admission was planned"
			o := f.mp.pendingOutpoints
			switch name {
			case "C survivor record", "C victim record":
				updated := chosen.cloneOwnerReady()
				updated.commit.txBytes[0]++
				f.relay.sets[chosen.daID] = updated
			case "C survivor payload nilness":
				updated := chosen.cloneOwnerReady()
				chunk := updated.chunks[0]
				chunk.payload = []byte{}
				updated.chunks[0] = chunk
				f.relay.sets[chosen.daID] = updated
			case "C survivor token":
				o.byToken[chosen.commit.member.token].finalized = false
				want = "DA victim claim mismatch"
			case "C survivor input":
				delete(o.byOutpoint, chosen.chunks[0].member.inputs[0])
				want = "DA victim input mismatch"
			case "C victim claim before baseline":
				f.relay.records++
				o.byToken[chosen.commit.member.token].finalized = false
				want = "DA victim claim mismatch"
			}
			before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(o)
			out, rejected, err := f.relay.applyDACompleteCommit(a, p)
			if out != (daRelayAdmissionOutcome{}) || rejected || daAdmit(t, err, "unavailable").Message != want {
				t.Fatal("C survivor and victim exact revalidation", err)
			}
			owner.tokenHighWater++
			requireDANonReplayUnchanged(t, f.relay, o, before, owner)
			if name == "C survivor payload nilness" {
				payload := f.relay.sets[chosen.daID].chunks[0].payload
				if payload == nil || len(payload) != 0 {
					t.Fatal("C survivor payload nilness preserved")
				}
			}
		})
	}
	for _, field := range []string{"daID", "state", "revision", "receivedTime", "payloadBytes", "wireBytes", "replaceable nilness", "replaceable contents", "commit metadata", "chunk metadata", "member token", "member inputs", "member raw", "mempool", "owner"} {
		t.Run(field, func(t *testing.T) {
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
				chunk := r.chunks[0]
				chunk.chunkHash[0]++
				r.chunks[0] = chunk
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
			}
			f.relay.sets[[32]byte{1}] = r
			before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(a.guard.owner)
			out, rejected, err := f.relay.applyDACompleteCommit(a, p)
			if out != (daRelayAdmissionOutcome{}) || rejected || daAdmit(t, err, "unavailable").Message != "retained DA record moved while this admission was planned" {
				t.Fatal("full retained baseline field", field, err)
			}
			owner.tokenHighWater++
			requireDANonReplayUnchanged(t, f.relay, a.guard.owner, before, owner)
		})
	}
}

// Signed DA members and finalized claims; fixed-B pressure is a numerical image.
// No setup path invokes the completion consumer under mutation.
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
	lastResident := residents[len(residents)-1]
	required := total - uint64(len(lastResident.commit.txBytes)+len(lastResident.chunks[0].txBytes)) + 1
	f.relay.stagedBytes = 536870912 - total - (uint64(len(chunk.raw)+len(last.raw)) - required)
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
	if r.state != 1 || len(r.chunks) != 0 || len(got.locators) != 1 || got.locators[a.snapshot.TxID] != c.member.locator {
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
}

func TestDACompleteCommitMismatchOrder(t *testing.T) {
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
				f.relay.records++
				want = "retained DA record moved while this admission was planned"
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
		})
	}
}

func TestDACompleteCommitLifecycle(t *testing.T) {
	for _, final := range []bool{false, true} {
		f, a, c := daCompleteTestCandidate(t, true, 0, 0)
		var p *daCompleteCommitPlan
		if final {
			p, _ = daCompleteCommitTestPlan(t, f, a, c)
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
		requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
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
	if out, rejected, err := f.relay.applyDACompleteCommit(a, p); out != (daRelayAdmissionOutcome{}) || rejected || !daCompleteTestError(err, errDARelayImageIncompatible) {
		t.Fatal("second attempt requires new admission")
	}
	requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)

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
	for _, name := range []string{"missing", "invalid duplicate", "duplicate prepared", "duplicate mismatch", "prepared mismatch", "all variants", "nil source", "image", "txid", "wtxid", "bytes", "fee", "inputs", "owner", "revision", "projection"} {
		t.Run(name, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, false, 0, 0)
			s := daCompleteTestCapture(t, f, c)
			result, err := prepareDACompleteSnapshot(s, daRelayAdmissionOutcome{})
			if err != nil {
				t.Fatal(err)
			}
			want := errDARelayImageIncompatible
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
			case "revision":
				s.records = math.MaxUint64
				want = errDARelayArithmeticOverflow
			case "projection":
				s.publicationBase.orphanCommitOverheadBytes = 0
				want = errDARelayArithmeticOverflow
			}
			before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
			p, err := f.relay.prepareDACompleteCommit(a, result)
			if p != nil || !daCompleteTestError(err, want) || a.guard.state.Load() != 0 {
				t.Fatal("same admission identity and owner closed preparation", name, err)
			}
			requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
		})
	}
	f, a, c := daCompleteTestCandidate(t, true, 1, 0)
	s := daCompleteTestCapture(t, f, c)
	base := daRelayStateSnapshot(s.publicationBase)
	baseOwner := cloneDAAdmissionOwner(s.owner)
	result, err := prepareDACompleteSnapshot(s, daRelayAdmissionOutcome{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.relay.prepareDACompleteCommit(a, result)
	if err != nil {
		t.Fatal(err)
	}
	c.member.txBytes[0]++
	c.member.member.inputs[0].Vout++
	result.prepared.image.next.commit.txBytes[0]++
	result.prepared.image.next.commit.member.inputs[0].Vout++
	projected := p.projected.sets[[32]byte{1}].commit
	requireDANonReplayUnchanged(t, s.publicationBase, s.owner, base, baseOwner)
	if !bytes.Equal(projected.txBytes, a.snapshot.TxBytes) || !slices.Equal(projected.member.inputs, a.snapshot.Inputs) || !slices.Equal(p.owner.candidate.inputs, a.snapshot.Inputs) {
		t.Fatal("owned snapshot remains unchanged")
	}
	f.relay.sets[[32]byte{1}].chunks[0].txBytes[0]++
	requireDANonReplayUnchanged(t, s.publicationBase, s.owner, base, baseOwner)
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
		if p, err := f.relay.prepareDACompleteCommit(a, result); p != nil || !daCompleteTestError(err, errDARelayImageIncompatible) || a.guard.state.Load() != 0 {
			t.Fatal("closed mismatch shape", name, err)
		}
	}
	f, a, c = daCompleteTestCandidate(t, false, 0, 0)
	f.relay.caps.stagedBytes = 4294967295
	p, _ = daCompleteCommitTestPlan(t, f, a, c)
	daCompleteCommitTestApply(t, f, a, p)
}

func TestDACompleteCommitVictims(t *testing.T) {
	for _, count := range []int{1, 2, 65} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, true, 0, 0)
			s := daCompleteTestCapture(t, f, c)
			result, err := prepareDACompleteSnapshot(s, daRelayAdmissionOutcome{})
			if err != nil {
				t.Fatal(err)
			}
			// Direct valid owner-image expansion, independent of canonical snapshot parsing.
			// 65 two-member records prove the 129th claim, without 130 signatures.
			o := f.mp.pendingOutpoints
			var removed []PendingOutpointToken
			var ids [][32]byte
			for i := 0; i < count; i++ {
				id := [32]byte{byte(i + 10)}
				ids = append(ids, id)
				r := daRelaySetRecord{daID: id, state: 2, revision: 1, receivedTime: 1, payloadBytes: 1, chunks: map[uint16]daRelayChunk{}}
				for j := 0; j < 2; j++ {
					txid := [32]byte{byte(i + 10), byte(j + 1)}
					input := consensus.Outpoint{Txid: txid}
					token := mustReserve(t, o, txid, input)
					// mustReserve uses standard domain; the constructed image is explicitly DA.
					o.byToken[token].domain, o.byToken[token].finalized = PendingOutpointDA, true
					m := &daRelayMemberIdentity{txid: txid, wtxid: txid, fee: consensus.Uint128{Lo: 1}, token: token, inputs: []consensus.Outpoint{input}, provenance: LocalDAProvenance()}
					if j == 0 {
						r.commit = daRelayCommit{daID: id, member: m, chunkCount: 1, txBytes: []byte{1}}
					} else {
						r.chunks[0] = daRelayChunk{daID: id, member: m, txBytes: []byte{2}}
					}
					f.relay.locators[txid] = daRelayLocator{daID: id, kind: daRelayLocatorKind(j + 1)}
					removed = append(removed, token)
				}
				f.relay.sets[id] = r
				s.residents = append(s.residents, r.cloneOwnerReady())
				result.prepared.input.residents = append(result.prepared.input.residents, daCompleteCapacitySet{id: id, fee: consensus.Uint128{Lo: 2}, totalBytes: 2, payloadBytes: 1, receivedSequence: 1})
			}
			candidateBytes := result.prepared.input.candidate.totalBytes
			f.relay.completeBytes, f.relay.completeCount, f.relay.pinnedPayloadBytes = uint64(count*2), uint64(count), uint64(count)
			f.relay.stagedBytes = 536870912 - candidateBytes
			s.publicationBase = f.relay.cloneForAtomicBatchLocked()
			in := &result.prepared.input
			in.stagedBytes, in.completeBytes, in.completeCount, in.completePayload = f.relay.stagedBytes, uint64(count*2), uint64(count), uint64(count)
			p, err := f.relay.prepareDACompleteCommit(a, result)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(p.prefetch[:count], ids) {
				t.Fatal("deterministic planner victim order")
			}
			daCompleteCommitTestApply(t, f, a, p)
			for i, token := range removed {
				if o.byToken[token] != nil {
					t.Fatalf("all selected member claims absent: row %d", i+1)
				}
			}
			for _, id := range ids {
				if _, ok := f.relay.sets[id]; ok {
					t.Fatal("whole selected records absent")
				}
				for j := 1; j <= 2; j++ {
					if _, ok := f.relay.locators[[32]byte{id[0], byte(j)}]; ok {
						t.Fatal("selected member locators absent")
					}
				}
			}
			if f.relay.completeCount != 1 || f.relay.completeBytes != candidateBytes || f.relay.pinnedPayloadBytes != 16 {
				t.Fatal("victim C projections")
			}
		})
	}
	f, a, c, residents := daCompleteCommitPhysicalVictims(t, 1)
	p, _ := daCompleteCommitTestPlan(t, f, a, c)
	daCompleteCommitTestApply(t, f, a, p)
	for _, member := range []*daRelayMemberIdentity{residents[0].commit.member, residents[0].chunks[0].member} {
		if f.mp.pendingOutpoints.byToken[member.token] != nil {
			t.Fatal("physically admitted selected member claim absent")
		}
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
			f.relay.mu.Lock()
			switch {
			case strings.HasPrefix(operation, "insert"):
				r := f.relay.sets[id].cloneOwnerReady()
				r.daID = [32]byte{42}
				f.relay.sets[r.daID] = r
			case strings.HasPrefix(operation, "delete"):
				delete(f.relay.sets, id)
			case strings.HasPrefix(operation, "replace"):
				r := f.relay.sets[id].cloneOwnerReady()
				r.revision++
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
			f.relay.mu.Unlock()
			f.relay.rejectCache.entries = map[[32]byte]struct{}{{99}: {}}
			before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
			out, rejected, err := f.relay.applyDACompleteCommit(a, p)
			if operation != "preserve" {
				if out != (daRelayAdmissionOutcome{}) || rejected || daAdmit(t, err, "unavailable").Message != "retained DA record moved while this admission was planned" {
					t.Fatal("current state preserved after stale refusal", err)
				}
				owner.tokenHighWater++
				requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
			} else {
				if err != nil || rejected || out.disposition != 1 {
					t.Fatal(err)
				}
				got := daRelayStateSnapshot(f.relay)
				if !reflect.DeepEqual(got.sets[x.spec.daID], before.sets[x.spec.daID]) || !reflect.DeepEqual(got.sets[y.spec.daID], before.sets[y.spec.daID]) || got.locators[x.txid] != before.locators[x.txid] || got.locators[y.txid] != before.locators[y.txid] {
					t.Fatal("unrelated records and exact locators preserved")
				}
				if got.stagedBytes != before.stagedBytes || got.commitBytes != before.commitBytes || got.orphanBytes != uint64(len(x.raw)+1) || got.peerBytes["other"] != uint64(len(x.raw)+1) || got.daIDBytes[x.spec.daID] != uint64(len(x.raw)+1) {
					t.Fatal("unrelated retained charges")
				}
				if !reflect.DeepEqual(got.prefetchIndexes, map[[32]byte]map[uint16]string{{40}: {0: "live"}}) || !reflect.DeepEqual(got.prefetchExpires, map[[32]byte]time.Time{{40}: time.Unix(4, 0)}) {
					t.Fatal("unrelated live prefetch preserved exact targeted deletion")
				}
			}
			if !maps.Equal(f.relay.rejectCache.entries, map[[32]byte]struct{}{{99}: {}}) {
				t.Fatal("unrelated live prefetch/reject preserved")
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
	for _, path := range []string{"da_complete_commit.go", "da_admission.go", "pending_outpoint_owner.go", "da_relay_state.go"} {
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
		{"p := projected; s.sets = (p.sets)", true},
		{"x := PendingOutpointToken{}; _ = x", true},
		{"p := projected; *s = (*p)", true},
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
		"da_complete_snapshot.go": {"cloneForAtomicBatchLocked": 1},
		"da_complete_commit.go":   {"prepareDAAdmissionCommit": 1, "reservePreparedDAAdmissionCommit": 1, "validateDAAdmissionVictimsLocked": 1, "cloneForAtomicBatchLocked": 1, "applyDACompleteCommit": 0, "prepareDACompleteCommit": 0},
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
