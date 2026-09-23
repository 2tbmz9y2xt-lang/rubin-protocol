package node

import (
	"crypto/sha3"
	"errors"
	"math"
	"reflect"
	"runtime"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func daCompleteTestError(err, want error) bool {
	return errors.Is(err, want) && reflect.TypeOf(err) == reflect.TypeOf(want)
}

// Signed fixture bytes and real admission tokens supply identity/provenance.
func daCompleteTestCandidate(t *testing.T, commitLast bool, prune, residents int) (*daNonReplayFixture, *DAAdmission, daRelayAdmissionCandidate) {
	t.Helper()
	f := newDANonReplayFixture(t, 20)
	for i := residents; i > 0; i-- {
		id := [32]byte{byte(10 + i)}
		f.completeReplay(id, 1, byte(i))
		r := f.relay.sets[id]
		r.wireBytes = 0
		f.relay.sets[id] = r
		f.relay.completeCount++
		f.relay.completeBytes += uint64(len(r.commit.txBytes) + len(r.chunks[0].txBytes))
		f.relay.pinnedPayloadBytes += r.payloadBytes
	}
	id := [32]byte{1}
	payload := []byte("complete payload")
	chunk := f.signed(daNonReplayTxSpec{kind: 2, daID: id, payload: payload, inputCount: 2})
	commit := f.signed(daNonReplayTxSpec{kind: 1, daID: id, chunkCount: 1, commitment: sha3.Sum256(payload), commitmentOutputs: 1})
	last := chunk
	if commitLast {
		f.admit(chunk, daNonReplayPeer("retained"))
		for i := 0; i < prune; i++ {
			extra := f.signed(daNonReplayTxSpec{kind: 2, daID: id, chunkIndex: uint16(i + 3), payload: []byte{byte(i + 1)}})
			f.admit(extra, LocalDAProvenance())
		}
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

func daCompleteTestCapture(t *testing.T, f *daNonReplayFixture, c daRelayAdmissionCandidate) *daCompleteSnapshot {
	t.Helper()
	s, duplicate, err := f.relay.captureDACompleteSnapshot(c)
	if err != nil || s == nil || duplicate != (daRelayAdmissionOutcome{}) {
		t.Fatalf("capture=(%v,%+v,%v)", s, duplicate, err)
	}
	return s
}

func daCompleteTestPrepare(t *testing.T, f *daNonReplayFixture, a *DAAdmission, s *daCompleteSnapshot) (daCompletePreparation, error) {
	t.Helper()
	before, owner, admission := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints), a.Snapshot()
	result, err := prepareDACompleteSnapshot(s, daRelayAdmissionOutcome{})
	requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
	if !reflect.DeepEqual(a.Snapshot(), admission) || a.guard == nil {
		t.Fatal("preparation changed admission lifecycle")
	}
	return result, err
}

func requireDACompleteImageRefusal(t *testing.T, f *daNonReplayFixture, a *DAAdmission, result daCompletePreparation) {
	t.Helper()
	p, err := f.relay.prepareDACompleteCommit(a, result)
	if err != nil {
		t.Fatal(err)
	}
	before, owner := daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints)
	out, rejected, err := f.relay.applyDACompleteCommit(a, p)
	if out != (daRelayAdmissionOutcome{}) || rejected || !daCompleteTestError(err, errDARelayImageIncompatible) || a.guard.state.Load() != daAdmissionOpen {
		t.Fatal("live image refusal before Reserve", out, rejected, err)
	}
	requireDANonReplayUnchanged(t, f.relay, f.mp.pendingOutpoints, before, owner)
}

func daCompleteTestChunk(s *daCompleteSnapshot, mutate func(*daRelayChunk)) {
	c := s.prior.chunks[0]
	mutate(&c)
	s.prior.chunks[0] = c
}

func TestDACompleteSnapshotPlannerInput(t *testing.T) {
	for _, commitLast := range []bool{true, false} {
		for _, residents := range []int{0, 1, 2} {
			f, a, c := daCompleteTestCandidate(t, commitLast, 0, residents)
			source := daCompleteTestCapture(t, f, c)
			result, err := daCompleteTestPrepare(t, f, a, source)
			if err != nil || result.prepared == nil || result.duplicate != nil || result.mismatch != nil {
				t.Fatalf("candidate preparation: %+v %v", result, err)
			}
			priorRaw, payload, credit := uint64(0), uint64(0), uint64(0)
			if commitLast {
				priorRaw = uint64(len(source.prior.chunks[0].txBytes))
				payload = uint64(len(source.prior.chunks[0].payload))
			} else {
				priorRaw = uint64(len(source.prior.commit.txBytes))
				payload = uint64(len(c.member.payload))
				credit = priorRaw
			}
			wantSet := daCompleteCapacitySet{id: [32]byte{1}, fee: consensus.Uint128{Lo: 1200000}, totalBytes: priorRaw + uint64(len(c.member.txBytes)), payloadBytes: payload, receivedSequence: source.prior.receivedTime}
			if result.prepared.set != wantSet || result.prepared.source != source {
				t.Fatalf("off-DA candidate descriptor: got=%+v want=%+v", result.prepared.set, wantSet)
			}
			f.relay.mu.Lock()
			input, err := f.relay.capacityInput(source, result.prepared.set)
			f.relay.mu.Unlock()
			want := daCompleteCapacityInput{byteCap: 536870912, stagedBytes: credit, priorCredit: credit, completeBytes: f.relay.completeBytes, completeCount: uint64(residents), completePayload: uint64(residents), candidate: wantSet}
			for i := 1; i <= residents; i++ {
				r := f.relay.sets[[32]byte{byte(10 + i)}]
				want.residents = append(want.residents, r.completeIntrinsic)
			}
			if err != nil || input.byteCap != want.byteCap || input.stagedBytes != want.stagedBytes || input.priorCredit != want.priorCredit || input.completeBytes != want.completeBytes || input.completeCount != want.completeCount || input.completePayload != want.completePayload || input.candidate != want.candidate || !sameDACompleteSets(input.residents, want.residents) {
				t.Fatalf("final-lock planner input: got=%+v want=%+v err=%v", input, want, err)
			}
		}
	}
	t.Run("two chunks ascending", func(t *testing.T) {
		f := newDANonReplayFixture(t, 4)
		id := [32]byte{51}
		first := f.signed(daNonReplayTxSpec{kind: 2, daID: id, payload: []byte("left")})
		second := f.signed(daNonReplayTxSpec{kind: 2, daID: id, chunkIndex: 1, payload: []byte("right")})
		f.admit(second, LocalDAProvenance())
		f.admit(first, DetachedReorgDAProvenance())
		commit := f.signed(daNonReplayTxSpec{kind: 1, daID: id, chunkCount: 2, commitment: sha3.Sum256([]byte("leftright")), commitmentOutputs: 1})
		a := f.begin(commit)
		defer a.Close()
		c, err := a.renderDARelayAdmissionCandidate(LocalDAProvenance())
		if err != nil {
			t.Fatal(err)
		}
		out, err := daCompleteTestPrepare(t, f, a, daCompleteTestCapture(t, f, c))
		want := daCompleteCapacitySet{id: id, fee: consensus.Uint128{Lo: 1800000}, totalBytes: uint64(len(first.raw) + len(second.raw) + len(commit.raw)), payloadBytes: 9, receivedSequence: 1}
		if err != nil || out.prepared == nil || out.prepared.set != want {
			t.Fatal("ascending candidate descriptor", err)
		}
		r := out.prepared.image.next
		if !slices.Equal(r.chunks[0].member.inputs, first.inputs) || !slices.Equal(r.chunks[1].member.inputs, second.inputs) || !slices.Equal(r.commit.member.inputs, commit.inputs) || r.chunks[0].member.token.seq != 2 || r.chunks[1].member.token.seq != 1 {
			t.Fatal("ascending retained members")
		}
	})
}

func sameDACompleteSets(a, b []daCompleteCapacitySet) bool {
	return len(a) == len(b) && !slices.ContainsFunc(b, func(set daCompleteCapacitySet) bool { return !slices.Contains(a, set) })
}

func TestDACompleteSnapshotPrune(t *testing.T) {
	for _, count := range []int{0, 1, 2} {
		f, a, c := daCompleteTestCandidate(t, true, count, 0)
		s := daCompleteTestCapture(t, f, c)
		if count == 2 {
			s.prior.chunks[3].member.fee = consensus.Uint128{Hi: math.MaxUint64, Lo: math.MaxUint64}
			s.prior.chunks[4].member.fee = consensus.Uint128{Lo: 1}
		}
		result, err := daCompleteTestPrepare(t, f, a, s)
		if err != nil || result.prepared == nil {
			t.Fatal("isolated prune", err)
		}
		var want []DAAdmissionVictim
		for i := 0; i < count; i++ {
			m := s.prior.chunks[uint16(i+3)].member
			want = append(want, DAAdmissionVictim{TxID: m.txid, Token: m.token, Inputs: slices.Clone(m.inputs)})
		}
		if !reflect.DeepEqual(result.prepared.pruned, want) || len(result.prepared.image.next.chunks) != 1 || result.prepared.set.fee != (consensus.Uint128{Lo: 1200000}) || result.prepared.set.totalBytes != uint64(len(c.member.txBytes)+len(s.prior.chunks[0].txBytes)) {
			t.Fatal("pruned fee or exact claim list")
		}
	}
}

func TestDACompleteSnapshotRepresentation(t *testing.T) {
	f, a, c := daCompleteTestCandidate(t, true, 0, 1)
	for _, field := range []string{"incomplete cache", "incomplete hash", "incomplete empty shadow"} {
		s := daCompleteTestCapture(t, f, c)
		switch field {
		case "incomplete cache":
			daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.payload[0] ^= 1 })
		case "incomplete hash":
			daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.chunkHash[0] ^= 1 })
		case "incomplete empty shadow":
			daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.payload = []byte{} })
		}
		out, err := daCompleteTestPrepare(t, f, a, s)
		if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
			t.Fatal(field, err)
		}
	}
	for _, shadow := range [][]byte{nil, {}, {1}} {
		r := f.relay.sets[[32]byte{11}]
		chunk := r.chunks[0]
		chunk.payload = shadow
		r.chunks[0] = chunk
		f.relay.sets[r.daID] = r
		s := daCompleteTestCapture(t, f, c)
		out, err := daCompleteTestPrepare(t, f, a, s)
		if err != nil || out.prepared == nil {
			t.Fatal("C must not be inspected off DA", err)
		}
		f.relay.mu.Lock()
		_, err = f.relay.capacityInput(s, out.prepared.set)
		f.relay.mu.Unlock()
		if (shadow == nil && err != nil) || (shadow != nil && !daCompleteTestError(err, errDARelayImageIncompatible)) {
			t.Fatal("C nil shadow validated only under final DA", err)
		}
	}
	t.Run("canonical payload hash", func(t *testing.T) {
		s := daCompleteTestCapture(t, f, c)
		wrong := f.signed(daNonReplayTxSpec{kind: 2, daID: s.prior.daID, payload: []byte("mutated! payload"), literalChunkHash: true, chunkHash: s.prior.chunks[0].chunkHash})
		ch := s.prior.chunks[0]
		delete(s.locators, ch.member.txid)
		ch.txBytes, ch.payload = slices.Clone(wrong.raw), slices.Clone(wrong.spec.payload)
		ch.member.txid, ch.member.wtxid, ch.member.inputs = wrong.txid, wrong.wtxid, slices.Clone(wrong.inputs)
		s.prior.chunks[0] = ch
		s.locators[wrong.txid] = daRelayLocator{daID: s.prior.daID, kind: daRelayLocatorChunk}
		out, err := daCompleteTestPrepare(t, f, a, s)
		if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
			t.Fatal("candidate canonical payload hash", err)
		}
	})
	s := daCompleteTestCapture(t, f, c)
	out, err := daCompleteTestPrepare(t, f, a, s)
	if err != nil || out.prepared == nil {
		t.Fatal(err)
	}
	r := out.prepared.image.next
	if r.state != 2 || r.ttlBlocksRemaining != 0 || r.payloadBytes != 16 || r.replaceableChunks != nil || r.wireBytes != 0 || r.chunks[0].payload != nil || r.revision != s.prior.revision || r.receivedTime != s.prior.receivedTime || r.chunks[0].member.token != s.prior.chunks[0].member.token || r.commit.member.token != (PendingOutpointToken{}) {
		t.Fatal("candidate complete representation")
	}
}

func TestDACompleteSnapshotAccounting(t *testing.T) {
	f, a, c := daCompleteTestCandidate(t, false, 0, 2)
	for _, row := range []struct {
		name                    string
		prior, completing, want consensus.Uint128
		overflow                bool
	}{
		{"zero", consensus.Uint128{}, consensus.Uint128{}, consensus.Uint128{}, false},
		{"high limb", consensus.Uint128{Hi: 7, Lo: 3}, consensus.Uint128{Hi: 2, Lo: 9}, consensus.Uint128{Hi: 9, Lo: 12}, false},
		{"maximum", consensus.Uint128{Hi: math.MaxUint64, Lo: math.MaxUint64 - 1}, consensus.Uint128{Lo: 1}, consensus.Uint128{Hi: math.MaxUint64, Lo: math.MaxUint64}, false},
		{"overflow", consensus.Uint128{Hi: math.MaxUint64, Lo: math.MaxUint64}, consensus.Uint128{Lo: 1}, consensus.Uint128{}, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			s := daCompleteTestCapture(t, f, c)
			s.prior.commit.member.fee = row.prior
			s.candidate.member.member.fee = row.completing
			out, err := daCompleteTestPrepare(t, f, a, s)
			if row.overflow {
				if !daCompleteTestError(err, errDARelayArithmeticOverflow) || out != (daCompletePreparation{}) {
					t.Fatal("candidate fee overflow", err)
				}
			} else if err != nil || out.prepared == nil || out.prepared.set.fee != row.want {
				t.Fatal("candidate exact fee", err)
			}
		})
	}
	for _, field := range []string{"bytes", "count", "payload", "staged", "byte cap", "commit overhead"} {
		t.Run(field, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, false, 0, 2)
			s := daCompleteTestCapture(t, f, c)
			out, err := daCompleteTestPrepare(t, f, a, s)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "bytes":
				f.relay.completeBytes++
			case "count":
				f.relay.completeCount++
			case "payload":
				f.relay.pinnedPayloadBytes++
			case "staged":
				f.relay.stagedBytes++
			case "byte cap":
				f.relay.caps.stagedBytes = 536870911
			case "commit overhead":
				f.relay.orphanCommitOverheadBytes++
			}
			requireDACompleteImageRefusal(t, f, a, out)
		})
	}
}

func TestDACompleteSnapshotMismatch(t *testing.T) {
	for _, commitLast := range []bool{true, false} {
		f, a, c := daCompleteTestCandidate(t, commitLast, 2, 1)
		wrong := f.signed(daNonReplayTxSpec{kind: 1, daID: [32]byte{1}, chunkCount: 1, commitment: [32]byte{99}, commitmentOutputs: 1})
		s := daCompleteTestCapture(t, f, c)
		identity := daRelayMemberIdentity{txid: wrong.txid, wtxid: wrong.wtxid, fee: wrong.spec.fee, inputs: slices.Clone(wrong.inputs), provenance: LocalDAProvenance()}
		if commitLast {
			s.candidate.member.member = identity
			s.candidate.member.txBytes = slices.Clone(wrong.raw)
			s.candidate.payloadCommitment = [32]byte{99}
		} else {
			old := s.prior.commit.member
			identity.token = old.token
			delete(s.locators, old.txid)
			s.locators[wrong.txid] = daRelayLocator{daID: [32]byte{1}, kind: daRelayLocatorCommit}
			s.prior.commit.member = &identity
			s.prior.commit.txBytes = slices.Clone(wrong.raw)
			s.prior.commit.payloadCommitment = [32]byte{99}
		}
		f.relay.nextReceivedTime = math.MaxUint64
		resident := f.relay.sets[[32]byte{11}]
		resident.commit.txBytes = []byte{0}
		f.relay.sets[resident.daID] = resident
		out, err := daCompleteTestPrepare(t, f, a, s)
		if err != nil || out.mismatch == nil || out.prepared != nil || out.duplicate != nil {
			t.Fatal("mismatch before sequence and C scan", err)
		}
		if commitLast {
			if len(out.mismatch.removed) != 3 || len(out.mismatch.image.next.chunks) != 0 || out.mismatch.image.next.state != 1 {
				t.Fatal("exact commit-last mismatch removal")
			}
		} else if len(out.mismatch.removed) != 0 || !reflect.DeepEqual(out.mismatch.image.next, s.prior) {
			t.Fatal("chunk-last mismatch preserves B")
		}
	}
}

func TestDACompleteSnapshotIsolation(t *testing.T) {
	for _, commitLast := range []bool{true, false} {
		f, a, c := daCompleteTestCandidate(t, commitLast, 1, 1)
		s := daCompleteTestCapture(t, f, c)
		wantCandidate := slices.Clone(s.candidate.member.txBytes)
		wantInputs := slices.Clone(s.candidate.member.member.inputs)
		wantPrior := s.prior.cloneOwnerReady()
		c.member.txBytes[0] ^= 1
		c.member.member.inputs[0].Vout++
		live := f.relay.sets[[32]byte{1}]
		if commitLast {
			live.chunks[0].txBytes[0] ^= 1
			live.chunks[0].member.inputs[0].Vout++
		} else {
			live.commit.txBytes[0] ^= 1
			live.commit.member.inputs[0].Vout++
		}
		if !slices.Equal(s.candidate.member.txBytes, wantCandidate) || !slices.Equal(s.candidate.member.member.inputs, wantInputs) || !reflect.DeepEqual(s.prior, wantPrior) || len(s.locators) != len(wantPrior.locatorRows()) {
			t.Fatal("candidate/target snapshot aliases caller or live state")
		}
		out, err := daCompleteTestPrepare(t, f, a, s)
		if err != nil || out.prepared == nil {
			t.Fatal("off-lock parse uses owned target bytes", err)
		}
	}
}

func TestDACompleteSnapshotIntegrity(t *testing.T) {
	t.Run("set parse before fee overflow", func(t *testing.T) {
		f, a, c := daCompleteTestCandidate(t, true, 2, 0)
		s := daCompleteTestCapture(t, f, c)
		s.prior.chunks[0].member.fee = consensus.Uint128{Hi: math.MaxUint64, Lo: math.MaxUint64}
		s.prior.chunks[3].member.fee = consensus.Uint128{Lo: 1}
		invalid := s.prior.chunks[4]
		invalid.txBytes = []byte{0}
		s.prior.chunks[4] = invalid
		out, err := daCompleteTestPrepare(t, f, a, s)
		if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
			t.Fatal("candidate set parse must precede fee overflow", err)
		}
	})
	for _, row := range []struct {
		name   string
		change func(*daCompleteSnapshot)
	}{
		{"parse", func(s *daCompleteSnapshot) { daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.txBytes = []byte{0} }) }},
		{"trailing", func(s *daCompleteSnapshot) {
			daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.txBytes = append(ch.txBytes, 0) })
		}},
		{"txid", func(s *daCompleteSnapshot) { daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.member.txid[0] ^= 1 }) }},
		{"same txid different wtxid", func(s *daCompleteSnapshot) {
			daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.member.wtxid[0] ^= 1 })
		}},
		{"input order", func(s *daCompleteSnapshot) {
			daCompleteTestChunk(s, func(ch *daRelayChunk) { slices.Reverse(ch.member.inputs) })
		}},
		{"chunk id", func(s *daCompleteSnapshot) { daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.daID[0] ^= 1 }) }},
		{"chunk index", func(s *daCompleteSnapshot) { daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.chunkIndex = 1 }) }},
		{"missing member", func(s *daCompleteSnapshot) { daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.member = nil }) }},
		{"provenance invalid", func(s *daCompleteSnapshot) {
			daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.member.provenance = DAProvenance{} })
		}},
		{"peer missing identity", func(s *daCompleteSnapshot) {
			daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.member.provenance.peerIdentity = "" })
		}},
		{"peer missing quota", func(s *daCompleteSnapshot) {
			daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.member.provenance.quotaIdentity = "" })
		}},
		{"local extra quota", func(s *daCompleteSnapshot) { s.candidate.member.member.provenance.quotaIdentity = "extra" }},
		{"zero token", func(s *daCompleteSnapshot) {
			daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.member.token = PendingOutpointToken{} })
		}},
		{"foreign token", func(s *daCompleteSnapshot) {
			daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.member.token.owner = &PendingOutpointOwner{} })
		}},
		{"completing token", func(s *daCompleteSnapshot) { s.candidate.member.member.token = s.prior.chunks[0].member.token }},
		{"missing locator", func(s *daCompleteSnapshot) { delete(s.locators, s.prior.chunks[0].member.txid) }},
		{"wrong locator", func(s *daCompleteSnapshot) {
			s.locators[s.prior.chunks[0].member.txid] = daRelayLocator{daID: s.prior.daID, kind: daRelayLocatorCommit}
		}},
		{"pruned canonical corruption", func(s *daCompleteSnapshot) { ch := s.prior.chunks[3]; ch.txBytes = []byte{0}; s.prior.chunks[3] = ch }},
		{"not completing", func(s *daCompleteSnapshot) { delete(s.prior.chunks, 0) }},
		{"already C", func(s *daCompleteSnapshot) { s.prior.state = daRelayStateCompleteSet }},
		{"unknown state", func(s *daCompleteSnapshot) { s.prior.state = 255 }},
		{"wrong completing role", func(s *daCompleteSnapshot) { s.candidate.member.locator.kind = daRelayLocatorChunk }},
		{"unknown completing role", func(s *daCompleteSnapshot) { s.candidate.member.locator.kind = 0 }},
		{"commit index", func(s *daCompleteSnapshot) { s.candidate.member.locator.chunkIndex = 1 }},
		{"commit chunk residue", func(s *daCompleteSnapshot) { s.candidate.chunkHash[0] = 1 }},
		{"declared count", func(s *daCompleteSnapshot) { s.candidate.chunkCount = 2 }},
		{"commitment output", func(s *daCompleteSnapshot) { s.candidate.payloadCommitment[0] ^= 1 }},
		{"prior revision zero", func(s *daCompleteSnapshot) { s.prior.revision = 0 }},
		{"prior sequence zero", func(s *daCompleteSnapshot) { s.prior.receivedTime = 0 }},
		{"prior ttl", func(s *daCompleteSnapshot) { s.prior.ttlBlocksRemaining = 0 }},
		{"prior wire", func(s *daCompleteSnapshot) { s.prior.wireBytes = 1 }},
		{"prior payload", func(s *daCompleteSnapshot) { s.prior.payloadBytes = 1 }},
		{"prior replaceable", func(s *daCompleteSnapshot) { s.prior.replaceableChunks = map[uint16]bool{} }},
		{"prior chunk wire", func(s *daCompleteSnapshot) { daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.wireBytes = 1 }) }},
		{"prior chunk quota", func(s *daCompleteSnapshot) { daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.peerQuotaKey = "x" }) }},
		{"prior chunk hash checked", func(s *daCompleteSnapshot) { daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.hashChecked = true }) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, true, 1, 0)
			s := daCompleteTestCapture(t, f, c)
			row.change(s)
			out, err := daCompleteTestPrepare(t, f, a, s)
			if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
				t.Fatalf("candidate integrity %s: %+v %v", row.name, out, err)
			}
		})
	}
	t.Run("chunk candidate role residues", func(t *testing.T) {
		for _, field := range []string{"count", "commitment", "outside commit"} {
			t.Run(field, func(t *testing.T) {
				f, a, c := daCompleteTestCandidate(t, false, 0, 0)
				s := daCompleteTestCapture(t, f, c)
				switch field {
				case "count":
					s.candidate.chunkCount = 1
				case "commitment":
					s.candidate.payloadCommitment[0] = 1
				case "outside commit":
					s.candidate.member.locator.chunkIndex = 1
				}
				out, err := daCompleteTestPrepare(t, f, a, s)
				if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
					t.Fatal("chunk candidate role residue", field, err)
				}
			})
		}
	})
	for _, row := range []struct {
		name   string
		change func(*daRelaySetRecord)
	}{
		{"missing descriptor", func(r *daRelaySetRecord) { r.completeIntrinsic = daCompleteCapacitySet{} }},
		{"zero total bytes", func(r *daRelaySetRecord) { r.completeIntrinsic.totalBytes = 0 }},
		{"intrinsic descriptor", func(r *daRelaySetRecord) { r.completeIntrinsic.totalBytes++ }},
		{"fee descriptor", func(r *daRelaySetRecord) { r.commit.member.fee.Lo++ }},
		{"record identity", func(r *daRelaySetRecord) { r.daID[0]++ }},
		{"payload total", func(r *daRelaySetRecord) { r.payloadBytes++ }},
		{"payload shadow", func(r *daRelaySetRecord) { ch := r.chunks[0]; ch.payload = []byte{}; r.chunks[0] = ch }},
		{"payload nonempty shadow", func(r *daRelaySetRecord) { ch := r.chunks[0]; ch.payload = []byte{1}; r.chunks[0] = ch }},
		{"revision zero", func(r *daRelaySetRecord) { r.revision = 0 }},
		{"revision high", func(r *daRelaySetRecord) { r.revision = math.MaxUint64 }},
		{"sequence zero", func(r *daRelaySetRecord) { r.receivedTime = 0 }},
		{"sequence high", func(r *daRelaySetRecord) { r.receivedTime = math.MaxUint64 }},
		{"TTL", func(r *daRelaySetRecord) { r.ttlBlocksRemaining = 1 }},
		{"replaceable", func(r *daRelaySetRecord) { r.replaceableChunks = map[uint16]bool{} }},
		{"record wire", func(r *daRelaySetRecord) { r.wireBytes = 1 }},
		{"commit wire", func(r *daRelaySetRecord) { r.commit.wireBytes = 1 }},
		{"commit quota", func(r *daRelaySetRecord) { r.commit.peerQuotaKey = "x" }},
		{"commit id", func(r *daRelaySetRecord) { r.commit.daID[0] ^= 1 }},
		{"chunk wire", func(r *daRelaySetRecord) { ch := r.chunks[0]; ch.wireBytes = 1; r.chunks[0] = ch }},
		{"chunk quota", func(r *daRelaySetRecord) { ch := r.chunks[0]; ch.peerQuotaKey = "x"; r.chunks[0] = ch }},
		{"chunk hash checked", func(r *daRelaySetRecord) { ch := r.chunks[0]; ch.hashChecked = true; r.chunks[0] = ch }},
		{"chunk id", func(r *daRelaySetRecord) { ch := r.chunks[0]; ch.daID[0]++; r.chunks[0] = ch }},
		{"chunk index", func(r *daRelaySetRecord) { ch := r.chunks[0]; ch.chunkIndex++; r.chunks[0] = ch }},
		{"absent chunk", func(r *daRelaySetRecord) { delete(r.chunks, 0) }},
		{"extra chunk", func(r *daRelaySetRecord) { r.chunks[1] = r.chunks[0] }},
		{"missing commit", func(r *daRelaySetRecord) { r.commit.member = nil }},
		{"token zero", func(r *daRelaySetRecord) { r.commit.member.token = PendingOutpointToken{} }},
		{"token foreign", func(r *daRelaySetRecord) { r.commit.member.token.owner = &PendingOutpointOwner{} }},
		{"duplicate member token", func(r *daRelaySetRecord) { r.chunks[0].member.token = r.commit.member.token }},
		{"fee overflow", func(r *daRelaySetRecord) {
			r.commit.member.fee = consensus.Uint128{Hi: math.MaxUint64, Lo: math.MaxUint64}
			r.chunks[0].member.fee = consensus.Uint128{Lo: 1}
		}},
	} {
		t.Run("resident "+row.name, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, true, 1, 2)
			s := daCompleteTestCapture(t, f, c)
			out, err := daCompleteTestPrepare(t, f, a, s)
			if err != nil || out.prepared == nil {
				t.Fatal(err)
			}
			r := f.relay.sets[[32]byte{12}].cloneOwnerReady()
			row.change(&r)
			f.relay.sets[[32]byte{12}] = r
			requireDACompleteImageRefusal(t, f, a, out)
		})
	}
	for _, field := range []string{"missing C locator", "extra C locator", "wrong C locator", "duplicate target token"} {
		t.Run(field, func(t *testing.T) {
			f, a, c := daCompleteTestCandidate(t, true, 0, 2)
			s := daCompleteTestCapture(t, f, c)
			out, err := daCompleteTestPrepare(t, f, a, s)
			if err != nil {
				t.Fatal(err)
			}
			r := f.relay.sets[[32]byte{12}]
			switch field {
			case "missing C locator":
				delete(f.relay.locators, r.commit.member.txid)
			case "extra C locator":
				f.relay.locators[[32]byte{99}] = daRelayLocator{daID: r.daID, kind: daRelayLocatorCommit}
			case "wrong C locator":
				f.relay.locators[r.commit.member.txid] = daRelayLocator{daID: r.daID, kind: daRelayLocatorChunk}
			case "duplicate target token":
				r.commit.member.token = s.prior.chunks[0].member.token
				f.relay.sets[r.daID] = r
			}
			requireDACompleteImageRefusal(t, f, a, out)
		})
	}
	t.Run("capture target only", func(t *testing.T) {
		for _, name := range []string{"absent", "nil sets", "nil locators", "prior key", "locator missing", "locator duplicate slot"} {
			f, _, c := daCompleteTestCandidate(t, true, 1, 1)
			switch name {
			case "absent":
				delete(f.relay.sets, [32]byte{1})
			case "nil sets":
				f.relay.sets = nil
			case "nil locators":
				f.relay.locators = nil
			case "prior key":
				r := f.relay.sets[[32]byte{1}]
				r.daID[0]++
				f.relay.sets[[32]byte{1}] = r
			case "locator missing":
				delete(f.relay.locators, f.relay.sets[[32]byte{1}].chunks[0].member.txid)
			case "locator duplicate slot":
				r := f.relay.sets[[32]byte{1}]
				ch := r.chunks[3]
				ch.member = r.chunks[0].member.clone()
				r.chunks[3] = ch
				f.relay.sets[r.daID] = r
			}
			got, dup, err := f.relay.captureDACompleteSnapshot(c)
			if got != nil || dup != (daRelayAdmissionOutcome{}) || !daCompleteTestError(err, errDARelayImageIncompatible) {
				t.Fatal("target-only capture", name, err)
			}
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		f, _, c := daCompleteTestCandidate(t, true, 1, 0)
		c.member.member = *f.relay.sets[[32]byte{1}].chunks[0].member.clone()
		delete(f.relay.sets, [32]byte{1}) // duplicate wins over a missing target
		s, duplicate, err := f.relay.captureDACompleteSnapshot(c)
		want := daRelayAdmissionOutcome{daID: [32]byte{1}, disposition: 2}
		if err != nil || s != nil || duplicate != want {
			t.Fatal("duplicate before target capture", err)
		}
		out, err := prepareDACompleteSnapshot(s, duplicate)
		if err != nil || out.duplicate == nil || *out.duplicate != want {
			t.Fatal("duplicate preparation", err)
		}
	})
	t.Run("commit duplicate outcome", func(t *testing.T) {
		f, _, c := daCompleteTestCandidate(t, false, 0, 0)
		prior := f.relay.sets[[32]byte{1}]
		for _, same := range []bool{true, false} {
			candidate := c
			candidate.member.locator = daRelayLocator{daID: prior.daID, kind: daRelayLocatorCommit}
			if same {
				candidate.member.member.txid = prior.commit.member.txid
			}
			s, duplicate, err := f.relay.captureDACompleteSnapshot(candidate)
			want := daRelayAdmissionOutcome{daID: [32]byte{1}, disposition: 2, sameDAIDCommitConflict: !same}
			if err != nil || s != nil || duplicate != want {
				t.Fatal("same/competing commit", err)
			}
		}
	})
}

func TestDACompleteResidentNoRawTouch(t *testing.T) {
	f, a, c, residents := daCompleteCommitPhysicalVictims(t, 1)
	p, _ := daCompleteCommitTestPlan(t, f, a, c)
	victim := residents[0]
	corrupt := f.relay.sets[victim.daID].cloneOwnerReady()
	corrupt.commit.txBytes[0] ^= 1
	f.relay.sets[victim.daID] = corrupt
	if !daCompleteTestError(checkOwnerReadyRetainedRecordLocked(corrupt), errDARelayImageIncompatible) {
		t.Fatal("canonical removal must still reject corrupt retained bytes")
	}
	beforeSequence, beforeHigh := f.relay.nextReceivedTime, f.mp.pendingOutpoints.tokenHighWater
	daCompleteCommitTestApply(t, f, a, p)
	if !slices.Equal(p.capacity.victims, [][32]byte{victim.daID}) || f.relay.completeCount != 65536 || f.relay.pinnedPayloadBytes != 65535+16 || f.relay.nextReceivedTime != beforeSequence+1 || f.mp.pendingOutpoints.tokenHighWater != beforeHigh+1 {
		t.Fatal("completion read resident raw bytes or ignored metadata victim order")
	}
	if _, present := f.relay.sets[victim.daID]; present {
		t.Fatal("metadata-selected victim survived")
	}
	for _, member := range []*daRelayMemberIdentity{victim.commit.member, victim.chunks[0].member} {
		if f.mp.pendingOutpoints.byToken[member.token] != nil || f.relay.locators[member.txid] != (daRelayLocator{}) {
			t.Fatal("metadata-selected victim claim or locator survived")
		}
	}
	measure := func(large bool) uint64 {
		f, a, c := daCompleteTestCandidate(t, true, 0, 0)
		id := [32]byte{11}
		f.completeReplayPinned(id)
		if large {
			record := f.relay.sets[id]
			chunk := record.chunks[0]
			delta := uint64(8<<20 - len(chunk.txBytes))
			chunk.txBytes = make([]byte, 8<<20) // actual owned C bytes, not an inflated counter alone
			record.chunks[0] = chunk
			record.completeIntrinsic.totalBytes += delta
			f.relay.sets[id], f.relay.completeBytes = record, f.relay.completeBytes+delta
		}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		source, duplicate, err := f.relay.captureDACompleteSnapshot(c)
		if err != nil || duplicate != (daRelayAdmissionOutcome{}) {
			t.Fatal("first DA capture", err)
		}
		result, err := prepareDACompleteSnapshot(source, duplicate)
		if err != nil {
			t.Fatal("off-DA preparation", err)
		}
		plan, err := f.relay.prepareDACompleteCommit(a, result)
		if err != nil {
			t.Fatal("commit preparation", err)
		}
		out, rejected, err := f.relay.applyDACompleteCommit(a, plan)
		runtime.ReadMemStats(&after)
		if err != nil || rejected || out != (daRelayAdmissionOutcome{daID: [32]byte{1}, disposition: daRelayAdmissionRetained}) || f.relay.completeCount != 2 || len(plan.capacity.victims) != 0 {
			t.Fatal("full completion attempt with C owned bytes", err)
		}
		return after.TotalAlloc - before.TotalAlloc
	}
	small, large := measure(false), measure(true)
	if large > small+(4<<20) {
		t.Fatalf("completion cloned resident bytes: small=%d large=%d", small, large)
	}
}

func TestDACompleteSnapshotCaptureBound(t *testing.T) {
	f, _, c := daCompleteTestCandidate(t, true, 0, 0)
	for i := 0; i <= 65536; i++ {
		id := [32]byte{2, byte(i), byte(i >> 8), byte(i >> 16)}
		f.relay.sets[id] = daRelaySetRecord{daID: id, state: daRelayStateCompleteSet}
	}
	s, duplicate, err := f.relay.captureDACompleteSnapshot(c)
	if len(f.relay.sets) != 65538 || err != nil || s == nil || duplicate != (daRelayAdmissionOutcome{}) || len(s.locators) != 1 {
		t.Fatal("65537 distinct C residents changed target-only first DA capture", err)
	}
}
