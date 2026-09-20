package node

import (
	"crypto/sha3"
	"errors"
	"math"
	"reflect"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func daCompleteTestError(err, want error) bool {
	return errors.Is(err, want) && reflect.TypeOf(err) == reflect.TypeOf(want)
}

// Signed fixture bytes and real admission tokens supply identity/provenance.
// Direct fee edits in Accounting below are sum-layer evidence only.
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

func TestDACompleteSnapshotPublicationBase(t *testing.T) {
	f, _, c := daCompleteTestCandidate(t, true, 1, 1)
	unrelated := f.signed(daNonReplayTxSpec{kind: 2, daID: [32]byte{90}, payload: []byte{9}})
	f.admit(unrelated, LocalDAProvenance())
	s := daCompleteTestCapture(t, f, c)
	if s.publicationBase == nil {
		t.Fatal("publication base must share the first coherent capture")
	}
	base := daRelayStateSnapshot(s.publicationBase)
	baseOwner := cloneDAAdmissionOwner(s.owner)
	requireDANonReplayUnchanged(t, s.publicationBase, s.owner, daRelayStateSnapshot(f.relay), cloneDAAdmissionOwner(f.mp.pendingOutpoints))
	delete(f.relay.locators, unrelated.txid)
	r := f.relay.sets[unrelated.spec.daID]
	r.ttlBlocksRemaining--
	f.relay.sets[r.daID] = r
	f.relay.sets[[32]byte{1}].chunks[0].txBytes[0]++
	requireDANonReplayUnchanged(t, s.publicationBase, s.owner, base, baseOwner)
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

func daCompleteTestChunk(s *daCompleteSnapshot, mutate func(*daRelayChunk)) {
	c := s.prior.chunks[0]
	mutate(&c)
	s.prior.chunks[0] = c
}

func TestDACompleteSnapshotPlannerInput(t *testing.T) {
	for _, commitLast := range []bool{true, false} {
		for _, residents := range []int{0, 1, 2} {
			f, a, c := daCompleteTestCandidate(t, commitLast, 0, residents)
			s := daCompleteTestCapture(t, f, c)
			result, err := daCompleteTestPrepare(t, f, a, s)
			if err != nil || result.prepared == nil || result.duplicate != nil || result.mismatch != nil {
				t.Fatalf("prepared planner input: result=%+v err=%v", result, err)
			}
			p := result.prepared
			priorRaw, payload, credit := uint64(0), uint64(0), uint64(0)
			if commitLast {
				priorRaw = uint64(len(s.prior.chunks[0].txBytes))
				payload = uint64(len(s.prior.chunks[0].payload))
			} else {
				priorRaw = uint64(len(s.prior.commit.txBytes))
				payload = uint64(len(c.member.payload))
				credit = priorRaw
			}
			want := daCompleteCapacityInput{
				byteCap: 536870912, stagedBytes: credit, priorCredit: credit,
				completeBytes: f.relay.completeBytes, completeCount: uint64(residents), completePayload: uint64(residents),
				candidate: daCompleteCapacitySet{id: [32]byte{1}, fee: consensus.Uint128{Lo: 1200000}, totalBytes: priorRaw + uint64(len(c.member.txBytes)), payloadBytes: payload, receivedSequence: s.prior.receivedTime},
			}
			for i := 1; i <= residents; i++ {
				r := f.relay.sets[[32]byte{byte(10 + i)}]
				want.residents = append(want.residents, daCompleteCapacitySet{id: [32]byte{byte(10 + i)}, fee: consensus.Uint128{Lo: 1200000}, totalBytes: uint64(len(r.commit.txBytes) + len(r.chunks[0].txBytes)), payloadBytes: 1, receivedSequence: r.receivedTime})
			}
			if !reflect.DeepEqual(p.input, want) || p.source != s {
				t.Fatalf("prepared planner input: got=%+v want=%+v", p.input, want)
			}
			plan, err := planDACompleteCapacity(p.input)
			wantPlan := daCompleteCapacityPlan{accepted: true, sharedBytes: want.completeBytes + want.candidate.totalBytes, completeCount: uint64(residents + 1), payloadBytes: uint64(residents) + payload}
			if err != nil || !reflect.DeepEqual(plan, wantPlan) {
				t.Fatalf("prepared planner input: plan=%+v want=%+v err=%v", plan, wantPlan, err)
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
		want := daCompleteCapacityInput{byteCap: 536870912, candidate: daCompleteCapacitySet{
			id:  id,
			fee: consensus.Uint128{Lo: 1800000}, totalBytes: uint64(len(first.raw) + len(second.raw) + len(commit.raw)), payloadBytes: 9, receivedSequence: 1,
		}}
		if err != nil || out.prepared == nil || out.mismatch != nil || out.duplicate != nil || !reflect.DeepEqual(out.prepared.input, want) {
			t.Fatal("prepared planner input: ascending chunks", err)
		}
		r := out.prepared.image.next
		if !slices.Equal(r.chunks[0].member.inputs, first.inputs) || !slices.Equal(r.chunks[1].member.inputs, second.inputs) || !slices.Equal(r.commit.member.inputs, commit.inputs) || r.chunks[0].member.token.seq != 2 || r.chunks[1].member.token.seq != 1 || r.commit.chunkCount != 2 {
			t.Fatal("prepared planner input: exact retained members")
		}
		plan, err := planDACompleteCapacity(out.prepared.input)
		if err != nil || !reflect.DeepEqual(plan, daCompleteCapacityPlan{accepted: true, sharedBytes: want.candidate.totalBytes, completeCount: 1, payloadBytes: 9}) {
			t.Fatal("prepared planner input: ascending plan", err)
		}
	})
}

func TestDACompleteSnapshotPrune(t *testing.T) {
	for _, count := range []int{0, 1, 2} {
		f, a, c := daCompleteTestCandidate(t, true, count, 0)
		s := daCompleteTestCapture(t, f, c)
		if count == 2 { // Synthetic sum-layer witness: pruned fees do not aggregate.
			s.prior.chunks[3].member.fee = consensus.Uint128{Hi: math.MaxUint64, Lo: math.MaxUint64}
			s.prior.chunks[4].member.fee = consensus.Uint128{Lo: 1}
		}
		result, err := daCompleteTestPrepare(t, f, a, s)
		if err != nil || result.prepared == nil {
			t.Fatalf("exact isolated prune evidence: %v", err)
		}
		p := result.prepared
		var want []DAAdmissionVictim
		for i := 0; i < count; i++ {
			m := s.prior.chunks[uint16(i+3)].member
			want = append(want, DAAdmissionVictim{TxID: m.txid, Token: m.token, Inputs: slices.Clone(m.inputs)})
		}
		if !reflect.DeepEqual(p.pruned, want) || len(p.image.next.chunks) != 1 || p.input.candidate.fee != (consensus.Uint128{Lo: 1200000}) || p.input.candidate.totalBytes != uint64(len(c.member.txBytes)+len(s.prior.chunks[0].txBytes)) {
			t.Fatal("exact isolated prune evidence")
		}
	}
}

func TestDACompleteSnapshotRepresentation(t *testing.T) {
	f, a, c := daCompleteTestCandidate(t, true, 0, 1)
	for _, shadow := range [][]byte{nil, {}, {1}} {
		r := f.relay.sets[[32]byte{11}]
		chunk := r.chunks[0]
		chunk.payload = shadow
		r.chunks[0] = chunk
		s := daCompleteTestCapture(t, f, c)
		out, err := daCompleteTestPrepare(t, f, a, s)
		if shadow == nil {
			if err != nil || out.prepared == nil {
				t.Fatal("complete representation binding: live nil shadow", err)
			}
		} else if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
			t.Fatal("complete representation binding: live nonnil shadow", err)
		}
		live := f.relay.sets[[32]byte{11}].chunks[0].payload
		if (live == nil) != (shadow == nil) || !slices.Equal(live, shadow) {
			t.Fatal("complete representation binding: live shadow changed")
		}
		s.nextReceivedTime = math.MaxUint64
		out, err = daCompleteTestPrepare(t, f, a, s)
		if !daCompleteTestError(err, errDARelayArithmeticOverflow) || out != (daCompletePreparation{}) {
			t.Fatal("complete representation binding: sequence precedes resident shadow", err)
		}
		chunk.payload = nil
		r.chunks[0] = chunk
	}
	t.Run("chunk last retained token", func(t *testing.T) {
		f, a, c := daCompleteTestCandidate(t, false, 0, 0)
		s := daCompleteTestCapture(t, f, c)
		out, err := daCompleteTestPrepare(t, f, a, s)
		if err != nil || out.prepared == nil || out.prepared.image.next.commit.member.token != s.prior.commit.member.token || out.prepared.image.next.receivedTime != s.prior.receivedTime {
			t.Fatal("complete representation binding", err)
		}
	})
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
			t.Fatal("complete representation binding", err)
		}
	})
	for _, row := range []struct {
		name   string
		change func(*daCompleteSnapshot)
	}{
		{"C shadow", func(s *daCompleteSnapshot) {
			r := &s.residents[0]
			ch := r.chunks[0]
			ch.payload = []byte{1}
			r.chunks[0] = ch
		}},
		{"C empty nonnil shadow", func(s *daCompleteSnapshot) {
			r := &s.residents[0]
			ch := r.chunks[0]
			ch.payload = []byte{}
			r.chunks[0] = ch
		}},
		{"incomplete cache", func(s *daCompleteSnapshot) { daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.payload[0] ^= 1 }) }},
		{"incomplete hash", func(s *daCompleteSnapshot) { daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.chunkHash[0] ^= 1 }) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			s := daCompleteTestCapture(t, f, c)
			row.change(s)
			out, err := daCompleteTestPrepare(t, f, a, s)
			if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
				t.Fatalf("complete representation binding: %+v %v", out, err)
			}
		})
	}
	s := daCompleteTestCapture(t, f, c)
	out, err := daCompleteTestPrepare(t, f, a, s)
	if err != nil || out.prepared == nil {
		t.Fatal("complete representation binding", err)
	}
	r := out.prepared.image.next
	if r.state != daRelaySetState(2) || r.ttlBlocksRemaining != 0 || r.payloadBytes != 16 || r.replaceableChunks != nil || r.wireBytes != 0 || r.chunks[0].payload != nil || r.revision != s.prior.revision || r.receivedTime != s.prior.receivedTime || r.chunks[0].member.token != s.prior.chunks[0].member.token || r.commit.member.token != (PendingOutpointToken{}) {
		t.Fatal("complete representation binding")
	}
	if !reflect.DeepEqual(r.chunks[0].txBytes, s.prior.chunks[0].txBytes) || !reflect.DeepEqual(r.commit.txBytes, c.member.txBytes) {
		t.Fatal("complete representation binding: retained bytes")
	}
}

func TestDACompleteSnapshotAccounting(t *testing.T) {
	f, a, c := daCompleteTestCandidate(t, false, 0, 2)
	s := daCompleteTestCapture(t, f, c)
	baseline, err := daCompleteTestPrepare(t, f, a, s)
	if err != nil || baseline.prepared == nil || baseline.prepared.input.priorCredit != uint64(len(s.prior.commit.txBytes)) {
		t.Fatal("captured totals or prior credit", err)
	}
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
					t.Fatal("exact arithmetic overflow", err)
				}
				return
			}
			if err != nil || out.prepared == nil || out.prepared.input.candidate.fee != row.want {
				t.Fatal("exact retained accounting", err)
			}
			if out.prepared.input.priorCredit != uint64(len(s.prior.commit.txBytes)) || out.prepared.input.residents[0].totalBytes != uint64(len(s.residents[0].commit.txBytes)+len(s.residents[0].chunks[0].txBytes)) {
				t.Fatal("captured totals or prior credit")
			}
		})
	}
	for _, field := range []string{"bytes", "count", "payload", "staged", "byte cap"} {
		t.Run(field, func(t *testing.T) {
			s := daCompleteTestCapture(t, f, c)
			switch field {
			case "bytes":
				s.input.completeBytes++
			case "count":
				s.input.completeCount++
			case "payload":
				s.input.completePayload++
			case "staged":
				s.input.stagedBytes = 0
			case "byte cap":
				s.input.byteCap = 536870911
			}
			out, err := daCompleteTestPrepare(t, f, a, s)
			if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
				t.Fatal("captured totals or prior credit", err)
			}
		})
	}
	t.Run("resident sum overflow", func(t *testing.T) {
		s := daCompleteTestCapture(t, f, c)
		s.residents[0].commit.member.fee = consensus.Uint128{Hi: math.MaxUint64, Lo: math.MaxUint64}
		out, err := daCompleteTestPrepare(t, f, a, s)
		if !daCompleteTestError(err, errDARelayArithmeticOverflow) || out != (daCompletePreparation{}) {
			t.Fatal("exact arithmetic overflow", err)
		}
	})
	for _, field := range []string{"live bytes", "live count", "live payload"} {
		t.Run(field, func(t *testing.T) {
			originalBytes, originalCount, originalPayload := f.relay.completeBytes, f.relay.completeCount, f.relay.pinnedPayloadBytes
			defer func() {
				f.relay.completeBytes, f.relay.completeCount, f.relay.pinnedPayloadBytes = originalBytes, originalCount, originalPayload
			}()
			switch field {
			case "live bytes":
				f.relay.completeBytes++
			case "live count":
				f.relay.completeCount++
			case "live payload":
				f.relay.pinnedPayloadBytes++
			}
			s := daCompleteTestCapture(t, f, c)
			if s.input.completeBytes != f.relay.completeBytes || s.input.completeCount != f.relay.completeCount || s.input.completePayload != f.relay.pinnedPayloadBytes {
				t.Fatal("captured totals or prior credit")
			}
			out, err := daCompleteTestPrepare(t, f, a, s)
			if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
				t.Fatal("captured totals or prior credit", err)
			}
		})
	}
	t.Run("oversized scalar never hides last resident", func(t *testing.T) {
		s := daCompleteTestCapture(t, f, c)
		for i := range s.residents {
			if s.residents[i].daID == ([32]byte{12}) {
				s.residents[i].payloadBytes++
			}
		}
		// This is the source-to-scalar boundary, not a synthetic parsing claim.
		in, err := s.capacityInput(daCompleteCapacitySet{id: [32]byte{1}, totalBytes: 536870913, receivedSequence: 1})
		if !daCompleteTestError(err, errDARelayImageIncompatible) || !reflect.DeepEqual(in, daCompleteCapacityInput{}) {
			t.Fatal("captured totals or prior credit", err)
		}
	})
}

func TestDACompleteSnapshotMismatch(t *testing.T) {
	for _, commitLast := range []bool{true, false} {
		f, a, c := daCompleteTestCandidate(t, commitLast, 2, 1)
		// Change canonical bytes and the bound descriptor together. The signed
		// alternate is only a commitment-mismatch witness, not a new admission.
		wrong := f.signed(daNonReplayTxSpec{kind: 1, daID: [32]byte{1}, chunkCount: 1, commitment: [32]byte{99}, commitmentOutputs: 1})
		resident := f.relay.sets[[32]byte{11}]
		shadow := resident.chunks[0]
		shadow.payload = []byte{}
		resident.chunks[0] = shadow
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
		s.nextReceivedTime = math.MaxUint64
		s.residents[0].commit.txBytes = []byte{0} // No resident parse on mismatch.
		out, err := daCompleteTestPrepare(t, f, a, s)
		if err != nil || out.mismatch == nil || out.prepared != nil || out.duplicate != nil {
			t.Fatal("mismatch before sequence and capacity", err)
		}
		m := out.mismatch
		if m.kind != c.member.locator.kind || m.source != s {
			t.Fatal("mismatch before sequence and capacity: role")
		}
		if commitLast {
			var want []DAAdmissionVictim
			for _, index := range []uint16{0, 3, 4} {
				member := s.prior.chunks[index].member
				want = append(want, DAAdmissionVictim{TxID: member.txid, Token: member.token, Inputs: slices.Clone(member.inputs)})
			}
			if !reflect.DeepEqual(m.removed, want) || len(m.image.next.chunks) != 0 || m.image.next.state != daRelaySetState(1) || m.image.next.commit.member.txid != wrong.txid {
				t.Fatal("exact mismatch removal set")
			}
		} else if len(m.removed) != 0 || !reflect.DeepEqual(m.image.next, s.prior) {
			t.Fatal("exact mismatch removal set")
		}
	}
	t.Run("chunk last retained sibling", func(t *testing.T) {
		f := newDANonReplayFixture(t, 4)
		id := [32]byte{42}
		commit := f.signed(daNonReplayTxSpec{kind: 1, daID: id, chunkCount: 2, commitment: [32]byte{99}, commitmentOutputs: 1})
		f.admit(commit, LocalDAProvenance())
		first := f.signed(daNonReplayTxSpec{kind: 2, daID: id, payload: []byte{1}})
		f.admit(first, LocalDAProvenance())
		last := f.signed(daNonReplayTxSpec{kind: 2, daID: id, chunkIndex: 1, payload: []byte{2}})
		a := f.begin(last)
		defer a.Close()
		c, err := a.renderDARelayAdmissionCandidate(LocalDAProvenance())
		if err != nil {
			t.Fatal(err)
		}
		s := daCompleteTestCapture(t, f, c)
		s.nextReceivedTime = math.MaxUint64
		out, err := daCompleteTestPrepare(t, f, a, s)
		if err != nil || out.mismatch == nil || out.prepared != nil || out.duplicate != nil {
			t.Fatal("mismatch before sequence and capacity", err)
		}
		if len(out.mismatch.removed) != 0 || !reflect.DeepEqual(out.mismatch.image.next, s.prior) || len(out.mismatch.image.next.chunks) != 1 {
			t.Fatal("exact mismatch removal set")
		}
	})
}

func TestDACompleteSnapshotIsolation(t *testing.T) {
	f, a, c := daCompleteTestCandidate(t, true, 2, 1)
	s := daCompleteTestCapture(t, f, c)
	wantCandidateRaw := slices.Clone(c.member.txBytes)
	wantCandidateInputs := slices.Clone(c.member.member.inputs)
	wantPriorRaw := slices.Clone(s.prior.chunks[0].txBytes)
	wantPayload := slices.Clone(s.prior.chunks[0].payload)
	wantInputs := slices.Clone(s.prior.chunks[0].member.inputs)
	wantToken, wantProvenance := s.prior.chunks[0].member.token, s.prior.chunks[0].member.provenance
	wantResidentRaw := slices.Clone(s.residents[0].commit.txBytes)
	wantResidentInputs := slices.Clone(s.residents[0].commit.member.inputs)
	wantLocator := s.locators[s.residents[0].commit.member.txid]
	// Independently exercise each capture ownership boundary.
	c.member.txBytes[0] ^= 1
	c.member.member.inputs[0].Vout++
	r := f.relay.sets[[32]byte{1}]
	r.chunks[0].txBytes[0] ^= 1
	r.chunks[0].payload[0] ^= 1
	r.chunks[0].member.inputs[0].Vout++
	r.chunks[0].member.provenance = DetachedReorgDAProvenance()
	r.chunks[0].member.token.seq++
	delete(r.chunks, 3)
	f.relay.sets[[32]byte{1}] = r
	resident := f.relay.sets[[32]byte{11}]
	resident.commit.txBytes[0] ^= 1
	resident.commit.member.inputs[0].Vout++
	delete(f.relay.locators, resident.commit.member.txid)
	if !slices.Equal(s.candidate.member.txBytes, wantCandidateRaw) || !slices.Equal(s.candidate.member.member.inputs, wantCandidateInputs) || !slices.Equal(s.prior.chunks[0].txBytes, wantPriorRaw) || !slices.Equal(s.prior.chunks[0].payload, wantPayload) || !slices.Equal(s.prior.chunks[0].member.inputs, wantInputs) || s.prior.chunks[0].member.token != wantToken || s.prior.chunks[0].member.provenance != wantProvenance || len(s.prior.chunks) != 3 || !slices.Equal(s.residents[0].commit.txBytes, wantResidentRaw) || !slices.Equal(s.residents[0].commit.member.inputs, wantResidentInputs) || s.locators[s.residents[0].commit.member.txid] != wantLocator {
		t.Fatal("snapshot aliases retained state")
	}
	out, err := daCompleteTestPrepare(t, f, a, s)
	if err != nil || out.prepared == nil {
		t.Fatal(err)
	}
	before := daRelayStateSnapshot(f.relay)
	p := out.prepared
	p.image.next.commit.txBytes[0] ^= 1
	p.image.next.chunks[0].member.inputs[0].Vout++
	p.image.next.chunks[0].member.token.seq++
	p.pruned[0].Inputs[0].Vout++
	p.input.residents[0].fee.Lo++
	requireDARelayStateUnchanged(t, f.relay, before)
	if s.prior.chunks[0].member.token.owner != f.mp.pendingOutpoints {
		t.Fatal("snapshot cloned opaque token owner")
	}
	f, _, c = daCompleteTestCandidate(t, false, 0, 0)
	s = daCompleteTestCapture(t, f, c)
	wantPayload = slices.Clone(c.member.payload)
	wantPriorRaw = slices.Clone(s.prior.commit.txBytes)
	wantInputs = slices.Clone(s.prior.commit.member.inputs)
	c.member.payload[0] ^= 1
	f.relay.sets[[32]byte{1}].commit.txBytes[0] ^= 1
	f.relay.sets[[32]byte{1}].commit.member.inputs[0].Vout++
	if !slices.Equal(s.candidate.member.payload, wantPayload) || !slices.Equal(s.prior.commit.txBytes, wantPriorRaw) || !slices.Equal(s.prior.commit.member.inputs, wantInputs) {
		t.Fatal("snapshot aliases retained state")
	}
}

func TestDACompleteSnapshotIntegrity(t *testing.T) {
	t.Run("set parse before fee overflow", func(t *testing.T) {
		f, a, c := daCompleteTestCandidate(t, true, 2, 0)
		s := daCompleteTestCapture(t, f, c)
		s.prior.chunks[0].member.fee = consensus.Uint128{Hi: math.MaxUint64, Lo: math.MaxUint64}
		s.prior.chunks[3].member.fee = consensus.Uint128{Lo: 1}
		last := s.prior.chunks[4]
		last.txBytes = []byte{0}
		s.prior.chunks[4] = last
		out, err := daCompleteTestPrepare(t, f, a, s)
		if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
			t.Fatal("set parse before fee overflow", err)
		}
	})
	f, a, c := daCompleteTestCandidate(t, true, 1, 2)
	baseline, err := daCompleteTestPrepare(t, f, a, daCompleteTestCapture(t, f, c))
	if err != nil || baseline.prepared == nil || len(baseline.prepared.input.residents) != 2 {
		t.Fatal("resident integrity before capacity", err)
	}
	t.Run("canonical txid binding", func(t *testing.T) {
		s := daCompleteTestCapture(t, f, c)
		ch := s.prior.chunks[0]
		ch.member.txid[0] ^= 1
		_, err := parseDACompleteMember(ch.txBytes, ch.member)
		if !daCompleteTestError(err, errDARelayImageIncompatible) {
			t.Fatal("exact snapshot integrity error", err)
		}
	})
	t.Run("canonical role bindings", func(t *testing.T) {
		for _, field := range []string{"chunk id", "chunk index", "commit id", "commit count", "chunk kind", "commit kind"} {
			t.Run(field, func(t *testing.T) {
				defer func() {
					if recover() != nil {
						t.Fatal("exact snapshot integrity error: role panic")
					}
				}()
				s := daCompleteTestCapture(t, f, c)
				r := s.residents[0]
				var err error
				switch field {
				case "chunk id":
					r.daID[0] ^= 1
					ch := r.chunks[0]
					ch.daID = r.daID
					r.chunks[0] = ch
					_, err = parseDACompleteChunk(r, 0)
				case "chunk index":
					ch := r.chunks[0]
					ch.chunkIndex = 1
					r.chunks[1] = ch
					_, err = parseDACompleteChunk(r, 1)
				case "commit id":
					r.daID[0] ^= 1
					r.commit.daID = r.daID
					err = parseDACompleteCommit(r)
				case "commit count":
					r.commit.chunkCount = 2
					err = parseDACompleteCommit(r)
				case "chunk kind":
					ch := r.chunks[0]
					ch.txBytes, ch.member = r.commit.txBytes, r.commit.member
					r.chunks[0] = ch
					_, err = parseDACompleteChunk(r, 0)
				case "commit kind":
					r.commit.txBytes, r.commit.member = r.chunks[0].txBytes, r.chunks[0].member
					err = parseDACompleteCommit(r)
				}
				if !daCompleteTestError(err, errDARelayImageIncompatible) {
					t.Fatal("exact snapshot integrity error", field, err)
				}
			})
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
		{"extra locator", func(s *daCompleteSnapshot) {
			s.locators[[32]byte{99}] = daRelayLocator{daID: s.prior.daID, kind: daRelayLocatorChunk}
		}},
		{"wrong locator", func(s *daCompleteSnapshot) {
			s.locators[s.prior.chunks[0].member.txid] = daRelayLocator{daID: s.prior.daID, kind: daRelayLocatorCommit}
		}},
		{"pruned canonical corruption", func(s *daCompleteSnapshot) {
			ch := s.prior.chunks[3]
			ch.txBytes = []byte{0}
			s.prior.chunks[3] = ch
		}},
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
		{"prior revision high", func(s *daCompleteSnapshot) { s.prior.revision = s.records + 1 }},
		{"prior sequence zero", func(s *daCompleteSnapshot) { s.prior.receivedTime = 0 }},
		{"prior sequence high", func(s *daCompleteSnapshot) { s.prior.receivedTime = s.nextReceivedTime + 1 }},
		{"prior ttl", func(s *daCompleteSnapshot) { s.prior.ttlBlocksRemaining = 0 }},
		{"prior wire", func(s *daCompleteSnapshot) { s.prior.wireBytes = 1 }},
		{"prior payload", func(s *daCompleteSnapshot) { s.prior.payloadBytes = 1 }},
		{"prior replaceable", func(s *daCompleteSnapshot) { s.prior.replaceableChunks = map[uint16]bool{} }},
		{"prior chunk wire", func(s *daCompleteSnapshot) { daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.wireBytes = 1 }) }},
		{"prior chunk quota", func(s *daCompleteSnapshot) { daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.peerQuotaKey = "x" }) }},
		{"prior chunk hash checked", func(s *daCompleteSnapshot) { daCompleteTestChunk(s, func(ch *daRelayChunk) { ch.hashChecked = true }) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			s := daCompleteTestCapture(t, f, c)
			row.change(s)
			out, err := daCompleteTestPrepare(t, f, a, s)
			if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
				t.Fatalf("exact snapshot integrity error: out=%+v err=%v", out, err)
			}
		})
	}
	t.Run("resident corruption", func(t *testing.T) {
		for _, row := range []struct {
			name   string
			change func(*daRelaySetRecord)
		}{
			{"parse", func(r *daRelaySetRecord) { r.commit.txBytes = []byte{0} }},
			{"payload total", func(r *daRelaySetRecord) { r.payloadBytes++ }},
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
			{"chunk wire", func(r *daRelaySetRecord) {
				ch := r.chunks[0]
				ch.wireBytes = 1
				r.chunks[0] = ch
			}},
			{"chunk quota", func(r *daRelaySetRecord) {
				ch := r.chunks[0]
				ch.peerQuotaKey = "x"
				r.chunks[0] = ch
			}},
			{"chunk hash checked", func(r *daRelaySetRecord) {
				ch := r.chunks[0]
				ch.hashChecked = true
				r.chunks[0] = ch
			}},
			{"absent chunk", func(r *daRelaySetRecord) { delete(r.chunks, 0) }},
			{"extra chunk", func(r *daRelaySetRecord) { r.chunks[1] = r.chunks[0] }},
			{"missing commit", func(r *daRelaySetRecord) { r.commit.member = nil }},
			{"token zero", func(r *daRelaySetRecord) { r.commit.member.token = PendingOutpointToken{} }},
		} {
			t.Run(row.name, func(t *testing.T) {
				s := daCompleteTestCapture(t, f, c)
				// Raw-id last, independently of initial map insertion order.
				for i := range s.residents {
					if s.residents[i].daID == ([32]byte{12}) {
						row.change(&s.residents[i])
					}
				}
				out, err := daCompleteTestPrepare(t, f, a, s)
				if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
					t.Fatal("resident integrity before capacity", err)
				}
			})
		}
	})
	t.Run("sequence", func(t *testing.T) {
		for _, seq := range []uint64{math.MaxUint64 - 1, math.MaxUint64} {
			s := daCompleteTestCapture(t, f, c)
			s.nextReceivedTime = seq
			out, err := daCompleteTestPrepare(t, f, a, s)
			if seq == math.MaxUint64 {
				if !daCompleteTestError(err, errDARelayArithmeticOverflow) || out != (daCompletePreparation{}) {
					t.Fatal("exact arithmetic overflow", err)
				}
			} else if err != nil || out.prepared == nil || out.prepared.input.candidate.receivedSequence != s.prior.receivedTime {
				t.Fatal("last available sequence", err)
			}
		}
	})
	t.Run("capture", func(t *testing.T) {
		for _, row := range []struct {
			name   string
			change func(*DARelayState)
		}{
			{"absent", func(r *DARelayState) { delete(r.sets, [32]byte{1}) }},
			{"nil sets", func(r *DARelayState) { r.sets = nil }},
			{"nil locators", func(r *DARelayState) { r.locators = nil }},
			{"prior key", func(r *DARelayState) {
				p := r.sets[[32]byte{1}]
				p.daID[0] = 8
				r.sets[[32]byte{1}] = p
			}},
			{"resident key", func(r *DARelayState) {
				p := r.sets[[32]byte{11}]
				p.daID[0] = 8
				r.sets[[32]byte{11}] = p
			}},
			{"locator missing", func(r *DARelayState) { delete(r.locators, r.sets[[32]byte{1}].chunks[0].member.txid) }},
			{"locator extra", func(r *DARelayState) {
				r.locators[[32]byte{99}] = daRelayLocator{daID: [32]byte{1}, kind: daRelayLocatorChunk}
			}},
			{"locator duplicate slot", func(r *DARelayState) {
				p := r.sets[[32]byte{1}]
				ch := p.chunks[3]
				ch.member = p.chunks[0].member.clone()
				p.chunks[3] = ch
				r.sets[p.daID] = p
			}},
		} {
			t.Run(row.name, func(t *testing.T) {
				originalSets, originalLocators := f.relay.sets, f.relay.locators
				view := daRelayStateSnapshot(f.relay)
				f.relay.sets, f.relay.locators = view.sets, view.locators
				defer func() { f.relay.sets, f.relay.locators = originalSets, originalLocators }()
				row.change(f.relay)
				before := daRelayStateSnapshot(f.relay)
				s, duplicate, err := f.relay.captureDACompleteSnapshot(c)
				if !daCompleteTestError(err, errDARelayImageIncompatible) || s != nil || duplicate != (daRelayAdmissionOutcome{}) {
					t.Fatal("duplicate or locator closure", err)
				}
				requireDARelayStateUnchanged(t, f.relay, before)
			})
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		retained := f.relay.sets[[32]byte{1}].chunks[0]
		duplicateCandidate := c
		duplicateCandidate.member.member = *retained.member.clone()
		s, duplicate, err := f.relay.captureDACompleteSnapshot(duplicateCandidate)
		want := daRelayAdmissionOutcome{daID: [32]byte{1}, disposition: daRelayAdmissionDisposition(2)}
		if err != nil || s != nil || duplicate != want {
			t.Fatal("duplicate or locator closure", err)
		}
		out, err := prepareDACompleteSnapshot(s, duplicate)
		if err != nil || out.duplicate == nil || *out.duplicate != want || out.prepared != nil || out.mismatch != nil {
			t.Fatal("duplicate or locator closure", err)
		}
	})
	t.Run("token bijection", func(t *testing.T) {
		for _, slot := range []string{"prior prune", "resident commit", "resident chunk"} {
			s := daCompleteTestCapture(t, f, c)
			token := s.prior.chunks[0].member.token
			switch slot {
			case "prior prune":
				s.prior.chunks[3].member.token = token
			case "resident commit":
				s.residents[0].commit.member.token = token
			case "resident chunk":
				s.residents[0].chunks[0].member.token = token
			}
			out, err := daCompleteTestPrepare(t, f, a, s)
			if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
				t.Fatal("retained identity bijection", slot, err)
			}
		}
	})
	t.Run("resident token before fee overflow", func(t *testing.T) {
		for _, role := range []string{"zero", "foreign", "duplicate prior", "duplicate resident"} {
			s := daCompleteTestCapture(t, f, c)
			for i := range s.residents {
				if s.residents[i].daID != ([32]byte{12}) {
					continue
				}
				r := &s.residents[i]
				r.commit.member.fee = consensus.Uint128{Hi: math.MaxUint64, Lo: math.MaxUint64}
				r.chunks[0].member.fee = consensus.Uint128{Lo: 1}
				switch role {
				case "zero":
					r.commit.member.token = PendingOutpointToken{}
				case "foreign":
					r.commit.member.token.owner = &PendingOutpointOwner{}
				case "duplicate prior":
					r.commit.member.token = s.prior.chunks[0].member.token
				case "duplicate resident":
					r.commit.member.token = f.relay.sets[[32]byte{11}].commit.member.token
				}
			}
			out, err := daCompleteTestPrepare(t, f, a, s)
			if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
				t.Fatal("resident token before fee overflow", role, err)
			}
		}
	})
	t.Run("identity owner", func(t *testing.T) {
		// These are identity-layer witnesses; no modified scalar claims to be
		// a canonical transaction. Each guard is isolated from parser rejection.
		s := daCompleteTestCapture(t, f, c)
		row := s.prior.locatorRows()[0]
		member := s.prior.chunks[row.locator.chunkIndex].member
		for _, mode := range []string{"retained txid", "completing txid", "extra row"} {
			var err error
			switch mode {
			case "retained txid":
				err = s.checkRetainedIdentity(row, member, map[[32]byte]bool{row.txid: true}, map[PendingOutpointToken]bool{})
			case "completing txid":
				s.candidate.member.member.txid = row.txid
				err = s.checkRetainedIdentity(row, member, map[[32]byte]bool{}, map[PendingOutpointToken]bool{})
				s.candidate = c
			case "extra row":
				s.locators[[32]byte{99}] = row.locator
				_, err = s.capacityInput(baseline.prepared.input.candidate)
			}
			if !daCompleteTestError(err, errDARelayImageIncompatible) {
				t.Fatal("retained identity bijection", mode, err)
			}
		}
	})
	t.Run("matching sequence precedes resident", func(t *testing.T) {
		s := daCompleteTestCapture(t, f, c)
		s.nextReceivedTime = math.MaxUint64
		s.residents[0].commit.txBytes = []byte{0}
		out, err := daCompleteTestPrepare(t, f, a, s)
		if !daCompleteTestError(err, errDARelayArithmeticOverflow) || out != (daCompletePreparation{}) {
			t.Fatal("exact arithmetic overflow: sequence precedes resident", err)
		}
	})
	t.Run("resident commitment mismatch", func(t *testing.T) {
		s := daCompleteTestCapture(t, f, c)
		r := &s.residents[0]
		wrong := f.signed(daNonReplayTxSpec{kind: 1, daID: r.daID, chunkCount: 1, commitment: [32]byte{99}, commitmentOutputs: 1})
		delete(s.locators, r.commit.member.txid)
		r.commit.txBytes = slices.Clone(wrong.raw)
		r.commit.member.txid, r.commit.member.wtxid = wrong.txid, wrong.wtxid
		r.commit.member.inputs = slices.Clone(wrong.inputs)
		r.commit.payloadCommitment = [32]byte{99}
		s.locators[wrong.txid] = daRelayLocator{daID: r.daID, kind: daRelayLocatorCommit}
		out, err := daCompleteTestPrepare(t, f, a, s)
		if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
			t.Fatal("resident integrity before capacity", err)
		}
	})
	t.Run("resident count with matching commitment", func(t *testing.T) {
		s := daCompleteTestCapture(t, f, c)
		r := &s.residents[0]
		wrong := f.signed(daNonReplayTxSpec{kind: 1, daID: r.daID, chunkCount: 2, commitment: r.commit.payloadCommitment, commitmentOutputs: 1})
		delete(s.locators, r.commit.member.txid)
		r.commit.txBytes = slices.Clone(wrong.raw)
		r.commit.member.txid, r.commit.member.wtxid = wrong.txid, wrong.wtxid
		r.commit.member.inputs = slices.Clone(wrong.inputs)
		r.commit.chunkCount = 2
		s.locators[wrong.txid] = daRelayLocator{daID: r.daID, kind: daRelayLocatorCommit}
		out, err := daCompleteTestPrepare(t, f, a, s)
		if !daCompleteTestError(err, errDARelayImageIncompatible) || out != (daCompletePreparation{}) {
			t.Fatal("resident integrity before capacity", err)
		}
	})
	t.Run("unrelated A and B", func(t *testing.T) {
		for _, state := range []daRelaySetState{0, 1} {
			id := [32]byte{byte(80 + state)}
			f.relay.sets[id] = daRelaySetRecord{state: state, chunks: map[uint16]daRelayChunk{9: {txBytes: []byte{0}}}}
		}
		defer delete(f.relay.sets, [32]byte{80})
		defer delete(f.relay.sets, [32]byte{81})
		s := daCompleteTestCapture(t, f, c)
		out, err := daCompleteTestPrepare(t, f, a, s)
		if err != nil || out.prepared == nil || len(s.residents) != 2 {
			t.Fatal("unrelated A/B bodies were captured or validated", err)
		}
	})
	t.Run("chunk role payload shape", func(t *testing.T) {
		f, a, c := daCompleteTestCandidate(t, false, 0, 0)
		for _, field := range []string{"count", "commitment", "outside commit"} {
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
				t.Fatal("exact snapshot integrity error", field, err)
			}
		}
		s := daCompleteTestCapture(t, f, c)
		out, err := daCompleteTestPrepare(t, f, a, s)
		if err != nil || out.prepared == nil || out.prepared.image.next.commit.member.token != s.prior.commit.member.token || out.prepared.image.next.receivedTime != s.prior.receivedTime {
			t.Fatal("complete representation binding: chunk last", err)
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
				t.Fatal("duplicate or locator closure", err)
			}
		}
	})
}

func TestDACompleteSnapshotCaptureBound(t *testing.T) {
	f, _, c := daCompleteTestCandidate(t, true, 0, 0)
	// Capture-count evidence only; these empty records are never parsed or
	// represented as canonically valid complete residents.
	for i := 0; i < 65536; i++ {
		id := [32]byte{2, byte(i), byte(i >> 8)}
		f.relay.sets[id] = daRelaySetRecord{daID: id, state: daRelayStateCompleteSet}
	}
	s, duplicate, err := f.relay.captureDACompleteSnapshot(c)
	if err != nil || s == nil || len(s.residents) != 65536 || duplicate != (daRelayAdmissionOutcome{}) {
		t.Fatal("capture count inclusive boundary", err)
	}
	id := [32]byte{3}
	f.relay.sets[id] = daRelaySetRecord{daID: id, state: daRelayStateCompleteSet}
	s, duplicate, err = f.relay.captureDACompleteSnapshot(c)
	if !daCompleteTestError(err, errDARelayImageIncompatible) || s != nil || duplicate != (daRelayAdmissionOutcome{}) {
		t.Fatal("capture count exclusive boundary", err)
	}
}
