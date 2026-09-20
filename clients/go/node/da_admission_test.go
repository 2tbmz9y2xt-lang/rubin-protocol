package node

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func daAdmissionTestMempool(t *testing.T, count int) (*Mempool, [][]byte) {
	from := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(from.PubkeyBytes())
	values := make([]uint64, count)
	for i := range values {
		values[i] = 1_000_000
	}
	state, outpoints := testSpendableChainState(fromAddress, values)
	mp, _ := NewMempool(state, nil, devnetGenesisChainID)
	raw := make([][]byte, count)
	for i, outpoint := range outpoints {
		if i%2 != 0 {
			payload := []byte("chunk")
			tx := &consensus.Tx{Version: 1, TxKind: 0x02, TxNonce: uint64(i + 1), Inputs: []consensus.TxInput{{PrevTxid: outpoint.Txid, PrevVout: outpoint.Vout}}, Outputs: []consensus.TxOutput{{Value: 100_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), fromAddress...)}}, DaPayload: payload, DaChunkCore: &consensus.DaChunkCore{DaID: [32]byte{1}, ChunkHash: sha3.Sum256(payload)}}
			if err := consensus.SignTransaction(tx, state.Utxos, devnetGenesisChainID, from); err != nil {
				t.Fatalf("SignTransaction(chunk): %v", err)
			}
			raw[i] = mustMarshalTxForNodeTest(t, tx)
			continue
		}
		raw[i] = mustBuildSignedDaCommitTx(t, state.Utxos, outpoint, 100_000, 900_000, uint64(i+1), from, fromAddress, []byte("manifest"))
	}
	return mp, raw
}

func mustDAAdmission(t *testing.T, mp *Mempool, raw []byte) *DAAdmission {
	a, err := mp.BeginDAAdmission(raw)
	if err != nil {
		t.Fatalf("BeginDAAdmission: %v", err)
	}
	return a
}

func mustFinalizeDAAdmission(t *testing.T, mp *Mempool, raw []byte) (DAAdmissionSnapshot, PendingOutpointToken) {
	a := mustDAAdmission(t, mp, raw)
	snapshot := a.Snapshot()
	commit, _ := a.BeginCommit(nil)
	token := commit.CandidateToken()
	commit.Commit()
	a.Close()
	return snapshot, token
}

func mustPanic(t *testing.T, fn func()) {
	defer func() {
		if recover() == nil {
			t.Fatal("want panic")
		}
	}()
	fn()
}

func daAdmit(t *testing.T, err error, want TxAdmitErrorKind) *TxAdmitError {
	t.Helper()
	var got *TxAdmitError
	if !errors.As(err, &got) || got.Kind != want {
		t.Fatalf("admission error=%v, want %s", err, want)
	}
	return got
}

func TestBeginDAAdmission(t *testing.T) {
	mp, raw := daAdmissionTestMempool(t, 2)
	owner := mp.PendingOutpointOwner()
	mustDAAdmission(t, mp, raw[0]).Close()
	chunk := mustDAAdmission(t, mp, raw[1])
	chunkCommit, err := chunk.BeginCommit(nil)
	if err != nil || chunkCommit.CandidateToken() == (PendingOutpointToken{}) {
		t.Fatalf("chunk BeginCommit=(%v,%v), want nonzero token", chunkCommit, err)
	}
	chunkCommit.Abort()
	chunk.Close()
	tx, _, _, _, _ := consensus.ParseTx(raw[0])
	tx.TxKind, tx.DaCommitCore, tx.DaChunkCore, tx.DaPayload = 0x02, nil, &consensus.DaChunkCore{}, []byte("bad")
	badChunk, _ := consensus.MarshalTx(tx)
	standard := *tx
	standard.TxKind, standard.DaChunkCore, standard.DaPayload = 0, nil, nil
	standardBytes, _ := consensus.MarshalTx(&standard)
	unknown := append([]byte(nil), raw[0]...)
	unknown[4] = 3
	for _, bad := range [][]byte{nil, append(append([]byte(nil), raw[0]...), 0), standardBytes, unknown} {
		if a, err := mp.BeginDAAdmission(bad); a != nil || daAdmit(t, err, TxAdmitRejected) == nil {
			t.Fatalf("BeginDAAdmission(%d bytes)=(%v,%v), want reject", len(bad), a, err)
		}
	}
	inputless, _, _, _, _ := consensus.ParseTx(raw[0])
	inputless.Inputs, inputless.Witness = nil, nil
	inputlessBytes, _ := consensus.MarshalTx(inputless)
	if a, err := mp.BeginDAAdmission(inputlessBytes); a != nil || daAdmit(t, err, TxAdmitRejected) == nil {
		t.Fatal("inputless DA transaction admitted")
	}
	oversized := make([]byte, consensus.MAX_RELAY_MSG_BYTES+1)
	for _, tc := range []struct {
		raw  []byte
		want string
	}{{badChunk, ""}, {oversized, fmt.Sprintf("tx payload exceeds MAX_RELAY_MSG_BYTES: %d > %d", len(oversized), consensus.MAX_RELAY_MSG_BYTES)}} {
		high, claims, rows, state, done := owner.tokenHighWater, len(owner.byToken), len(owner.byOutpoint), mp.chainState, make(chan error, 1)
		state.admissionMu.Lock()
		go func() { _, err := mp.BeginDAAdmission(tc.raw); done <- err }()
		select {
		case err := <-done:
			state.admissionMu.Unlock()
			if got := daAdmit(t, err, TxAdmitRejected); tc.want != "" && got.Message != tc.want {
				t.Fatalf("context-free rejection=%q, want %q", got.Message, tc.want)
			}
		case <-time.After(time.Second):
			state.admissionMu.Unlock()
			<-done
			t.Fatal("context-free rejection took admission guard")
		}
		if owner.tokenHighWater != high || len(owner.byToken) != claims || len(owner.byOutpoint) != rows {
			t.Fatal("context-free rejection changed owner")
		}
	}
}

func TestDAAdmissionSnapshot(t *testing.T) {
	mp, raw := daAdmissionTestMempool(t, 1)
	a := mustDAAdmission(t, mp, raw[0])
	first := a.Snapshot()
	first.TxBytes[0] ^= 0xff
	first.Inputs[0].Vout++
	second := a.Snapshot()
	if !bytes.Equal(second.TxBytes, raw[0]) || second.TxID != a.snapshot.TxID || second.WTxID != a.snapshot.WTxID || second.Fee != a.snapshot.Fee || second.Inputs[0] != a.snapshot.Inputs[0] || second.Inputs[0].Vout == first.Inputs[0].Vout || second.RetainedBytes != uint64(len(raw[0])) {
		t.Fatal("Snapshot returned a mutable alias or wrong retained bytes")
	}
	a.Close()
	small := testing.AllocsPerRun(5, func() { mustDAAdmission(t, mp, raw[0]).Close() })
	entry := mp.chainState.Utxos[second.Inputs[0]]
	for i := 1; i <= 64; i++ {
		op := second.Inputs[0]
		op.Vout += uint32(i)
		mp.chainState.Utxos[op] = entry
	}
	if got, full := testing.AllocsPerRun(5, func() { mustDAAdmission(t, mp, raw[0]).Close() }), testing.AllocsPerRun(5, func() { _ = mp.chainState.admissionSnapshot() }); got != small || full <= got {
		t.Fatalf("public/input/full snapshot allocations small=%v input=%v full=%v", small, got, full)
	}
}

func TestDAAdmissionBeginCommit(t *testing.T) {
	mp, raw := daAdmissionTestMempool(t, 2)
	owner := mp.PendingOutpointOwner()
	_, token := mustFinalizeDAAdmission(t, mp, raw[0])
	if token == (PendingOutpointToken{}) {
		t.Fatal("BeginCommit returned a zero candidate")
	}
	type raceResult struct {
		commit *DACommit
		token  PendingOutpointToken
		err    error
	}
	for _, standardRace := range []bool{false, true} {
		left := mustDAAdmission(t, mp, raw[1])
		snapshot := left.Snapshot()
		var right *DAAdmission
		start, results := make(chan struct{}), make(chan raceResult, 2)
		go func() { <-start; c, e := left.BeginCommit(nil); results <- raceResult{commit: c, err: e} }()
		if standardRace {
			context, _ := owner.AdmissionContext()
			go func() {
				<-start
				token, e := owner.Reserve(context, PendingOutpointStandardMempool, [32]byte{7}, snapshot.Inputs)
				results <- raceResult{token: token, err: e}
			}()
		} else {
			right = mustDAAdmission(t, mp, raw[1])
			go func() { <-start; c, e := right.BeginCommit(nil); results <- raceResult{commit: c, err: e} }()
		}
		close(start)
		winner, loser, haveLoser := <-results, raceResult{}, false
		if standardRace && winner.commit == nil && winner.token == (PendingOutpointToken{}) {
			loser, winner, haveLoser = winner, <-results, true
		}
		if winner.err != nil || (winner.commit == nil && winner.token == (PendingOutpointToken{})) || len(owner.byToken) != 2 || len(owner.byOutpoint) != 2 {
			t.Fatal("same-outpoint race did not publish one complete winner")
		}
		winnerToken := winner.token
		if winner.commit != nil {
			winnerToken = winner.commit.CandidateToken()
			winner.commit.Commit()
		}
		if !haveLoser {
			loser = <-results
		}
		if standardRace && winner.commit != nil {
			if testOwnerKind(t, loser.err) != PendingOutpointConflict || loser.err.Error() != fmt.Sprintf("mempool double-spend conflict with %x", snapshot.TxID) {
				t.Fatalf("standard loser=%v", loser.err)
			}
		} else if daAdmit(t, loser.err, TxAdmitConflict).Message != fmt.Sprintf("mempool double-spend conflict with %x", map[bool][32]byte{false: snapshot.TxID, true: {7}}[standardRace]) {
			t.Fatalf("DA loser=%v", loser.err)
		}
		if err := owner.Release(winnerToken); err != nil {
			t.Fatalf("cleanup race winner: %v", err)
		}
		left.Close()
		if right != nil {
			right.Close()
		}
	}
	blocked := mustDAAdmission(t, mp, raw[1])
	owner.inTransition = true
	if _, err := blocked.BeginCommit(nil); daAdmit(t, err, TxAdmitUnavailable).Message != "pending-outpoint owner transition in progress" {
		t.Fatal("wrong unavailable error")
	}
	owner.inTransition = false
	blocked.Close()
	stale := mustDAAdmission(t, mp, raw[1])
	if _, err := owner.beginTransition(); err != nil {
		t.Fatalf("begin stale transition: %v", err)
	}
	owner.endTransitionAborted()
	if _, err := stale.BeginCommit(nil); daAdmit(t, err, TxAdmitUnavailable) == nil {
		t.Fatal("stale DA context was accepted")
	}
	stale.Close()
	exhausted := mustDAAdmission(t, mp, raw[1])
	high, claims, rows := owner.tokenHighWater, len(owner.byToken), len(owner.byOutpoint)
	owner.tokenHighWater = ^uint64(0)
	got, err := exhausted.BeginCommit(nil)
	unchanged := owner.tokenHighWater == ^uint64(0) && len(owner.byToken) == claims && len(owner.byOutpoint) == rows
	owner.tokenHighWater = high
	if got != nil || daAdmit(t, err, TxAdmitUnavailable).Message != "pending-outpoint token sequence exhausted" || !unchanged {
		t.Fatalf("exhausted BeginCommit=(%v,%v), changed=%v", got, err, !unchanged)
	}
	exhausted.Close()
	conflictOwner := newPendingOutpointOwner(PendingOutpointTip{})
	inputs := []consensus.Outpoint{testOutpoint(7), testOutpoint(8)}
	firstTxID, secondTxID := [32]byte{1}, [32]byte{2}
	mustReserve(t, conflictOwner, firstTxID, inputs[0])
	mustReserve(t, conflictOwner, secondTxID, inputs[1])
	context, _ := conflictOwner.AdmissionContext()
	conflictOwner.mu.Lock()
	conflictHigh, conflictClaims, conflictRows := conflictOwner.tokenHighWater, len(conflictOwner.byToken), len(conflictOwner.byOutpoint)
	reserved, failure, failed := conflictOwner.reserveDAAdmissionLocked(context, &pendingOutpointClaim{domain: PendingOutpointDA, txid: [32]byte{3}, inputs: inputs})
	conflictOwner.mu.Unlock()
	if !failed || reserved != (PendingOutpointToken{}) || failure.Kind != PendingOutpointConflict || failure.InputIndex != 0 || failure.Outpoint != inputs[0] || failure.ExistingTxid != firstTxID || conflictOwner.tokenHighWater != conflictHigh || len(conflictOwner.byToken) != conflictClaims || len(conflictOwner.byOutpoint) != conflictRows {
		t.Fatal("DA candidate conflict did not retain first canonical outpoint evidence")
	}
	if got := daAdmit(t, txAdmitFromPendingOutpointError(&failure), TxAdmitConflict); got.Message != fmt.Sprintf("mempool double-spend conflict with %x", firstTxID) {
		t.Fatalf("DA candidate conflict message=%q", got.Message)
	}
}

func TestDAAdmissionVictimBatch(t *testing.T) {
	mp, raw := daAdmissionTestMempool(t, 4)
	owner := mp.PendingOutpointOwner()
	base := DAAdmissionVictim{TxID: [32]byte{2}, Inputs: []consensus.Outpoint{testOutpoint(1)}, Token: PendingOutpointToken{owner: owner, seq: 1}}
	other := PendingOutpointToken{owner: owner, seq: 2}
	for _, victims := range [][]DAAdmissionVictim{
		{{Token: base.Token, Inputs: base.Inputs}},
		{{TxID: base.TxID, Inputs: base.Inputs}},
		{{TxID: base.TxID, Token: base.Token}},
		{{TxID: base.TxID, Token: base.Token, Inputs: []consensus.Outpoint{testOutpoint(1), testOutpoint(1)}}},
		{base, {TxID: base.TxID, Token: other, Inputs: base.Inputs}},
		{base, {TxID: [32]byte{3}, Token: base.Token, Inputs: base.Inputs}},
	} {
		a := mustDAAdmission(t, mp, raw[0])
		if _, err := a.BeginCommit(victims); daAdmit(t, err, TxAdmitUnavailable) == nil {
			t.Fatal("public BeginCommit accepted invalid victim shape")
		}
		a.Close()
	}
	mixed := []DAAdmissionVictim{{TxID: base.TxID, Token: base.Token, Inputs: []consensus.Outpoint{testOutpoint(1), testOutpoint(1)}}, {Token: base.Token, Inputs: base.Inputs}}
	a := mustDAAdmission(t, mp, raw[0])
	if _, err := a.BeginCommit(mixed); daAdmit(t, err, TxAdmitUnavailable).Message != fmt.Sprintf("duplicate pending-outpoint input txid=%x vout=%d", testOutpoint(1).Txid, testOutpoint(1).Vout) {
		t.Fatalf("mixed victim order error=%v", err)
	}
	a.Close()
	candidate := mustDAAdmission(t, mp, raw[0])
	candidateSnapshot := candidate.Snapshot()
	predicted := PendingOutpointToken{owner: owner, seq: owner.tokenHighWater + 1}
	if _, err := candidate.BeginCommit([]DAAdmissionVictim{{TxID: candidateSnapshot.TxID, Inputs: candidateSnapshot.Inputs, Token: predicted}}); daAdmit(t, err, TxAdmitUnavailable).Message != "DA candidate is also a victim" {
		t.Fatal("public BeginCommit accepted candidate victim")
	}
	candidate.Close()
	empty, oversized := base, base
	empty.Inputs, oversized.Inputs = nil, make([]consensus.Outpoint, consensus.MAX_TX_INPUTS+1)
	zeroAllocs := testing.AllocsPerRun(5, func() { _, _ = prepareDAAdmissionVictims([]DAAdmissionVictim{empty}, [32]byte{1}) })
	if got := testing.AllocsPerRun(5, func() { _, _ = prepareDAAdmissionVictims([]DAAdmissionVictim{oversized}, [32]byte{1}) }); got != zeroAllocs {
		t.Fatalf("victim length checked after copy: empty=%v oversized=%v", zeroAllocs, got)
	}
	probe := mustDAAdmission(t, mp, raw[0])
	high, claims, rows := owner.tokenHighWater, len(owner.byToken), len(owner.byOutpoint)
	owner.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := probe.BeginCommit([]DAAdmissionVictim{{}}); done <- err }()
	select {
	case err := <-done:
		owner.mu.Unlock()
		if err == nil {
			t.Fatal("malformed victim accepted")
		}
	case <-time.After(time.Second):
		owner.mu.Unlock()
		<-done
		t.Fatal("malformed victim took owner lock")
	}
	if owner.tokenHighWater != high || len(owner.byToken) != claims || len(owner.byOutpoint) != rows {
		t.Fatal("malformed victim changed owner")
	}
	probe.Close()
	firstSnapshot, firstToken := mustFinalizeDAAdmission(t, mp, raw[0])
	population := mustDAAdmission(t, mp, raw[1])
	populationSnapshot, beforePopulation := population.Snapshot(), owner.tokenHighWater
	populationVictims := []DAAdmissionVictim{{TxID: firstSnapshot.TxID, Inputs: firstSnapshot.Inputs, Token: firstToken}, {TxID: [32]byte{9}, Inputs: []consensus.Outpoint{testOutpoint(9)}, Token: PendingOutpointToken{owner: owner, seq: beforePopulation + 2}}}
	if got, err := population.BeginCommit(populationVictims); got != nil || daAdmit(t, err, TxAdmitUnavailable).Message != "DA victim batch exceeds live claim population" {
		t.Fatalf("population-precedence BeginCommit=(%v,%v)", got, err)
	}
	populationToken := PendingOutpointToken{owner: owner, seq: beforePopulation + 1}
	if owner.tokenHighWater != beforePopulation+1 || owner.byToken[firstToken] == nil || owner.byToken[populationToken] != nil || owner.byOutpoint[populationSnapshot.Inputs[0]].token != (PendingOutpointToken{}) || populationVictims[1].Inputs[0] != testOutpoint(9) {
		t.Fatal("population failure changed live claims or caller victims")
	}
	population.Close()
	secondSnapshot, secondToken := mustFinalizeDAAdmission(t, mp, raw[1])
	failed := mustDAAdmission(t, mp, raw[2])
	before := owner.tokenHighWater
	failedSnapshot, failedToken := failed.Snapshot(), PendingOutpointToken{owner: owner, seq: before + 1}
	bad := DAAdmissionVictim{TxID: [32]byte{9}, Inputs: secondSnapshot.Inputs, Token: secondToken}
	if got, err := failed.BeginCommit([]DAAdmissionVictim{{TxID: firstSnapshot.TxID, Inputs: firstSnapshot.Inputs, Token: firstToken}, bad}); got != nil || daAdmit(t, err, TxAdmitUnavailable) == nil {
		t.Fatalf("invalid final victim BeginCommit=(%v,%v), want error", got, err)
	}
	_, live := owner.byOutpoint[failedSnapshot.Inputs[0]]
	if owner.tokenHighWater != before+1 || live || owner.byToken[failedToken] != nil || owner.byToken[firstToken] == nil || owner.byToken[secondToken] == nil {
		t.Fatal("post-reserve failure did not preserve victims and high-water")
	}
	mustPanic(t, func() { _, _ = failed.BeginCommit(nil) })
	mustPanic(t, func() { _ = failed.Snapshot() })
	failed.Close()
	next := mustDAAdmission(t, mp, raw[3])
	commit, _ := next.BeginCommit([]DAAdmissionVictim{{TxID: firstSnapshot.TxID, Inputs: firstSnapshot.Inputs, Token: firstToken}, {TxID: secondSnapshot.TxID, Inputs: secondSnapshot.Inputs, Token: secondToken}})
	nextToken := commit.CandidateToken()
	commit.Commit()
	next.Close()
	if owner.byToken[firstToken] != nil || owner.byToken[secondToken] != nil || owner.byToken[nextToken] == nil {
		t.Fatal("multi-victim Commit did not atomically replace claims")
	}
}

func TestDAAdmissionClose(t *testing.T) {
	mp, raw := daAdmissionTestMempool(t, 1)
	a := mustDAAdmission(t, mp, raw[0])
	copy := *a
	mustPanic(t, copy.Close)
	a.Close()
	mustPanic(t, a.Close)
	mustPanic(t, func() { _ = a.Snapshot() })
	mustPanic(t, func() { _, _ = a.BeginCommit(nil) })
	wait := mustDAAdmission(t, mp, raw[0])
	before := wait.context
	started, done := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		mp.chainState.admissionMu.Lock()
		defer mp.chainState.admissionMu.Unlock()
		tipB := before.StableTip
		tipB.Height++
		tipB.Hash[0]++
		owner := mp.PendingOutpointOwner()
		_, err := owner.beginTransition()
		if err == nil {
			err = owner.commitStableTip(tipB)
		}
		if err == nil {
			_, err = owner.beginTransition()
		}
		if err == nil {
			err = owner.commitStableTip(before.StableTip)
		}
		done <- err
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("transition bypassed DA guard: %v", err)
	case <-time.After(time.Second):
	}
	wait.Close()
	if err := <-done; err != nil {
		t.Fatalf("A-B-A transition: %v", err)
	}
	after, ok := mp.PendingOutpointOwner().AdmissionContext()
	if !ok || after.StableTip != before.StableTip || after.Generation != before.Generation+2 {
		t.Fatalf("A-B-A context=(%+v,%v), want generation %d", after, ok, before.Generation+2)
	}
	attempt := mustDAAdmission(t, mp, raw[0])
	owner := mp.PendingOutpointOwner()
	owner.mu.Lock()
	doneCommit := make(chan *DACommit, 1)
	go func() { commit, _ := attempt.BeginCommit(nil); doneCommit <- commit }()
	for i := 0; i < 10_000 && attempt.guard.state.Load() != daAdmissionAttempting; i++ {
		runtime.Gosched()
	}
	seen := attempt.guard.state.Load() == daAdmissionAttempting
	if seen {
		mustPanic(t, attempt.Close)
	}
	owner.mu.Unlock()
	commit := <-doneCommit
	if !seen || commit == nil {
		if commit != nil {
			commit.Abort()
			attempt.Close()
		}
		t.Fatal("BeginCommit did not remain ATTEMPTING under owner lock")
	}
	commit.Abort()
	attempt.Close()
}

func TestDARemovalBeginCommit(t *testing.T) {
	mp, raw := daAdmissionTestMempool(t, 1)
	for _, bad := range []*Mempool{nil, {}, {chainState: mp.chainState}} {
		if _, err := bad.BeginDAAdmission(raw[0]); daAdmit(t, err, TxAdmitUnavailable) == nil {
			t.Fatal("invalid mempool admitted DA transaction")
		}
		if _, err := bad.BeginDARemoval(); daAdmit(t, err, TxAdmitUnavailable) == nil {
			t.Fatal("invalid mempool began DA removal")
		}
	}
	owner := mp.PendingOutpointOwner()
	snapshot, token := mustFinalizeDAAdmission(t, mp, raw[0])
	empty, _ := mp.BeginDARemoval()
	copy := *empty
	mustPanic(t, copy.Close)
	if got, err := empty.BeginCommit(nil); got != nil || err == nil {
		t.Fatalf("empty removal BeginCommit=(%v,%v), want error", got, err)
	}
	mustPanic(t, func() { _, _ = empty.BeginCommit(nil) })
	empty.Close()
	mustPanic(t, empty.Close)
	r, _ := mp.BeginDARemoval()
	remove, err := r.BeginCommit([]DAAdmissionVictim{{TxID: snapshot.TxID, Inputs: snapshot.Inputs, Token: token}})
	if err != nil || remove.CandidateToken() != (PendingOutpointToken{}) {
		t.Fatalf("removal BeginCommit=(%v,%v), want zero candidate", remove, err)
	}
	remove.Abort()
	r.Close()
	if mp.PendingOutpointOwner().byToken[token] == nil {
		t.Fatal("removal Abort deleted victim")
	}
	context, _ := owner.AdmissionContext()
	multiTxID, multiInputs := [32]byte{5}, []consensus.Outpoint{testOutpoint(5), testOutpoint(6)}
	multi, err := owner.Reserve(context, PendingOutpointDA, multiTxID, multiInputs)
	if err != nil || owner.Finalize(multi) != nil {
		t.Fatal("could not create finalized multi-input DA victim")
	}
	multiVictim := DAAdmissionVictim{TxID: multiTxID, Inputs: multiInputs, Token: multi}
	r, _ = mp.BeginDARemoval()
	remove, err = r.BeginCommit([]DAAdmissionVictim{multiVictim})
	if err != nil || remove.CandidateToken() != (PendingOutpointToken{}) {
		t.Fatalf("multi-input removal BeginCommit=(%v,%v)", remove, err)
	}
	remove.Abort()
	r.Close()
	if owner.byToken[multi] == nil || owner.byOutpoint[multiInputs[0]].token != multi || owner.byOutpoint[multiInputs[1]].token != multi {
		t.Fatal("multi-input removal Abort changed victim")
	}
	valid := DAAdmissionVictim{TxID: snapshot.TxID, Inputs: snapshot.Inputs, Token: token}
	stale, _ := owner.Reserve(context, PendingOutpointDA, [32]byte{2}, []consensus.Outpoint{testOutpoint(2)})
	_ = owner.Release(stale)
	standard, _ := owner.Reserve(context, PendingOutpointStandardMempool, [32]byte{3}, []consensus.Outpoint{testOutpoint(3)})
	_ = owner.Finalize(standard)
	unfinalized, _ := owner.Reserve(context, PendingOutpointDA, [32]byte{4}, []consensus.Outpoint{testOutpoint(4)})
	foreign := PendingOutpointToken{owner: newPendingOutpointOwner(PendingOutpointTip{}), seq: 1}
	for _, tc := range []struct {
		victims []DAAdmissionVictim
		want    string
		corrupt bool
	}{
		{[]DAAdmissionVictim{{TxID: snapshot.TxID, Inputs: snapshot.Inputs, Token: foreign}}, "invalid DA victim token", false},
		{[]DAAdmissionVictim{{TxID: snapshot.TxID, Inputs: snapshot.Inputs, Token: PendingOutpointToken{owner: owner, seq: owner.tokenHighWater + 1}}}, "invalid DA victim token", false},
		{[]DAAdmissionVictim{{TxID: [32]byte{2}, Inputs: []consensus.Outpoint{testOutpoint(2)}, Token: stale}}, "DA victim claim mismatch", false},
		{[]DAAdmissionVictim{{TxID: [32]byte{3}, Inputs: []consensus.Outpoint{testOutpoint(3)}, Token: standard}}, "DA victim claim mismatch", false},
		{[]DAAdmissionVictim{{TxID: [32]byte{4}, Inputs: []consensus.Outpoint{testOutpoint(4)}, Token: unfinalized}}, "DA victim claim mismatch", false},
		{[]DAAdmissionVictim{{TxID: [32]byte{9}, Inputs: snapshot.Inputs, Token: token}}, "DA victim claim mismatch", false},
		{[]DAAdmissionVictim{{TxID: snapshot.TxID, Inputs: []consensus.Outpoint{testOutpoint(99)}, Token: token}}, "DA victim input mismatch", false},
		{[]DAAdmissionVictim{{TxID: multiTxID, Inputs: []consensus.Outpoint{multiInputs[1], multiInputs[0]}, Token: multi}}, "DA victim input mismatch", false},
		{[]DAAdmissionVictim{valid}, "DA victim input mismatch", true},
		{[]DAAdmissionVictim{{TxID: [32]byte{8}, Inputs: snapshot.Inputs, Token: foreign}, valid}, "invalid DA victim token", false},
	} {
		high, claims, rows, victim := owner.tokenHighWater, len(owner.byToken), len(owner.byOutpoint), tc.victims[0]
		if tc.corrupt {
			owner.byOutpoint[victim.Inputs[0]] = pendingOutpointRow{token: standard, txid: [32]byte{3}}
		}
		r, _ := mp.BeginDARemoval()
		got, err := r.BeginCommit(tc.victims)
		if tc.corrupt {
			owner.byOutpoint[victim.Inputs[0]] = pendingOutpointRow{token: token, txid: snapshot.TxID}
		}
		if got != nil || daAdmit(t, err, TxAdmitUnavailable).Message != tc.want || owner.tokenHighWater != high || len(owner.byToken) != claims || len(owner.byOutpoint) != rows || owner.byToken[multi] == nil || owner.byOutpoint[multiInputs[0]].token != multi || owner.byOutpoint[multiInputs[1]].token != multi || tc.victims[0].TxID != victim.TxID || tc.victims[0].Token != victim.Token || tc.victims[0].Inputs[0] != victim.Inputs[0] {
			t.Fatalf("invalid removal BeginCommit=(%v,%v), want %q", got, err, tc.want)
		}
		r.Close()
	}
	r, _ = mp.BeginDARemoval()
	remove, _ = r.BeginCommit([]DAAdmissionVictim{valid})
	remove.Commit()
	r.Close()
	if mp.PendingOutpointOwner().byToken[token] != nil {
		t.Fatal("removal left victim claim live")
	}
}

func TestDACommit(t *testing.T) {
	mp, raw := daAdmissionTestMempool(t, 2)
	a := mustDAAdmission(t, mp, raw[0])
	commit, _ := a.BeginCommit(nil)
	commit.Commit()
	copy := *commit
	mustPanic(t, copy.Abort)
	mustPanic(t, commit.Commit)
	mustPanic(t, func() { _ = commit.CandidateToken() })
	mustPanic(t, commit.Abort)
	a.Close()
	abort := mustDAAdmission(t, mp, raw[1])
	aborted, _ := abort.BeginCommit(nil)
	token := aborted.CandidateToken()
	mustPanic(t, abort.Close)
	aborted.Abort()
	abort.Close()
	if mp.PendingOutpointOwner().byToken[token] != nil {
		t.Fatal("Abort left a live candidate")
	}
	live := mustDAAdmission(t, mp, raw[1])
	concurrent, _ := live.BeginCommit(nil)
	token = concurrent.CandidateToken()
	terminals := make(chan bool, 2)
	for _, terminal := range []func(){concurrent.Commit, concurrent.Abort} {
		go func(f func()) { defer func() { terminals <- recover() != nil }(); f() }(terminal)
	}
	first, second := <-terminals, <-terminals
	if first == second || concurrent.guard.state.Load() != daAdmissionResolved {
		t.Fatal("concurrent terminal operations did not yield one resolution")
	}
	if claim := mp.PendingOutpointOwner().byToken[token]; claim != nil && !claim.finalized {
		t.Fatal("concurrent terminal left an unfinalized candidate")
	}
	live.Close()
}

func TestDAPreparedCommitLifecycle(t *testing.T) {
	mp, raw := daAdmissionTestMempool(t, 1)
	a := mustDAAdmission(t, mp, raw[0])
	before := cloneDAAdmissionOwner(a.guard.owner)
	assertPanic := func(want string, call func()) {
		t.Helper()
		defer func() {
			if got := recover(); got != want {
				t.Fatalf("failed public attempt remains one-shot: panic=%v want=%s", got, want)
			}
		}()
		call()
	}
	if commit, err := a.BeginCommit([]DAAdmissionVictim{{}}); commit != nil || daAdmit(t, err, TxAdmitUnavailable).Message != "zero DA victim txid or token" || a.guard.state.Load() != daAdmissionResolved {
		t.Fatal("failed public attempt remains one-shot")
	}
	for _, tc := range []struct {
		call func()
		want string
	}{
		{func() { _, _ = a.BeginCommit(nil) }, "DA admission is not available for BeginCommit"},
		{func() { _ = a.Snapshot() }, "DA admission snapshot is not available"},
	} {
		assertPanic(tc.want, tc.call)
	}
	if !reflect.DeepEqual(before, cloneDAAdmissionOwner(a.guard.owner)) {
		t.Fatal("failed public attempt changed owner")
	}
	a.Close()
	assertPanic("DA admission is not available for BeginCommit", func() { _, _ = a.BeginCommit(nil) })
	var nilAdmission *DAAdmission
	assertPanic("invalid DAAdmission", func() { _, _ = nilAdmission.BeginCommit(nil) })
	a = mustDAAdmission(t, mp, raw[0])
	copy := *a
	assertPanic("invalid DAAdmission", func() { _, _ = copy.BeginCommit(nil) })
	commit, err := a.BeginCommit(nil)
	if err != nil {
		t.Fatal(err)
	}
	assertPanic("DA admission is not available for BeginCommit", func() { _, _ = a.BeginCommit(nil) })
	commit.Abort()
	a.Close()
}

func TestDAPreparedCommitIsolation(t *testing.T) {
	mp, raw := daAdmissionTestMempool(t, 3)
	owner := mp.PendingOutpointOwner()
	victims := make([]DAAdmissionVictim, 2)
	for i := range victims {
		snapshot, token := mustFinalizeDAAdmission(t, mp, raw[i])
		victims[i] = DAAdmissionVictim{TxID: snapshot.TxID, Inputs: snapshot.Inputs, Token: token}
	}
	a := mustDAAdmission(t, mp, raw[2])
	before, snapshot := cloneDAAdmissionOwner(owner), a.Snapshot()
	prepared, err := prepareDAAdmissionCommit(a, victims)
	if err != nil || prepared == nil || !reflect.DeepEqual(before, cloneDAAdmissionOwner(owner)) || !reflect.DeepEqual(snapshot, a.Snapshot()) {
		t.Fatal("preparation changed admission or owner")
	}
	a.snapshot.Inputs[0].Vout++
	for i := range victims {
		victims[i].Inputs[0].Vout++
		victims[i].TxID[0]++
		victims[i].Token = PendingOutpointToken{}
	}
	if !slices.Equal(prepared.candidate.inputs, snapshot.Inputs) {
		t.Fatal("prepared inputs alias caller: candidate")
	}
	for _, victim := range prepared.commit.victims {
		claim := before.byToken[victim.Token]
		if claim == nil || claim.txid != victim.TxID || !slices.Equal(claim.inputs, victim.Inputs) {
			t.Fatal("prepared inputs alias caller: victim")
		}
	}
	if !a.guard.state.CompareAndSwap(daAdmissionOpen, daAdmissionAttempting) {
		t.Fatal("claim attempt")
	}
	commit, failure, failed := reservePreparedDAAdmissionCommit(prepared)
	if failed || failure != (PendingOutpointError{}) || commit != prepared.commit {
		t.Fatal("prepared inputs alias caller: reservation")
	}
	commit.Commit()
	a.Close()
	if len(owner.byToken) != 1 || !owner.byToken[commit.candidate].finalized || !slices.Equal(owner.byToken[commit.candidate].inputs, snapshot.Inputs) {
		t.Fatal("copied claims not committed")
	}
}

func TestDAPreparedCommitOrder(t *testing.T) {
	mp, raw := daAdmissionTestMempool(t, 1)
	owner := mp.PendingOutpointOwner()
	base := DAAdmissionVictim{TxID: [32]byte{2}, Inputs: []consensus.Outpoint{testOutpoint(2)}, Token: PendingOutpointToken{owner: owner, seq: 1}}
	duplicate := fmt.Sprintf("duplicate pending-outpoint input txid=%x vout=%d", testOutpoint(2).Txid, testOutpoint(2).Vout)
	for _, tc := range []struct {
		name, want string
		inputs     []consensus.Outpoint
		zeroTxID   bool
		victims    []DAAdmissionVictim
	}{
		{"count before request", "invalid DA candidate input count", make([]consensus.Outpoint, 1025), true, []DAAdmissionVictim{{}}},
		{"txid before inputs", "zero pending-outpoint txid", nil, true, []DAAdmissionVictim{{}}},
		{"empty before victims", "empty pending-outpoint input set", nil, false, []DAAdmissionVictim{{}}},
		{"duplicate before victims", duplicate, []consensus.Outpoint{testOutpoint(2), testOutpoint(2)}, false, []DAAdmissionVictim{{}}},
		{"victim zero txid", "zero DA victim txid or token", base.Inputs, false, []DAAdmissionVictim{{Token: base.Token, Inputs: base.Inputs}}},
		{"victim zero token", "zero DA victim txid or token", base.Inputs, false, []DAAdmissionVictim{{TxID: base.TxID, Inputs: base.Inputs}}},
		{"victim empty", "invalid DA victim input count", base.Inputs, false, []DAAdmissionVictim{{TxID: base.TxID, Token: base.Token}}},
		{"victim oversized", "invalid DA victim input count", base.Inputs, false, []DAAdmissionVictim{{TxID: base.TxID, Token: base.Token, Inputs: make([]consensus.Outpoint, 1025)}}},
		{"victim duplicate input", duplicate, base.Inputs, false, []DAAdmissionVictim{{TxID: base.TxID, Token: base.Token, Inputs: []consensus.Outpoint{testOutpoint(2), testOutpoint(2)}}}},
		{"duplicate txid before token", "duplicate DA victim txid", base.Inputs, false, []DAAdmissionVictim{base, base}},
		{"duplicate token", "duplicate DA victim token", base.Inputs, false, []DAAdmissionVictim{base, {TxID: [32]byte{3}, Token: base.Token, Inputs: base.Inputs}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := mustDAAdmission(t, mp, raw[0])
			a.snapshot.Inputs = tc.inputs
			if tc.zeroTxID {
				a.snapshot.TxID = [32]byte{}
			}
			owner.inTransition = true
			before, snapshot := cloneDAAdmissionOwner(owner), a.Snapshot()
			prepared, err := prepareDAAdmissionCommit(a, tc.victims)
			var failure *PendingOutpointError
			if prepared != nil || !errors.As(err, &failure) || *failure != (PendingOutpointError{Kind: PendingOutpointInternal, Msg: tc.want}) || !reflect.DeepEqual(snapshot, a.Snapshot()) || !reflect.DeepEqual(before, cloneDAAdmissionOwner(owner)) {
				t.Fatalf("preparation error before owner: %v", err)
			}
			if commit, err := a.BeginCommit(tc.victims); commit != nil || daAdmit(t, err, TxAdmitUnavailable).Message != tc.want || a.guard.state.Load() != daAdmissionResolved || !reflect.DeepEqual(before, cloneDAAdmissionOwner(owner)) {
				t.Fatalf("preparation error before owner: public %v", err)
			}
			owner.inTransition = false
			a.Close()
		})
	}
	a := mustDAAdmission(t, mp, raw[0])
	for _, victims := range [][]DAAdmissionVictim{
		{{TxID: a.snapshot.TxID, Token: base.Token, Inputs: base.Inputs}},
		make([]DAAdmissionVictim, daAdmissionMaxVictims+1),
	} {
		want := "DA candidate is also a victim"
		if len(victims) > 1 {
			want = "DA victim batch exceeds bound"
		}
		if prepared, err := prepareDAAdmissionCommit(a, victims); prepared != nil || err == nil || err.Error() != want {
			t.Fatal("preparation error before owner: batch bounds/identity")
		}
	}
	a.Close()
	// The second input conflicts; the first does not. A later conflict and an
	// invalid live victim must not replace the first conflict descriptor.
	a = mustDAAdmission(t, mp, raw[0])
	a.snapshot.Inputs = []consensus.Outpoint{testOutpoint(1), testOutpoint(2), testOutpoint(3)}
	mustReserve(t, owner, [32]byte{8}, testOutpoint(2))
	mustReserve(t, owner, [32]byte{9}, testOutpoint(3))
	prepared, err := prepareDAAdmissionCommit(a, []DAAdmissionVictim{base})
	if err != nil {
		t.Fatal(err)
	}
	before := cloneDAAdmissionOwner(owner)
	a.guard.state.CompareAndSwap(daAdmissionOpen, daAdmissionAttempting)
	commit, failure, failed := reservePreparedDAAdmissionCommit(prepared)
	if !owner.mu.TryLock() {
		t.Fatal("reserve before live victim validation: refusal retained owner")
	}
	owner.mu.Unlock()
	if commit != nil || !failed || failure != (PendingOutpointError{Kind: PendingOutpointConflict, Outpoint: testOutpoint(2), InputIndex: 1, ExistingTxid: [32]byte{8}}) || !reflect.DeepEqual(before, cloneDAAdmissionOwner(owner)) {
		t.Fatal("reserve before live victim validation")
	}
	a.guard.state.CompareAndSwap(daAdmissionAttempting, daAdmissionResolved)
	a.Close()
}

func TestDAPreparedCommitContext(t *testing.T) {
	mp, raw := daAdmissionTestMempool(t, 1)
	owner := mp.PendingOutpointOwner()
	for _, tc := range []struct {
		name, message string
	}{
		{"transition", "pending-outpoint owner transition in progress"},
		{"tip", "pending-outpoint expected tip mismatch"},
		{"generation", "pending-outpoint expected generation mismatch"},
		{"exhaustion", "pending-outpoint token sequence exhausted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := mustDAAdmission(t, mp, raw[0])
			public := mustDAAdmission(t, mp, raw[0])
			prepared, err := prepareDAAdmissionCommit(a, nil)
			if err != nil {
				t.Fatal(err)
			}
			context := a.context
			owner.tokenHighWater = ^uint64(0)
			if tc.name != "exhaustion" {
				owner.generation++
			}
			if tc.name == "tip" || tc.name == "transition" {
				owner.stableTip.Height++
			}
			owner.inTransition = tc.name == "transition"
			// The owner and original admission now agree; only captured data is stale.
			a.context = PendingOutpointAdmissionContext{StableTip: owner.stableTip, Generation: owner.generation}
			before := cloneDAAdmissionOwner(owner)
			a.guard.state.CompareAndSwap(daAdmissionOpen, daAdmissionAttempting)
			commit, failure, failed := reservePreparedDAAdmissionCommit(prepared)
			if !owner.mu.TryLock() {
				t.Fatal("captured admission context: refusal retained owner")
			}
			owner.mu.Unlock()
			if commit != nil || !failed || failure != (PendingOutpointError{Kind: PendingOutpointUnavailable, Msg: tc.message}) || !reflect.DeepEqual(before, cloneDAAdmissionOwner(owner)) || a.guard.state.Load() != daAdmissionAttempting {
				t.Fatal("captured admission context")
			}
			a.guard.state.CompareAndSwap(daAdmissionAttempting, daAdmissionResolved)
			a.Close()
			if commit, err := public.BeginCommit(nil); commit != nil || daAdmit(t, err, TxAdmitUnavailable).Message != tc.message || public.guard.state.Load() != daAdmissionResolved || !reflect.DeepEqual(before, cloneDAAdmissionOwner(owner)) {
				t.Fatal("captured admission context: public mapping")
			}
			public.Close()
			owner.tokenHighWater, owner.generation, owner.stableTip, owner.inTransition = 0, context.Generation, context.StableTip, false
		})
	}
}

func TestDAPreparedCommitOwnerEffects(t *testing.T) {
	mp, raw := daAdmissionTestMempool(t, 3)
	owner := mp.PendingOutpointOwner()
	victims := make([]DAAdmissionVictim, 2)
	for i := range victims {
		admission := mustDAAdmission(t, mp, raw[i])
		snapshot := admission.Snapshot()
		token, err := owner.Reserve(admission.context, PendingOutpointDA, snapshot.TxID, snapshot.Inputs)
		if err != nil {
			admission.Close()
			t.Fatal(err)
		}
		if err := owner.Finalize(token); err != nil {
			admission.Close()
			t.Fatal(err)
		}
		admission.Close()
		victims[i] = DAAdmissionVictim{TxID: snapshot.TxID, Inputs: snapshot.Inputs, Token: token}
	}
	a := mustDAAdmission(t, mp, raw[2])
	bad := slices.Clone(victims)
	bad[1].TxID = [32]byte{9}
	prepared, err := prepareDAAdmissionCommit(a, bad)
	if err != nil {
		t.Fatal(err)
	}
	before := cloneDAAdmissionOwner(owner)
	a.guard.state.CompareAndSwap(daAdmissionOpen, daAdmissionAttempting)
	commit, failure, failed := reservePreparedDAAdmissionCommit(prepared)
	before.tokenHighWater++
	if !owner.mu.TryLock() {
		t.Fatal("post-reserve refusal state: owner retained")
	}
	owner.mu.Unlock()
	if commit != nil || !failed || failure != (PendingOutpointError{Kind: PendingOutpointInternal, Msg: "DA victim claim mismatch"}) || !reflect.DeepEqual(before, cloneDAAdmissionOwner(owner)) || a.guard.state.Load() != daAdmissionAttempting {
		t.Fatal("post-reserve refusal state")
	}
	a.guard.state.CompareAndSwap(daAdmissionAttempting, daAdmissionResolved)
	a.Close()
	for count := 0; count <= 2; count++ {
		a = mustDAAdmission(t, mp, raw[2])
		prepared, err = prepareDAAdmissionCommit(a, victims[:count])
		if err != nil {
			t.Fatal(err)
		}
		high := owner.tokenHighWater
		a.guard.state.CompareAndSwap(daAdmissionOpen, daAdmissionAttempting)
		commit, failure, failed = reservePreparedDAAdmissionCommit(prepared)
		if failed || failure != (PendingOutpointError{}) || commit != prepared.commit || commit.candidate != (PendingOutpointToken{owner: owner, seq: high + 1}) || a.guard.state.Load() != daAdmissionLive || owner.tokenHighWater != high+1 || owner.byToken[commit.candidate] != prepared.candidate {
			t.Fatal("single live commit transfer")
		}
		if owner.mu.TryLock() {
			owner.mu.Unlock()
			t.Fatal("single live commit transfer: owner not held")
		}
		commit.Abort()
		a.Close()
		before.tokenHighWater++
		if !reflect.DeepEqual(before, cloneDAAdmissionOwner(owner)) {
			t.Fatal("Abort changed surviving victims")
		}
	}
}

func TestDAPreparedCommitIdentity(t *testing.T) {
	mp, raw := daAdmissionTestMempool(t, 1)
	owner := mp.PendingOutpointOwner()
	for _, count := range []int{1, 1024} {
		a := mustDAAdmission(t, mp, raw[0])
		inputs := make([]consensus.Outpoint, count)
		for i := range inputs {
			inputs[i] = consensus.Outpoint{Txid: [32]byte{7}, Vout: uint32(i)}
		}
		a.snapshot.Inputs = inputs
		a.context = PendingOutpointAdmissionContext{StableTip: PendingOutpointTip{HasTip: true, Height: 17, Hash: [32]byte{6}}, Generation: 19}
		victims := []DAAdmissionVictim{{TxID: [32]byte{3}, Inputs: []consensus.Outpoint{testOutpoint(3)}, Token: PendingOutpointToken{owner: owner, seq: 5}}, {TxID: [32]byte{4}, Inputs: []consensus.Outpoint{testOutpoint(4)}, Token: PendingOutpointToken{owner: owner, seq: 6}}}
		prepared, err := prepareDAAdmissionCommit(a, victims)
		if err != nil || prepared == nil || prepared.candidate.domain != PendingOutpointDomain(2) || prepared.candidate.txid != a.snapshot.TxID || !slices.Equal(prepared.candidate.inputs, inputs) || prepared.candidate.token != (PendingOutpointToken{}) || prepared.candidate.generation != 0 || prepared.candidate.finalized || prepared.context != (PendingOutpointAdmissionContext{StableTip: PendingOutpointTip{HasTip: true, Height: 17, Hash: [32]byte{6}}, Generation: 19}) || prepared.commit.guard != a.guard || prepared.commit.self != prepared.commit || prepared.commit.candidate != (PendingOutpointToken{}) || !reflect.DeepEqual(prepared.commit.victims, victims) {
			t.Fatal("exact prepared identity and failure descriptor")
		}
		a.Close()
	}
	for _, unavailable := range []bool{false, true} {
		a := mustDAAdmission(t, mp, raw[0])
		prepared, err := prepareDAAdmissionCommit(a, nil)
		if err != nil {
			t.Fatal(err)
		}
		owner.inTransition = unavailable
		a.guard.state.CompareAndSwap(daAdmissionOpen, daAdmissionAttempting)
		commit, failure, failed := reservePreparedDAAdmissionCommit(prepared)
		want := PendingOutpointError{}
		if unavailable {
			want = PendingOutpointError{Kind: PendingOutpointUnavailable, Msg: "pending-outpoint owner transition in progress"}
		}
		if failure != want || failed != unavailable || (!unavailable && commit != prepared.commit) || (unavailable && commit != nil) {
			t.Fatal("exact prepared identity and failure descriptor")
		}
		if unavailable {
			a.guard.state.CompareAndSwap(daAdmissionAttempting, daAdmissionResolved)
		} else {
			commit.Abort()
		}
		a.Close()
		owner.inTransition = false
	}
	// A nonzero index distinguishes an omitted InputIndex from the first conflict.
	a := mustDAAdmission(t, mp, raw[0])
	a.snapshot.Inputs = []consensus.Outpoint{testOutpoint(1), testOutpoint(2)}
	mustReserve(t, owner, [32]byte{8}, testOutpoint(2))
	prepared, err := prepareDAAdmissionCommit(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.guard.state.CompareAndSwap(daAdmissionOpen, daAdmissionAttempting)
	commit, failure, failed := reservePreparedDAAdmissionCommit(prepared)
	if commit != nil || !failed || failure != (PendingOutpointError{Kind: PendingOutpointConflict, Msg: "", Outpoint: testOutpoint(2), InputIndex: 1, ExistingTxid: [32]byte{8}}) {
		t.Fatal("exact prepared identity and failure descriptor")
	}
	if !owner.mu.TryLock() {
		t.Fatal("raw failure retained owner")
	}
	owner.mu.Unlock()
	if daAdmit(t, txAdmitFromPendingOutpointError(&failure), TxAdmitConflict).Message != fmt.Sprintf("mempool double-spend conflict with %x", [32]byte{8}) {
		t.Fatal("raw failure mapping")
	}
	a.guard.state.CompareAndSwap(daAdmissionAttempting, daAdmissionResolved)
	a.Close()
}
