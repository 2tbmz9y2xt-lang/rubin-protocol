//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// stepWorld uses real bootstrap and replay entry. Higher context prefixes use the existing literal seeding boundary.
type stepWorld struct {
	*replayWorld
	step         *ReplayStepOwnerV1
	bodies       map[uint64][]byte
	view         *pathView
	extraHeaders [][32]byte
}

func stepBlock(t *testing.T, height uint64, parent [32]byte, timestamp uint64, txs ...*Tx) []byte {
	t.Helper()
	input := inputViewBlock(t, height, 1, txs...)
	raw := input.BlockBytes
	copy(raw[4:36], parent[:])
	binary.LittleEndian.PutUint64(raw[68:76], timestamp)
	for nonce := uint64(0); ; nonce++ {
		binary.LittleEndian.PutUint64(raw[108:116], nonce)
		if PowCheck(raw[:116], filledHash(0xff)) == nil {
			return raw
		}
	}
}

func newStepWorld(t *testing.T, tip int, active bool, txs ...*Tx) *stepWorld {
	t.Helper()
	a := -1
	if active {
		a = 0
	}
	w := &stepWorld{replayWorld: newReplayWorld(t, a), bodies: map[uint64][]byte{}, view: &pathView{}}
	w.bodies[0] = bytes.Clone(w.genesis.Published)
	for h := 1; h <= tip; h++ {
		var suffix []*Tx
		if h == tip {
			suffix = txs
		}
		raw := stepBlock(t, uint64(h), w.hashes[h-1], w.lastTime+uint64(h)*240, suffix...)
		hash := mustHash([116]byte(raw[:116]))
		w.headers, w.hashes = append(w.headers, [116]byte(raw[:116])), append(w.hashes, hash)
		w.bodies[uint64(h)] = raw
	}
	if active {
		w.pending(mdbx.StorageProfilePrunedV1, 2)
	}
	entry := &replayView{inv: replayComplete([][32]byte{w.hashes[tip]}, slices.Clone(w.headers))}
	out := w.enter(entry, replayIdentityOnly())
	logicalMDBXAssert(t, out.Err == nil && out.CanonicalTruth == "NEW" && out.Truth == 2 && out.Stage == 3, "real entry: %+v", out)
	var headers []mdbx.Mutation
	for h, hash := range w.hashes {
		if h == 0 && active {
			continue
		}
		headers = append(headers, mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: bytes.Clone(hash[:]), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(w.headers[h][:])})
	}
	for from := 0; from < len(headers); from += 1000 {
		w.apply(headers[from:min(from+1000, len(headers))]...)
	}
	w.step = NewReplayStepOwnerV1(ReplayStepContextV1{Genesis: w.genesis}, w.view, uint64(tip+1)*32)
	w.view.owner = w.step.path
	return w
}

func (w *stepWorld) call(h uint64) ReplayStepOutcomeV1 {
	return w.step.StepReplayMDBX(w.store, w.owner, w.bodies[h])
}

// The independent image includes every known key/value and all DBI counts, including artifacts, UTXOs and owners.
func (w *stepWorld) image() []mdbx.PrefixRow {
	w.t.Helper()
	rows := w.replayWorld.image()
	err := w.store.View(func(r *mdbx.Reader) error {
		for _, g := range []uint64{1, 2} {
			for _, rank := range []uint8{1, 6} {
				if err := replayImagePrefix(r, &rows, rank, binary.BigEndian.AppendUint64(nil, g)); err != nil {
					return err
				}
			}
		}
		for _, hash := range w.hashes {
			if err := replayImageGet(r, &rows, 4, hash[:]); err != nil {
				return err
			}
			if err := replayImagePrefix(r, &rows, 5, hash[:]); err != nil {
				return err
			}
		}
		for _, hash := range w.extraHeaders {
			if err := replayImageGet(r, &rows, 3, hash[:]); err != nil {
				return err
			}
		}
		return nil
	})
	logicalMDBXAssert(w.t, err == nil, "complete STEP image: %v", err)
	slices.SortFunc(rows, func(a, b mdbx.PrefixRow) int { return bytes.Compare(a.Key, b.Key) })
	return rows
}

func stepTuple(t *testing.T, out ReplayStepOutcomeV1, result, decision, canonical string, truth, stage uint8, clean bool) {
	t.Helper()
	logicalMDBXAssert(t, out.Result == result && out.Decision == decision && out.CanonicalTruth == canonical && uint8(out.Truth) == truth && uint8(out.Stage) == stage && (out.Err == nil) == clean, "STEP tuple: %+v want %s/%s/%s/%d/%d/clean%v", out, result, decision, canonical, truth, stage, clean)
}

func stepReleased(t *testing.T, w *stepWorld) {
	t.Helper()
	logicalMDBXAssert(t, w.owner.WithReservation(154611151, func() error { return nil }) == nil, "full lane retained")
	logicalMDBXAssert(t, !w.step.path.guarded && w.step.path.release == nil && w.step.path.dst == ([116]byte{}), "PATH guard/source retained")
}

func stepRead(t *testing.T, store *mdbx.Store, rank uint8, key []byte) ([]byte, bool) {
	t.Helper()
	var raw []byte
	var present bool
	err := store.View(func(r *mdbx.Reader) (err error) { raw, present, err = r.Get(logicalMDBXDBIs[rank], key); return err })
	logicalMDBXAssert(t, err == nil, "read %d/%x: %v", rank, key, err)
	return raw, present
}

func stepKey(g, h uint64) []byte {
	return binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, g), h)
}

func stepManifest(h, generated uint64, txs, spent uint32) []byte {
	raw := make([]byte, 33)
	raw[0] = 1
	binary.BigEndian.PutUint64(raw[1:9], h)
	binary.BigEndian.PutUint64(raw[17:25], generated)
	binary.BigEndian.PutUint32(raw[25:29], txs)
	binary.BigEndian.PutUint32(raw[29:33], spent)
	return raw
}

func stepArtifact(t *testing.T, w *stepWorld, rank uint8, h uint64, expected []byte, present bool) {
	t.Helper()
	key := w.hashes[h][:]
	if rank == 5 {
		key = append(bytes.Clone(key), 0)
	}
	raw, exists := stepRead(t, w.store, rank, key)
	logicalMDBXAssert(t, exists == present && bytes.Equal(raw, expected), "artifact %d at %d: %x/%v want %x/%v", rank, h, raw, exists, expected, present)
}

func stepProgress(t *testing.T, w *stepWorld, h uint64, before mdbx.StorageAuthorityV1, out ReplayStepOutcomeV1) {
	t.Helper()
	stepTuple(t, out, "", "", "NEW", 2, 3, true)
	logicalMDBXAssert(t, out.Needed == nil, "progress exposed Need")
	a := w.authority()
	logicalMDBXAssert(t, a.Replay.Cursor == (mdbx.ReplayCursorV1{Kind: 2, Height: h, BlockHash: w.hashes[h]}), "cursor is not one exact step: %+v", a.Replay.Cursor)
	a.Replay.Cursor = before.Replay.Cursor
	logicalMDBXAssert(t, reflect.DeepEqual(a, before), "STEP changed non-cursor authority: %+v %+v", a, before)
	index, present := stepRead(t, w.store, 2, stepKey(2, h))
	expected := append(bytes.Clone(w.hashes[h][:]), make([]byte, 72)...)
	if h > 0 {
		copy(expected[32:64], w.hashes[h-1][:])
	}
	binary.BigEndian.PutUint64(expected[96:], h+1)
	logicalMDBXAssert(t, present && bytes.Equal(index, expected), "exact target index: %x want %x", index, expected)
	owner, exists := stepRead(t, w.store, 7, append(binary.BigEndian.AppendUint64(nil, 2), w.hashes[h][:]...))
	logicalMDBXAssert(t, exists && bytes.Equal(owner, binary.BigEndian.AppendUint64(nil, h)), "target owner is unpaired")
	stepReleased(t, w)
}

func (w *stepWorld) prefix(t *testing.T, h uint64) {
	t.Helper()
	if h == 0 {
		return
	}
	before := w.authority()
	stepProgress(t, w, 0, before, w.call(0))
	for from := uint64(1); from < h; from += 1000 {
		var rows []mdbx.Mutation
		for i := from; i < min(from+1000, h); i++ {
			work := sideWorldWork(i + 1)
			rows = append(rows, mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: stepKey(2, i), AfterKind: mdbx.AfterLiteral, Literal: append(append(bytes.Clone(w.hashes[i][:]), w.hashes[i-1][:]...), work[:]...)})
			rows = append(rows, mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: append(binary.BigEndian.AppendUint64(nil, 2), w.hashes[i][:]...), AfterKind: mdbx.AfterLiteral, Literal: binary.BigEndian.AppendUint64(nil, i)})
		}
		if len(rows) != 0 {
			w.apply(rows...)
		}
	}
	if h > 1 {
		w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
			a.Replay.Cursor = mdbx.ReplayCursorV1{Kind: 2, Height: h - 1, BlockHash: w.hashes[h-1]}
		})
	}
}

func TestReplayStepMDBXV1(t *testing.T) {
	t.Run("progress", testStepProgress)
	t.Run("retention", testStepRetention)
	t.Run("bounds", testStepBounds)
	t.Run("need", testStepNeed)
	t.Run("context", testStepContext)
	t.Run("observation", testStepObservation)
	t.Run("constructor", testStepConstructor)
	t.Run("supplied", testStepSupplied)
	t.Run("discard", testStepDiscard)
	t.Run("panic", testStepPanic)
	t.Run("artifacts", testStepArtifacts)
	t.Run("memo", testStepMemo)
	t.Run("context_copy", testStepContextCopy)
	t.Run("retry", testStepRetry)
	t.Run("source_guard", testStepSourceGuard)
	t.Run("spent", testStepSpent)
	t.Run("parent_witness", testStepParentWitness)
	t.Run("inactive", testStepInactive)
	t.Run("historical", testStepHistorical)
	t.Run("state_remainder", testStepRemainder)
	t.Run("authority_links", testStepAuthorityLinks)
}

func testStepProgress(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprintf("B1_B1a_active%v", active), func(t *testing.T) {
			w := newStepWorld(t, 2, active)
			var slot *replayPathSlot
			for h := uint64(0); h <= 2; h++ {
				before, raw := w.authority(), bytes.Clone(w.bodies[h])
				image := w.image()
				stepProgress(t, w, h, before, w.call(h))
				stepExactImage(t, w, h, image, false)
				logicalMDBXAssert(t, bytes.Equal(w.bodies[h], raw), "caller body changed")
				if h == 0 {
					slot = w.step.path.slot
				}
				logicalMDBXAssert(t, slot == w.step.path.slot, "B29: repeated path establishment")
				generated := uint64(0)
				if h == 2 {
					generated = 4673004150
				}
				stepArtifact(t, w, 3, h, w.headers[h][:], true)
				stepArtifact(t, w, 4, h, w.bodies[h], true)
				stepArtifact(t, w, 5, h, stepManifest(h, generated, 1, 0), true)
			}
			before := w.image()
			stepTuple(t, w.call(2), "", "not applicable", "OLD", 1, 1, true)
			replaySameImage(t, before, w.image(), "B15: no activation")
		})
	}
}

func testStepRetention(t *testing.T) {
	for _, limit := range []uint64{0, 63, 64, 65} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			w.step = NewReplayStepOwnerV1(ReplayStepContextV1{Genesis: w.genesis}, w.view, limit)
			before := w.image()
			out := w.call(0)
			if limit < 64 {
				stepTuple(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "", "OLD", 1, 1, true)
				logicalMDBXAssert(t, out.Needed == nil && !w.step.DiscardV1(), "RC1: refused hold")
				replaySameImage(t, before, w.image(), "RC1 refused")
			} else {
				stepTuple(t, out, "", "", "NEW", 2, 3, true)
				logicalMDBXAssert(t, len(w.step.path.slot.hashes) == 2, "RC1 exact N")
			}
			stepReleased(t, w)
		})
	}
	w := newStepWorld(t, 1, false)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.Replay.Target.TipHeight = 0xffffffff
		a.Replay.Target.CumulativeChainwork = sideWorldWork(0x100000000)
	})
	w.step.path.limit = 137438953471
	before := w.image()
	stepTuple(t, w.call(0), "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "", "OLD", 1, 1, true)
	replaySameImage(t, before, w.image(), "RC2 checked max")
	logicalMDBXAssert(t, w.step.path.slot == nil, "RC2 allocated path")
	stepReleased(t, w)
}

func testStepBounds(t *testing.T) {
	for _, row := range []struct {
		tip        int
		h          uint64
		profile    mdbx.StorageProfileV1
		body, undo bool
	}{
		{1439, 1, 2, true, true},
		{1440, 0, 2, true, false},
		{15119, 0, 1, true, false},
		{15120, 0, 1, false, false},
		{20000, 4880, 1, false, false},
		{20000, 4881, 1, true, false},
		{2000, 100, 2, true, false},
		{20000, 18560, 1, true, false},
		{20000, 18561, 1, true, true},
	} {
		t.Run(fmt.Sprintf("tip%d_h%d_p%d", row.tip, row.h, row.profile), func(t *testing.T) {
			w := newStepWorld(t, row.tip, false)
			w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Replay.TargetProfile = row.profile })
			w.prefix(t, row.h)
			before := w.authority()
			image := w.image()
			stepProgress(t, w, row.h, before, w.call(row.h))
			stepExactImage(t, w, row.h, image, false)
			body, exists := stepRead(t, w.store, 4, w.hashes[row.h][:])
			logicalMDBXAssert(t, exists == row.body && (!exists || bytes.Equal(body, w.bodies[row.h])), "B5/B7/B17-B20 body boundary")
			_, exists = stepRead(t, w.store, 5, append(bytes.Clone(w.hashes[row.h][:]), 0))
			logicalMDBXAssert(t, exists == row.undo, "B6/B7 undo boundary")
		})
	}
}

func stepDrop(w *stepWorld, rank uint8, key []byte) {
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[rank], Key: bytes.Clone(key), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
}

func testStepNeed(t *testing.T) {
	for _, missing := range []uint64{0, 1, 2} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			w := newStepWorld(t, 2, false)
			stepDrop(w, 3, w.hashes[missing][:])
			before := w.image()
			out := w.step.StepReplayMDBX(w.store, w.owner, nil)
			stepTuple(t, out, "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)", "", "OLD", 1, 1, true)
			logicalMDBXAssert(t, out.Needed != nil && *out.Needed == (ReplayStepNeedV1{Kind: 1, Height: missing, Hash: w.hashes[missing]}), "HEADER Need: %+v", out.Needed)
			replaySameImage(t, before, w.image(), "B35 HEADER")
			logicalMDBXAssert(t, !w.step.DiscardV1(), "failed establishment published path")
			w.view.admit(w.headers[missing])
			stepProgress(t, w, 0, w.authority(), w.call(0))
			logicalMDBXAssert(t, w.view.releases == 2, "guard was not held/released on each acquisition")
			stepReleased(t, w)
		})
	}
	w := newStepWorld(t, 1, false)
	before := w.image()
	out := w.step.StepReplayMDBX(w.store, w.owner, nil)
	stepTuple(t, out, "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)", "", "OLD", 1, 1, true)
	logicalMDBXAssert(t, out.Needed != nil && *out.Needed == (ReplayStepNeedV1{Kind: 2, Hash: w.hashes[0]}), "BLOCK_BYTES Need")
	replaySameImage(t, before, w.image(), "missing body")
	logicalMDBXAssert(t, w.step.path.slot != nil, "RC6: completed path lost")
	stepProgress(t, w, 0, w.authority(), w.call(0))
}

func testStepContext(t *testing.T) {
	for _, h := range []uint64{1, 12, 10080} {
		t.Run(fmt.Sprint(h), func(t *testing.T) {
			w := newStepWorld(t, int(h), false)
			w.prefix(t, h)
			before := w.authority()
			image := w.image()
			stepProgress(t, w, h, before, w.call(h))
			stepExactImage(t, w, h, image, false)
			stepArtifact(t, w, 3, h, w.headers[h][:], true)
		})
	}
	for _, offset := range []int{32, 63, 103} {
		t.Run(fmt.Sprintf("target_local_%d", offset), func(t *testing.T) {
			w := newStepWorld(t, 2, false)
			w.prefix(t, 2)
			key := stepKey(2, 1)
			raw, _ := stepRead(t, w.store, 2, key)
			raw[offset] ^= 1
			owner := append(binary.BigEndian.AppendUint64(nil, 2), w.hashes[1][:]...)
			w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: key, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: raw}, mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: owner, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: binary.BigEndian.AppendUint64(nil, 1)})
			before := w.image()
			stepTuple(t, w.call(2), "", "target local", "OLD", 1, 1, true)
			replaySameImage(t, before, w.image(), "C14/C26")
			stepReleased(t, w)
		})
	}
}

func testStepObservation(t *testing.T) {
	t.Run("missing_input", func(t *testing.T) {
		w := newStepWorld(t, 1, false, inputViewTx(1, Outpoint{Txid: hashWithPrefix(0xa2)}))
		w.prefix(t, 1)
		before := w.image()
		i := replayStepRun(w.step, w.store, w.owner, w.bodies[1])
		stepTuple(t, i.out, "", "consensus invalid", "OLD", 1, 1, true)
		e, ok := any(i.observation.incoming).(*TxError)
		logicalMDBXAssert(t, ok && e.Code == "TX_ERR_MISSING_UTXO" && i.observation.h == 1 && i.observation.x == w.hashes[1] && i.observation.failure == nil && i.observation.cause == nil, "C31 definitive R1 first code/h/x: %+v", i.observation)
		replaySameImage(t, before, w.image(), "definitive missing input")
		stepReleased(t, w)
	})
	t.Run("missing_counter", func(t *testing.T) {
		w := newStepWorld(t, 1, false)
		w.prefix(t, 1)
		stepDrop(w, 0, binary.BigEndian.AppendUint64([]byte{0x10}, 2))
		before := w.image()
		i := replayStepRun(w.step, w.store, w.owner, w.bodies[1])
		stepTuple(t, i.out, "", "target local", "OLD", 1, 1, true)
		failure, ok := any(i.observation.incoming).(*logicalStateFailure)
		logicalMDBXAssert(t, ok && any(failure) == any(i.observation.failure) && stepSameError(failure.cause, errLogicalMDBXAbsentCounter) && stepSameError(failure.cause, i.observation.cause) && i.observation.h == 1 && i.observation.x == w.hashes[1], "C31 exact required-counter witness and cause: %+v", i.observation)
		replaySameImage(t, before, w.image(), "definitive missing counter")
		stepReleased(t, w)
	})
	t.Run("consensus_first", func(t *testing.T) {
		op := Outpoint{Txid: hashWithPrefix(0xa1)}
		w := newStepWorld(t, 1, false, inputViewTx(0, op))
		stepProgress(t, w, 0, w.authority(), w.call(0))
		before := w.image()
		i := replayStepRun(w.step, w.store, w.owner, w.bodies[1])
		stepTuple(t, i.out, "", "consensus invalid", "OLD", 1, 1, true)
		e, ok := any(i.observation.incoming).(*TxError)
		logicalMDBXAssert(t, ok && e != nil && e.Code == ErrorCode("TX_ERR_TX_NONCE_INVALID") && i.observation.h == 1 && i.observation.x == w.hashes[1] && i.observation.failure == nil && i.observation.cause == nil, "exact original consensus payload: %+v", i.observation)
		replaySameImage(t, before, w.image(), "B37/C13")
		stepReleased(t, w)
	})
	t.Run("target_local", func(t *testing.T) {
		w := newStepWorld(t, 1, false)
		stepProgress(t, w, 0, w.authority(), w.call(0))
		counter := make([]byte, 16)
		counter[15] = 1
		w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: binary.BigEndian.AppendUint64([]byte{0x10}, 2), BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: counter})
		before := w.image()
		i := replayStepRun(w.step, w.store, w.owner, w.bodies[1])
		stepTuple(t, i.out, "", "target local", "OLD", 1, 1, true)
		failure, ok := any(i.observation.incoming).(*logicalStateFailure)
		logicalMDBXAssert(t, ok && failure != nil && any(failure) == any(i.observation.failure) && stepSameError(failure.cause, i.observation.cause) && failure.kind == logicalStateFailureStoreIntegrity && failure.cause.Error() == "invalid logical state counters" && i.observation.h == 1 && i.observation.x == w.hashes[1], "original target outer/nested/predicate cause: %+v", i.observation)
		replaySameImage(t, before, w.image(), "C32a")
		stepReleased(t, w)
	})
}

func testStepConstructor(t *testing.T) {
	w := newStepWorld(t, 1, false)
	before := w.image()
	for _, n := range []int{0, 265, 267, 68000126} {
		g := w.genesis
		g.Published = make([]byte, n)
		o := NewReplayStepOwnerV1(ReplayStepContextV1{Genesis: g}, w.view, 64)
		out := o.StepReplayMDBX(w.store, w.owner, nil)
		stepTuple(t, out, "TERMINAL_LOCAL_INVARIANT(evidence)", "", "OLD", 1, 1, false)
		logicalMDBXAssert(t, out.Err.Error() == "invalid published genesis context" && o.state.context.Genesis.Published == nil && out.Needed == nil, "C33 shape before clone")
	}
	for _, zero := range []int{1, 2} {
		g := w.genesis
		if zero == 1 {
			g.ChainID = [32]byte{}
		} else {
			g.GenesisHash = [32]byte{}
		}
		out := NewReplayStepOwnerV1(ReplayStepContextV1{Genesis: g}, w.view, 64).StepReplayMDBX(nil, nil, nil)
		stepTuple(t, out, "TERMINAL_LOCAL_INVARIANT(evidence)", "", "OLD", 1, 1, false)
	}
	for _, o := range []*ReplayStepOwnerV1{nil, {}, {path: w.step.path}} {
		stepTuple(t, o.StepReplayMDBX(w.store, w.owner, nil), "TERMINAL_LOCAL_INVARIANT(evidence)", "", "OLD", 1, 1, false)
	}
	out := w.step.StepReplayMDBX(nil, nil, nil)
	stepTuple(t, out, "", "", "", 1, 1, false)
	e, ok := any(out.Err).(*mdbx.EngineError)
	logicalMDBXAssert(t, ok && e.Operation == "update" && e.Class == mdbx.EngineInvalidInput && e.Code == 22 && e.Diagnostic == "nil Store" && e.Cause == nil && !e.ReopenRequired, "nil Store priority: %+v", e)
	for _, reservation := range []*mdbx.OperationReservationOwner{nil, {}} {
		out := w.step.StepReplayMDBX(w.store, reservation, nil)
		stepTuple(t, out, "", "", "", 1, 1, false)
		logicalMDBXAssert(t, out.Err.Error() == "invalid storage operation reservation input" && out.Needed == nil, "reservation input")
	}
	replaySameImage(t, before, w.image(), "C28/C33 input")
	logicalMDBXAssert(t, w.view.headerCalls == 0 && w.view.protects == 0, "preflight provider calls")
	stepProgress(t, w, 0, w.authority(), w.call(0))
}

func testStepSupplied(t *testing.T) {
	for _, row := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"nil", func([]byte) []byte { return nil }},
		{"header", func(b []byte) []byte { return b[:116] }},
		{"truncated", func(b []byte) []byte { return b[:len(b)-1] }},
		{"trailing", func(b []byte) []byte { return append(b, 0) }},
		{"merkle", func(b []byte) []byte { b[117] ^= 1; return b }},
		{"wrong_hash", func(b []byte) []byte { b[108] ^= 1; return b }},
		{"count", func(b []byte) []byte { return append(b[:116], 0xff, 255, 255, 255, 255, 255, 255, 255, 255) }},
		{"oversized", func([]byte) []byte { return make([]byte, 68000126) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			before := w.image()
			input := row.edit(bytes.Clone(w.bodies[0]))
			snapshot := bytes.Clone(input)
			out := w.step.StepReplayMDBX(w.store, w.owner, input)
			stepTuple(t, out, "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)", "", "OLD", 1, 1, true)
			logicalMDBXAssert(t, out.Needed != nil && out.Needed.Kind == 2 && out.Needed.Height == 0 && out.Needed.Hash == w.hashes[0] && bytes.Equal(input, snapshot), "K1-K6 acquisition/ownership")
			replaySameImage(t, before, w.image(), row.name)
			stepReleased(t, w)
		})
	}
}

func testStepDiscard(t *testing.T) {
	w := newStepWorld(t, 2, false)
	stepProgress(t, w, 0, w.authority(), w.call(0))
	copy := *w.step
	logicalMDBXAssert(t, copy.path == w.step.path && copy.state == w.step.state, "public copies split ownership")
	var wg sync.WaitGroup
	var mu sync.Mutex
	count := 0
	for range 8 {
		wg.Go(func() {
			if copy.DiscardV1() {
				mu.Lock()
				count++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	logicalMDBXAssert(t, count == 1 && !copy.DiscardV1(), "RC7/RC10 discard count=%d", count)
	stepProgress(t, w, 1, w.authority(), copy.StepReplayMDBX(w.store, w.owner, w.bodies[1]))
	logicalMDBXAssert(t, copy.state.generated == w.step.state.generated && w.step.path.slot != nil, "shared next state")
	stepReleased(t, w)
}

func testStepPanic(t *testing.T) {
	w := newStepWorld(t, 1, false)
	stepDrop(w, 3, w.hashes[1][:])
	marker := &struct{ n int }{17}
	w.view.panicWith = marker
	before := w.image()
	func() {
		defer func() { logicalMDBXAssert(t, recover() == marker, "original panic payload changed") }()
		_ = w.call(0)
	}()
	logicalMDBXAssert(t, w.view.releases == 1 && w.step.path.slot == nil, "K17 failed hold/guard cleanup")
	replaySameImage(t, before, w.image(), "panic")
	stepReleased(t, w)
	w.view.panicWith = nil
	w.view.admit(w.headers[1])
	stepProgress(t, w, 0, w.authority(), w.call(0))
}

// A blocked real point provider makes Step/Discard exclusion observable without a production test seam.
func TestReplayStepMDBXV1SharedExclusion(t *testing.T) {
	w := newStepWorld(t, 1, false)
	stepDrop(w, 3, w.hashes[1][:])
	w.view.admit(w.headers[1])
	before := w.image()
	w.view.entered, w.view.block = make(chan struct{}), make(chan struct{})
	finished, discarded := make(chan ReplayStepOutcomeV1, 1), make(chan bool, 1)
	go func() { finished <- w.call(0) }()
	<-w.view.entered
	copy := *w.step
	go func() { discarded <- copy.DiscardV1() }()
	select {
	case <-discarded:
		t.Fatal("Discard crossed synchronous STEP guard")
	case <-time.After(20 * time.Millisecond):
	}
	close(w.view.block)
	stepTuple(t, <-finished, "", "", "NEW", 2, 3, true)
	logicalMDBXAssert(t, <-discarded && w.view.releases == 1, "shared release/discard")
	stepExactImage(t, w, 0, before, false)
	stepReleased(t, w)
}

func stepSameError(a, b error) bool {
	return reflect.ValueOf(a).IsValid() && reflect.ValueOf(b).IsValid() && reflect.ValueOf(a).Equal(reflect.ValueOf(b))
}

// The oracle changes only independently encoded expected rows; every other byte and DBI count stays pinned.
func stepExactImage(t *testing.T, w *stepWorld, h uint64, before []mdbx.PrefixRow, deleteBelow bool) {
	stepExactImageExtra(t, w, h, before, deleteBelow, nil, nil)
}

func stepExactImageExtra(t *testing.T, w *stepWorld, h uint64, before []mdbx.PrefixRow, deleteBelow bool, manifest []byte, extra []mdbx.PrefixRow) {
	t.Helper()
	expected := map[string][]byte{}
	beforeKeys := map[string]bool{}
	for _, row := range before {
		expected[string(row.Key)] = bytes.Clone(row.Value)
		beforeKeys[string(row.Key)] = true
	}
	for _, row := range extra {
		expected[string(row.Key)] = bytes.Clone(row.Value)
	}
	a, err := mdbx.DecodeStorageAuthorityV1(expected[string([]byte{0, 2})])
	logicalMDBXAssert(t, err == nil, "oracle authority: %v", err)
	a.Replay.Cursor = mdbx.ReplayCursorV1{Kind: 2, Height: h, BlockHash: w.hashes[h]}
	expected[string([]byte{0, 2})], err = a.Encode()
	logicalMDBXAssert(t, err == nil, "oracle legal cursor: %v", err)
	index := append(bytes.Clone(w.hashes[h][:]), make([]byte, 72)...)
	if h > 0 {
		copy(index[32:64], w.hashes[h-1][:])
	}
	binary.BigEndian.PutUint64(index[96:], h+1)
	expected[string(append([]byte{2}, stepKey(2, h)...))] = index
	expected[string(append(binary.BigEndian.AppendUint64([]byte{7}, 2), w.hashes[h][:]...))] = binary.BigEndian.AppendUint64(nil, h)
	expected[string(append([]byte{3}, w.hashes[h][:]...))] = bytes.Clone(w.headers[h][:])
	stepOracleState(t, w, h, expected)
	stepOracleArtifacts(t, w, h, a, expected, deleteBelow, manifest)
	counts := bytes.Clone(expected[string([]byte{255})])
	for _, rank := range []byte{0, 1, 2, 3, 4, 5, 6, 7} {
		var delta int64
		for key := range expected {
			if key[0] == rank && !beforeKeys[key] {
				delta++
			}
		}
		for _, row := range before {
			if row.Key[0] == rank {
				if _, ok := expected[string(row.Key)]; !ok {
					delta--
				}
			}
		}
		count := binary.BigEndian.Uint64(counts[int(rank)*8:])
		binary.BigEndian.PutUint64(counts[int(rank)*8:], uint64(int64(count)+delta))
	}
	expected[string([]byte{255})] = counts
	after := w.image()
	logicalMDBXAssert(t, len(after) == len(expected), "complete image member count: %d want %d", len(after), len(expected))
	for _, row := range after {
		logicalMDBXAssert(t, bytes.Equal(row.Value, expected[string(row.Key)]), "complete image differs at %x: %x want %x", row.Key, row.Value, expected[string(row.Key)])
	}
}

func stepOracleState(t *testing.T, w *stepWorld, h uint64, expected map[string][]byte) {
	t.Helper()
	pb, err := ParseBlockBytes(w.bodies[h])
	logicalMDBXAssert(t, err == nil, "oracle parse")
	for i, tx := range pb.Txs {
		if i > 0 {
			for _, input := range tx.Inputs {
				delete(expected, string(append(binary.BigEndian.AppendUint64([]byte{1}, 2), append(input.PrevTxid[:], binary.BigEndian.AppendUint32(nil, input.PrevVout)...)...)))
			}
		}
		for vout, output := range tx.Outputs {
			if output.CovenantType == 2 || output.CovenantType == 0x103 {
				continue
			}
			key := append(binary.BigEndian.AppendUint64([]byte{1}, 2), pb.Txids[i][:]...)
			key = binary.BigEndian.AppendUint32(key, uint32(vout))
			value := binary.LittleEndian.AppendUint64(nil, output.Value)
			value = binary.LittleEndian.AppendUint16(value, output.CovenantType)
			logicalMDBXAssert(t, len(output.CovenantData) < 253, "oracle corpus requires short independent data encoding")
			value = append(append(value, byte(len(output.CovenantData))), output.CovenantData...)
			value = binary.LittleEndian.AppendUint64(value, h)
			value = append(value, byte(0))
			if i == 0 {
				value[len(value)-1] = 1
			}
			expected[string(key)] = value
		}
	}
	var total, entries uint64
	for key, value := range expected {
		if key[0] == 1 && len(key) == 45 && binary.BigEndian.Uint64([]byte(key)[1:9]) == 2 {
			total += 36 + uint64(len(value))
			entries++
		}
	}
	key := binary.BigEndian.AppendUint64([]byte{0, 0x10}, 2)
	expected[string(key)] = binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, total), entries)
}

func stepOracleArtifacts(t *testing.T, w *stepWorld, h uint64, a mdbx.StorageAuthorityV1, expected map[string][]byte, deleteBelow bool, manifest []byte) {
	t.Helper()
	tip := a.Replay.Target.TipHeight
	b, u := uint64(0), uint64(0)
	if a.Replay.TargetProfile == 1 && tip >= 15120 {
		b = tip - 15119
	}
	if tip >= 1440 {
		u = tip - 1439
	}
	bodyKey := string(append([]byte{4}, w.hashes[h][:]...))
	if h >= b {
		expected[bodyKey] = bytes.Clone(w.bodies[h])
	} else if deleteBelow {
		delete(expected, bodyKey)
	}
	pb, err := ParseBlockBytes(w.bodies[h])
	logicalMDBXAssert(t, err == nil, "oracle parsed body")
	key := string(append(append([]byte{5}, w.hashes[h][:]...), 0))
	if h < u {
		if deleteBelow {
			delete(expected, key)
		}
		return
	}
	if manifest != nil {
		expected[key] = manifest
		return
	}
	logicalMDBXAssert(t, len(pb.Txs) == 1, "normal oracle must not invent spent undo")
	generated := uint64(0)
	for i := uint64(1); i < h; i++ {
		generated += (4900000000000000 - generated) >> 20
	}
	expected[key] = stepManifest(h, generated, 1, 0)
}

func stepSeedArtifact(w *stepWorld, rank uint8, h uint64, value []byte) {
	key := bytes.Clone(w.hashes[h][:])
	if rank == 5 {
		key = append(key, 0)
	}
	_, present := stepRead(w.t.(*testing.T), w.store, rank, key)
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[rank], Key: key, BeforePresent: present, AfterKind: mdbx.AfterLiteral, Literal: value})
}

func testStepArtifacts(t *testing.T) {
	for _, kind := range []uint8{3, 4, 5} {
		t.Run(fmt.Sprintf("identical_%d", kind), func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			if kind == 4 {
				stepSeedArtifact(w, kind, 0, w.bodies[0])
			}
			if kind == 5 {
				stepSeedArtifact(w, kind, 0, stepManifest(0, 0, 1, 0))
			}
			before := w.image()
			stepProgress(t, w, 0, w.authority(), w.call(0))
			stepExactImage(t, w, 0, before, false)
		})
	}
	for _, row := range []struct {
		name  string
		rank  uint8
		value func(*stepWorld) []byte
	}{
		{"header_misnamed", 3, func(w *stepWorld) []byte { b := bytes.Clone(w.headers[0][:]); b[68] ^= 1; return b }},
		{"body_merkle", 4, func(w *stepWorld) []byte { b := bytes.Clone(w.bodies[0]); b[117] ^= 1; return b }},
		{"body_trailing", 4, func(w *stepWorld) []byte { return append(bytes.Clone(w.bodies[0]), 0) }},
		{"undo_height", 5, func(*stepWorld) []byte { return stepManifest(1, 0, 1, 0) }},
		{"undo_generated", 5, func(*stepWorld) []byte { return stepManifest(0, 1, 1, 0) }},
		{"undo_tx_zero", 5, func(*stepWorld) []byte { return stepManifest(0, 0, 0, 0) }},
		{"undo_tx_two", 5, func(*stepWorld) []byte { return stepManifest(0, 0, 2, 0) }},
		{"undo_spent", 5, func(*stepWorld) []byte { return stepManifest(0, 0, 1, 1) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			stepSeedArtifact(w, row.rank, 0, row.value(w))
			before := w.image()
			out := w.call(0)
			stepTuple(t, out, selectedSideIntegrity, "", "OLD", 1, 1, false)
			logicalMDBXAssert(t, out.Needed == nil, "stored defect exposed Need")
			w.store = w.reopen()
			replaySameImage(t, before, w.image(), row.name)
			stepReleased(t, w)
		})
	}
	for _, row := range []struct {
		name   string
		active bool
		h      uint64
		staged bool
	}{
		{"exact_old", true, 0, false},
		{"pre_genesis", false, 0, false},
		{"above_old", true, 1, false},
		{"staged_target", false, 0, true},
		{"different_old", true, 1, false},
	} {
		t.Run("below_"+row.name, func(t *testing.T) {
			w := newStepWorld(t, 15120, row.active)
			if row.name == "different_old" {
				stepActiveOther(t, w)
			}
			w.prefix(t, row.h)
			stepSeedArtifact(w, 4, row.h, w.bodies[row.h])
			stepSeedArtifact(w, 5, row.h, stepManifest(row.h, 0, 1, 0))
			if row.staged {
				index := append(bytes.Clone(w.hashes[0][:]), make([]byte, 72)...)
				index[103] = 1
				w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: stepKey(2, 0), AfterKind: mdbx.AfterLiteral, Literal: index}, mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: append(binary.BigEndian.AppendUint64(nil, 2), w.hashes[0][:]...), AfterKind: mdbx.AfterLiteral, Literal: make([]byte, 8)})
			}
			before := w.image()
			stepProgress(t, w, row.h, w.authority(), w.call(row.h))
			keep := row.name == "exact_old"
			body, undo := []byte(nil), []byte(nil)
			if keep {
				body, undo = w.bodies[row.h], stepManifest(row.h, 0, 1, 0)
			}
			stepArtifact(t, w, 4, row.h, body, keep)
			stepArtifact(t, w, 5, row.h, undo, keep)
			stepExactImage(t, w, row.h, before, !keep)
		})
	}
}

func testStepMemo(t *testing.T) {
	for _, memoHeight := range []uint64{0, 1, 2, 3} {
		t.Run(fmt.Sprint(memoHeight), func(t *testing.T) {
			w := newStepWorld(t, 3, false)
			w.prefix(t, 2)
			generated := uint64(0)
			for h := uint64(1); h < memoHeight; h++ {
				generated += (4900000000000000 - generated) >> 20
			}
			w.step.state.height, w.step.state.generated, w.step.state.memo = memoHeight, Uint128{Lo: generated}, memoHeight != 0
			logicalMDBXAssert(t, w.step.DiscardV1() && !w.step.DiscardV1(), "memo discard")
			before := w.image()
			stepProgress(t, w, 2, w.authority(), w.call(2))
			stepArtifact(t, w, 5, 2, stepManifest(2, 4673004150, 1, 0), true)
			stepExactImage(t, w, 2, before, false)
		})
	}
}

func testStepContextCopy(t *testing.T) {
	w := newStepWorld(t, 1, false)
	g := w.genesis
	g.Published = bytes.Clone(g.Published)
	o := NewReplayStepOwnerV1(ReplayStepContextV1{Genesis: g}, w.view, 64)
	g.Published[117] ^= 1
	g.ChainID, g.GenesisHash = [32]byte{}, [32]byte{}
	before := w.image()
	stepTuple(t, o.StepReplayMDBX(w.store, w.owner, w.bodies[0]), "", "", "NEW", 2, 3, true)
	stepExactImage(t, w, 0, before, false)
	g = w.genesis
	g.Published = bytes.Clone(g.Published)
	g.Published[117] ^= 1
	bad := NewReplayStepOwnerV1(ReplayStepContextV1{Genesis: g}, w.view, 64)
	out := bad.StepReplayMDBX(nil, nil, nil)
	stepTuple(t, out, selectedSideInvariant, "", "OLD", 1, 1, false)
	logicalMDBXAssert(t, out.Err.Error() == "published genesis context commitment mismatch", "C33 valid-shape exact commitment error: %v", out.Err)
}

func testStepRetry(t *testing.T) {
	w := newStepWorld(t, 3, false)
	stepDrop(w, 3, w.hashes[3][:])
	stepDrop(w, 3, w.hashes[2][:])
	before := w.image()
	for _, h := range []uint64{3, 2} {
		out := w.step.StepReplayMDBX(w.store, w.owner, nil)
		stepTuple(t, out, replayEntryRecovery, "", "OLD", 1, 1, true)
		logicalMDBXAssert(t, out.Needed != nil && *out.Needed == (ReplayStepNeedV1{Kind: 1, Height: h, Hash: w.hashes[h]}) && w.step.path.slot == nil && !w.step.DiscardV1(), "B35 two acquisitions: %+v", out)
		replaySameImage(t, before, w.image(), "retry no partial hold")
		w.view.admit(w.headers[h])
	}
	stepProgress(t, w, 0, w.authority(), w.call(0))
	logicalMDBXAssert(t, w.view.releases == 3, "three guard lifetimes")
	w.store = w.reopen()
	w.step = NewReplayStepOwnerV1(ReplayStepContextV1{Genesis: w.genesis}, w.view, 128)
	w.view.owner = w.step.path
	stepProgress(t, w, 1, w.authority(), w.call(1))
	logicalMDBXAssert(t, w.step.path.slot != nil, "RC8 real reopened owner")
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.Replay.Target.TipHeight, a.Replay.Target.TipHash, a.Replay.Target.CumulativeChainwork = 2, w.hashes[2], sideWorldWork(3)
	})
	before = w.image()
	oldSlot := w.step.path.slot
	stepTuple(t, w.call(2), selectedSideCapacity, "", "OLD", 1, 1, true)
	logicalMDBXAssert(t, w.step.path.slot == oldSlot, "foreign slot was changed")
	replaySameImage(t, before, w.image(), "RC9 foreign target")
	logicalMDBXAssert(t, w.step.DiscardV1() && !w.step.DiscardV1(), "foreign discard")
	stepProgress(t, w, 2, w.authority(), w.call(2))
}

func testStepSourceGuard(t *testing.T) {
	for _, mode := range []string{"churn", "nil_release", "nil_source"} {
		t.Run(mode, func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			stepDrop(w, 3, w.hashes[1][:])
			w.view.admit(w.headers[1])
			before := w.image()
			authority := w.authority()
			if mode == "churn" {
				w.view.churn = true
			}
			if mode == "nil_release" {
				w.view.nilRelease = true
			}
			if mode == "nil_source" {
				w.step = NewReplayStepOwnerV1(ReplayStepContextV1{Genesis: w.genesis}, nil, 64)
			}
			out := w.call(0)
			if mode == "churn" {
				stepProgress(t, w, 0, authority, out)
				stepExactImage(t, w, 0, before, false)
				logicalMDBXAssert(t, w.view.releases == 1 && w.view.headerCalls == 1 && w.view.unclear == 0, "B40 false Protect must guard admitted point")
			} else {
				result := replayEntryRecovery
				if mode == "nil_release" {
					result = selectedSideInvariant
				}
				stepTuple(t, out, result, "", "OLD", 1, 1, mode == "nil_source")
				replaySameImage(t, before, w.image(), mode)
				logicalMDBXAssert(t, w.step.path.slot == nil, "failed provider published slot")
			}
			stepReleased(t, w)
		})
	}
}

func stepReplaceSuffix(t *testing.T, w *stepWorld, txs ...*Tx) {
	t.Helper()
	logicalMDBXAssert(t, len(w.hashes) == 2, "suffix corpus is exactly h1")
	old := w.hashes[1]
	raw := stepBlock(t, 1, w.hashes[0], w.lastTime+240, txs...)
	w.bodies[1], w.headers[1], w.hashes[1] = raw, [116]byte(raw[:116]), mustHash([116]byte(raw[:116]))
	stepDrop(w, 3, old[:])
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: w.hashes[1][:], AfterKind: mdbx.AfterLiteral, Literal: w.headers[1][:]})
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Replay.Target.TipHash = w.hashes[1] })
	w.step.DiscardV1()
}

func stepSeedInputs(t *testing.T, w *stepWorld, entries map[Outpoint]UtxoEntry) map[Outpoint][]byte {
	t.Helper()
	values := map[Outpoint][]byte{}
	var total, count uint64
	key := binary.BigEndian.AppendUint64([]byte{0x10}, 2)
	counter, present := stepRead(t, w.store, 0, key)
	logicalMDBXAssert(t, present && len(counter) == 16, "seed complete target counter")
	total, count = binary.BigEndian.Uint64(counter[:8]), binary.BigEndian.Uint64(counter[8:])
	var rows []mdbx.Mutation
	for op, entry := range entries {
		value := logicalMDBXValue(entry)
		values[op] = value
		total += uint64(len(value)) + 36
		count++
		rowKey := append(binary.BigEndian.AppendUint64(nil, 2), op.Txid[:]...)
		rowKey = binary.BigEndian.AppendUint32(rowKey, op.Vout)
		rows = append(rows, mdbx.Mutation{DBI: logicalMDBXDBIs[1], Key: rowKey, AfterKind: mdbx.AfterLiteral, Literal: value})
	}
	rows = append(rows, mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: key, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, total), count)})
	for from := 0; from < len(rows); from += 1000 {
		w.apply(rows[from:min(from+1000, len(rows))]...)
	}
	return values
}

// The real connector creates these output identities, and the real planner observes their identical OLD rows.
// No view verdict or successful plan is supplied by the test.
func stepRemainderWorld(t *testing.T, outputs int) (*stepWorld, []mdbx.PrefixRow, []byte, []byte) {
	t.Helper()
	w := newStepWorld(t, 1, false)
	w.prefix(t, 1)
	kp := mustMLDSA87Keypair(t)
	data := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	entries := map[Outpoint]UtxoEntry{}
	var txs []*Tx
	var firstKey, undoKey []byte
	var firstOld []byte
	for remaining := outputs; remaining > 0; {
		ordinal := uint32(len(txs))
		op := Outpoint{Txid: hashWithPrefix(0xa5), Vout: ordinal}
		entries[op] = UtxoEntry{Value: 2000, CovenantType: 1, CovenantData: data}
		tx := inputViewTx(uint64(ordinal)+1, op)
		n := min(1000, remaining)
		tx.Outputs = make([]TxOutput, n)
		for j := range tx.Outputs {
			tx.Outputs[j] = TxOutput{Value: 1, CovenantType: 1, CovenantData: bytes.Clone(data)}
		}
		tx.Witness[0] = signP2PKInputWitness(t, tx, 0, 2000, w.genesis.ChainID, kp)
		raw, err := MarshalTx(tx)
		logicalMDBXAssert(t, err == nil, "actual remainder tx")
		txid := testTxID(t, raw)
		for j := 0; j < n; j++ {
			entries[Outpoint{Txid: txid, Vout: uint32(j)}] = UtxoEntry{Value: 1, CovenantType: 1, CovenantData: bytes.Clone(data), CreationHeight: 1}
		}
		if ordinal == 0 {
			firstKey = binary.BigEndian.AppendUint32(append(binary.BigEndian.AppendUint64(nil, 2), txid[:]...), 0)
			firstOld = logicalMDBXValue(entries[op])
		}
		txs = append(txs, tx)
		remaining -= n
	}
	stepSeedInputs(t, w, entries)
	stepReplaceSuffix(t, w, txs...)
	undoKey = binary.BigEndian.AppendUint32(append(bytes.Clone(w.hashes[1][:]), 1), 1)
	undoKey = binary.BigEndian.AppendUint32(undoKey, 0)
	input := hashWithPrefix(0xa5)
	undoKey = binary.BigEndian.AppendUint32(append(undoKey, input[:]...), 0)
	return w, w.image(), firstKey, append(bytes.Clone(undoKey), firstOld...)
}

func testStepRemainder(t *testing.T) {
	t.Run("B41_actual_identical_output", func(t *testing.T) {
		w, before, key, undo := stepRemainderWorld(t, 1)
		old, present := stepRead(t, w.store, 1, key)
		logicalMDBXAssert(t, present, "actual readonly STATE source")
		stepProgress(t, w, 1, w.authority(), w.call(1))
		after, present := stepRead(t, w.store, 1, key)
		logicalMDBXAssert(t, present && bytes.Equal(old, after), "readonly STATE changed")
		extra := []mdbx.PrefixRow{{Key: append([]byte{5}, undo[:77]...), Value: undo[77:]}}
		stepExactImageExtra(t, w, 1, before, false, stepManifest(1, 0, 2, 1), extra)
	})
	t.Run("C35_actual_count_before_copy", func(t *testing.T) {
		w, before, _, _ := stepRemainderWorld(t, 17000)
		out := w.call(1)
		stepTuple(t, out, selectedSideCapacity, "", "OLD", 1, 1, false)
		failure, ok := any(out.Err).(*selectedSideFailure)
		logicalMDBXAssert(t, out.Needed == nil && ok && failure.result == selectedSideCapacity && failure.cause.Error() == "replay consulted remainder exceeds bound", "actual remainder refusal: %+v", out)
		replaySameImage(t, before, w.image(), "count admission before copy and native writes")
		stepReleased(t, w)
	})
}

func stepSigned(t *testing.T, w *stepWorld, kp *MLDSA87Keypair, nonce uint64, entries map[Outpoint]UtxoEntry, ops ...Outpoint) *Tx {
	t.Helper()
	tx := inputViewSignedTx(t, nonce, entries, kp, ops...)
	for i, op := range ops {
		tx.Witness[i] = signP2PKInputWitness(t, tx, uint32(i), entries[op].Value, w.genesis.ChainID, kp)
	}
	return tx
}

func stepSpentWorld(t *testing.T) (*stepWorld, Outpoint, []byte, []byte) {
	t.Helper()
	w := newStepWorld(t, 1, false)
	w.prefix(t, 1)
	kp := mustMLDSA87Keypair(t)
	op := Outpoint{Txid: hashWithPrefix(0x91), Vout: 3}
	entries := map[Outpoint]UtxoEntry{op: {Value: 1000, CovenantType: 1, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}}
	oldValues := stepSeedInputs(t, w, entries)
	first := stepSigned(t, w, kp, 1, entries, op)
	raw, err := MarshalTx(first)
	logicalMDBXAssert(t, err == nil, "first transaction")
	created := Outpoint{Txid: testTxID(t, raw)}
	entries[created] = UtxoEntry{Value: 990, CovenantType: 1, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes()), CreationHeight: 1}
	second := stepSigned(t, w, kp, 2, entries, created)
	stepReplaceSuffix(t, w, first, second)
	key := append(bytes.Clone(w.hashes[1][:]), 1)
	key = binary.BigEndian.AppendUint32(key, 1)
	key = binary.BigEndian.AppendUint32(key, 0)
	key = append(key, op.Txid[:]...)
	key = binary.BigEndian.AppendUint32(key, 3)
	return w, created, oldValues[op], key
}

func testStepSpent(t *testing.T) {
	w, created, oldValue, key := stepSpentWorld(t)
	before := w.image()
	stepProgress(t, w, 1, w.authority(), w.call(1))
	stepArtifact(t, w, 5, 1, stepManifest(1, 0, 3, 1), true)
	value, present := stepRead(t, w.store, 5, key)
	logicalMDBXAssert(t, present && bytes.Equal(value, oldValue), "B25 original OLD/ref exact tx/input/vout: %x", value)
	var family []mdbx.PrefixRow
	err := w.store.View(func(r *mdbx.Reader) error { return replayImagePrefix(r, &family, 5, w.hashes[1][:]) })
	logicalMDBXAssert(t, err == nil && len(family) == 2, "created-and-spent entered undo: %+v %v", family, err)
	for _, spent := range []Outpoint{{Txid: hashWithPrefix(0x91), Vout: 3}, created} {
		key := append(binary.BigEndian.AppendUint64(nil, 2), spent.Txid[:]...)
		key = binary.BigEndian.AppendUint32(key, spent.Vout)
		_, exists := stepRead(t, w.store, 1, key)
		logicalMDBXAssert(t, !exists, "spent output remains")
	}
	stepExactSpentImage(t, w, before, key, oldValue)
}

func stepExactSpentImage(t *testing.T, w *stepWorld, before []mdbx.PrefixRow, undoKey, oldValue []byte) {
	t.Helper()
	// Expected state is independently derived from the original body; undo's one physical value is the preimage.
	extra := []mdbx.PrefixRow{{Key: append([]byte{5}, undoKey...), Value: bytes.Clone(oldValue)}}
	stepExactImageExtra(t, w, 1, before, false, stepManifest(1, 0, 3, 1), extra)
}

func testStepParentWitness(t *testing.T) {
	for _, residual := range []bool{false, true} {
		t.Run(fmt.Sprint(residual), func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			w.prefix(t, 1)
			kp := mustMLDSA87Keypair(t)
			op1, op2 := Outpoint{Txid: hashWithPrefix(0x92)}, Outpoint{Txid: hashWithPrefix(0x93)}
			entry := UtxoEntry{Value: 1000, CovenantType: 1, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}
			entries := map[Outpoint]UtxoEntry{op1: entry, op2: entry}
			values := stepSeedInputs(t, w, entries)
			tx := stepSigned(t, w, kp, 1, entries, op1, op2)
			stepReplaceSuffix(t, w, tx)
			length := uint64(len(values[op1])) + 36
			cause := "parent counters are insufficient for present rows"
			if residual {
				length++
				cause = "invalid residual logical state counters"
			}
			key := binary.BigEndian.AppendUint64([]byte{0x10}, 2)
			w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: key, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, length), 1)})
			before := w.image()
			i := replayStepRun(w.step, w.store, w.owner, w.bodies[1])
			stepTuple(t, i.out, "", "target local", "OLD", 1, 1, true)
			failure, ok := any(i.observation.incoming).(*logicalStateFailure)
			logicalMDBXAssert(t, ok && any(failure) == any(i.observation.failure) && stepSameError(failure.cause, i.observation.cause) && failure.cause.Error() == cause && i.observation.h == 1 && i.observation.x == w.hashes[1], "C32b/c exact current epoch outer/cause: %+v", i.observation)
			replaySameImage(t, before, w.image(), "real decoded parent-prefix witness")
			stepReleased(t, w)
		})
	}
}

func testStepInactive(t *testing.T) {
	w := newStepWorld(t, 1, false)
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Phase, a.Lifecycle, a.Replay = 1, 1, nil })
	before := w.image()
	stepTuple(t, w.call(0), "", "not applicable", "OLD", 1, 1, true)
	replaySameImage(t, before, w.image(), "C15 legal NONE")
	logicalMDBXAssert(t, w.view.protects == 0 && w.view.headerCalls == 0 && w.step.path.slot == nil, "not-applicable data reads")
	stepReleased(t, w)
}

func testStepAuthorityLinks(t *testing.T) {
	for _, mode := range []string{"chain", "genesis", "cursor"} {
		t.Run(mode, func(t *testing.T) {
			w := newStepWorld(t, 3, false)
			w.prefix(t, 2)
			w.step.DiscardV1()
			w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
				switch mode {
				case "chain":
					a.Replay.Target.ChainID[0] ^= 1
				case "genesis":
					a.Replay.Target.GenesisHash[0] ^= 1
				case "cursor":
					a.Replay.Cursor.BlockHash[0] ^= 1
				}
			})
			before := w.image()
			out := w.call(2)
			stepTuple(t, out, selectedSideIntegrity, "", "OLD", 1, 1, false)
			failure, ok := any(out.Err).(*selectedSideFailure)
			cause := "replay target contradicts the genesis context"
			if mode == "cursor" {
				cause = "replay path ancestry does not reach the cursor"
			}
			logicalMDBXAssert(t, ok && failure.cause.Error() == cause && out.Needed == nil && w.step.path.slot == nil, "C21/C23/C24 original first source: %+v", out)
			stepReleased(t, w)
			w.store = w.reopen()
			replaySameImage(t, before, w.image(), "authority/source contradiction")
		})
	}
}

func stepActiveOther(t *testing.T, w *stepWorld) [32]byte {
	t.Helper()
	header, hash := replayHeader(t, w.hashes[0], filledHash(0xff), w.lastTime+239)
	w.extraHeaders = append(w.extraHeaders, hash)
	index := append(append(bytes.Clone(hash[:]), w.hashes[0][:]...), make([]byte, 40)...)
	index[103] = 2
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: hash[:], AfterKind: mdbx.AfterLiteral, Literal: header[:]}, mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: stepKey(1, 1), AfterKind: mdbx.AfterLiteral, Literal: index}, mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: append(binary.BigEndian.AppendUint64(nil, 1), hash[:]...), AfterKind: mdbx.AfterLiteral, Literal: binary.BigEndian.AppendUint64(nil, 1)})
	return hash
}

// The context's supplied rotation is height-sensitive; replacing it with an ambient default changes the result.
type stepHistoricalRotation struct {
	boundary uint64
	heights  []uint64
}

func (r *stepHistoricalRotation) NativeCreateSuites(h uint64) *NativeSuiteSet {
	r.heights = append(r.heights, h)
	if h < r.boundary {
		return NewNativeSuiteSet()
	}
	return NewNativeSuiteSet(SUITE_ID_ML_DSA_87)
}

func (r *stepHistoricalRotation) NativeSpendSuites(h uint64) *NativeSuiteSet {
	r.heights = append(r.heights, h)
	return NewNativeSuiteSet(SUITE_ID_ML_DSA_87)
}

func testStepHistorical(t *testing.T) {
	for _, h := range []uint64{1, 2} {
		t.Run(fmt.Sprint(h), func(t *testing.T) {
			w := newStepWorld(t, 2, false)
			w.prefix(t, h)
			rotation := &stepHistoricalRotation{boundary: 2}
			registry := NewSuiteRegistryFromParams([]SuiteParams{canonicalDefaultRuntimeSuiteParams()})
			w.step = NewReplayStepOwnerV1(ReplayStepContextV1{Genesis: w.genesis, Rotation: rotation, Registry: registry}, w.view, 96)
			w.view.owner = w.step.path
			before := w.image()
			authority := w.authority()
			i := replayStepRun(w.step, w.store, w.owner, w.bodies[h])
			logicalMDBXAssert(t, len(rotation.heights) > 0, "selected historical rotation was replaced")
			for _, observed := range rotation.heights {
				logicalMDBXAssert(t, observed == h, "historical height became %d want %d", observed, h)
			}
			if h == 1 {
				stepTuple(t, i.out, "", "consensus invalid", "OLD", 1, 1, true)
				e, ok := any(i.observation.incoming).(*TxError)
				logicalMDBXAssert(t, ok && e.Code == "TX_ERR_SIG_ALG_INVALID" && i.observation.h == h && i.observation.x == w.hashes[h], "B33 historical boundary code/h/x")
				replaySameImage(t, before, w.image(), "historical pre-boundary")
			} else {
				stepProgress(t, w, h, authority, i.out)
				stepExactImage(t, w, h, before, false)
			}
			stepReleased(t, w)
		})
	}
	w, _, oldValue, key := stepSpentWorld(t)
	rotation := &stepHistoricalRotation{}
	context := ReplayStepContextV1{Genesis: w.genesis, Rotation: rotation, Registry: NewSuiteRegistryFromParams(nil)}
	w.step = NewReplayStepOwnerV1(context, w.view, 64)
	w.view.owner = w.step.path
	before := w.image()
	i := replayStepRun(w.step, w.store, w.owner, w.bodies[1])
	stepTuple(t, i.out, "", "consensus invalid", "OLD", 1, 1, true)
	e, ok := any(i.observation.incoming).(*TxError)
	logicalMDBXAssert(t, ok && e.Code == "TX_ERR_SIG_ALG_INVALID" && e.Msg == "CORE_P2PK suite not registered" && i.observation.h == 1 && i.observation.x == w.hashes[1], "B33 selected native registry was replaced by ambient default")
	replaySameImage(t, before, w.image(), "selected registry rejection")
	context.Registry = NewSuiteRegistryFromParams([]SuiteParams{canonicalDefaultRuntimeSuiteParams()})
	w.step = NewReplayStepOwnerV1(context, w.view, 64)
	w.view.owner = w.step.path
	stepProgress(t, w, 1, w.authority(), w.call(1))
	stepExactSpentImage(t, w, before, key, oldValue)
	for _, h := range rotation.heights {
		logicalMDBXAssert(t, h == 1, "supplied spend context height drifted")
	}
}
