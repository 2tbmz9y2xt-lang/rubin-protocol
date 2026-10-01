//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"bytes"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// prepareSide invokes the separate RP entrypoint with retain's input and lane proofs.
func (w *ssqWorld) prepareSide(raw []byte, tip *mdbx.AuthorityPointV1) SelectedSideMutationOutcome {
	w.t.Helper()
	return w.operate(PrepareSelectedSideRollingMDBX, raw, tip)
}

// rollWorld is canonical 0..2 (tip work 2^40) beside a mined full side 1..1440/F0, g2, tip work 1441, 1000 logical
// bytes per row; its exact-tip child at 1441 is selected and does not win K23.
func rollWorld(t *testing.T) (*ssqWorld, []byte) {
	t.Helper()
	w := newRetainWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
	w.retainSide(0, 1_440, 1_440, 1_441, false)
	return w, w.child(w.side[1_440], 1_441, nil)
}

// wantIncomingAbsent proves the incoming child's header, body and SideLink(2,1441) were never written.
func (w *ssqWorld) wantIncomingAbsent(label string, raw []byte) {
	w.t.Helper()
	hash := ssqHash(raw)
	w.wantAbsent(label+": incoming header", 3, bytes.Clone(hash[:]))
	w.wantAbsent(label+": body1441 absent", 4, bytes.Clone(hash[:]))
	w.wantAbsent(label+": incoming link", 6, ssqMust(mdbx.HeightKey(2, 1_441)))
}

// expectPrepared records RP over the full pre-state: count 1439, logical bytes 1440000 minus the literal oldest body
// length, tip/hash/work/g/F/next unchanged, PRUNE_GC/STABLE with SIDE(2,1,1,1); the unkept oldest header is deleted.
func (w *ssqWorld) expectPrepared(prior mdbx.StorageAuthorityV1) {
	w.t.Helper()
	oldest := w.side[1]
	body := w.rows[string(append([]byte{4}, oldest[:]...))].value
	side := *prior.SelectedSide
	side.RowCount, side.LogicalBytes = 1_439, 1_440_000-uint64(len(body))
	a := prior
	a.SelectedSide, a.Phase = &side, mdbx.StoragePhasePruneGCV1
	a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 2, FirstHeight: 1, LastHeight: 1, NextHeight: 1}}}
	w.authorityMutation(a)
	w.absentRow(3, bytes.Clone(oldest[:]))
}

func TestSelectedSideRolling(t *testing.T) {
	old, pre := mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite
	newT, crossed := mdbx.CommitTruthNew, mdbx.UpdateStageCommitMayHaveCrossed
	t.Run("A5", func(t *testing.T) {
		w, raw := rollWorld(t)
		prior := w.tracked()
		retainWant(t, "healthy RP clean NEW empty Result/NOT_APPLICABLE", w.prepareSide(raw, w.tipAt(2)), "", "", retainNA, newT, crossed, true)
		got := w.persisted()
		if got.SelectedSide == nil || got.SelectedSide.TipHeight != 1_440 || got.SelectedSide.TipHash != w.side[1_440] || got.SelectedSide.CumulativeChainwork != ssqWork(1_441) {
			t.Fatalf("Prepared tip/hash/work unchanged: %+v", got.SelectedSide)
		}
		w.expectPrepared(prior)
		w.wantImage("exact Prepared F0 image: oldest body and link kept, other bodies/links 2..1440 kept")
		w.wantAbsent("unkept header1 deleted", 3, bytes.Clone(w.side[1][:]))
		w.wantIncomingAbsent("A5", raw)
		w.wantAbsent("no compact undo", 5, mdbx.UndoManifestKey(ssqHash(raw)))
		// R-e: the Prepared side plus its pending SIDE row and the incoming child exceed the aggregate; Retain refuses
		// with typed branch_data and the preparation stays committed (on the verified handle, before reopen).
		retainWantRefusal(t, "R-e Prepared preserved/no body1441", w.retain(raw, w.tipAt(2)), ssqBranch, "")
		w.wantImage("R-e Prepared preserved")
		w.wantIncomingAbsent("R-e", raw)
		w.reopen()
		w.wantImage("A5 persisted image after reopen")
	})
	t.Run("A5-generation", func(t *testing.T) {
		// An unrelated pending GENERATION span (obsolete g3) is preserved; the SIDE span is appended after it.
		w := newRetainWorld(t, ssqSpec{tip: 2, work: retainHeavy(2), authority: func(a *mdbx.StorageAuthorityV1) {
			a.NextGenerationID, a.Phase = 4, mdbx.StoragePhasePruneGCV1
			a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: 3}}}
		}})
		w.retainSide(0, 1_440, 1_440, 1_441, false)
		raw := w.child(w.side[1_440], 1_441, nil)
		prior := w.tracked()
		retainWant(t, "healthy RP with GENERATION span", w.prepareSide(raw, w.tipAt(2)), "", "", retainNA, newT, crossed, true)
		oldest := w.side[1]
		side := *prior.SelectedSide
		side.RowCount, side.LogicalBytes = 1_439, 1_440_000-uint64(len(w.rows[string(append([]byte{4}, oldest[:]...))].value))
		a := prior
		a.SelectedSide = &side
		a.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{
			{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: 3},
			{Kind: mdbx.CleanupSpanSideV1, GenerationID: 2, FirstHeight: 1, LastHeight: 1, NextHeight: 1},
		}}
		w.authorityMutation(a)
		w.absentRow(3, bytes.Clone(oldest[:]))
		w.wantImage("GENERATION span/progress preserved")
		w.wantIncomingAbsent("A5-generation", raw)
	})
	t.Run("R-p", func(t *testing.T) {
		w, raw := rollWorld(t)
		retainWantConsensus(t, "exact merkle result/no SIDE", w.prepareSide(retainMerkle(raw), w.tipAt(2)), consensus.BLOCK_ERR_MERKLE_INVALID)
		w.wantImage("full side unchanged after invalid merkle")
	})
	t.Run("R-m", func(t *testing.T) {
		// The oldest body is positively absent (owner NONE, B0): the complete clear SIDE(2,1,1440,1), not Prepared.
		w, raw := rollWorld(t)
		oldest := w.side[1]
		w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(oldest[:]))})
		retainWant(t, "complete side clear, not Prepared", w.prepareSide(raw, w.tipAt(2)), retainCleared, "", retainNA, newT, crossed, true)
		w.wantCleared("positive oldest damage clear", 1, 1_440)
		w.wantIncomingAbsent("R-m", raw)
	})
	t.Run("R-f", func(t *testing.T) {
		// Cleaned one-slot F0/C1441/count1439: Prepare refuses with no second SIDE or automatic RA.
		w := newRetainWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
		w.retainSide(0, 1_441, 1_439, 1_442, true)
		out := w.prepareSide(w.child(w.side[1_441], 1_442, nil), w.tipAt(2))
		retainWantRefusal(t, "no second SIDE/shrink", out, ssqBranch, "selected side rolling preparation needs an exact-tip child of a full side")
		w.wantImage("one-slot side unchanged")
	})
	t.Run("R-domain-node", func(t *testing.T) {
		// Prepare with no side, and with a winning canonical-parent child beside a non-full side, is typed branch_data.
		w := newRetainWorld(t, ssqSpec{tip: 10})
		out := w.prepareSide(w.child(w.canonical[5], 6, nil), w.tipAt(10))
		retainWantRefusal(t, "Prepare no side", out, ssqBranch, "selected side rolling preparation needs an exact-tip child of a full side")
		w.wantImage("Prepare no side unchanged")
		w = newRetainWorld(t, ssqSpec{tip: 20})
		w.retainSide(10, 15, 5, 16, false)
		out = w.prepareSide(w.child(w.canonical[17], 18, nil), w.tipAt(20))
		retainWantRefusal(t, "Prepare non-tip", out, ssqBranch, "selected side rolling preparation needs an exact-tip child of a full side")
		w.wantImage("Prepare non-tip unchanged")
		w = newRetainWorld(t, ssqSpec{tip: 20})
		w.retainSide(10, 15, 5, 16, false)
		out = w.prepareSide(w.child(w.side[15], 16, nil), w.tipAt(20))
		retainWantRefusal(t, "Prepare full<1440", out, ssqBranch, "selected side rolling preparation needs an exact-tip child of a full side")
		w.wantImage("Prepare full<1440 unchanged")
	})
	t.Run("A9-reopen", func(t *testing.T) {
		w, raw := rollWorld(t)
		prior := w.tracked()
		retainWant(t, "RP before reopen", w.prepareSide(raw, w.tipAt(2)), "", "", retainNA, newT, crossed, true)
		w.expectPrepared(prior)
		w.reopen()
		w.wantImage("byte-identical persisted Prepared image only")
		out := w.prepareSide(raw, w.tipAt(2))
		retainWant(t, "unclassified exact get EINVAL/not verified/no effect", out, "", "", "OLD", old, pre, false)
		retainWantEngine(t, "unverified owner after RP", out.Err, "get", mdbx.EngineInvalidInput, 22, "canonical owner index is not verified")
		w.wantImage("unverified owner refusal after RP")
	})
	t.Run("inputs", func(t *testing.T) {
		out := PrepareSelectedSideRollingMDBX(nil, nil, nil, nil)
		retainWant(t, "nil Store", out, "", "", "", old, pre, false)
		retainWantEngine(t, "nil Store", out.Err, "update", mdbx.EngineInvalidInput, 22, "nil Store")
	})
	// RP charges 2n+L <= 437205 with L the linking tip body read once: nFit=floor((437205-L)/2) prepares, nFit+1
	// refuses storage_capacity before any planner read, Batch or write.
	t.Run("H11-link-length", func(t *testing.T) {
		for _, fits := range []bool{false, true} {
			w := newRetainWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
			blocks := w.retainSide(0, 1_440, 1_440, 1_441, false)
			n := (437_205-len(blocks[1_440]))/2 + 1
			if fits {
				n--
			}
			raw := retainLarge(t, w.side[1_440], w.ts(w.side[1_440])+120, n)
			w.absent = append(w.absent, ssqHash(raw))
			if !fits {
				retainWant(t, "actual L resource bound/no second body read", w.prepareSide(raw, w.tipAt(2)), retainCapacity, "", "OLD", old, pre, true)
				w.wantImage("conservative planner Q>G refused before planner allocation/read/Batch")
				continue
			}
			prior := w.tracked()
			retainWant(t, "largest fitting RP candidate prepares", w.prepareSide(raw, w.tipAt(2)), "", "", retainNA, newT, crossed, true)
			w.expectPrepared(prior)
			w.wantImage("large RP Prepared image")
			w.wantIncomingAbsent("H11-link-length", raw)
		}
	})
	t.Run("H11-planner", func(t *testing.T) {
		// Independent literals: Proll 144720634 and slack G-(Proll+7223040+2*16384*64+2048+131072) = 437205 for 2n+L.
		if selectedRetainRoll != 144_720_634 {
			t.Fatalf("Proll %d", selectedRetainRoll)
		}
		for _, c := range []struct {
			n, l uint64
			fits bool
		}{{218_602, 1, true}, {218_602, 2, false}, {0, 437_205, true}, {0, 437_206, false}, {218_603, 0, false}} {
			if selectedRetainRollFits(c.n, c.l) != c.fits {
				t.Fatalf("conservative planner Q>G refused before planner allocation: n=%d L=%d", c.n, c.l)
			}
		}
	})
}
