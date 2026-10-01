//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// prepareSide invokes the separate RP entrypoint with retain's input and lane proofs.
func (w *ssqWorld) prepareSide(raw []byte, tip *mdbx.AuthorityPointV1) SelectedSideMutationOutcome {
	w.t.Helper()
	return w.operate(PrepareSelectedSideRollingMDBX, raw, tip)
}

// sideKey is an owned copy of the tracked side hash at j (a map value is not addressable).
func (w *ssqWorld) sideKey(j uint64) []byte {
	hash := w.side[j]
	return bytes.Clone(hash[:])
}

// rollWorld is canonical 0..2 (tip work 2^40) beside a mined full side 1..1440/F0, g2, tip work 1441, 1000 logical
// bytes per row; its exact-tip child at 1441 is selected and does not win K23.
func rollWorld(t *testing.T) (*ssqWorld, []byte) {
	t.Helper()
	w := newRetainWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
	w.retainSide(0, 1_440, 1_440, 1_441, false)
	return w, w.child(w.side[1_440], 1_441, nil)
}

// raWorld is canonical 0..2 (tip work 2^40) beside the cleaned one-slot side 3..1441/F0 (g2, C1441, count 1439,
// header-only history 1..2, tip work 1442); its exact-tip child at 1442 is selected and does not win K23.
func raWorld(t *testing.T) (*ssqWorld, []byte) {
	t.Helper()
	w := newRetainWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
	w.retainSide(0, 1_441, 1_439, 1_442, true)
	return w, w.child(w.side[1_441], 1_442, nil)
}

// rfWorld is canonical 0..tip (tip >= f) beside a cleaned one-slot side over canonical f: heights f+1..first-1 are
// header-only history, first..first+1438 carry header/body/SideLink(2,j) with work j+1 (each block works 1 under the
// all-FF target, canonical k works k+1), descriptor g2/F f/count 1439/actual body bytes. History below first-1 is mined
// gap seconds apart (gap 0: the expected median-plus-one child); the RF candidate at first-1 is cand(prev, ts) when
// given, else the expected child, so its context (target, MTP) is the one RF must re-derive. It returns the candidate.
func rfWorld(t *testing.T, tip, f, first, gap uint64, cand func(w *ssqWorld, prev [32]byte) []byte) (*ssqWorld, []byte) {
	t.Helper()
	w := newRetainWorld(t, ssqSpec{tip: tip})
	var rows []mdbx.Mutation
	var raw []byte
	var total uint64
	prev, last := w.canonical[f], first+1_438
	for j := f + 1; j <= last; j++ {
		var block []byte
		switch {
		case j == first-1 && cand != nil:
			block = cand(w, prev)
			w.headers[ssqHash(block)] = block[:consensus.BLOCK_HEADER_BYTES]
		case j < first && (gap == 0 || j == first-1):
			block = w.child(prev, j, nil)
		case j < first:
			block = w.mined(prev, gap)
		default:
			block = w.mined(prev, 113)
		}
		hash := ssqHash(block)
		w.side[j] = hash
		rows = append(rows, w.literal(3, bytes.Clone(hash[:]), block[:consensus.BLOCK_HEADER_BYTES], false))
		switch {
		case j == first-1:
			raw = block
		case j >= first:
			total += uint64(len(block))
			rows = append(rows, w.literal(4, bytes.Clone(hash[:]), block, false), w.literal(6, ssqMust(mdbx.HeightKey(2, j)), mdbx.ChainValue(hash, prev, ssqWork(j+1)), false))
		}
		prev = hash
	}
	a := w.authorityValue()
	a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 2, F: f, TipHeight: last, TipHash: prev, CumulativeChainwork: ssqWork(last + 1), RowCount: 1_439, LogicalBytes: total}
	w.apply(append(rows, w.authorityMutation(a)))
	return w, raw
}

// refill invokes the separate RF entrypoint with retain's input and lane proofs (no locator).
func (w *ssqWorld) refill(raw []byte) SelectedSideMutationOutcome {
	w.t.Helper()
	return w.operate(func(s *mdbx.Store, o *mdbx.OperationReservationOwner, raw []byte, _ *mdbx.AuthorityPointV1) SelectedSideMutationOutcome {
		return RefillSelectedSideMDBX(s, o, raw)
	}, raw, nil)
}

// expectRefilled records RF at first-1 over pre-state prior: count 1440, bytes+n, every other descriptor field, the
// incumbent tip and authority unchanged; the candidate header (already present history) stays, its body is inserted
// and SideLink(2,first-1) names parent with the literal restored work.
func (w *ssqWorld) expectRefilled(raw []byte, prior mdbx.StorageAuthorityV1, first uint64, parent [32]byte, work [40]byte) {
	w.t.Helper()
	hash := ssqHash(raw)
	side := *prior.SelectedSide
	side.RowCount, side.LogicalBytes = 1_440, side.LogicalBytes+uint64(len(raw))
	prior.SelectedSide = &side
	w.authorityMutation(prior)
	w.literal(4, bytes.Clone(hash[:]), bytes.Clone(raw), false)
	w.literal(6, ssqMust(mdbx.HeightKey(2, first-1)), mdbx.ChainValue(hash, parent, work), false)
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
		w.wantAbsent("unkept header1 deleted", 3, w.sideKey(1))
		w.wantIncomingAbsent("A5", raw)
		w.wantAbsent("no compact undo", 5, mdbx.UndoManifestKey(ssqHash(raw)))
		w.reopen()
		w.wantImage("A5 persisted image after reopen")
	})
	// A5-body and A5-link each own one oldest physical row: its exact pre-state bytes survive the preparation.
	for _, c := range []struct {
		name string
		rank uint8
		key  func(w *ssqWorld) []byte
	}{
		{"A5-body", 4, func(w *ssqWorld) []byte { return w.sideKey(1) }},
		{"A5-link", 6, func(w *ssqWorld) []byte { return ssqMust(mdbx.HeightKey(2, 1)) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, raw := rollWorld(t)
			want := bytes.Clone(w.rows[string(append([]byte{c.rank}, c.key(w)...))].value)
			prior := w.tracked()
			retainWant(t, c.name+" RP", w.prepareSide(raw, w.tipAt(2)), "", "", retainNA, newT, crossed, true)
			if equal, err := w.viewEqual(c.rank, c.key(w), want); want == nil || err != nil || !equal {
				t.Fatalf("oldest physical image unchanged: rank %d (%v)", c.rank, err)
			}
			w.expectPrepared(prior)
			w.wantImage(c.name + " complete Prepared image")
			w.wantIncomingAbsent(c.name, raw)
			w.reopen()
			w.wantImage(c.name + " persisted image after reopen")
		})
	}
	t.Run("R-e", func(t *testing.T) {
		// Prepared side (count 1439) with its pending SIDE(2,1,1,1) row owed from next_height: 1439+1+incoming 1 = 1441
		// exceeds the aggregate, so Retain's RA is typed branch_data and the preparation stays committed (M12).
		w, raw := rollWorld(t)
		prior := w.tracked()
		retainWant(t, "R-e preparation", w.prepareSide(raw, w.tipAt(2)), "", "", retainNA, newT, crossed, true)
		w.expectPrepared(prior)
		retainWantRefusal(t, "Prepared preserved/no body1441", w.retain(raw, w.tipAt(2)), ssqBranch, "selected side append exceeds the retention aggregate")
		w.wantImage("R-e Prepared preserved")
		w.wantIncomingAbsent("R-e", raw)
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
		w.reopen()
		w.wantImage("A5-generation persisted image after reopen")
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
	t.Run("R-planner-error", func(t *testing.T) {
		// The oldest required SideLink(2,1) is absent: the qualifier (tip link, linking body, context) does not read it,
		// the planner's required read fails, and Prepare keeps that recorded canonical integrity with OLD/Prewrite, no
		// write and the grant released (operate); the image is unchanged except that link stays absent.
		w, raw := rollWorld(t)
		link := ssqMust(mdbx.HeightKey(2, 1))
		w.apply([]mdbx.Mutation{w.absentRow(6, link)})
		retainWantIntegrity(t, "planner required link integrity", w.prepareSide(raw, w.tipAt(2)), "selected side link is absent")
		w.wantImage("planner error keeps OLD")
		w.wantAbsent("oldest link still absent", 6, link)
		w.wantIncomingAbsent("R-planner-error", raw)
	})
	// A6: cleaned one-slot side 3..1441/F0 (C1441, count 1439, history 1..2 header-only, 1000 logical bytes per row);
	// a fresh exact-tip child 1442 (work 1443, below canonical 2^40) is RA: count 1440, bytes+n, tip/hash/work advance,
	// first 3, g2, F0 and next 3 unchanged, exact header/body/link, no SIDE, no delete, no second preparation.
	t.Run("A6", func(t *testing.T) {
		w, raw := raWorld(t)
		prior := w.tracked()
		retainWant(t, "clean RA STORED_NONCANONICAL/not-applicable", w.retain(raw, w.tipAt(2)), retainStored, "", retainNA, newT, crossed, true)
		side := mdbx.SelectedSideV1{GenerationID: 2, F: 0, TipHeight: 1_442, TipHash: ssqHash(raw), CumulativeChainwork: ssqWork(1_443), RowCount: 1_440, LogicalBytes: 1_439_000 + uint64(len(raw))}
		w.expectN2(raw, prior, side, w.side[1_441])
		w.wantN1Image("RA exact append image", raw)
		if a := w.persisted(); a.Cleanup != nil || a.Phase != prior.Phase || a.NextGenerationID != prior.NextGenerationID {
			t.Fatalf("RA no SIDE/phase/next preserved: %+v", a)
		}
		w.reopen()
		w.wantN1Image("RA persisted image after reopen", raw)
		out := w.retain(raw, w.tipAt(2))
		retainWant(t, "unclassified exact get EINVAL/not verified/no effect", out, "", "", "OLD", old, pre, false)
		retainWantEngine(t, "unverified owner after RA", out.Err, "get", mdbx.EngineInvalidInput, 22, "canonical owner index is not verified")
		w.wantN1Image("unverified owner refusal after RA", raw)
	})
	// H11 RA resource instance: RA charges the same 3n+L <= 140965583 as N2, with L the cleaned tip 1441 body read once.
	// nFit=floor((140965583-L)/3) appends through Retain; nFit+1 is storage_capacity/OLD before any expected-row read.
	t.Run("H11-RA-L", func(t *testing.T) {
		for _, fits := range []bool{false, true} {
			w, _ := raWorld(t)
			l := len(w.rows[string(append([]byte{4}, w.sideKey(1_441)...))].value)
			if l <= 119 {
				t.Fatalf("cleaned tip body %d bytes does not exceed the header bound", l)
			}
			n := (140_965_583-l)/3 + 1
			if fits {
				n--
			}
			raw := retainLarge(t, w.side[1_441], w.ts(w.side[1_441])+120, n)
			if !fits {
				w.absent = append(w.absent, ssqHash(raw))
				retainWant(t, "RA linking length L charged/refusal", w.retain(raw, w.tipAt(2)), retainCapacity, "", "OLD", old, pre, true)
				w.wantImage("RA L refusal before any expected-row read")
				continue
			}
			prior := w.tracked()
			retainWant(t, "largest fitting RA candidate with L commits", w.retain(raw, w.tipAt(2)), retainStored, "", retainNA, newT, crossed, true)
			side := mdbx.SelectedSideV1{GenerationID: 2, F: 0, TipHeight: 1_442, TipHash: ssqHash(raw), CumulativeChainwork: ssqWork(1_443), RowCount: 1_440, LogicalBytes: 1_439_000 + uint64(n)}
			w.expectN2(raw, prior, side, w.side[1_441])
			w.wantN1Image("large RA image", raw)
		}
	})
	t.Run("R-s", func(t *testing.T) {
		// The cleaned tip 1441's optional linking body changed to invalid commitments before a fresh RA: the fresh
		// qualification's current linking check yields the damage locator, its recheck is the complete positive clear
		// SIDE(2,3,1441,3); no append ever reuses an earlier observation (M31).
		w, raw := raWorld(t)
		tip := w.side[1_441]
		bad := retainMerkle(w.rows[string(append([]byte{4}, tip[:]...))].value)
		// Update admits a rank-4 literal only with BeforePresent false: delete the healthy body, then insert the bad one,
		// as the retention linking-commitment setups do.
		w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(tip[:]))})
		w.apply([]mdbx.Mutation{w.literal(4, bytes.Clone(tip[:]), bad, false)})
		w.absent = append(w.absent, ssqHash(raw))
		retainWant(t, "current damaged linking row cannot authorize append/exact image", w.retain(raw, w.tipAt(2)), retainCleared, "", retainNA, newT, crossed, true)
		w.wantCleared("RA damaged linking body complete clear", 3, 1_441)
	})
	// RF accepted rows: the stored tuple, the literal restored image, the unchanged incumbent descriptor tip/hash/work.
	refilled := func(t *testing.T, w *ssqWorld, raw []byte, first uint64, parent [32]byte, work [40]byte, label string) {
		t.Helper()
		prior := w.tracked()
		retainWant(t, label+": clean RF STORED_NONCANONICAL/not-applicable", w.refill(raw), retainStored, "", retainNA, newT, crossed, true)
		got := w.persisted().SelectedSide
		if got == nil || got.TipHeight != prior.SelectedSide.TipHeight || got.TipHash != prior.SelectedSide.TipHash || got.CumulativeChainwork != prior.SelectedSide.CumulativeChainwork || got.RowCount != 1_440 {
			t.Fatalf("%s: valid refill unchanged incumbent: %+v", label, got)
		}
		w.expectRefilled(raw, prior, first, parent, work)
		w.wantN1Image(label+": restored link literal work/forward recurrence", raw)
	}
	t.Run("A7a", func(t *testing.T) {
		// Canonical-parent refill: side 2..1440/F0, candidate row 1 over canonical 0 (work 1); restored link work is
		// first-link work 3 minus first-header work 1 = 2 = canonical-0 work 1 plus the candidate's 1.
		w, raw := rfWorld(t, 2, 0, 2, 113, nil)
		refilled(t, w, raw, 2, w.canonical[0], ssqWork(2), "A7a")
		w.reopen()
		w.wantN1Image("A7a persisted image after reopen", raw)
		out := w.refill(raw)
		retainWant(t, "unclassified exact get EINVAL/not verified/no effect", out, "", "", "OLD", old, pre, false)
		retainWantEngine(t, "unverified owner after RF", out.Err, "get", mdbx.EngineInvalidInput, 22, "canonical owner index is not verified")
	})
	t.Run("A7b", func(t *testing.T) {
		// Later refill: side 3..1441/F0, candidate row 2 over the unowned planted history header of row 1 (neither
		// canonical nor the tip); its context is that header and the canonical anchor 0. Restored work 4-1 = 3.
		w, raw := rfWorld(t, 2, 0, 3, 113, nil)
		refilled(t, w, raw, 3, w.side[1], ssqWork(3), "A7b")
	})
	t.Run("A7c-mtp", func(t *testing.T) {
		// History 1..12 are median-plus-one children, so the candidate at 12 sits exactly one second above its
		// 11-header median; an omitted or shortened MTP window changes that result.
		w, raw := rfWorld(t, 2, 0, 13, 0, nil)
		times := w.timestamps(w.side[11], 11)
		slices.Sort(times)
		if binary.LittleEndian.Uint64(raw[68:76]) != times[5]+1 {
			t.Fatal("A7c-mtp fixture: candidate is not at its median boundary")
		}
		refilled(t, w, raw, 13, w.side[11], ssqWork(13), "exact timestamp boundary/result")
	})
	t.Run("A7c-retarget", func(t *testing.T) {
		// Canonical 0..9000 (120 s), history 9001..10079 mined 60 s apart: the candidate at retarget height 10080 is
		// mined under the window's retargeted target, which differs from the inherited all-FF target.
		w, raw := rfWorld(t, 9_000, 9_000, 10_081, 60, nil)
		if [32]byte(raw[76:108]) == consensus.POW_LIMIT {
			t.Fatal("A7c-retarget fixture: retarget did not move the target")
		}
		refilled(t, w, raw, 10_081, w.side[10_079], ssqWork(10_081), "exact target/steps1-12 result and refill image")
	})
	t.Run("R-g", func(t *testing.T) {
		w, _ := rfWorld(t, 2, 0, 3, 113, nil)
		other := w.mined(w.side[1], 200)
		w.absent = append(w.absent, ssqHash(other))
		retainWantRefusal(t, "branch_data/no refill", w.refill(other), ssqBranch, "refill candidate is not the first retained row's parent")
		w.wantImage("R-g unchanged")
	})
	t.Run("R-r", func(t *testing.T) {
		w, raw := rfWorld(t, 2, 0, 3, 113, nil)
		w.apply([]mdbx.Mutation{w.absentRow(3, w.sideKey(1))})
		retainWantRefusal(t, "missing context branch_data/no write", w.refill(raw), ssqBranch, "selected side refill parent history is unavailable")
		w.wantImage("R-r unchanged")
		w.wantAbsent("R-r no refill link", 6, ssqMust(mdbx.HeightKey(2, 2)))
	})
	t.Run("R-h-link", func(t *testing.T) {
		// A valid, identical SideLink(2,1) already present: branch_data, no overwrite or adoption.
		w, raw := rfWorld(t, 2, 0, 2, 113, nil)
		hash := ssqHash(raw)
		w.apply([]mdbx.Mutation{w.literal(6, ssqMust(mdbx.HeightKey(2, 1)), mdbx.ChainValue(hash, w.canonical[0], ssqWork(2)), false)})
		retainWantRefusal(t, "branch_data/no overwrite or adoption", w.refill(raw), ssqBranch, "selected side refill height already has a SideLink")
		w.wantImage("R-h-link unchanged")
		w.wantAbsent("R-h-link no candidate body", 4, bytes.Clone(hash[:]))
	})
	t.Run("R-h", func(t *testing.T) {
		// Prepared side with its exact pending SIDE: RF refuses on its domain; the SIDE and the oldest body stay.
		w, raw := rollWorld(t)
		prior := w.tracked()
		retainWant(t, "R-h preparation", w.prepareSide(raw, w.tipAt(2)), "", "", retainNA, newT, crossed, true)
		w.expectPrepared(prior)
		retainWantRefusal(t, "Prepared exact SIDE remains", w.refill(raw), ssqBranch, "selected side refill needs a cleaned one-slot side without a pending SIDE")
		w.wantImage("R-h Prepared preserved")
	})
	t.Run("R-domain-node-refill", func(t *testing.T) {
		w := newRetainWorld(t, ssqSpec{tip: 10})
		retainWantRefusal(t, "Refill absent side", w.refill(w.child(w.canonical[5], 6, nil)), ssqBranch, "selected side refill needs a cleaned one-slot side without a pending SIDE")
		w.wantImage("Refill absent side unchanged")
		w, raw := rollWorld(t)
		retainWantRefusal(t, "Refill full side", w.refill(raw), ssqBranch, "selected side refill needs a cleaned one-slot side without a pending SIDE")
		w.wantImage("Refill full side unchanged")
	})
	t.Run("R-s-RF", func(t *testing.T) {
		// The first retained row 3's optional body changed to invalid commitments before a fresh RF: its locator, then
		// the recheck's complete positive clear SIDE(2,3,1441,3); nothing is refilled.
		w, raw := rfWorld(t, 2, 0, 3, 113, nil)
		bad := retainMerkle(w.rows[string(append([]byte{4}, w.sideKey(3)...))].value)
		w.apply([]mdbx.Mutation{w.absentRow(4, w.sideKey(3))})
		w.apply([]mdbx.Mutation{w.literal(4, w.sideKey(3), bad, false)})
		w.absent = append(w.absent, ssqHash(raw))
		retainWant(t, "current damaged first row cannot authorize refill", w.refill(raw), retainCleared, "", retainNA, newT, crossed, true)
		w.wantCleared("RF damaged first row complete clear", 3, 1_441)
	})
	// H11 RF resource instance: 3n+L <= 140965583 with L the first retained row's body (read once).
	t.Run("H11-RF-L", func(t *testing.T) {
		probe, _ := rfWorld(t, 2, 0, 3, 113, nil)
		l := len(probe.rows[string(append([]byte{4}, probe.sideKey(3)...))].value)
		for _, fits := range []bool{false, true} {
			n := (140_965_583-l)/3 + 1
			if fits {
				n--
			}
			w, raw := rfWorld(t, 2, 0, 3, 113, func(w *ssqWorld, prev [32]byte) []byte { return retainLarge(t, prev, w.ts(prev)+120, n) })
			if got := len(w.rows[string(append([]byte{4}, w.sideKey(3)...))].value); got != l {
				t.Fatalf("H11-RF-L fixture: first body %d bytes, probe %d", got, l)
			}
			if !fits {
				retainWant(t, "RF L charged/refusal", w.refill(raw), retainCapacity, "", "OLD", old, pre, true)
				w.wantImage("RF L refusal")
				w.wantAbsent("RF L refusal no candidate body", 4, w.sideKey(2))
				continue
			}
			refilled(t, w, raw, 3, w.side[1], ssqWork(3), "largest fitting RF candidate")
		}
	})
	t.Run("R-f", func(t *testing.T) {
		// Cleaned one-slot F0/C1441/count1439: Prepare refuses with no second SIDE or automatic RA.
		w := newRetainWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
		w.retainSide(0, 1_441, 1_439, 1_442, true)
		out := w.prepareSide(w.child(w.side[1_441], 1_442, nil), w.tipAt(2))
		retainWantRefusal(t, "no second SIDE/shrink", out, ssqBranch, "selected side rolling preparation needs an exact-tip child of a full side")
		w.wantImage("one-slot side unchanged")
		// A separate fresh Retain of the same child chooses RA (count 1440, no SIDE).
		retainWant(t, "separate fresh Retain chooses RA", w.retain(w.child(w.side[1_441], 1_442, nil), w.tipAt(2)), retainStored, "", retainNA, newT, crossed, true)
		if a := w.persisted(); a.SelectedSide == nil || a.SelectedSide.RowCount != 1_440 || a.Cleanup != nil {
			t.Fatalf("R-f separate RA: %+v", a.SelectedSide)
		}
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
		w = newRetainWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
		w.retainSide(0, 1_441, 1_439, 1_442, true)
		out = w.prepareSide(w.child(w.side[1_441], 1_442, nil), w.tipAt(2))
		retainWantRefusal(t, "Prepare one-slot", out, ssqBranch, "selected side rolling preparation needs an exact-tip child of a full side")
		w.wantImage("Prepare one-slot unchanged")
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
			w.reopen()
			w.wantImage("large RP persisted image after reopen")
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
