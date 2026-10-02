//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
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

// rollWorld is canonical 0..2 (tip work 2^40) beside a mined full side 1..1440/F0, g2, tip work 1441, logical bytes
// the actual retained body sum; its exact-tip child at 1441 is selected and does not win K23.
func rollWorld(t *testing.T) (*ssqWorld, []byte) {
	t.Helper()
	w := newRetainWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
	w.exactSide(w.retainSide(0, 1_440, 1_440, 1_441, false), 1, 1_440)
	return w, w.child(w.side[1_440], 1_441, nil)
}

// exactSide replaces retainSide's synthetic rows*1000 descriptor bytes with the independent sum of the retained
// BlockBytes lengths first..tip and requires the committed descriptor to carry exactly that sum.
func (w *ssqWorld) exactSide(blocks map[uint64][]byte, first, tip uint64) {
	w.t.Helper()
	var sum uint64
	for j := first; j <= tip; j++ {
		sum += uint64(len(blocks[j]))
	}
	w.setSide(func(s *mdbx.SelectedSideV1) { s.LogicalBytes = sum })
	if got := w.persisted().SelectedSide; got == nil || got.LogicalBytes != sum || sum == uint64(got.RowCount)*1_000 {
		w.t.Fatalf("admitted selected sum %d: %+v", sum, got)
	}
}

// raWorld is canonical 0..2 (tip work 2^40) beside the cleaned one-slot side 3..1441/F0 (g2, C1441, count 1439,
// header-only history 1..2, tip work 1442, actual retained body sum); its exact-tip child at 1442 is selected and does
// not win K23.
func raWorld(t *testing.T) (*ssqWorld, []byte) {
	t.Helper()
	w := newRetainWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
	w.exactSide(w.retainSide(0, 1_441, 1_439, 1_442, true), 3, 1_441)
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
	// Restored work W(first-1) is the literal first; each retained row j adds its own block work floor(2^256/target)
	// under the target inherited from its parent header (1 under the all-FF target, so W(j) = j+1 there).
	cumulative := new(big.Int).SetUint64(first)
	for j := f + 1; j <= last; j++ {
		var block []byte
		switch {
		case j == first-1 && cand != nil:
			block = cand(w, prev)
		case j < first && (gap == 0 || j == first-1):
			block = w.child(prev, j, nil)
		case j < first:
			block = w.mined(prev, gap)
		default:
			inherited := [32]byte(w.headers[prev][76:108])
			block = ssqMine(t, prev, w.ts(prev)+113, inherited, nil)
			cumulative.Add(cumulative, rfBlockWork(inherited))
		}
		// Every produced block's real header is tracked here, before the next iteration reads its target, timestamp
		// or child context (child()/childAt() and ssqMine do not track it; mined() already did, identically).
		hash := ssqHash(block)
		w.headers[hash] = block[:consensus.BLOCK_HEADER_BYTES]
		w.side[j] = hash
		// An already committed identical header (a canonical candidate) is reused, never reinserted (NOOVERWRITE).
		if _, tracked := w.rows[string(append([]byte{3}, hash[:]...))]; !tracked {
			rows = append(rows, w.literal(3, bytes.Clone(hash[:]), block[:consensus.BLOCK_HEADER_BYTES], false))
		}
		switch {
		case j == first-1:
			raw = block
		case j >= first:
			total += uint64(len(block))
			rows = append(rows, w.literal(4, bytes.Clone(hash[:]), block, false), w.literal(6, ssqMust(mdbx.HeightKey(2, j)), mdbx.ChainValue(hash, prev, rfWork(cumulative)), false))
		}
		prev = hash
	}
	// History rows f+1..first-1 (the candidate included) are header-present/body-absent: child()/childAt() listed their
	// hashes in the combined header+body absence domain, so they leave it and the body absence becomes a tracked row.
	for j := f + 1; j < first; j++ {
		hash := w.side[j]
		w.absent = slices.DeleteFunc(w.absent, func(h [32]byte) bool { return h == hash })
		if _, tracked := w.rows[string(append([]byte{4}, hash[:]...))]; !tracked {
			w.rows[string(append([]byte{4}, hash[:]...))] = ssqRow{rank: 4, key: bytes.Clone(hash[:])}
		}
	}
	a := w.authorityValue()
	a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 2, F: f, TipHeight: last, TipHash: prev, CumulativeChainwork: rfWork(cumulative), RowCount: 1_439, LogicalBytes: total}
	w.apply(append(rows, w.authorityMutation(a)))
	return w, raw
}

// rfBlockWork is the spec block work floor(2^256/target), computed here independently of the production owner.
func rfBlockWork(target [32]byte) *big.Int {
	return new(big.Int).Div(new(big.Int).Lsh(big.NewInt(1), 256), new(big.Int).SetBytes(target[:]))
}

// rfWork is a 40-byte big-endian work literal.
func rfWork(v *big.Int) (work [40]byte) {
	v.FillBytes(work[:])
	return work
}

// rfTimes reads the newest-first timestamps of count tracked headers ending at hash straight from their header
// bytes (offset 68), independently of the child()/timestamps fixture path.
func (w *ssqWorld) rfTimes(hash [32]byte, count int) []uint64 {
	times := make([]uint64, 0, count)
	for len(times) < count {
		header := w.headers[hash]
		times = append(times, binary.LittleEndian.Uint64(header[68:76]))
		hash = [32]byte(header[4:36])
	}
	return times
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

// expectPrepared records RP over the full pre-state: count 1439, the pre-state actual sum minus the literal oldest
// body length, tip/hash/work/g/F/next unchanged, PRUNE_GC/STABLE with SIDE(2,1,1,1); the unkept oldest header is deleted.
func (w *ssqWorld) expectPrepared(prior mdbx.StorageAuthorityV1) {
	w.t.Helper()
	oldest := w.side[1]
	body := w.rows[string(append([]byte{4}, oldest[:]...))].value
	side := *prior.SelectedSide
	side.RowCount, side.LogicalBytes = 1_439, prior.SelectedSide.LogicalBytes-uint64(len(body))
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
		w.exactSide(w.retainSide(0, 1_440, 1_440, 1_441, false), 1, 1_440)
		raw := w.child(w.side[1_440], 1_441, nil)
		prior := w.tracked()
		retainWant(t, "healthy RP with GENERATION span", w.prepareSide(raw, w.tipAt(2)), "", "", retainNA, newT, crossed, true)
		oldest := w.side[1]
		side := *prior.SelectedSide
		side.RowCount, side.LogicalBytes = 1_439, prior.SelectedSide.LogicalBytes-uint64(len(w.rows[string(append([]byte{4}, oldest[:]...))].value))
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
	// Remaining-selected keep (RUBIN_MEMPOOL_POLICY 6.4.1.3): keep700 rewrites the valid SideLink(2,700), outside the
	// exact-tip child's recent qualification context, to name the oldest hash with its own legal parent and work.
	keep700 := func(w *ssqWorld) {
		w.apply([]mdbx.Mutation{w.literal(6, ssqMust(mdbx.HeightKey(2, 700)), mdbx.ChainValue(w.side[1], w.side[699], ssqWork(701)), true)})
	}
	t.Run("A5-remaining-keep", func(t *testing.T) {
		// The unowned oldest header is kept by the remaining hash at 700; count, bytes, SIDE, bodies and links as A5.
		w, raw := rollWorld(t)
		keep700(w)
		prior := w.tracked()
		header := w.headers[w.side[1]]
		retainWant(t, "remaining keep Prepared", w.prepareSide(raw, w.tipAt(2)), "", "", retainNA, newT, crossed, true)
		w.expectPrepared(prior)
		w.literal(3, w.sideKey(1), header, false)
		w.wantImage("remaining hash keeps the oldest header")
		w.wantIncomingAbsent("A5-remaining-keep", raw)
		w.reopen()
		w.wantImage("remaining keep persisted image after reopen")
	})
	// An absent remaining SideLink is the unknown identity, canonical integrity/OLD with no write: alone at 700, and at
	// 701 after the match at 700 (the traversal completes after a match).
	for _, c := range []struct {
		name   string
		keep   bool
		height uint64
	}{{"A5-remaining-absent", false, 700}, {"A5-remaining-keep-later-absent", true, 701}} {
		t.Run(c.name, func(t *testing.T) {
			w, raw := rollWorld(t)
			if c.keep {
				keep700(w)
			}
			link := ssqMust(mdbx.HeightKey(2, c.height))
			w.apply([]mdbx.Mutation{w.absentRow(6, link)})
			retainWantIntegrity(t, c.name, w.prepareSide(raw, w.tipAt(2)), "selected side link is absent")
			w.wantImage(c.name + " keeps OLD")
			w.wantAbsent(c.name+": link still absent", 6, link)
			w.wantIncomingAbsent(c.name, raw)
		})
	}
	t.Run("A5-canonical-keep", func(t *testing.T) {
		// The oldest row is canonical 1 (owner height 1, its header, body, parent genesis and canonical work 2) under F0,
		// side 2..1440 mined over it: CanonicalOwnerV1 keeps the header, so the absent SideLink(2,700) is never read.
		w := newRetainWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
		blocks := w.retainSide(1, 1_440, 1_439, 1_441, false)
		w.side[1] = w.canonical[1]
		blocks[1] = w.rows[string(append([]byte{4}, w.sideKey(1)...))].value
		link := ssqMust(mdbx.HeightKey(2, 700))
		w.apply([]mdbx.Mutation{w.literal(6, ssqMust(mdbx.HeightKey(2, 1)), mdbx.ChainValue(w.side[1], w.canonical[0], ssqWork(2)), false), w.absentRow(6, link)})
		w.setSide(func(s *mdbx.SelectedSideV1) { s.F, s.RowCount = 0, 1_440 })
		w.exactSide(blocks, 1, 1_440)
		raw := w.child(w.side[1_440], 1_441, nil)
		prior := w.tracked()
		retainWant(t, "canonical keep Prepared", w.prepareSide(raw, w.tipAt(2)), "", "", retainNA, newT, crossed, true)
		w.expectPrepared(prior)
		w.literal(3, w.sideKey(1), w.headers[w.side[1]], false)
		w.wantImage("canonical keep: owned header kept, no remaining scan")
		w.wantAbsent("link700 still absent", 6, link)
		w.wantIncomingAbsent("A5-canonical-keep", raw)
		w.reopen()
		w.wantImage("canonical keep persisted image after reopen")
	})
	// A6: cleaned one-slot side 3..1441/F0 (C1441, count 1439, history 1..2 header-only, actual retained body sum);
	// a fresh exact-tip child 1442 (work 1443, below canonical 2^40) is RA: count 1440, bytes+n, tip/hash/work advance,
	// first 3, g2, F0 and next 3 unchanged, exact header/body/link, no SIDE, no delete, no second preparation.
	t.Run("A6", func(t *testing.T) {
		w, raw := raWorld(t)
		prior := w.tracked()
		retainWant(t, "clean RA STORED_NONCANONICAL/not-applicable", w.retain(raw, w.tipAt(2)), retainStored, "", retainNA, newT, crossed, true)
		side := mdbx.SelectedSideV1{GenerationID: 2, F: 0, TipHeight: 1_442, TipHash: ssqHash(raw), CumulativeChainwork: ssqWork(1_443), RowCount: 1_440, LogicalBytes: prior.SelectedSide.LogicalBytes + uint64(len(raw))}
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
			side := mdbx.SelectedSideV1{GenerationID: 2, F: 0, TipHeight: 1_442, TipHash: ssqHash(raw), CumulativeChainwork: ssqWork(1_443), RowCount: 1_440, LogicalBytes: prior.SelectedSide.LogicalBytes + uint64(n)}
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
		// A9: reopen proves the byte-identical persisted image only. A second RF would stop at its full-side domain
		// before any owner read, so the next operation is Retain of the same raw under the literal canonical tip: its
		// parent evidence reads the keyed CanonicalOwner first, the direct get EINVAL on the unverified handle, with
		// empty fields, no effect and a released grant (operate).
		w.reopen()
		w.wantN1Image(label+": persisted image after reopen", raw)
		out := w.retain(raw, w.tipAt(uint64(len(w.canonical)-1)))
		retainWant(t, label+": unclassified exact get EINVAL/not verified/no effect", out, "", "", "OLD", old, pre, false)
		retainWantEngine(t, label+": unverified owner after RF", out.Err, "get", mdbx.EngineInvalidInput, 22, "canonical owner index is not verified")
		w.wantN1Image(label+": unverified owner refusal leaves the image", raw)
	}
	t.Run("A7a", func(t *testing.T) {
		// Canonical-parent refill: side 2..1440/F0, candidate row 1 over canonical 0 (work 1); restored link work is
		// first-link work 3 minus first-header work 1 = 2 = canonical-0 work 1 plus the candidate's 1.
		w, raw := rfWorld(t, 2, 0, 2, 113, nil)
		refilled(t, w, raw, 2, w.canonical[0], ssqWork(2), "A7a")
	})
	t.Run("A7b", func(t *testing.T) {
		// Later refill: side 3..1441/F0, candidate row 2 over the unowned planted history header of row 1 (neither
		// canonical nor the tip); its context is that header and the canonical anchor 0. Restored work 4-1 = 3.
		w, raw := rfWorld(t, 2, 0, 3, 113, nil)
		refilled(t, w, raw, 3, w.side[1], ssqWork(3), "A7b")
	})
	// RF owner corrections on the A7b shape (X1 = unowned sibling of canonical 1 over canonical 0, candidate B2, first
	// B3 naming B2, SideLink(2,2) absent). Each refusal is typed branch_data/OLD/Prewrite, empty Decision, no write,
	// image unchanged and the grant released (operate); the accepted A7b is the control pair.
	rfRefused := func(t *testing.T, w *ssqWorld, raw []byte, cause, label string) {
		t.Helper()
		retainWantRefusal(t, label, w.refill(raw), ssqBranch, cause)
		w.wantImage(label + ": image unchanged")
		w.wantAbsent(label+": no refill link", 6, ssqMust(mdbx.HeightKey(2, 2)))
	}
	t.Run("RF-anchor-F", func(t *testing.T) {
		// Same physical history with the descriptor F moved 0 -> 1 (legal one-slot: C 1440, count 1439): the candidate's
		// parent X1 sits at F but is unowned, so it is not the canonical anchor; refused before context and steps.
		w, raw := rfWorld(t, 2, 0, 3, 113, nil)
		w.setSide(func(s *mdbx.SelectedSideV1) { s.F = 1 })
		rfRefused(t, w, raw, "selected side anchor is not the canonical block at F", "unowned parent at F is not the anchor")
	})
	for _, c := range []struct {
		name  string
		first uint64
	}{{"RF-implied-parent-zero", 2}, {"RF-first-work-zero", 1}} {
		t.Run(c.name, func(t *testing.T) {
			// First link work literal 2: the restored candidate work 2-1 = 1 passes the first subtraction, context and
			// steps 1-12 pass, and the unowned parent's implied work 1-1 = 0 is refused. Literal 1 is refused earlier
			// by the first subtraction (restored work 0).
			w, raw := rfWorld(t, 2, 0, 3, 113, nil)
			w.apply([]mdbx.Mutation{w.literal(6, ssqMust(mdbx.HeightKey(2, 3)), mdbx.ChainValue(w.side[3], w.side[2], ssqWork(c.first)), true)})
			rfRefused(t, w, raw, "selected side refill work underflows", c.name)
		})
	}
	t.Run("RF-candidate-canonical", func(t *testing.T) {
		// The candidate is the complete canonical block 1 over canonical 0 (its header and body already committed and
		// reused, not reinserted); the cleaned side 2..1440/F0 starts with a row naming it. Qualification restores work
		// 2 and passes; the same-Reader candidate owner is Owned, so RF is the clean canonical no-op with no mutation:
		// canonical header/body/index/undo, the descriptor, every link and the absent SideLink(2,1) stay.
		w, raw := rfWorld(t, 2, 0, 2, 113, func(w *ssqWorld, prev [32]byte) []byte {
			hash := w.canonical[1]
			return w.rows[string(append([]byte{4}, hash[:]...))].value
		})
		if ssqHash(raw) != w.canonical[1] || [32]byte(w.headers[w.side[2]][4:36]) != w.canonical[1] {
			t.Fatal("RF-candidate-canonical fixture: candidate is not the canonical block 1 named by the first row")
		}
		retainWant(t, "candidate Owned clean KNOWN_BLOCK_NOOP(CANONICAL)", w.refill(raw), retainKnown, "", retainNA, old, pre, true)
		w.wantImage("canonical-known refill leaves every row")
		w.wantAbsent("canonical-known no refill link", 6, ssqMust(mdbx.HeightKey(2, 1)))
	})
	// rfZeroFirst replaces the A7b first retained row 3 by a coherent hash-bound block over the candidate whose stored
	// target is zero (ssqBlock, no PoW is possible under it) with valid body commitments; SideLink(2,3) keeps the legal
	// positive work 4 and names linkPrev; owned pairs it with a canonical forward/owner at free height 12 (B 0, so its
	// header and body are required). Old header/body are deleted before the new ones are inserted (NOOVERWRITE).
	// The whole retained path 3..1441 is rebuilt in place so every non-target relation holds: row 3 keeps its own
	// timestamp with a zero target over the candidate; rows 4..1441 keep their own timestamps and all-FF targets and are
	// re-mined over the new parent; every SideLink keeps its literal work and names the new parent (row 3's names
	// linkPrev). Each height deletes the old header/body and inserts the new ones (NOOVERWRITE) in one apply group; the
	// descriptor takes the new tip hash and the new body total; g, F, count and tip height stay.
	rfZeroFirst := func(t *testing.T, w *ssqWorld, linkPrev [32]byte, owned bool) {
		t.Helper()
		cand, prev := w.side[2], w.side[2]
		var groups [][]mdbx.Mutation
		var total uint64
		for j := uint64(3); j <= 1_441; j++ {
			oldHash := w.side[j]
			oldHeader, key := w.headers[oldHash], ssqMust(mdbx.HeightKey(2, j))
			oldWork := [40]byte(w.rows[string(append([]byte{6}, key...))].value[64:104])
			timestamp := binary.LittleEndian.Uint64(oldHeader[68:76])
			block, parent := ssqMine(t, prev, timestamp, [32]byte(oldHeader[76:108]), nil), prev
			if j == 3 {
				block, parent = ssqBlock(t, prev, timestamp, [32]byte{}, 0, true), linkPrev
			}
			hash := ssqHash(block)
			groups = append(groups, []mdbx.Mutation{
				w.absentRow(3, bytes.Clone(oldHash[:])), w.absentRow(4, bytes.Clone(oldHash[:])),
				w.literal(3, bytes.Clone(hash[:]), block[:consensus.BLOCK_HEADER_BYTES], false), w.literal(4, bytes.Clone(hash[:]), block, false),
				w.literal(6, key, mdbx.ChainValue(hash, parent, oldWork), true),
			})
			w.headers[hash], w.side[j] = block[:consensus.BLOCK_HEADER_BYTES], hash
			total += uint64(len(block))
			prev = hash
		}
		if owned {
			first := w.side[3]
			groups = append(groups, []mdbx.Mutation{
				w.literal(2, ssqMust(mdbx.HeightKey(1, 12)), mdbx.ChainValue(first, cand, ssqWork(13)), false),
				w.literal(7, ssqMust(mdbx.CanonicalOwnerKey(1, first)), mdbx.CanonicalOwnerValue(12), false),
			})
		}
		w.apply(groups...)
		w.setSide(func(s *mdbx.SelectedSideV1) { s.TipHash, s.LogicalBytes = prev, total })
	}
	t.Run("R-s-target-optional", func(t *testing.T) {
		// NONE first row with a zero stored target: RF's work step is that row's locator (never the supplied
		// candidate's CONSENSUS_INVALID); the released-grant recheck sees positive optional damage at the first one-slot
		// row and completes the selected clear SIDE(2,3,1441,3): no refill, bodies/links kept, headers 3..1441 deleted.
		w, raw := rfWorld(t, 2, 0, 3, 113, nil)
		rfZeroFirst(t, w, w.side[2], false)
		retainWant(t, "stored target optional clear/no supplied validity", w.refill(raw), retainCleared, "", retainNA, newT, crossed, true)
		w.wantCleared("stored target optional clear image", 3, 1_441)
		w.reopen()
		w.wantImage("stored target optional clear persisted after reopen")
		out := w.retain(raw, w.tipAt(2))
		retainWantEngine(t, "next owner use after reopen", out.Err, "get", mdbx.EngineInvalidInput, 22, "canonical owner index is not verified")
	})
	t.Run("R-s-target-required", func(t *testing.T) {
		// The same zero-target first row is canonically Owned (paired forward/owner) and its SideLink also names another
		// parent: RF's link-parent check yields the locator, and the recheck's required target check wins over the
		// optional link-parent diagnosis: canonical integrity with the literal cause, no clear, image unchanged.
		w, raw := rfWorld(t, 2, 0, 3, 113, nil)
		rfZeroFirst(t, w, [32]byte{0x77}, true)
		out := w.refill(raw)
		retainWant(t, "stored target canonical integrity/no clear", out, ssqIntegrity, "", "OLD", old, pre, false)
		if cause := errors.Unwrap(out.Err); cause == nil || cause.Error() != "required canonical header target is outside its domain" {
			t.Fatalf("stored target canonical integrity/no clear: cause %v", out.Err)
		}
		w.wantImage("stored target required image unchanged")
	})
	// rfOwnFirst pairs the healthy A7b first row 3 with a canonical forward/owner at free height 12 (B 0: required).
	rfOwnFirst := func(w *ssqWorld) {
		hash := w.side[3]
		w.apply([]mdbx.Mutation{
			w.literal(2, ssqMust(mdbx.HeightKey(1, 12)), mdbx.ChainValue(hash, w.side[2], ssqWork(13)), false),
			w.literal(7, ssqMust(mdbx.CanonicalOwnerKey(1, hash)), mdbx.CanonicalOwnerValue(12), false),
		})
	}
	t.Run("RF-cleaned-full", func(t *testing.T) {
		// The actual completed full state: a successful A7b RF yields 2..1441, count 1440 (first 2 > F+1, no SIDE). A
		// second RF of the same raw refuses on the domain's count clause before any artifact read; without that clause it
		// would reach the now-present SideLink(2,2) refusal instead. The refilled image is preserved.
		w, raw := rfWorld(t, 2, 0, 3, 113, nil)
		prior := w.tracked()
		retainWant(t, "full-state RF", w.refill(raw), retainStored, "", retainNA, newT, crossed, true)
		w.expectRefilled(raw, prior, 3, w.side[1], ssqWork(3))
		w.wantN1Image("full-state refilled image", raw)
		retainWantRefusal(t, "cleaned full domain refusal", w.refill(raw), ssqBranch, "selected side refill needs a cleaned one-slot side without a pending SIDE")
		w.wantN1Image("cleaned full refusal keeps the refilled image", raw)
	})
	t.Run("RF-parent-other-height", func(t *testing.T) {
		// The candidate at 2 names canonical block 2 (Owned at height 2, not first-2 = 1) and the first row names it.
		w, raw := rfWorld(t, 2, 0, 3, 113, func(w *ssqWorld, _ [32]byte) []byte {
			parent := w.canonical[2]
			return w.childAt(parent, w.ts(parent)+120, consensus.POW_LIMIT, nil)
		})
		rfRefused(t, w, raw, "refill parent is canonical at another height", "parent Owned at another height")
	})
	t.Run("RF-first-body-required", func(t *testing.T) {
		// First row Owned at k 12 >= B 0 with commitment-invalid body: required canonical body integrity, no locator.
		w, raw := rfWorld(t, 2, 0, 3, 113, nil)
		rfOwnFirst(w)
		bad := retainMerkle(w.rows[string(append([]byte{4}, w.sideKey(3)...))].value)
		w.apply([]mdbx.Mutation{w.absentRow(4, w.sideKey(3))})
		w.apply([]mdbx.Mutation{w.literal(4, w.sideKey(3), bad, false)})
		retainWantRefusal(t, "required first body integrity", w.refill(raw), ssqIntegrity, "required canonical body does not match its header or commitments")
		w.wantImage("required first body defect image unchanged")
	})
	t.Run("RF-first-header-required", func(t *testing.T) {
		// First row Owned with its required header deleted: keyed owner/header owner integrity before any later step.
		w, raw := rfWorld(t, 2, 0, 3, 113, nil)
		rfOwnFirst(w)
		w.apply([]mdbx.Mutation{w.absentRow(3, w.sideKey(3))})
		retainWantRefusal(t, "required first header integrity", w.refill(raw), ssqIntegrity, "required canonical row is absent")
		w.wantImage("required first header defect image unchanged")
	})
	t.Run("RF-first-link-parent", func(t *testing.T) {
		// Healthy first header/body, SideLink(2,3) naming another parent: RF's locator, recheck positive clear.
		w, raw := rfWorld(t, 2, 0, 3, 113, nil)
		w.apply([]mdbx.Mutation{w.literal(6, ssqMust(mdbx.HeightKey(2, 3)), mdbx.ChainValue(w.side[3], [32]byte{0x77}, ssqWork(4)), true)})
		retainWant(t, "first link parent mismatch locator/clear", w.refill(raw), retainCleared, "", retainNA, newT, crossed, true)
		w.wantCleared("first link parent mismatch clear", 3, 1_441)
	})
	t.Run("RF-first-link-missing", func(t *testing.T) {
		w, raw := rfWorld(t, 2, 0, 3, 113, nil)
		w.apply([]mdbx.Mutation{w.absentRow(6, ssqMust(mdbx.HeightKey(2, 3)))})
		retainWantIntegrity(t, "missing required first SideLink", w.refill(raw), "selected side link is absent")
		w.wantImage("missing first link image unchanged")
	})
	t.Run("RF-owned-recurrence", func(t *testing.T) {
		// A7a shape with SideLink(2,2) work 4: restored work 3 passes the first subtraction, but canonical parent 0's
		// work 1 plus the candidate's 1 is 2, so the Owned recurrence refuses.
		w, raw := rfWorld(t, 2, 0, 2, 113, nil)
		w.apply([]mdbx.Mutation{w.literal(6, ssqMust(mdbx.HeightKey(2, 2)), mdbx.ChainValue(w.side[2], ssqHash(raw), ssqWork(4)), true)})
		retainWantRefusal(t, "owned parent work recurrence", w.refill(raw), ssqBranch, "refill work does not extend its canonical parent")
		w.wantImage("owned recurrence image unchanged")
		w.wantAbsent("owned recurrence no refill link", 6, ssqMust(mdbx.HeightKey(2, 1)))
	})
	t.Run("RF-control-and-parse", func(t *testing.T) {
		// Non-STABLE authority refuses before any RF read; a truncated candidate header is BLOCK_ERR_PARSE.
		w := newRetainWorld(t, ssqSpec{tip: 10, authority: ssqPendingNone})
		retainWantRefusal(t, "RF control precedes everything", w.refill(w.child(w.canonical[5], 6, nil)), ssqRequired, "")
		w.wantImage("RF control refusal unchanged")
		w, raw := rfWorld(t, 2, 0, 3, 113, nil)
		retainWantConsensus(t, "RF truncated candidate header", w.refill(raw[:10]), consensus.BLOCK_ERR_PARSE)
		w.wantImage("RF parse refusal unchanged")
	})
	// A7c-mtp: history 1..11 are expected children; the candidate at 12 is built at an explicit timestamp against the
	// median of its 11 ancestors read straight from their header bytes (rfTimes, not the child() path). median+1 is
	// accepted; the exact median is BLOCK_ERR_TIMESTAMP_OLD at steps 1-12 with OLD and no effect, although the first
	// retained header names that exact candidate. Skipping or shortening the MTP comparison flips the refusal.
	mtpCandidate := func(offset uint64) func(w *ssqWorld, prev [32]byte) []byte {
		return func(w *ssqWorld, prev [32]byte) []byte {
			times := w.rfTimes(prev, 11)
			slices.Sort(times)
			return w.childAt(prev, times[5]+offset, consensus.POW_LIMIT, nil)
		}
	}
	t.Run("A7c-mtp", func(t *testing.T) {
		w, raw := rfWorld(t, 2, 0, 13, 0, mtpCandidate(1))
		refilled(t, w, raw, 13, w.side[11], ssqWork(13), "exact timestamp boundary/result")
	})
	t.Run("A7c-mtp-median", func(t *testing.T) {
		w, raw := rfWorld(t, 2, 0, 13, 0, mtpCandidate(0))
		if [32]byte(w.headers[w.side[13]][4:36]) != ssqHash(raw) {
			t.Fatal("A7c-mtp-median fixture: first retained header does not name the candidate")
		}
		retainWantConsensus(t, "exact median timestamp refused", w.refill(raw), consensus.BLOCK_ERR_TIMESTAMP_OLD)
		w.wantImage("A7c-mtp-median unchanged")
		w.wantAbsent("A7c-mtp-median no refill link", 6, ssqMust(mdbx.HeightKey(2, 12)))
	})
	// A7c-retarget: canonical 0..9000 at 120 s and history 9001..10079 at 60 s give the 10080-header window (heights
	// 0..10079, monotone steps inside [1,1200], so no clamp) T_actual = 9000*120+1079*60 = 1144740 against
	// T_expected = 120*10080 = 1209600; the expected target is floor(POW_LIMIT*1144740/1209600), above POW_LIMIT/4,
	// computed here without RetargetV1Clamped. Retained rows inherit it. The wrong all-FF target at 10080 reaches
	// steps 1-12 as BLOCK_ERR_TARGET_INVALID with the first retained header naming that candidate.
	retargeted := func() [32]byte {
		limit := new(big.Int).SetBytes(consensus.POW_LIMIT[:])
		v := new(big.Int).Div(new(big.Int).Mul(limit, big.NewInt(1_144_740)), big.NewInt(1_209_600))
		var target [32]byte
		v.FillBytes(target[:])
		return target
	}
	retargetCandidate := func(target [32]byte) func(w *ssqWorld, prev [32]byte) []byte {
		return func(w *ssqWorld, prev [32]byte) []byte { return w.childAt(prev, w.ts(prev)+60, target, nil) }
	}
	t.Run("A7c-retarget", func(t *testing.T) {
		w, raw := rfWorld(t, 9_000, 9_000, 10_081, 60, retargetCandidate(retargeted()))
		if [32]byte(w.headers[w.side[10_081]][76:108]) != retargeted() {
			t.Fatal("A7c-retarget fixture: retained rows do not inherit the retargeted target")
		}
		refilled(t, w, raw, 10_081, w.side[10_079], ssqWork(10_081), "exact target/steps1-12 result and refill image")
	})
	t.Run("A7c-retarget-wrong", func(t *testing.T) {
		w, raw := rfWorld(t, 9_000, 9_000, 10_081, 60, retargetCandidate(consensus.POW_LIMIT))
		if [32]byte(w.headers[w.side[10_081]][4:36]) != ssqHash(raw) {
			t.Fatal("A7c-retarget-wrong fixture: first retained header does not name the candidate")
		}
		retainWantConsensus(t, "default target instead of current retarget refused", w.refill(raw), consensus.BLOCK_ERR_TARGET_INVALID)
		w.wantImage("A7c-retarget-wrong unchanged")
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
		// Prepared side with its exact pending SIDE: RF of the physical still-owed oldest block 1 (the predecessor the
		// new first retained header 2 names) refuses on its domain; the SIDE, the oldest body and link stay.
		w, raw := rollWorld(t)
		oldest := bytes.Clone(w.rows[string(append([]byte{4}, w.sideKey(1)...))].value)
		prior := w.tracked()
		retainWant(t, "R-h preparation", w.prepareSide(raw, w.tipAt(2)), "", "", retainNA, newT, crossed, true)
		w.expectPrepared(prior)
		if [32]byte(w.headers[w.side[2]][4:36]) != ssqHash(oldest) {
			t.Fatal("R-h fixture: first retained header does not name the oldest block")
		}
		retainWantRefusal(t, "Prepared exact SIDE remains", w.refill(oldest), ssqBranch, "selected side refill needs a cleaned one-slot side without a pending SIDE")
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
		w.exactSide(w.retainSide(0, 1_441, 1_439, 1_442, true), 3, 1_441)
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
			w.exactSide(blocks, 1, 1_440)
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
