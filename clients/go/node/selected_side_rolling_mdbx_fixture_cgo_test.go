//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"bytes"
	"errors"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// armedPrepare invokes the real RP entrypoint exactly once under one armed native scenario; a site not reached as
// armed fails.
func (w *ssqWorld) armedPrepare(scenario mdbx.SelectedDamageScenario, rank uint8, key, raw []byte) (SelectedSideMutationOutcome, mdbx.SelectedDamageEvidence) {
	w.t.Helper()
	return w.armedPrepareAt(scenario, rank, key, raw, w.tipAt(2))
}

// armedPrepareAt is armedPrepare under an explicit literal expected-tip locator.
func (w *ssqWorld) armedPrepareAt(scenario mdbx.SelectedDamageScenario, rank uint8, key, raw []byte, tip *mdbx.AuthorityPointV1) (SelectedSideMutationOutcome, mdbx.SelectedDamageEvidence) {
	w.t.Helper()
	var out SelectedSideMutationOutcome
	calls := 0
	evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() {
		calls++
		out = w.prepareSide(raw, tip)
	})
	if err != nil || calls != 1 {
		w.t.Fatalf("scenario %d: %v (%+v)", scenario, err, evidence)
	}
	return out, evidence
}

// rollFixtureWorld is rollWorld with native row comparison.
func rollFixtureWorld(t *testing.T) (*ssqWorld, []byte) {
	t.Helper()
	w, raw := rollWorld(t)
	w.rawEqual = func(rank uint8, key, want []byte) (bool, error) {
		return mdbx.FixtureRawRowEqual(w.store, rank, key, want)
	}
	return w, raw
}

// rollUnionWorld is the live contract's LF[H11-union] pre-state (RP_composed_union_source_correction): published
// genesis and mined canonical 1..30000 with B14881/U28561; a full 1440-row side 8640..10079 (g2) whose SideLinks name
// the canonical rows with their canonical works, header-only history F+1..8639 being the owned canonical headers; the
// oldest body 8640 (owner height below B, optional) positively absent. wide=false: F7651/C2428 with every leaving row
// canonical-owned, so only the authority is a target. wide=true: F7650/C2429 and the tip 10079 an unowned block mined
// over canonical 10078, whose leaving header is a second target. It returns the exact-tip child at retarget height
// 10080. The 16384/16385 identity totals are the contract's source-derived premises, unexecuted here.
func rollUnionWorld(t *testing.T, wide bool) (*ssqWorld, []byte) {
	t.Helper()
	w := newRetainWorld(t, ssqSpec{tip: 30_000, b: 14_881})
	w.rawEqual = func(rank uint8, key, want []byte) (bool, error) {
		return mdbx.FixtureRawRowEqual(w.store, rank, key, want)
	}
	f, tip := uint64(7_651), w.canonical[10_079]
	var rows []mdbx.Mutation
	if wide {
		block := w.mined(w.canonical[10_078], 113)
		f, tip = 7_650, ssqHash(block)
		rows = append(rows, w.literal(3, bytes.Clone(tip[:]), block[:consensus.BLOCK_HEADER_BYTES], false), w.literal(4, bytes.Clone(tip[:]), block, false))
	}
	var total uint64
	prev := w.canonical[8_639]
	for j := uint64(8_640); j <= 10_079; j++ {
		hash := w.canonical[j]
		if j == 10_079 {
			hash = tip
		}
		w.side[j] = hash
		total += uint64(len(w.rows[string(append([]byte{4}, hash[:]...))].value))
		rows = append(rows, w.literal(6, ssqMust(mdbx.HeightKey(2, j)), mdbx.ChainValue(hash, prev, ssqWork(j+1)), false))
		prev = hash
	}
	a := w.authorityValue()
	a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 2, F: f, TipHeight: 10_079, TipHash: tip, CumulativeChainwork: ssqWork(10_080), RowCount: 1_440, LogicalBytes: total}
	w.apply(append(rows, w.authorityMutation(a)))
	w.apply([]mdbx.Mutation{w.absentRow(4, w.sideKey(8_640))})
	return w, w.child(tip, 10_080, nil)
}

// rollLocatorWorld is rollFixtureWorld whose tip 1440 is a hash-bound block naming an absent unowned parent Z (its
// SideLink and descriptor are rewritten to it): qualification of the exact-tip child asks row 1439 by Z, a clean damage
// locator (2,1440,1439); the recheck of 1439 finds that row healthy and the single retry repeats the same locator.
func rollLocatorWorld(t *testing.T) (*ssqWorld, []byte) {
	t.Helper()
	w, _ := rollFixtureWorld(t)
	z := [32]byte{0x5a}
	w.headers[z] = w.headers[w.side[1_439]]
	tip := w.mined(z, 113)
	hash := ssqHash(tip)
	w.side[1_440] = hash
	a := w.tracked()
	side := *a.SelectedSide
	side.TipHash = hash
	a.SelectedSide = &side
	w.apply([]mdbx.Mutation{
		w.literal(3, bytes.Clone(hash[:]), tip[:consensus.BLOCK_HEADER_BYTES], false), w.literal(4, bytes.Clone(hash[:]), tip, false),
		w.literal(6, ssqMust(mdbx.HeightKey(2, 1_440)), mdbx.ChainValue(hash, z, ssqWork(1_441)), true), w.authorityMutation(a),
	})
	// The previous tip's header and body stay as unrelated preserved rows.
	delete(w.headers, z)
	return w, w.childAt(hash, w.ts(hash)+120, consensus.POW_LIMIT, nil)
}

// rollTipBodyAbsent removes the tip 1440 body: the exact-tip qualification reads it through its optional linking owner
// and stops at a positive-absence damage locator (2,1440,1440) before RP planning.
func rollTipBodyAbsent(t *testing.T) (*ssqWorld, []byte) {
	t.Helper()
	w, raw := rollFixtureWorld(t)
	tip := w.side[1_440]
	w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(tip[:]))})
	return w, raw
}

func TestSelectedSideRollingFixture(t *testing.T) {
	old, crossed := mdbx.CommitTruthOld, mdbx.UpdateStageCommitMayHaveCrossed
	t.Run("H8-lifetime", func(t *testing.T) {
		w, raw := rollFixtureWorld(t)
		prior := w.tracked()
		out, evidence := w.armedPrepare(mdbx.SelectedDamageProbeOnly, 0, nil, raw)
		retainWant(t, "probed RP", out, "", "", retainNA, mdbx.CommitTruthNew, crossed, true)
		if evidence.Probes == 0 || evidence.ProbeDenied != evidence.Probes || evidence.ProbeRan != 0 || evidence.BeginWrite != 1 || evidence.Commits != 1 || evidence.BeginRead != 0 {
			t.Fatalf("every native full-lane probe denied; grant released after return: %+v", evidence)
		}
		w.expectPrepared(prior)
		w.wantImage("probed RP image")
	})
	t.Run("H8a-delete", func(t *testing.T) {
		// RP's one definite delete is the unkept oldest header; DeleteEIO fails it before commit.
		w, raw := rollFixtureWorld(t)
		out, evidence := w.armedPrepare(mdbx.SelectedDamageDeleteEIO, 0, nil, raw)
		retainWant(t, "definite precommit write", out, retainPrecommit, "", "OLD", old, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, false)
		ssqWantNative(t, "RP delete", out.Err, ssqNative{"update", mdbx.EngineIO, 5})
		if evidence.BeginWrite != 1 || evidence.Deletes != 1 || evidence.Commits != 0 || evidence.Faults != 1 {
			t.Fatalf("RP delete evidence %+v", evidence)
		}
		w.wantImage("precommit keeps OLD")
	})
	t.Run("R-n", func(t *testing.T) {
		// The optional oldest body read faults transiently: branch_data/OLD with the exact native cause, no plan or write.
		w, raw := rollFixtureWorld(t)
		out, evidence := w.armedPrepare(mdbx.SelectedDamageGetEIO, 4, w.sideKey(1), raw)
		retainWant(t, "oldest transient read branch_data", out, ssqBranch, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		ssqWantNative(t, "oldest body GetEIO", out.Err, ssqGetEIO)
		if evidence.BeginWrite != 0 || evidence.Commits != 0 {
			t.Fatalf("R-n evidence %+v", evidence)
		}
		w.wantImage("oldest transient read keeps OLD")
	})
	t.Run("R-n-owner", func(t *testing.T) {
		// The oldest row's required CanonicalOwnerV1 read (rank 7, active generation 1) faults transiently: it keeps
		// canonical_artifact_read at its fixed position, with no plan, write or commit and the grant released (operate).
		w, raw := rollFixtureWorld(t)
		out, evidence := w.armedPrepare(mdbx.SelectedDamageGetEIO, 7, ssqMust(mdbx.CanonicalOwnerKey(1, w.side[1])), raw)
		retainWant(t, "required owner transient read canonical_artifact_read", out, ssqCanonical, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		ssqWantNative(t, "oldest owner GetEIO", out.Err, ssqGetEIO)
		if evidence.BeginWrite != 0 || evidence.Commits != 0 {
			t.Fatalf("R-n-owner evidence %+v", evidence)
		}
		w.wantImage("required owner transient read keeps OLD")
	})
	t.Run("H6b-NEW", func(t *testing.T) {
		w, raw := rollFixtureWorld(t)
		prior := w.tracked()
		out, evidence := w.armedPrepare(mdbx.SelectedDamageCommitNew, 0, nil, raw)
		retainWant(t, "proved NEW/raw causes retained/NOT_APPLICABLE empty Result", out, "", "", retainNA, mdbx.CommitTruthNew, crossed, false)
		var commit *mdbx.CommitError
		if !errors.As(out.Err, &commit) || commit.Truth != mdbx.CommitTruthNew || evidence.Commits != 1 {
			t.Fatalf("equality NEW error %v (%+v)", out.Err, evidence)
		}
		ssqWantNative(t, "commit ENOSPC", commit.Cause, ssqNative{"update", mdbx.EngineCapacity, 28})
		w.expectPrepared(prior)
		w.wantImage("equality NEW Prepared image")
	})
	t.Run("H6b-OLD", func(t *testing.T) {
		w, raw := rollFixtureWorld(t)
		out, _ := w.armedPrepare(mdbx.SelectedDamageCommitOld, 0, nil, raw)
		retainWant(t, "equality OLD empty Result", out, "", "", retainNA, old, crossed, false)
		retainWantCommit(t, "equality OLD", out, false)
		w.wantImage("equality OLD full image")
	})
	for _, c := range []struct {
		name string
		scen mdbx.SelectedDamageScenario
		key  []byte
	}{{"H6a-RP", mdbx.SelectedDamageCommitUnreadable, []byte{2}}, {"H6a-RP-third", mdbx.SelectedDamageCommitThird, nil}} {
		t.Run(c.name, func(t *testing.T) {
			w, raw := rollFixtureWorld(t)
			out, _ := w.armedPrepare(c.scen, 0, c.key, raw)
			retainWant(t, "noncanonical/NOT_APPLICABLE with exact raw UNKNOWN", out, retainCleared, "", retainNA, mdbx.CommitTruthUnknown, crossed, false)
			retainWantCommit(t, c.name, out, c.key != nil)
		})
	}
	for _, c := range []struct {
		name  string
		scen  mdbx.SelectedDamageScenario
		truth mdbx.CommitTruth
	}{{"H6a-RP-positive-OLD", mdbx.SelectedDamageCommitOld, mdbx.CommitTruthOld}, {"H6a-RP-positive-NEW", mdbx.SelectedDamageCommitNew, mdbx.CommitTruthNew}, {"H6a-RP-positive-UNKNOWN", mdbx.SelectedDamageCommitThird, mdbx.CommitTruthUnknown}} {
		t.Run(c.name, func(t *testing.T) {
			// Positive oldest damage: the complete clear keeps its all-outcome noncanonical exception.
			w, raw := rollFixtureWorld(t)
			oldest := w.side[1]
			w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(oldest[:]))})
			out, evidence := w.armedPrepare(c.scen, 0, nil, raw)
			retainWant(t, "positive-damage clear keeps its all-outcome exception", out, retainCleared, "", retainNA, c.truth, crossed, false)
			if evidence.BeginWrite != 1 || evidence.Commits != 1 {
				t.Fatalf("positive clear write evidence %+v", evidence)
			}
			switch c.truth {
			case mdbx.CommitTruthOld:
				w.wantImage("crossed OLD full image")
			case mdbx.CommitTruthNew:
				w.wantCleared("crossed NEW complete clear image", 1, 1_440)
			}
		})
	}
	for _, c := range []struct {
		name string
		code int
		kind mdbx.EngineClass
		scen mdbx.SelectedDamageScenario
	}{{"H8a-begin-txnfull", -30_788, mdbx.EngineTransaction, mdbx.SelectedDamageBeginTxnFull}, {"H8a-begin-eio", 5, mdbx.EngineIO, mdbx.SelectedDamageBeginEIO}} {
		t.Run(c.name, func(t *testing.T) {
			w, raw := rollFixtureWorld(t)
			out, evidence := w.armedPrepare(c.scen, 0, nil, raw)
			retainWant(t, "no-callback native begin keeps empty fields", out, "", "", "", old, mdbx.UpdateStagePrewrite, false)
			ssqWantNative(t, c.name, out.Err, ssqNative{"update", c.kind, c.code})
			if evidence.BeginOld != 1 || evidence.OldGets != [8]uint64{} {
				t.Fatalf("begin evidence %+v", evidence)
			}
			w.wantImage("RP begin failure")
		})
	}
	t.Run("H8a-get-tip", func(t *testing.T) {
		w, raw := rollFixtureWorld(t)
		out, _ := w.armedPrepare(mdbx.SelectedDamageGetEIO, 2, ssqMust(mdbx.HeightKey(1, 2)), raw)
		retainWantRefusal(t, "tip read canonical_artifact_read", out, ssqCanonical, "")
		ssqWantNative(t, "tip GetEIO", out.Err, ssqGetEIO)
		w.wantImage("RP tip read fault")
	})
	t.Run("H8a-getabort-tip", func(t *testing.T) {
		w, raw := rollFixtureWorld(t)
		out, _ := w.armedPrepare(mdbx.SelectedDamageGetAbortEIO, 2, ssqMust(mdbx.HeightKey(1, 2)), raw)
		retainWantRefusal(t, "first typed result kept over abort IO", out, ssqCanonical, "")
		ssqWantNative(t, "tip Get+abort EIO", out.Err, ssqGetEIO, ssqAbortEIO)
		w.wantImage("RP tip read and abort fault")
	})
	t.Run("H8a-put", func(t *testing.T) {
		// RP's only put is the authority literal; PutEIO fails it before commit.
		w, raw := rollFixtureWorld(t)
		out, evidence := w.armedPrepare(mdbx.SelectedDamagePutEIO, 0, []byte{2}, raw)
		retainWant(t, "definite precommit write", out, retainPrecommit, "", "OLD", old, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, false)
		ssqWantNative(t, "RP put", out.Err, ssqNative{"update", mdbx.EngineIO, 5})
		if evidence.BeginWrite != 1 || evidence.Commits != 0 || evidence.BeginRead != 0 {
			t.Fatalf("RP put evidence %+v", evidence)
		}
		w.wantImage("precommit keeps OLD")
	})
	t.Run("H8-cache", func(t *testing.T) {
		// A Prepare whose child K23-outranks the canonical tip decides ORDINARY through the no-write sentinel; abort EIO
		// consumes the Store and the next RP call returns the cached tuple with empty invocation fields.
		w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
		raw := w.child(w.canonical[10], 11, nil)
		var first SelectedSideMutationOutcome
		if _, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageAbortEIO, 0, nil, func() { first = w.prepareSide(raw, w.tipAt(10)) }); err != nil {
			t.Fatalf("H8-cache fixture: %v", err)
		}
		retainWant(t, "joined abort IO storage_io/raw ordered join/CLOSED", first, retainStorageIO, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		ssqWantNative(t, "sentinel abort", first.Err, ssqAbortEIO)
		next := w.prepareSide(raw, w.tipAt(10))
		retainWant(t, "empty invocation fields/raw cached tuple", next, "", "", "", old, mdbx.UpdateStagePrewrite, false)
		// Mutual errors.Is over an acyclic error tree holds only for the identical error value.
		if next.Err == nil || !errors.Is(next.Err, first.Err) || !errors.Is(first.Err, next.Err) {
			t.Fatalf("empty invocation fields/raw cached tuple: error %v, want %v", next.Err, first.Err)
		}
		w.wantImage("cached next call persisted image")
	})
	t.Run("H12-capacity-abortIO", func(t *testing.T) {
		// The RP capacity refusal is a non-read sentinel exit: ReadResource is clear, so abort EIO maps storage_io, never
		// the linking body's branch_data class; no clean Result or Decision survives the joined cause.
		w := newRetainFixtureWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
		blocks := w.retainSide(0, 1_440, 1_440, 1_441, false)
		raw := retainLarge(t, w.side[1_440], w.ts(w.side[1_440])+120, (437_205-len(blocks[1_440]))/2+1)
		var out SelectedSideMutationOutcome
		if _, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageAbortEIO, 0, nil, func() { out = w.prepareSide(raw, w.tipAt(2)) }); err != nil {
			t.Fatalf("H12 fixture: %v", err)
		}
		retainWant(t, "capacity sentinel abort storage_io", out, retainStorageIO, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		ssqWantNative(t, "capacity sentinel abort", out.Err, ssqAbortEIO)
	})
	t.Run("H12-optional-read-abortIO", func(t *testing.T) {
		// An actual failed optional oldest-body read keeps its branch_data class through projection; a Get+abort EIO
		// keeps that first typed class with the raw ordered join.
		w, raw := rollFixtureWorld(t)
		out, _ := w.armedPrepare(mdbx.SelectedDamageGetAbortEIO, 4, w.sideKey(1), raw)
		retainWant(t, "failed-read resource retained", out, ssqBranch, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		ssqWantNative(t, "oldest body Get+abort EIO", out.Err, ssqGetEIO, ssqAbortEIO)
		w.wantImage("RP failed read keeps OLD")
	})
	// Remaining-link failures at an otherwise valid middle SideLink(2,700), outside the qualification context: seeded
	// malformed width or zero-work identity is recorded canonical integrity/OLD; a Get EIO or Get+abort EIO is
	// branch_data/OLD with the raw ordered native causes and no write; OLD image.
	for _, c := range []struct {
		name, diagnostic string
		width            bool
	}{{"remaining-width", "stored value width outside SchemaV2 bound", true}, {"remaining-zero-work", "selected side link identity is undecodable", false}} {
		t.Run(c.name, func(t *testing.T) {
			w, raw := rollFixtureWorld(t)
			key := ssqMust(mdbx.HeightKey(2, 700))
			value := mdbx.ChainValue(w.side[700], w.side[699], [40]byte{})
			if c.width {
				value = make([]byte, 103)
			}
			if err := mdbx.FixtureSeedRawRow(w.store, 6, key, value); err != nil {
				t.Fatalf("%s seed: %v", c.name, err)
			}
			w.rows[string(append([]byte{6}, key...))] = ssqRow{rank: 6, key: key, value: value}
			retainWantIntegrity(t, c.name, w.prepareSide(raw, w.tipAt(2)), c.diagnostic)
			w.wantImage(c.name + " keeps the damaged OLD image")
		})
	}
	for _, c := range []struct {
		name   string
		scen   mdbx.SelectedDamageScenario
		causes []ssqNative
	}{{"remaining-get-eio", mdbx.SelectedDamageGetEIO, []ssqNative{ssqGetEIO}}, {"remaining-getabort-eio", mdbx.SelectedDamageGetAbortEIO, []ssqNative{ssqGetEIO, ssqAbortEIO}}} {
		t.Run(c.name, func(t *testing.T) {
			w, raw := rollFixtureWorld(t)
			out, evidence := w.armedPrepare(c.scen, 6, ssqMust(mdbx.HeightKey(2, 700)), raw)
			retainWant(t, c.name+" branch_data", out, ssqBranch, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
			ssqWantNative(t, c.name, out.Err, c.causes...)
			if evidence.BeginWrite != 0 {
				t.Fatalf("%s: remaining link read wrote: %+v", c.name, evidence)
			}
			w.wantImage(c.name + " keeps OLD")
		})
	}
	t.Run("H5", func(t *testing.T) {
		// Each relied-on RP observation is in the final union: a readback-only Get EIO on it turns the committed image
		// UNKNOWN. The tuple is asserted inside the callback before fixture bookkeeping.
		for _, c := range []struct {
			name string
			rank uint8
			key  func(w *ssqWorld, raw []byte) []byte
		}{
			{"candidate owner absence", 7, func(w *ssqWorld, raw []byte) []byte { return ssqMust(mdbx.CanonicalOwnerKey(1, ssqHash(raw))) }},
			{"absent next-height tip boundary", 2, func(*ssqWorld, []byte) []byte { return ssqMust(mdbx.HeightKey(1, 3)) }},
			{"oldest SideLink", 6, func(*ssqWorld, []byte) []byte { return ssqMust(mdbx.HeightKey(2, 1)) }},
			{"oldest owner NONE", 7, func(w *ssqWorld, _ []byte) []byte { return ssqMust(mdbx.CanonicalOwnerKey(1, w.side[1])) }},
			{"oldest body", 4, func(w *ssqWorld, _ []byte) []byte { return w.sideKey(1) }},
			{"remaining SideLink700", 6, func(*ssqWorld, []byte) []byte { return ssqMust(mdbx.HeightKey(2, 700)) }},
		} {
			w, raw := rollFixtureWorld(t)
			prior := w.tracked()
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageCommitUnreadable, c.rank, c.key(w, raw), func() {
				out := w.prepareSide(raw, w.tipAt(2))
				var commit *mdbx.CommitError
				if out.Result != retainCleared || out.Decision != "" || out.CanonicalTruth != retainNA || out.Truth != mdbx.CommitTruthUnknown || out.Stage != crossed ||
					!errors.As(out.Err, &commit) || commit.Truth != mdbx.CommitTruthUnknown {
					t.Fatalf("required native OLD/Consulted observation captured and equality rejected: %s %+v", c.name, out)
				}
				ssqWantNative(t, c.name+": readback get EIO", commit.ReadbackCause, ssqNative{"update", mdbx.EngineIO, 5})
			})
			if err != nil || evidence.Commits != 1 || evidence.BeginWrite != 1 {
				t.Fatalf("%s: fixture site %v (%+v)", c.name, err, evidence)
			}
			w.expectPrepared(prior)
			w.wantImage(c.name + ": independently checked committed Prepared image")
		}
	})
	t.Run("H10-abortIO", func(t *testing.T) {
		w, raw := rollTipBodyAbsent(t)
		out, evidence := w.armedPrepare(mdbx.SelectedDamageAbortEIO, 0, nil, raw)
		retainWant(t, "storage_io/raw join/CLOSED/no recheck", out, retainStorageIO, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		var request *selectedSideDamageRequest
		if !errors.As(out.Err, &request) || *request != (selectedSideDamageRequest{Generation: 2, Tip: 1_440, Height: 1_440}) || evidence.BeginOld != 1 || evidence.BeginRead != 0 {
			t.Fatalf("locator abort %+v (%+v)", out, evidence)
		}
		w.wantImage("side kept without recheck")
	})
	for _, c := range []struct {
		name  string
		scen  mdbx.SelectedDamageScenario
		truth mdbx.CommitTruth
	}{{"H10-positive", mdbx.SelectedDamageCommitNew, mdbx.CommitTruthNew}, {"H10-positive-OLD", mdbx.SelectedDamageCommitOld, mdbx.CommitTruthOld}, {"H10-positive-UNKNOWN", mdbx.SelectedDamageCommitThird, mdbx.CommitTruthUnknown}} {
		t.Run(c.name, func(t *testing.T) {
			// The tip locator's recheck is a complete positive clear: its whole tuple terminates, never the locator's.
			w, raw := rollTipBodyAbsent(t)
			out, evidence := w.armedPrepare(c.scen, 0, nil, raw)
			retainWant(t, "complete recheck NEW/raw/error image tuple", out, retainCleared, "", retainNA, c.truth, crossed, false)
			if evidence.BeginOld != 1 || evidence.BeginWrite != 1 || evidence.Commits != 1 {
				t.Fatalf("recheck write evidence %+v", evidence)
			}
			switch c.truth {
			case mdbx.CommitTruthOld:
				w.wantImage("crossed OLD recheck image")
			case mdbx.CommitTruthNew:
				w.wantCleared("crossed NEW recheck image", 1, 1_440)
			}
		})
	}
	for _, name := range []string{"A10", "H10-second"} {
		t.Run(name, func(t *testing.T) {
			// Healthy recheck between released grants, then ONE fresh qualification whose second locator is typed
			// branch_data; no clear, no write and no nested operation.
			w, raw := rollLocatorWorld(t)
			out, evidence := w.armedPrepare(mdbx.SelectedDamageProbeOnly, 0, nil, raw)
			retainWantRefusal(t, "one retry/branch_data/operation counts", out, ssqBranch, "")
			var request *selectedSideDamageRequest
			if !errors.As(out.Err, &request) || *request != (selectedSideDamageRequest{Generation: 2, Tip: 1_440, Height: 1_439}) {
				t.Fatalf("second locator cause %v", out.Err)
			}
			if evidence.BeginOld != 1 || evidence.BeginRead != 2 || evidence.BeginWrite != 0 || evidence.Deletes != 0 || evidence.Commits != 0 || evidence.Faults != 0 ||
				evidence.OldAborts < 1 || evidence.OldAborts > 3 || evidence.Probes != 2+2*evidence.OldAborts || evidence.ProbeDenied != evidence.Probes || evidence.ProbeRan != 0 {
				t.Fatalf("recheck between released grants/no nested operation: %+v", evidence)
			}
			w.wantImage("bounded retry left the image unchanged")
		})
	}
	// H11-oldest / H11-planner: the nFit+1 refusal reads exactly one body natively (the linking tip body, L) and no
	// planner row; a planner run before the preflight would also read the oldest SideLink and body. The intended
	// assertion precedes fixture bookkeeping.
	for _, name := range []string{"H11-oldest", "H11-planner", "H11-link-length"} {
		t.Run(name, func(t *testing.T) {
			w := newRetainFixtureWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
			blocks := w.retainSide(0, 1_440, 1_440, 1_441, false)
			raw := retainLarge(t, w.side[1_440], w.ts(w.side[1_440])+120, (437_205-len(blocks[1_440]))/2+1)
			w.absent = append(w.absent, ssqHash(raw))
			out, evidence := w.armedPrepare(mdbx.SelectedDamageProbeOnly, 0, nil, raw)
			retainWant(t, "conservative planner Q>G refused before planner allocation/read/Batch", out, retainCapacity, "", "OLD", old, mdbx.UpdateStagePrewrite, true)
			if evidence.OldGets[4] != 1 || evidence.BeginWrite != 0 || evidence.Commits != 0 {
				t.Fatalf("actual L resource bound/no second body read: %+v", evidence)
			}
			w.wantImage(name + " refusal image")
		})
	}
	t.Run("H6a-RP-incomplete", func(t *testing.T) {
		// Positively absent optional oldest body, then the complete transfer meets an absent required SideLink(2,first+1):
		// canonical integrity from that required read, OLD/Prewrite, no native write or commit, the damaged pre-state
		// unchanged and the grant released (operate). A flag-only change on this error path is not observable here.
		w, raw := rollFixtureWorld(t)
		bodyKey, linkKey := w.sideKey(1), ssqMust(mdbx.HeightKey(2, 2))
		w.apply([]mdbx.Mutation{w.absentRow(4, bodyKey), w.absentRow(6, linkKey)})
		out, evidence := w.armedPrepare(mdbx.SelectedDamageProbeOnly, 0, nil, raw)
		retainWantIntegrity(t, "incomplete plan/stronger error is not positive clear", out, "selected side link is absent")
		ssqWantNative(t, "incomplete plan raw cause", out.Err, ssqNative{"get", mdbx.EngineIntegrity, -30_793})
		if evidence.BeginOld != 1 || evidence.BeginWrite != 0 || evidence.Deletes != 0 || evidence.Commits != 0 {
			t.Fatalf("incomplete plan wrote: %+v", evidence)
		}
		w.wantImage("incomplete plan keeps the damaged OLD image")
		w.wantAbsent("oldest body still absent", 4, bodyKey)
		w.wantAbsent("first+1 link still absent", 6, linkKey)
	})
	// RA native outcomes on raWorld (cleaned one-slot 3..1441/F0, child 1442): one public Retain per scenario through the
	// existing armed helper, tuple asserted first; the expected appended side is the literal of L[A6].
	raFixture := func(t *testing.T) (*ssqWorld, []byte, mdbx.StorageAuthorityV1, mdbx.SelectedSideV1) {
		w, raw := raWorld(t)
		w.rawEqual = func(rank uint8, key, want []byte) (bool, error) {
			return mdbx.FixtureRawRowEqual(w.store, rank, key, want)
		}
		prior := w.tracked()
		side := mdbx.SelectedSideV1{GenerationID: 2, F: 0, TipHeight: 1_442, TipHash: ssqHash(raw), CumulativeChainwork: ssqWork(1_443), RowCount: 1_440, LogicalBytes: prior.SelectedSide.LogicalBytes + uint64(len(raw))}
		return w, raw, prior, side
	}
	for _, c := range []struct {
		name string
		scen mdbx.SelectedDamageScenario
		key  []byte
	}{{"H6a-RA", mdbx.SelectedDamageCommitUnreadable, []byte{2}}, {"H6a-RA-third", mdbx.SelectedDamageCommitThird, nil}} {
		t.Run(c.name, func(t *testing.T) {
			w, raw, _, _ := raFixture(t)
			out, _ := w.armed(c.scen, 0, c.key, raw, w.tipAt(2))
			retainWant(t, "noncanonical/NOT_APPLICABLE with exact raw UNKNOWN", out, retainCleared, "", retainNA, mdbx.CommitTruthUnknown, crossed, false)
			retainWantCommit(t, c.name, out, c.key != nil)
		})
	}
	t.Run("H6b-RA-NEW", func(t *testing.T) {
		w, raw, prior, side := raFixture(t)
		out, evidence := w.armed(mdbx.SelectedDamageCommitNew, 0, nil, raw, w.tipAt(2))
		retainWant(t, "proved NEW/raw causes retained/NOT_APPLICABLE empty Result", out, "", "", retainNA, mdbx.CommitTruthNew, crossed, false)
		var commit *mdbx.CommitError
		if !errors.As(out.Err, &commit) || commit.Truth != mdbx.CommitTruthNew || evidence.Commits != 1 {
			t.Fatalf("RA equality NEW error %v (%+v)", out.Err, evidence)
		}
		w.expectN2(raw, prior, side, w.side[1_441])
		w.wantN1Image("RA equality NEW image", raw)
	})
	t.Run("H6b-RA-OLD", func(t *testing.T) {
		w, raw, _, _ := raFixture(t)
		out, _ := w.armed(mdbx.SelectedDamageCommitOld, 0, nil, raw, w.tipAt(2))
		retainWant(t, "equality OLD empty Result", out, "", "", retainNA, old, crossed, false)
		retainWantCommit(t, "RA equality OLD", out, false)
		w.wantImage("RA equality OLD image")
	})
	for _, c := range []struct {
		name string
		code int
		kind mdbx.EngineClass
		scen mdbx.SelectedDamageScenario
	}{{"H8a-RA-begin-txnfull", -30_788, mdbx.EngineTransaction, mdbx.SelectedDamageBeginTxnFull}, {"H8a-RA-begin-eio", 5, mdbx.EngineIO, mdbx.SelectedDamageBeginEIO}} {
		t.Run(c.name, func(t *testing.T) {
			w, raw, _, _ := raFixture(t)
			out, evidence := w.armed(c.scen, 0, nil, raw, w.tipAt(2))
			retainWant(t, "no-callback native begin keeps empty fields", out, "", "", "", old, mdbx.UpdateStagePrewrite, false)
			ssqWantNative(t, c.name, out.Err, ssqNative{"update", c.kind, c.code})
			if evidence.BeginOld != 1 || evidence.OldGets != [8]uint64{} || evidence.BeginWrite != 0 {
				t.Fatalf("RA begin evidence %+v", evidence)
			}
			w.wantImage("RA begin failure")
		})
	}
	t.Run("H8a-RA-get-tip", func(t *testing.T) {
		w, raw, _, _ := raFixture(t)
		out, evidence := w.armed(mdbx.SelectedDamageGetEIO, 2, ssqMust(mdbx.HeightKey(1, 2)), raw, w.tipAt(2))
		retainWantRefusal(t, "RA tip read canonical_artifact_read", out, ssqCanonical, "")
		ssqWantNative(t, "RA tip GetEIO", out.Err, ssqGetEIO)
		if evidence.BeginWrite != 0 || evidence.Commits != 0 {
			t.Fatalf("RA tip read wrote: %+v", evidence)
		}
		w.wantImage("RA tip read fault")
	})
	t.Run("H8a-RA-getabort-tip", func(t *testing.T) {
		// Get+abort EIO keeps the first typed result with the ordered raw join and consumes the Store: the next RA call
		// returns that cached raw error with empty invocation fields; the image is read after the helper's reopen.
		w, raw, _, _ := raFixture(t)
		first, evidence := w.armed(mdbx.SelectedDamageGetAbortEIO, 2, ssqMust(mdbx.HeightKey(1, 2)), raw, w.tipAt(2))
		retainWantRefusal(t, "RA first typed result kept over abort IO", first, ssqCanonical, "")
		ssqWantNative(t, "RA tip Get+abort EIO", first.Err, ssqGetEIO, ssqAbortEIO)
		if evidence.BeginWrite != 0 || evidence.Commits != 0 {
			t.Fatalf("RA tip read and abort wrote: %+v", evidence)
		}
		next := w.retain(raw, w.tipAt(2))
		retainWant(t, "RA cached next call empty fields", next, "", "", "", old, mdbx.UpdateStagePrewrite, false)
		// Mutual errors.Is over an acyclic error tree holds only for the identical error value.
		if !errors.Is(next.Err, first.Err) || !errors.Is(first.Err, next.Err) {
			t.Fatalf("RA cached raw error %v, want %v", next.Err, first.Err)
		}
		w.wantImage("RA tip read and abort fault")
	})
	t.Run("H12-RA-capacity-abortIO", func(t *testing.T) {
		// RA's 3n+L capacity refusal is a non-read sentinel exit: abort EIO maps storage_io with the raw abort cause, no
		// clean Result or Decision; the consumed Store answers the next call from its cached raw error.
		w, _, _, _ := raFixture(t)
		l := len(w.rows[string(append([]byte{4}, w.sideKey(1_441)...))].value)
		raw := retainLarge(t, w.side[1_441], w.ts(w.side[1_441])+120, (140_965_583-l)/3+1)
		w.absent = append(w.absent, ssqHash(raw))
		first, _ := w.armed(mdbx.SelectedDamageAbortEIO, 0, nil, raw, w.tipAt(2))
		retainWant(t, "RA capacity sentinel abort storage_io", first, retainStorageIO, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		ssqWantNative(t, "RA capacity sentinel abort", first.Err, ssqAbortEIO)
		next := w.retain(raw, w.tipAt(2))
		retainWant(t, "RA cached next call empty fields", next, "", "", "", old, mdbx.UpdateStagePrewrite, false)
		if !errors.Is(next.Err, first.Err) || !errors.Is(first.Err, next.Err) {
			t.Fatalf("RA cached raw error %v, want %v", next.Err, first.Err)
		}
		w.wantImage("RA capacity abort keeps OLD")
	})
	t.Run("H8a-RA-put", func(t *testing.T) {
		w, raw, _, _ := raFixture(t)
		out, evidence := w.armed(mdbx.SelectedDamagePutEIO, 6, ssqMust(mdbx.HeightKey(2, 1_442)), raw, w.tipAt(2))
		retainWant(t, "definite precommit RA link write", out, retainPrecommit, "", "OLD", old, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, false)
		ssqWantNative(t, "RA put", out.Err, ssqNative{"update", mdbx.EngineIO, 5})
		if evidence.BeginWrite != 1 || evidence.Commits != 0 || evidence.BeginRead != 0 {
			t.Fatalf("RA put evidence %+v", evidence)
		}
		w.wantImage("RA precommit keeps OLD")
	})
	t.Run("H8a-RA-get-linking", func(t *testing.T) {
		w, raw, _, _ := raFixture(t)
		out, _ := w.armed(mdbx.SelectedDamageGetEIO, 4, w.sideKey(1_441), raw, w.tipAt(2))
		retainWantRefusal(t, "transient optional linking body branch_data", out, ssqBranch, "")
		ssqWantNative(t, "RA linking GetEIO", out.Err, ssqGetEIO)
		w.wantImage("RA linking read fault")
	})
	t.Run("H8-RA-lifetime", func(t *testing.T) {
		w, raw, prior, side := raFixture(t)
		out, evidence := w.armed(mdbx.SelectedDamageProbeOnly, 0, nil, raw, w.tipAt(2))
		retainWant(t, "probed RA", out, retainStored, "", retainNA, mdbx.CommitTruthNew, crossed, true)
		if evidence.Probes == 0 || evidence.ProbeDenied != evidence.Probes || evidence.ProbeRan != 0 || evidence.BeginWrite != 1 || evidence.Commits != 1 || evidence.BeginRead != 0 {
			t.Fatalf("every native full-lane probe denied; grant released after return: %+v", evidence)
		}
		w.expectN2(raw, prior, side, w.side[1_441])
		w.wantN1Image("probed RA image", raw)
	})
	t.Run("H10-RA-abortIO", func(t *testing.T) {
		// The cleaned tip body positively absent: the fresh RA qualification's locator (2,1441,1441) with abort EIO is
		// storage_io/CLOSED with no recheck.
		w, raw, _, _ := raFixture(t)
		w.apply([]mdbx.Mutation{w.absentRow(4, w.sideKey(1_441))})
		out, evidence := w.armed(mdbx.SelectedDamageAbortEIO, 0, nil, raw, w.tipAt(2))
		retainWant(t, "storage_io/raw join/CLOSED/no recheck", out, retainStorageIO, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		var request *selectedSideDamageRequest
		if !errors.As(out.Err, &request) || *request != (selectedSideDamageRequest{Generation: 2, Tip: 1_441, Height: 1_441}) || evidence.BeginOld != 1 || evidence.BeginRead != 0 {
			t.Fatalf("RA locator abort %+v (%+v)", out, evidence)
		}
		w.wantImage("RA side kept without recheck")
	})
	// RF native outcomes on the A7b world (side 3..1441/F0, candidate row 2 over unowned history row 1): one public
	// Refill per scenario, tuple asserted first; the expected image is the literal of L[A7b].
	rfFixture := func(t *testing.T) (*ssqWorld, []byte, mdbx.StorageAuthorityV1) {
		w, raw := rfWorld(t, 2, 0, 3, 113, nil)
		w.rawEqual = func(rank uint8, key, want []byte) (bool, error) {
			return mdbx.FixtureRawRowEqual(w.store, rank, key, want)
		}
		return w, raw, w.tracked()
	}
	armedRefill := func(w *ssqWorld, scen mdbx.SelectedDamageScenario, rank uint8, key, raw []byte) (SelectedSideMutationOutcome, mdbx.SelectedDamageEvidence) {
		w.t.Helper()
		var out SelectedSideMutationOutcome
		calls := 0
		evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scen, rank, key, func() { calls++; out = w.refill(raw) })
		if err != nil || calls != 1 {
			w.t.Fatalf("RF scenario %d: %v (%+v)", scen, err, evidence)
		}
		return out, evidence
	}
	for _, c := range []struct {
		name string
		scen mdbx.SelectedDamageScenario
		key  []byte
	}{{"H6a-RF", mdbx.SelectedDamageCommitUnreadable, []byte{2}}, {"H6a-RF-third", mdbx.SelectedDamageCommitThird, nil}} {
		t.Run(c.name, func(t *testing.T) {
			w, raw, _ := rfFixture(t)
			out, _ := armedRefill(w, c.scen, 0, c.key, raw)
			retainWant(t, "noncanonical/NOT_APPLICABLE with exact raw UNKNOWN", out, retainCleared, "", retainNA, mdbx.CommitTruthUnknown, crossed, false)
			retainWantCommit(t, c.name, out, c.key != nil)
		})
	}
	t.Run("H6b-RF-NEW", func(t *testing.T) {
		w, raw, prior := rfFixture(t)
		out, evidence := armedRefill(w, mdbx.SelectedDamageCommitNew, 0, nil, raw)
		retainWant(t, "proved NEW/raw causes retained/NOT_APPLICABLE empty Result", out, "", "", retainNA, mdbx.CommitTruthNew, crossed, false)
		var commit *mdbx.CommitError
		if !errors.As(out.Err, &commit) || commit.Truth != mdbx.CommitTruthNew || evidence.Commits != 1 {
			t.Fatalf("RF equality NEW error %v (%+v)", out.Err, evidence)
		}
		w.expectRefilled(raw, prior, 3, w.side[1], ssqWork(3))
		w.wantN1Image("RF equality NEW image", raw)
	})
	t.Run("H6b-RF-OLD", func(t *testing.T) {
		w, raw, _ := rfFixture(t)
		out, _ := armedRefill(w, mdbx.SelectedDamageCommitOld, 0, nil, raw)
		retainWant(t, "equality OLD empty Result", out, "", "", retainNA, old, crossed, false)
		retainWantCommit(t, "RF equality OLD", out, false)
		w.wantImage("RF equality OLD image")
	})
	t.Run("H5-tip-RF", func(t *testing.T) {
		// The proved-absent SideLink(2,2) is the RF link target whose OLD image Update captures: a readback fault on it
		// turns the committed image UNKNOWN; the tuple is asserted inside the callback before fixture bookkeeping.
		w, raw, prior := rfFixture(t)
		evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageCommitUnreadable, 6, ssqMust(mdbx.HeightKey(2, 2)), func() {
			out := w.refill(raw)
			retainWant(t, "RF missing-link absence captured/equality rejected", out, retainCleared, "", retainNA, mdbx.CommitTruthUnknown, crossed, false)
		})
		if err != nil || evidence.Commits != 1 || evidence.BeginWrite != 1 {
			t.Fatalf("H5-tip-RF fixture site %v (%+v)", err, evidence)
		}
		w.expectRefilled(raw, prior, 3, w.side[1], ssqWork(3))
		w.wantN1Image("RF independently checked committed image", raw)
	})
	for _, c := range []struct {
		name string
		code int
		kind mdbx.EngineClass
		scen mdbx.SelectedDamageScenario
	}{{"H8a-RF-begin-txnfull", -30_788, mdbx.EngineTransaction, mdbx.SelectedDamageBeginTxnFull}, {"H8a-RF-begin-eio", 5, mdbx.EngineIO, mdbx.SelectedDamageBeginEIO}} {
		t.Run(c.name, func(t *testing.T) {
			w, raw, _ := rfFixture(t)
			out, evidence := armedRefill(w, c.scen, 0, nil, raw)
			retainWant(t, "no-callback native begin keeps empty fields", out, "", "", "", old, mdbx.UpdateStagePrewrite, false)
			ssqWantNative(t, c.name, out.Err, ssqNative{"update", c.kind, c.code})
			if evidence.BeginOld != 1 || evidence.OldGets != [8]uint64{} {
				t.Fatalf("RF begin evidence %+v", evidence)
			}
			w.wantImage("RF begin failure")
		})
	}
	t.Run("H8a-RF-get-link", func(t *testing.T) {
		// The missing-height SideLink Get faults transiently: branch_data, exact native cause, no write.
		w, raw, _ := rfFixture(t)
		out, evidence := armedRefill(w, mdbx.SelectedDamageGetEIO, 6, ssqMust(mdbx.HeightKey(2, 2)), raw)
		retainWantRefusal(t, "RF missing-link transient branch_data", out, ssqBranch, "")
		ssqWantNative(t, "RF link GetEIO", out.Err, ssqGetEIO)
		if evidence.BeginWrite != 0 {
			t.Fatalf("RF link read wrote: %+v", evidence)
		}
		w.wantImage("RF link read fault")
	})
	t.Run("H8a-RF-getabort-link", func(t *testing.T) {
		w, raw, _ := rfFixture(t)
		first, _ := armedRefill(w, mdbx.SelectedDamageGetAbortEIO, 6, ssqMust(mdbx.HeightKey(2, 2)), raw)
		retainWantRefusal(t, "RF first typed result kept over abort IO", first, ssqBranch, "")
		ssqWantNative(t, "RF link Get+abort EIO", first.Err, ssqGetEIO, ssqAbortEIO)
		next := w.refill(raw)
		retainWant(t, "RF cached next call empty fields", next, "", "", "", old, mdbx.UpdateStagePrewrite, false)
		if !errors.Is(next.Err, first.Err) || !errors.Is(first.Err, next.Err) {
			t.Fatalf("RF cached raw error %v, want %v", next.Err, first.Err)
		}
		w.wantImage("RF link read and abort fault")
	})
	t.Run("H8a-RF-put", func(t *testing.T) {
		w, raw, _ := rfFixture(t)
		out, evidence := armedRefill(w, mdbx.SelectedDamagePutEIO, 6, ssqMust(mdbx.HeightKey(2, 2)), raw)
		retainWant(t, "definite precommit RF link write", out, retainPrecommit, "", "OLD", old, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, false)
		ssqWantNative(t, "RF put", out.Err, ssqNative{"update", mdbx.EngineIO, 5})
		if evidence.BeginWrite != 1 || evidence.Commits != 0 {
			t.Fatalf("RF put evidence %+v", evidence)
		}
		w.wantImage("RF precommit keeps OLD")
	})
	t.Run("H8-RF-lifetime", func(t *testing.T) {
		w, raw, prior := rfFixture(t)
		out, evidence := armedRefill(w, mdbx.SelectedDamageProbeOnly, 0, nil, raw)
		retainWant(t, "probed RF", out, retainStored, "", retainNA, mdbx.CommitTruthNew, crossed, true)
		if evidence.Probes == 0 || evidence.ProbeDenied != evidence.Probes || evidence.ProbeRan != 0 || evidence.BeginWrite != 1 || evidence.Commits != 1 || evidence.BeginRead != 0 {
			t.Fatalf("every native full-lane probe denied; grant released after return: %+v", evidence)
		}
		w.expectRefilled(raw, prior, 3, w.side[1], ssqWork(3))
		w.wantN1Image("probed RF image", raw)
	})
	t.Run("H10-RF-abortIO", func(t *testing.T) {
		// The first retained body positively absent: RF's locator (2,1441,3) with abort EIO is storage_io, no recheck.
		w, raw, _ := rfFixture(t)
		w.apply([]mdbx.Mutation{w.absentRow(4, w.sideKey(3))})
		out, evidence := armedRefill(w, mdbx.SelectedDamageAbortEIO, 0, nil, raw)
		retainWant(t, "storage_io/raw join/CLOSED/no recheck", out, retainStorageIO, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		var request *selectedSideDamageRequest
		if !errors.As(out.Err, &request) || *request != (selectedSideDamageRequest{Generation: 2, Tip: 1_441, Height: 3}) || evidence.BeginOld != 1 || evidence.BeginRead != 0 {
			t.Fatalf("RF locator abort %+v (%+v)", out, evidence)
		}
		w.wantImage("RF side kept without recheck")
	})
	t.Run("H10-RF-positive", func(t *testing.T) {
		// The same locator rechecked: the complete positive clear terminates with its whole tuple.
		w, raw, _ := rfFixture(t)
		w.apply([]mdbx.Mutation{w.absentRow(4, w.sideKey(3))})
		out, evidence := armedRefill(w, mdbx.SelectedDamageProbeOnly, 0, nil, raw)
		retainWant(t, "complete recheck NEW/raw/error image tuple", out, retainCleared, "", retainNA, mdbx.CommitTruthNew, crossed, true)
		if evidence.BeginOld != 1 || evidence.BeginWrite != 1 || evidence.Commits != 1 {
			t.Fatalf("RF recheck write evidence %+v", evidence)
		}
		w.wantCleared("RF positive recheck clear", 3, 1_441)
	})
	t.Run("H12-RF-capacity-abortIO", func(t *testing.T) {
		// RF's 3n+L capacity refusal is a non-read sentinel exit: abort EIO maps storage_io, no clean Result/Decision.
		probe, _, _ := rfFixture(t)
		l := len(probe.rows[string(append([]byte{4}, probe.sideKey(3)...))].value)
		n := (140_965_583-l)/3 + 1
		w, raw := rfWorld(t, 2, 0, 3, 113, func(w *ssqWorld, prev [32]byte) []byte { return retainLarge(t, prev, w.ts(prev)+120, n) })
		out, _ := armedRefill(w, mdbx.SelectedDamageAbortEIO, 0, nil, raw)
		retainWant(t, "RF capacity sentinel abort storage_io", out, retainStorageIO, "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		ssqWantNative(t, "RF capacity sentinel abort", out.Err, ssqAbortEIO)
		// The abort consumed the Store: the next RF is answered from its cached raw error with empty invocation fields,
		// no callback, retry or write; the image is read after the helper's reopen.
		next := w.refill(raw)
		retainWant(t, "RF cached next call empty fields", next, "", "", "", old, mdbx.UpdateStagePrewrite, false)
		if !errors.Is(next.Err, out.Err) || !errors.Is(out.Err, next.Err) {
			t.Fatalf("RF cached raw error %v, want %v", next.Err, out.Err)
		}
		w.wantImage("RF capacity abort keeps OLD")
	})
	// H12 RF typed refusals + abort EIO at the real Refill: the first typed result (domain branch_data on a full side;
	// steps-1-12 CONSENSUS_INVALID for a wrong-merkle candidate whose physical first header names it) survives the
	// nonterminal abort with the ordered raw join; no clean decision, no write.
	t.Run("H12-RF-typed-abortIO", func(t *testing.T) {
		w, full := rollFixtureWorld(t)
		out, evidence := armedRefill(w, mdbx.SelectedDamageAbortEIO, 0, nil, full)
		retainWantRefusal(t, "RF domain typed result kept over abort IO", out, ssqBranch, "selected side refill needs a cleaned one-slot side without a pending SIDE")
		ssqWantNative(t, "RF domain abort", out.Err, ssqAbortEIO)
		if evidence.BeginWrite != 0 || evidence.Commits != 0 {
			t.Fatalf("RF domain abort wrote: %+v", evidence)
		}
		w.wantImage("RF domain abort keeps OLD")
		w, raw := rfWorld(t, 2, 0, 3, 113, func(w *ssqWorld, prev [32]byte) []byte {
			return retainMerkle(w.childAt(prev, w.ts(prev)+120, consensus.POW_LIMIT, nil))
		})
		out, evidence = armedRefill(w, mdbx.SelectedDamageAbortEIO, 0, nil, raw)
		retainWant(t, "RF steps typed result kept over abort IO", out, "CONSENSUS_INVALID("+string(consensus.BLOCK_ERR_MERKLE_INVALID)+")", "", "OLD", old, mdbx.UpdateStagePrewrite, false)
		ssqWantNative(t, "RF steps abort", out.Err, ssqAbortEIO)
		if evidence.BeginWrite != 0 || evidence.Commits != 0 {
			t.Fatalf("RF steps abort wrote: %+v", evidence)
		}
		w.wantImage("RF steps abort keeps OLD")
	})
	t.Run("R-h-link-width", func(t *testing.T) {
		// A malformed-width SideLink(2,2) (ordinary Update grammar cannot write it; FixtureSeedRawRow seeds the exact
		// bytes): Reader.Get records the width integrity failure, so RF is canonical integrity with that exact raw cause,
		// no write/commit, and the recorded failure consumes the Store (applyReadAbort with infrastructure): the next RF
		// returns the cached error with empty fields; the damaged image is read after reopen.
		w, raw, _ := rfFixture(t)
		key := ssqMust(mdbx.HeightKey(2, 2))
		w.seed(6, key, []byte{0x01, 0x02, 0x03})
		out, evidence := armedRefill(w, mdbx.SelectedDamageProbeOnly, 0, nil, raw)
		retainWantIntegrity(t, "malformed missing-height link canonical integrity", out, "stored value width outside SchemaV2 bound")
		if evidence.BeginWrite != 0 || evidence.Commits != 0 {
			t.Fatalf("malformed link wrote: %+v", evidence)
		}
		next := w.refill(raw)
		retainWant(t, "RF cached next call after recorded integrity", next, "", "", "", old, mdbx.UpdateStagePrewrite, false)
		if !errors.Is(next.Err, out.Err) || !errors.Is(out.Err, next.Err) {
			t.Fatalf("RF cached raw error %v, want %v", next.Err, out.Err)
		}
		w.wantImage("malformed link image after reopen")
		w.wantAbsent("no candidate body", 4, w.sideKey(2))
	})
	// LF[H11-union]: the exact composed identity union of the real Prepare is admitted at 16384 (authority the only
	// target) and refused at 16385 (authority plus the unowned tip header) before any callback Batch or native OLD.
	t.Run("H11-union-16384", func(t *testing.T) {
		w, raw := rollUnionWorld(t, false)
		out, evidence := w.armedPrepareAt(mdbx.SelectedDamageProbeOnly, 0, nil, raw, w.tipAt(30_000))
		retainWant(t, "accepted 16384 exact positive clear", out, retainCleared, "", retainNA, mdbx.CommitTruthNew, crossed, true)
		if evidence.BeginWrite != 1 || evidence.Commits != 1 || evidence.ProbeRan != 0 || evidence.ProbeDenied != evidence.Probes {
			t.Fatalf("16384 union commit evidence %+v", evidence)
		}
		kept := make([]uint64, 0, 1_440)
		for j := uint64(8_640); j <= 10_079; j++ {
			kept = append(kept, j)
		}
		w.wantCleared("16384 complete clear keeps every owned header", 8_640, 10_079, kept...)
		w.reopen()
		w.wantImage("16384 persisted image after reopen")
	})
	t.Run("H11-union-16385", func(t *testing.T) {
		w, raw := rollUnionWorld(t, true)
		out, evidence := w.armedPrepareAt(mdbx.SelectedDamageProbeOnly, 0, nil, raw, w.tipAt(30_000))
		retainWantRefusal(t, "branch_data before callback Batch/native OLD", out, ssqBranch, "selected side rolling union exceeds its identity bound")
		if evidence.BeginWrite != 0 || evidence.Commits != 0 || evidence.Deletes != 0 || evidence.BeginOld != 1 || evidence.ProbeRan != 0 {
			t.Fatalf("16385 union refusal evidence %+v", evidence)
		}
		w.wantImage("16385 refusal keeps the damaged OLD image")
		w.wantAbsent("16385 oldest body still absent", 4, w.sideKey(8_640))
		w.reopen()
		w.wantImage("16385 persisted image after reopen")
	})
}
