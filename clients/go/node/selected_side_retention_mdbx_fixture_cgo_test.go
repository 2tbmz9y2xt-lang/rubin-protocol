//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// newRetainFixtureWorld compares committed rows natively, so a consumed or seeded image is observed without Reader.Get.
func newRetainFixtureWorld(t *testing.T, spec ssqSpec) *ssqWorld {
	t.Helper()
	w := newRetainWorld(t, spec)
	w.rawEqual = func(rank uint8, key, want []byte) (bool, error) {
		return mdbx.FixtureRawRowEqual(w.store, rank, key, want)
	}
	return w
}

// armed invokes the real entrypoint exactly once, through retain, under one armed native scenario; a site not reached as
// armed fails. retain's input and lane checks are Go-only reservation and byte checks, so they add no native Get.
func (w *ssqWorld) armed(scenario mdbx.SelectedDamageScenario, rank uint8, key, raw []byte, tip *mdbx.AuthorityPointV1) (SelectedSideMutationOutcome, mdbx.SelectedDamageEvidence) {
	w.t.Helper()
	var out SelectedSideMutationOutcome
	calls := 0
	evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() {
		calls++
		out = w.retain(raw, tip)
	})
	if err != nil || calls != 1 {
		w.t.Fatalf("scenario %d: %v (%+v)", scenario, err, evidence)
	}
	return out, evidence
}

// exhaust commits next_generation_id=maxuint64 over the tracked authority, leaving every other byte unchanged.
func (w *ssqWorld) exhaust() {
	w.t.Helper()
	a, err := mdbx.DecodeStorageAuthorityV1(w.rows[string([]byte{0, 2})].value)
	if err != nil {
		w.t.Fatalf("authority decode: %v", err)
	}
	a.NextGenerationID = math.MaxUint64
	w.apply([]mdbx.Mutation{w.authorityMutation(a)})
}

func TestSelectedSideRetentionFixture(t *testing.T) {
	old, pre, crossed := mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, mdbx.UpdateStageCommitMayHaveCrossed
	n1 := func(t *testing.T) (*ssqWorld, []byte, mdbx.StorageAuthorityV1) {
		w := newRetainFixtureWorld(t, ssqSpec{tip: 10, authority: func(a *mdbx.StorageAuthorityV1) { a.NextGenerationID = 2 }})
		return w, w.child(w.canonical[5], 6, nil), w.authorityValue()
	}
	u64 := func(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }
	at := func(base []byte, offset int, value []byte) []byte {
		out := bytes.Clone(base)
		copy(out[offset:], value)
		return out
	}
	t.Run("H1", func(t *testing.T) {
		// One-slot side 2..1440 (F0, C1440, count 1439) with its header-only history row 1. NONE encoding: selected
		// generation 39, F 47, tip 55, work 95, count 135; PRUNE_GC one-span encoding: span generation 38, first 46,
		// last 54, next 62, selected count 169 (authority_encode.go field order).
		w := newRetainFixtureWorld(t, ssqSpec{tip: 2, work: retainHeavy(2)})
		w.retainSide(0, 1_440, 1_439, 1_441, true)
		legal := w.rows[string([]byte{0, 2})].value
		prepared, err := mdbx.DecodeStorageAuthorityV1(legal)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		prepared.Phase = mdbx.StoragePhasePruneGCV1
		prepared.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanSideV1, GenerationID: 2, FirstHeight: 1, LastHeight: 1, NextHeight: 1}}}
		withSpan, err := prepared.Encode()
		if err != nil {
			t.Fatalf("prepared encode: %v", err)
		}
		raws := [][]byte{w.child(w.side[1_440], 1_441, nil), make([]byte, mdbx.MaxBlockBytes+1)}
		for _, c := range []struct {
			name  string
			value []byte
		}{
			{"C>=1440 count 1438", at(legal, 135, []byte{0x05, 0x9e})},
			{"tip <= F", at(legal, 47, u64(1_440))},
			{"tip height outside domain", at(legal, 55, u64(1<<32))},
			{"work outside domain", at(legal, 98, []byte{2})},
			{"illegal full+SIDE", at(withSpan, 169, []byte{0x05, 0xa0})},
			{"SIDE gap", at(at(at(withSpan, 46, u64(0)), 54, u64(0)), 62, u64(0))},
			{"SIDE overlapping selected rows", at(withSpan, 54, u64(2))},
			{"SIDE different generation", at(withSpan, 38, u64(3))},
			{"SIDE wider span", at(at(withSpan, 46, u64(0)), 62, u64(0))},
			{"SIDE displaced", at(at(at(withSpan, 46, u64(3)), 54, u64(3)), 62, u64(3))},
		} {
			w.seed(0, []byte{2}, c.value)
			for _, raw := range raws {
				out, evidence := w.armed(mdbx.SelectedDamageProbeOnly, 0, nil, raw, nil)
				retainWantIntegrity(t, c.name+": recorded malformed authority before optional read", out, "invalid storage authority")
				ssqWantGets(t, c.name, evidence, [8]uint64{1})
				w.reopen()
			}
		}
	})
	t.Run("H5", func(t *testing.T) {
		// M46: the relied-on candidate-owner absence (and the absent next-height tip boundary) must be in the final
		// Consulted union. A Get EIO armed on exactly that key fires only in the readback transaction (scenario 9) after
		// the commit's injected ENOSPC, so a compared row turns the committed image UNKNOWN; an omitted row leaves raw NEW.
		// The tuple is asserted inside the callback, before the fixture's fault-count bookkeeping, and before the
		// baseline Get counts below, which an omitted row would also change.
		for _, c := range []struct {
			name string
			rank uint8
		}{{"candidate owner absence", 7}, {"absent next-height tip boundary", 2}} {
			w, raw, prior := n1(t)
			key := ssqMust(mdbx.HeightKey(1, 11))
			if c.rank == 7 {
				key = ssqMust(mdbx.CanonicalOwnerKey(1, ssqHash(raw)))
			}
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageCommitUnreadable, c.rank, key, func() {
				out := w.retain(raw, w.tipAt(10))
				var commit *mdbx.CommitError
				if out.Result != retainCleared || out.Decision != "" || out.CanonicalTruth != retainNA || out.Truth != mdbx.CommitTruthUnknown || out.Stage != crossed ||
					!errors.As(out.Err, &commit) || commit.Truth != mdbx.CommitTruthUnknown {
					t.Fatalf("required native OLD/Consulted observation captured and equality rejected: %s %+v", c.name, out)
				}
				ssqWantNative(t, c.name+": primary commit ENOSPC", commit.Cause, ssqNative{"update", mdbx.EngineCapacity, 28})
				ssqWantNative(t, c.name+": readback get EIO", commit.ReadbackCause, ssqNative{"update", mdbx.EngineIO, 5})
			})
			if err != nil || evidence.Faults != 2 || evidence.Commits != 1 || evidence.BeginWrite != 1 || evidence.BeginRead != 1 {
				t.Fatalf("%s: fixture site %v (%+v)", c.name, err, evidence)
			}
			// The fixture commits before the failed readback; UNKNOWN itself proves no image, so NEW is checked independently.
			w.expectN1(raw, prior, 2, 5, ssqWork(7))
			w.wantN1Image(c.name+": independently checked committed NEW image", raw)
		}
		w, raw, prior := n1(t)
		out, evidence := w.armed(mdbx.SelectedDamageCommitNew, 0, nil, raw, w.tipAt(10))
		retainWant(t, "equality NEW with commit error", out, "", "", retainNA, mdbx.CommitTruthNew, crossed, false)
		// OLD Gets: callback 1/0/2/7/1/0/0/2, Consulted capture 0/0/3/6/0/0/0/2, target images and readback recapture
		// 2x 1/0/0/1/1/0/1/0. Readback: 4 targets twice plus the 11 relied-on rows (forward 5, 10, 11; headers 0..5;
		// owners of 5 and of the candidate NONE) once.
		if evidence.OldGets != [8]uint64{3, 0, 5, 15, 3, 0, 2, 4} || evidence.ReadGets != 19 {
			t.Fatalf("required native OLD/Consulted observation captured: %+v", evidence)
		}
		w.expectN1(raw, prior, 2, 5, ssqWork(7))
		w.wantN1Image("equality NEW image", raw)
	})
	t.Run("H5-tip", func(t *testing.T) {
		w, raw, prior := n1(t)
		tip := [32]byte{0x58}
		w.apply([]mdbx.Mutation{
			w.literal(2, ssqMust(mdbx.HeightKey(1, 0xffffffff)), mdbx.ChainValue(tip, w.canonical[10], ssqWork(1<<40)), false),
			w.literal(7, ssqMust(mdbx.CanonicalOwnerKey(1, tip)), mdbx.CanonicalOwnerValue(0xffffffff), false),
		})
		out, evidence := w.armed(mdbx.SelectedDamageCommitNew, 0, nil, raw, &mdbx.AuthorityPointV1{Height: 0xffffffff, BlockHash: tip})
		retainWant(t, "tip 0xffffffff equality NEW", out, "", "", retainNA, mdbx.CommitTruthNew, crossed, false)
		if evidence.OldGets != [8]uint64{3, 0, 5, 15, 3, 0, 2, 4} || evidence.ReadGets != 19 {
			t.Fatalf("tip boundary image present/equality protection: %+v", evidence)
		}
		w.expectN1(raw, prior, 2, 5, ssqWork(7))
		w.wantN1Image("tip boundary N1 image", raw)
	})
	t.Run("R-tip-suffix", func(t *testing.T) {
		// The tip entry (1,10) is healthy, but the stored suffix row (1,11) is 103 bytes: the suffix page's own stored-row
		// check fails with prefix-page Integrity (codeInvalid = MDBX_INVALID -30793 in the pinned mdbx.h), recorded on the
		// Reader, before any stale decision. A healthy suffix row would instead be STALE_LOCAL_PLAN (R-tip-stale-height).
		w, raw, _ := n1(t)
		w.seed(2, ssqMust(mdbx.HeightKey(1, 11)), mdbx.ChainValue([32]byte{0x11}, w.canonical[10], ssqWork(12))[:103])
		out := w.retain(raw, w.tipAt(10))
		retainWantRefusal(t, "suffix page integrity before stale", out, ssqIntegrity, "")
		var failure *selectedSideQualificationError
		errors.As(out.Err, &failure)
		engine, ok := failure.Cause.(*mdbx.EngineError) //nolint:errorlint // The classified wrapper's own direct cause.
		if !ok || engine.Class != mdbx.EngineIntegrity || engine.Operation != "prefix-page" || engine.Code != -30_793 || engine.Diagnostic != "stored value width outside SchemaV2 bound" {
			t.Fatalf("suffix page cause %v", failure.Cause)
		}
		// The qualifier's cause and the Reader's recorded failure are one EngineError: exactly one distinct native cause.
		ssqWantNative(t, "suffix page integrity", out.Err, ssqNative{"prefix-page", mdbx.EngineIntegrity, -30_793})
		// The recorded Reader failure consumed the Store: the next invocation is the cached tuple with empty fields.
		next := w.retain(raw, w.tipAt(10))
		retainWant(t, "consumed Store cached tuple", next, "", "", "", old, pre, false)
		if next.Err != out.Err { //nolint:errorlint // A consumed Store returns its exact terminal error.
			t.Fatalf("cached error %v, want %v", next.Err, out.Err)
		}
		w.wantImage("seeded suffix row and image unchanged")
	})
	t.Run("R-kc5", func(t *testing.T) {
		// A byte-identical expected row is consulted, not a target. NF[H5] OLD Gets are callback 1/0/2/7/1/0/0/2, Consulted
		// capture 0/0/3/6/0/0/0/2 and target image plus readback recapture 2x 1/0/0/1/1/0/1/0; each reused row moves one
		// Get from the two target passes to the capture. Readback: header 3 targets twice+12 rows, body 3x2+12, both 2x2+13.
		for _, c := range []struct {
			name  string
			ranks []uint8
			gets  [8]uint64
			reads uint64
		}{
			{"header", []uint8{3}, [8]uint64{3, 0, 5, 14, 3, 0, 2, 4}, 18},
			{"body", []uint8{4}, [8]uint64{3, 0, 5, 15, 2, 0, 2, 4}, 18},
			{"header+body", []uint8{3, 4}, [8]uint64{3, 0, 5, 14, 2, 0, 2, 4}, 17},
		} {
			w, raw, prior := n1(t)
			hash := ssqHash(raw)
			present := map[uint8][]byte{3: raw[:consensus.BLOCK_HEADER_BYTES], 4: raw}
			var reused []mdbx.Mutation
			for _, rank := range c.ranks {
				reused = append(reused, w.literal(rank, bytes.Clone(hash[:]), bytes.Clone(present[rank]), false))
			}
			w.apply(reused)
			out, evidence := w.armed(mdbx.SelectedDamageCommitNew, 0, nil, raw, w.tipAt(10))
			retainWant(t, c.name+" reused equality NEW", out, "", "", retainNA, mdbx.CommitTruthNew, crossed, false)
			if evidence.OldGets != c.gets || evidence.ReadGets != c.reads {
				t.Fatalf("candidate owner absence captured/exact image comparison: %s %+v", c.name, evidence)
			}
			w.expectN1(raw, prior, 2, 5, ssqWork(7))
			w.wantN1Image(c.name+" reused N1 image", raw)
		}
	})
	t.Run("H11-third", func(t *testing.T) {
		// One n=46988528 construction over sequential valid pre-states. 3n+7223040+6422528 = 154611152 = G+1, so only the
		// charged third candidate image refuses step 10, after the full qualification and before any expected-row read.
		// H4d: the same length/header with a step-5 merkle failure wins before that execution capacity, and an exhausted
		// sequence wins before it too.
		w, _, _ := n1(t)
		raw := retainLarge(t, w.canonical[5], w.ts(w.canonical[5])+120, 46_988_528)
		w.absent = append(w.absent, ssqHash(raw))
		out, evidence := w.armed(mdbx.SelectedDamageProbeOnly, 0, nil, raw, w.tipAt(10))
		retainWant(t, "charged third image bound/refusal", out, retainCapacity, "", "OLD", old, pre, true)
		if evidence.BeginOld != 1 || evidence.OldAborts != 1 || evidence.BeginWrite != 0 || evidence.Commits != 0 || evidence.BeginRead != 0 {
			t.Fatalf("charged third image bound/refusal: no write %+v", evidence)
		}
		w.wantImage("step-10 refusal before any expected-row read")
		merkle := retainMerkle(raw)
		if len(merkle) != len(raw) || !bytes.Equal(merkle[:consensus.BLOCK_HEADER_BYTES], raw[:consensus.BLOCK_HEADER_BYTES]) || bytes.Equal(merkle, raw) {
			t.Fatal("merkle variant must keep the length and header and change only the body")
		}
		retainWantConsensus(t, "established candidate error before execution capacity", w.retain(merkle, w.tipAt(10)), consensus.BLOCK_ERR_MERKLE_INVALID)
		w.wantImage("merkle variant writes nothing")
		w.exhaust()
		retainWant(t, "exhausted sequence before step-10 capacity", w.retain(raw, w.tipAt(10)), retainInvariant, "", "OLD", old, pre, false)
		w.wantImage("exhausted sequence allocates nothing")
	})
	t.Run("H8-lifetime", func(t *testing.T) {
		w, raw, prior := n1(t)
		out, evidence := w.armed(mdbx.SelectedDamageProbeOnly, 0, nil, raw, w.tipAt(10))
		retainWant(t, "probed N1", out, retainStored, "", retainNA, mdbx.CommitTruthNew, crossed, true)
		// Probes at write begin, commit and twice around the OLD abort: all inside the grant.
		if evidence.Probes != 4 || evidence.ProbeDenied != 4 || evidence.ProbeRan != 0 || evidence.BeginWrite != 1 || evidence.Commits != 1 || evidence.BeginRead != 0 ||
			evidence.OldGets != [8]uint64{2, 0, 5, 14, 2, 0, 1, 4} {
			t.Fatalf("every native full-lane probe denied; grant released after return: %+v", evidence)
		}
		w.expectN1(raw, prior, 2, 5, ssqWork(7))
		w.wantN1Image("probed N1 image", raw)
	})
	for _, c := range []struct {
		name string
		code int
		kind mdbx.EngineClass
		scen mdbx.SelectedDamageScenario
	}{{"H8a-begin-txnfull", -30_788, mdbx.EngineTransaction, mdbx.SelectedDamageBeginTxnFull}, {"H8a-begin-eio", 5, mdbx.EngineIO, mdbx.SelectedDamageBeginEIO}} {
		t.Run(c.name, func(t *testing.T) {
			w, raw, _ := n1(t)
			out, evidence := w.armed(c.scen, 0, nil, raw, w.tipAt(10))
			retainWant(t, "no-callback native begin keeps empty fields", out, "", "", "", old, pre, false)
			ssqWantNative(t, c.name, out.Err, ssqNative{"update", c.kind, c.code})
			if evidence.BeginOld != 1 || evidence.OldGets != [8]uint64{} {
				t.Fatalf("begin evidence %+v", evidence)
			}
			w.wantImage("begin failure")
		})
	}
	t.Run("H8a-get-tip", func(t *testing.T) {
		w, raw, _ := n1(t)
		out, _ := w.armed(mdbx.SelectedDamageGetEIO, 2, ssqMust(mdbx.HeightKey(1, 10)), raw, w.tipAt(10))
		retainWantRefusal(t, "tip read canonical_artifact_read", out, ssqCanonical, "")
		ssqWantNative(t, "tip GetEIO", out.Err, ssqGetEIO)
		w.wantImage("tip read fault")
	})
	t.Run("H8a-getabort-tip", func(t *testing.T) {
		w, raw, _ := n1(t)
		out, _ := w.armed(mdbx.SelectedDamageGetAbortEIO, 2, ssqMust(mdbx.HeightKey(1, 10)), raw, w.tipAt(10))
		retainWantRefusal(t, "first typed result kept over abort IO", out, ssqCanonical, "")
		ssqWantNative(t, "tip Get+abort EIO", out.Err, ssqGetEIO, ssqAbortEIO)
		w.wantImage("tip read and abort fault")
	})
	t.Run("H8a-delete", func(t *testing.T) {
		// N1's Batch has no delete; the Retain invocation's definite delete is the fresh positive-damage Recheck. The first
		// attempt locates the absent optional body 6 and releases; the recheck's complete clear deletes only the unkept
		// side header 6, and DeleteEIO fails that delete before commit.
		w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
		w.retainSide(5, 6, 1, 7, false)
		tip := w.side[6]
		w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(tip[:]))})
		out, evidence := w.armed(mdbx.SelectedDamageDeleteEIO, 0, nil, w.child(tip, 7, nil), w.tipAt(10))
		retainWant(t, "definite precommit write", out, retainPrecommit, "", "OLD", old, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, false)
		ssqWantNative(t, "H8a-delete", out.Err, ssqNative{"update", mdbx.EngineIO, 5})
		// First attempt: the OLD read and its abort. Recheck: one later read-only begin, one write begin, one faulted
		// delete, no commit and so no readback. The fixture keeps the first OLD transaction pointer until disarm, so the
		// recheck's separate read-only transaction may reuse that address and count its abort as an OLD abort too:
		// A is 1..2, and each counted abort adds two probes to the recheck's read-begin and write-begin probes.
		if evidence.BeginOld != 1 || evidence.BeginRead != 1 || evidence.BeginWrite != 1 || evidence.Deletes != 1 || evidence.Commits != 0 || evidence.Faults != 1 ||
			evidence.OldAborts < 1 || evidence.OldAborts > 2 || evidence.Probes != 2+2*evidence.OldAborts || evidence.ProbeDenied != evidence.Probes || evidence.ProbeRan != 0 {
			t.Fatalf("H8a-delete evidence %+v", evidence)
		}
		w.wantImage("precommit keeps OLD")
	})
	t.Run("H8a-put", func(t *testing.T) {
		w, raw, _ := n1(t)
		out, evidence := w.armed(mdbx.SelectedDamagePutEIO, 6, ssqMust(mdbx.HeightKey(2, 6)), raw, w.tipAt(10))
		retainWant(t, "definite precommit write", out, retainPrecommit, "", "OLD", old, mdbx.UpdateStageWriteStartedDefinitelyPrecommit, false)
		ssqWantNative(t, "H8a-put", out.Err, ssqNative{"update", mdbx.EngineIO, 5})
		if evidence.BeginWrite != 1 || evidence.Commits != 0 || evidence.BeginRead != 0 {
			t.Fatalf("H8a-put evidence %+v", evidence)
		}
		w.wantImage("precommit keeps OLD")
	})
	t.Run("H6b-NEW", func(t *testing.T) {
		w, raw, prior := n1(t)
		out, evidence := w.armed(mdbx.SelectedDamageCommitNew, 0, nil, raw, w.tipAt(10))
		retainWant(t, "proved NEW/raw causes retained/NOT_APPLICABLE empty Result", out, "", "", retainNA, mdbx.CommitTruthNew, crossed, false)
		var commit *mdbx.CommitError
		if !errors.As(out.Err, &commit) || commit.Truth != mdbx.CommitTruthNew || evidence.Commits != 1 {
			t.Fatalf("equality NEW error %v (%+v)", out.Err, evidence)
		}
		ssqWantNative(t, "commit ENOSPC", commit.Cause, ssqNative{"update", mdbx.EngineCapacity, 28})
		w.expectN1(raw, prior, 2, 5, ssqWork(7))
		w.wantN1Image("equality NEW image", raw)
	})
	t.Run("H6b-OLD", func(t *testing.T) {
		w, raw, _ := n1(t)
		out, _ := w.armed(mdbx.SelectedDamageCommitOld, 0, nil, raw, w.tipAt(10))
		retainWant(t, "equality OLD empty Result", out, "", "", retainNA, old, crossed, false)
		w.wantImage("equality OLD image")
	})
	for _, c := range []struct {
		name string
		scen mdbx.SelectedDamageScenario
		key  []byte
	}{{"H6a-N1", mdbx.SelectedDamageCommitUnreadable, []byte{2}}, {"H6a-third", mdbx.SelectedDamageCommitThird, nil}} {
		t.Run(c.name, func(t *testing.T) {
			w, raw, _ := n1(t)
			out, _ := w.armed(c.scen, 0, c.key, raw, w.tipAt(10))
			retainWant(t, "noncanonical/NOT_APPLICABLE with exact raw UNKNOWN", out, retainCleared, "", retainNA, mdbx.CommitTruthUnknown, crossed, false)
		})
	}
	t.Run("H12-sentinel", func(t *testing.T) {
		w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
		raw := w.child(w.canonical[10], 11, nil)
		out, evidence := w.armed(mdbx.SelectedDamageAbortEIO, 0, nil, raw, w.tipAt(10))
		// The clean decision here would be ORDINARY with a nil Err; the joined abort cause must keep it unemitted.
		if out.Err == nil || out.Decision != "" || out.Result == "" {
			t.Fatalf("cleanup error retained/no clean Result or Decision: %+v", out)
		}
		retainWant(t, "joined abort IO storage_io/raw ordered join/CLOSED", out, retainStorageIO, "", "OLD", old, pre, false)
		ssqWantNative(t, "sentinel abort", out.Err, ssqAbortEIO)
		if evidence.OldAborts != 1 || evidence.BeginWrite != 0 {
			t.Fatalf("sentinel abort evidence %+v", evidence)
		}
		w.wantImage("sentinel abort")
	})
	t.Run("H8-cache", func(t *testing.T) {
		// The sentinel plus abort EIO consumes the Store (CLOSED). The next invocation is answered from the cached terminal
		// tuple before any callback: empty invocation fields, the first raw error itself, OLD/Prewrite, the grant released.
		w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
		raw := w.child(w.canonical[10], 11, nil)
		first, _ := w.armed(mdbx.SelectedDamageAbortEIO, 0, nil, raw, w.tipAt(10))
		retainWant(t, "consuming first tuple", first, retainStorageIO, "", "OLD", old, pre, false)
		next := w.retain(raw, w.tipAt(10))
		retainWant(t, "empty invocation fields/raw cached tuple", next, "", "", "", old, pre, false)
		if next.Err != first.Err { //nolint:errorlint // A consumed Store returns its exact terminal error.
			t.Fatalf("empty invocation fields/raw cached tuple: error %v, want %v", next.Err, first.Err)
		}
		w.wantImage("cached next call persisted image")
	})
	t.Run("H12-terminal", func(t *testing.T) {
		// Producer composition, not native machinery: this attempt binds its own typed branch_data result, then a stronger
		// cleanup cause follows in the same raw join. Terminal integrity and the outer THREAD invariant override the first
		// typed result; projection keeps the raw join's identity and its cause order.
		for _, c := range []struct {
			name, want string
			cleanup    error
		}{
			{"stronger canonical exact result", ssqIntegrity, &mdbx.EngineError{Class: mdbx.EngineIntegrity, Operation: "abort", Code: -30_796}},
			{"outer invariant wins", retainInvariant, &mdbx.EngineError{Class: mdbx.EngineLocalInvariant, Operation: "abort", Code: -30_416}},
		} {
			leaf := &selectedSideQualificationError{Result: ssqBranch, Cause: errors.New("bound")}
			a := &selectedRetainAttempt{ran: true, sentinel: errors.New("decision")}
			joined := errors.Join(a.bind(leaf), c.cleanup)
			out, request := a.project(SelectedSideMutationOutcome{Truth: old, Stage: pre, Err: joined})
			parts := joined.(interface{ Unwrap() []error }).Unwrap()                                                                                                       //nolint:errorlint // The exact raw join.
			if out.Result != c.want || out.Decision != "" || out.CanonicalTruth != "OLD" || out.Truth != old || out.Stage != pre || out.Err != joined || request != nil || //nolint:errorlint // Raw identity.
				len(parts) != 2 || parts[0] != error(leaf) || parts[1] != c.cleanup { //nolint:errorlint // Exact cause order.
				t.Fatalf("stronger canonical/invariant exact result/raw joined causes: %s projected %+v", c.name, out)
			}
		}
	})
	t.Run("R-kc4-io", func(t *testing.T) {
		w, raw, _ := n1(t)
		out, _ := w.armed(mdbx.SelectedDamageGetEIO, 7, ssqMust(mdbx.CanonicalOwnerKey(1, ssqHash(raw))), raw, w.tipAt(10))
		retainWantRefusal(t, "canonical_artifact_read/exact raw error/no write", out, ssqCanonical, "")
		ssqWantNative(t, "candidate owner GetEIO", out.Err, ssqGetEIO)
		w.wantImage("candidate owner read fault")
	})
	t.Run("R-kc4-malformed", func(t *testing.T) {
		const inconsistent = "canonical owner index inconsistency"
		var zeroWork [40]byte
		for _, c := range []struct {
			name, diagnostic string
			seed             func(w *ssqWorld, cand [32]byte)
		}{
			{"inverse width", "", func(w *ssqWorld, cand [32]byte) { w.seed(7, ssqMust(mdbx.CanonicalOwnerKey(1, cand)), make([]byte, 7)) }},
			{"missing forward", inconsistent, func(w *ssqWorld, cand [32]byte) {
				w.seed(7, ssqMust(mdbx.CanonicalOwnerKey(1, cand)), mdbx.CanonicalOwnerValue(99))
			}},
			{"conflicting forward", inconsistent, func(w *ssqWorld, cand [32]byte) {
				w.seed(7, ssqMust(mdbx.CanonicalOwnerKey(1, cand)), mdbx.CanonicalOwnerValue(6))
			}},
			{"forward work outside domain", inconsistent, func(w *ssqWorld, cand [32]byte) {
				w.seed(2, ssqMust(mdbx.HeightKey(1, 50)), mdbx.ChainValue(cand, w.canonical[5], zeroWork))
				w.seed(7, ssqMust(mdbx.CanonicalOwnerKey(1, cand)), mdbx.CanonicalOwnerValue(50))
			}},
			{"forward width", "", func(w *ssqWorld, cand [32]byte) {
				w.seed(2, ssqMust(mdbx.HeightKey(1, 50)), mdbx.ChainValue(cand, w.canonical[5], ssqWork(7))[:103])
				w.seed(7, ssqMust(mdbx.CanonicalOwnerKey(1, cand)), mdbx.CanonicalOwnerValue(50))
			}},
		} {
			w, raw, _ := n1(t)
			c.seed(w, ssqHash(raw))
			retainWantIntegrity(t, c.name+": never NONE or damage", w.retain(raw, w.tipAt(10)), c.diagnostic)
			w.wantImage(c.name)
		}
	})
	for _, c := range []struct {
		name      string
		tip, work uint64
		rows      uint16
		gets      [8]uint64
	}{{"R-k-first-one", 6, 7, 1, [8]uint64{1, 0, 2, 7, 1, 0, 1, 3}}, {"R-k-first-many", 8, 9, 3, [8]uint64{1, 0, 2, 8, 1, 0, 2, 3}}} {
		t.Run(c.name, func(t *testing.T) {
			// Count 1: no Get beyond the qualification's tip link; count > 1: one extra Get(g,F+1) and its header. One
			// body either way, no second validator/context walk, no Batch and so no native OLD capture.
			w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
			blocks := w.retainSide(5, c.tip, c.rows, c.work, false)
			out, evidence := w.armed(mdbx.SelectedDamageProbeOnly, 0, nil, blocks[6], w.tipAt(10))
			retainWant(t, "first-row stored-known", out, retainDuplicate, "", retainNA, old, pre, true)
			ssqWantGets(t, c.name+" exact reads", evidence, c.gets)
			if evidence.BeginWrite != 0 || evidence.OldAborts != 1 {
				t.Fatalf("%s: wrote or leaked OLD: %+v", c.name, evidence)
			}
			w.wantImage("first-row duplicate")
		})
	}
	t.Run("R-k-first-order", func(t *testing.T) {
		w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
		blocks := w.retainSide(5, 6, 1, 7, false)
		hash := w.side[6]
		w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(hash[:]))})
		out, evidence := w.armed(mdbx.SelectedDamageProbeOnly, 0, nil, retainMerkle(blocks[6]), w.tipAt(10))
		retainWantConsensus(t, "supplied failure prevents probe/body read", out, consensus.BLOCK_ERR_MERKLE_INVALID)
		ssqWantGets(t, "steps stop before selection and probe", evidence, [8]uint64{1, 0, 1, 6, 0, 0, 0, 1})
		w.wantImage("unobserved damaged body")
	})
	t.Run("R-k-first-link", func(t *testing.T) {
		linkKey := ssqMust(mdbx.HeightKey(2, 6))
		for _, c := range []string{"missing", "malformed"} {
			w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
			blocks := w.retainSide(5, 8, 3, 9, false)
			if c == "missing" {
				w.apply([]mdbx.Mutation{w.absentRow(6, linkKey)})
			} else {
				w.seed(6, linkKey, w.rows[string(append([]byte{6}, linkKey...))].value[:103])
			}
			retainWantIntegrity(t, c+" first required link integrity", w.retain(blocks[6], w.tipAt(10)), "")
			w.wantImage(c + " first link")
		}
		w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
		blocks := w.retainSide(5, 8, 3, 9, false)
		out, _ := w.armed(mdbx.SelectedDamageGetEIO, 6, linkKey, blocks[6], w.tipAt(10))
		retainWantRefusal(t, "transient first link branch_data", out, ssqBranch, "")
		ssqWantNative(t, "first link GetEIO", out.Err, ssqGetEIO)
	})
	t.Run("R-k-first-body-transient", func(t *testing.T) {
		w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
		blocks := w.retainSide(5, 8, 3, 9, false)
		hash := w.side[6]
		out, _ := w.armed(mdbx.SelectedDamageGetEIO, 4, bytes.Clone(hash[:]), blocks[6], w.tipAt(10))
		retainWantRefusal(t, "transient matched optional body branch_data", out, ssqBranch, "")
		ssqWantNative(t, "first body GetEIO", out.Err, ssqGetEIO)
		w.wantImage("first body transient")
	})
	t.Run("R-k-first-abortIO", func(t *testing.T) {
		w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
		blocks := w.retainSide(5, 6, 1, 7, false)
		hash := w.side[6]
		w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(hash[:]))})
		out, evidence := w.armed(mdbx.SelectedDamageAbortEIO, 0, nil, blocks[6], w.tipAt(10))
		retainWant(t, "locator+abortIO storage_io after cleared resource", out, retainStorageIO, "", "OLD", old, pre, false)
		var request *selectedSideDamageRequest
		if !errors.As(out.Err, &request) || *request != (selectedSideDamageRequest{Generation: 2, Tip: 6, Height: 6}) || evidence.BeginRead != 0 {
			t.Fatalf("first-row locator abort %+v (%+v)", out, evidence)
		}
		w.wantImage("first row kept without recheck")
	})
	t.Run("R-k-link-transient", func(t *testing.T) {
		w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
		blocks := w.retainSide(3, 8, 5, 9, false)
		out, _ := w.armed(mdbx.SelectedDamageGetEIO, 6, ssqMust(mdbx.HeightKey(2, 4)), blocks[8], w.tipAt(10))
		retainWantRefusal(t, "transient fallback link branch_data", out, ssqBranch, "")
		ssqWantNative(t, "fallback link GetEIO", out.Err, ssqGetEIO)
	})
	t.Run("R-k-owner", func(t *testing.T) {
		// The matched last row is canonically Owned at k=12: B<=k makes its body required, B>k optional.
		for _, b := range []uint64{0, 13} {
			w := newRetainFixtureWorld(t, ssqSpec{tip: 10, b: b})
			blocks := w.retainSide(3, 8, 5, 9, false)
			tip := w.side[8]
			w.own(tip, w.side[7], 12)
			w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(tip[:]))})
			out := w.retain(blocks[8], w.tipAt(10))
			if b == 0 {
				retainWantRefusal(t, "required owner-height body terminal", out, ssqIntegrity, "required canonical row is absent")
				w.wantImage("required body defect")
				continue
			}
			retainWant(t, "optional owner-height body locator then clear", out, retainCleared, "", retainNA, mdbx.CommitTruthNew, crossed, true)
			w.wantCleared("owned kept header", 4, 8, 8)
		}
	})
	t.Run("H7b-unowned", func(t *testing.T) {
		w, raw, _ := n1(t)
		hash := ssqHash(raw)
		w.apply([]mdbx.Mutation{w.literal(4, bytes.Clone(hash[:]), retainMerkle(raw), false)})
		w.absent = nil
		retainWantRefusal(t, "terminal/no differing overwrite", w.retain(raw, w.tipAt(10)), ssqIntegrity, "unowned expected selected side row differs from the candidate")
		w.wantImage("differing body kept")
		w.wantAbsent("candidate header not written", 3, bytes.Clone(hash[:]))
	})
	t.Run("R-l", func(t *testing.T) {
		// H4d: a denied full-lane charge ends in the control-only Update before any candidate read, so the capacity refusal
		// precedes an undiscovered step-5 merkle failure and an exhausted sequence alike (independent sequential pre-states).
		w, raw, _ := n1(t)
		for _, c := range []struct {
			name  string
			raw   []byte
			setup func()
		}{{"valid candidate", raw, nil}, {"undiscovered merkle failure", retainMerkle(raw), nil}, {"exhausted sequence", raw, w.exhaust}} {
			if c.setup != nil {
				c.setup()
			}
			var out SelectedSideMutationOutcome
			var evidence mdbx.SelectedDamageEvidence
			before, tip := bytes.Clone(c.raw), w.tipAt(10)
			locator := *tip
			held := w.owner.WithReservation(1, func() error {
				var err error
				evidence, err = mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() {
					out = RetainSelectedSideMDBX(w.store, w.owner, c.raw, tip)
				})
				return err
			})
			if held != nil {
				t.Fatalf("%s: aggregate hold: %v", c.name, held)
			}
			w.wantRaw(c.raw, before)
			if *tip != locator {
				t.Fatalf("%s: retention changed the caller's tip locator", c.name)
			}
			retainWant(t, "storage_capacity/OLD and no copy", out, retainCapacity, "", "OLD", old, pre, true)
			ssqWantGets(t, c.name+": control-only Update", evidence, [8]uint64{1})
			retainWantReleased(t, w.owner)
			w.wantImage(c.name + ": capacity denial")
		}
	})
	t.Run("H10-abortIO", func(t *testing.T) {
		w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
		w.retainSide(5, 6, 1, 7, false)
		tip := w.side[6]
		w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(tip[:]))})
		out, evidence := w.armed(mdbx.SelectedDamageAbortEIO, 0, nil, w.child(tip, 7, nil), w.tipAt(10))
		retainWant(t, "storage_io/raw join/CLOSED/no recheck", out, retainStorageIO, "", "OLD", old, pre, false)
		var request *selectedSideDamageRequest
		if !errors.As(out.Err, &request) || *request != (selectedSideDamageRequest{Generation: 2, Tip: 6, Height: 6}) || evidence.BeginOld != 1 || evidence.BeginRead != 0 {
			t.Fatalf("locator abort %+v (%+v)", out, evidence)
		}
		w.wantImage("side kept without recheck")
	})
	t.Run("H10-second", func(t *testing.T) {
		// Rows 6 and 7 stay healthy; tip 8 is replaced by a hash-bound block whose header, body and link name an
		// absent unowned Z, with descriptor hash and work equal to its link. The exact-tip child's ancestry asks for
		// row 7 by Z (locator 7); the fresh recheck of row 7 follows its physical healthy link; the one retry finds
		// the same unchanged image and its second locator is typed branch_data. No write happens anywhere.
		w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
		w.retainSide(5, 8, 3, 9, false)
		z := [32]byte{0x5a}
		w.headers[z] = w.headers[w.side[7]]
		tip := w.mined(z, 113)
		hash := ssqHash(tip)
		w.side[8] = hash
		a := w.authorityValue()
		a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 2, F: 5, TipHeight: 8, TipHash: hash, CumulativeChainwork: ssqWork(9), RowCount: 3, LogicalBytes: 3_000}
		w.apply([]mdbx.Mutation{
			w.literal(3, bytes.Clone(hash[:]), tip[:consensus.BLOCK_HEADER_BYTES], false), w.literal(4, bytes.Clone(hash[:]), tip, false),
			w.literal(6, ssqMust(mdbx.HeightKey(2, 8)), mdbx.ChainValue(hash, z, ssqWork(9)), true), w.authorityMutation(a),
		})
		delete(w.headers, z)
		raw := w.childAt(hash, w.ts(hash)+120, consensus.POW_LIMIT, nil)
		out, evidence := w.armed(mdbx.SelectedDamageProbeOnly, 0, nil, raw, w.tipAt(10))
		retainWantRefusal(t, "one retry/branch_data/operation counts", out, ssqBranch, "")
		var request *selectedSideDamageRequest
		if !errors.As(out.Err, &request) || *request != (selectedSideDamageRequest{Generation: 2, Tip: 8, Height: 7}) {
			t.Fatalf("second locator cause %v", out.Err)
		}
		// Three read-only Updates: the first attempt's OLD, then the recheck and the retry (counted as later read-only
		// begins); every probe is inside one of the three separately released grants. The fixture keeps the first OLD
		// transaction pointer until disarm, so a later read-only transaction reusing that address also counts its abort:
		// A is 1..3 and each counted abort adds two probes to the two read-begin probes, all denied.
		if evidence.BeginOld != 1 || evidence.BeginRead != 2 || evidence.BeginWrite != 0 || evidence.Deletes != 0 || evidence.Commits != 0 || evidence.Faults != 0 ||
			evidence.OldAborts < 1 || evidence.OldAborts > 3 || evidence.Probes != 2+2*evidence.OldAborts || evidence.ProbeDenied != evidence.Probes || evidence.ProbeRan != 0 {
			t.Fatalf("recheck between released grants/no nested operation: %+v", evidence)
		}
		w.wantImage("bounded retry left the image unchanged")
	})
	for _, c := range []struct {
		name  string
		scen  mdbx.SelectedDamageScenario
		truth mdbx.CommitTruth
	}{{"H10-positive-OLD", mdbx.SelectedDamageCommitOld, mdbx.CommitTruthOld}, {"H10-positive-NEW", mdbx.SelectedDamageCommitNew, mdbx.CommitTruthNew}, {"H10-positive-UNKNOWN", mdbx.SelectedDamageCommitThird, mdbx.CommitTruthUnknown}} {
		t.Run(c.name, func(t *testing.T) {
			w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
			w.retainSide(5, 6, 1, 7, false)
			tip := w.side[6]
			w.apply([]mdbx.Mutation{w.absentRow(4, bytes.Clone(tip[:]))})
			out, evidence := w.armed(c.scen, 0, nil, w.child(tip, 7, nil), w.tipAt(10))
			retainWant(t, "positive-damage clear keeps its all-outcome exception", out, retainCleared, "", retainNA, c.truth, crossed, false)
			if evidence.BeginWrite != 1 || evidence.Commits != 1 {
				t.Fatalf("recheck write evidence %+v", evidence)
			}
			switch c.truth {
			case mdbx.CommitTruthOld:
				w.wantImage("crossed OLD recheck image")
			case mdbx.CommitTruthNew:
				w.wantCleared("crossed NEW recheck image", 6, 6)
			}
		})
	}
	t.Run("owner-input-oversize", func(t *testing.T) {
		// A nil or zero owner with an oversized candidate on an open Store returns the owner's own exact input sentinel
		// before any grant, Update or native operation, on a STABLE and on a recovery pre-state alike. The same Store
		// instance then serves the next valid-owner invocation in its control-only order before any image check.
		want := (*mdbx.OperationReservationOwner)(nil).WithReservation(1, nil)
		for _, c := range []struct {
			name, next string
			spec       ssqSpec
		}{{"open STABLE", ssqBranch, ssqSpec{tip: 10}}, {"recovery", ssqRequired, ssqSpec{tip: 10, authority: ssqPendingNone}}} {
			w := newRetainFixtureWorld(t, c.spec)
			raw := make([]byte, mdbx.MaxBlockBytes+1)
			before := bytes.Clone(raw)
			for _, owner := range []*mdbx.OperationReservationOwner{nil, {}} {
				tip := w.tipAt(10)
				var out SelectedSideMutationOutcome
				evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() {
					out = RetainSelectedSideMDBX(w.store, owner, raw, tip)
				})
				if err != nil || evidence != (mdbx.SelectedDamageEvidence{}) {
					t.Fatalf("%s: owner input reached native operations: %v %+v", c.name, err, evidence)
				}
				retainWant(t, c.name+": owner input before raw bound", out, "", "", "", old, pre, false)
				if out.Err != want || out.Err.Error() != "invalid storage operation reservation input" { //nolint:errorlint // The owner's exact sentinel.
					t.Fatalf("%s: owner input error %v", c.name, out.Err)
				}
				w.wantRaw(raw, before)
				if *tip != *w.tipAt(10) {
					t.Fatalf("%s: owner input changed the caller's tip locator", c.name)
				}
				retainWantReleased(t, w.owner)
				retainWantRefusal(t, c.name+": next valid-owner control-only order", w.retain(raw, w.tipAt(10)), c.next, "")
				w.wantImage(c.name + ": owner input refusal and next valid-owner refusal")
			}
		}
	})
	t.Run("A9-reopen-abortIO", func(t *testing.T) {
		w := newRetainFixtureWorld(t, ssqSpec{tip: 10})
		w.reopen()
		out, _ := w.armed(mdbx.SelectedDamageAbortEIO, 0, nil, w.child(w.canonical[5], 6, nil), w.tipAt(10))
		retainWant(t, "empty API Result/OLD with raw joined abort/CLOSED", out, "", "", "OLD", old, pre, false)
		ssqWantNative(t, "unverified owner abort", out.Err, ssqNative{"get", mdbx.EngineInvalidInput, 22}, ssqAbortEIO)
		w.wantImage("unverified owner abort")
	})
}
