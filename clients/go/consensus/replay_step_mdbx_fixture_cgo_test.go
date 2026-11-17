//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func TestReplayStepTreeV1Fixture(t *testing.T) {
	t.Run("A4", testStepTreeRetentionV1)
	t.Run("R7_R8_R9_R10", testStepTreeSourcesV1)
	t.Run("R9_LAG", testStepTreeLagV1)
	t.Run("A3_R4_R5_H1", testStepTreeUndoV1)
	t.Run("R6_H1_capacity_abort", testStepTreeCapacityAbortV1)
	t.Run("R6_floor", testStepTreeFloorV1)
	t.Run("H1_H3_native", testStepTreeNativeV1)
	t.Run("A5_R9_H2", testStepTreeContextFaultV1)
	t.Run("H1_unwind", testStepTreeUnwindV1)
	t.Run("H1_retained", testStepTreeRetainedV1)
	t.Run("R4_H4", testStepTreeGlobalRowsV1)
	t.Run("R11", testStepTreeGrowthBeforeRootV1)
	t.Run("R9_unequal", testStepTreeUnequalV1)
}

func stepTreeSeedV1(t *testing.T, w *stepTreeWorldV1, rank uint8, key, value []byte) {
	t.Helper()
	var err error
	if value == nil {
		err = mdbx.FixtureStartupDeleteRow(w.s, rank, key)
	} else {
		err = mdbx.FixtureSeedRawRow(w.s, rank, key, value)
	}
	logicalMDBXAssert(t, err == nil, "seed native row %d/%x: %v", rank, key, err)
}

func stepTreeUnchangedV1(t *testing.T, w *stepTreeWorldV1, h uint64) {
	t.Helper()
	err := w.s.View(func(r *mdbx.Reader) error {
		a, _, err := r.ReadTreeAuthorityV1()
		logicalMDBXAssert(t, err == nil && a.Authority.Replay.Cursor == (mdbx.ReplayCursorV1{Kind: 2, Height: h - 1, BlockHash: w.hashes[h-1]}), "aborted cursor changed")
		for _, g := range []uint64{1, 2} {
			if g == 2 && !replayPairAppliesV1(w.a.Authority.Replay.Target.TipHeight, h) {
				continue
			}
			root, _, err := r.ReadTreeRootBindingV1(g)
			logicalMDBXAssert(t, err == nil && root.Endpoint == w.endpoint(h-1) && root.RootDigest == [32]byte(w.raw[h-1][108:140]), "role%d partial root/endpoint", g)
		}
		return nil
	})
	logicalMDBXAssert(t, err == nil, "unchanged physical state: %v", err)
}

func testStepTreeRetentionV1(t *testing.T) {
	t.Run("one-shared-old-active", testStepTreeOldActiveOnceV1)
	t.Run("nonaligned15839_h1", func(t *testing.T) {
		w := stepTreeNewV1(t, 15839, 1, nil)
		w.a.Authority.Replay.TargetProfile = 1
		w.setAuthority(t)
		out := w.call(1)
		w.btWorld.reopen(t)
		stepTreeProgressV1(t, w, 1, out)
		w.read(t, 4, w.hashes[1][:], w.raw[1]) // L_body=1, despite h1<B_target720.
	})
	for _, mode := range []string{"neither", "body", "undo", "both", "exact", "different", "above-tip"} {
		t.Run(mode, func(t *testing.T) {
			w := stepTreeNewV1(t, 15840, 5, nil)
			w.a.Authority.Replay.TargetProfile = 1
			w.setAuthority(t)
			body := mode != "neither" && mode != "undo"
			undo := mode != "neither" && mode != "body"
			if body {
				stepTreeSeedV1(t, w, 4, w.hashes[5][:], w.raw[5])
			}
			manifest := stepManifest(5, 18691989860, 1, 0)
			if undo {
				stepTreeSeedV1(t, w, 5, mdbx.UndoManifestKey(w.hashes[5]), manifest)
			}
			if mode == "exact" || mode == "different" || mode == "above-tip" {
				stepTreeSeedV1(t, w, 2, stepKey(3, 4), mdbx.ChainValue(w.hashes[4], w.hashes[3], w.endpoint(4).CumulativeChainwork))
				owner, _ := mdbx.CanonicalOwnerKey(3, w.hashes[4])
				stepTreeSeedV1(t, w, 7, owner, mdbx.CanonicalOwnerValue(4))
				if mode != "above-tip" {
					x, raw := w.hashes[5], w.raw[5][:148]
					if mode == "different" {
						h, _ := ParseInitial148HeaderBytes(raw)
						h.Timestamp--
						raw = initial148BlockMine(t, initial148BlockHead{version: h.Version, parent: h.PrevBlockHash, merkle: h.MerkleRoot, target: h.Target, root: h.UtxoRoot, timestamp: h.Timestamp})
						x = sha3.Sum256(raw)
					}
					stepTreeSeedV1(t, w, 3, x[:], raw)
					stepTreeSeedV1(t, w, 2, stepKey(3, 5), mdbx.ChainValue(x, w.hashes[4], w.endpoint(5).CumulativeChainwork))
					owner, _ := mdbx.CanonicalOwnerKey(3, x)
					stepTreeSeedV1(t, w, 7, owner, mdbx.CanonicalOwnerValue(5))
				}
			}
			var out ReplayStepOutcomeV1
			evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = w.call(5) })
			logicalMDBXAssert(t, err == nil && evidence.BeginWrite == 1 && evidence.Commits == 1, "single retention commit")
			w.btWorld.reopen(t)
			stepTreeProgressV1(t, w, 5, out)
			var wantBody, wantUndo []byte
			if mode == "exact" {
				wantBody, wantUndo = w.raw[5], manifest
			}
			w.read(t, 4, w.hashes[5][:], wantBody)
			w.read(t, 5, mdbx.UndoManifestKey(w.hashes[5]), wantUndo)
		})
	}
}

func testStepTreeOldActiveOnceV1(t *testing.T) {
	var ownerReads [3]uint64
	for i, mask := range []uint8{1, 2, 3} {
		w := stepTreeNewV1(t, 15840, 5, nil)
		w.a.Authority.Replay.TargetProfile = 1
		w.setAuthority(t)
		for _, h := range []uint64{4, 5} {
			stepTreeSeedV1(t, w, 3, w.hashes[h][:], w.raw[h][:148])
			stepTreeSeedV1(t, w, 2, stepKey(3, h), mdbx.ChainValue(w.hashes[h], w.hashes[h-1], w.endpoint(h).CumulativeChainwork))
			owner, _ := mdbx.CanonicalOwnerKey(3, w.hashes[h])
			stepTreeSeedV1(t, w, 7, owner, mdbx.CanonicalOwnerValue(h))
		}
		manifest := stepManifest(5, 18691989860, 1, 0)
		if mask&1 != 0 {
			stepTreeSeedV1(t, w, 4, w.hashes[5][:], w.raw[5])
		}
		if mask&2 != 0 {
			stepTreeSeedV1(t, w, 5, mdbx.UndoManifestKey(w.hashes[5]), manifest)
		}
		var out ReplayStepOutcomeV1
		evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = w.call(5) })
		logicalMDBXAssert(t, err == nil && evidence.BeginWrite == 1 && evidence.Commits == 1, "reached compared below-promise artifacts")
		ownerReads[i] = evidence.OldGets[7]
		stepTreeProgressV1(t, w, 5, out)
		var body, undo []byte
		if mask&1 != 0 {
			body = w.raw[5]
		}
		if mask&2 != 0 {
			undo = manifest
		}
		w.read(t, 4, w.hashes[5][:], body)
		w.read(t, 5, mdbx.UndoManifestKey(w.hashes[5]), undo)
	}
	logicalMDBXAssert(t, ownerReads[0] != 0 && ownerReads[0] == ownerReads[1] && ownerReads[1] == ownerReads[2], "body/undo/both must share one OLD-owner lookup, rank7 gets: %v", ownerReads)
}

func testStepTreeSourcesV1(t *testing.T) {
	for _, mode := range []string{"context-index-absent", "context-parent", "context-work", "shared-header-absent", "counter-absent", "counter-IO", "root-IO", "root-malformed", "own-header-IO", "cursor"} {
		t.Run(mode, func(t *testing.T) {
			w := stepTreeNewV1(t, 12, 12, nil)
			key, rank := stepKey(1, 11), uint8(2)
			scenario := mdbx.SelectedDamageProbeOnly
			switch mode {
			case "context-index-absent":
				stepTreeSeedV1(t, w, rank, key, nil)
			case "context-parent", "context-work":
				entry := mdbx.ChainValue(w.hashes[11], w.hashes[10], w.endpoint(11).CumulativeChainwork)
				if mode == "context-parent" {
					entry[32] ^= 1
				} else {
					entry[103] ^= 1
				}
				stepTreeSeedV1(t, w, rank, key, entry)
			case "shared-header-absent":
				rank, key = 3, w.hashes[11][:]
				stepTreeSeedV1(t, w, rank, key, nil)
			case "counter-absent":
				rank, key = 0, btMeta(0x10, 1)
				stepTreeSeedV1(t, w, rank, key, nil)
			case "counter-IO":
				rank, key, scenario = 0, btMeta(0x10, 1), mdbx.SelectedDamageGetEIO
			case "root-IO":
				rank, key, scenario = 0, btMeta(0x11, 1), mdbx.SelectedDamageGetEIO
			case "root-malformed":
				rank, key = 0, btMeta(0x11, 1)
				stepTreeSeedV1(t, w, rank, key, []byte{0xff})
			case "own-header-IO":
				rank, key, scenario = 3, w.hashes[12][:], mdbx.SelectedDamageGetEIO
			case "cursor":
				w.a.Authority.Replay.Cursor.BlockHash[0] ^= 1
				w.setAuthority(t)
			}
			var out ReplayStepOutcomeV1
			evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, scenario, rank, key, func() { out = w.call(12) })
			logicalMDBXAssert(t, err == nil && evidence.BeginWrite == 0 && evidence.Commits == 0 && out.NativeCalled && out.Truth == 1 && out.Stage == 1 && out.Index == -1 && out.Role == "CURRENT" && out.Cause != nil && out.Err != nil, "source product/site: %+v/%+v/%v", out, evidence, err)
			want, decision := replayEntryRecovery, "target local"
			switch mode {
			case "counter-IO", "root-IO":
				want, decision = "LOCAL_RESOURCE_UNAVAILABLE(state_view_read)", ""
			case "own-header-IO":
				decision = ""
			case "shared-header-absent", "cursor":
				want, decision = selectedSideIntegrity, ""
			}
			logicalMDBXAssert(t, out.Result == want && out.Decision == decision, "source owning projection: %+v", out)
			if mode == "counter-absent" {
				failure, ok := any(out.Cause).(*logicalStateFailure)
				logicalMDBXAssert(t, ok && failure.kind == logicalStateFailureStoreIntegrity && !out.HasObservation && out.Observation == (mdbx.TreeObservationV1{}) && any(out.Err) == any(out.Cause), "required counter's exact no-observation result")
			}
			if mode == "root-malformed" {
				logicalMDBXAssert(t, out.HasObservation && out.Observation.Primitive == 0 && out.Observation.Generation == 1 && out.Observation.Rank == 0, "CURRENT actual root observation")
			}
			calls := 0
			next := w.s.View(func(*mdbx.Reader) error { calls++; return nil })
			consumed := scenario == mdbx.SelectedDamageGetEIO || mode == "root-malformed"
			if consumed {
				logicalMDBXAssert(t, any(next) == any(out.Err) && calls == 0, "native consumption was healed")
			} else {
				logicalMDBXAssert(t, next == nil && calls == 1, "application source refusal consumed Store")
			}
			btReservationsReleased(t, w.owner)
		})
	}
}

func testStepTreeLagV1(t *testing.T) {
	for _, mode := range []string{"index-absent", "index-width", "index-hash", "index-work", "owner-absent", "owner-width", "owner-height", "index-IO", "root-IO", "root-malformed"} {
		t.Run(mode, func(t *testing.T) {
			w := stepTreeNewV1(t, 15840, 5, nil)
			key, rank := stepKey(2, 4), uint8(2)
			scenario := mdbx.SelectedDamageProbeOnly
			switch mode {
			case "index-absent":
				stepTreeSeedV1(t, w, rank, key, nil)
			case "index-width":
				stepTreeSeedV1(t, w, rank, key, []byte{1})
			case "index-hash", "index-work":
				entry := mdbx.ChainValue(w.hashes[4], w.hashes[3], w.endpoint(4).CumulativeChainwork)
				if mode == "index-hash" {
					entry[0] ^= 1
				} else {
					entry[103] ^= 1
				}
				stepTreeSeedV1(t, w, rank, key, entry)
			case "owner-absent", "owner-width", "owner-height":
				rank = 7
				key, _ = mdbx.CanonicalOwnerKey(2, w.hashes[4])
				value := []byte(nil)
				if mode == "owner-width" {
					value = []byte{1}
				}
				if mode == "owner-height" {
					value = mdbx.CanonicalOwnerValue(3)
				}
				stepTreeSeedV1(t, w, rank, key, value)
			case "index-IO":
				scenario = mdbx.SelectedDamageGetEIO
			case "root-IO":
				rank, key, scenario = 0, btMeta(0x11, 2), mdbx.SelectedDamageGetEIO
			case "root-malformed":
				rank, key = 0, btMeta(0x11, 2)
				stepTreeSeedV1(t, w, rank, key, []byte{1})
			}
			var invocation *replayStepInvocation
			evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, scenario, rank, key, func() { invocation = replayStepRun(w.step, w.s, w.owner, w.raw[5]) })
			out := invocation.out
			logicalMDBXAssert(t, err == nil && evidence.BeginWrite == 0 && evidence.Commits == 0 && out.Role == "LAG" && out.Index == -1 && out.Truth == 1 && out.Stage == 1 && any(out.Cause) == any(invocation.observation.incoming), "reached LAG preserves original selection: %+v/%+v/%v", out, evidence, err)
			decision := "target local"
			if scenario == mdbx.SelectedDamageGetEIO {
				decision = ""
			}
			logicalMDBXAssert(t, out.Result == replayEntryRecovery && out.Decision == decision, "LAG owning branch: %+v", out)
			if mode == "index-width" || mode == "owner-width" {
				e, ok := any(out.Cause).(*mdbx.EngineError)
				logicalMDBXAssert(t, ok && e.Operation == "get" && e.Class == "Integrity" && e.Code == -30796 && e.Diagnostic == "invalid tree native representation" && e.Cause != nil && !e.ReopenRequired && e.TreeObservation == nil && !out.HasObservation && out.Observation == (mdbx.TreeObservationV1{}) && errors.Is(out.Err, e), "recorded exact LAG Get and real Cause: %+v", out)
				if mode == "index-width" {
					t.Run("private-predicate-controls", func(t *testing.T) {
						// Pure private predicate controls; altered copies are not native-produced
						// tuples or public reproductions. The actual error and Cause stay untouched.
						logicalMDBXAssert(t, replayStepLagWidth148V1(e), "actual native width must match")
						var typedNil *mdbx.EngineError
						for _, row := range []struct {
							name string
							err  error
						}{
							{"nil", nil}, {"typed-nil", typedNil}, {"wrapped", fmt.Errorf("wrapped: %w", e)},
						} {
							logicalMDBXAssert(t, !replayStepLagWidth148V1(row.err), "private width predicate accepted %s", row.name)
						}
						for _, row := range []struct {
							name   string
							change func(*mdbx.EngineError)
						}{
							{"operation", func(copy *mdbx.EngineError) { copy.Operation = "update" }},
							{"class", func(copy *mdbx.EngineError) { copy.Class = mdbx.EngineIO }},
							{"code", func(copy *mdbx.EngineError) { copy.Code = -30779 }},
							{"diagnostic", func(copy *mdbx.EngineError) { copy.Diagnostic = "other integrity" }},
							{"reopen", func(copy *mdbx.EngineError) { copy.ReopenRequired = true }},
							{"cause", func(copy *mdbx.EngineError) { copy.Cause = nil }},
							{"observation", func(copy *mdbx.EngineError) { copy.TreeObservation = &mdbx.TreeObservationV1{} }},
						} {
							copy := *e
							row.change(&copy)
							logicalMDBXAssert(t, !replayStepLagWidth148V1(&copy), "private width predicate accepted changed %s", row.name)
						}
						// Pure pre-held-evidence predicate controls need no Reader or later reads.
						proof := replayStepCall{h: 5, a: w.a.Authority, parent: w.hashes[4], parentHeader: [148]byte(w.raw[4][:148]), parentEndpoint: w.endpoint(4)}
						logicalMDBXAssert(t, proof.lagEvidence148V1(), "private qualified evidence baseline")
						for _, row := range []struct {
							name   string
							change func(*replayStepCall)
						}{
							{"header", func(copy *replayStepCall) { copy.parentHeader[108] ^= 1 }},
							{"kind", func(copy *replayStepCall) { copy.parentEndpoint.Kind = mdbx.TreeEndpointPreGenesisV1 }},
							{"height", func(copy *replayStepCall) { copy.parentEndpoint.Height++ }},
							{"endpoint-hash", func(copy *replayStepCall) { copy.parentEndpoint.BlockHash[0] ^= 1 }},
							{"cursor-hash", func(copy *replayStepCall) { copy.a.Replay.Cursor.BlockHash[0] ^= 1 }},
						} {
							copy, replay := proof, *proof.a.Replay
							copy.a.Replay = &replay
							row.change(&copy)
							logicalMDBXAssert(t, !copy.lagEvidence148V1(), "private evidence predicate accepted changed %s", row.name)
						}
					})
				}
				if mode == "index-width" {
					logicalMDBXAssert(t, evidence.OldGets[7] == 2, "reciprocal Get followed expired index Reader: %+v", evidence)
				}
			}
			if mode == "root-malformed" {
				logicalMDBXAssert(t, out.HasObservation && out.Observation.Primitive == 0 && out.Observation.Generation == 2 && out.Observation.Block == w.hashes[5] && out.Observation.Height == 5, "LAG root observation0 is not native index1")
			}
			consumed := scenario == mdbx.SelectedDamageGetEIO || mode == "index-width" || mode == "owner-width" || mode == "root-malformed"
			calls := 0
			next := w.s.View(func(*mdbx.Reader) error { calls++; return nil })
			if consumed {
				logicalMDBXAssert(t, any(next) == any(out.Err) && calls == 0, "target-local projection healed native consumption")
			} else {
				logicalMDBXAssert(t, next == nil && calls == 1, "healthy application abort lost Store")
			}
			btReservationsReleased(t, w.owner)
		})
	}
}

func testStepTreeUndoV1(t *testing.T) {
	for _, mode := range []string{"equal", "extra", "missing", "differing", "truncated", "partial-IO", "body-second-IO"} {
		t.Run(mode, func(t *testing.T) {
			w, final := stepTreeGrowthWorldV1(t, "equal", 15840)
			p, err := ParseInitial148BlockBytes(w.raw[1])
			logicalMDBXAssert(t, err == nil, "undo funding identity")
			generated := new(big.Int)
			for h := uint64(0); h < 200; h++ {
				generated.Add(generated, new(big.Int).SetUint64(BlockSubsidyBig(h, generated)))
			}
			manifest := stepManifest(200, generated.Uint64(), 10, 9)
			stepTreeSeedV1(t, w, 5, mdbx.UndoManifestKey(w.hashes[200]), manifest)
			var first []byte
			for j := uint32(0); j < 9; j++ {
				op := Outpoint{Txid: p.Txids[0], Vout: j}
				key := mdbx.UndoEntryKey(w.hashes[200], op.Txid, j+1, 0, j)
				if j == 0 {
					first = key
				}
				if mode == "missing" && j == 8 {
					continue
				}
				value := logicalMDBXValue(w.rows[op])
				if mode == "differing" && j == 0 {
					value[0] ^= 1
				}
				stepTreeSeedV1(t, w, 5, key, value)
			}
			if mode == "extra" {
				stepTreeSeedV1(t, w, 5, mdbx.UndoEntryKey(w.hashes[200], p.Txids[0], 10, 0, 99), logicalMDBXValue(w.rows[Outpoint{Txid: p.Txids[0]}]))
			}
			if mode == "truncated" {
				manifest[32] = 10
				stepTreeSeedV1(t, w, 5, mdbx.UndoManifestKey(w.hashes[200]), manifest)
			}
			if mode == "body-second-IO" {
				stepTreeSeedV1(t, w, 4, w.hashes[200][:], w.raw[200])
			}
			var out ReplayStepOutcomeV1
			if mode == "partial-IO" {
				evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 5, first, func() { out = w.call(200) })
				logicalMDBXAssert(t, err == nil && evidence.OldGets[5] == 2 && evidence.Faults == 1 && out.Result == selectedSideCanonical && out.Decision == "" && out.Role == "CURRENT", "manifest bytes before non-EOF entry read: %+v/%+v", out, evidence)
			} else if mode == "body-second-IO" {
				gets, err := mdbx.FixtureBodySecondGetEIO(w.s, 4, w.hashes[200][:], func() { out = w.call(200) })
				logicalMDBXAssert(t, err == nil && gets == 2 && out.Result == selectedSideCanonical && out.Role == "CURRENT", "complete body comparison before undo/old-active: %+v", out)
			} else {
				out = w.call(200)
			}
			if mode == "equal" {
				w.btWorld.reopen(t)
				stepTreeProgressV1(t, w, 200, out)
				for _, g := range []uint64{1, 2} {
					btState(t, w.btWorld, g, w.endpoint(200), final)
				}
				w.read(t, 5, mdbx.UndoManifestKey(w.hashes[200]), nil)
				return
			}
			if mode != "partial-IO" && mode != "body-second-IO" {
				logicalMDBXAssert(t, out.Result == selectedSideIntegrity && out.Decision == "", "complete original-order family rejection: %+v", out)
			}
			logicalMDBXAssert(t, out.Truth == 1 && out.Stage == 1 && out.Index == -1 && out.Cause != nil && out.Err != nil, "family error raw tuple")
			w.btWorld.reopen(t)
			stepTreeUnchangedV1(t, w, 200)
			for _, g := range []uint64{1, 2} {
				btState(t, w.btWorld, g, w.endpoint(199), w.rows)
			}
			btReservationsReleased(t, w.owner)
		})
	}
}

// testStepTreeFloorV1 reaches public STEP before funding; bare account tests
// cannot detect a zero-charge admission inserted outside the native operation.
func testStepTreeFloorV1(t *testing.T) {
	for _, limit := range []uint64{0, 805306367} {
		for _, authority := range []string{"replay", "not-applicable", "malformed"} {
			t.Run(fmt.Sprintf("limit%d/%s", limit, authority), func(t *testing.T) {
				w := stepTreeNewV1(t, 0, 0, nil)
				if authority == "not-applicable" {
					w.a.Authority.Phase, w.a.Authority.Lifecycle, w.a.Authority.Replay = mdbx.StoragePhaseNoneV1, mdbx.StorageLifecycleStableV1, nil
					w.a.TargetLagGenerationID, w.a.SourceKind = 0, mdbx.TreeSourceNoneV1
					w.setAuthority(t)
				}
				before := rtImageRow(t, w.btWorld, []byte{2})
				if authority == "malformed" {
					stepTreeSeedV1(t, w, 0, []byte{2}, []byte{0xff})
				}
				owner, err := mdbx.NewOperationReservationOwner(limit)
				logicalMDBXAssert(t, err == nil, "valid below-floor owner")
				w.owner = owner
				var out ReplayStepOutcomeV1
				evidence, err := mdbx.FixtureSelectedDamage(w.s, owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = w.call(0) })
				logicalMDBXAssert(t, err == nil && out.NativeCalled && evidence.BeginOld == 1 && evidence.OldGets[0] == 1 && evidence.BeginWrite == 0 && evidence.BeginRead == 0 && evidence.Commits == 0 && evidence.Deletes == 0 && evidence.NodeGets == 0 && evidence.NodePulls == 0 && evidence.OldPulls == ([8]uint64{}), "below-floor STEP must read actual authority before funding: %+v/%+v/%v", out, evidence, err)
				for rank := 1; rank < len(evidence.OldGets); rank++ {
					logicalMDBXAssert(t, evidence.OldGets[rank] == 0, "postauthority data rank%d read before successful precheck", rank)
				}
				logicalMDBXAssert(t, out.Truth == 1 && out.Stage == 1 && out.Index == -1 && out.Role == "CURRENT" && out.CanonicalTruth == "OLD" && out.Height == 0 && out.Block == ([32]byte{}) && !out.HasObservation && out.Observation == (mdbx.TreeObservationV1{}) && out.Needed == nil, "authority/funding exact raw position: %+v", out)
				switch authority {
				case "replay":
					logicalMDBXAssert(t, mdbx.IsOperationReservationCapacity(out.Cause) && any(out.Err) == any(out.Cause) && out.Result == "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)" && out.Decision == "", "in-callback below-floor direct capacity: %+v", out)
				case "not-applicable":
					logicalMDBXAssert(t, out.Err != nil && out.Cause == nil && out.Result == "" && out.Decision == "not applicable", "earlier authority decision precedes below-floor capacity: %+v", out)
				case "malformed":
					engine, ok := any(out.Cause).(*mdbx.EngineError)
					logicalMDBXAssert(t, ok && any(out.Err) == any(out.Cause) && out.Result == selectedSideIntegrity && out.Decision == "" && engine.Operation == "get" && engine.Class == "Integrity" && engine.Code == -30796 && engine.Diagnostic == "invalid tree native representation" && engine.Cause != nil && !engine.ReopenRequired && engine.TreeObservation == nil, "earlier malformed authority retains exact native integrity: %+v", out)
				}
				logicalMDBXAssert(t, w.step.path.slot == nil && w.step.path.release == nil && !w.step.path.guarded && w.step.path.dst148 == ([148]byte{}) && w.view.versions == 0 && w.view.protects == 0 && w.view.headerCalls == 0 && w.view.releases == 0 && mdbx.FixtureReservationLive(owner) == 0, "refused funding reached PATH or retained gross")
				calls := 0
				next := w.s.View(func(*mdbx.Reader) error { calls++; return nil })
				if authority == "malformed" {
					logicalMDBXAssert(t, calls == 0 && any(next) == any(out.Err), "native authority failure consumption was healed")
				} else {
					logicalMDBXAssert(t, calls == 1 && next == nil, "capacity/application abort consumed healthy Store")
					w.read(t, 0, []byte{2}, before)
					for _, g := range []uint64{1, 2} {
						btState(t, w.btWorld, g, mdbx.TreeEndpointV1{}, map[Outpoint]UtxoEntry{})
						w.read(t, 2, stepKey(g, 0), nil)
						key, _ := mdbx.CanonicalOwnerKey(g, w.hashes[0])
						w.read(t, 7, key, nil)
					}
					w.read(t, 3, w.hashes[0][:], nil)
					w.read(t, 4, w.hashes[0][:], nil)
					w.read(t, 5, mdbx.UndoManifestKey(w.hashes[0]), nil)
				}
				callback := 0
				primary := errors.New("next below-floor operation")
				err = owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
					truth, stage, index, got := w.s.UpdateTreeV1(a, func(*mdbx.Reader) (mdbx.TreeOperationV1, error) { callback++; return mdbx.TreeOperationV1{}, primary })
					want, count := primary, 1
					if authority == "malformed" {
						want, count = out.Err, 0
					}
					logicalMDBXAssert(t, truth == 1 && stage == 1 && index == -1 && got == want && callback == count, "actual next Store/account operation: %d/%d/%d/%v", truth, stage, index, got)
					return nil
				})
				logicalMDBXAssert(t, err == nil && mdbx.FixtureReservationLive(owner) == 0, "next operation leaked gross funding")
			})
		}
	}
}

func testStepTreeCapacityAbortV1(t *testing.T) {
	w := stepTreeNewV1(t, 0, 0, nil)
	w.owner, _ = reservationRemaining(t, 399999999)
	var out ReplayStepOutcomeV1
	evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageAbortEIO, 0, nil, func() { out = w.call(0) })
	logicalMDBXAssert(t, err == nil && evidence.Faults == 1 && evidence.BeginWrite == 0 && evidence.OldGets[1] == 0 && evidence.OldGets[2] == 0 && evidence.OldGets[3] == 0 && evidence.OldGets[4] == 0, "T refusal before data: %+v/%v", evidence, err)
	parts, ok := out.Err.(interface{ Unwrap() []error })
	logicalMDBXAssert(t, ok && len(parts.Unwrap()) == 2 && any(parts.Unwrap()[0]) == any(out.Cause) && mdbx.IsOperationReservationCapacity(out.Cause) && out.Result == selectedSideCapacity && out.Truth == 1 && out.Stage == 1 && out.Index == -1 && out.Role == "CURRENT", "capacity leaf with actual abort IO: %+v", out)
	abort, ok := any(parts.Unwrap()[1]).(*mdbx.EngineError)
	logicalMDBXAssert(t, ok && abort.Operation == "abort" && abort.Class == "IO" && abort.Code == 5 && abort.Diagnostic == "error 5" && abort.Cause == nil && !abort.ReopenRequired, "actual cleanup tuple %v", out.Err)
	calls := 0
	next := w.s.View(func(*mdbx.Reader) error { calls++; return nil })
	logicalMDBXAssert(t, any(next) == any(out.Err) && calls == 0, "capacity+IO consumption changed")
}

func testStepTreeNativeV1(t *testing.T) {
	for _, row := range []struct {
		name     string
		scenario mdbx.SelectedDamageScenario
		truth    mdbx.CommitTruth
		stage    mdbx.UpdateStage
		index    int
	}{
		{"CURRENT-precommit", mdbx.SelectedDamagePutEIO, 1, 2, 0},
		{"LAG-precommit", mdbx.SelectedDamagePutEIO, 1, 2, 1},
		{"crossed-OLD", mdbx.SelectedDamageCommitOld, 1, 3, -1},
		{"crossed-NEW", mdbx.SelectedDamageCommitNew, 2, 3, -1},
		{"crossed-unreadable", mdbx.SelectedDamageCommitUnreadable, 3, 3, -1},
		{"crossed-neither", mdbx.SelectedDamageCommitThird, 3, 3, -1},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := stepTreeNewV1(t, 15840, 5, nil)
			key := []byte{2}
			if row.index == 0 {
				key = btMeta(0x11, 1)
			}
			if row.index == 1 {
				key = btMeta(0x11, 2)
			}
			var out ReplayStepOutcomeV1
			evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, row.scenario, 0, key, func() { out = w.call(5) })
			logicalMDBXAssert(t, err == nil && out.Truth == row.truth && out.Stage == row.stage && out.Index == row.index && out.Err != nil && out.Cause != nil && out.CanonicalTruth == "OLD" && evidence.BeginWrite == 1, "native exact product: %+v/%+v/%v", out, evidence, err)
			if row.index >= 0 {
				role := "CURRENT"
				if row.index == 1 {
					role = "LAG"
				}
				logicalMDBXAssert(t, out.Role == role && out.Result == selectedSidePrecommit, "actual native primitive role")
			}
			calls := 0
			next := w.s.View(func(*mdbx.Reader) error { calls++; return nil })
			logicalMDBXAssert(t, calls == 0 && any(next) == any(out.Err), "terminal native truth/disposition lost")
			w.btWorld.reopen(t)
			if row.truth == 2 {
				stepTreeImageV1(t, w, 5)
			} else if row.name != "crossed-neither" {
				stepTreeUnchangedV1(t, w, 5)
			}
			btReservationsReleased(t, w.owner)
		})
	}
}

// stepTreeContextStoreV1 is a bounded native-to-STEP-private join probe. It
// preserves the qualified STEP descriptor and rebinds only the submitted one
// so the real native Q owner produces its incomplete-OLD tuple. This is not a
// full public StepReplayMDBX G2 execution.
type stepTreeContextStoreV1 struct {
	store    *mdbx.Store
	original mdbx.CanonicalContextWindowV1
	raw      replayPairOutcomeV1
}

func (s *stepTreeContextStoreV1) UpdateTreeV1(account *mdbx.OperationAccount, prepare func(*mdbx.Reader) (mdbx.TreeOperationV1, error)) (mdbx.CommitTruth, mdbx.UpdateStage, int, error) {
	s.raw.Truth, s.raw.Stage, s.raw.Index, s.raw.Err = s.store.UpdateTreeV1(account, func(reader *mdbx.Reader) (mdbx.TreeOperationV1, error) {
		op, err := prepare(reader)
		if err != nil {
			return op, err
		}
		s.original = *op.Pair.ContextConsulted
		absent := s.original
		absent.Generation = 999
		op.Pair.ContextConsulted = &absent
		return op, nil
	})
	return s.raw.Truth, s.raw.Stage, s.raw.Index, s.raw.Err
}

func testStepTreeContextFaultV1(t *testing.T) {
	t.Run("G2_private_join", testStepTreeContextJoinV1)
	for _, h := range []uint64{10080, 20160} {
		for _, late := range []bool{false, true} {
			t.Run(fmt.Sprintf("drift%d/late%v", h, late), func(t *testing.T) {
				w := stepTreeNewV1(t, h, h, nil)
				k := h - 10080
				if late {
					k = h - 1
				}
				var out ReplayStepOutcomeV1
				drift, err := mdbx.FixtureWriteSnapshotDrift(w.s, 2, stepKey(1, k), func() { out = w.call(h) })
				e, ok := any(out.Cause).(*mdbx.EngineError)
				logicalMDBXAssert(t, err == nil && drift == 1 && ok && out.Result == replayEntryStale && out.Truth == 1 && out.Stage == 1 && out.Index == -1 && any(out.Cause) == any(out.Err) && e.Operation == "update" && e.Class == "StateMismatch" && e.Code == -30779 && e.Diagnostic == "OLD/write snapshot mismatch" && !out.HasObservation, "actual first/last full-window drift: %+v/%d/%v", out, drift, err)
				btReservationsReleased(t, w.owner)
			})
		}
	}
}

func testStepTreeContextJoinV1(t *testing.T) {
	w := stepTreeNewV1(t, 12, 12, nil)
	i := &replayStepInvocation{out: ReplayStepOutcomeV1{Truth: 1, Stage: 1, Index: -1, CanonicalTruth: "OLD"}}
	c := &replayStepCall{owner: w.step, invocation: i, entry: replayEntryCall{sentinel: errors.New("context join decision")}}
	store := &stepTreeContextStoreV1{store: w.s}
	w.step.path.mu.Lock()
	err := w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		defer w.step.path.finishLocked()
		defer c.release148V1()
		c.account = a
		out, runErr := withInitial148ReplayCompleteBlockV1(a, func(validate func(*mdbx.Reader, initial148CompleteBlockInputV1) (*initial148CompleteBlockResultV1, error)) error {
			c.validate148, i.out.NativeCalled = validate, true
			raw := applyReplayPairV1(store, a, func(r *mdbx.Reader) (replayPairRequestV1, *initial148CompleteBlockResultV1, replayPairRowsV1, error) {
				return c.prepare148V1(r, w.raw[12])
			}, c.lagInputs148V1)
			i.out.Truth, i.out.Stage, i.out.Index, i.out.Err, i.out.Role = raw.Truth, raw.Stage, raw.Index, raw.Err, raw.Role
			logicalMDBXAssert(t, store.original == (mdbx.CanonicalContextWindowV1{Generation: 1, FirstHeight: 1, Count: 11}) && *c.context == store.original, "qualified original STEP window was changed")
			return raw.Err
		})
		c.complete148 = out
		c.project148V1(runErr)
		return nil
	})
	w.step.path.mu.Unlock()
	e, ok := any(i.out.Cause).(*mdbx.EngineError)
	logicalMDBXAssert(t, err == nil && ok && any(i.out.Err) == any(store.raw.Err) && any(i.out.Cause) == any(store.raw.Err) && i.out.Truth == store.raw.Truth && i.out.Stage == store.raw.Stage && i.out.Index == -1 && i.out.Role == "" && i.out.Result == selectedSideInvariant && e.Class == "StateMismatch" && e.Operation == "update" && e.Code == -30779 && e.Diagnostic == "canonical context OLD image is incomplete" && e.Cause == nil && !e.ReopenRequired && !i.out.HasObservation, "actual native Q -> STEP invariant: %+v", i.out)
	stepTreeUnchangedV1(t, w, 12)
	btReservationsReleased(t, w.owner)
}

func testStepTreeUnwindV1(t *testing.T) {
	for _, mode := range []string{"nil", "panic", "Goexit"} {
		t.Run(mode, func(t *testing.T) {
			w := stepTreeNewV1(t, 0, 0, nil)
			primary := errors.New("STEP point provider unwind")
			if mode == "panic" {
				w.view.panicWith = primary
			}
			if mode == "Goexit" {
				w.view.panicWith = func() { runtime.Goexit() }
			}
			done := make(chan any, 1)
			var observation mdbx.PairReadObservation
			var fixtureErr error
			var out ReplayStepOutcomeV1
			funded, changed := false, false
			go func() {
				defer func() { done <- recover() }()
				observation, fixtureErr = mdbx.FixturePairReadObservation(w.s, func(uint32) {
					live := mdbx.FixtureReservationLive(w.owner)
					if live == 400000000 {
						funded = true
					}
					if funded && live != 400000000 {
						changed = true
					}
				}, func() { out = w.call(0) })
			}()
			got := <-done
			logicalMDBXAssert(t, mode == "panic" && any(got) == any(primary) || mode != "panic" && got == nil, "provider unwind identity: %v", got)
			logicalMDBXAssert(t, !changed && mdbx.FixtureReservationLive(w.owner) == 0 && w.step.path.release == nil && !w.step.path.guarded && w.step.path.dst148 == ([148]byte{}) && w.view.releases == 1, "gross/source retirement after native unwind")
			if mode == "nil" {
				logicalMDBXAssert(t, fixtureErr == nil && funded && observation.Writes != 0, "actual writer funding")
				stepTreeProgressV1(t, w, 0, out)
			} else {
				logicalMDBXAssert(t, w.step.path.slot == nil && w.s.View(func(*mdbx.Reader) error { return nil }) == nil, "clean provider abort consumed Store or kept partial slot")
			}
			btReservationsReleased(t, w.owner)
		})
	}
}

func testStepTreeRetainedV1(t *testing.T) {
	for _, mode := range []uint32{9, 10} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			w := stepTreeNewV1(t, 1, 1, nil)
			parsed, err := ParseInitial148BlockBytes(w.raw[1])
			logicalMDBXAssert(t, err == nil, "bound cleanup fixture")
			parsed.Txs[0].TxNonce = 1
			tx, err := MarshalTx(parsed.Txs[0])
			logicalMDBXAssert(t, err == nil, "cleanup coinbase")
			w.replace(t, 1, w.body(t, tx))
			var invocation *replayStepInvocation
			state, _, err := mdbx.FixtureStartupCleanup(w.s, mode, false, func() { invocation = replayStepRun(w.step, w.s, w.owner, w.raw[1]) })
			out := invocation.out
			original, ok := any(out.Cause).(*TxError)
			wantState, wantResult := "CLOSED", "LOCAL_RESOURCE_UNAVAILABLE(state_view_read)"
			if mode == 10 {
				wantState, wantResult = "POISONED_THREAD", selectedSideInvariant
			}
			logicalMDBXAssert(t, err == nil && state == wantState && ok && original.Code == BLOCK_ERR_COINBASE_INVALID && any(out.Cause) == any(invocation.observation.incoming) && out.Height == 1 && out.Block == w.hashes[1] && out.Decision == "consensus invalid" && out.Result == wantResult && out.Truth == 1 && out.Stage == 1 && out.Index == -1 && out.Role == "CURRENT" && !out.HasObservation, "selected invalidity with actual consumed/retained cleanup: %+v/%s/%v", out, state, err)
			var primary error
			if mode == 9 {
				joined, ok := out.Err.(interface{ Unwrap() []error })
				logicalMDBXAssert(t, ok && len(joined.Unwrap()) == 2, "raw application/cleanup join")
				primary = joined.Unwrap()[0]
			} else {
				engine, ok := any(out.Err).(*mdbx.EngineError)
				logicalMDBXAssert(t, ok, "retained raw error")
				primary = engine.Cause
			}
			logicalMDBXAssert(t, primary != nil && any(primary) != any(out.Cause), "logical sentinel and original TxError were conflated")
			btfAbortResult(t, out.Err, mode, primary)
			btfCached(t, w.btWorld, btResult{truth: out.Truth, stage: out.Stage, index: out.Index, err: out.Err})
			logicalMDBXAssert(t, w.step.path.release == nil && !w.step.path.guarded && w.step.path.dst148 == ([148]byte{}), "cleanup retained caller source guard")
			btReservationsReleased(t, w.owner)
			if mode == 10 {
				logicalMDBXAssert(t, mdbx.FixtureStartupRelease(w.s) == nil, "release observed retained fixture handle")
			}
		})
	}
}

func testStepTreeGlobalRowsV1(t *testing.T) {
	for _, family := range []string{"header-root", "body", "stored-unbound"} {
		t.Run(family, func(t *testing.T) {
			w := stepTreeNewV1(t, 15840, 5, nil)
			rank, value := uint8(4), bytes.Clone(w.raw[5])
			if family == "header-root" {
				rank, value = 3, bytes.Clone(w.raw[5][:148])
				value[108] ^= 1
			} else if family == "stored-unbound" {
				value[148] = 0
			} else {
				value[len(value)-1] ^= 1
			}
			stepTreeSeedV1(t, w, rank, w.hashes[5][:], value)
			var out ReplayStepOutcomeV1
			evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = w.call(5) })
			logicalMDBXAssert(t, err == nil && out.Result == selectedSideIntegrity && out.Decision == "" && out.Truth == 1 && out.Stage == 1 && out.Index == -1 && out.Role == "CURRENT" && out.Cause != nil && evidence.BeginWrite == 0 && evidence.Commits == 0 && evidence.OldGets[5] == 0 && evidence.OldGets[7] == 0, "hash-global first result precedes undo/membership/LAG: %+v/%+v", out, evidence)
			w.btWorld.reopen(t)
			stepTreeUnchangedV1(t, w, 5)
			btReservationsReleased(t, w.owner)
		})
	}
}

func testStepTreeGrowthBeforeRootV1(t *testing.T) {
	w, _ := stepTreeGrowthWorldV1(t, "over", 200)
	var out ReplayStepOutcomeV1
	evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageProbeOnly, 0, btMeta(0x11, 1), func() { out = w.call(200) })
	selected, ok := any(out.Cause).(*TxError)
	logicalMDBXAssert(t, err == nil && ok && selected.Code == BLOCK_ERR_STATE_GROWTH_EXCEEDED && out.Decision == "consensus invalid" && evidence.NodeGets == 0 && evidence.NodePulls == 0 && evidence.BeginWrite == 0 && evidence.Commits == 0, "growth rejection suppresses D: %+v/%+v", out, evidence)
	stepTreeUnchangedV1(t, w, 200)
	btReservationsReleased(t, w.owner)
}

func testStepTreeUnequalV1(t *testing.T) {
	w := stepTreeNewV1(t, 15840, 5, nil)
	parent, _ := mdbx.CanonicalOwnerKey(2, w.hashes[4])
	extra := btTransaction(999, 0, nil, [][]byte{btFrame(1, 0, []byte{99})}, nil, []byte{0}, nil)
	rows := map[Outpoint]UtxoEntry{{Txid: extra.id}: btEntry(1, 0, []byte{99}, 4, true)}
	root := canonicalUTXORoot(rows)
	raw := btBody(148, 99, w.hashes[3], extra)
	copy(raw[108:140], root[:])
	req := btRequest(raw, 4)
	req.Generation, req.Kind, req.Undo, req.BodyKind, req.CanonicalBeforePresent = 2, mdbx.TreeKindDirectApplyV1, mdbx.UndoTransientV1, 3, true
	req.Endpoint.CumulativeChainwork = w.endpoint(4).CumulativeChainwork
	seed, _, _ := w.btWorld.run(t, []blockTreeRequestV1{req}, func(_ []blockTreeEffectV1, _ []*btObserved, op *mdbx.TreeOperationV1) {
		op.Pair.Mutations = append(op.Pair.Mutations, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[7], Key: parent, BeforePresent: true, AfterKind: mdbx.AfterAbsent})
		btSort(op.Pair.Mutations)
	})
	seed.want(t, 2, 3, -1)
	logicalMDBXAssert(t, seed.err == nil, "native coherent LAG extra leaf")
	var binding mdbx.RootBindingV1
	err := w.s.View(func(r *mdbx.Reader) error { var err error; binding, _, err = r.ReadTreeRootBindingV1(2); return err })
	logicalMDBXAssert(t, err == nil && binding.RootDigest == root, "real alternative LAG root")
	binding.Endpoint = w.endpoint(4)
	encoded, err := binding.Encode()
	logicalMDBXAssert(t, err == nil, "restore qualified endpoint")
	alternateOwner, _ := mdbx.CanonicalOwnerKey(2, req.Block)
	meta, index := btMutation(0, btMeta(0x11, 2), encoded), btMutation(2, stepKey(2, 4), mdbx.ChainValue(w.hashes[4], w.hashes[3], w.endpoint(4).CumulativeChainwork))
	meta.BeforePresent, index.BeforePresent = true, true
	w.pair(t, meta, index, btMutation(7, parent, mdbx.CanonicalOwnerValue(4)), mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[7], Key: alternateOwner, BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	var out ReplayStepOutcomeV1
	counts, err := mdbx.FixturePairReadObservation(w.s, nil, func() { out = w.call(5) })
	unequal, ok := any(out.Cause).(*replayPairUnequalV1)
	logicalMDBXAssert(t, err == nil && ok && unequal.Generation == 2 && unequal.Height == 5 && unequal.Block == w.hashes[5] && unequal.Derived == root && unequal.Accepted == [32]byte(w.raw[5][108:140]) && out.Result == selectedSideInvariant && out.Decision == "" && out.Role == "LAG" && out.Index == -1 && out.Truth == 1 && out.Stage == 1 && !out.HasObservation && counts.Writes == 0, "coherent unequal accepted-prefix root is local invariant: %+v", out)
	w.read(t, 2, stepKey(1, 5), nil)
	w.read(t, 2, stepKey(2, 5), nil)
	btState(t, w.btWorld, 2, w.endpoint(4), rows)
	btReservationsReleased(t, w.owner)
}

func stepArmed(t *testing.T, w *stepWorld, h uint64, scenario mdbx.SelectedDamageScenario, rank uint8, key []byte) (ReplayStepOutcomeV1, mdbx.SelectedDamageEvidence) {
	t.Helper()
	var out ReplayStepOutcomeV1
	evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() { out = w.call(h) })
	logicalMDBXAssert(t, err == nil, "STEP fixture %d/%d: %v", scenario, rank, err)
	return out, evidence
}

// The next public STEP invocation must classify the cached original cause, with no callback or source query.
func stepCached(t *testing.T, w *stepWorld, h uint64, previous ReplayStepOutcomeV1, result string) {
	t.Helper()
	versions, protects, calls := w.view.versions, w.view.protects, w.view.headerCalls
	again := w.call(h)
	stepTuple(t, again, result, "", "OLD", uint8(previous.Truth), 1, false)
	logicalMDBXAssert(t, stepSameError(again.Err, previous.Err) && again.Needed == nil && versions == w.view.versions && protects == w.view.protects && calls == w.view.headerCalls, "cached STEP changed error identity or reached sources: %+v", again)
	stepReleased(t, w)
}

func TestReplayStepMDBXFixtureBeginAndPrecommit(t *testing.T) {
	for _, row := range []struct {
		name     string
		scenario mdbx.SelectedDamageScenario
		rank     uint8
		class    mdbx.EngineClass
		result   string
		stage    uint8
		write    uint64
	}{
		{"begin_io", mdbx.SelectedDamageBeginEIO, 0, mdbx.EngineIO, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", 1, 0},
		{"begin_full", mdbx.SelectedDamageBeginTxnFull, 0, mdbx.EngineTransaction, "LOCAL_RESOURCE_UNAVAILABLE(storage_transaction)", 1, 0},
		{"write_begin", mdbx.SelectedDamageWriteBeginTxnFull, 0, mdbx.EngineTransaction, "LOCAL_RESOURCE_UNAVAILABLE(storage_transaction)", 1, 1},
		{"put", mdbx.SelectedDamagePutEIO, 1, mdbx.EngineIO, "LOCAL_PERSISTENCE_ERROR(precommit)", 2, 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			before := w.image()
			var key []byte
			if row.scenario == mdbx.SelectedDamagePutEIO {
				parsed, err := ParseBlockBytes(w.bodies[0])
				logicalMDBXAssert(t, err == nil && len(parsed.Txs) == 1 && len(parsed.Txids) == 1 && len(parsed.Txs[0].Outputs) > 0, "genesis PUT source: %v", err)
				logicalMDBXAssert(t, parsed.Txs[0].Outputs[0].CovenantType != 2 && parsed.Txs[0].Outputs[0].CovenantType != 0x103, "genesis PUT output is prunable")
				key = append(binary.BigEndian.AppendUint64(nil, 2), parsed.Txids[0][:]...)
				key = binary.BigEndian.AppendUint32(key, 0)
			}
			out, evidence := stepArmed(t, w, 0, row.scenario, row.rank, key)
			stepTuple(t, out, row.result, "", "OLD", 1, row.stage, false)
			replayEngineClass(t, out.Err, row.class, row.name)
			logicalMDBXAssert(t, evidence.BeginOld == 1 && evidence.BeginWrite == row.write && evidence.Commits == 0 && evidence.Faults == 1 && out.Needed == nil, "actual site: %+v", evidence)
			cached := row.result
			if row.stage == 2 {
				cached = "LOCAL_RESOURCE_UNAVAILABLE(storage_io)"
			}
			stepCached(t, w, 0, out, cached)
			w.step.DiscardV1()
			logicalMDBXAssert(t, !w.step.DiscardV1(), "restart slot retained")
			w.store = w.reopen()
			startupTuple(t, startupRun(w.replayWorld), true, 1, "")
			replaySameImage(t, before, w.image(), row.name)
			stepProgress(t, w, 0, w.authority(), w.call(0))
			stepExactImage(t, w, 0, before, false)
		})
	}
}

func TestReplayStepMDBXFixtureCrossed(t *testing.T) {
	for _, row := range []struct {
		name              string
		scenario          mdbx.SelectedDamageScenario
		truth             uint8
		result, canonical string
		faults            uint64
	}{
		{"OLD", mdbx.SelectedDamageCommitOld, 1, "TERMINAL_PERSISTENCE(old)", "OLD", 1},
		{"NEW", mdbx.SelectedDamageCommitNew, 2, "TERMINAL_PERSISTENCE(new)", "NEW", 1},
		{"unreadable", mdbx.SelectedDamageCommitUnreadable, 3, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", 2},
		{"neither", mdbx.SelectedDamageCommitThird, 3, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			before := w.image()
			out, evidence := stepArmed(t, w, 0, row.scenario, 0, []byte{2})
			stepTuple(t, out, row.result, "", row.canonical, row.truth, 3, false)
			replayCrossedErr(t, out.Err, mdbx.CommitTruth(row.truth), row.name == "unreadable")
			logicalMDBXAssert(t, evidence.Faults == row.faults && evidence.BeginWrite == 1 && evidence.Commits == 1 && evidence.BeginRead == 1 && out.Needed == nil, "crossed evidence: %+v", evidence)
			stepCached(t, w, 0, out, selectedSideCapacity)
			w.step.DiscardV1()
			logicalMDBXAssert(t, !w.step.DiscardV1(), "restart slot retained")
			w.store = w.reopen()
			switch row.name {
			case "OLD":
				startupTuple(t, startupRun(w.replayWorld), true, 1, "")
				replaySameImage(t, before, w.image(), "crossed OLD")
				stepProgress(t, w, 0, w.authority(), w.call(0))
				stepExactImage(t, w, 0, before, false)
			case "neither":
				control := newStepWorld(t, 1, false)
				controlBefore := control.image()
				stepProgress(t, control, 0, control.authority(), control.call(0))
				stepExactImage(t, control, 0, controlBefore, false)
				replaySameImage(t, replayThirdImage(control.image()), w.image(), "neither persisted complete image")
				stepTuple(t, w.call(1), selectedSideIntegrity, "", "OLD", 1, 1, false)
			case "NEW", "unreadable":
				startupTuple(t, startupRun(w.replayWorld), true, 1, "")
				stepExactImage(t, w, 0, before, false)
				before = w.image()
				stepProgress(t, w, 1, w.authority(), w.call(1))
				stepExactImage(t, w, 1, before, false)
			}
			stepReleased(t, w)
		})
	}
}

// All source-site faults are reached by the actual planner; transient absence never becomes a Need.
func TestReplayStepMDBXFixtureSourceReads(t *testing.T) {
	for _, row := range []struct {
		name   string
		h      uint64
		rank   uint8
		key    string
		result string
	}{
		{"authority", 0, 0, "authority", "LOCAL_RESOURCE_UNAVAILABLE(storage_io)"},
		{"path_header", 0, 3, "tip", replayEntryRecovery},
		{"body", 0, 4, "current", replayEntryRecovery},
		{"context", 1, 2, "context", replayEntryRecovery},
		{"context_header", 1, 3, "genesis", replayEntryRecovery},
		{"counter", 1, 0, "counter", replayEntryRecovery},
		{"target_index", 0, 2, "target", replayEntryRecovery},
		{"target_owner", 0, 7, "owner", replayEntryRecovery},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			if row.h > 0 {
				w.prefix(t, row.h)
			}
			key := stepFixtureKey(w, row.key, row.h)
			before := w.image()
			out, evidence := stepArmed(t, w, row.h, mdbx.SelectedDamageGetEIO, row.rank, key)
			stepTuple(t, out, row.result, "", "OLD", 1, 1, false)
			if row.name == "counter" {
				joined, ok := out.Err.(interface{ Unwrap() []error })
				logicalMDBXAssert(t, ok && len(joined.Unwrap()) == 2, "C32d application/native cause order: %T %v", out.Err, out.Err)
				parts := joined.Unwrap()
				failure, ok := parts[0].(*logicalStateFailure)
				logicalMDBXAssert(t, ok && failure.kind == logicalStateFailureUnavailable && failure.cause != nil, "C32d original failure: %T %v", out.Err, out.Err)
				logicalMDBXAssert(t, stepSameError(failure.cause, parts[1]), "C32d nested cause is not the original recorded native object")
				replayEngineClass(t, parts[1], mdbx.EngineIO, row.name)
			} else {
				replayEngineClass(t, out.Err, mdbx.EngineIO, row.name)
			}
			logicalMDBXAssert(t, out.Needed == nil && evidence.BeginWrite == 0 && evidence.Commits == 0 && evidence.OldGets[row.rank] > 0 && evidence.Faults == 1, "fault site/projection: %+v %+v", out, evidence)
			cached := "LOCAL_RESOURCE_UNAVAILABLE(storage_io)"
			stepCached(t, w, row.h, out, cached)
			w.step.DiscardV1()
			logicalMDBXAssert(t, !w.step.DiscardV1(), "restart slot retained")
			w.store = w.reopen()
			startupTuple(t, startupRun(w.replayWorld), true, 1, "")
			replaySameImage(t, before, w.image(), row.name)
			stepProgress(t, w, row.h, w.authority(), w.call(row.h))
			stepExactImage(t, w, row.h, before, false)
		})
	}
}

func stepFixtureKey(w *stepWorld, name string, h uint64) []byte {
	switch name {
	case "authority":
		return []byte{2}
	case "tip":
		return w.hashes[len(w.hashes)-1][:]
	case "current":
		return w.hashes[h][:]
	case "genesis":
		return w.hashes[0][:]
	case "context":
		return stepKey(2, h-1)
	case "counter":
		return binary.BigEndian.AppendUint64([]byte{0x10}, 2)
	case "target":
		return stepKey(2, h)
	case "owner":
		return append(binary.BigEndian.AppendUint64(nil, 2), w.hashes[h][:]...)
	}
	panic("unknown fixed test site")
}

func TestReplayStepMDBXFixtureEndpoint(t *testing.T) {
	for _, scenario := range []uint8{1, 2, 3} {
		t.Run(fmt.Sprint(scenario), func(t *testing.T) {
			w := newStepWorld(t, 1, true)
			w.prefix(t, 1)
			before := w.image()
			versions, protects, calls := w.view.versions, w.view.protects, w.view.headerCalls
			var out ReplayStepOutcomeV1
			evidence, err := mdbx.FixtureCanonicalTipStep(w.store, scenario, nil, nil, false, func() { out = w.call(1) })
			logicalMDBXAssert(t, err == nil, "endpoint adapter: %v", err)
			if scenario == 1 {
				stepTuple(t, out, "", "", "NEW", 2, 3, true)
				logicalMDBXAssert(t, evidence.Queries == 3 && evidence.Opens == 3 && evidence.Gets == 6 && evidence.Closes == 3 && evidence.Faults == 0, "B38 endpoint census: %+v", evidence)
				stepExactImage(t, w, 1, before, false)
			} else {
				result, class := selectedSideCanonical, mdbx.EngineIO
				code, diagnostic := 5, "error 5"
				if scenario == 3 {
					result, class = selectedSideInvariant, mdbx.EngineLocalInvariant
					code, diagnostic = -30779, "mdbx_cursor_get returned invalid result shape"
				}
				stepTuple(t, out, result, "", "OLD", 1, 1, false)
				e, ok := out.Err.(*mdbx.EngineError)
				logicalMDBXAssert(t, ok && e.Class == class && e.Operation == "prefix-page" && out.Needed == nil && evidence.Queries == 1 && evidence.Opens == 1 && evidence.Gets == 1 && evidence.Closes == 1 && evidence.Faults == 1, "C31 endpoint fault: %+v %+v", e, evidence)
				logicalMDBXAssert(t, e.Code == code && e.Diagnostic == diagnostic && e.Cause == nil && !e.ReopenRequired, "C31 exact endpoint error: %+v", e)
				logicalMDBXAssert(t, versions == w.view.versions && protects == w.view.protects && calls == w.view.headerCalls, "C31 endpoint failure reached PATH")
				cached := "LOCAL_RESOURCE_UNAVAILABLE(storage_io)"
				if scenario == 3 {
					cached = selectedSideInvariant
				}
				stepCached(t, w, 1, out, cached)
				stepReleased(t, w)
				w.step.DiscardV1()
				logicalMDBXAssert(t, !w.step.DiscardV1(), "restart slot retained")
				w.store = w.reopen()
				startupTuple(t, startupRun(w.replayWorld), true, 1, "")
				replaySameImage(t, before, w.image(), "endpoint fault")
				stepProgress(t, w, 1, w.authority(), w.call(1))
				stepExactImage(t, w, 1, before, false)
			}
		})
	}
}

func TestReplayStepMDBXFixtureEndpointAndContextDrift(t *testing.T) {
	for _, generation := range []uint64{1, 2} {
		for _, offset := range []int{32, 63, 103} {
			for _, scenario := range []uint8{4, 5, 6} {
				t.Run(fmt.Sprintf("g%d_o%d_s%d", generation, offset, scenario), func(t *testing.T) {
					w := newStepWorld(t, 1, true)
					w.prefix(t, 1)
					before := w.image()
					key := stepKey(generation, 0)
					value, present := stepRead(t, w.store, 2, key)
					logicalMDBXAssert(t, present && len(value) == 104, "drift setup")
					value[offset] ^= 1
					var out ReplayStepOutcomeV1
					evidence, err := mdbx.FixtureCanonicalTipStep(w.store, scenario, key, value, true, func() { out = w.call(1) })
					logicalMDBXAssert(t, err == nil && evidence.Drift == 1, "full 104-byte drift: %v %+v", err, evidence)
					stage, queries, commits := uint8(1), uint32(2), uint32(0)
					result, canon, truth := replayEntryStale, "OLD", uint8(1)
					if scenario == 5 {
						stage, queries, result = 2, 3, selectedSidePrecommit
					}
					if scenario == 6 {
						stage, queries, commits, result, canon, truth = 3, 4, 1, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", 3
					}
					// Context inequality stops scoped proof before its later endpoint query; crossed proof still visits it.
					if generation == 2 && scenario != 6 {
						queries--
					}
					stepTuple(t, out, result, "", canon, truth, stage, false)
					if scenario == 6 {
						commit, ok := out.Err.(*mdbx.CommitError)
						logicalMDBXAssert(t, ok && commit.Truth == 3 && commit.ReadbackCause == nil, "K12 exact crossed error: %T %+v", out.Err, out.Err)
						e, ok := commit.Cause.(*mdbx.EngineError)
						logicalMDBXAssert(t, ok && e.Class == "Capacity" && e.Operation == "update" && e.Code == 28 && e.Diagnostic == "error 28" && e.Cause == nil && !e.ReopenRequired, "K12 original commit cause: %+v", e)
					} else {
						diagnostic := "OLD/write snapshot mismatch"
						if scenario == 5 {
							diagnostic = "final update image mismatch"
						}
						e, ok := out.Err.(*mdbx.EngineError)
						logicalMDBXAssert(t, ok && e.Class == "StateMismatch" && e.Operation == "update" && e.Code == -30779 && e.Diagnostic == diagnostic && e.Cause == nil && !e.ReopenRequired, "K10 exact proof mismatch: %+v", e)
					}
					logicalMDBXAssert(t, evidence.Queries == queries && evidence.Opens == queries && evidence.Closes == queries && evidence.Gets == queries*2 && evidence.Commits == commits && out.Needed == nil, "K10/K12 exact query/commit path: %+v", evidence)
					stepReleased(t, w)
					w.store = w.reopen()
					if scenario == 5 {
						replaySameImage(t, before, w.image(), "final proof aborted drift")
					}
					if scenario == 4 {
						for i := range before {
							if bytes.Equal(before[i].Key, append([]byte{2}, key...)) {
								before[i].Value = value
							}
						}
						replaySameImage(t, before, w.image(), "prewrite only fixture drift")
					}
					if scenario == 6 {
						replayCrossedErr(t, out.Err, mdbx.CommitTruthUnknown, false)
						stepExactImageExtra(t, w, 1, before, false, nil, []mdbx.PrefixRow{{Key: append([]byte{2}, key...), Value: value}})
					}
					if scenario != 5 {
						equal, err := mdbx.FixtureRawRowEqual(w.store, 2, key, value)
						logicalMDBXAssert(t, err == nil && equal, "persisted full 104-byte selected drift: %v", err)
					}
				})
			}
		}
	}
}

func TestReplayStepMDBXFixtureJoinedOriginalOrder(t *testing.T) {
	for _, abort := range []bool{false, true} {
		t.Run(fmt.Sprint(abort), func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			before := w.image()
			scenario := mdbx.SelectedDamageGetEIO
			if abort {
				scenario = mdbx.SelectedDamageGetAbortEIO
			}
			out, evidence := stepArmed(t, w, 0, scenario, 3, w.hashes[1][:])
			stepTuple(t, out, replayEntryRecovery, "", "OLD", 1, 1, false)
			if abort {
				joined, ok := out.Err.(interface{ Unwrap() []error })
				logicalMDBXAssert(t, ok, "native joined cause lost: %T", out.Err)
				causes := joined.Unwrap()
				logicalMDBXAssert(t, len(causes) == 2 && causes[0] != nil && causes[1] != nil, "original cause cardinality")
				first, second := causes[0].(*mdbx.EngineError), causes[1].(*mdbx.EngineError)
				logicalMDBXAssert(t, first.Operation == "get" && first.Class == mdbx.EngineIO && second.Operation == "abort" && second.Class == mdbx.EngineIO && evidence.Faults == 2, "original cause order: %+v %+v %+v", first, second, evidence)
			} else {
				replayEngineClass(t, out.Err, mdbx.EngineIO, "direct original cause")
			}
			stepCached(t, w, 0, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)")
			w.store = w.reopen()
			replaySameImage(t, before, w.image(), "joined source/abort")
		})
	}
}

func TestReplayStepMDBXFixtureSentinelAbort(t *testing.T) {
	w := newStepWorld(t, 1, false)
	stepDrop(w, 3, w.hashes[1][:])
	before := w.image()
	out, evidence := stepArmed(t, w, 0, mdbx.SelectedDamageAbortEIO, 0, nil)
	stepTuple(t, out, replayEntryRecovery, "", "OLD", 1, 1, false)
	logicalMDBXAssert(t, evidence.Faults == 1 && evidence.Commits == 0 && out.Needed != nil && out.Needed.Kind == 1 && out.Needed.Hash == w.hashes[1], "original missing observation plus abort: %+v %+v", out, evidence)
	joined, ok := out.Err.(interface{ Unwrap() []error })
	logicalMDBXAssert(t, ok && len(joined.Unwrap()) == 2, "original refusal/abort cardinality: %T %v", out.Err, out.Err)
	parts := joined.Unwrap()
	failure, ok := parts[0].(*selectedSideFailure)
	logicalMDBXAssert(t, ok && failure.result == "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)" && failure.cause != nil && failure.cause.Error() == "replay path ancestry header unavailable", "original refusal wrapper/cause: %T %v", parts[0], parts[0])
	abort, ok := parts[1].(*mdbx.EngineError)
	logicalMDBXAssert(t, ok && abort.Operation == "abort" && abort.Class == mdbx.EngineIO && abort.Code == 5 && abort.Diagnostic == "error 5" && abort.Cause == nil && !abort.ReopenRequired && w.step.path.slot == nil, "original native abort order and partial hold: %+v", abort)
	stepCached(t, w, 0, out, replayEntryRecovery)
	w.store = w.reopen()
	replaySameImage(t, before, w.image(), "sentinel refusal joined abort")
}

// This read reaches the connector's original R1 carrier. It has no Unwrap method; its nested cause stays intact.
func TestReplayStepMDBXFixtureInputCarrier(t *testing.T) {
	for _, row := range []struct {
		name             string
		value            []byte
		fault            bool
		decision, result string
	}{
		{"native_io", nil, true, "", "LOCAL_RESOURCE_UNAVAILABLE(state_view_read)"},
		{"positive_decode", append(make([]byte, 19), 2), false, "target local", ""},
		{"native_width", make([]byte, 19), false, "", selectedSideIntegrity},
	} {
		t.Run(row.name, func(t *testing.T) {
			op := Outpoint{Txid: hashWithPrefix(0xac), Vout: 2}
			w := newStepWorld(t, 1, false, inputViewTx(1, op))
			w.prefix(t, 1)
			key := append(binary.BigEndian.AppendUint64(nil, 2), op.Txid[:]...)
			key = binary.BigEndian.AppendUint32(key, op.Vout)
			var before []mdbx.PrefixRow
			var restore []byte
			if row.name == "native_width" {
				restore = make([]byte, 20)
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 1, key, restore) == nil, "native width readable census control")
				before = w.image()
			}
			if !row.fault {
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 1, key, row.value) == nil, "positive native row setup")
			}
			if before == nil {
				before = w.image()
			}
			var invocation *replayStepInvocation
			if row.fault {
				evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageGetEIO, 1, key, func() { invocation = replayStepRun(w.step, w.store, w.owner, w.bodies[1]) })
				logicalMDBXAssert(t, err == nil && evidence.Faults == 1 && evidence.OldGets[1] == 1 && evidence.Commits == 0, "R1 exact native site: %v %+v", err, evidence)
			} else {
				invocation = replayStepRun(w.step, w.store, w.owner, w.bodies[1])
			}
			stepTuple(t, invocation.out, row.result, row.decision, "OLD", 1, 1, row.decision != "")
			incoming := invocation.out.Err
			var recorded error
			if row.decision != "" {
				incoming = invocation.observation.incoming
			}
			if row.decision == "" {
				joined, ok := incoming.(interface{ Unwrap() []error })
				logicalMDBXAssert(t, ok && len(joined.Unwrap()) == 2, "R1 application/native cause order: %T %v", incoming, incoming)
				parts := joined.Unwrap()
				incoming, recorded = parts[0], parts[1]
			}
			carrier, ok := incoming.(*blockInputViewReadError)
			logicalMDBXAssert(t, ok && carrier != nil && carrier.txIndex == 1 && carrier.inputIndex == 0 && carrier.outpoint == op && carrier.failure != nil && carrier.failure.cause != nil, "actual original R1 carrier: %T %+v", incoming, carrier)
			_, unwrap := any(carrier).(interface{ Unwrap() error })
			logicalMDBXAssert(t, !unwrap, "carrier acquired an Unwrap API")
			if row.decision != "" {
				logicalMDBXAssert(t, invocation.observation.failure == carrier.failure && stepSameError(invocation.observation.cause, carrier.failure.cause), "C31 outer/nested cause identity")
				replaySameImage(t, before, w.image(), "positive decode clean OLD")
			} else {
				kind, class := logicalStateFailureStoreIntegrity, mdbx.EngineIntegrity
				if row.fault {
					kind, class = logicalStateFailureUnavailable, mdbx.EngineIO
				}
				logicalMDBXAssert(t, carrier.failure.kind == kind && stepSameError(carrier.failure.cause, recorded), "C31 original nested/recorded native cause identity")
				replayEngineClass(t, recorded, class, row.name)
				cached := row.result
				stepCached(t, w, 1, invocation.out, cached)
				w.store = w.reopen()
				if restore != nil {
					equal, err := mdbx.FixtureRawRowEqual(w.store, 1, key, row.value)
					logicalMDBXAssert(t, err == nil && equal, "raw malformed width preimage changed: %v", err)
					logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 1, key, restore) == nil, "restore census control after exact raw assertion")
				}
				replaySameImage(t, before, w.image(), "R1 fault OLD")
			}
			stepReleased(t, w)
		})
	}
}

func TestReplayStepMDBXFixtureRetentionEndpoint(t *testing.T) {
	for _, row := range []struct {
		name   string
		active bool
		h      uint64
		limit  uint64
	}{
		{"empty", false, 0, 63},
		{"present", true, 1, 31},
		{"maximum", false, 0, 137438953471},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := newStepWorld(t, 1, row.active)
			if row.h != 0 {
				w.prefix(t, row.h)
			}
			if row.name == "maximum" {
				w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
					a.Replay.Target.TipHeight = 0xffffffff
					a.Replay.Target.CumulativeChainwork = sideWorldWork(0x100000000)
				})
			}
			w.step = NewReplayStepOwnerV1(ReplayStepContextV1{Genesis: w.genesis}, w.view, row.limit)
			w.view.owner = w.step.path
			before := w.image()
			versions, protects, calls := w.view.versions, w.view.protects, w.view.headerCalls
			var out ReplayStepOutcomeV1
			evidence, err := mdbx.FixtureCanonicalTipStep(w.store, 1, nil, nil, false, func() { out = w.call(row.h) })
			logicalMDBXAssert(t, err == nil, "retention endpoint adapter: %v", err)
			stepRefusal(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "replay path retention exceeds its limit")
			logicalMDBXAssert(t, evidence == (mdbx.CanonicalTipStepFixtureEvidence{Opens: 1, Gets: 2, Closes: 1, Queries: 1}), "RC1/RC2 one source, no committing proof: %+v", evidence)
			logicalMDBXAssert(t, out.Needed == nil && w.step.path.slot == nil && !w.step.DiscardV1() && versions == w.view.versions && protects == w.view.protects && calls == w.view.headerCalls, "RC1/RC2 refusal reached PATH or retained a hold: %+v", out)
			replaySameImage(t, before, w.image(), "retention refusal has no STEP effects")
			stepReleased(t, w)
		})
	}
}

func TestReplayStepMDBXFixtureGrantAndCardinality(t *testing.T) {
	w := newStepWorld(t, 1, false)
	before := w.image()
	var out ReplayStepOutcomeV1
	var evidence mdbx.SelectedDamageEvidence
	var endpoint mdbx.CanonicalTipStepFixtureEvidence
	err := w.owner.WithReservation(1, func() error {
		var fixtureErr error
		evidence, fixtureErr = mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() {
			var endpointErr error
			endpoint, endpointErr = mdbx.FixtureCanonicalTipStep(w.store, 1, nil, nil, false, func() { out = w.call(0) })
			logicalMDBXAssert(t, endpointErr == nil, "denied grant endpoint adapter: %v", endpointErr)
		})
		return fixtureErr
	})
	logicalMDBXAssert(t, err == nil, "aggregate grant fixture: %v", err)
	stepTuple(t, out, selectedSideCapacity, "", "OLD", 1, 1, true)
	logicalMDBXAssert(t, endpoint == (mdbx.CanonicalTipStepFixtureEvidence{}) && out.Needed == nil, "RC3 grant denial queried endpoint: %+v", endpoint)
	logicalMDBXAssert(t, evidence.OldGets[0] == 1 && evidence.OldGets[1] == 0 && evidence.OldGets[2] == 0 && evidence.OldGets[3] == 0 && evidence.BeginWrite == 0 && evidence.Commits == 0 && w.view.protects == 0 && w.step.path.slot == nil, "RC3 authority-only denial: %+v", evidence)
	replaySameImage(t, before, w.image(), "aggregate grant denial")
	stepProgress(t, w, 0, w.authority(), w.call(0))
	w = newStepWorld(t, 1, false, inputViewTx(0, Outpoint{Txid: hashWithPrefix(0xbd)}))
	w.prefix(t, 1)
	before = w.image()
	out, evidence = stepArmed(t, w, 1, mdbx.SelectedDamageProbeOnly, 0, nil)
	stepTuple(t, out, "", "consensus invalid", "OLD", 1, 1, true)
	// No writer starts; the OLD abort probes the held grant once before and once after native cleanup.
	logicalMDBXAssert(t, evidence.OldGets[1] == 0 && evidence.BeginWrite == 0 && evidence.Commits == 0 && evidence.OldAborts == 1 && evidence.Probes == 2 && evidence.ProbeDenied == 2 && evidence.ProbeRan == 0, "C27/C30/B37 first validation before UTXO reads, full lane: %+v", evidence)
	replaySameImage(t, before, w.image(), "first consensus observation")
	stepReleased(t, w)
}

func TestReplayStepMDBXFixtureNoArtifactRewrite(t *testing.T) {
	for _, rank := range []uint8{3, 4, 5} {
		t.Run(fmt.Sprint(rank), func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			if rank == 4 {
				stepSeedArtifact(w, 4, 0, w.bodies[0])
			}
			if rank == 5 {
				stepSeedArtifact(w, 5, 0, stepManifest(0, 0, 1, 0))
			}
			before := w.image()
			var out ReplayStepOutcomeV1
			key := w.hashes[0][:]
			if rank == 5 {
				key = append(bytes.Clone(key), 0)
			}
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamagePutEIO, rank, key, func() { out = w.call(0) })
			logicalMDBXAssert(t, err != nil && err.Error() == "selected damage fixture site was not reached exactly as armed" && evidence.Faults == 0 && evidence.BeginWrite == 1 && evidence.Commits == 1, "B2/B3/B4 actual unchanged-row PUT site must remain unreachable: %v %+v", err, evidence)
			stepTuple(t, out, "", "", "NEW", 2, 3, true)
			stepExactImage(t, w, 0, before, false)
			stepReleased(t, w)
		})
	}
}

func TestReplayStepMDBXFixtureMisnamedHeader(t *testing.T) {
	w := newStepWorld(t, 1, false)
	value := bytes.Clone(w.headers[0][:])
	value[68] ^= 1
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 3, w.hashes[0][:], value) == nil, "seed misnamed header")
	equal, err := mdbx.FixtureRawRowEqual(w.store, 3, w.hashes[0][:], value)
	logicalMDBXAssert(t, err == nil && equal, "misnamed header raw seed readback: %v", err)
	before := w.image()
	out, evidence := stepArmed(t, w, 0, mdbx.SelectedDamageProbeOnly, 0, nil)
	stepTuple(t, out, selectedSideIntegrity, "", "OLD", 1, 1, false)
	logicalMDBXAssert(t, out.Needed == nil && evidence.BeginWrite == 0 && evidence.Commits == 0 && evidence.OldGets[1] == 0 && evidence.OldGets[4] == 0 && evidence.OldGets[5] == 0, "C2 misnamed header precedes body/state/undo: %+v %+v", out, evidence)
	stepReleased(t, w)
	w.store = w.reopen()
	equal, err = mdbx.FixtureRawRowEqual(w.store, 3, w.hashes[0][:], value)
	logicalMDBXAssert(t, err == nil && equal, "misnamed header exact preimage changed: %v", err)
	replaySameImage(t, before, w.image(), "header_misnamed")
}

func TestReplayStepMDBXFixtureUndoFamily(t *testing.T) {
	for _, kind := range []string{"missing", "extra", "version", "width", "wrong_entry", "body_header"} {
		t.Run(kind, func(t *testing.T) {
			w, _, oldValue, entryKey := stepSpentWorld(t)
			manifestKey := append(bytes.Clone(w.hashes[1][:]), 0)
			stepSeedArtifact(w, 5, 1, stepManifest(1, 0, 3, 1))
			if kind != "missing" {
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 5, entryKey, oldValue) == nil, "seed complete family")
			}
			var before []mdbx.PrefixRow
			if kind == "width" {
				before = w.image()
			}
			switch kind {
			case "extra":
				key := bytes.Clone(entryKey)
				key[76] ^= 1
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 5, key, oldValue) == nil, "seed extra member")
			case "version":
				value := stepManifest(1, 0, 3, 1)
				value[0] = 2
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 5, manifestKey, value) == nil, "seed malformed manifest")
			case "width":
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 5, manifestKey, make([]byte, 32)) == nil, "seed malformed width")
			case "wrong_entry":
				value := bytes.Clone(oldValue)
				value[0] ^= 1
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 5, entryKey, value) == nil, "seed differing complete row")
			case "body_header":
				value := bytes.Clone(w.bodies[1])
				value[108] ^= 1
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 4, w.hashes[1][:], value) == nil, "seed positively misbound body")
			}
			if before == nil {
				before = w.image()
			}
			out := w.call(1)
			stepTuple(t, out, selectedSideIntegrity, "", "OLD", 1, 1, false)
			logicalMDBXAssert(t, out.Needed == nil && w.step.path.slot != nil, "K7 comparison lost completed hold or fabricated Need")
			stepReleased(t, w)
			w.store = w.reopen()
			if kind == "width" {
				equal, err := mdbx.FixtureRawRowEqual(w.store, 5, manifestKey, make([]byte, 32))
				logicalMDBXAssert(t, err == nil && equal, "malformed family width exact preimage changed")
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 5, manifestKey, stepManifest(1, 0, 3, 1)) == nil, "restore readable family census control")
			}
			replaySameImage(t, before, w.image(), "whole-family rejection "+kind)
		})
	}
}

func TestReplayStepMDBXFixtureOldActive(t *testing.T) {
	for _, kind := range []string{"absent_header", "parent", "work", "predecessor", "native_io"} {
		t.Run(kind, func(t *testing.T) {
			w := newStepWorld(t, 15120, true)
			y := stepActiveOther(t, w)
			w.prefix(t, 1)
			stepSeedArtifact(w, 4, 1, w.bodies[1])
			stepSeedArtifact(w, 5, 1, stepManifest(1, 0, 1, 0))
			switch kind {
			case "absent_header":
				stepDrop(w, 3, y[:])
			case "parent", "work":
				value, _ := stepRead(t, w.store, 2, stepKey(1, 1))
				if kind == "parent" {
					value[32] ^= 1
				} else {
					value[103] ^= 1
				}
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, stepKey(1, 1), value) == nil, "seed old health contradiction")
			case "predecessor":
				value, _ := stepRead(t, w.store, 2, stepKey(1, 0))
				value[0] ^= 1
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, stepKey(1, 0), value) == nil, "seed predecessor contradiction")
			}
			before := w.image()
			var out ReplayStepOutcomeV1
			if kind == "native_io" {
				var evidence mdbx.SelectedDamageEvidence
				out, evidence = stepArmed(t, w, 1, mdbx.SelectedDamageGetEIO, 3, y[:])
				logicalMDBXAssert(t, evidence.Faults == 1 && evidence.BeginWrite == 0 && evidence.Commits == 0, "canonical old health fault")
				stepTuple(t, out, selectedSideCanonical, "", "OLD", 1, 1, false)
				replayEngineClass(t, out.Err, mdbx.EngineIO, "C10 old-active")
			} else {
				out = w.call(1)
				stepTuple(t, out, selectedSideIntegrity, "", "OLD", 1, 1, false)
			}
			logicalMDBXAssert(t, out.Needed == nil, "old-active damage became acquisition")
			stepReleased(t, w)
			w.store = w.reopen()
			replaySameImage(t, before, w.image(), "C7-C10/C22 "+kind)
		})
	}
}

func TestReplayStepMDBXFixtureCardinality(t *testing.T) {
	for _, variant := range []string{"absent", "io", "nonce", "creation", "earlier_qualification"} {
		t.Run(variant, func(t *testing.T) {
			later, _, _, _, err := ParseTx(coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1))
			logicalMDBXAssert(t, err == nil, "extra exact coinbase")
			ordinary := inputViewTx(1, Outpoint{Txid: hashWithPrefix(0xb1)})
			if variant == "nonce" {
				ordinary.TxNonce = 0
			}
			w := newStepWorld(t, 1, false, ordinary, later)
			w.prefix(t, 1)
			if variant == "creation" {
				input := inputViewRewriteFirst(t, inputViewBlock(t, 1, 1, ordinary, later), func(tx *Tx) { tx.Outputs[0].CovenantType = COV_TYPE_VAULT })
				stepReplaceRaw(t, w, stepFixHeader(t, w, input.BlockBytes, w.lastTime+240))
			}
			if variant == "earlier_qualification" {
				stepReplaceRaw(t, w, stepFixHeader(t, w, bytes.Clone(w.bodies[1]), w.lastTime))
			}
			before := w.image()
			var invocation *replayStepInvocation
			scenario, rank := mdbx.SelectedDamageProbeOnly, uint8(0)
			var key []byte
			if variant == "io" {
				scenario, rank = mdbx.SelectedDamageGetEIO, 1
				op := Outpoint{Txid: hashWithPrefix(0xb1)}
				key = append(binary.BigEndian.AppendUint64(nil, 2), op.Txid[:]...)
				key = binary.BigEndian.AppendUint32(key, 0)
			}
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() { invocation = replayStepRun(w.step, w.store, w.owner, w.bodies[1]) })
			unreached := variant == "io" && err != nil && err.Error() == "selected damage fixture site was not reached exactly as armed"
			logicalMDBXAssert(t, (err == nil || unreached) && evidence.Faults == 0 && evidence.OldGets[1] == 0 && evidence.BeginWrite == 0 && evidence.Commits == 0, "C30 first cardinality/qualification before inputs: %v %+v", err, evidence)
			stepTuple(t, invocation.out, "", "consensus invalid", "OLD", 1, 1, true)
			code := ErrorCode("BLOCK_ERR_COINBASE_INVALID")
			if variant == "earlier_qualification" {
				code = "BLOCK_ERR_TIMESTAMP_OLD"
			}
			original, ok := invocation.observation.incoming.(*TxError)
			logicalMDBXAssert(t, ok && original.Code == code && invocation.observation.h == 1 && invocation.observation.x == w.hashes[1], "literal original cardinality code/h/x: %+v", invocation.observation)
			replaySameImage(t, before, w.image(), variant)
			stepReleased(t, w)
		})
	}
}

func TestReplayStepMDBXFixtureQualifierBindingPriority(t *testing.T) {
	for _, source := range []string{"supplied", "stored", "bound_control"} {
		t.Run(source, func(t *testing.T) {
			w := newStepWorld(t, 1, false, inputViewTx(1, Outpoint{Txid: hashWithPrefix(0xb2)}))
			w.prefix(t, 1)
			raw := stepFixHeader(t, w, bytes.Clone(w.bodies[1]), w.lastTime)
			stepReplaceRaw(t, w, raw)
			if source != "bound_control" {
				raw[len(raw)-1] ^= 1
			}
			if source == "stored" {
				stepSeedArtifact(w, 4, 1, raw)
			}
			before := w.image()
			var invocation *replayStepInvocation
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { invocation = replayStepRun(w.step, w.store, w.owner, raw) })
			logicalMDBXAssert(t, err == nil && evidence.OldGets[1] == 0 && evidence.Commits == 0 && evidence.BeginWrite == 0, "C34 binding-only recheck order: %v %+v", err, evidence)
			switch source {
			case "supplied":
				stepRefusal(t, invocation.out, "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)", "replay block bytes unavailable or unbound")
				logicalMDBXAssert(t, invocation.out.Needed != nil && *invocation.out.Needed == (ReplayStepNeedV1{Kind: 2, Height: 1, Hash: w.hashes[1]}) && invocation.observation.incoming == nil, "unbound supplied did not erase invalidity observation")
			case "stored":
				stepTuple(t, invocation.out, selectedSideIntegrity, "", "OLD", 1, 1, false)
				logicalMDBXAssert(t, invocation.out.Needed == nil && invocation.observation.incoming == nil, "unbound stored exposed local invalidity")
				w.store = w.reopen()
			case "bound_control":
				stepTuple(t, invocation.out, "", "consensus invalid", "OLD", 1, 1, true)
				e, ok := invocation.observation.incoming.(*TxError)
				logicalMDBXAssert(t, ok && e.Code == "BLOCK_ERR_TIMESTAMP_OLD" && invocation.observation.h == 1 && invocation.observation.x == w.hashes[1], "bound earlier qualifier literal code/h/x")
			}
			replaySameImage(t, before, w.image(), source)
			stepReleased(t, w)
		})
	}
}

func TestReplayStepMDBXFixtureFullContextWindow(t *testing.T) {
	for _, h := range []uint64{12, 10080} {
		first := uint64(1)
		if h == 10080 {
			first = 0
		}
		for _, changed := range []uint64{first, h - 1} {
			for _, scenario := range []uint8{4, 5, 6} {
				t.Run(fmt.Sprintf("h%d_k%d_s%d", h, changed, scenario), func(t *testing.T) {
					w := newStepWorld(t, int(h), true)
					w.prefix(t, h)
					before := w.image()
					key := stepKey(2, changed)
					value, exists := stepRead(t, w.store, 2, key)
					logicalMDBXAssert(t, exists && len(value) == 104, "actual full context row")
					value[63] ^= 1
					var out ReplayStepOutcomeV1
					evidence, err := mdbx.FixtureCanonicalTipStep(w.store, scenario, key, value, true, func() { out = w.call(h) })
					logicalMDBXAssert(t, err == nil && evidence.Drift == 1 && out.Needed == nil, "B38 complete target descriptor: %v %+v", err, evidence)
					if scenario == 4 {
						stepTuple(t, out, replayEntryStale, "", "OLD", 1, 1, false)
						for i := range before {
							if bytes.Equal(before[i].Key, append([]byte{2}, key...)) {
								before[i].Value = value
							}
						}
					} else if scenario == 5 {
						stepTuple(t, out, selectedSidePrecommit, "", "OLD", 1, 2, false)
					} else {
						stepTuple(t, out, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "", "UNKNOWN", 3, 3, false)
					}
					stepReleased(t, w)
					w.store = w.reopen()
					if scenario != 6 {
						replaySameImage(t, before, w.image(), "full target window equality")
					}
					if scenario == 6 {
						replayCrossedErr(t, out.Err, mdbx.CommitTruthUnknown, false)
						logicalMDBXAssert(t, evidence.Commits == 1, "full target window STEP commit count: %+v", evidence)
						stepExactImageExtra(t, w, h, before, false, nil, []mdbx.PrefixRow{{Key: append([]byte{2}, key...), Value: value}})
					}
					if scenario != 5 {
						equal, err := mdbx.FixtureRawRowEqual(w.store, 2, key, value)
						logicalMDBXAssert(t, err == nil && equal, "persisted full context selected drift: %v", err)
					}
				})
			}
		}
	}
	w := newStepWorld(t, 12, false)
	w.prefix(t, 12)
	stepDrop(w, 3, w.hashes[1][:])
	key := stepKey(2, 11)
	value, _ := stepRead(t, w.store, 2, key)
	value[32] ^= 1
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, key, value) == nil, "later positive context contradiction")
	before := w.image()
	out := w.call(12)
	stepRefusal(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "target context named header absent or misnamed")
	logicalMDBXAssert(t, out.Needed == nil, "B30 ascending context first observation invented Need")
	w.store = w.reopen()
	replaySameImage(t, before, w.image(), "ascending complete target context")
	stepReleased(t, w)
}

func TestReplayStepMDBXFixtureOneBelowClassification(t *testing.T) {
	for _, presence := range []string{"both", "neither", "undo_only", "body_only", "exact_old", "pre_genesis"} {
		t.Run(presence, func(t *testing.T) {
			w := newStepWorld(t, 15120, presence != "pre_genesis")
			y := w.hashes[1]
			if presence == "exact_old" {
				// newStepWorld already admitted X's immutable header; seed only the active index/owner pair.
				rows := w.canonicalRows(1, 1)
				w.apply(rows[1:]...)
			} else if presence != "pre_genesis" {
				y = stepActiveOther(t, w)
			}
			w.prefix(t, 1)
			if presence == "both" || presence == "body_only" || presence == "exact_old" || presence == "pre_genesis" {
				stepSeedArtifact(w, 4, 1, w.bodies[1])
			}
			if presence == "both" || presence == "undo_only" || presence == "exact_old" || presence == "pre_genesis" {
				stepSeedArtifact(w, 5, 1, stepManifest(1, 0, 1, 0))
			}
			before := w.image()
			logicalMDBXAssert(t, w.step.DiscardV1() && !w.step.DiscardV1(), "classification restart hold release")
			w.store = w.reopen()
			startupTuple(t, startupRun(w.replayWorld), true, 1, "")
			replaySameImage(t, before, w.image(), "old-active legal startup "+presence)
			out, evidence := stepArmed(t, w, 1, mdbx.SelectedDamageProbeOnly, 0, nil)
			stepTuple(t, out, "", "", "NEW", 2, 3, true)
			// At h1, B=1/U=13681. Exact X reuses its own header; different Y adds one; PRE_GENESIS adds none.
			want := uint64(1)
			if presence == "neither" || presence == "body_only" || presence == "exact_old" || presence == "pre_genesis" {
				want = 0
			}
			// Cold path: 15120 descent/own headers + one context header + six admission/preflight/final Gets.
			// One classification adds Y's header at source and the same three consulted-proof phases.
			logicalMDBXAssert(t, evidence.OldGets[3] == 15127+4*want && evidence.Commits == 1 && evidence.ProbeRan == 0 && evidence.Probes == evidence.ProbeDenied, "B13/B14/B21 one or zero OLD health classification: %+v y=%x", evidence, y)
			stepExactImage(t, w, 1, before, presence != "neither" && presence != "exact_old")
			undo := []byte(nil)
			if presence == "exact_old" {
				undo = stepManifest(1, 0, 1, 0)
			}
			stepArtifact(t, w, 4, 1, w.bodies[1], true)
			stepArtifact(t, w, 5, 1, undo, presence == "exact_old")
			stepReleased(t, w)
			before = w.image()
			stepProgress(t, w, 2, w.authority(), w.call(2))
			stepExactImage(t, w, 2, before, false)
		})
	}
}

func TestReplayStepMDBXFixtureBelowMismatch(t *testing.T) {
	for _, row := range []struct {
		name  string
		tip   int
		rank  uint8
		cause string
	}{
		{"body", 15121, 4, "stored replay body does not bind the target"},
		{"undo", 15120, 5, "undo value differs"},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := newStepWorld(t, row.tip, true)
			stepActiveOther(t, w)
			w.prefix(t, 1)
			stepSeedArtifact(w, 4, 1, w.bodies[1])
			stepSeedArtifact(w, 5, 1, stepManifest(1, 0, 1, 0))
			value := bytes.Clone(w.bodies[1])
			if row.rank == 4 {
				value[122] = 1 // Same header/framing; tx_nonce changes the committed core.
			} else {
				value = stepManifest(1, 0, 1, 0)
				value[24] = 1 // Pre-block generated value must be zero at h1.
			}
			stepSeedArtifact(w, row.rank, 1, value)
			before := w.image()
			out, evidence := stepArmed(t, w, 1, mdbx.SelectedDamageProbeOnly, 0, nil)
			stepRefusal(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", row.cause)
			// h1 is below B=2 at tip15121 and below U=13681 at tip15120.
			// Only own/context headers are read; canonical-owner Gets would start old-active classification.
			logicalMDBXAssert(t, out.Needed == nil && evidence.OldGets[3] == 2 && evidence.OldGets[7] == 0 && evidence.BeginWrite == 0 && evidence.BeginRead == 0 && evidence.Commits == 0 && evidence.Deletes == 0, "C2-C20 below-promise mismatch proceeded: %+v %+v", out, evidence)
			stepReleased(t, w)
			w.store = w.reopen()
			replaySameImage(t, before, w.image(), "below-promise mismatch "+row.name)
		})
	}
}

func TestReplayStepMDBXFixtureDeleteAtomic(t *testing.T) {
	w := newStepWorld(t, 15120, false)
	stepSeedArtifact(w, 4, 0, w.bodies[0])
	stepSeedArtifact(w, 5, 0, stepManifest(0, 0, 1, 0))
	before := w.image()
	out, evidence := stepArmed(t, w, 0, mdbx.SelectedDamageDeleteEIO, 4, w.hashes[0][:])
	stepTuple(t, out, selectedSidePrecommit, "", "OLD", 1, 2, false)
	logicalMDBXAssert(t, evidence.Deletes == 1 && evidence.Faults == 1 && evidence.Commits == 0 && out.Needed == nil, "K13 delete site: %+v", evidence)
	stepCached(t, w, 0, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)")
	w.step.DiscardV1()
	logicalMDBXAssert(t, !w.step.DiscardV1(), "restart slot retained")
	w.store = w.reopen()
	startupTuple(t, startupRun(w.replayWorld), true, 1, "")
	replaySameImage(t, before, w.image(), "atomic artifact deletion fault")
	stepProgress(t, w, 0, w.authority(), w.call(0))
	stepExactImage(t, w, 0, before, true)
}

func TestReplayStepMDBXFixtureCachedSentinel(t *testing.T) {
	w := newStepWorld(t, 1, false)
	stepProgress(t, w, 0, w.authority(), w.call(0))
	stepProgress(t, w, 1, w.authority(), w.call(1))
	before := w.image()
	out, evidence := stepArmed(t, w, 1, mdbx.SelectedDamageAbortEIO, 0, nil)
	stepTuple(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "", "OLD", 1, 1, false)
	joined, ok := out.Err.(interface{ Unwrap() []error })
	logicalMDBXAssert(t, ok && len(joined.Unwrap()) == 2 && joined.Unwrap()[0].Error() == "replay step decision" && joined.Unwrap()[1].(*mdbx.EngineError).Operation == "abort" && evidence.OldGets[0] == 1 && evidence.BeginWrite == 0 && evidence.Commits == 0, "sentinel normalization must preserve native cleanup: %+v %v", evidence, out.Err)
	stepCached(t, w, 1, out, selectedSideInvariant)
	w.store = w.reopen()
	replaySameImage(t, before, w.image(), "sentinel/cached native cleanup")
	stepReleased(t, w)
}

func TestReplayStepMDBXFixtureStateRemainder(t *testing.T) {
	w, before, key, undo := stepRemainderWorld(t, 1)
	value, present := stepRead(t, w.store, 1, key)
	logicalMDBXAssert(t, present, "B41 actual readonly row")
	var out ReplayStepOutcomeV1
	drift, err := mdbx.FixtureWriteSnapshotDrift(w.store, 1, key, func() { out = w.call(1) })
	logicalMDBXAssert(t, err == nil && drift == 1, "STATE equality proof fixture: %d %v", drift, err)
	stepTuple(t, out, replayEntryStale, "", "OLD", 1, 1, false)
	logicalMDBXAssert(t, out.Needed == nil, "STATE drift invented Need")
	stepReleased(t, w)
	w.step.DiscardV1()
	logicalMDBXAssert(t, !w.step.DiscardV1(), "restart slot retained")
	w.store = w.reopen()
	equal, err := mdbx.FixtureRawRowEqual(w.store, 1, key, []byte{0x7f})
	logicalMDBXAssert(t, err == nil && equal, "only fixture changed readonly STATE")
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 1, key, value) == nil, "restore physical fixture row")
	startupTuple(t, startupRun(w.replayWorld), true, 1, "")
	replaySameImage(t, before, w.image(), "complete OLD after restoring the single fixture drift")
	stepProgress(t, w, 1, w.authority(), w.call(1))
	stepExactImageExtra(t, w, 1, before, false, stepManifest(1, 0, 2, 1), []mdbx.PrefixRow{{Key: append([]byte{5}, undo[:77]...), Value: undo[77:]}})
}

func TestReplayStepMDBXFixtureGrantPriority(t *testing.T) {
	for _, mode := range []string{"malformed", "none", "at_tip", "differing_header"} {
		t.Run(mode, func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			if mode == "none" {
				w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Phase, a.Lifecycle, a.Replay = 1, 1, nil })
			}
			if mode == "at_tip" {
				stepProgress(t, w, 0, w.authority(), w.call(0))
				stepProgress(t, w, 1, w.authority(), w.call(1))
				w.step.DiscardV1()
			}
			before := w.image()
			authority, _ := stepRead(t, w.store, 0, []byte{2})
			if mode == "malformed" {
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 0, []byte{2}, []byte{0x7f}) == nil, "malformed authority")
			}
			if mode == "differing_header" {
				value := bytes.Clone(w.headers[0][:])
				value[68] ^= 1
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 3, w.hashes[0][:], value) == nil, "later differing header")
				before = w.image()
			}
			protects, calls := w.view.protects, w.view.headerCalls
			if mode != "at_tip" {
				logicalMDBXAssert(t, protects == 0 && calls == 0, "authority-only setup reached provider")
			}
			var out ReplayStepOutcomeV1
			var evidence mdbx.SelectedDamageEvidence
			err := w.owner.WithReservation(1, func() error {
				var err error
				evidence, err = mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = w.call(0) })
				return err
			})
			logicalMDBXAssert(t, err == nil, "authority-only fixture")
			result, decision, clean := selectedSideCapacity, "", true
			if mode == "malformed" {
				result, clean = selectedSideIntegrity, false
			}
			if mode == "none" || mode == "at_tip" {
				result, decision = "", "not applicable"
			}
			stepTuple(t, out, result, decision, "OLD", 1, 1, clean)
			logicalMDBXAssert(t, out.Needed == nil && evidence.OldGets == ([8]uint64{1}) && evidence.BeginWrite == 0 && evidence.Commits == 0 && w.view.protects == protects && w.view.headerCalls == calls && w.step.path.slot == nil, "C1/C17/C19 first authority result: %+v", evidence)
			stepReleased(t, w)
			if mode == "malformed" {
				w.store = w.reopen()
				equal, err := mdbx.FixtureRawRowEqual(w.store, 0, []byte{2}, []byte{0x7f})
				logicalMDBXAssert(t, equal && err == nil, "original invalid authority retained")
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 0, []byte{2}, authority) == nil, "restore authority census control")
			}
			replaySameImage(t, before, w.image(), "priority committed no STEP effect")
		})
	}
}

func TestReplayStepMDBXFixtureDescriptorPresence(t *testing.T) {
	for _, generation := range []uint64{1, 2} {
		for _, scenario := range []uint8{4, 5, 6} {
			t.Run(fmt.Sprintf("g%d_s%d", generation, scenario), func(t *testing.T) {
				w := newStepWorld(t, 1, true)
				w.prefix(t, 1)
				before := w.image()
				key := stepKey(generation, 0)
				value, exists := stepRead(t, w.store, 2, key)
				logicalMDBXAssert(t, exists, "actual descriptor presence source")
				var out ReplayStepOutcomeV1
				evidence, err := mdbx.FixtureCanonicalTipStep(w.store, scenario, key, nil, false, func() { out = w.call(1) })
				logicalMDBXAssert(t, err == nil && evidence.Drift == 1 && out.Needed == nil, "presence drift: %v %+v", err, evidence)
				if scenario == 4 {
					stepTuple(t, out, replayEntryStale, "", "OLD", 1, 1, false)
				}
				if scenario == 5 {
					stepTuple(t, out, selectedSidePrecommit, "", "OLD", 1, 2, false)
				}
				if scenario == 6 {
					stepTuple(t, out, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "", "UNKNOWN", 3, 3, false)
				}
				stepReleased(t, w)
				w.store = w.reopen()
				if scenario != 5 {
					equal, err := mdbx.FixtureRawRowEqual(w.store, 2, key, nil)
					logicalMDBXAssert(t, err == nil && equal, "exact physical descriptor absence")
					logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, key, value) == nil, "restore descriptor census control")
				}
				if scenario == 6 {
					stepExactImage(t, w, 1, before, false)
				} else {
					replaySameImage(t, before, w.image(), "complete OLD with fixture restored")
				}
			})
		}
	}
}

func TestReplayStepMDBXFixtureEndpointKey(t *testing.T) {
	for _, scenario := range []uint8{4, 5, 6} {
		t.Run(fmt.Sprint(scenario), func(t *testing.T) {
			w := newStepWorld(t, 1, true)
			w.prefix(t, 1)
			before := w.image()
			key := stepKey(1, 1)
			value := append(append(bytes.Clone(w.hashes[1][:]), w.hashes[0][:]...), make([]byte, 40)...)
			value[103] = 2
			var out ReplayStepOutcomeV1
			evidence, err := mdbx.FixtureCanonicalTipStep(w.store, scenario, key, value, true, func() { out = w.call(1) })
			logicalMDBXAssert(t, err == nil && evidence.Drift == 1 && out.Needed == nil, "actual maximal endpoint key change: %v %+v", err, evidence)
			if scenario == 4 {
				stepTuple(t, out, replayEntryStale, "", "OLD", 1, 1, false)
			}
			if scenario == 5 {
				stepTuple(t, out, selectedSidePrecommit, "", "OLD", 1, 2, false)
			}
			if scenario == 6 {
				stepTuple(t, out, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "", "UNKNOWN", 3, 3, false)
			}
			stepReleased(t, w)
			w.store = w.reopen()
			if scenario != 5 {
				equal, err := mdbx.FixtureRawRowEqual(w.store, 2, key, value)
				logicalMDBXAssert(t, err == nil && equal, "fixture alone added the endpoint")
				stepDrop(w, 2, key)
			}
			if scenario == 6 {
				stepExactImage(t, w, 1, before, false)
			} else {
				replaySameImage(t, before, w.image(), "endpoint maximality proof preserved OLD")
			}
		})
	}
}

func TestReplayStepMDBXFixtureStagingMismatch(t *testing.T) {
	for _, rank := range []uint8{2, 7} {
		t.Run(fmt.Sprint(rank), func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			key, value := stepKey(2, 0), append(bytes.Clone(w.hashes[0][:]), make([]byte, 72)...)
			value[0] ^= 1
			value[103] = 1
			cause := "replay target staging entry differs"
			if rank == 7 {
				key = append(binary.BigEndian.AppendUint64(nil, 2), w.hashes[0][:]...)
				value, cause = binary.BigEndian.AppendUint64(nil, 1), "replay target staging owner differs"
			}
			logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, rank, key, value) == nil, "actual differing staging row")
			before := w.image()
			out := w.call(0)
			stepTuple(t, out, selectedSideIntegrity, "", "OLD", 1, 1, false)
			failure, ok := out.Err.(*selectedSideFailure)
			logicalMDBXAssert(t, ok && failure.cause.Error() == cause && out.Needed == nil && w.step.path.slot != nil, "staging comparison guard: %+v", out)
			stepReleased(t, w)
			w.store = w.reopen()
			replaySameImage(t, before, w.image(), "no partial cursor pair")
		})
	}
}
