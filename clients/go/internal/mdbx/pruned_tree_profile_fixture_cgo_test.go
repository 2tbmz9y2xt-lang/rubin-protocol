//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

type prunedTreeScene struct {
	s     *Store
	path  string
	o     *OperationReservationOwner
	a     TreeAuthorityV1
	tip   *AuthorityPointV1
	key   []byte
	value []byte
}

// newPrunedTreeScene seeds ARCHIVE NONE/STABLE with U, an optional tip row and an optional binding.
func newPrunedTreeScene(t *testing.T, u uint64, tip *AuthorityPointV1, p *uint64, edit func(*TreeAuthorityV1)) *prunedTreeScene {
	t.Helper()
	a := prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, u)
	if edit != nil {
		edit(&a)
	}
	s, path, o := prunedTreeSeed(t, a)
	scene := &prunedTreeScene{s: s, path: path, o: o, a: a, tip: tip}
	if tip != nil {
		key, err := HeightKey(1, tip.Height)
		mustEnvironment(t, err)
		scene.key, scene.value = key, ChainValue(tip.BlockHash, [32]byte{}, modelWork(false))
		treeNativeSeed(t, s, 2, key, scene.value)
	}
	treeNativeSeed(t, s, 0, prunedTreeLagKey(), prunedTreeBindingBytes(t, p))
	return scene
}

func prunedTreeU64(v uint64) *uint64 { return &v }

func prunedTreeAt(height uint64) *AuthorityPointV1 {
	return &AuthorityPointV1{Height: height, BlockHash: modelHash(height)}
}

// expected builds the committed envelope from spec literals, never from laggedPromise.
func (sc *prunedTreeScene) expected(b uint64, last *uint64) TreeAuthorityV1 {
	want := sc.a
	want.Authority.ActiveProfile, want.Authority.B = StorageProfilePrunedV1, b
	if last != nil {
		want.Authority.Phase = StoragePhasePruneGCV1
		want.Authority.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: CleanupSpanBlocksV1, GenerationID: 1, FirstHeight: 0, LastHeight: *last, NextHeight: 0}}}
	}
	return want
}

func (sc *prunedTreeScene) committed(t *testing.T, out PrunedTreeProfileOutcomeV1, want TreeAuthorityV1, marker string) {
	t.Helper()
	if out.Err != nil || out.Truth != CommitTruthNew || out.Stage != UpdateStageCommitMayHaveCrossed || out.Decision != "" || out.Authority == nil {
		t.Fatalf("%s: %+v", marker, out)
	}
	if !reflect.DeepEqual(*out.Authority, want) {
		t.Fatalf("%s: outcome authority %+v, want %+v", marker, *out.Authority, want)
	}
	mustEnvironment(t, sc.s.Close())
	reopened, err := OpenTreeV1(sc.path, environmentConfig(), [32]byte{7})
	mustEnvironment(t, err)
	defer func() { _ = reopened.Close() }()
	mustEnvironment(t, reopened.View(func(r *Reader) error {
		got, present, readErr := r.ReadTreeAuthorityV1()
		if !present || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: durable %+v present=%v, want %+v", marker, got, present, want)
		}
		return readErr
	}))
}

func TestPrunedTreeProfileCommit(t *testing.T) {
	for _, row := range []struct {
		name string
		h, u uint64
		p    *uint64
		b    uint64
		last *uint64
	}{
		{"A6 p4320", 20000, 18561, prunedTreeU64(4320), 4881, prunedTreeU64(4320)},
		{"A6 p2880", 20000, 18561, prunedTreeU64(2880), 4881, prunedTreeU64(2880)},
		// APPLIED p=0 is PAIR-legal at b(15500)=0; L_body=1 (LBODY) gives span 0..0.
		{"A6 p0", 15500, 14061, prunedTreeU64(0), 381, prunedTreeU64(0)},
		{"A7 pre-genesis lag", 15500, 14061, nil, 381, nil},
		{"A8 h1000", 1000, 0, nil, 0, nil},
		{"A8 h5000", 5000, 3561, nil, 0, nil},
		{"A11 p4500 outside pair", 20000, 18561, prunedTreeU64(4500), 4881, prunedTreeU64(4500)},
	} {
		t.Run(row.name, func(t *testing.T) {
			sc := newPrunedTreeScene(t, row.u, prunedTreeAt(row.h), row.p, nil)
			sc.committed(t, sc.s.SelectPrunedTreeProfileV1(true, sc.tip, sc.o), sc.expected(row.b, row.last), row.name)
		})
	}
	t.Run("A9 pre-genesis current", func(t *testing.T) {
		sc := newPrunedTreeScene(t, 0, nil, nil, nil)
		sc.committed(t, sc.s.SelectPrunedTreeProfileV1(true, nil, sc.o), sc.expected(0, nil), "A9")
	})
	// A10 and A7: the two optional fields an ARCHIVE NONE/STABLE envelope may carry
	// survive on both the positive and the zero L_body branch.
	optional := func(a *TreeAuthorityV1) {
		a.Authority.ExcludedInvalidBranch = &InvalidBranchV1{FirstInvalidHeight: 20001, FirstInvalidBlockHash: modelHash(9), ExactConsensusError: []byte{1}}
		a.Authority.SelectedSide = modelSide(3, 19000, 19001, 1, 117)
	}
	for _, row := range []struct {
		name string
		h, u uint64
		p    *uint64
		b    uint64
		last *uint64
	}{
		{"A10 positive L_body", 20000, 18561, prunedTreeU64(4320), 4881, prunedTreeU64(4320)},
		{"A7 zero L_body", 15500, 14061, nil, 381, nil},
	} {
		t.Run(row.name+" ExcludedInvalidBranch and SelectedSide unchanged", func(t *testing.T) {
			sc := newPrunedTreeScene(t, row.u, prunedTreeAt(row.h), row.p, optional)
			want := sc.expected(row.b, row.last)
			if want.Authority.ExcludedInvalidBranch == nil || want.Authority.ExcludedInvalidBranch.FirstInvalidHeight != 20001 || want.Authority.SelectedSide == nil || want.Authority.SelectedSide.TipHeight != 19001 {
				t.Fatal(row.name + ": optional fields not set")
			}
			sc.committed(t, sc.s.SelectPrunedTreeProfileV1(true, sc.tip, sc.o), want, row.name)
		})
	}
}

// TestPrunedTreeProfileConsulted drifts a consulted row before the write
// transaction: a committed plan that consults it refuses, so the row is in the plan.
// The non-NEW tuple is also X4: it is returned unchanged with no Authority.
func TestPrunedTreeProfileConsulted(t *testing.T) {
	for _, row := range []struct {
		name string
		tip  *AuthorityPointV1
		rank uint8
		key  func(*prunedTreeScene) []byte
	}{
		{"A9 lag binding", nil, 0, func(*prunedTreeScene) []byte { return prunedTreeLagKey() }},
		{"A6 lag binding", prunedTreeAt(20000), 0, func(*prunedTreeScene) []byte { return prunedTreeLagKey() }},
		{"A6 tip row", prunedTreeAt(20000), 2, func(sc *prunedTreeScene) []byte { return sc.key }},
	} {
		t.Run(row.name, func(t *testing.T) {
			u, p := uint64(0), (*uint64)(nil)
			if row.tip != nil {
				u, p = 18561, prunedTreeU64(4320)
			}
			sc := newPrunedTreeScene(t, u, row.tip, p, nil)
			before := prunedTreeBytes(t, sc.s)
			var out PrunedTreeProfileOutcomeV1
			count, err := FixtureWriteSnapshotDrift(sc.s, row.rank, row.key(sc), func() { out = sc.s.SelectPrunedTreeProfileV1(true, sc.tip, sc.o) })
			mustEnvironment(t, err)
			if count != 1 || out.Err == nil || out.Truth == CommitTruthNew || out.Authority != nil || out.Decision != "" {
				t.Fatalf("%s: drift%d %+v", row.name, count, out)
			}
			truth, stage, engineErr := prunedTreeEngineDrift(t, row.tip, u, p, row.rank, row.key)
			if out.Truth != truth || out.Stage != stage || !prunedTreeSameEngine(out.Err, engineErr) {
				t.Fatalf("X4 %s: method %s/%d %v, engine %s/%d %v", row.name, out.Truth, out.Stage, out.Err, truth, stage, engineErr)
			}
			if sc.s.state == storeOPEN && !bytes.Equal(prunedTreeBytes(t, sc.s), before) {
				t.Fatal(row.name + ": envelope changed")
			}
		})
	}
}

// TestPrunedTreeProfileConsultedList pins D13's whole operation as UpdateTreeV1
// receives it: the callback prunedTreePlan returns is the value
// SelectPrunedTreeProfileV1 passes to the engine unwrapped, and on the A9 and A6
// scenes its operation must equal, field for field, one Pair with exactly one
// mutation (meta key 0x02, the expected envelope encoded from literals) and the
// LAG binding key followed, on A6, by the seeded tip row key. An extra, missing
// or reordered Mutations or Consulted row fails here.
func TestPrunedTreeProfileConsultedList(t *testing.T) {
	dbis := TreeSchemaV1DBIs()
	for _, row := range []struct {
		name string
		tip  *AuthorityPointV1
		u    uint64
		p    *uint64
	}{
		{"A9", nil, 0, nil},
		{"A6", prunedTreeAt(20000), 18561, prunedTreeU64(4320)},
	} {
		sc := newPrunedTreeScene(t, row.u, row.tip, row.p, nil)
		envelope := sc.expected(0, nil)
		consulted := []ConsultedRow{{DBI: dbis[0], Key: []byte{0x11, 0, 0, 0, 0, 0, 0, 0, 2}}}
		if row.tip != nil {
			envelope = sc.expected(4881, prunedTreeU64(4320))
			consulted = append(consulted, ConsultedRow{DBI: dbis[2], Key: sc.key})
		}
		encoded, err := envelope.Encode()
		mustEnvironment(t, err)
		want := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{{DBI: dbis[0], Key: []byte{0x02}, BeforePresent: true, AfterKind: AfterLiteral, Literal: encoded}}, Consulted: consulted}}
		mustEnvironment(t, sc.o.WithOperation(LaneOperation, func(account *OperationAccount) error {
			return sc.s.View(func(r *Reader) error {
				var run prunedTreeRun
				op, err := prunedTreePlan(account, true, row.tip, &run, errors.New("stale"))(r)
				if err != nil || run.decision != "" || !reflect.DeepEqual(op, want) {
					t.Fatalf("D13 %s operation %+v (%v %q), want %+v", row.name, op, err, run.decision, want)
				}
				return nil
			})
		}))
	}
}

// prunedTreeEngineDrift runs the same drift on a twin scene against a direct
// UpdateTreeV1 call whose pair plan is built from spec literals (X4 oracle).
func prunedTreeEngineDrift(t *testing.T, tip *AuthorityPointV1, u uint64, p *uint64, rank uint8, key func(*prunedTreeScene) []byte) (CommitTruth, UpdateStage, error) {
	t.Helper()
	sc := newPrunedTreeScene(t, u, tip, p, nil)
	want := sc.expected(0, nil)
	if tip != nil {
		want = sc.expected(4881, prunedTreeU64(4320))
	}
	encoded, err := want.Encode()
	mustEnvironment(t, err)
	dbis := TreeSchemaV1DBIs()
	consulted := []ConsultedRow{{DBI: dbis[0], Key: prunedTreeLagKey()}}
	if tip != nil {
		consulted = append(consulted, ConsultedRow{DBI: dbis[2], Key: sc.key})
	}
	op := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{{DBI: dbis[0], Key: []byte{2}, BeforePresent: true, AfterKind: AfterLiteral, Literal: encoded}}, Consulted: consulted}}
	var r tsResult
	count, err := FixtureWriteSnapshotDrift(sc.s, rank, key(sc), func() { r = tsRun(t, sc.s, sc.o, LaneOperation, op) })
	mustEnvironment(t, err)
	if count != 1 || r.err == nil {
		t.Fatalf("engine drift%d %+v", count, r)
	}
	return r.truth, r.stage, r.err
}

func prunedTreeSameEngine(got, want error) bool {
	g, gok := directTestEngineError(got)
	w, wok := directTestEngineError(want)
	return gok && wok && reflect.DeepEqual(g, w)
}

func TestPrunedTreeProfileStale(t *testing.T) {
	for _, name := range []string{"absent row", "hash differs", "row above tip", "nil tip nonempty"} {
		t.Run(name, func(t *testing.T) {
			sc := newPrunedTreeScene(t, 18561, prunedTreeAt(20000), prunedTreeU64(4320), nil)
			tip := *sc.tip
			call := &tip
			switch name {
			case "absent row":
				call.Height = 20001
				call.BlockHash = modelHash(20001)
			case "hash differs":
				call.BlockHash = modelHash(1)
			case "row above tip":
				key, err := HeightKey(1, 20001)
				mustEnvironment(t, err)
				treeNativeSeed(t, sc.s, 2, key, ChainValue(modelHash(20001), [32]byte{}, modelWork(false)))
			case "nil tip nonempty":
				call = nil
			}
			before := prunedTreeBytes(t, sc.s)
			prunedTreeDecision(t, sc.s.SelectPrunedTreeProfileV1(true, call, sc.o), "STALE_LOCAL_PLAN", "R6 "+name)
			prunedTreeOpenUnchanged(t, sc.s, before, "R6 "+name)
		})
	}
}

// TestPrunedTreeProfileSuffixBeforeBinding pins the D7-before-D8 order: with no LAG
// binding, a stale suffix (a nil tip over a nonempty index, or a row above the tip)
// returns STALE_LOCAL_PLAN, not R10's latched integrity.
func TestPrunedTreeProfileSuffixBeforeBinding(t *testing.T) {
	for _, tip := range []*AuthorityPointV1{nil, prunedTreeAt(0)} {
		s, _, o := prunedTreeSeed(t, prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0))
		for _, height := range []uint64{0, 1} {
			key, err := HeightKey(1, height)
			mustEnvironment(t, err)
			treeNativeSeed(t, s, 2, key, ChainValue(modelHash(height), [32]byte{}, modelWork(false)))
		}
		before := prunedTreeBytes(t, s)
		prunedTreeDecision(t, s.SelectPrunedTreeProfileV1(true, tip, o), "STALE_LOCAL_PLAN", "D7 suffix before D8")
		prunedTreeOpenUnchanged(t, s, before, "D7 suffix before D8")
	}
}

func TestPrunedTreeProfileLatched(t *testing.T) {
	// "R8 U zero p at B'" also fails D12 (R9): D9 refuses the promises first.
	for _, name := range []string{"R7 work before hash", "R7 work before suffix", "R8 U zero", "R8 U plus one", "R8 U zero p at B'", "X1 corrupt binding", "X1 database mismatch", "X2 index width", "D7 suffix read failure", "D7 nil tip read failure", "D3 envelope read failure"} {
		t.Run(name, func(t *testing.T) {
			u, p := uint64(18561), uint64(4320)
			switch name {
			case "R8 U zero":
				u = 0
			case "R8 U plus one":
				u = 18562
			case "R8 U zero p at B'":
				u, p = 0, 4881
			}
			sc := newPrunedTreeScene(t, u, prunedTreeAt(20000), &p, nil)
			tip := *sc.tip
			call := &tip
			diagnostic, raw := "pruned tree profile promises disagree with tip", "invalid tree native representation"
			switch name {
			case "R7 work before hash":
				treeNativeSeed(t, sc.s, 2, sc.key, ChainValue(tip.BlockHash, [32]byte{}, [40]byte{}))
				tip.BlockHash = modelHash(1)
				diagnostic = "invalid pruned tree profile tip work"
			case "R7 work before suffix":
				treeNativeSeed(t, sc.s, 2, sc.key, ChainValue(tip.BlockHash, [32]byte{}, [40]byte{}))
				above, err := HeightKey(1, 20001)
				mustEnvironment(t, err)
				treeNativeSeed(t, sc.s, 2, above, ChainValue(modelHash(20001), [32]byte{}, modelWork(false)))
				diagnostic = "invalid pruned tree profile tip work"
			case "X1 corrupt binding":
				encoded := prunedTreeBindingBytes(t, prunedTreeU64(4320))
				encoded[0] = 2
				treeNativeSeed(t, sc.s, 0, prunedTreeLagKey(), encoded)
				diagnostic = ""
			case "X1 database mismatch":
				encoded := prunedTreeBindingBytes(t, prunedTreeU64(4320))
				encoded[1] ^= 1
				treeNativeSeed(t, sc.s, 0, prunedTreeLagKey(), encoded)
				diagnostic = ""
			case "X2 index width":
				treeNativeSeed(t, sc.s, 2, sc.key, append(bytes.Clone(sc.value), 0))
				diagnostic = ""
			case "D7 suffix read failure":
				above, err := HeightKey(1, 20001)
				mustEnvironment(t, err)
				treeNativeSeed(t, sc.s, 2, above, append(ChainValue(modelHash(20001), [32]byte{}, modelWork(false)), 0))
				diagnostic, raw = "", "stored value width outside SchemaV2 bound"
			case "D7 nil tip read failure":
				treeNativeSeed(t, sc.s, 2, sc.key, append(bytes.Clone(sc.value), 0))
				call = nil
				diagnostic, raw = "", "stored value width outside SchemaV2 bound"
			case "D3 envelope read failure":
				treeNativeSeed(t, sc.s, 0, []byte{2}, []byte{0x7f})
				diagnostic = ""
			}
			before := prunedTreeImage(t, sc.s)
			out := sc.s.SelectPrunedTreeProfileV1(true, call, sc.o)
			if diagnostic == "" {
				engine, direct := directTestEngineError(out.Err)
				if !direct || engine.Class != EngineIntegrity || engine.Diagnostic != raw {
					t.Fatalf("%s: %+v", name, out)
				}
			}
			if name == "D3 envelope read failure" {
				prunedTreeCorruptEnvelope(t, sc, out)
				return
			}
			prunedTreeLatched(t, sc.s, sc.path, out, before, diagnostic, sc.o)
		})
	}
}

// prunedTreeCorruptEnvelope is the latched route for an envelope ReadTreeAuthorityV1
// cannot decode: OpenTreeV1 still refuses the same corrupt bytes, so nothing committed.
func prunedTreeCorruptEnvelope(t *testing.T, sc *prunedTreeScene, out PrunedTreeProfileOutcomeV1) {
	t.Helper()
	prunedTreeConsumed(t, sc.s, out, sc.o)
	reopened, err := OpenTreeV1(sc.path, environmentConfig(), [32]byte{7})
	engine, direct := directTestEngineError(err)
	if reopened != nil || !direct || engine.Class != EngineIntegrity || engine.Diagnostic != "invalid tree native representation" {
		t.Fatalf("D3 envelope reopen: %v", err)
	}
}

func TestPrunedTreeProfileReplacementInvariant(t *testing.T) {
	sc := newPrunedTreeScene(t, 18561, prunedTreeAt(20000), prunedTreeU64(4881), nil)
	before := prunedTreeBytes(t, sc.s)
	out := sc.s.SelectPrunedTreeProfileV1(true, sc.tip, sc.o)
	treeNativeError(t, out.Err, operationUpdate, EngineLocalInvariant, codeProblem, "invalid pruned tree profile replacement", nil)
	prunedTreeRefusal(t, out, "R9")
	prunedTreeOpenUnchanged(t, sc.s, before, "R9")
}

// TestPrunedTreeProfileConsultedExclusion is A9's exclusion half (D13 fixes the
// Consulted list exactly): each row outside it is drifted before the write
// transaction. A plan consulting the row refuses with OLD/write snapshot mismatch;
// this plan commits (the fixture's commit hook then reports ENOSPC with the commit
// readback NEW). Rows: the active generation's binding, the binding of
// LagGenerationID+1, and meta key 1 (the schema row: its drift leaves 0x7f, so
// that row skips the durable reopen).
func TestPrunedTreeProfileConsultedExclusion(t *testing.T) {
	for _, row := range []struct {
		name   string
		key    []byte
		seed   bool
		reopen bool
	}{
		{"active binding", binary.BigEndian.AppendUint64([]byte{0x11}, 1), true, true},
		{"lag+1 binding", binary.BigEndian.AppendUint64([]byte{0x11}, 3), false, true},
		{"meta key 1", []byte{1}, false, false},
	} {
		t.Run(row.name, func(t *testing.T) { prunedTreeExcluded(t, row.key, row.seed, row.reopen) })
	}
}

func prunedTreeExcluded(t *testing.T, key []byte, seed, reopen bool) {
	sc := newPrunedTreeScene(t, 0, nil, nil, nil)
	if seed {
		treeNativeSeed(t, sc.s, 0, key, prunedTreeBindingBytes(t, nil))
	}
	var out PrunedTreeProfileOutcomeV1
	count, err := FixtureWriteSnapshotDrift(sc.s, 0, key, func() { out = sc.s.SelectPrunedTreeProfileV1(true, nil, sc.o) })
	mustEnvironment(t, err)
	want := sc.expected(0, nil)
	if count != 1 || out.Truth != CommitTruthNew || out.Stage != UpdateStageCommitMayHaveCrossed || out.Authority == nil || !reflect.DeepEqual(*out.Authority, want) {
		t.Fatalf("A9 exclusion drift%d: %+v", count, out)
	}
	var engine *EngineError
	if !errors.As(out.Err, &engine) || engine.Class != EngineCapacity || engine.Code != codeENOSPC {
		t.Fatalf("A9 exclusion commit error %v", out.Err)
	}
	// D2: the commit error consumed the Store (mdbx_cgo.go:2369-2370), which is closed and
	// retains truth NEW (refusedUpdate, :2432-2438), so the following refusal is
	// NEW/Prewrite, as a direct UpdateTreeV1 call returns.
	again := sc.s.SelectPrunedTreeProfileV1(true, nil, sc.o)
	var direct tsResult
	mustEnvironment(t, sc.o.WithOperation(LaneOperation, func(a *OperationAccount) error {
		direct = tsInvoke(sc.s, a, func(*Reader) (TreeOperationV1, error) { return TreeOperationV1{}, nil })
		return nil
	}))
	if again.Truth != CommitTruthNew || again.Stage != UpdateStagePrewrite || again.Err == nil || again.Decision != "" || again.Authority != nil || direct.truth != again.Truth || direct.stage != again.Stage {
		t.Fatalf("D2 retained truth refusal: %+v, direct %+v", again, direct)
	}
	// The terminal Store's refusal is its retained error value itself.
	if direct.err == nil || !sameError(again.Err, direct.err) {
		t.Fatalf("D2 retained truth refusal error: %v vs %v", again.Err, direct.err)
	}
	_ = sc.s.Close()
	if !reopen {
		return
	}
	reopened, err := OpenTreeV1(sc.path, environmentConfig(), [32]byte{7})
	mustEnvironment(t, err)
	defer func() { _ = reopened.Close() }()
	mustEnvironment(t, reopened.View(func(r *Reader) error {
		got, present, readErr := r.ReadTreeAuthorityV1()
		if !present || !reflect.DeepEqual(got, want) {
			t.Fatalf("A9 exclusion durable %+v", got)
		}
		return readErr
	}))
}

// TestPrunedTreeProfileProjection pins the D14 projection over the full tuple table,
// including tuples no existing hook returns for a pair-only plan. X4 through the public
// method is TestPrunedTreeProfileConsulted; the sentinel and new crossed rows are also
// reached through it by the decision and commit tests. Only the exact sentinel at
// OLD/Prewrite becomes Decision, only NEW/CommitMayHaveCrossed sets Authority, and every
// other tuple keeps its error by identity.
func TestPrunedTreeProfileProjection(t *testing.T) {
	sentinel, other := errors.New("decision"), errors.New("other")
	joined := errors.Join(sentinel, other)
	planned := &TreeAuthorityV1{LagGenerationID: 9}
	for _, row := range []struct {
		name      string
		truth     CommitTruth
		stage     UpdateStage
		err       error
		decision  string
		authority *TreeAuthorityV1
	}{
		{"sentinel", CommitTruthOld, UpdateStagePrewrite, sentinel, "STALE_LOCAL_PLAN", nil},
		{"joined sentinel", CommitTruthOld, UpdateStagePrewrite, joined, "", nil},
		{"sentinel unknown truth", CommitTruthUnknown, UpdateStagePrewrite, sentinel, "", nil},
		{"sentinel write started", CommitTruthOld, UpdateStageWriteStartedDefinitelyPrecommit, sentinel, "", nil},
		{"new crossed", CommitTruthNew, UpdateStageCommitMayHaveCrossed, other, "", planned},
		{"new write started", CommitTruthNew, UpdateStageWriteStartedDefinitelyPrecommit, other, "", nil},
		{"unknown crossed", CommitTruthUnknown, UpdateStageCommitMayHaveCrossed, other, "", nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			in := PrunedTreeProfileOutcomeV1{Truth: row.truth, Stage: row.stage, Err: row.err}
			got := prunedTreeOutcome(in, planned, "STALE_LOCAL_PLAN", sentinel)
			wantErr := row.err
			if row.decision != "" {
				wantErr = nil
			}
			if got.Decision != row.decision || got.Authority != row.authority || got.Truth != row.truth || got.Stage != row.stage || !sameError(got.Err, wantErr) {
				t.Fatalf("D14 %s: %+v", row.name, got)
			}
		})
	}
}

// TestPrunedTreeProfileZeroPromiseMismatch is D9 where laggedPromise(H,15120) is 0:
// the decoder accepts these U values with B=0, so D9 alone refuses them (TIPB).
func TestPrunedTreeProfileZeroPromiseMismatch(t *testing.T) {
	for _, row := range []struct {
		name string
		u    uint64
		tip  *AuthorityPointV1
	}{
		{"D9 nil tip U one", 1, nil},
		{"D9 h5000 U zero", 0, prunedTreeAt(5000)},
		{"D9 h5000 U plus one", 3562, prunedTreeAt(5000)},
	} {
		t.Run(row.name, func(t *testing.T) {
			sc := newPrunedTreeScene(t, row.u, row.tip, nil, nil)
			before := prunedTreeImage(t, sc.s)
			out := sc.s.SelectPrunedTreeProfileV1(true, row.tip, sc.o)
			prunedTreeLatched(t, sc.s, sc.path, out, before, "pruned tree profile promises disagree with tip", sc.o)
		})
	}
}
