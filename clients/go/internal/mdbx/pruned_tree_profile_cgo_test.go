//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

// prunedTreeEnvelope is a STABLE-or-not format-3 envelope with LAG generation 2.
func prunedTreeEnvelope(profile StorageProfileV1, phase StoragePhaseV1, lifecycle StorageLifecycleV1, u uint64) TreeAuthorityV1 {
	return TreeAuthorityV1{Authority: StorageAuthorityV1{Version: 1, ActiveProfile: profile, U: u, ActiveGenerationID: 1, NextGenerationID: 5, Phase: phase, Lifecycle: lifecycle}, LagGenerationID: 2}
}

// prunedTreeSeed creates a format-3 store and inserts the envelope through a pair-only UpdateTreeV1.
func prunedTreeSeed(t *testing.T, a TreeAuthorityV1) (*Store, string, *OperationReservationOwner) {
	t.Helper()
	s, path, _ := treeNativeStore(t)
	o := reservationOwner(t, MinReservationLimit)
	encoded, err := a.Encode()
	mustEnvironment(t, err)
	op := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[0], Key: []byte{2}, AfterKind: AfterLiteral, Literal: encoded}}}}
	r := tsRun(t, s, o, LaneOperation, op)
	r.tuple(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
	mustEnvironment(t, r.err)
	return s, path, o
}

// prunedTreeBindingBytes encodes the LAG root binding; a nil p is PRE_GENESIS.
func prunedTreeBindingBytes(t *testing.T, p *uint64) []byte {
	t.Helper()
	root := RootBindingV1{DatabaseID: [32]byte{7}, CommitmentVersion: 1, RootDigest: sha3.Sum256([]byte("RUBIN_UTXO_TREE_V1\x00")), Assurance: TreeAssuranceV1{Kind: TreeAssuranceFullHistoryV1}}
	if p != nil {
		root.Endpoint = TreeEndpointV1{Kind: TreeEndpointAppliedV1, Height: *p, BlockHash: modelHash(*p), CumulativeChainwork: modelWork(false)}
	}
	encoded, err := root.Encode()
	mustEnvironment(t, err)
	return encoded
}

// prunedTreeSameRefusal reports whether got is an *EngineError equal field by
// field to want, the freshly built *EngineError a direct UpdateTreeV1 call on a
// closed Store returned; Cause is compared by identity.
func prunedTreeSameRefusal(got, want error) bool {
	g, gok := directTestEngineError(got)
	w, wok := directTestEngineError(want)
	if !gok || !wok || !sameError(g.Cause, w.Cause) || !reflect.DeepEqual(g.TreeObservation, w.TreeObservation) {
		return false
	}
	gc, wc := *g, *w
	gc.Cause, gc.TreeObservation, wc.Cause, wc.TreeObservation = nil, nil, nil, nil
	return gc == wc
}

func prunedTreeLagKey() []byte { return binary.BigEndian.AppendUint64([]byte{0x11}, 2) }

func prunedTreeBytes(t *testing.T, s *Store) []byte {
	t.Helper()
	var out []byte
	mustEnvironment(t, s.View(func(r *Reader) error {
		value, present, err := r.Get(TreeSchemaV1DBIs()[0], []byte{2})
		if present {
			out = append([]byte(nil), value...)
		}
		return err
	}))
	return out
}

// prunedTreeImage is every committed row of every rank, length-prefixed in key
// order; treeReadNextV1 reads rows that Reader.Get refuses (X2, D7).
func prunedTreeImage(t *testing.T, s *Store) []byte {
	t.Helper()
	var out []byte
	mustEnvironment(t, s.View(func(r *Reader) error {
		var err error
		for rank := range r.dbis {
			if out, err = prunedTreeRankImage(r, rank, out); err != nil {
				return err
			}
		}
		return nil
	}))
	return out
}

func prunedTreeRankImage(r *Reader, rank int, out []byte) ([]byte, error) {
	for from := []byte{0}; ; {
		key, value, ok, err := treeReadNextV1(r.txn, r.dbis[rank], from)
		if err != nil || !ok {
			return out, err
		}
		out = binary.BigEndian.AppendUint32(append(binary.BigEndian.AppendUint32(append(out, byte(rank)), uint32(len(key))), key...), uint32(len(value.value)))
		out = append(out, value.value...)
		from = append(bytes.Clone(key), 0)
	}
}

func prunedTreeDecision(t *testing.T, out PrunedTreeProfileOutcomeV1, want, marker string) {
	t.Helper()
	if out.Decision != want || out.Authority != nil || out.Truth != CommitTruthOld || out.Stage != UpdateStagePrewrite || out.Err != nil {
		t.Fatalf("%s: %+v, want decision %q", marker, out, want)
	}
}

func prunedTreeRefusal(t *testing.T, out PrunedTreeProfileOutcomeV1, marker string) {
	t.Helper()
	if out.Decision != "" || out.Authority != nil || out.Truth != CommitTruthOld || out.Stage != UpdateStagePrewrite || out.Err == nil {
		t.Fatalf("%s: %+v", marker, out)
	}
}

// prunedTreeOpenUnchanged asserts the Store is open and reusable with the envelope bytes unchanged.
func prunedTreeOpenUnchanged(t *testing.T, s *Store, before []byte, marker string) {
	t.Helper()
	bootstrapOpenUnchanged(t, s, marker)
	if !bytes.Equal(prunedTreeBytes(t, s), before) {
		t.Fatal(marker + ": envelope changed")
	}
}

// prunedTreeConsumed asserts the refusal tuple, the CLOSED Store and the same error on reuse.
func prunedTreeConsumed(t *testing.T, s *Store, out PrunedTreeProfileOutcomeV1, owner *OperationReservationOwner) {
	t.Helper()
	prunedTreeRefusal(t, out, "latched tuple")
	if s.state != storeCLOSED {
		t.Fatalf("latched store state %s", s.state)
	}
	again := s.SelectPrunedTreeProfileV1(true, nil, owner)
	if !sameError(again.Err, out.Err) || again.Truth != CommitTruthOld || again.Stage != UpdateStagePrewrite {
		t.Fatalf("latched reuse: %+v", again)
	}
}

// prunedTreeLatched asserts the consumed-Store integrity route of R7, R8, R10, X1 and X2;
// before is the prunedTreeImage taken before the call.
func prunedTreeLatched(t *testing.T, s *Store, path string, out PrunedTreeProfileOutcomeV1, before []byte, diagnostic string, owner *OperationReservationOwner) {
	t.Helper()
	if diagnostic != "" {
		bootstrapRefusal(t, diagnostic, out.Truth, out.Err, EngineIntegrity, operationGet, codeInvalid, diagnostic, nil, true)
	}
	prunedTreeConsumed(t, s, out, owner)
	reopened, err := OpenTreeV1(path, environmentConfig(), [32]byte{7})
	mustEnvironment(t, err)
	defer func() { _ = reopened.Close() }()
	if !bytes.Equal(prunedTreeImage(t, reopened), before) {
		t.Fatal("latched durable rows changed")
	}
}

// A1 holds for every confirmation and tip input: exact empty precedes D4 and D5.
func TestPrunedTreeProfileExactEmpty(t *testing.T) {
	for _, owner := range []*OperationReservationOwner{reservationOwner(t, MinReservationLimit), reservationOwner(t, MinReservationLimit-1)} {
		s, _, _ := treeNativeStore(t)
		before := reservationLive(owner)
		for _, confirmed := range []bool{true, false} {
			for _, tip := range []*AuthorityPointV1{nil, {Height: 0x100000000}} {
				prunedTreeDecision(t, s.SelectPrunedTreeProfileV1(confirmed, tip, owner), "not eligible", "A1 exact empty")
			}
		}
		if reservationLive(owner) != before {
			t.Fatal("A1 owner live changed")
		}
		mustEnvironment(t, s.View(func(r *Reader) error {
			_, present, err := r.ReadTreeAuthorityV1()
			if present {
				t.Fatal("A1 envelope created")
			}
			return err
		}))
	}
}

func TestPrunedTreeProfileControl(t *testing.T) {
	recovery := prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleRecoveryRequiredV1, 0)
	pending := StorageProfilePrunedV1
	recovery.Authority.PendingTargetProfile = &pending
	prunedRecovery := prunedTreeEnvelope(StorageProfilePrunedV1, StoragePhaseNoneV1, StorageLifecycleRecoveryRequiredV1, 0)
	prunedRecovery.Authority.PendingTargetProfile = &pending
	busyArchive := prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhasePruneGCV1, StorageLifecycleStableV1, 0)
	busyArchive.Authority.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: CleanupSpanGenerationV1, GenerationID: 3, FirstHeight: 0, LastHeight: 0, NextHeight: 0}}}
	recoveryGC := busyArchive
	recoveryGC.Authority.Lifecycle = StorageLifecycleRecoveryRequiredV1
	recoveryGC.Authority.PendingTargetProfile = &pending
	busyPruned := busyArchive
	busyPruned.Authority.ActiveProfile = StorageProfilePrunedV1
	high := &AuthorityPointV1{Height: 0x100000000}
	for _, row := range []struct {
		name      string
		a         TreeAuthorityV1
		confirmed bool
		want      string
	}{
		{"A2 archive recovery", recovery, false, "RECOVERY_REQUIRED"},
		{"A2 pruned recovery", prunedRecovery, false, "RECOVERY_REQUIRED"},
		{"A2 archive recovery prune gc", recoveryGC, true, "RECOVERY_REQUIRED"},
		{"A3 pruned none", prunedTreeEnvelope(StorageProfilePrunedV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0), false, "PROFILE_NOOP"},
		{"A3 pruned gc", busyPruned, false, "PROFILE_NOOP"},
		{"A4 busy confirmed", busyArchive, true, "LOCAL_BUSY"},
		{"A4 busy unconfirmed", busyArchive, false, "LOCAL_BUSY"},
		{"A5 unconfirmed", prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0), false, "PROFILE_CONFIRMATION_REQUIRED"},
	} {
		t.Run(row.name, func(t *testing.T) {
			s, _, _ := prunedTreeSeed(t, row.a)
			before := prunedTreeBytes(t, s)
			// Each decision precedes the D5 tip input check, so it holds with a tip above 0xffffffff too.
			for _, tip := range []*AuthorityPointV1{nil, high} {
				for _, owner := range []*OperationReservationOwner{reservationOwner(t, MinReservationLimit), reservationOwner(t, MinReservationLimit-1)} {
					live := reservationLive(owner)
					prunedTreeDecision(t, s.SelectPrunedTreeProfileV1(row.confirmed, tip, owner), row.want, row.name)
					if reservationLive(owner) != live || !bytes.Equal(prunedTreeBytes(t, s), before) {
						t.Fatal(row.name + ": owner or envelope changed")
					}
				}
			}
		})
	}
}

func TestPrunedTreeProfileStaticRefusals(t *testing.T) {
	// Each static refusal is checked with a confirmed call, an unconfirmed call
	// and a tip above 0xffffffff: D2 precedes D4 confirmation and D5.
	high := &AuthorityPointV1{Height: 0x100000000}
	inputs := []struct {
		confirmed bool
		tip       *AuthorityPointV1
	}{{true, nil}, {false, nil}, {true, high}}
	var nilStore *Store
	var out PrunedTreeProfileOutcomeV1
	for _, in := range inputs {
		out = nilStore.SelectPrunedTreeProfileV1(in.confirmed, in.tip, nil)
		treeNativeError(t, out.Err, operationUpdate, EngineInvalidInput, codeEINVAL, "nil Store", nil)
		prunedTreeRefusal(t, out, "R1 nil Store")
	}

	archive := prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0)
	s, _, o := prunedTreeSeed(t, archive)
	for _, owner := range []*OperationReservationOwner{nil, {}} {
		for _, in := range inputs {
			out = s.SelectPrunedTreeProfileV1(in.confirmed, in.tip, owner)
			if !sameError(out.Err, errOperationReservationInput) {
				t.Fatalf("R2 owner refusal: %+v", out)
			}
			prunedTreeRefusal(t, out, "R2 owner")
		}
	}
	prunedTreeDecision(t, s.SelectPrunedTreeProfileV1(false, nil, o), "PROFILE_CONFIRMATION_REQUIRED", "R2 reusable")

	v2, _, _, v2Rows := prunedStore(t, modelBase(2, 0, 0), nil, modelWork(false))
	v2Before := prunedImage(t, v2, v2Rows)
	for _, in := range inputs {
		out = v2.SelectPrunedTreeProfileV1(in.confirmed, in.tip, o)
		treeNativeError(t, out.Err, operationUpdate, EngineStateMismatch, -30779, "typed tree operation requires tree store", nil)
		prunedTreeRefusal(t, out, "R3 format 2")
	}
	prunedUnchanged(t, v2, v2Rows, v2Before, "R3 format 2")
	prunedDecision(t, v2.SelectPrunedProfileV1(false, nil, o), "PROFILE_CONFIRMATION_REQUIRED", "R3 format-2 owner")

	busy, _, _ := prunedTreeSeed(t, archive)
	busyBefore := prunedTreeBytes(t, busy)
	for _, in := range inputs {
		busy.operations.Lock()
		out = busy.SelectPrunedTreeProfileV1(in.confirmed, in.tip, o)
		busy.operations.Unlock()
		treeNativeError(t, out.Err, operationUpdate, EngineConcurrency, codeBusy, "store operation in progress", nil)
		prunedTreeRefusal(t, out, "R3 busy")
	}
	prunedTreeOpenUnchanged(t, busy, busyBefore, "R3 busy")
	prunedTreeDecision(t, busy.SelectPrunedTreeProfileV1(false, nil, o), "PROFILE_CONFIRMATION_REQUIRED", "R3 busy reusable")

	closed, _, _ := prunedTreeSeed(t, archive)
	mustEnvironment(t, closed.Close())
	var direct tsResult
	mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
		direct = tsInvoke(closed, a, func(*Reader) (TreeOperationV1, error) { return TreeOperationV1{}, nil })
		return nil
	}))
	for _, in := range inputs {
		out = closed.SelectPrunedTreeProfileV1(in.confirmed, in.tip, o)
		if !prunedTreeSameRefusal(out.Err, direct.err) {
			t.Fatalf("R3 closed: %+v vs %+v", out, direct)
		}
		if out.Truth != direct.truth || out.Stage != direct.stage || out.Decision != "" || out.Authority != nil {
			t.Fatalf("R3 closed tuple: %+v vs %+v", out, direct)
		}
	}
}

func TestPrunedTreeProfileTipInput(t *testing.T) {
	s, _, o := prunedTreeSeed(t, prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0))
	before := prunedTreeBytes(t, s)
	out := s.SelectPrunedTreeProfileV1(true, &AuthorityPointV1{Height: 0x100000000}, reservationOwner(t, MinReservationLimit-1))
	treeNativeError(t, out.Err, operationUpdate, EngineInvalidInput, codeEINVAL, "invalid pruned tree profile tip", nil)
	prunedTreeRefusal(t, out, "R4 tip")
	// Height 0xffffffff is not above the bound: it passes D5 and reaches D6's refusal.
	edge := s.SelectPrunedTreeProfileV1(true, &AuthorityPointV1{Height: 0xffffffff}, reservationOwner(t, MinReservationLimit-1))
	if !IsOperationReservationCapacity(edge.Err) {
		t.Fatalf("R4 boundary 0xffffffff: %+v", edge)
	}
	prunedTreeRefusal(t, edge, "R4 boundary")
	prunedTreeOpenUnchanged(t, s, before, "R4 tip")
	prunedTreeDecision(t, s.SelectPrunedTreeProfileV1(true, &AuthorityPointV1{BlockHash: modelHash(1)}, o), "STALE_LOCAL_PLAN", "R4 reusable")
}

func TestPrunedTreeProfileCapacity(t *testing.T) {
	// The absent-tip-row case separates a charge placed after the first index read.
	for _, tip := range []*AuthorityPointV1{nil, {BlockHash: modelHash(1)}} {
		s, path, o := prunedTreeSeed(t, prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0))
		before, image := prunedTreeBytes(t, s), prunedTreeImage(t, s)
		out := s.SelectPrunedTreeProfileV1(true, tip, reservationOwner(t, MinReservationLimit-1))
		if !IsOperationReservationCapacity(out.Err) {
			t.Fatalf("R5 capacity: %+v", out)
		}
		prunedTreeRefusal(t, out, "R5 capacity")
		prunedTreeOpenUnchanged(t, s, before, "R5 capacity")
		out = s.SelectPrunedTreeProfileV1(true, tip, o)
		if tip != nil {
			prunedTreeDecision(t, out, "STALE_LOCAL_PLAN", "R5 follow-up stale")
			continue
		}
		prunedTreeLatched(t, s, path, out, image, "missing pruned tree profile root binding", o)
	}
	// D6 amount: 999 remaining owner bytes refuse the 1000-byte charge and 1000 admit it.
	// The absent tip row returns before the engine's own hold for the Pair copies.
	for _, remaining := range []uint64{999, 1000} {
		s, _, _ := prunedTreeSeed(t, prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 0))
		out := s.SelectPrunedTreeProfileV1(true, &AuthorityPointV1{BlockHash: modelHash(1)}, reservationFilled(t, remaining))
		if remaining == 999 {
			if !IsOperationReservationCapacity(out.Err) {
				t.Fatalf("R5 charge amount at 999: %+v", out)
			}
			prunedTreeRefusal(t, out, "R5 charge amount at 999")
			continue
		}
		prunedTreeDecision(t, out, "STALE_LOCAL_PLAN", "R5 charge amount at 1000")
	}
}

// TestPrunedTreeProfileMissingBinding is R10 (Capacity's nil-tip follow-up covers U=0);
// U=1 also differs from the nil tip's promise 0 (R8), and D8 refuses the missing binding before D9.
func TestPrunedTreeProfileMissingBinding(t *testing.T) {
	s, path, o := prunedTreeSeed(t, prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 1))
	before := prunedTreeImage(t, s)
	out := s.SelectPrunedTreeProfileV1(true, nil, o)
	prunedTreeLatched(t, s, path, out, before, "missing pruned tree profile root binding", o)
}

// TestPrunedTreeProfileSizeBound is R11 (the tip row is paired with its rank-7
// owner row, as the canonical pairing rule requires): the BLOCKS span (34 encoded bytes) moves
// an Encode-accepted envelope past MaxMetadataBytes-27; one byte less commits. With p=4881
// the replacement is also invalid (R9), and D12 refuses validity before size.
func TestPrunedTreeProfileSizeBound(t *testing.T) {
	for _, row := range []struct {
		over bool
		p    uint64
	}{{false, 4320}, {true, 4320}, {true, 4881}} {
		// authoritySize before the call: 40 + 44 + len(error); after: +1+9+24.
		n := MaxMetadataBytes - 27 - 84 - 34
		if row.over {
			n++
		}
		a := prunedTreeEnvelope(StorageProfileArchiveV1, StoragePhaseNoneV1, StorageLifecycleStableV1, 18561)
		a.Authority.ExcludedInvalidBranch = &InvalidBranchV1{FirstInvalidHeight: 20001, FirstInvalidBlockHash: modelHash(9), ExactConsensusError: bytes.Repeat([]byte{1}, n)}
		s, _, o := prunedTreeSeed(t, a)
		tip := &AuthorityPointV1{Height: 20000, BlockHash: modelHash(20000)}
		key, err := HeightKey(1, 20000)
		mustEnvironment(t, err)
		dbis := TreeSchemaV1DBIs()
		op := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{
			{DBI: dbis[0], Key: prunedTreeLagKey(), AfterKind: AfterLiteral, Literal: prunedTreeBindingBytes(t, &row.p)},
			{DBI: dbis[2], Key: key, AfterKind: AfterLiteral, Literal: ChainValue(tip.BlockHash, [32]byte{}, modelWork(false))},
			{DBI: dbis[7], Key: append(binary.BigEndian.AppendUint64(nil, 1), tip.BlockHash[:]...), AfterKind: AfterLiteral, Literal: binary.BigEndian.AppendUint64(nil, 20000)},
		}}}
		r := tsRun(t, s, o, LaneOperation, op)
		r.tuple(t, CommitTruthNew, UpdateStageCommitMayHaveCrossed, -1)
		mustEnvironment(t, r.err)
		before := prunedTreeBytes(t, s)
		out := s.SelectPrunedTreeProfileV1(true, tip, o)
		if !row.over {
			if out.Err != nil || out.Truth != CommitTruthNew || out.Authority == nil || len(prunedTreeBytes(t, s)) != MaxMetadataBytes {
				t.Fatalf("R11 control at the bound: %+v", out)
			}
			continue
		}
		if row.p == 4881 {
			treeNativeError(t, out.Err, operationUpdate, EngineLocalInvariant, codeProblem, "invalid pruned tree profile replacement", nil)
			prunedTreeRefusal(t, out, "R11 validity before size")
			prunedTreeOpenUnchanged(t, s, before, "R11 validity before size")
			continue
		}
		bootstrapRefusal(t, "R11 size bound", out.Truth, out.Err, EngineCapacity, operationUpdate, codeTooLarge, "Update Batch exceeds bound", nil, false)
		if out.Stage != UpdateStagePrewrite || out.Authority != nil || out.Decision != "" {
			t.Fatalf("R11 size bound: %+v", out)
		}
		prunedTreeOpenUnchanged(t, s, before, "R11 size bound")
	}
}

// TestPrunedTreeProfileChargeSpan is D6's source-structure evidence: in
// pruned_tree_profile_cgo.go the plan steps (D7 tip witness and suffix page, D8
// binding read, D9/D12 checks and Encode) are reached only through
// prunedTreeOperation, and prunedTreeOperation is called only inside the
// WithReservation callback of prunedTreeCompose, so the 1000-byte charge is held
// until every plan step has returned.
func TestPrunedTreeProfileChargeSpan(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "pruned_tree_profile_cgo.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	sites := map[string][]string{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Body != nil {
			prunedTreeCallSites(fn.Name.Name, fn.Body, sites)
		}
	}
	want := map[string][]string{
		"prunedTreeOperation":   {"prunedTreeCompose/WithReservation"},
		"prunedTreeTip":         {"prunedTreeOperation"},
		"prunedTreeBodyLimit":   {"prunedTreeOperation"},
		"prunedTreeReplacement": {"prunedTreeOperation"},
		"Encode":                {"prunedTreeReplacement"},
	}
	for name, at := range want {
		if !reflect.DeepEqual(sites[name], at) {
			t.Fatalf("D6 %s called at %v, want %v", name, sites[name], at)
		}
	}
}

// prunedTreeCallSites records, per called name, the enclosing function, marking
// calls inside a WithReservation callback literal with a /WithReservation suffix.
func prunedTreeCallSites(owner string, body ast.Node, sites map[string][]string) {
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := prunedTreeCallName(call.Fun)
		if name == "WithReservation" && len(call.Args) == 2 {
			prunedTreeCallSites(owner+"/WithReservation", call.Args[1], sites)
			return false
		}
		sites[name] = append(sites[name], owner)
		return true
	})
}

func prunedTreeCallName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}
