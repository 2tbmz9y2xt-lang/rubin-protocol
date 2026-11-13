//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"unsafe"
)

// Expected literals in this file come from the RUB-1660 contract text, the
// cited spec (TREE_LANE_MAX, RUBIN_COMPACT_BLOCKS.md section 10) and the
// independent test tree builder (testTreeBuild, testTreeLeafPreimage,
// testTreeBranchPreimage, testTreeC01), never from the producer's helpers.
const (
	treeRoleLaneMaxV1     uint64 = 154611183
	treeRoleTreeLaneMaxV1 uint64 = 402653184
	treeRoleRetainV1      uint64 = 8192
	treeRolePeakBindV1    uint64 = 11572
	treeRolePeakFiniteV1  uint64 = 143220
	treeRolePeakEvidV1    uint64 = 2107460
)

var (
	treeRoleChainV1   = testTreeHash(0x55)
	treeRoleGenesisV1 = testTreeHash(0x66)
	treeRoleAppliedV1 = testTreeApplied(5, 9, 37)
)

// treeRoleTreeV1 is one generation's independent row set and its literals.
type treeRoleTreeV1 struct {
	g        uint64
	binding  RootBindingV1
	counters TreeRoleCountersV1
	rows     map[string]Mutation
	nodes    map[string][]byte
}

func treeRoleValueV1(i byte) []byte { return tdFormed(tdFrame(uint64(i)+1, 0, nil), 1, 0) }

func treeRoleBuildV1(t *testing.T, g uint64, ep TreeEndpointV1, keys ...[36]byte) *treeRoleTreeV1 {
	t.Helper()
	tr := &treeRoleTreeV1{g: g, rows: map[string]Mutation{}}
	nodes := map[string][]byte{}
	var top *testTreeNode
	entries := make([]testTreeEntry, len(keys))
	for i, k := range keys {
		entries[i] = testTreeEntry{k: k, v: treeRoleValueV1(byte(i))}
		tr.setV1(1, tdUTXOKey(g, [32]byte(k[:32]), binary.BigEndian.Uint32(k[32:])), entries[i].v)
		tr.counters.LogicalStateBytes += 36 + uint64(len(entries[i].v))
	}
	tr.counters.UTXOCount = uint64(len(keys))
	if len(entries) != 0 {
		root := testTreeBuild(g, entries, nodes)
		top = &root
	}
	// Rank-8 node rows are refused by a Pair batch; node-bearing rows are
	// seeded by treeNativeSeed in tree_role_fixture_cgo_test.go.
	tr.nodes = nodes
	tr.binding = testTreeOldBinding(top, ep)
	tr.binding.DatabaseID = [32]byte{7}
	return tr
}

// setV1 sets the row at rank and key.
func (tr *treeRoleTreeV1) setV1(rank uint8, key, value []byte) {
	tr.rows[fmt.Sprintf("%d:%x", rank, key)] = Mutation{DBI: TreeSchemaV1DBIs()[rank], Key: key, AfterKind: 2, Literal: value}
}

// seedV1 writes the binding, the counter (unless noCounter) and the rows.
func (tr *treeRoleTreeV1) seedV1(t *testing.T, s *Store, o *OperationReservationOwner, noCounter bool) {
	t.Helper()
	encoded, err := tr.binding.Encode()
	mustEnvironment(t, err)
	tr.setV1(0, tsRootKey(tr.g), encoded)
	if !noCounter {
		tr.setV1(0, tsCounterKey(tr.g), tsCounterLiteral(tr.counters.LogicalStateBytes, tr.counters.UTXOCount))
	}
	treeRoleWriteV1(t, s, o, tr.rows)
}

func treeRoleWriteV1(t *testing.T, s *Store, o *OperationReservationOwner, rows map[string]Mutation) {
	t.Helper()
	muts := make([]Mutation, 0, len(rows))
	for _, m := range rows {
		muts = append(muts, m)
	}
	slices.SortFunc(muts, func(a, b Mutation) int {
		if a.DBI.Rank != b.DBI.Rank {
			return int(a.DBI.Rank) - int(b.DBI.Rank)
		}
		return bytes.Compare(a.Key, b.Key)
	})
	r := tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: TreePairV1{Mutations: muts}})
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
}

func treeRoleActiveV1(current, lag uint64) TreeAuthorityV1 {
	return TreeAuthorityV1{Authority: StorageAuthorityV1{Version: 1, ActiveProfile: 1, ActiveGenerationID: current, NextGenerationID: 90, Phase: 1, Lifecycle: 1}, LagGenerationID: lag}
}

func treeRoleReplayV1(source TreeSourceKindV1, progress TreeProgressKindV1, cursor ReplayCursorV1) TreeAuthorityV1 {
	a := treeRoleActiveV1(1, 2)
	a.Authority.Phase = StoragePhaseReplayV1
	a.Authority.Replay = &ReplayV1{TargetProfile: 1, TargetGenerationID: 3, Cursor: cursor}
	a.TargetLagGenerationID, a.SourceKind = 4, source
	a.Progress.Kind = progress
	if progress != TreeProgressNoneV1 {
		a.Progress.Payload = []byte{0xa5}
	}
	return a
}

func treeRoleReqV1(a TreeAuthorityV1, role TreeRoleSelectorV1) TreeRoleBindingRequestV1 {
	return TreeRoleBindingRequestV1{Authority: a, Role: role, ChainID: treeRoleChainV1, GenesisHash: treeRoleGenesisV1}
}

// treeRoleViewV1 runs use inside one account frame and one View; it returns the View error.
func treeRoleViewV1(t *testing.T, s *Store, o *OperationReservationOwner, kind OperationKind, use func(*Reader, *OperationAccount)) error {
	t.Helper()
	var viewErr error
	mustEnvironment(t, o.WithOperation(kind, func(a *OperationAccount) error {
		viewErr = s.View(func(r *Reader) error { use(r, a); return nil })
		return nil
	}))
	if reservationLive(o) != 0 {
		t.Fatalf("owner live %d after the frame", reservationLive(o))
	}
	return viewErr
}

func treeRoleFinalReqV1(bound TreeRoleObservationV1, ep TreeEndpointV1, counters *TreeRoleCountersV1) TreeRoleRequestV1 {
	request := TreeRoleRequestV1{Bound: bound, Endpoint: ep, Counters: counters}
	if ep.Kind == TreeEndpointAppliedV1 {
		root := bound.Binding.RootDigest
		request.HeaderRoot = &root
	}
	return request
}

// treeRoleObserveV1 runs the binding stage then the finite stage of one role.
func treeRoleObserveV1(t *testing.T, r *Reader, a *OperationAccount, request TreeRoleBindingRequestV1, ep TreeEndpointV1, counters *TreeRoleCountersV1) (TreeRoleObservationV1, TreeRoleObservationV1) {
	t.Helper()
	bound, err := r.ObserveTreeRoleBindingV1(a, request)
	mustEnvironment(t, err)
	if bound.Status != TreeRoleBoundV1 {
		return bound, TreeRoleObservationV1{}
	}
	final, err := treeRoleFiniteCallV1(t, r, a, treeRoleFinalReqV1(bound, ep, counters))
	mustEnvironment(t, err)
	if final.Binding.Top.Node != nil && final.Binding.Top.Node == bound.Binding.Top.Node {
		t.Fatal("Qualified role shares a public Top.Node pointer with its separately returned Bound role")
	}
	return bound, final
}

// treeRoleSafeV1 runs one producer call and turns a panic into a test error
// and a zero result with a nil error, so the calling row still reaches its own
// assertion and a panic never ends the test binary before later tests run.
func treeRoleSafeV1[T any](t *testing.T, call func() (T, error)) (got T, err error) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("producer call panicked: %v", p)
			var zero T
			got, err = zero, nil
		}
	}()
	return call()
}

func treeRoleFiniteCallV1(t *testing.T, r *Reader, a *OperationAccount, request TreeRoleRequestV1) (TreeRoleObservationV1, error) {
	t.Helper()
	return treeRoleSafeV1(t, func() (TreeRoleObservationV1, error) { return r.ObserveTreeRoleV1(a, request) })
}

// treeRolePublicV1 is the exported projection of an observation. The private
// stage records reach *Reader, which holds an error, so they are compared by
// identity and never by reflect.DeepEqual.
type treeRolePublicV1 struct {
	Status     TreeRoleStatusV1
	Role       TreeRoleSelectorV1
	Generation uint64
	Binding    RootBindingV1
	Counters   TreeRoleCountersV1
	Position   TreeRolePositionV1
	Finding    TreeRoleFindingV1
}

func treeRoleProjectV1(o TreeRoleObservationV1) treeRolePublicV1 {
	return treeRolePublicV1{o.Status, o.Role, o.Generation, o.Binding, o.Counters, o.Position, o.Finding}
}

// treeRoleSameV1 is true when both observations hold the same private stage
// records and equal exported fields, nested pointer targets included.
func treeRoleSameV1(a, b TreeRoleObservationV1) bool {
	return a.bound == b.bound && a.finite == b.finite && reflect.DeepEqual(treeRoleProjectV1(a), treeRoleProjectV1(b))
}

func treeRoleWantPositiveV1(t *testing.T, got TreeRoleObservationV1, role TreeRoleSelectorV1, g uint64, position TreeRolePositionV1, finding TreeRoleFindingV1) {
	t.Helper()
	want := TreeRoleObservationV1{Status: TreeRolePositiveV1, Role: role, Generation: g, Position: position, Finding: finding}
	if !treeRoleSameV1(got, want) {
		t.Fatalf("observation %+v, want %+v", got, want)
	}
}

func treeRoleWantQualifiedV1(t *testing.T, got TreeRoleObservationV1, role TreeRoleSelectorV1, tr *treeRoleTreeV1) {
	t.Helper()
	want := treeRolePublicV1{Status: TreeRoleQualifiedV1, Role: role, Generation: tr.g, Binding: tr.binding, Counters: tr.counters}
	if !reflect.DeepEqual(treeRoleProjectV1(got), want) {
		t.Fatalf("observation %+v, want %+v", treeRoleProjectV1(got), want)
	}
}

func treeRoleWantInvalidV1(t *testing.T, err error) {
	t.Helper()
	engine, direct := directTestEngineError(err)
	if !direct || engine.Class != EngineInvalidInput || engine.Code != codeEINVAL || engine.Operation != string(operationGet) || engine.Diagnostic == "Reader is not active" {
		t.Fatalf("error %v, want the producer EngineInvalidInput/EINVAL/get refusal", err)
	}
}

func TestTreeRoleQualificationV1(t *testing.T) {
	t.Run("sizes", treeRoleSizesV1)
	t.Run("shapes", treeRoleShapesV1)
	t.Run("targets", treeRoleTargetsV1)
	t.Run("binding-corpus", treeRoleBindingCorpusV1)
	t.Run("target-local", treeRoleTargetLocalV1)
	t.Run("stream-top", treeRoleStreamTopV1)
	t.Run("import-pointee-edit", treeRoleImportEditV1)
	t.Run("ledger", treeRoleLedgerV1)
	t.Run("lifetime", treeRoleLifetimeV1)
	t.Run("admission", treeRoleAdmissionV1)
}

// treeRoleSizesV1 pins the inventoried layouts on the supported 64-bit
// targets: contract line 141 (TreeChildV1 108, TreeNodeV1 48, UTXOValue 56),
// line 142 (TreeEvidenceV1 72, reference 88), the S1 measured retention sizes,
// and the retention components of line 139.
func treeRoleSizesV1(t *testing.T) {
	sizes := []struct {
		name      string
		got, want uintptr
	}{
		{"TreeChildV1", unsafe.Sizeof(TreeChildV1{}), 108},
		{"TreeNodeV1", unsafe.Sizeof(TreeNodeV1{}), 48},
		{"UTXOValue", unsafe.Sizeof(UTXOValue{}), 56},
		{"TreeEvidenceV1", unsafe.Sizeof(TreeEvidenceV1{}), 72},
		{"TreeImportReferenceV1", unsafe.Sizeof(TreeImportReferenceV1{}), 88},
		{"TreeNodeIDV1", unsafe.Sizeof(TreeNodeIDV1{}), 76},
		{"TreeRoleObservationV1", unsafe.Sizeof(TreeRoleObservationV1{}), 312},
		{"TreePairQualificationV1", unsafe.Sizeof(TreePairQualificationV1{}), 640},
		{"TreeRoleBindingRequestV1", unsafe.Sizeof(TreeRoleBindingRequestV1{}), 240},
		{"TreeRoleRequestV1", unsafe.Sizeof(TreeRoleRequestV1{}), 416},
		// Producer-frame inventory types (S1: RootBindingV1 256, treeRoleVisitV1 200).
		{"RootBindingV1", unsafe.Sizeof(RootBindingV1{}), 256},
		{"treeRoleVisitV1", unsafe.Sizeof(treeRoleVisitV1{}), 200},
		{"treeRolePairIDV1", unsafe.Sizeof(treeRolePairIDV1{}), 184},
		{"treeRoleBoundV1", unsafe.Sizeof(treeRoleBoundV1{}), 632},
		{"treeRoleFiniteV1", unsafe.Sizeof(treeRoleFiniteV1{}), 24},
		{"treePairStageV1", unsafe.Sizeof(treePairStageV1{}), 48},
		{"TreeEndpointV1", unsafe.Sizeof(TreeEndpointV1{}), 88},
		{"TreeRoleCountersV1", unsafe.Sizeof(TreeRoleCountersV1{}), 16},
		{"treeImageV1", unsafe.Sizeof(treeImageV1{}), 32},
		// Producer-frame array and pointer-array locals (meta key, evidence key,
		// txid/digest, routing key, branch child pair).
		{"[9]byte", unsafe.Sizeof([9]byte{}), 9},
		{"[32]byte", unsafe.Sizeof([32]byte{}), 32},
		{"[33]byte", unsafe.Sizeof([33]byte{}), 33},
		{"[36]byte", unsafe.Sizeof([36]byte{}), 36},
		{"[2]*TreeChildV1", unsafe.Sizeof([2]*TreeChildV1{}), 16},
	}
	for _, size := range sizes {
		if size.got != size.want {
			t.Errorf("unsafe.Sizeof(%s) = %d, want %d", size.name, size.got, size.want)
		}
	}
	slot := unsafe.Sizeof(TreeRoleObservationV1{}) + unsafe.Sizeof(TreeNodeIDV1{}) + unsafe.Sizeof(TreeImportReferenceV1{})
	if slot > 512 {
		t.Errorf("observation slot with owned pointees %d > 512", slot)
	}
	if b := unsafe.Sizeof(treeRoleBoundV1{}) + unsafe.Sizeof(TreeNodeIDV1{}) + unsafe.Sizeof(TreeImportReferenceV1{}); b > 1024 {
		t.Errorf("private binding record %d > 1024", b)
	}
	if f, p := unsafe.Sizeof(treeRoleFiniteV1{}), unsafe.Sizeof(treePairStageV1{}); f > 256 || p > 256 {
		t.Errorf("private finite %d or pair stage %d > 256", f, p)
	}
}

// treeRoleShapesV1 is the node-free part of A1: N=0 shapes are Qualified
// with independent literals in two generations holding byte-identical maps.
func treeRoleShapesV1(t *testing.T) {
	s, _, o := tsNew(t)
	shapes := []struct {
		name string
		ep   TreeEndpointV1
		keys [][36]byte
	}{
		{"empty-pre-genesis", TreeEndpointV1{}, nil},
		{"empty-applied", treeRoleAppliedV1, nil},
	}
	for i, shape := range shapes {
		current := treeRoleBuildV1(t, uint64(10+2*i), shape.ep, shape.keys...)
		lag := treeRoleBuildV1(t, uint64(11+2*i), shape.ep, shape.keys...)
		current.seedV1(t, s, o, false)
		lag.seedV1(t, s, o, false)
		if current.binding.RootDigest != lag.binding.RootDigest {
			t.Fatalf("%s: equal maps built different digests", shape.name)
		}
		auth := treeRoleActiveV1(current.g, lag.g)
		mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
			_, c := treeRoleObserveV1(t, r, a, treeRoleReqV1(auth, TreeRoleCurrentV1), shape.ep, nil)
			_, l := treeRoleObserveV1(t, r, a, treeRoleReqV1(auth, TreeRoleLagV1), shape.ep, nil)
			treeRoleWantQualifiedV1(t, c, TreeRoleCurrentV1, current)
			treeRoleWantQualifiedV1(t, l, TreeRoleLagV1, lag)
		}))
	}
}

// treeRoleTargetsV1 is A2: GENESIS_REPLAY target at its exact cursor, IMAGE
// COMPLETE target, and IMAGE PARTIAL as PartialDomain with zero reservation.
func treeRoleTargetsV1(t *testing.T) {
	s, _, o := tsNew(t)
	targetCurrent := treeRoleBuildV1(t, 3, treeRoleAppliedV1)
	targetLag := treeRoleBuildV1(t, 4, TreeEndpointV1{})
	targetCurrent.seedV1(t, s, o, false)
	targetLag.seedV1(t, s, o, false)
	cursor := ReplayCursorV1{Kind: ReplayCursorAppliedV1, Height: treeRoleAppliedV1.Height, BlockHash: treeRoleAppliedV1.BlockHash}
	replay := treeRoleReplayV1(TreeSourceGenesisReplayV1, TreeProgressNoneV1, cursor)
	image := treeRoleReplayV1(TreeSourceImageV1, TreeProgressCompleteV1, ReplayCursorV1{})
	partial := treeRoleReplayV1(TreeSourceImageV1, TreeProgressPartialV1, ReplayCursorV1{})
	mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
		for _, auth := range []TreeAuthorityV1{replay, image} {
			_, c := treeRoleObserveV1(t, r, a, treeRoleReqV1(auth, TreeRoleTargetCurrentV1), treeRoleAppliedV1, nil)
			_, l := treeRoleObserveV1(t, r, a, treeRoleReqV1(auth, TreeRoleTargetLagV1), TreeEndpointV1{}, nil)
			treeRoleWantQualifiedV1(t, c, TreeRoleTargetCurrentV1, targetCurrent)
			treeRoleWantQualifiedV1(t, l, TreeRoleTargetLagV1, targetLag)
		}
		// Zero reservation: the whole account ceiling is held by the caller.
		mustEnvironment(t, a.WithReservation(treeRoleLaneMaxV1, func() error {
			for _, role := range []TreeRoleSelectorV1{TreeRoleTargetCurrentV1, TreeRoleTargetLagV1} {
				got, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(partial, role))
				want := TreeRoleObservationV1{Status: TreeRolePartialDomainV1, Role: role, Generation: uint64(role)}
				if err != nil || !treeRoleSameV1(got, want) {
					t.Fatalf("PARTIAL role %d = %+v, %v", role, got, err)
				}
			}
			return nil
		}))
		// Target CURRENT under GENESIS_REPLAY must equal the cursor.
		bound, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(replay, TreeRoleTargetCurrentV1))
		mustEnvironment(t, err)
		for _, ep := range []TreeEndpointV1{testTreeApplied(6, 9, 37), testTreeApplied(5, 8, 37)} {
			_, err = r.ObserveTreeRoleV1(a, treeRoleFinalReqV1(bound, ep, nil))
			treeRoleWantInvalidV1(t, err)
		}
		// Kind alone: a PRE_GENESIS cursor against a valid APPLIED endpoint
		// at height 0 with the zero hash is refused; the PRE_GENESIS endpoint
		// passes admission (selectivity control).
		pre := treeRoleReplayV1(TreeSourceGenesisReplayV1, TreeProgressNoneV1, ReplayCursorV1{Kind: ReplayCursorPreGenesisV1})
		bound, err = r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(pre, TreeRoleTargetCurrentV1))
		mustEnvironment(t, err)
		root := bound.Binding.RootDigest
		kindOnly := TreeEndpointV1{Kind: TreeEndpointAppliedV1, CumulativeChainwork: [40]byte{39: 1}}
		_, err = r.ObserveTreeRoleV1(a, TreeRoleRequestV1{Bound: bound, Endpoint: kindOnly, HeaderRoot: &root})
		treeRoleWantInvalidV1(t, err)
		got, err := r.ObserveTreeRoleV1(a, treeRoleFinalReqV1(bound, TreeEndpointV1{}, nil))
		mustEnvironment(t, err)
		treeRoleWantPositiveV1(t, got, TreeRoleTargetCurrentV1, 3, TreeRoleAtBindingV1, TreeRoleWrongIdentityV1)
	}))
}

// treeRoleBindingCorpusV1 is the store-encodable part of R4 plus H2's first
// relation: each row Positive at Binding with its Finding.
func treeRoleBindingCorpusV1(t *testing.T) {
	s, _, o := tsNew(t)
	good := treeRoleBuildV1(t, 40, treeRoleAppliedV1, testKA)
	foreign := treeRoleBuildV1(t, 41, treeRoleAppliedV1, testKA)
	foreign.binding.DatabaseID = [32]byte{9}
	good.seedV1(t, s, o, false)
	foreign.seedV1(t, s, o, false)
	mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
		at := func(current uint64, mutate func(*TreeRoleBindingRequestV1)) TreeRoleObservationV1 {
			request := treeRoleReqV1(treeRoleActiveV1(current, 2), TreeRoleCurrentV1)
			mutate(&request)
			got, err := r.ObserveTreeRoleBindingV1(a, request)
			mustEnvironment(t, err)
			return got
		}
		none := func(*TreeRoleBindingRequestV1) {}
		treeRoleWantPositiveV1(t, at(49, none), TreeRoleCurrentV1, 49, TreeRoleAtBindingV1, TreeRoleAbsentV1)
		treeRoleWantPositiveV1(t, at(41, none), TreeRoleCurrentV1, 41, TreeRoleAtBindingV1, TreeRoleWrongIdentityV1)
		treeRoleWantPositiveV1(t, at(40, func(q *TreeRoleBindingRequestV1) { q.ChainID[0] ^= 1 }), TreeRoleCurrentV1, 40, TreeRoleAtBindingV1, TreeRoleWrongIdentityV1)
		treeRoleWantPositiveV1(t, at(40, func(q *TreeRoleBindingRequestV1) { q.GenesisHash[31] ^= 1 }), TreeRoleCurrentV1, 40, TreeRoleAtBindingV1, TreeRoleWrongIdentityV1)
		bound := at(40, none)
		if bound.Status != TreeRoleBoundV1 || !reflect.DeepEqual(bound.Binding, good.binding) || bound.Counters != (TreeRoleCountersV1{}) || bound.Position != 0 || bound.Finding != 0 {
			t.Fatalf("Bound %+v, want binding literal only", bound)
		}
		other := treeRoleAppliedV1
		other.CumulativeChainwork[39]++
		endpoints := []TreeEndpointV1{{}, testTreeApplied(6, 9, 37), testTreeApplied(5, 8, 37), other}
		for _, ep := range endpoints {
			got, err := r.ObserveTreeRoleV1(a, treeRoleFinalReqV1(bound, ep, nil))
			mustEnvironment(t, err)
			treeRoleWantPositiveV1(t, got, TreeRoleCurrentV1, 40, TreeRoleAtBindingV1, TreeRoleWrongIdentityV1)
		}
		request := treeRoleFinalReqV1(bound, treeRoleAppliedV1, nil)
		request.HeaderRoot[0] ^= 1
		got, err := r.ObserveTreeRoleV1(a, request)
		mustEnvironment(t, err)
		treeRoleWantPositiveV1(t, got, TreeRoleCurrentV1, 40, TreeRoleAtBindingV1, TreeRoleWrongIdentityV1)
	}))
}

// treeRoleTargetLocalV1 is R1's distinguishing rows: a foreign target binding
// and an absent target node are Positive, unrecorded, and the same Store
// handle serves a following View.
func treeRoleTargetLocalV1(t *testing.T) {
	image := treeRoleReplayV1(TreeSourceImageV1, TreeProgressCompleteV1, ReplayCursorV1{})
	for _, row := range []struct {
		name               string
		role               TreeRoleSelectorV1
		foreign, noCounter bool
		position           TreeRolePositionV1
		finding            TreeRoleFindingV1
	}{
		{"current-foreign", TreeRoleTargetCurrentV1, true, false, TreeRoleAtBindingV1, TreeRoleWrongIdentityV1},
		{"lag-foreign", TreeRoleTargetLagV1, true, false, TreeRoleAtBindingV1, TreeRoleWrongIdentityV1},
		{"current-counter-absent", TreeRoleTargetCurrentV1, false, true, TreeRoleAtCounterV1, TreeRoleAbsentV1},
		{"lag-counter-absent", TreeRoleTargetLagV1, false, true, TreeRoleAtCounterV1, TreeRoleAbsentV1},
		{"current-top-absent", TreeRoleTargetCurrentV1, false, false, TreeRoleAtTopV1, TreeRoleAbsentV1},
		{"lag-top-absent", TreeRoleTargetLagV1, false, false, TreeRoleAtTopV1, TreeRoleAbsentV1},
	} {
		t.Run(row.name, func(t *testing.T) {
			s, _, o := tsNew(t)
			tr := treeRoleBuildV1(t, uint64(row.role), treeRoleAppliedV1, testKA)
			if row.foreign {
				tr.binding.DatabaseID = [32]byte{9}
			}
			tr.seedV1(t, s, o, row.noCounter)
			err := treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
				bound, final := treeRoleObserveV1(t, r, a, treeRoleReqV1(image, row.role), treeRoleAppliedV1, nil)
				got := final
				if row.position == TreeRoleAtBindingV1 {
					got = bound
				}
				treeRoleWantPositiveV1(t, got, row.role, uint64(row.role), row.position, row.finding)
				if !r.usable() || r.failure != nil {
					t.Fatal("Positive target finding left the Reader unusable or recorded")
				}
			})
			mustEnvironment(t, err)
			mustEnvironment(t, s.View(func(*Reader) error { return nil }))
		})
	}
}

// treeRoleImportV1 is an independent reference and its evidence bytes.
func treeRoleImportV1(role TreeOriginalRoleV1, lag uint64) (TreeImportReferenceV1, []byte) {
	database := testTreeHash(0x21)
	value := append([]byte{1}, database[:]...)
	value = binary.BigEndian.AppendUint64(value, 7)
	value = binary.BigEndian.AppendUint64(value, 8)
	value = binary.BigEndian.AppendUint32(value, 3)
	value = append(value, 0xc1, 0xc2, 0xc3)
	return TreeImportReferenceV1{OriginalDatabaseID: testTreeHash(0x21), OriginalCurrentID: 7, OriginalLagID: lag, OriginalRole: role, EvidenceID: sha3.Sum256(value)}, value
}

func treeRoleAssuredV1(t *testing.T, s *Store, o *OperationReservationOwner, g uint64, ref *TreeImportReferenceV1) *treeRoleTreeV1 {
	t.Helper()
	tr := treeRoleBuildV1(t, g, TreeEndpointV1{})
	if ref != nil {
		copied := *ref
		tr.binding.Assurance = TreeAssuranceV1{Kind: TreeAssuranceImportedBaseV1, Import: &copied}
	}
	tr.seedV1(t, s, o, false)
	return tr
}

// treeRoleImportEditV1 is A7/M26 for Assurance.Import: a second Bound call
// returns its own Import allocation, and editing a returned Import target in
// place makes the role altered input for both later stages.
func treeRoleImportEditV1(t *testing.T) {
	s, _, o := tsNew(t)
	ref, _ := treeRoleImportV1(TreeOriginalCurrentV1, 8)
	treeRoleAssuredV1(t, s, o, 1, &ref)
	treeRoleAssuredV1(t, s, o, 2, nil)
	auth := treeRoleActiveV1(1, 2)
	mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
		c, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleCurrentV1))
		mustEnvironment(t, err)
		again, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleCurrentV1))
		mustEnvironment(t, err)
		l, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleLagV1))
		mustEnvironment(t, err)
		if c.Binding.Assurance.Import == nil || c.Binding.Assurance.Import == again.Binding.Assurance.Import {
			t.Fatal("separately returned Bound roles share one public Import allocation")
		}
		// Positive control: the same three calls on the unedited role are
		// admitted, so each refusal below is attributable to the Import edit.
		// No evidence row is seeded: the C, F pair is Defective, Affected Current.
		pair, err := r.QualifyTreePairAssuranceV1(a, c, l)
		mustEnvironment(t, err)
		if pair.Status != TreePairDefectiveV1 || pair.Affected != TreePairAffectedCurrentV1 || pair.Defect != TreePairEvidenceAbsentV1 {
			t.Fatalf("unedited pair %+v, want Defective, Affected Current, EvidenceAbsent", pair)
		}
		fin, err := treeRoleFiniteCallV1(t, r, a, treeRoleFinalReqV1(c, TreeEndpointV1{}, nil))
		mustEnvironment(t, err)
		if fin.Status != TreeRoleQualifiedV1 {
			t.Fatalf("unedited finite call %+v, want Qualified", fin)
		}
		wrong, err := treeRoleFiniteCallV1(t, r, a, treeRoleFinalReqV1(c, treeRoleAppliedV1, nil))
		mustEnvironment(t, err)
		treeRoleWantPositiveV1(t, wrong, TreeRoleCurrentV1, 1, TreeRoleAtBindingV1, TreeRoleWrongIdentityV1)
		c.Binding.Assurance.Import.OriginalCurrentID++
		_, err = r.QualifyTreePairAssuranceV1(a, c, l)
		treeRoleWantInvalidV1(t, err)
		_, err = treeRoleFiniteCallV1(t, r, a, treeRoleFinalReqV1(c, TreeEndpointV1{}, nil))
		treeRoleWantInvalidV1(t, err)
		// Bound validation precedes endpoint equality: this valid endpoint differs
		// from the PRE_GENESIS binding, so the reverse order is WrongIdentity.
		_, err = treeRoleFiniteCallV1(t, r, a, treeRoleFinalReqV1(c, treeRoleAppliedV1, nil))
		treeRoleWantInvalidV1(t, err)
	}))
}

// treeRoleLedgerV1 is A6 and R8: exact temporary admission boundaries under a
// held 8192 retention frame, on LaneOperation and TreeOperation.
func treeRoleLedgerV1(t *testing.T) {
	s, _, o := tsNew(t)
	// The evidence row is absent here: the evidence call still reserves its
	// full temporary bound before its read and returns Defective. The
	// fixture file's ledger-resolved row seeds the evidence and requires
	// AssuranceOnly at the same boundary.
	treeRoleLedgerSeedV1(t, s, o)
	treeRoleLedgerLanesV1(t, s, o, TreePairDefectiveV1)
}

// treeRoleLedgerSeedV1 seeds an N=0 APPLIED conditional CURRENT (generation
// 1, Qualified without node rows) and a FULL_HISTORY LAG (generation 2); it
// returns the CURRENT reference and its evidence bytes.
func treeRoleLedgerSeedV1(t *testing.T, s *Store, o *OperationReservationOwner) (TreeImportReferenceV1, []byte) {
	t.Helper()
	ref, value := treeRoleImportV1(TreeOriginalCurrentV1, 8)
	current := treeRoleBuildV1(t, 1, treeRoleAppliedV1)
	current.binding.Assurance = TreeAssuranceV1{Kind: TreeAssuranceImportedBaseV1, Import: &ref}
	current.seedV1(t, s, o, false)
	treeRoleAssuredV1(t, s, o, 2, nil)
	return ref, value
}

// treeRoleLedgerLanesV1 runs the A6/R8 boundary on both lanes; at the exact
// boundary the binding call returns Bound, the finite call Qualified and the
// evidence call evidence.
func treeRoleLedgerLanesV1(t *testing.T, s *Store, o *OperationReservationOwner, evidence TreePairStatusV1) {
	t.Helper()
	for _, lane := range []struct {
		kind    OperationKind
		ceiling uint64
	}{{LaneOperation, treeRoleLaneMaxV1}, {TreeOperation, treeRoleTreeLaneMaxV1}} {
		for _, extra := range []uint64{0, 1} {
			t.Run(fmt.Sprintf("%d+%d", lane.kind, extra), func(t *testing.T) {
				treeRoleBoundaryV1(t, s, o, lane.kind, lane.ceiling, extra, evidence)
			})
		}
	}
}

// treeRoleSucceededV1 fails the test when a call that returned no error did
// not return its success status; it returns err unchanged.
func treeRoleSucceededV1(t *testing.T, err error, ok bool, name string) error {
	t.Helper()
	if err == nil && !ok {
		t.Fatalf("%s call at its admitted boundary did not return its success status", name)
	}
	return err
}

func treeRoleBoundaryV1(t *testing.T, s *Store, o *OperationReservationOwner, kind OperationKind, ceiling, extra uint64, evidence TreePairStatusV1) {
	t.Helper()
	auth := treeRoleActiveV1(1, 2)
	mustEnvironment(t, treeRoleViewV1(t, s, o, kind, func(r *Reader, a *OperationAccount) {
		mustEnvironment(t, a.WithReservation(treeRoleRetainV1, func() error {
			base := reservationLive(o)
			c, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleCurrentV1))
			mustEnvironment(t, err)
			l, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleLagV1))
			mustEnvironment(t, err)
			calls := []struct {
				peak uint64
				call func() error
			}{
				{treeRolePeakBindV1, func() error {
					got, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleCurrentV1))
					return treeRoleSucceededV1(t, err, got.Status == TreeRoleBoundV1, "binding")
				}},
				{treeRolePeakFiniteV1, func() error {
					got, err := r.ObserveTreeRoleV1(a, treeRoleFinalReqV1(c, treeRoleAppliedV1, nil))
					return treeRoleSucceededV1(t, err, got.Status == TreeRoleQualifiedV1, "finite")
				}},
				{treeRolePeakEvidV1, func() error {
					q, err := r.QualifyTreePairAssuranceV1(a, c, l)
					return treeRoleSucceededV1(t, err, q.Status == evidence, "evidence")
				}},
			}
			for _, call := range calls {
				treeRoleHeldCallV1(t, r, a, o, ceiling-call.peak+extra, extra != 0, call.call)
				if reservationLive(o) != base {
					t.Fatalf("live %d after the call, want %d", reservationLive(o), base)
				}
			}
			return nil
		}))
	}))
}

func treeRoleHeldCallV1(t *testing.T, r *Reader, a *OperationAccount, o *OperationReservationOwner, hold uint64, refuse bool, call func() error) {
	t.Helper()
	mustEnvironment(t, a.WithReservation(hold, func() error {
		before := reservationLive(o)
		err := call()
		switch {
		case refuse && !IsOperationReservationCapacity(err):
			t.Fatalf("hold %d: error %v, want capacity", hold, err)
		case !refuse && err != nil:
			t.Fatalf("hold %d: %v", hold, err)
		}
		if reservationLive(o) != before || !r.usable() {
			t.Fatal("call changed held charges or the Reader")
		}
		if refuse {
			_, err = r.ObserveTreeRoleBindingV1(a, TreeRoleBindingRequestV1{})
			treeRoleWantInvalidV1(t, err)
		}
		return nil
	}))
}

// treeRoleFullChainV1 runs the full valid one-pair chain on r.
func treeRoleFullChainV1(t *testing.T, r *Reader, a *OperationAccount, auth TreeAuthorityV1) (TreePairQualificationV1, TreePairQualificationV1, [4]TreeRoleObservationV1) {
	t.Helper()
	cb, cq := treeRoleObserveV1(t, r, a, treeRoleReqV1(auth, TreeRoleCurrentV1), treeRoleAppliedV1, nil)
	lb, lq := treeRoleObserveV1(t, r, a, treeRoleReqV1(auth, TreeRoleLagV1), TreeEndpointV1{}, nil)
	early, err := r.QualifyTreePairAssuranceV1(a, cb, lb)
	mustEnvironment(t, err)
	final, err := r.CompleteTreePairQualificationV1(early, cq, lq)
	mustEnvironment(t, err)
	return early, final, [4]TreeRoleObservationV1{cb, lb, cq, lq}
}

// treeRoleLifetimeV1 is A5's HealthyOn progression, A7, the store-encodable
// rows of R3 and H6.
func treeRoleLifetimeV1(t *testing.T) {
	s, _, o := tsNew(t)
	current := treeRoleBuildV1(t, 1, treeRoleAppliedV1)
	current.seedV1(t, s, o, false)
	treeRoleAssuredV1(t, s, o, 2, nil)
	other := treeRoleBuildV1(t, 5, treeRoleAppliedV1)
	other.seedV1(t, s, o, false)
	for _, g := range []uint64{3, 4, 6, 7} { // target pair; 6 and 7 carry another chain_id, genesis_hash
		tr := treeRoleBuildV1(t, g, TreeEndpointV1{})
		switch g {
		case 6:
			tr.binding.ChainID[0] ^= 1
		case 7:
			tr.binding.GenesisHash[0] ^= 1
		}
		tr.seedV1(t, s, o, false)
	}
	s2, _, o2 := tsNew(t)
	current.seedV1(t, s2, o2, false)
	treeRoleAssuredV1(t, s2, o2, 2, nil)
	auth := treeRoleActiveV1(1, 2)
	var expired *Reader
	var held TreePairQualificationV1
	var heldRoles [4]TreeRoleObservationV1
	mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
		early, final, roles := treeRoleFullChainV1(t, r, a, auth)
		expired, held, heldRoles = r, final, roles
		if early.HealthyOn(r) || !final.HealthyOn(r) || final.HealthyOn(nil) || (TreePairQualificationV1{}).HealthyOn(r) {
			t.Fatal("HealthyOn progression")
		}
		treeRoleWantQualifiedV1(t, final.Current, TreeRoleCurrentV1, current)
		copied := final
		if !copied.HealthyOn(r) {
			t.Fatal("an unchanged copy lost its identity")
		}
		treeRoleAlteredV1(t, r, a, final)
		treeRoleCompletionRefusalsV1(t, r, a, early, roles)
		treeRoleCrossPairsV1(t, r, a)
		_, later := treeRoleObserveV1(t, r, a, treeRoleReqV1(treeRoleActiveV1(5, 2), TreeRoleCurrentV1), treeRoleAppliedV1, nil)
		treeRoleWantQualifiedV1(t, later, TreeRoleCurrentV1, other)
		treeRoleWantQualifiedV1(t, final.Current, TreeRoleCurrentV1, current)
		treeRoleWantQualifiedV1(t, roles[2], TreeRoleCurrentV1, current)
		mustEnvironment(t, treeRoleViewV1(t, s2, o2, LaneOperation, func(r2 *Reader, _ *OperationAccount) {
			if final.HealthyOn(r2) {
				t.Fatal("HealthyOn true on another usable Reader")
			}
		}))
	}))
	if held.HealthyOn(expired) {
		t.Fatal("HealthyOn true after the View ended")
	}
	mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
		if held.HealthyOn(r) {
			t.Fatal("an expired pair is HealthyOn on a later live Reader")
		}
		_, err := r.QualifyTreePairAssuranceV1(a, heldRoles[0], heldRoles[1])
		treeRoleWantInvalidV1(t, err)
		_, err = r.ObserveTreeRoleV1(a, treeRoleFinalReqV1(heldRoles[0], treeRoleAppliedV1, nil))
		treeRoleWantInvalidV1(t, err)
		_, err = r.CompleteTreePairQualificationV1(held, heldRoles[2], heldRoles[3])
		treeRoleWantInvalidV1(t, err)
		_, _, _ = treeRoleFullChainV1(t, r, a, auth)
	}))
}

// treeRoleAlteredV1: every exported-field edit invalidates a final pair.
func treeRoleAlteredV1(t *testing.T, r *Reader, a *OperationAccount, final TreePairQualificationV1) {
	t.Helper()
	// One edit per compared field (treeRoleOwnsV1, treeRoleBindingEqualV1 and
	// the Counters check); the empty FULL_HISTORY CURRENT has nil Top.Node and
	// Assurance.Import, so their edits set a pointer. A real Positive
	// observation: generation 9 has no binding row.
	positive, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(treeRoleActiveV1(1, 9), TreeRoleLagV1))
	if err != nil || positive.Status != TreeRolePositiveV1 {
		t.Fatalf("absent lag binding: %+v %v", positive, err)
	}
	node := TreeNodeIDV1{Kind: TreeNodeLeafV1, Depth: 288}
	edits := []func(*TreePairQualificationV1){
		func(q *TreePairQualificationV1) { q.Status = TreePairAssuranceOnlyV1 },
		func(q *TreePairQualificationV1) { q.Affected = TreePairAffectedLagV1 },
		func(q *TreePairQualificationV1) { q.Defect = TreePairWrongRoleV1 },
		func(q *TreePairQualificationV1) { q.Current.Counters.UTXOCount++ },
		func(q *TreePairQualificationV1) { q.Lag.Generation++ },
		func(q *TreePairQualificationV1) { q.Current.Binding.RootDigest[0] ^= 1 },
		func(q *TreePairQualificationV1) { q.Current.Binding.Top.Node = &node },
		func(q *TreePairQualificationV1) { q.Current, q.Lag = q.Lag, q.Current },
		func(q *TreePairQualificationV1) { q.Current.Position = TreeRoleAtTopV1 },
		func(q *TreePairQualificationV1) { q.Current.Status = TreeRolePositiveV1 },
		func(q *TreePairQualificationV1) {
			q.Lag.Status, q.Lag.Position, q.Lag.Finding = TreeRolePositiveV1, TreeRoleAtTopV1, TreeRoleAbsentV1
		},
		func(q *TreePairQualificationV1) { q.Lag = positive },
		func(q *TreePairQualificationV1) { q.Current.Role = TreeRoleTargetCurrentV1 },
		func(q *TreePairQualificationV1) { q.Current.Finding = TreeRoleAbsentV1 },
		func(q *TreePairQualificationV1) { q.Current.Binding.DatabaseID[0] ^= 1 },
		func(q *TreePairQualificationV1) { q.Current.Binding.CommitmentVersion++ },
		func(q *TreePairQualificationV1) { q.Current.Binding.ChainID[0] ^= 1 },
		func(q *TreePairQualificationV1) { q.Current.Binding.GenesisHash[0] ^= 1 },
		func(q *TreePairQualificationV1) { q.Current.Binding.Endpoint.Height++ },
		func(q *TreePairQualificationV1) { q.Current.Binding.Top.Kind = TreeTopLeafV1 },
		func(q *TreePairQualificationV1) { q.Current.Binding.Assurance.Kind = TreeAssuranceImportedBaseV1 },
		func(q *TreePairQualificationV1) { q.Current.Binding.Assurance.Import = &TreeImportReferenceV1{} },
	}
	for i, edit := range edits {
		q := final
		edit(&q)
		if q.HealthyOn(r) {
			t.Fatalf("edit %d kept HealthyOn", i)
		}
	}
	forged := final
	forged.Current = TreeRoleObservationV1{Status: final.Current.Status, Role: final.Current.Role, Generation: final.Current.Generation, Binding: final.Current.Binding, Counters: final.Current.Counters}
	if forged.HealthyOn(r) || !final.HealthyOn(r) {
		t.Fatal("forged public literal acquired identity or the original lost it")
	}
}

// treeRoleCompletionRefusalsV1 is H6's completion domain and R3's stage rows.
func treeRoleCompletionRefusalsV1(t *testing.T, r *Reader, a *OperationAccount, early TreePairQualificationV1, roles [4]TreeRoleObservationV1) {
	t.Helper()
	cb, lb, cq, lq := roles[0], roles[1], roles[2], roles[3]
	forgedQ := TreeRoleObservationV1{Status: cq.Status, Role: cq.Role, Generation: cq.Generation, Binding: cq.Binding, Counters: cq.Counters}
	// A second observation of the same role has equal public fields but another private Bound identity.
	_, crossedQ := treeRoleObserveV1(t, r, a, treeRoleReqV1(treeRoleActiveV1(cq.Generation, lq.Generation), TreeRoleCurrentV1), treeRoleAppliedV1, nil)
	completions := [][3]any{
		{early, crossedQ, lq},
		{early, lq, cq},
		{early, cb, lb},
		{early, forgedQ, lq},
		{TreePairQualificationV1{}, cq, lq},
		{early, TreeRoleObservationV1{}, lq},
	}
	for _, in := range completions {
		_, err := r.CompleteTreePairQualificationV1(in[0].(TreePairQualificationV1), in[1].(TreeRoleObservationV1), in[2].(TreeRoleObservationV1))
		treeRoleWantInvalidV1(t, err)
	}
	altered := early
	altered.Current.Binding.RootDigest[0] ^= 1
	_, err := r.CompleteTreePairQualificationV1(altered, cq, lq)
	treeRoleWantInvalidV1(t, err)
	// H6: an altered Qualified role, current or lag, is refused by completion.
	alteredQ, alteredL := cq, lq
	alteredQ.Counters.UTXOCount++
	alteredL.Binding.RootDigest[0] ^= 1
	for _, roles := range [][2]TreeRoleObservationV1{{alteredQ, lq}, {cq, alteredL}} {
		_, err = r.CompleteTreePairQualificationV1(early, roles[0], roles[1])
		treeRoleWantInvalidV1(t, err)
	}
	partial := TreeRoleObservationV1{Status: TreeRolePartialDomainV1, Role: TreeRoleCurrentV1, Generation: 1}
	for _, pair := range [][2]TreeRoleObservationV1{{cq, lq}, {partial, lb}, {lb, cb}, {cb, cb}} {
		_, err = r.QualifyTreePairAssuranceV1(a, pair[0], pair[1])
		treeRoleWantInvalidV1(t, err)
	}
	for _, bound := range []TreeRoleObservationV1{cq, partial, {Status: TreeRolePositiveV1, Role: 1, Generation: 1, Position: 3, Finding: 1}} {
		_, err = r.ObserveTreeRoleV1(a, treeRoleFinalReqV1(bound, treeRoleAppliedV1, nil))
		treeRoleWantInvalidV1(t, err)
	}
	if !r.usable() {
		t.Fatal("refusals changed the Reader")
	}
}

// treeRoleCrossPairsV1 is line 110's "not the ordered two roles of one
// pair": both members authentic, ordered and Bound on this Reader, their pair
// projections differing, for the active and the target pair. Each row changes
// one projection component, except the source rows: a legal source change
// also changes progress and cursor (GENESIS_REPLAY carries a cursor and no
// progress, IMAGE COMPLETE the reverse). The database (r.databaseID) and the
// target flag (fixed by the ordered roles) cannot differ; a target member's
// progress follows its source, since an IMAGE PARTIAL target is
// PartialDomain, never Bound.
func treeRoleCrossPairsV1(t *testing.T, r *Reader, a *OperationAccount) {
	t.Helper()
	applied := ReplayCursorV1{Kind: ReplayCursorAppliedV1, Height: 1}
	with := func(base TreeAuthorityV1, edit func(*TreeAuthorityV1)) TreeAuthorityV1 { edit(&base); return base }
	gen, img := treeRoleGenesisAuthV1, treeRoleImageAuthV1
	lag6 := func(a *TreeAuthorityV1) { a.TargetLagGenerationID = 6 }
	lag7 := func(a *TreeAuthorityV1) { a.TargetLagGenerationID = 7 }
	type side struct {
		auth           TreeAuthorityV1
		chain, genesis byte
	}
	rows := []struct {
		name     string
		target   bool
		cur, lag side
	}{
		{"active-generation", false, side{auth: treeRoleActiveV1(1, 2)}, side{auth: treeRoleActiveV1(5, 2)}},
		{"lag-generation", false, side{auth: treeRoleActiveV1(1, 2)}, side{auth: treeRoleActiveV1(1, 5)}},
		{"target-generation", false, side{auth: gen()}, side{auth: with(gen(), func(a *TreeAuthorityV1) { a.Authority.Replay.TargetGenerationID = 9 })}},
		{"target-lag-generation", false, side{auth: gen()}, side{auth: with(gen(), func(a *TreeAuthorityV1) { a.TargetLagGenerationID = 9 })}},
		{"chain", false, side{auth: treeRoleActiveV1(1, 6)}, side{auth: treeRoleActiveV1(1, 6), chain: 1}},
		{"genesis", false, side{auth: treeRoleActiveV1(1, 7)}, side{auth: treeRoleActiveV1(1, 7), genesis: 1}},
		{"source", false, side{auth: gen()}, side{auth: img()}},
		{"progress", false, side{auth: img()}, side{auth: treeRoleReplayV1(TreeSourceImageV1, TreeProgressPartialV1, ReplayCursorV1{})}},
		{"cursor", false, side{auth: gen()}, side{auth: treeRoleReplayV1(TreeSourceGenesisReplayV1, TreeProgressNoneV1, applied)}},
		{"t-active-generation", true, side{auth: gen()}, side{auth: with(gen(), func(a *TreeAuthorityV1) { a.Authority.ActiveGenerationID = 5 })}},
		{"t-lag-generation", true, side{auth: gen()}, side{auth: with(gen(), func(a *TreeAuthorityV1) { a.LagGenerationID = 5 })}},
		{"t-target-generation", true, side{auth: gen()}, side{auth: with(gen(), func(a *TreeAuthorityV1) { a.Authority.Replay.TargetGenerationID = 9 })}},
		{"t-target-lag-generation", true, side{auth: with(gen(), func(a *TreeAuthorityV1) { a.TargetLagGenerationID = 9 })}, side{auth: gen()}},
		{"t-chain", true, side{auth: with(gen(), lag6)}, side{auth: with(gen(), lag6), chain: 1}},
		{"t-genesis", true, side{auth: with(gen(), lag7)}, side{auth: with(gen(), lag7), genesis: 1}},
		{"t-source", true, side{auth: gen()}, side{auth: img()}},
		{"t-cursor", true, side{auth: gen()}, side{auth: treeRoleReplayV1(TreeSourceGenesisReplayV1, TreeProgressNoneV1, applied)}},
	}
	for _, row := range rows {
		roles := [2]TreeRoleSelectorV1{TreeRoleCurrentV1, TreeRoleLagV1}
		if row.target {
			roles = [2]TreeRoleSelectorV1{TreeRoleTargetCurrentV1, TreeRoleTargetLagV1}
		}
		var bound [2]TreeRoleObservationV1
		for i, sd := range []side{row.cur, row.lag} {
			request := treeRoleReqV1(sd.auth, roles[i])
			request.ChainID[0] ^= sd.chain
			request.GenesisHash[0] ^= sd.genesis
			got, err := r.ObserveTreeRoleBindingV1(a, request)
			if err != nil || got.Status != TreeRoleBoundV1 {
				t.Fatalf("%s member %d: %+v %v", row.name, i, got, err)
			}
			bound[i] = got
		}
		q, err := r.QualifyTreePairAssuranceV1(a, bound[0], bound[1])
		if q.stage != nil || q.Status != 0 {
			t.Errorf("%s: cross pair returned status %d", row.name, q.Status)
			continue
		}
		treeRoleWantInvalidV1(t, err)
	}
}

// treeRoleAdmissionV1 is R7's precedence matrix.
func treeRoleAdmissionV1(t *testing.T) {
	s, _, o := tsNew(t)
	treeRoleAssuredV1(t, s, o, 1, nil)
	treeRoleAssuredV1(t, s, o, 2, nil)
	auth := treeRoleActiveV1(1, 2)
	var nilReader *Reader
	_, err := nilReader.ObserveTreeRoleBindingV1(nil, TreeRoleBindingRequestV1{})
	treeRoleWantInvalidV1(t, err)
	_, err = nilReader.ObserveTreeRoleV1(nil, TreeRoleRequestV1{})
	treeRoleWantInvalidV1(t, err)
	_, err = nilReader.QualifyTreePairAssuranceV1(nil, TreeRoleObservationV1{}, TreeRoleObservationV1{})
	treeRoleWantInvalidV1(t, err)
	_, err = nilReader.CompleteTreePairQualificationV1(TreePairQualificationV1{}, TreeRoleObservationV1{}, TreeRoleObservationV1{})
	treeRoleWantInvalidV1(t, err)
	var expired *Reader
	var closed *OperationAccount
	var bound TreeRoleObservationV1
	mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
		expired, closed = r, a
		var err error
		bound, err = r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleCurrentV1))
		mustEnvironment(t, err)
	}))
	inactive := []error{}
	_, err = expired.ObserveTreeRoleBindingV1(closed, treeRoleReqV1(auth, TreeRoleCurrentV1))
	inactive = append(inactive, err)
	_, err = expired.ObserveTreeRoleV1(closed, treeRoleFinalReqV1(bound, TreeEndpointV1{}, nil))
	inactive = append(inactive, err)
	_, err = expired.QualifyTreePairAssuranceV1(closed, bound, bound)
	inactive = append(inactive, err)
	_, err = expired.CompleteTreePairQualificationV1(TreePairQualificationV1{}, bound, bound)
	inactive = append(inactive, err)
	for _, err := range inactive {
		treeNativeError(t, err, "get", "InvalidInput", 22, "Reader is not active", nil)
	}
	if expired.usable() {
		t.Fatal("an inactive Reader was revived")
	}
	treeRoleNonTreeV1(t, o, closed, auth, bound)
	mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
		cb, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleCurrentV1))
		mustEnvironment(t, err)
		lb, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleLagV1))
		mustEnvironment(t, err)
		live := reservationLive(o)
		for _, account := range []*OperationAccount{nil, {}, closed} {
			_, err := r.ObserveTreeRoleBindingV1(account, treeRoleReqV1(auth, TreeRoleCurrentV1))
			treeRoleWantInvalidV1(t, err)
			_, err = r.ObserveTreeRoleV1(account, treeRoleFinalReqV1(cb, TreeEndpointV1{}, nil))
			treeRoleWantInvalidV1(t, err)
			_, err = r.QualifyTreePairAssuranceV1(account, cb, lb)
			treeRoleWantInvalidV1(t, err)
			_, err = r.QualifyTreePairAssuranceV1(account, TreeRoleObservationV1{}, TreeRoleObservationV1{})
			treeRoleWantInvalidV1(t, err)
		}
		if reservationLive(o) != live || !r.usable() {
			t.Fatalf("account refusals charged %d or changed the Reader", reservationLive(o)-live)
		}
		if q, err := r.QualifyTreePairAssuranceV1(a, cb, lb); err != nil || q.Status != TreePairAssuranceOnlyV1 {
			t.Fatalf("valid pair after account refusals: %+v %v", q, err)
		}
		treeRoleBadRequestsV1(t, r, a, auth)
	}))
}

// treeRoleNonTreeV1 is R7's non-tree receiver row: on a usable format-2
// Reader every method returns the existing treeContext error with a live or
// a closed account, charges nothing and leaves the Reader usable.
func treeRoleNonTreeV1(t *testing.T, o *OperationReservationOwner, closed *OperationAccount, auth TreeAuthorityV1, bound TreeRoleObservationV1) {
	t.Helper()
	historical, err := Create(filepath.Join(t.TempDir(), "old"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = historical.Close() }()
	mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
		live := reservationLive(o)
		return historical.View(func(r *Reader) error {
			for _, account := range []*OperationAccount{a, closed} {
				errs := make([]error, 4)
				_, errs[0] = r.ObserveTreeRoleBindingV1(account, treeRoleReqV1(auth, TreeRoleCurrentV1))
				_, errs[1] = r.ObserveTreeRoleV1(account, treeRoleFinalReqV1(bound, TreeEndpointV1{}, nil))
				_, errs[2] = r.QualifyTreePairAssuranceV1(account, bound, bound)
				_, errs[3] = r.CompleteTreePairQualificationV1(TreePairQualificationV1{}, bound, bound)
				for _, err := range errs {
					treeNativeError(t, err, "get", "InvalidInput", 22, "tree Reader required", nil)
				}
			}
			if (TreePairQualificationV1{}).HealthyOn(r) || !r.usable() || r.failure != nil || reservationLive(o) != live {
				t.Fatalf("non-tree Reader: usable %v, failure %v, live %d want %d", r.usable(), r.failure, reservationLive(o), live)
			}
			return nil
		})
	}))
}

// treeRoleBadRequestsV1: each invalid request refuses before any charge, even
// with the whole account ceiling already held (invalid input precedes
// capacity); R7's hand-built and altered Bound rows and the finite request
// domain (endpoint validity and HeaderRoot nilness) included. A following
// valid finite and assurance call succeeds on the unchanged Bound values.
func treeRoleBadRequestsV1(t *testing.T, r *Reader, a *OperationAccount, auth TreeAuthorityV1) {
	t.Helper()
	cb, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleCurrentV1))
	mustEnvironment(t, err)
	lb, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleLagV1))
	mustEnvironment(t, err)
	handBuilt := TreeRoleObservationV1{Status: cb.Status, Role: cb.Role, Generation: cb.Generation, Binding: cb.Binding}
	altered := cb
	altered.Binding.RootDigest[0] ^= 1
	root := cb.Binding.RootDigest
	badWork := treeRoleAppliedV1
	badWork.CumulativeChainwork[0] = 1
	finals := []TreeRoleRequestV1{
		{Bound: handBuilt, Endpoint: cb.Binding.Endpoint},
		{Bound: altered, Endpoint: cb.Binding.Endpoint},
		{Bound: cb, Endpoint: TreeEndpointV1{}, HeaderRoot: &root},
		{Bound: cb, Endpoint: treeRoleAppliedV1},
		{Bound: cb, Endpoint: TreeEndpointV1{Kind: 9}},
		{Bound: cb, Endpoint: TreeEndpointV1{Height: 1}},
		{Bound: cb, Endpoint: badWork, HeaderRoot: &root},
	}
	pairs := [][2]TreeRoleObservationV1{{handBuilt, lb}, {altered, lb}, {cb, handBuilt}}
	target := treeRoleReplayV1(TreeSourceGenesisReplayV1, TreeProgressNoneV1, ReplayCursorV1{Kind: ReplayCursorPreGenesisV1})
	noSource := target
	noSource.SourceKind = TreeSourceNoneV1
	requests := []TreeRoleBindingRequestV1{
		treeRoleReqV1(auth, 0), treeRoleReqV1(auth, 5),
		{Authority: auth, Role: TreeRoleCurrentV1, GenesisHash: treeRoleGenesisV1},
		{Authority: auth, Role: TreeRoleCurrentV1, ChainID: treeRoleChainV1},
		treeRoleReqV1(treeRoleActiveV1(1, 0), TreeRoleLagV1),
		treeRoleReqV1(auth, TreeRoleTargetCurrentV1),
		treeRoleReqV1(noSource, TreeRoleTargetLagV1),
	}
	requests = append(requests, treeRoleSourceRowsV1(auth)...)
	mustEnvironment(t, a.WithReservation(treeRoleLaneMaxV1, func() error {
		for i, request := range requests {
			got, err := treeRoleSafeV1(t, func() (TreeRoleObservationV1, error) { return r.ObserveTreeRoleBindingV1(a, request) })
			if !treeRoleSameV1(got, TreeRoleObservationV1{}) {
				t.Fatalf("request %d returned %+v", i, got)
			}
			treeRoleWantInvalidV1(t, err)
		}
		_, err := r.ObserveTreeRoleV1(a, TreeRoleRequestV1{})
		treeRoleWantInvalidV1(t, err)
		for i, request := range finals {
			got, err := r.ObserveTreeRoleV1(a, request)
			if !treeRoleSameV1(got, TreeRoleObservationV1{}) {
				t.Fatalf("finite request %d returned %+v", i, got)
			}
			treeRoleWantInvalidV1(t, err)
		}
		for i, pair := range pairs {
			q, err := r.QualifyTreePairAssuranceV1(a, pair[0], pair[1])
			if q.stage != nil || q.Status != 0 {
				t.Fatalf("pair %d returned %+v", i, q)
			}
			treeRoleWantInvalidV1(t, err)
		}
		return nil
	}))
	got, err := r.ObserveTreeRoleV1(a, treeRoleFinalReqV1(cb, cb.Binding.Endpoint, nil))
	if err != nil || got.Status != TreeRoleQualifiedV1 {
		t.Fatalf("following valid finite call: %+v %v", got, err)
	}
	if q, err := r.QualifyTreePairAssuranceV1(a, cb, lb); err != nil || q.Status != TreePairAssuranceOnlyV1 {
		t.Fatalf("following valid assurance call: %+v %v", q, err)
	}
	// Selectivity control for treeRoleSourceRowsV1: each unedited base is Bound.
	for _, base := range []TreeAuthorityV1{treeRoleGenesisAuthV1(), treeRoleImageAuthV1()} {
		if got, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(base, TreeRoleCurrentV1)); err != nil || got.Status != TreeRoleBoundV1 {
			t.Fatalf("legal source base: %+v %v", got, err)
		}
	}
}

func treeRoleGenesisAuthV1() TreeAuthorityV1 {
	return treeRoleReplayV1(TreeSourceGenesisReplayV1, TreeProgressNoneV1, ReplayCursorV1{Kind: ReplayCursorPreGenesisV1})
}

func treeRoleImageAuthV1() TreeAuthorityV1 {
	return treeRoleReplayV1(TreeSourceImageV1, TreeProgressCompleteV1, ReplayCursorV1{})
}

// treeRoleSourceRowsV1 is line 110's "without legal source": CURRENT
// requests covering every conjunct of the source check (the Replay conjunct on
// both REPLAY bases), each breaking only that conjunct of an otherwise legal
// base (active, GENESIS_REPLAY or IMAGE COMPLETE).
func treeRoleSourceRowsV1(active TreeAuthorityV1) []TreeRoleBindingRequestV1 {
	edits := []struct {
		base func() TreeAuthorityV1
		edit func(*TreeAuthorityV1)
	}{
		{nil, func(a *TreeAuthorityV1) { a.SourceKind = TreeSourceGenesisReplayV1 }},
		{nil, func(a *TreeAuthorityV1) { a.TargetLagGenerationID = 4 }},
		{nil, func(a *TreeAuthorityV1) { a.Progress.Kind = TreeProgressCompleteV1 }},
		{nil, func(a *TreeAuthorityV1) { a.Progress.Payload = []byte{1} }},
		{treeRoleGenesisAuthV1, func(a *TreeAuthorityV1) { a.Authority.Replay = nil }},
		{treeRoleGenesisAuthV1, func(a *TreeAuthorityV1) { a.TargetLagGenerationID = 0 }},
		{treeRoleGenesisAuthV1, func(a *TreeAuthorityV1) { a.SourceKind = 9 }},
		{treeRoleGenesisAuthV1, func(a *TreeAuthorityV1) { a.Authority.Replay.Cursor.Kind = 0 }},
		{treeRoleGenesisAuthV1, func(a *TreeAuthorityV1) { a.Progress.Kind = TreeProgressCompleteV1 }},
		{treeRoleGenesisAuthV1, func(a *TreeAuthorityV1) { a.Progress.Payload = []byte{1} }},
		{treeRoleImageAuthV1, func(a *TreeAuthorityV1) { a.Authority.Replay = nil }},
		{treeRoleImageAuthV1, func(a *TreeAuthorityV1) { a.Authority.Replay.Cursor.Kind = ReplayCursorPreGenesisV1 }},
		{treeRoleImageAuthV1, func(a *TreeAuthorityV1) { a.Authority.Replay.Cursor.Height = 1 }},
		{treeRoleImageAuthV1, func(a *TreeAuthorityV1) { a.Authority.Replay.Cursor.BlockHash[0] = 1 }},
		{treeRoleImageAuthV1, func(a *TreeAuthorityV1) { a.Progress.Kind = TreeProgressNoneV1 }},
		{treeRoleImageAuthV1, func(a *TreeAuthorityV1) { a.Progress.Kind = 9 }},
		{treeRoleImageAuthV1, func(a *TreeAuthorityV1) { a.Progress.Payload = nil }},
	}
	out := make([]TreeRoleBindingRequestV1, 0, len(edits))
	for _, e := range edits {
		a := active
		if e.base != nil {
			a = e.base()
		}
		e.edit(&a)
		out = append(out, treeRoleReqV1(a, TreeRoleCurrentV1))
	}
	return out
}

// treeRoleStreamTopV1 is A7 on a top written by the production writer
// UpdateTreeV1 (the one-entry tree of TestTreeCoveredCountersV1): altering the
// Qualified role's public Top.Node never changes its separately returned
// Bound role.
func treeRoleStreamTopV1(t *testing.T) {
	s, _, o := tsNew(t)
	tsRoots(t, s, o, 1)
	tsSeedCounter(t, s, o, 1, false, make([]byte, 16))
	frame := tdFrame(71, 0, nil)
	event := tsCreate(0x11, 0, 0, 148, uint32(len(frame)))
	op := tsCoveredDelta(t, 5, 0x41, TreeBlockV1{TxCount: 1, EventCount: 1, Generated: [16]byte{0: 5}}, []TreeEventV1{event}, frame)
	run := tsRun(t, s, o, TreeOperation, op)
	mustEnvironment(t, run.err)
	mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
		bound, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(treeRoleActiveV1(1, 2), TreeRoleCurrentV1))
		mustEnvironment(t, err)
		if bound.Status != TreeRoleBoundV1 || bound.Binding.Top.Node == nil {
			t.Fatalf("binding of the written tree: %+v", bound)
		}
		literal := *bound.Binding.Top.Node
		edited, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(treeRoleActiveV1(1, 2), TreeRoleCurrentV1))
		mustEnvironment(t, err)
		if edited.Binding.Top.Node == nil || edited.Binding.Top.Node == bound.Binding.Top.Node {
			t.Fatal("separately returned Bound roles share one public Top.Node allocation")
		}
		edited.Binding.Top.Node.Depth ^= 1 // in place: the pointer is unchanged
		_, err = treeRoleFiniteCallV1(t, r, a, treeRoleFinalReqV1(edited, op.Primitives[0].Endpoint, nil))
		treeRoleWantInvalidV1(t, err)
		final, err := treeRoleFiniteCallV1(t, r, a, treeRoleFinalReqV1(bound, op.Primitives[0].Endpoint, nil))
		mustEnvironment(t, err)
		if final.Status != TreeRoleQualifiedV1 || final.Binding.Top.Node == nil {
			t.Fatalf("written one-entry tree: %+v", final)
		}
		final.Binding.Top.Node.Depth ^= 1
		if *bound.Binding.Top.Node != literal {
			t.Fatal("altering the Qualified role's public Top.Node changed its separately returned Bound role")
		}
	}))
}
