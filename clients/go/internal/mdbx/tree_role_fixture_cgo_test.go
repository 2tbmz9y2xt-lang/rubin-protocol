//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

// Fixture-tag rows of RUB-1660: node and evidence rows need treeNativeSeed,
// native faults need FixtureSelectedDamage. Expected literals come from the
// contract text and the independent test tree builder.

var treeRoleKDV1 = testTreeKey(0x80, 0, 1)

// treeRoleShapeV1 is one legal shape, its generation-1 finite read census
// (hit), rows outside it (miss) and its exact reads at rank 0, rank 8 (nodes)
// and rank 1 (points).
type treeRoleShapeV1 struct {
	name      string
	keys      [][36]byte
	hit, miss [][2]any
	gets      [3]uint64
}

func treeRoleNodeSiteV1(g uint64, depth int, key [36]byte) [2]any {
	return [2]any{uint8(8), testTreeNodeKey(g, depth, key)}
}

func treeRolePointSiteV1(g uint64, k [36]byte) [2]any {
	return [2]any{uint8(1), tdUTXOKey(g, [32]byte(k[:32]), binary.BigEndian.Uint32(k[32:]))}
}

func treeRoleMetaSitesV1(g uint64) [][2]any {
	return [][2]any{{uint8(0), tsRootKey(g)}, {uint8(0), tsCounterKey(g)}}
}

func treeRoleShapesSetV1() []treeRoleShapeV1 {
	var zero, one [36]byte
	one[0] = 0x80
	node := func(depth int, key [36]byte) [2]any { return treeRoleNodeSiteV1(1, depth, key) }
	point := func(key [36]byte) [2]any { return treeRolePointSiteV1(1, key) }
	meta := func(rows ...[2]any) [][2]any { return append(treeRoleMetaSitesV1(1), rows...) }
	return []treeRoleShapeV1{
		{"empty", nil, meta(), [][2]any{node(288, testKA), point(testKA)}, [3]uint64{2, 0, 0}},
		{"singleton", [][36]byte{testKA}, meta(node(288, testKA), point(testKA)), [][2]any{node(0, zero)}, [3]uint64{2, 1, 1}},
		{"two-leaf", [][36]byte{testKA, testKC}, meta(node(0, zero), node(288, testKA), node(288, testKC), point(testKA), point(testKC)), [][2]any{node(287, zero)}, [3]uint64{2, 3, 2}},
		{"leaf-branch", [][36]byte{testKA, testKB, testKC}, meta(node(0, zero), node(287, zero), node(288, testKC), point(testKC)), [][2]any{node(288, testKA), node(288, testKB), point(testKA), point(testKB)}, [3]uint64{2, 3, 1}},
		{"branch-branch", [][36]byte{testKA, testKB, testKC, treeRoleKDV1}, meta(node(0, zero), node(287, zero), node(287, one)), [][2]any{node(288, testKA), node(288, treeRoleKDV1), point(testKA), point(treeRoleKDV1)}, [3]uint64{2, 3, 0}},
	}
}

// treeRoleSeededV1 builds and seeds one generation including its node rows.
func treeRoleSeededV1(t *testing.T, s *Store, o *OperationReservationOwner, g uint64, ep TreeEndpointV1, keys ...[36]byte) *treeRoleTreeV1 {
	t.Helper()
	tr := treeRoleBuildV1(t, g, ep, keys...)
	treeRoleSeedAllV1(t, s, o, tr)
	return tr
}

// treeRoleSeedAllV1 seeds the binding, counter, point and node rows of tr.
func treeRoleSeedAllV1(t *testing.T, s *Store, o *OperationReservationOwner, tr *treeRoleTreeV1) {
	t.Helper()
	tr.seedV1(t, s, o, false)
	for name, value := range tr.nodes {
		key, err := hex.DecodeString(name[2:])
		mustEnvironment(t, err)
		treeNativeSeed(t, s, 8, key, value)
	}
}

func treeRoleDeleteV1(t *testing.T, s *Store, site [2]any) {
	t.Helper()
	mustEnvironment(t, fixtureDeletePrefixRow(s, TreeSchemaV1DBIs()[site[0].(uint8)], site[1].([]byte)))
}

func treeRolePutV1(t *testing.T, s *Store, site [2]any, value []byte) {
	t.Helper()
	treeNativeSeed(t, s, site[0].(uint8), site[1].([]byte), value)
}

// treeRoleTryV1 runs the binding then the finite stage, returning the first error.
func treeRoleTryV1(t *testing.T, r *Reader, a *OperationAccount, request TreeRoleBindingRequestV1, ep TreeEndpointV1) (TreeRoleObservationV1, error) {
	t.Helper()
	bound, err := r.ObserveTreeRoleBindingV1(a, request)
	if err != nil || bound.Status != TreeRoleBoundV1 {
		return bound, err
	}
	return treeRoleFiniteCallV1(t, r, a, treeRoleFinalReqV1(bound, ep, nil))
}

func treeRoleWantNativeV1(t *testing.T, r *Reader, got TreeRoleObservationV1, err error) {
	t.Helper()
	treeNativeError(t, err, "update", "IO", 5, "error 5", nil)
	if !treeRoleSameV1(got, TreeRoleObservationV1{}) || r.usable() || any(r.failure) != any(err) {
		t.Fatalf("native failure: observation %+v, usable %v, recorded %v", got, r.usable(), r.failure)
	}
}

func TestTreeRoleFaultV1(t *testing.T) {
	t.Run("shapes", treeRoleFixtureShapesV1)
	t.Run("census", treeRoleCensusV1)
	t.Run("order-pairs", treeRoleOrderPairsV1)
	t.Run("counters", treeRoleCountersReuseV1)
	t.Run("early-faults", treeRoleEarlyFaultsV1)
	t.Run("binding-corpus", treeRoleRawBindingCorpusV1)
	t.Run("node-corpus", treeRoleNodeCorpusV1)
	t.Run("pairs", treeRolePairsV1)
	t.Run("evidence-eio", treeRoleEvidenceEIOV1)
	t.Run("zero-io", treeRoleZeroIOV1)
	t.Run("binding-reuse", treeRoleBindingReuseV1)
	t.Run("abort", treeRoleAbortV1)
	t.Run("image-targets", treeRoleImageTargetsV1)
	t.Run("nested-pointers", treeRoleNestedV1)
	t.Run("shape-corpus", treeRoleShapeCorpusV1)
	t.Run("ledger-resolved", treeRoleLedgerResolvedV1)
	t.Run("grandchild-absent", treeRoleGrandchildAbsentV1)
	t.Run("capacity-reads", treeRoleCapacityReadsV1)
	t.Run("admission-reads", treeRoleAdmissionReadsV1)
}

// treeRoleFixtureShapesV1 is A1: every non-empty legal shape is Qualified in
// two generations holding byte-identical maps, and the full pair is HealthyOn;
// deleting generation 2's top row leaves generation 1 Qualified.
func treeRoleFixtureShapesV1(t *testing.T) {
	s, _, o := tsNew(t)
	for i, shape := range treeRoleShapesSetV1()[1:] {
		current := treeRoleSeededV1(t, s, o, uint64(10+2*i), treeRoleAppliedV1, shape.keys...)
		lag := treeRoleSeededV1(t, s, o, uint64(11+2*i), treeRoleAppliedV1, shape.keys...)
		if current.binding.RootDigest != lag.binding.RootDigest || current.binding.RootDigest == testTreeC01() {
			t.Fatalf("%s: equal maps built different digests", shape.name)
		}
		auth := treeRoleActiveV1(current.g, lag.g)
		mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
			cb, cq := treeRoleObserveV1(t, r, a, treeRoleReqV1(auth, TreeRoleCurrentV1), treeRoleAppliedV1, nil)
			lb, lq := treeRoleObserveV1(t, r, a, treeRoleReqV1(auth, TreeRoleLagV1), treeRoleAppliedV1, nil)
			treeRoleWantQualifiedV1(t, cq, TreeRoleCurrentV1, current)
			treeRoleWantQualifiedV1(t, lq, TreeRoleLagV1, lag)
			early, err := r.QualifyTreePairAssuranceV1(a, cb, lb)
			mustEnvironment(t, err)
			final, err := r.CompleteTreePairQualificationV1(early, cq, lq)
			mustEnvironment(t, err)
			if final.Status != TreePairQualifiedV1 || !final.HealthyOn(r) {
				t.Fatalf("%s: final pair %+v not HealthyOn", shape.name, final)
			}
		}))
	}
	var zero [36]byte
	one := treeRoleSeededV1(t, s, o, 1, treeRoleAppliedV1, testKA, testKC)
	two := treeRoleSeededV1(t, s, o, 2, treeRoleAppliedV1, testKA, testKC)
	treeRoleDeleteV1(t, s, treeRoleNodeSiteV1(2, 0, zero))
	mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
		_, got := treeRoleObserveV1(t, r, a, treeRoleReqV1(treeRoleActiveV1(1, 2), TreeRoleCurrentV1), treeRoleAppliedV1, nil)
		treeRoleWantQualifiedV1(t, got, TreeRoleCurrentV1, one)
		_, got = treeRoleObserveV1(t, r, a, treeRoleReqV1(treeRoleActiveV1(1, 2), TreeRoleLagV1), treeRoleAppliedV1, nil)
		treeRoleWantPositiveV1(t, got, TreeRoleLagV1, two.g, TreeRoleAtTopV1, TreeRoleAbsentV1)
	}))
}

// treeRoleArmedV1 runs one current-role observation on a fresh seeded store
// with SelectedDamageGetEIO armed on site.
func treeRoleArmedV1(t *testing.T, keys [][36]byte, site [2]any, prepare func(*Store), use func(*Reader, TreeRoleObservationV1, error)) (SelectedDamageEvidence, error, error) {
	t.Helper()
	s, _, o := tsNew(t)
	treeRoleSeededV1(t, s, o, 1, treeRoleAppliedV1, keys...)
	treeRoleAssuredV1(t, s, o, 2, nil)
	if prepare != nil {
		prepare(s)
	}
	var viewErr error
	evidence, err := FixtureSelectedDamage(s, o, SelectedDamageGetEIO, site[0].(uint8), site[1].([]byte), func() {
		viewErr = treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
			got, err := treeRoleTryV1(t, r, a, treeRoleReqV1(treeRoleActiveV1(1, 2), TreeRoleCurrentV1), treeRoleAppliedV1)
			use(r, got, err)
		})
	})
	if viewErr != nil {
		next := s.View(func(*Reader) error { t.Fatal("consumed Store invoked callback"); return nil })
		if any(next) != any(viewErr) {
			t.Fatalf("next View %v, want the recorded %v", next, viewErr)
		}
	}
	return evidence, err, viewErr
}

// treeRoleCensusV1 is A4, E2 (binding, counter, top, children, points) and
// R3's grandchild rows: every census row is read (its EIO is hit and returned
// unchanged, recorded as the Reader failure, grant released, Store consumed
// for the next call), no row outside the census is read, and the probe subtest pins the
// exact per-rank read count of each shape.
func treeRoleCensusV1(t *testing.T) {
	for _, shape := range treeRoleShapesSetV1() {
		for i, site := range shape.hit {
			t.Run(fmt.Sprintf("%s-hit-%d", shape.name, i), func(t *testing.T) {
				var raw error
				_, err, viewErr := treeRoleArmedV1(t, shape.keys, site, nil, func(r *Reader, got TreeRoleObservationV1, err error) {
					raw = err
					treeRoleWantNativeV1(t, r, got, err)
				})
				if err != nil || any(viewErr) != any(raw) {
					t.Fatalf("fixture %v, View %v, want the raw %v", err, viewErr, raw)
				}
			})
		}
		for i, site := range shape.miss {
			t.Run(fmt.Sprintf("%s-miss-%d", shape.name, i), func(t *testing.T) {
				evidence, err, viewErr := treeRoleArmedV1(t, shape.keys, site, nil, func(r *Reader, got TreeRoleObservationV1, err error) {
					mustEnvironment(t, err)
					if got.Status != TreeRoleQualifiedV1 {
						t.Fatalf("observation %+v, want Qualified", got)
					}
				})
				if err == nil || evidence.Faults != 0 || viewErr != nil {
					t.Fatalf("outside-census row was read: %v %+v %v", err, evidence, viewErr)
				}
			})
		}
		t.Run(shape.name+"-probe", func(t *testing.T) {
			s, _, o := tsNew(t)
			treeRoleSeededV1(t, s, o, 1, treeRoleAppliedV1, shape.keys...)
			treeRoleAssuredV1(t, s, o, 2, nil)
			e := treeRoleProbeV1(t, s, o, func(r *Reader, a *OperationAccount) {
				got, err := treeRoleTryV1(t, r, a, treeRoleReqV1(treeRoleActiveV1(1, 2), TreeRoleCurrentV1), treeRoleAppliedV1)
				if err != nil || got.Status != TreeRoleQualifiedV1 {
					t.Fatalf("observation %+v %v, want Qualified", got, err)
				}
			})
			treeRoleWantGetsV1(t, e, shape.gets[0], shape.gets[1], shape.gets[2])
		})
	}
}

// treeRoleOrderPairsV1 is line 75's adjacent finite-stage pairs: each row
// puts an EIO on the earlier row and removes the later row (or stores bad bytes
// at the armed row for read-before-decode) in one input, so only the
// earlier-first order returns the native error.
func treeRoleOrderPairsV1(t *testing.T) {
	var zero [36]byte
	two := [][36]byte{testKA, testKC}
	rows := []struct {
		name        string
		keys        [][36]byte
		armed, gone [2]any
		bad         []byte
	}{
		{"counter-before-top", two, treeRoleMetaSitesV1(1)[1], treeRoleNodeSiteV1(1, 0, zero), nil},
		{"top-before-zero-child", two, treeRoleNodeSiteV1(1, 0, zero), treeRoleNodeSiteV1(1, 288, testKA), nil},
		{"zero-child-before-one-child", two, treeRoleNodeSiteV1(1, 288, testKA), treeRoleNodeSiteV1(1, 288, testKC), nil},
		{"children-before-points", two, treeRoleNodeSiteV1(1, 288, testKC), treeRolePointSiteV1(1, testKA), nil},
		{"top-before-point", [][36]byte{testKA}, treeRoleNodeSiteV1(1, 288, testKA), treeRolePointSiteV1(1, testKA), nil},
		{"zero-point-before-one-point", two, treeRolePointSiteV1(1, testKA), treeRolePointSiteV1(1, testKC), nil},
		{"binding-read-before-decode", two, treeRoleMetaSitesV1(1)[0], [2]any{}, []byte{1}},
		{"counter-read-before-decode", two, treeRoleMetaSitesV1(1)[1], [2]any{}, []byte{1}},
		{"node-read-before-decode", two, treeRoleNodeSiteV1(1, 0, zero), [2]any{}, []byte{0xff}},
		{"point-read-before-decode", two, treeRolePointSiteV1(1, testKA), [2]any{}, []byte{1}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			prepare := func(s *Store) {
				if row.bad != nil {
					treeRolePutV1(t, s, row.armed, row.bad)
					return
				}
				treeRoleDeleteV1(t, s, row.gone)
			}
			_, err, _ := treeRoleArmedV1(t, row.keys, row.armed, prepare, func(r *Reader, got TreeRoleObservationV1, err error) {
				treeRoleWantNativeV1(t, r, got, err)
			})
			mustEnvironment(t, err)
		})
	}
	treeRoleOrderRelationsV1(t)
	// Endpoint and header root precede the counter read: either mismatch with
	// an absent counter row is WrongIdentity at Binding, never Absent at Counter.
	s, _, o := tsNew(t)
	treeRoleSeededV1(t, s, o, 1, treeRoleAppliedV1, testKA)
	treeRoleAssuredV1(t, s, o, 2, nil)
	treeRoleDeleteV1(t, s, treeRoleMetaSitesV1(1)[1])
	wrongRoot := testTreeHash(0x99)
	for name, edit := range map[string]func(*TreeRoleRequestV1){
		"endpoint-before-counter": func(q *TreeRoleRequestV1) { q.Endpoint = testTreeApplied(5, 9, 38) },
		"header-before-counter":   func(q *TreeRoleRequestV1) { q.HeaderRoot = &wrongRoot },
	} {
		t.Run(name, func(t *testing.T) {
			mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
				bound, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(treeRoleActiveV1(1, 2), TreeRoleCurrentV1))
				mustEnvironment(t, err)
				request := treeRoleFinalReqV1(bound, treeRoleAppliedV1, nil)
				edit(&request)
				got, err := r.ObserveTreeRoleV1(a, request)
				mustEnvironment(t, err)
				treeRoleWantPositiveV1(t, got, TreeRoleCurrentV1, 1, TreeRoleAtBindingV1, TreeRoleWrongIdentityV1)
			}))
		})
	}
}

// treeRoleOrderRelationsV1 is line 75's pairs whose earlier check is a relation: a false earlier relation with the
// next read EIO-armed is the earlier Positive, fault not hit (H2 shape); a last-point EIO before a final violation is native.
func treeRoleOrderRelationsV1(t *testing.T) {
	two, three, single := [][36]byte{testKA, testKC}, [][36]byte{testKA, testKB, testKC}, [][36]byte{testKA}
	other, count := testTreeHash(0x3c), treeRoleMetaSitesV1(1)[1]
	rows := []struct {
		name           string
		keys           [][36]byte
		damaged, armed [2]any
		value          []byte
		position       TreeRolePositionV1
		finding        TreeRoleFindingV1
	}{
		{"ns-before-top", two, count, treeRoleNodeSiteV1(1, 0, [36]byte{}), tsCounterLiteral(0, 1), TreeRoleAtCardinalityV1, TreeRoleRelationFailedV1},
		{"top-digest-before-zero-child", two, treeRoleNodeSiteV1(1, 0, [36]byte{}), treeRoleNodeSiteV1(1, 288, testKA), treeRoleBranchValueV1(testTreeNodeKey(1, 288, testKA), testTreeNodeKey(1, 288, testKC)), TreeRoleAtTopV1, TreeRoleRelationFailedV1},
		{"zero-digest-before-one-child", two, treeRoleNodeSiteV1(1, 288, testKA), treeRoleNodeSiteV1(1, 288, testKC), other[:], TreeRoleAtZeroChildV1, TreeRoleRelationFailedV1},
		{"one-digest-before-zero-point", two, treeRoleNodeSiteV1(1, 288, testKC), treeRolePointSiteV1(1, testKA), other[:], TreeRoleAtOneChildV1, TreeRoleRelationFailedV1},
		{"zero-hash-before-one-point", two, treeRolePointSiteV1(1, testKA), treeRolePointSiteV1(1, testKC), treeRoleValueV1(9), TreeRoleAtZeroPointV1, TreeRoleRelationFailedV1},
		{"n1-top-digest-before-point", single, treeRoleNodeSiteV1(1, 288, testKA), treeRolePointSiteV1(1, testKA), other[:], TreeRoleAtTopV1, TreeRoleRelationFailedV1},
		{"point-before-n1-s", single, count, treeRolePointSiteV1(1, testKA), tsCounterLiteral(1, 1), 0, 0},
		{"one-point-before-n2-s", two, count, treeRolePointSiteV1(1, testKC), tsCounterLiteral(1, 2), 0, 0},
		{"one-point-before-cardinality", three, count, treeRolePointSiteV1(1, testKC), tsCounterLiteral(0, 2), 0, 0},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			evidence, err, _ := treeRoleArmedV1(t, row.keys, row.armed, func(s *Store) { treeRolePutV1(t, s, row.damaged, row.value) }, func(r *Reader, got TreeRoleObservationV1, err error) {
				if row.position == 0 {
					treeRoleWantNativeV1(t, r, got, err)
					return
				}
				mustEnvironment(t, err)
				treeRoleWantPositiveV1(t, got, TreeRoleCurrentV1, 1, row.position, row.finding)
			})
			if (row.position == 0) != (err == nil && evidence.Faults == 1) {
				t.Fatalf("armed row reached %+v, fixture %v", evidence, err)
			}
		})
	}
}

// treeRoleCountersReuseV1 is A3 and H1: supplied Counters are reused and the
// armed counter fault is not hit; a counter EIO before a malformed child
// returns the native error, never a Positive result.
func treeRoleCountersReuseV1(t *testing.T) {
	keys := [][36]byte{testKA, testKC}
	s, _, o := tsNew(t)
	tr := treeRoleSeededV1(t, s, o, 1, treeRoleAppliedV1, keys...)
	treeRoleAssuredV1(t, s, o, 2, nil)
	evidence, err := FixtureSelectedDamage(s, o, SelectedDamageGetEIO, 0, tsCounterKey(1), func() {
		mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
			counters := tr.counters
			_, got := treeRoleObserveV1(t, r, a, treeRoleReqV1(treeRoleActiveV1(1, 2), TreeRoleCurrentV1), treeRoleAppliedV1, &counters)
			treeRoleWantQualifiedV1(t, got, TreeRoleCurrentV1, tr)
		}))
	})
	if err == nil || evidence.Faults != 0 {
		t.Fatalf("supplied counters read the counter row: %v %+v", err, evidence)
	}
	malformed := func(s *Store) { treeRolePutV1(t, s, treeRoleNodeSiteV1(1, 288, testKA), make([]byte, 31)) }
	_, err, _ = treeRoleArmedV1(t, keys, [2]any{uint8(0), tsCounterKey(1)}, malformed, func(r *Reader, got TreeRoleObservationV1, err error) {
		treeRoleWantNativeV1(t, r, got, err)
	})
	mustEnvironment(t, err)
}

// treeRoleEarlyFaultsV1 is H2: a wrong endpoint ends the finite call before
// the EIO-armed top row is read, and, separately, before the EIO-armed counter
// row (the first read after the identity checks) is read.
func treeRoleEarlyFaultsV1(t *testing.T) {
	var zero [36]byte
	for _, site := range [][2]any{{uint8(8), testTreeNodeKey(1, 0, zero)}, {uint8(0), tsCounterKey(1)}} {
		s, _, o := tsNew(t)
		treeRoleSeededV1(t, s, o, 1, treeRoleAppliedV1, testKA, testKC)
		evidence, err := FixtureSelectedDamage(s, o, SelectedDamageGetEIO, site[0].(uint8), site[1].([]byte), func() {
			mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
				got, err := treeRoleTryV1(t, r, a, treeRoleReqV1(treeRoleActiveV1(1, 2), TreeRoleCurrentV1), testTreeApplied(6, 9, 37))
				if err != nil {
					t.Fatalf("wrong endpoint did not end the finite call before the EIO-armed rank %d row: %v", site[0], err)
				}
				treeRoleWantPositiveV1(t, got, TreeRoleCurrentV1, 1, TreeRoleAtBindingV1, TreeRoleWrongIdentityV1)
			}))
		})
		if err == nil || evidence.Faults != 0 {
			t.Fatalf("wrong endpoint reached the rank %d row: %v %+v", site[0], err, evidence)
		}
	}
}

// treeRoleRawBindingCorpusV1 is R4's raw byte rows, each Positive Malformed at
// Binding: framing byte, width 132, width 329, commitment version 2, and
// PRE_GENESIS with a non-empty root or with a non-empty top, and a missing
// or an extra assurance payload.
func treeRoleRawBindingCorpusV1(t *testing.T) {
	s, _, o := tsNew(t)
	good := treeRoleBuildV1(t, 1, TreeEndpointV1{})
	encoded, err := good.binding.Encode()
	mustEnvironment(t, err)
	if len(encoded) != 133 {
		t.Fatalf("PRE_GENESIS empty binding width %d, want 133", len(encoded))
	}
	// A legal APPLIED singleton binding supplies a leaf top (kind byte at 207
	// plus its 38-byte suffix); it replaces the PRE_GENESIS empty top byte at
	// 131, keeping the empty root digest.
	applied, err := treeRoleBuildV1(t, 1, treeRoleAppliedV1, testKA).binding.Encode()
	mustEnvironment(t, err)
	if applied[207] != byte(TreeTopLeafV1) {
		t.Fatalf("APPLIED singleton top kind %d", applied[207])
	}
	leafTop := append(append(append([]byte(nil), encoded[:131]...), applied[207:246]...), encoded[132:]...)
	// The assurance kind is the last byte of a FULL_HISTORY binding (132); an
	// IMPORTED_BASE binding appends its reference after it. Kind IMPORTED_BASE
	// with no reference is a missing payload; kind FULL_HISTORY followed by a
	// reference is an extra payload (contract line 133).
	ref, _ := treeRoleImportV1(TreeOriginalCurrentV1, 8)
	importedBinding := good.binding
	importedBinding.Assurance = TreeAssuranceV1{Kind: TreeAssuranceImportedBaseV1, Import: &ref}
	imported, err := importedBinding.Encode()
	mustEnvironment(t, err)
	if encoded[132] != byte(TreeAssuranceFullHistoryV1) || imported[132] != byte(TreeAssuranceImportedBaseV1) || !bytes.Equal(imported[:132], encoded[:132]) {
		t.Fatalf("assurance kind byte not at 132: %x / %x", encoded[132:], imported[132:])
	}
	edit := func(f func([]byte) []byte) []byte { return f(append([]byte(nil), encoded...)) }
	rows := map[uint64][]byte{
		60: edit(func(b []byte) []byte { b[0] = 2; return b }),
		61: edit(func(b []byte) []byte { return b[:132] }),
		62: append(edit(func(b []byte) []byte { return b }), make([]byte, 329-133)...),
		63: edit(func(b []byte) []byte { b[33] = 2; return b }),
		64: edit(func(b []byte) []byte { b[99] ^= 1; return b }),
		65: leafTop,
		66: edit(func(b []byte) []byte { b[132] = byte(TreeAssuranceImportedBaseV1); return b }),
		67: append(append([]byte(nil), encoded...), imported[133:]...),
	}
	for g, value := range rows {
		treeNativeSeed(t, s, 0, tsRootKey(g), value)
	}
	mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
		for g := range rows {
			got, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(treeRoleActiveV1(g, 2), TreeRoleCurrentV1))
			mustEnvironment(t, err)
			treeRoleWantPositiveV1(t, got, TreeRoleCurrentV1, g, TreeRoleAtBindingV1, TreeRoleMalformedV1)
		}
	}))
}

// treeRoleNodeRowV1 is one R5 final-stage or R6 row on its own generation.
type treeRoleNodeRowV1 struct {
	name     string
	keys     [][36]byte
	damage   func(t *testing.T, s *Store, g uint64)
	counters func(tr *treeRoleTreeV1) *TreeRoleCountersV1
	position TreeRolePositionV1
	finding  TreeRoleFindingV1
}

func treeRoleCountsV1(sumDelta, n uint64) func(*treeRoleTreeV1) *TreeRoleCountersV1 {
	return func(tr *treeRoleTreeV1) *TreeRoleCountersV1 {
		return &TreeRoleCountersV1{LogicalStateBytes: tr.counters.LogicalStateBytes + sumDelta, UTXOCount: n}
	}
}

func treeRoleSetV1(rank uint8, site func(g uint64) [2]any, value []byte) func(*testing.T, *Store, uint64) {
	return func(t *testing.T, s *Store, g uint64) {
		if value == nil {
			treeRoleDeleteV1(t, s, site(g))
			return
		}
		treeRolePutV1(t, s, site(g), value)
	}
}

func treeRoleNodeRowsV1() []treeRoleNodeRowV1 {
	two, single := [][36]byte{testKA, testKC}, [][36]byte{testKA}
	var zero [36]byte
	three := [][36]byte{testKA, testKB, testKC}
	topBranch := func(g uint64) [2]any { return treeRoleNodeSiteV1(g, 0, zero) }
	zeroBranch := func(g uint64) [2]any { return treeRoleNodeSiteV1(g, 287, zero) }
	topLeaf := func(g uint64) [2]any { return treeRoleNodeSiteV1(g, 288, testKA) }
	zc, oc := topLeaf, func(g uint64) [2]any { return treeRoleNodeSiteV1(g, 288, testKC) }
	zp := func(g uint64) [2]any { return treeRolePointSiteV1(g, testKA) }
	op := func(g uint64) [2]any { return treeRolePointSiteV1(g, testKC) }
	other := testTreeHash(0x3c)
	n := func(*treeRoleTreeV1) *TreeRoleCountersV1 { return nil }
	return []treeRoleNodeRowV1{
		{"counter-width-15", single, func(t *testing.T, s *Store, g uint64) { treeNativeSeed(t, s, 0, tsCounterKey(g), make([]byte, 15)) }, n, TreeRoleAtCounterV1, TreeRoleMalformedV1},
		{"n2-leaf-branch", [][36]byte{testKA, testKB, testKC}, nil, treeRoleCountsV1(0, 2), TreeRoleAtCardinalityV1, TreeRoleRelationFailedV1},
		{"n3-two-leaves", two, nil, treeRoleCountsV1(0, 3), TreeRoleAtCardinalityV1, TreeRoleRelationFailedV1},
		{"n3-branch-branch", [][36]byte{testKA, testKB, testKC, treeRoleKDV1}, nil, treeRoleCountsV1(0, 3), TreeRoleAtCardinalityV1, TreeRoleRelationFailedV1},
		{"top-width-31", single, treeRoleSetV1(8, topLeaf, make([]byte, 31)), n, TreeRoleAtTopV1, TreeRoleMalformedV1},
		{"top-digest", single, treeRoleSetV1(8, topLeaf, other[:]), n, TreeRoleAtTopV1, TreeRoleRelationFailedV1},
		{"top-child-fits", two, treeRoleSwapChildrenV1, n, TreeRoleAtTopV1, TreeRoleMalformedV1},
		{"top-child-depth", two, treeRoleSetV1(8, topBranch, treeRoleBranchValueV1(testTreeNodeKey(1, 0, zero), testTreeNodeKey(1, 288, testKC))), n, TreeRoleAtTopV1, TreeRoleMalformedV1},
		{"zero-child-prefix", three, treeRoleSetV1(8, zeroBranch, treeRoleBranchValueV1(testTreeNodeKey(1, 288, testKA), testTreeNodeKey(1, 288, testKC))), n, TreeRoleAtZeroChildV1, TreeRoleMalformedV1},
		{"zero-absent", two, treeRoleSetV1(8, zc, nil), n, TreeRoleAtZeroChildV1, TreeRoleAbsentV1},
		{"zero-malformed", two, treeRoleSetV1(8, zc, make([]byte, 31)), n, TreeRoleAtZeroChildV1, TreeRoleMalformedV1},
		{"zero-digest", two, treeRoleSetV1(8, zc, other[:]), n, TreeRoleAtZeroChildV1, TreeRoleRelationFailedV1},
		{"one-absent", two, treeRoleSetV1(8, oc, nil), n, TreeRoleAtOneChildV1, TreeRoleAbsentV1},
		{"one-malformed", two, treeRoleSetV1(8, oc, make([]byte, 31)), n, TreeRoleAtOneChildV1, TreeRoleMalformedV1},
		{"one-digest", two, treeRoleSetV1(8, oc, other[:]), n, TreeRoleAtOneChildV1, TreeRoleRelationFailedV1},
		{"n1-point-absent", single, treeRoleSetV1(1, zp, nil), n, TreeRoleAtZeroPointV1, TreeRoleAbsentV1},
		{"n1-point-width-19", single, treeRoleSetV1(1, zp, make([]byte, 19)), n, TreeRoleAtZeroPointV1, TreeRoleMalformedV1},
		{"n1-point-hash", single, treeRoleSetV1(1, zp, treeRoleValueV1(9)), n, TreeRoleAtZeroPointV1, TreeRoleRelationFailedV1},
		{"zero-point-absent", two, treeRoleSetV1(1, zp, nil), n, TreeRoleAtZeroPointV1, TreeRoleAbsentV1},
		{"zero-point-width-19", two, treeRoleSetV1(1, zp, make([]byte, 19)), n, TreeRoleAtZeroPointV1, TreeRoleMalformedV1},
		{"zero-point-hash", two, treeRoleSetV1(1, zp, treeRoleValueV1(9)), n, TreeRoleAtZeroPointV1, TreeRoleRelationFailedV1},
		{"one-point-absent", two, treeRoleSetV1(1, op, nil), n, TreeRoleAtOnePointV1, TreeRoleAbsentV1},
		{"one-point-width-19", two, treeRoleSetV1(1, op, make([]byte, 19)), n, TreeRoleAtOnePointV1, TreeRoleMalformedV1},
		{"one-point-hash", two, treeRoleSetV1(1, op, treeRoleValueV1(9)), n, TreeRoleAtOnePointV1, TreeRoleRelationFailedV1},
		{"lb-one-point-absent", three, treeRoleSetV1(1, op, nil), n, TreeRoleAtOnePointV1, TreeRoleAbsentV1},
		{"lb-one-point-width-19", three, treeRoleSetV1(1, op, make([]byte, 19)), n, TreeRoleAtOnePointV1, TreeRoleMalformedV1},
		{"lb-one-point-hash", three, treeRoleSetV1(1, op, treeRoleValueV1(9)), n, TreeRoleAtOnePointV1, TreeRoleRelationFailedV1},
		{"n1-s", single, nil, treeRoleCountsV1(1, 1), TreeRoleAtCardinalityV1, TreeRoleRelationFailedV1},
		{"n2-s", two, nil, treeRoleCountsV1(1, 2), TreeRoleAtCardinalityV1, TreeRoleRelationFailedV1},
	}
}

// treeRoleBranchValueV1 is a 140-byte branch value naming the two child node
// keys (generation prefix dropped) with zero child digests. treeChildFits
// fails on a child depth not above the parent's (top-child-depth) or a child
// key outside the parent prefix (zero-child-prefix); the side branch is
// top-child-fits. Its validTreeNodeID branch is structurally unreachable
// from stored bytes: decodeTreeSuffix builds every child through
// DecodeTreeNodeKey, which only yields valid leaf or branch identities.
func treeRoleBranchValueV1(zero, one []byte) []byte {
	var digest [32]byte
	value := append(append([]byte{}, zero[8:]...), digest[:]...)
	return append(append(value, one[8:]...), digest[:]...)
}

// treeRoleSwapChildrenV1 exchanges the two child references of the two-leaf
// top branch: the zero side then names KC, which violates treeChildFits.
func treeRoleSwapChildrenV1(t *testing.T, s *Store, g uint64) {
	var zero [36]byte
	value := make([]byte, 0, 140)
	b := testTreeNodeKey(1, 288, testKC)[8:]
	kc := testTreeLeafPreimage(testKC, treeRoleValueV1(1))
	b = append(b, kc[:]...)
	value = append(append(value, b...), testTreeNodeKey(1, 288, testKA)[8:]...)
	digest := testTreeLeafPreimage(testKA, treeRoleValueV1(0))
	treeRolePutV1(t, s, treeRoleNodeSiteV1(g, 0, zero), append(value, digest[:]...))
}

// treeRoleRowV1 runs one CURRENT observation of tr under a ProbeOnly arm,
// requires the Positive result with the Reader usable, and returns the census.
func treeRoleRowV1(t *testing.T, s *Store, o *OperationReservationOwner, tr *treeRoleTreeV1, counters *TreeRoleCountersV1, position TreeRolePositionV1, finding TreeRoleFindingV1) SelectedDamageEvidence {
	t.Helper()
	return treeRoleProbeV1(t, s, o, func(r *Reader, a *OperationAccount) {
		_, got := treeRoleObserveV1(t, r, a, treeRoleReqV1(treeRoleActiveV1(tr.g, 2), TreeRoleCurrentV1), tr.binding.Endpoint, counters)
		treeRoleWantPositiveV1(t, got, TreeRoleCurrentV1, tr.g, position, finding)
		if !r.usable() {
			t.Fatal("Positive finding left the Reader unusable")
		}
	})
}

// treeRoleNodeCorpusV1 is R5's counter width and final-stage rows and R6.
func treeRoleNodeCorpusV1(t *testing.T) {
	s, _, o := tsNew(t)
	for i, row := range treeRoleNodeRowsV1() {
		g := uint64(200 + i)
		tr := treeRoleSeededV1(t, s, o, g, treeRoleAppliedV1, row.keys...)
		if row.damage != nil {
			row.damage(t, s, g)
		}
		t.Run(row.name, func(t *testing.T) { treeRoleRowV1(t, s, o, tr, row.counters(tr), row.position, row.finding) })
	}
}

// treeRoleEvidenceSeedV1 seeds one evidence row at 0x12 then id.
func treeRoleEvidenceSeedV1(t *testing.T, s *Store, id [32]byte, value []byte) {
	t.Helper()
	treeNativeSeed(t, s, 0, append([]byte{0x12}, id[:]...), value)
}

// treeRolePairsV1 is the pair table (A5, R2, H4, H5): every AssuranceOnly
// and Defective row with its exact status, affected roles and defect, its
// read census (the two binding reads plus the one evidence read of a row the
// table resolves through evidence; no counter, node or point read), the whole
// account ceiling held for every evidence-free row (zero temporary
// reservation), and every binding and evidence row unchanged afterwards
// (FixtureRawRowEqual).
func treeRolePairsV1(t *testing.T) {
	s, _, o := tsNew(t)
	refCur, value := treeRoleImportV1(TreeOriginalCurrentV1, 8)
	refLag, _ := treeRoleImportV1(TreeOriginalLagV1, 8)
	wrongLag, _ := treeRoleImportV1(TreeOriginalLagV1, 9) // same EvidenceID, different OriginalLagID
	bothWrong, _ := treeRoleImportV1(TreeOriginalCurrentV1, 9)
	absentCur, absentLag, hashCur := refCur, refLag, refCur
	absentCur.EvidenceID, absentLag.EvidenceID, hashCur.EvidenceID = testTreeHash(0x77), testTreeHash(0x77), testTreeHash(0x78)
	undecodable := append([]byte{2}, value[1:]...)
	decodeCur, decodeLag := refCur, refLag
	decodeCur.EvidenceID, decodeLag.EvidenceID = sha3.Sum256(undecodable), sha3.Sum256(undecodable)
	evidence := map[[32]byte][]byte{refCur.EvidenceID: value, hashCur.EvidenceID: value, decodeCur.EvidenceID: undecodable}
	for id, v := range evidence {
		treeRoleEvidenceSeedV1(t, s, id, v)
	}
	names := []string{"F", "F2", "cur", "lag", "curAsLag", "lagAsCur", "absentCur", "absentLag", "wrongLag", "bothWrong", "hashCur", "decodeCur", "decodeLag"}
	refs := []*TreeImportReferenceV1{nil, nil, &refCur, &refLag, &refLag, &refCur, &absentCur, &absentLag, &wrongLag, &bothWrong, &hashCur, &decodeCur, &decodeLag}
	gens, trees := map[string]uint64{}, make([]*treeRoleTreeV1, len(refs))
	for i, name := range names {
		gens[name] = uint64(100 + i)
		trees[i] = treeRoleAssuredV1(t, s, o, gens[name], refs[i])
	}
	assured, defective, both := TreePairAssuranceOnlyV1, TreePairDefectiveV1, TreePairAffectedBothV1
	rows := []struct {
		name, current, lag string
		reads              uint64
		status             TreePairStatusV1
		affected           TreePairAffectedV1
		defect             TreePairDefectV1
	}{
		{"F,F", "F", "F2", 0, assured, 0, 0},
		{"C,F", "cur", "F", 1, assured, 0, 0},
		{"F,C", "F", "lag", 1, assured, 0, 0},
		{"C,C", "cur", "lag", 1, assured, 0, 0},
		{"C,F-absent", "absentCur", "F", 1, defective, TreePairAffectedCurrentV1, TreePairEvidenceAbsentV1},
		{"F,C-absent", "F", "absentLag", 1, defective, TreePairAffectedLagV1, TreePairEvidenceAbsentV1},
		{"C,C-absent", "absentCur", "absentLag", 1, defective, both, TreePairEvidenceAbsentV1},
		{"C,F-hash", "hashCur", "F", 1, defective, TreePairAffectedCurrentV1, TreePairEvidenceUnresolvedV1},
		{"F,C-origin", "F", "wrongLag", 1, defective, TreePairAffectedLagV1, TreePairEvidenceUnresolvedV1},
		{"C,C-decode", "decodeCur", "decodeLag", 1, defective, both, TreePairEvidenceUnresolvedV1},
		{"C,F-wrong-role", "curAsLag", "F", 0, defective, TreePairAffectedCurrentV1, TreePairWrongRoleV1},
		{"F,C-wrong-role", "F", "lagAsCur", 0, defective, TreePairAffectedLagV1, TreePairWrongRoleV1},
		{"C,C-wrong-role", "curAsLag", "lag", 0, defective, both, TreePairWrongRoleV1},
		{"C,C-provenance", "cur", "wrongLag", 0, defective, both, TreePairProvenanceConflictV1},
		{"C,C-wrong-role-and-provenance", "cur", "bothWrong", 0, defective, both, TreePairWrongRoleV1},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			auth := treeRoleActiveV1(gens[row.current], gens[row.lag])
			e := treeRoleProbeV1(t, s, o, func(r *Reader, a *OperationAccount) {
				c, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleCurrentV1))
				mustEnvironment(t, err)
				l, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleLagV1))
				mustEnvironment(t, err)
				qualify := func() error {
					q, err := r.QualifyTreePairAssuranceV1(a, c, l)
					mustEnvironment(t, err)
					treeRoleWantPairV1(t, r, q, row.status, row.affected, row.defect, c, l)
					return nil
				}
				if row.reads == 0 {
					mustEnvironment(t, a.WithReservation(treeRoleLaneMaxV1, qualify))
					return
				}
				mustEnvironment(t, qualify())
			})
			treeRoleWantGetsV1(t, e, 2+row.reads, 0, 0)
		})
	}
	for _, tr := range trees {
		encoded, err := tr.binding.Encode()
		mustEnvironment(t, err)
		if equal, err := FixtureRawRowEqual(s, 0, tsRootKey(tr.g), encoded); err != nil || !equal {
			t.Fatalf("binding row of generation %d changed: %v", tr.g, err)
		}
	}
	for id, want := range evidence {
		if equal, err := FixtureRawRowEqual(s, 0, append([]byte{0x12}, id[:]...), want); err != nil || !equal {
			t.Fatalf("evidence row %x changed: %v", id[:4], err)
		}
	}
}

func treeRoleWantPairV1(t *testing.T, r *Reader, q TreePairQualificationV1, status TreePairStatusV1, affected TreePairAffectedV1, defect TreePairDefectV1, c, l TreeRoleObservationV1) {
	t.Helper()
	if q.Status != status || q.Affected != affected || q.Defect != defect {
		t.Fatalf("pair (%d,%d,%d), want (%d,%d,%d)", q.Status, q.Affected, q.Defect, status, affected, defect)
	}
	if !treeRoleSameV1(q.Current, c) || !treeRoleSameV1(q.Lag, l) {
		t.Fatal("pair roles differ from their Bound inputs")
	}
	if q.Current.Binding.Assurance.Import != nil && q.Current.Binding.Assurance.Import == c.Binding.Assurance.Import {
		t.Fatal("pair shares a public Import pointer with a separately returned role")
	}
	if q.HealthyOn(r) || !r.usable() {
		t.Fatal("early pair is HealthyOn or left the Reader unusable")
	}
}

// treeRoleEvidenceEIOV1 is H5 and E2's evidence row: an evidence EIO returns
// the native error, recorded as the Reader failure, with a zero result.
func treeRoleEvidenceEIOV1(t *testing.T) {
	s, _, o := tsNew(t)
	ref, value := treeRoleImportV1(TreeOriginalCurrentV1, 8)
	treeRoleEvidenceSeedV1(t, s, ref.EvidenceID, value)
	treeRoleAssuredV1(t, s, o, 1, &ref)
	treeRoleAssuredV1(t, s, o, 2, nil)
	var raw, viewErr error
	_, err := FixtureSelectedDamage(s, o, SelectedDamageGetEIO, 0, append([]byte{0x12}, ref.EvidenceID[:]...), func() {
		viewErr = treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
			auth := treeRoleActiveV1(1, 2)
			c, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleCurrentV1))
			mustEnvironment(t, err)
			l, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleLagV1))
			mustEnvironment(t, err)
			q, err := r.QualifyTreePairAssuranceV1(a, c, l)
			raw = err
			treeNativeError(t, err, "update", "IO", 5, "error 5", nil)
			if !treeRolePairZeroV1(q) || r.usable() || any(r.failure) != any(err) {
				t.Fatalf("evidence EIO: pair %+v, usable %v", q, r.usable())
			}
		})
	})
	if err != nil || any(viewErr) != any(raw) {
		t.Fatalf("fixture %v, View %v, want %v", err, viewErr, raw)
	}
	// E2 next legal call: the recorded failure consumed the Store handle.
	next := s.View(func(*Reader) error { t.Fatal("consumed Store invoked callback"); return nil })
	if any(next) != any(raw) || reservationLive(o) != 0 {
		t.Fatalf("next View %v, live %d, want the recorded %v", next, reservationLive(o), raw)
	}
}

// treeRolePairZeroV1 is true exactly for the zero pair value.
func treeRolePairZeroV1(q TreePairQualificationV1) bool {
	zero := TreeRoleObservationV1{}
	return all(q.stage == nil, q.Status == 0, q.Affected == 0, q.Defect == 0, treeRoleSameV1(q.Current, zero), treeRoleSameV1(q.Lag, zero))
}

// treeRoleZeroIOV1 is H6's reuse and zero-I/O rows: one full valid chain
// with supplied CURRENT counters reads exactly the two binding rows and the
// LAG counter at rank 0, the three CURRENT nodes and its two points: the
// finite call rereads no binding, and the F,F assurance, completion and
// HealthyOn add no read.
func treeRoleZeroIOV1(t *testing.T) {
	s, _, o := tsNew(t)
	tr := treeRoleSeededV1(t, s, o, 1, treeRoleAppliedV1, testKA, testKC)
	treeRoleAssuredV1(t, s, o, 2, nil)
	evidence := treeRoleProbeV1(t, s, o, func(r *Reader, a *OperationAccount) {
		auth := treeRoleActiveV1(1, 2)
		cb, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(auth, TreeRoleCurrentV1))
		mustEnvironment(t, err)
		lb, lq := treeRoleObserveV1(t, r, a, treeRoleReqV1(auth, TreeRoleLagV1), TreeEndpointV1{}, nil)
		counters := tr.counters
		cq, err := r.ObserveTreeRoleV1(a, treeRoleFinalReqV1(cb, treeRoleAppliedV1, &counters))
		mustEnvironment(t, err)
		early, err := r.QualifyTreePairAssuranceV1(a, cb, lb)
		mustEnvironment(t, err)
		final, err := r.CompleteTreePairQualificationV1(early, cq, lq)
		mustEnvironment(t, err)
		if !final.HealthyOn(r) {
			t.Fatal("final pair not HealthyOn")
		}
	})
	treeRoleWantGetsV1(t, evidence, 3, 3, 2)
}

// treeRoleBindingReuseV1 is H6's reuse row. The large-image fault serves the
// first get of the armed CURRENT binding key on the View's transaction and
// fails every later one with EIO (mdbx_cgo.go:223-229). The finite call is
// Qualified without reaching the fault; a second binding call on the same
// transaction then hits it, which shows the arm was live.
func treeRoleBindingReuseV1(t *testing.T) {
	s, _, o := tsNew(t)
	tr := treeRoleSeededV1(t, s, o, 1, treeRoleAppliedV1, testKA, testKC)
	var viewErr, raw error
	large, err := fixtureLargeFault(s, 1, 0, tsRootKey(1), func() {
		viewErr = treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
			request := treeRoleReqV1(treeRoleActiveV1(1, 2), TreeRoleCurrentV1)
			_, final := treeRoleObserveV1(t, r, a, request, treeRoleAppliedV1, nil)
			treeRoleWantQualifiedV1(t, final, TreeRoleCurrentV1, tr)
			if !r.usable() {
				t.Fatal("finite call left the Reader unusable")
			}
			again, err := r.ObserveTreeRoleBindingV1(a, request)
			raw = err
			treeNativeError(t, err, "update", "IO", 5, "error 5", nil)
			if !treeRoleSameV1(again, TreeRoleObservationV1{}) || r.usable() {
				t.Fatalf("armed binding reread: %+v, usable %v", again, r.usable())
			}
		})
	})
	if err != nil || large.gets != 2 || any(viewErr) != any(raw) {
		t.Fatalf("fixture %v, binding gets %d, View %v, want 2 and %v", err, large.gets, viewErr, raw)
	}
}

// treeRoleAbortV1 is H3: a Qualified pair produced inside
// StartupVerifyCanonicalV1 with an abort EIO armed is not HealthyOn after
// return, no later Reader passes the owner check, and every grant is released.
func treeRoleAbortV1(t *testing.T) {
	s, _, o := tsNew(t)
	treeRoleSeededV1(t, s, o, 1, treeRoleAppliedV1, testKA, testKC)
	treeRoleAssuredV1(t, s, o, 2, nil)
	var held TreePairQualificationV1
	var expired *Reader
	var startupErr error
	evidence, err := FixtureSelectedDamage(s, o, SelectedDamageAbortEIO, 0, nil, func() {
		mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
			startupErr, _ = s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
				_, final, _ := treeRoleFullChainV1(t, r, a, treeRoleActiveV1(1, 2))
				if !final.HealthyOn(r) {
					t.Fatal("final pair not HealthyOn inside the frame")
				}
				held, expired = final, r
				return StartupCanonicalActiveAndReplayCompleteV1, nil
			})
			return nil
		}))
	})
	if err != nil || evidence.Faults != 1 {
		t.Fatalf("abort EIO not hit as armed: fixture %v, faults %d", err, evidence.Faults)
	}
	if expired == nil || held.Status != TreePairQualifiedV1 {
		t.Fatalf("no Qualified pair held from the frame: status %v, reader %v", held.Status, expired != nil)
	}
	if startupErr == nil || held.HealthyOn(expired) || reservationLive(o) != 0 {
		t.Fatalf("abort EIO: startup %v, HealthyOn %v, live %d (fixture %v)", startupErr, held.HealthyOn(expired), reservationLive(o), err)
	}
	next := s.View(func(r *Reader) error {
		if r.RequireCanonicalOwnerVerificationV1() == nil {
			t.Fatal("a later Reader passed the owner check")
		}
		return nil
	})
	if any(next) != any(startupErr) {
		t.Fatalf("next View %v, want the retained %v", next, startupErr)
	}
}

// treeRoleImageTargetsV1 is A2's IMAGE COMPLETE row with a resolving
// reference and R1's malformed target bindings: the target pair is Qualified
// and HealthyOn; a malformed TargetCurrent and, separately, a malformed
// TargetLag binding is Positive Malformed at Binding, unrecorded, and the
// same Store handle serves a following View.
func treeRoleImageTargetsV1(t *testing.T) {
	s, _, o := tsNew(t)
	ref, value := treeRoleImportV1(TreeOriginalCurrentV1, 8)
	treeRoleEvidenceSeedV1(t, s, ref.EvidenceID, value)
	current := treeRoleBuildV1(t, 3, treeRoleAppliedV1, testKA)
	current.binding.Assurance = TreeAssuranceV1{Kind: TreeAssuranceImportedBaseV1, Import: &ref}
	treeRoleSeedAllV1(t, s, o, current)
	lag := treeRoleAssuredV1(t, s, o, 4, nil)
	image := treeRoleReplayV1(TreeSourceImageV1, TreeProgressCompleteV1, ReplayCursorV1{})
	mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
		cb, cq := treeRoleObserveV1(t, r, a, treeRoleReqV1(image, TreeRoleTargetCurrentV1), treeRoleAppliedV1, nil)
		lb, lq := treeRoleObserveV1(t, r, a, treeRoleReqV1(image, TreeRoleTargetLagV1), TreeEndpointV1{}, nil)
		treeRoleWantQualifiedV1(t, cq, TreeRoleTargetCurrentV1, current)
		treeRoleWantQualifiedV1(t, lq, TreeRoleTargetLagV1, lag)
		early, err := r.QualifyTreePairAssuranceV1(a, cb, lb)
		mustEnvironment(t, err)
		treeRoleWantPairV1(t, r, early, TreePairAssuranceOnlyV1, 0, 0, cb, lb)
		final, err := r.CompleteTreePairQualificationV1(early, cq, lq)
		mustEnvironment(t, err)
		if !final.HealthyOn(r) {
			t.Fatal("IMAGE COMPLETE target pair not HealthyOn")
		}
	}))
	// R1: a malformed TargetCurrent or TargetLag binding is Positive Malformed
	// at Binding and unrecorded; the sibling role's earlier Bound result stays
	// usable, the same Store handle serves a following View and the row keeps
	// its bytes (zero attempted mutation).
	for _, row := range []struct {
		tr, sibling *treeRoleTreeV1
		role, other TreeRoleSelectorV1
	}{{current, lag, TreeRoleTargetCurrentV1, TreeRoleTargetLagV1}, {lag, current, TreeRoleTargetLagV1, TreeRoleTargetCurrentV1}} {
		good, err := row.tr.binding.Encode()
		mustEnvironment(t, err)
		bad := append([]byte{2}, good[1:]...)
		treeNativeSeed(t, s, 0, tsRootKey(row.tr.g), bad)
		mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
			sb, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(image, row.other))
			mustEnvironment(t, err)
			got, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(image, row.role))
			mustEnvironment(t, err)
			treeRoleWantPositiveV1(t, got, row.role, row.tr.g, TreeRoleAtBindingV1, TreeRoleMalformedV1)
			if !r.usable() || r.failure != nil {
				t.Fatal("malformed target binding left the Reader unusable or recorded")
			}
			sq, err := r.ObserveTreeRoleV1(a, treeRoleFinalReqV1(sb, row.sibling.binding.Endpoint, nil))
			if err != nil || sq.Status != TreeRoleQualifiedV1 {
				t.Fatalf("earlier Bound after a Positive: %+v %v", sq, err)
			}
		}))
		mustEnvironment(t, s.View(func(*Reader) error { return nil }))
		if equal, err := FixtureRawRowEqual(s, 0, tsRootKey(row.tr.g), bad); err != nil || !equal {
			t.Fatalf("malformed target binding row changed: %v", err)
		}
		treeNativeSeed(t, s, 0, tsRootKey(row.tr.g), good)
	}
}

// treeRoleNestedV1 is A7 on both nested Binding pointer targets of a role
// whose Top.Node and Assurance.Import are non-nil: each returned stage value
// is accepted unchanged, refused after an in-place edit of either pointer
// target, and accepted again once the edit is undone; a later
// ObserveTreeRoleV1 of another generation leaves every Binding equal to its
// literal.
func treeRoleNestedV1(t *testing.T) {
	s, _, o := tsNew(t)
	ref, value := treeRoleImportV1(TreeOriginalCurrentV1, 8)
	treeRoleEvidenceSeedV1(t, s, ref.EvidenceID, value)
	tr := treeRoleBuildV1(t, 1, treeRoleAppliedV1, testKA, testKC)
	tr.binding.Assurance = TreeAssuranceV1{Kind: TreeAssuranceImportedBaseV1, Import: &ref}
	treeRoleSeedAllV1(t, s, o, tr)
	treeRoleSeededV1(t, s, o, 2, TreeEndpointV1{})
	treeRoleSeededV1(t, s, o, 5, treeRoleAppliedV1, testKA)
	auth := treeRoleActiveV1(1, 2)
	edits := []func(*TreeRoleObservationV1){
		func(w *TreeRoleObservationV1) { w.Binding.Top.Node.Depth ^= 1 },
		func(w *TreeRoleObservationV1) { w.Binding.Assurance.Import.OriginalLagID ^= 1 },
	}
	mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
		cb, cq := treeRoleObserveV1(t, r, a, treeRoleReqV1(auth, TreeRoleCurrentV1), treeRoleAppliedV1, nil)
		lb, lq := treeRoleObserveV1(t, r, a, treeRoleReqV1(auth, TreeRoleLagV1), TreeEndpointV1{}, nil)
		early, err := r.QualifyTreePairAssuranceV1(a, cb, lb)
		mustEnvironment(t, err)
		final, err := r.CompleteTreePairQualificationV1(early, cq, lq)
		mustEnvironment(t, err)
		_, later := treeRoleObserveV1(t, r, a, treeRoleReqV1(treeRoleActiveV1(5, 2), TreeRoleCurrentV1), treeRoleAppliedV1, nil)
		if later.Status != TreeRoleQualifiedV1 || final.Current.Binding.Top.Node == nil {
			t.Fatalf("later observation %+v", later)
		}
		for i, w := range []TreeRoleObservationV1{cb, cq, early.Current, final.Current} {
			if !reflect.DeepEqual(w.Binding, tr.binding) {
				t.Fatalf("value %d Binding %+v after a later call, want %+v", i, w.Binding, tr.binding)
			}
		}
		complete := func() bool { _, err := r.CompleteTreePairQualificationV1(early, cq, lq); return err == nil }
		uses := []struct {
			name string
			obs  *TreeRoleObservationV1
			ok   func() bool
		}{
			{"bound-assurance", &cb, func() bool { _, err := r.QualifyTreePairAssuranceV1(a, cb, lb); return err == nil }},
			{"bound-finite", &cb, func() bool {
				_, err := r.ObserveTreeRoleV1(a, treeRoleFinalReqV1(cb, treeRoleAppliedV1, nil))
				return err == nil
			}},
			{"early-completion", &early.Current, complete},
			{"qualified-completion", &cq, complete},
			{"final-healthy", &final.Current, func() bool { return final.HealthyOn(r) }},
		}
		values := []*TreeRoleObservationV1{&cb, &cq, &early.Current, &final.Current}
		for _, use := range uses {
			for i, edit := range edits {
				if !use.ok() {
					t.Fatalf("%s: unchanged value refused before edit %d", use.name, i)
				}
				edit(use.obs)
				if use.ok() {
					t.Errorf("%s: in-place edit %d still accepted", use.name, i)
				}
				for _, w := range values {
					if w != use.obs && !reflect.DeepEqual(w.Binding, tr.binding) {
						t.Errorf("%s: in-place edit %d reached another returned value", use.name, i)
					}
				}
				edit(use.obs)
			}
		}
		if !uses[0].ok() || !reflect.DeepEqual(*cq.Binding.Assurance.Import, ref) || !r.usable() {
			t.Fatal("restored values refused or the Reader changed")
		}
	}))
}

// treeRoleProbeV1 returns the read census of one View running use.
func treeRoleProbeV1(t *testing.T, s *Store, o *OperationReservationOwner, use func(*Reader, *OperationAccount)) SelectedDamageEvidence {
	t.Helper()
	evidence, err := FixtureSelectedDamage(s, o, SelectedDamageProbeOnly, 0, nil, func() {
		mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, use))
	})
	mustEnvironment(t, err)
	return evidence
}

// treeRoleWantGetsV1 checks the census: meta reads at rank 0, point reads at
// rank 1, node reads at rank 8 and no read of any other rank.
func treeRoleWantGetsV1(t *testing.T, e SelectedDamageEvidence, meta, nodes, points uint64) {
	t.Helper()
	if e.OldGets != [8]uint64{0: meta, 1: points} || e.NodeGets != nodes {
		t.Fatalf("read census %v nodes %d, want rank0 %d rank1 %d nodes %d", e.OldGets, e.NodeGets, meta, points, nodes)
	}
}

// treeRoleShapeCorpusV1 is R5's counter absence and every pre-read relation
// (each RelationFailed at Cardinality with no node or point read although
// the node and point rows are present), R3/R6's absent top under a binding
// equal to the header root (one node read, no point read), and A2/R1's legal
// IMAGE PARTIAL with absent target rows (PartialDomain, zero reads). The
// final-stage rows are in treeRoleNodeRowsV1.
func treeRoleShapeCorpusV1(t *testing.T) {
	s, _, o := tsNew(t)
	empty := treeRoleBuildV1(t, 50, TreeEndpointV1{})
	appliedEmpty := treeRoleBuildV1(t, 51, treeRoleAppliedV1)
	badDigest := treeRoleBuildV1(t, 52, treeRoleAppliedV1)
	badDigest.binding.RootDigest = testTreeHash(0x31)
	single := treeRoleBuildV1(t, 53, treeRoleAppliedV1, testKA)
	leafEmpty := treeRoleBuildV1(t, 54, treeRoleAppliedV1, testKA)
	leafEmpty.binding.RootDigest = testTreeC01()
	two := treeRoleBuildV1(t, 55, treeRoleAppliedV1, testKA, testKC)
	branchEmpty := treeRoleBuildV1(t, 56, treeRoleAppliedV1, testKA, testKC)
	branchEmpty.binding.RootDigest = testTreeC01()
	for _, tr := range []*treeRoleTreeV1{empty, appliedEmpty, badDigest, single, leafEmpty, two, branchEmpty} {
		treeRoleSeedAllV1(t, s, o, tr)
	}
	noCounter := treeRoleBuildV1(t, 59, TreeEndpointV1{})
	noCounter.seedV1(t, s, o, true)
	bare := treeRoleBuildV1(t, 64, treeRoleAppliedV1, testKA)
	bare.seedV1(t, s, o, false)
	c := func(sum, n uint64) *TreeRoleCountersV1 {
		return &TreeRoleCountersV1{LogicalStateBytes: sum, UTXOCount: n}
	}
	card, related := TreeRoleAtCardinalityV1, TreeRoleRelationFailedV1
	rows := []struct {
		name        string
		tr          *treeRoleTreeV1
		counters    *TreeRoleCountersV1
		position    TreeRolePositionV1
		finding     TreeRoleFindingV1
		meta, nodes uint64
	}{
		{"counter-absent", noCounter, nil, TreeRoleAtCounterV1, TreeRoleAbsentV1, 2, 0},
		{"n0-s1", empty, c(1, 0), card, related, 1, 0},
		{"n0-leaf", leafEmpty, c(0, 0), card, related, 1, 0},
		{"n0-branch", branchEmpty, c(0, 0), card, related, 1, 0},
		{"n0-digest", badDigest, c(0, 0), card, related, 1, 0},
		{"n0-dual", leafEmpty, c(1, 0), card, related, 1, 0},
		{"n1-branch", two, c(two.counters.LogicalStateBytes, 1), card, related, 1, 0},
		{"n1-empty", appliedEmpty, c(56, 1), card, related, 1, 0},
		{"n2-leaf", single, c(112, 2), card, related, 1, 0},
		{"n2-empty", appliedEmpty, c(112, 2), card, related, 1, 0},
		{"absent-top", bare, nil, TreeRoleAtTopV1, TreeRoleAbsentV1, 2, 1},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			e := treeRoleRowV1(t, s, o, row.tr, row.counters, row.position, row.finding)
			treeRoleWantGetsV1(t, e, row.meta, row.nodes, 0)
		})
	}
	partial := treeRoleReplayV1(TreeSourceImageV1, TreeProgressPartialV1, ReplayCursorV1{})
	treeRoleWantGetsV1(t, treeRoleProbeV1(t, s, o, func(r *Reader, a *OperationAccount) {
		for _, role := range []TreeRoleSelectorV1{TreeRoleTargetCurrentV1, TreeRoleTargetLagV1} {
			got, err := r.ObserveTreeRoleBindingV1(a, treeRoleReqV1(partial, role))
			if err != nil || got.Status != TreeRolePartialDomainV1 || !r.usable() {
				t.Fatalf("PARTIAL role %d: %+v %v", role, got, err)
			}
		}
	}), 0, 0, 0)
}

// treeRoleLedgerResolvedV1 is A6 with a resolving evidence row: at each exact
// boundary the binding, finite and evidence calls return Bound, Qualified
// and AssuranceOnly; one more held byte returns the capacity error.
func treeRoleLedgerResolvedV1(t *testing.T) {
	s, _, o := tsNew(t)
	ref, value := treeRoleLedgerSeedV1(t, s, o)
	treeRoleEvidenceSeedV1(t, s, ref.EvidenceID, value)
	treeRoleLedgerLanesV1(t, s, o, TreePairAssuranceOnlyV1)
}

// treeRoleGrandchildAbsentV1 is R3's absent grandchild: deleting a leaf
// below a branch child (leaf-branch and branch-branch) leaves the result
// Qualified.
func treeRoleGrandchildAbsentV1(t *testing.T) {
	for i, keys := range [][][36]byte{{testKA, testKB, testKC}, {testKA, testKB, testKC, treeRoleKDV1}} {
		s, _, o := tsNew(t)
		tr := treeRoleSeededV1(t, s, o, 1, treeRoleAppliedV1, keys...)
		treeRoleDeleteV1(t, s, treeRoleNodeSiteV1(1, 288, testKA))
		treeRoleDeleteV1(t, s, treeRoleNodeSiteV1(1, 288, testKB))
		if i == 1 {
			treeRoleDeleteV1(t, s, treeRoleNodeSiteV1(1, 288, treeRoleKDV1))
		}
		mustEnvironment(t, treeRoleViewV1(t, s, o, LaneOperation, func(r *Reader, a *OperationAccount) {
			_, got := treeRoleObserveV1(t, r, a, treeRoleReqV1(treeRoleActiveV1(1, 2), TreeRoleCurrentV1), treeRoleAppliedV1, nil)
			treeRoleWantQualifiedV1(t, got, TreeRoleCurrentV1, tr)
		}))
	}
}

// treeRoleCapacityReadsV1 is R8's "before reads": treeRoleBoundaryV1 with
// each additional A6 hold increased by one runs under a ProbeOnly arm; its
// binding, finite and evidence calls return the capacity error and the census
// holds only its two earlier binding reads.
func treeRoleCapacityReadsV1(t *testing.T) {
	s, _, o := tsNew(t)
	ref, value := treeRoleLedgerSeedV1(t, s, o)
	treeRoleEvidenceSeedV1(t, s, ref.EvidenceID, value)
	e, err := FixtureSelectedDamage(s, o, SelectedDamageProbeOnly, 0, nil, func() {
		treeRoleBoundaryV1(t, s, o, LaneOperation, treeRoleLaneMaxV1, 1, TreePairAssuranceOnlyV1)
	})
	mustEnvironment(t, err)
	treeRoleWantGetsV1(t, e, 2, 0, 0)
}

// treeRoleAdmissionReadsV1 is R7's zero new reads: every invalid request of
// treeRoleBadRequestsV1 reads nothing; the census holds its two binding
// reads, the one counter read of its following valid N=0 finite call and the
// two binding reads of its legal-source selectivity control.
func treeRoleAdmissionReadsV1(t *testing.T) {
	s, _, o := tsNew(t)
	treeRoleAssuredV1(t, s, o, 1, nil)
	treeRoleAssuredV1(t, s, o, 2, nil)
	e := treeRoleProbeV1(t, s, o, func(r *Reader, a *OperationAccount) {
		treeRoleBadRequestsV1(t, r, a, treeRoleActiveV1(1, 2))
	})
	treeRoleWantGetsV1(t, e, 5, 0, 0)
}
