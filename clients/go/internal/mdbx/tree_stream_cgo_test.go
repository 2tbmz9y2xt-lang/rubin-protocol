//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"runtime"
	"slices"
	"testing"
	"unsafe"
)

// These tests own public admission, accounting and lifetime observations. Engine
// tests cannot observe a refusal before the exported entry reaches the engine.
type tsSource func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error

func (f tsSource) TreeDeltaV1(p TreePositionV1, r *Reader, s *TreeDeltaSinkV1) error {
	return f(p, r, s)
}

type tsResult struct {
	truth CommitTruth
	stage UpdateStage
	index int
	err   error
}

func tsInvoke(s *Store, a *OperationAccount, f func(*Reader) (TreeOperationV1, error)) tsResult {
	var r tsResult
	r.truth, r.stage, r.index, r.err = s.UpdateTreeV1(a, f)
	return r
}

func (r tsResult) tuple(t *testing.T, truth CommitTruth, stage UpdateStage, index int) {
	t.Helper()
	if r.truth != truth || r.stage != stage || r.index != index {
		t.Fatalf("public result = (%d,%d,%d,%v), want (%d,%d,%d)", r.truth, r.stage, r.index, r.err, truth, stage, index)
	}
}

func tsRun(t *testing.T, s *Store, o *OperationReservationOwner, kind OperationKind, op TreeOperationV1) tsResult {
	t.Helper()
	var r tsResult
	calls := 0
	before := reservationLive(o)
	mustEnvironment(t, o.WithOperation(kind, func(a *OperationAccount) error {
		r = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { calls++; return op, nil })
		return nil
	}))
	if calls != 1 {
		t.Fatalf("public callback calls%d, want1", calls)
	}
	if got := reservationLive(o); got != before {
		t.Fatalf("owner live %d, want pre-call %d", got, before)
	}
	return r
}

func tsNew(t *testing.T) (*Store, string, *OperationReservationOwner) {
	t.Helper()
	s, path, _ := treeNativeStore(t)
	o := reservationOwner(t, 805_306_368)
	r := tsRun(t, s, o, TreeOperation, tsEntry(t))
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	return s, path, o
}

func tsEntry(t *testing.T) TreeOperationV1 {
	t.Helper()
	a := TreeAuthorityV1{Authority: StorageAuthorityV1{Version: 1, ActiveProfile: 1, ActiveGenerationID: 1, NextGenerationID: 5, Phase: 1, Lifecycle: 1}, LagGenerationID: 2}
	authority, err := a.Encode()
	mustEnvironment(t, err)
	header := initial148NativeLiteral(t)
	hash := sha3.Sum256(header)
	return TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{
		{DBI: TreeSchemaV1DBIs()[0], Key: []byte{2}, AfterKind: 2, Literal: authority},
		{DBI: TreeSchemaV1DBIs()[3], Key: hash[:], AfterKind: 2, Literal: header},
	}}}
}

func tsTarget(n uint64) Mutation {
	key := binary.BigEndian.AppendUint64(nil, 1)
	key = binary.BigEndian.AppendUint64(key, n)
	return Mutation{DBI: TreeSchemaV1DBIs()[6], Key: key, AfterKind: 2, Literal: make([]byte, 104)}
}

func tsPair(n uint64) TreeOperationV1 {
	return TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{tsTarget(n)}}}
}

func tsFollowing(t *testing.T, s *Store, o *OperationReservationOwner) {
	t.Helper()
	mustEnvironment(t, s.View(func(*Reader) error { return nil }))
	r := tsRun(t, s, o, TreeOperation, tsPair(900_000))
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
}

func tsConsumed(t *testing.T, s *Store, o *OperationReservationOwner, truth CommitTruth, terminal error) {
	t.Helper()
	if s.state != storeCLOSED || any(s.terminal) != any(terminal) || s.terminalTruth != truth {
		t.Fatalf("consumed %s terminal%v truth%d", s.state, s.terminal, s.terminalTruth)
	}
	calls := 0
	mustEnvironment(t, o.WithOperation(TreeOperation, func(a *OperationAccount) error {
		r := tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { calls++; return tsPair(9), nil })
		r.tuple(t, truth, 1, -1)
		if any(r.err) != any(terminal) || calls != 0 {
			t.Fatal("consumed UpdateTreeV1 did not reuse terminal")
		}
		return nil
	}))
	if err := s.View(func(*Reader) error { calls++; return nil }); any(err) != any(terminal) || calls != 0 {
		t.Fatal("consumed View did not reuse terminal")
	}
}

func tsRead(t *testing.T, s *Store, dbi DBI, key, want []byte) {
	t.Helper()
	mustEnvironment(t, s.View(func(r *Reader) error {
		got, present, err := r.Get(dbi, key)
		if err != nil || present != (want != nil) || !bytes.Equal(got, want) {
			t.Errorf("durable rank%d key%x = (%x,%v,%v), want %x", dbi.Rank, key, got, present, err, want)
		}
		return nil
	}))
}

func tsReopen(t *testing.T, s *Store, path string) *Store {
	t.Helper()
	if s.state == storeOPEN {
		mustEnvironment(t, s.Close())
	}
	opened, err := OpenTreeV1(path, environmentConfig(), [32]byte{7})
	mustEnvironment(t, err)
	t.Cleanup(func() { _ = opened.Close() })
	return opened
}

func tsExpiredReader(t *testing.T, r *Reader) {
	t.Helper()
	if r == nil {
		t.Fatal("Reader was not captured")
	}
	value, present, err := r.Get(TreeSchemaV1DBIs()[0], []byte{2})
	if value != nil || present {
		t.Fatal("expired Reader returned a value")
	}
	treeNativeError(t, err, "get", "InvalidInput", 22, "Reader is not active", nil)
}

func tsPrimitive(t *testing.T, source TreeSourceV1) (TreePrimitiveV1, Mutation) {
	t.Helper()
	body := append(initial148NativeLiteral(t), tdFrame(1, 0, nil)...)
	body[140] ^= 0x20 // differs from S0's header, keeping the row hash-bound
	block := sha3.Sum256(body[:148])
	ep := TreeEndpointV1{Kind: 1, Height: 5, BlockHash: block, CumulativeChainwork: [40]byte{39: 37}}
	p := TreePrimitiveV1{Direction: 1, Kind: 2, Generation: 1, Block: block, Height: 5, Source: source, Undo: 1, Endpoint: ep}
	return p, Mutation{DBI: TreeSchemaV1DBIs()[4], Key: block[:], AfterKind: 2, Literal: body}
}

func tsOperation(t *testing.T, source TreeSourceV1) TreeOperationV1 {
	p, body := tsPrimitive(t, source)
	return TreeOperationV1{Primitives: []TreePrimitiveV1{p}, Pair: TreePairV1{Mutations: []Mutation{body}}}
}

func tsRefusal(t *testing.T, r tsResult, capacity bool) {
	t.Helper()
	r.tuple(t, 1, 1, -1)
	if capacity {
		treeNativeError(t, r.err, "update", "Capacity", -30417, "Update Batch exceeds bound", nil)
		return
	}
	treeNativeError(t, r.err, "update", "InvalidInput", 22, "invalid Update Batch", nil)
}

func tsRejected(t *testing.T, kind OperationKind, build func(*testing.T) TreeOperationV1, capacity bool) {
	t.Helper()
	s, path, o := tsNew(t)
	op := build(t)
	snapshot := fmt.Sprintf("%#v", op.Pair)
	oldValues := make([][]byte, len(op.Pair.Mutations))
	readable := make([]bool, len(op.Pair.Mutations))
	mustEnvironment(t, s.View(func(reader *Reader) error {
		for i, m := range op.Pair.Mutations {
			// Only malformed DBI/key addresses cannot be read by public Reader.Get.
			if readerDBI(3, m.DBI) != nil || !readerKey(3, m.DBI.Rank, m.Key) {
				continue
			}
			value, _, err := reader.Get(m.DBI, m.Key)
			if err != nil {
				return err
			}
			oldValues[i], readable[i] = bytes.Clone(value), true
		}
		return nil
	}))
	r := tsRun(t, s, o, kind, op)
	tsRefusal(t, r, capacity)
	if s.state != storeOPEN || s.terminal != nil || s.terminalTruth != 0 {
		t.Fatalf("admission lifecycle %s/%v/%d", s.state, s.terminal, s.terminalTruth)
	}
	if snapshot != fmt.Sprintf("%#v", op.Pair) {
		t.Fatal("admission changed caller Pair")
	}
	tsFollowing(t, s, o)
	s = tsReopen(t, s, path)
	for i, m := range op.Pair.Mutations {
		if readable[i] && (m.DBI != tsTarget(900_000).DBI || !bytes.Equal(m.Key, tsTarget(900_000).Key)) {
			tsRead(t, s, m.DBI, m.Key, oldValues[i])
		}
	}
}

func TestTreeStreamEntryRefusalsV1(t *testing.T) {
	for _, name := range []string{"nil Store", "nil UpdateTreeV1 callback", "nil operation account", "closed operation account", "zero account", "closed account-free", "zero account-free"} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := treeNativeStore(t)
			o := reservationOwner(t, 805_306_368)
			var closed *OperationAccount
			mustEnvironment(t, o.WithOperation(TreeOperation, func(a *OperationAccount) error { closed = a; return nil }))
			mustEnvironment(t, o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				calls := 0
				callback := func(*Reader) (TreeOperationV1, error) { calls++; return tsPair(1), nil }
				receiver, supplied, diagnostic := s, a, name
				switch name {
				case "nil Store":
					receiver = nil
				case "nil UpdateTreeV1 callback":
					callback = nil
				case "nil operation account":
					supplied = nil
				case "closed operation account":
					supplied = closed
				case "zero account":
					supplied, diagnostic = &OperationAccount{}, "closed operation account"
				case "closed account-free":
					supplied, diagnostic = closed, "closed operation account"
				case "zero account-free":
					supplied, diagnostic = &OperationAccount{}, "closed operation account"
				}
				if name == "closed operation account" || name == "zero account" {
					s.operations.Lock()
					defer s.operations.Unlock()
				}
				r := tsInvoke(receiver, supplied, callback)
				r.tuple(t, 1, 1, -1)
				treeNativeError(t, r.err, "update", "InvalidInput", 22, diagnostic, nil)
				if calls != 0 || reservationLive(o) != 0 || s.state != storeOPEN {
					t.Fatal("step-1 effect")
				}
				return nil
			}))
			tsFollowing(t, s, o)
		})
	}
}

func TestTreeStreamStoreRefusalsV1(t *testing.T) {
	for _, name := range []string{"busy", "consumed", "closed", "format2", "legacy3"} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := treeNativeStore(t)
			o := reservationOwner(t, 805_306_368)
			if name == "format2" {
				s = newUpdateStore(t)
				t.Cleanup(func() { _ = s.Close() })
			}
			if name == "consumed" {
				_, _ = s.consume(nativeError(operationUpdate, 5))
				s.latchUpdateTerminalTruth()
			}
			if name == "closed" {
				mustEnvironment(t, s.Close())
			}
			calls := 0
			if name == "legacy3" {
				_, _, err := s.Update(func(*Reader) (Batch, error) { calls++; return Batch{}, nil })
				treeNativeError(t, err, "update", "StateMismatch", -30779, "tree store requires typed tree operation", nil)
				if calls != 0 {
					t.Fatal("legacy callback ran")
				}
				return
			}
			mustEnvironment(t, o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				if name == "busy" {
					s.operations.Lock()
				}
				r := tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { calls++; return tsPair(1), nil })
				if name == "busy" {
					s.operations.Unlock()
				}
				r.tuple(t, 1, 1, -1)
				switch name {
				case "busy":
					treeNativeError(t, r.err, "update", "Concurrency", -30778, "store operation in progress", nil)
				case "format2":
					treeNativeError(t, r.err, "update", "StateMismatch", -30779, "typed tree operation requires tree store", nil)
				case "consumed":
					if any(r.err) != any(s.terminal) {
						t.Fatal("terminal identity")
					}
				case "closed":
					treeNativeError(t, r.err, "update", "InvalidInput", 22, "Store is closed", nil)
				}
				if calls != 0 || reservationLive(o) != 0 {
					t.Fatal("step-2 effect")
				}
				return nil
			}))
			if name == "busy" {
				tsFollowing(t, s, o)
			}
			if name == "format2" {
				truth, stage, err := s.Update(func(*Reader) (Batch, error) { return updateLifecycleBatch(), nil })
				if truth != 2 || stage != 3 || err != nil {
					t.Fatalf("legacy format2 recovery %d/%d/%v", truth, stage, err)
				}
			}
		})
	}
}

func TestTreeStreamPrimitiveDomainsV1(t *testing.T) {
	for _, direction := range []int{0, 1, 2, 3, 255} {
		for _, kind := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 255} {
			for _, undo := range []int{0, 1, 2, 3, 4, 5, 6, 7, 255} {
				t.Run(fmt.Sprintf("dir%d/kind%d/undo%d", direction, kind, undo), func(t *testing.T) {
					s, path, o := tsNew(t)
					calls := 0
					marker := errors.New("domain source reached")
					op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { calls++; return marker }))
					p := &op.Primitives[0]
					p.Direction, p.Kind, p.Undo = TreeDirectionV1(direction), TreePrimitiveKindV1(kind), TreeUndoEffectV1(undo)
					if direction == 2 {
						p.Endpoint = TreeEndpointV1{Kind: 1, Height: 4, CumulativeChainwork: [40]byte{39: 19}}
					}
					// Closed table independently enumerates every (Kind, Undo) permission.
					allowed := [][]int{nil, {1, 2}, {1}, {1, 2, 3, 4}, {1}, {3}, {1, 2}, {5}, {5, 6}, {5, 6}}
					validKind := kind >= 1 && kind <= 9
					accepted := validKind && (direction == 1 && kind <= 6 || direction == 2 && kind >= 7)
					if validKind {
						accepted = accepted && slices.Contains(allowed[kind], undo)
					}
					accepted = accepted && kind != 6 && kind != 9 // CURRENT position
					r := tsRun(t, s, o, TreeOperation, op)
					if accepted {
						r.tuple(t, 1, 2, 0)
						if any(r.err) != any(marker) || calls != 1 {
							t.Fatalf("valid table row %v calls%d", r.err, calls)
						}
						tsConsumed(t, s, o, 1, marker)
					} else {
						tsRefusal(t, r, false)
						if calls != 0 {
							t.Fatal("rejected domain reached Source")
						}
						tsFollowing(t, s, o)
					}
					s = tsReopen(t, s, path)
					body := op.Pair.Mutations[0]
					tsRead(t, s, body.DBI, body.Key, nil)
					for _, m := range tsEntry(t).Pair.Mutations {
						tsRead(t, s, m.DBI, m.Key, m.Literal)
					}
				})
			}
		}
	}
}

func TestTreeStreamPrimitiveRefusalsV1(t *testing.T) {
	rows := []struct {
		name string
		edit func(*TreeOperationV1)
	}{
		{"nil-source", func(o *TreeOperationV1) { o.Primitives[0].Source = nil }},
		{"nonlag-at-one", func(o *TreeOperationV1) { o.Primitives = append(o.Primitives, o.Primitives[0]) }},
		{"forward-pregenesis", func(o *TreeOperationV1) { o.Primitives[0].Endpoint = TreeEndpointV1{} }},
		{"forward-height", func(o *TreeOperationV1) { o.Primitives[0].Endpoint.Height++ }},
		{"forward-hash", func(o *TreeOperationV1) { o.Primitives[0].Endpoint.BlockHash[0]++ }},
		{"zero-work", func(o *TreeOperationV1) { o.Primitives[0].Endpoint.CumulativeChainwork = [40]byte{} }},
		{"endpoint-kind", func(o *TreeOperationV1) { o.Primitives[0].Endpoint.Kind = 2 }},
		{"inverse-height0-applied", func(o *TreeOperationV1) { p := &o.Primitives[0]; p.Direction, p.Kind, p.Undo, p.Height = 2, 7, 5, 0 }},
		{"inverse-height5-applied5", func(o *TreeOperationV1) { p := &o.Primitives[0]; p.Direction, p.Kind, p.Undo = 2, 7, 5 }},
		{"pregenesis-height", func(o *TreeOperationV1) {
			p := &o.Primitives[0]
			p.Direction, p.Kind, p.Undo, p.Height = 2, 7, 5, 0
			p.Endpoint = TreeEndpointV1{Height: 1}
		}},
		{"pregenesis-hash", func(o *TreeOperationV1) {
			p := &o.Primitives[0]
			p.Direction, p.Kind, p.Undo, p.Height = 2, 7, 5, 0
			p.Endpoint = TreeEndpointV1{BlockHash: [32]byte{1}}
		}},
		{"pregenesis-work", func(o *TreeOperationV1) {
			p := &o.Primitives[0]
			p.Direction, p.Kind, p.Undo, p.Height = 2, 7, 5, 0
			p.Endpoint = TreeEndpointV1{CumulativeChainwork: [40]byte{39: 1}}
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			calls := 0
			tsRejected(t, TreeOperation, func(t *testing.T) TreeOperationV1 {
				op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { calls++; return nil }))
				row.edit(&op)
				return op
			}, false)
			if calls != 0 {
				t.Fatal("structural refusal called Source")
			}
		})
	}
	for _, kind := range []OperationKind{LaneOperation, TreeOperation} {
		t.Run(fmt.Sprintf("kind%d-empty", kind), func(t *testing.T) {
			tsRejected(t, kind, func(*testing.T) TreeOperationV1 { return TreeOperationV1{} }, false)
		})
		t.Run(fmt.Sprintf("kind%d-consult-only", kind), func(t *testing.T) {
			tsRejected(t, kind, func(*testing.T) TreeOperationV1 {
				return TreeOperationV1{Pair: TreePairV1{Consulted: []ConsultedRow{{DBI: TreeSchemaV1DBIs()[0], Key: []byte{3}}}}}
			}, false)
		})
	}
	t.Run("generation-zero", func(t *testing.T) {
		s, path, o := tsNew(t)
		tsRoots(t, s, o, 1)
		calls := 0
		op := tsOperation(t, tsSource(func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
			calls++
			return sink.BeginV1(TreeBlockV1{TxCount: 1})
		}))
		op.Primitives[0].Generation = 0
		r := tsRun(t, s, o, TreeOperation, op)
		tsRefusal(t, r, false)
		if calls != 0 || s.state != storeOPEN || s.terminal != nil || s.terminalTruth != 0 {
			t.Fatal("generation-zero admission effects")
		}
		mustEnvironment(t, s.View(func(*Reader) error { return nil }))
		body := op.Pair.Mutations[0]
		tsRead(t, s, body.DBI, body.Key, nil)
		op.Primitives[0].Generation = 1
		r = tsRun(t, s, o, TreeOperation, op)
		r.tuple(t, 2, 3, -1)
		mustEnvironment(t, r.err)
		if calls != 1 {
			t.Fatalf("generation-one Source calls%d, want1", calls)
		}
		s = tsReopen(t, s, path)
		tsRead(t, s, body.DBI, body.Key, body.Literal)
		tsRead(t, s, TreeSchemaV1DBIs()[0], tsRootKey(1), tsRootBytes(t, op.Primitives[0].Endpoint))
	})
	tsRejected(t, LaneOperation, func(t *testing.T) TreeOperationV1 {
		return tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { t.Fatal("Lane primitive Source"); return nil }))
	}, false)
}

func tsRootBytes(t *testing.T, endpoint TreeEndpointV1) []byte {
	t.Helper()
	b := testTreeOldBinding(nil, endpoint)
	b.DatabaseID = [32]byte{7}
	encoded, err := b.Encode()
	mustEnvironment(t, err)
	return encoded
}

func tsRootKey(g uint64) []byte { return binary.BigEndian.AppendUint64([]byte{0x11}, g) }

func tsRoots(t *testing.T, s *Store, o *OperationReservationOwner, generations ...uint64) {
	t.Helper()
	for _, g := range generations {
		op := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[0], Key: tsRootKey(g), AfterKind: 2, Literal: tsRootBytes(t, TreeEndpointV1{})}}}}
		r := tsRun(t, s, o, TreeOperation, op)
		r.tuple(t, 2, 3, -1)
		mustEnvironment(t, r.err)
	}
}

func TestTreeStreamEndpointAndLagDomainsV1(t *testing.T) {
	for _, inverseHeight := range []int{-1, 0, 5} {
		t.Run(fmt.Sprint(inverseHeight), func(t *testing.T) {
			s, path, o := tsNew(t)
			calls, marker := 0, errors.New("endpoint accepted")
			op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { calls++; return marker }))
			if inverseHeight >= 0 {
				p := &op.Primitives[0]
				p.Direction, p.Kind, p.Undo, p.Height = 2, 7, 5, uint64(inverseHeight)
				p.Endpoint = TreeEndpointV1{}
				if inverseHeight != 0 {
					p.Endpoint = TreeEndpointV1{Kind: 1, Height: uint64(inverseHeight - 1), CumulativeChainwork: [40]byte{39: 99}}
				}
			}
			r := tsRun(t, s, o, TreeOperation, op)
			r.tuple(t, 1, 2, 0)
			if any(r.err) != any(marker) || calls != 1 {
				t.Fatalf("endpoint source %v/%d", r.err, calls)
			}
			tsConsumed(t, s, o, 1, marker)
			s = tsReopen(t, s, path)
			body := op.Pair.Mutations[0]
			tsRead(t, s, body.DBI, body.Key, nil)
			for _, m := range tsEntry(t).Pair.Mutations {
				tsRead(t, s, m.DBI, m.Key, m.Literal)
			}
		})
	}
	var lagRows []struct{ kind, undo, direction byte }
	for _, kind := range []byte{6, 9} {
		for _, undo := range []byte{0, 1, 2, 3, 4, 5, 6, 7, 255} {
			direction := byte(1)
			if kind == 9 {
				direction = 2
			}
			lagRows = append(lagRows, struct{ kind, undo, direction byte }{kind, undo, direction})
		}
	}
	for _, row := range lagRows {
		t.Run(fmt.Sprintf("lag%d-%d", row.kind, row.undo), func(t *testing.T) {
			s, path, o := tsNew(t)
			tsRoots(t, s, o, 1)
			calls, currentCalls, marker := 0, 0, errors.New("LAG reached")
			first := tsSource(func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
				currentCalls++
				return sink.BeginV1(TreeBlockV1{TxCount: 1})
			})
			op := tsOperation(t, first)
			currentBody := op.Pair.Mutations[0]
			lag := op.Primitives[0]
			lag.Direction, lag.Kind, lag.Undo = TreeDirectionV1(row.direction), TreePrimitiveKindV1(row.kind), TreeUndoEffectV1(row.undo)
			lag.Source = tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { calls++; return marker })
			if row.direction == 2 {
				lag.Block[0] ^= 1
				lag.Endpoint.Height--
			}
			// A LAG's body must be in OLD; write it in a preceding pair-only call.
			body := op.Pair.Mutations[0]
			body.Key = lag.Block[:]
			if row.direction == 2 {
				seedCurrent := tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: op.Pair})
				mustEnvironment(t, seedCurrent.err)
			}
			if row.direction == 2 {
				body.Literal = append([]byte(nil), body.Literal...)
				body.Literal[140] ^= 1
				lag.Block = sha3.Sum256(body.Literal[:148])
				body.Key = lag.Block[:]
			}
			seed := tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{body}}})
			mustEnvironment(t, seed.err)
			// CURRENT reuses the stored body and has no Pair target.
			op.Pair = TreePairV1{}
			op.Primitives = append(op.Primitives, lag)
			r := tsRun(t, s, o, TreeOperation, op)
			accepted := row.kind == 6 && (row.undo == 1 || row.undo == 2) || row.kind == 9 && (row.undo == 5 || row.undo == 6)
			if accepted {
				r.tuple(t, 1, 2, 1)
				if any(r.err) != any(marker) || calls != 1 || currentCalls != 1 {
					t.Fatalf("LAG accepted %v calls%d/%d", r.err, calls, currentCalls)
				}
				tsConsumed(t, s, o, 1, marker)
			} else {
				tsRefusal(t, r, false)
				if calls != 0 || currentCalls != 0 {
					t.Fatal("LAG undo refusal reached Source")
				}
				tsFollowing(t, s, o)
			}
			s = tsReopen(t, s, path)
			tsRead(t, s, TreeSchemaV1DBIs()[0], tsRootKey(1), tsRootBytes(t, TreeEndpointV1{}))
			tsRead(t, s, TreeSchemaV1DBIs()[5], tdManifestKey(op.Primitives[0].Block), nil)
			tsRead(t, s, currentBody.DBI, currentBody.Key, currentBody.Literal)
			tsRead(t, s, body.DBI, body.Key, body.Literal)
			for _, m := range tsEntry(t).Pair.Mutations {
				tsRead(t, s, m.DBI, m.Key, m.Literal)
			}
		})
	}
}

func TestTreeStreamPairShapesV1(t *testing.T) {
	rows := []struct {
		name string
		edit func(*Mutation)
	}{
		{"after-zero", func(m *Mutation) { m.AfterKind = 0 }},
		{"after-unknown", func(m *Mutation) { m.AfterKind = 255 }},
		{"literal-nil", func(m *Mutation) { m.Literal = nil }},
		{"literal-empty-row", func(m *Mutation) { m.Literal = []byte{} }},
		{"literal-refdbi", func(m *Mutation) { m.RefDBI = TreeSchemaV1DBIs()[1] }},
		{"literal-refkey-empty", func(m *Mutation) { m.RefKey = []byte{} }},
		{"literal-refkey", func(m *Mutation) { m.RefKey = []byte{1} }},
		{"absent-not-present", func(m *Mutation) { m.AfterKind, m.Literal = 1, nil }},
		{"absent-literal-empty", func(m *Mutation) { m.AfterKind, m.BeforePresent, m.Literal = 1, true, []byte{} }},
		{"absent-literal", func(m *Mutation) { m.AfterKind, m.BeforePresent = 1, true }},
		{"absent-refdbi", func(m *Mutation) {
			m.AfterKind, m.BeforePresent, m.Literal, m.RefDBI = 1, true, nil, TreeSchemaV1DBIs()[1]
		}},
		{"absent-refkey-empty", func(m *Mutation) { m.AfterKind, m.BeforePresent, m.Literal, m.RefKey = 1, true, nil, []byte{} }},
		{"absent-refkey", func(m *Mutation) { m.AfterKind, m.BeforePresent, m.Literal, m.RefKey = 1, true, nil, []byte{1} }},
		{"key-nil", func(m *Mutation) { m.Key = nil }},
		{"key-empty", func(m *Mutation) { m.Key = []byte{} }},
		{"dbi-name", func(m *Mutation) { m.DBI.Name = "invented" }},
		{"dbi-unknown", func(m *Mutation) { m.DBI.Rank = 255 }},
		{"row-invalid", func(m *Mutation) { m.Literal = make([]byte, 103) }},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			tsRejected(t, TreeOperation, func(*testing.T) TreeOperationV1 { op := tsPair(42); row.edit(&op.Pair.Mutations[0]); return op }, false)
		})
	}
	for _, rank := range []uint8{3, 4, 5} {
		t.Run(fmt.Sprintf("immutable-literal-rank%d", rank), func(t *testing.T) {
			tsRejected(t, TreeOperation, func(t *testing.T) TreeOperationV1 {
				_, m := tsPrimitive(t, nil)
				m.DBI = TreeSchemaV1DBIs()[rank]
				m.BeforePresent = true
				if rank == 3 {
					m.Literal = m.Literal[:148]
				}
				if rank == 5 {
					m.Key = tdEntryKey(tdTxid(0xee), tdTxid(0x10), 1, 0, 0)
					m.Literal = tdFormed(tdFrame(1, 0, nil), 0, 0)
				}
				return TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{m}}}
			}, false)
		})
	}
	for _, mode := range []string{"mutation-order", "mutation-duplicate", "consulted-order", "consulted-duplicate", "consulted-key", "consulted-dbi", "mutation-rank8", "consulted-rank8"} {
		t.Run(mode, func(t *testing.T) {
			tsRejected(t, TreeOperation, func(*testing.T) TreeOperationV1 {
				op := tsPair(1)
				row := tsTarget(2)
				second := tsTarget(3)
				switch mode {
				case "mutation-order":
					op.Pair.Mutations = []Mutation{second, row}
				case "mutation-duplicate":
					op.Pair.Mutations = []Mutation{row, row}
				case "consulted-order":
					op.Pair.Consulted = []ConsultedRow{{row.DBI, second.Key}, {row.DBI, row.Key}}
				case "consulted-duplicate":
					op.Pair.Consulted = []ConsultedRow{{row.DBI, row.Key}, {row.DBI, row.Key}}
				case "consulted-key":
					op.Pair.Consulted = []ConsultedRow{{row.DBI, nil}}
				case "consulted-dbi":
					op.Pair.Consulted = []ConsultedRow{{DBI{Name: "bad", Rank: 6}, row.Key}}
				case "mutation-rank8":
					m := Mutation{DBI: TreeSchemaV1DBIs()[8], Key: testTreeNodeKey(1, 288, testKA), AfterKind: 2, Literal: make([]byte, 32)}
					op.Pair.Mutations = []Mutation{m}
				case "consulted-rank8":
					op.Pair.Consulted = []ConsultedRow{{TreeSchemaV1DBIs()[8], testTreeNodeKey(1, 288, testKA)}}
				}
				return op
			}, false)
		})
	}
}

func TestTreeStreamMetaRowsV1(t *testing.T) {
	for _, key := range [][]byte{{0}, {1}, {3}} {
		for _, after := range []AfterKind{1, 2} {
			t.Run(fmt.Sprintf("immutable-%x-%d", key, after), func(t *testing.T) {
				s, path, o := tsNew(t)
				var original []byte
				mustEnvironment(t, s.View(func(r *Reader) error { original, _, _ = r.Get(TreeSchemaV1DBIs()[0], key); return nil }))
				m := Mutation{DBI: TreeSchemaV1DBIs()[0], Key: bytes.Clone(key), BeforePresent: true, AfterKind: after}
				if after == 2 {
					m.Literal = bytes.Repeat([]byte{9}, 32)
					if len(key) == 1 && (key[0] == 0 || key[0] == 1) {
						m.Literal = bytes.Clone(original)
					}
				}
				r := tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{m}}})
				tsRefusal(t, r, false)
				tsFollowing(t, s, o)
				tsRead(t, tsReopen(t, s, path), m.DBI, key, original)
			})
		}
	}
	t.Run("key2-delete", func(t *testing.T) {
		tsRejected(t, TreeOperation, func(*testing.T) TreeOperationV1 {
			return TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[0], Key: []byte{2}, BeforePresent: true, AfterKind: 1}}}}
		}, false)
	})
	for _, tag := range []byte{0x10, 0x11} {
		t.Run(fmt.Sprintf("mutable-%x", tag), func(t *testing.T) {
			s, path, o := tsNew(t)
			suffix := uint64(7)
			if tag == 0x10 {
				suffix = 5
			}
			key := binary.BigEndian.AppendUint64([]byte{tag}, suffix)
			value := make([]byte, 16)
			if tag == 0x11 {
				value = tsRootBytes(t, TreeEndpointV1{})
			}
			m := Mutation{DBI: TreeSchemaV1DBIs()[0], Key: key, AfterKind: 2, Literal: value}
			r := tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{m}}})
			r.tuple(t, 2, 3, -1)
			mustEnvironment(t, r.err)
			s = tsReopen(t, s, path)
			tsRead(t, s, m.DBI, key, value)
			m.BeforePresent = true
			r = tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{m}}})
			r.tuple(t, 2, 3, -1)
			mustEnvironment(t, r.err)
			m.BeforePresent, m.AfterKind, m.Literal = true, 1, nil
			r = tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{m}}})
			r.tuple(t, 2, 3, -1)
			mustEnvironment(t, r.err)
			tsRead(t, tsReopen(t, s, path), m.DBI, key, nil)
		})
	}
	for _, key := range [][]byte{{0}, {1}, {2}, {3}, binary.BigEndian.AppendUint64([]byte{0x10}, 5), tsRootKey(7), append([]byte{0x12}, make([]byte, 32)...)} {
		t.Run(fmt.Sprintf("consult-%x", key), func(t *testing.T) {
			s, _, o := tsNew(t)
			op := tsPair(44)
			op.Pair.Consulted = []ConsultedRow{{TreeSchemaV1DBIs()[0], key}}
			r := tsRun(t, s, o, TreeOperation, op)
			r.tuple(t, 2, 3, -1)
			mustEnvironment(t, r.err)
		})
	}
}

func tsMany(n int) []Mutation {
	rows := make([]Mutation, n)
	for i := range rows {
		rows[i] = tsTarget(uint64(i + 1))
	}
	return rows
}

func tsConsulted(n int) []ConsultedRow {
	rows := make([]ConsultedRow, n)
	for i := range rows {
		m := tsTarget(uint64(i + 100_000))
		rows[i] = ConsultedRow{m.DBI, m.Key}
	}
	return rows
}

func TestTreeStreamPairCapsAndOrderV1(t *testing.T) {
	rows := []struct {
		name     string
		build    func() TreeOperationV1
		capacity bool
	}{
		{"R9-mutations-16385", func() TreeOperationV1 { return TreeOperationV1{Pair: TreePairV1{Mutations: tsMany(16385)}} }, true},
		{"R9-consulted-16385", func() TreeOperationV1 { op := tsPair(1); op.Pair.Consulted = tsConsulted(16385); return op }, true},
		{"R9-cap-before-later-shape", func() TreeOperationV1 {
			rows := tsMany(16386)
			rows[16385].AfterKind = 0
			return TreeOperationV1{Pair: TreePairV1{Mutations: rows}}
		}, true},
		{"R9-shape-before-cap", func() TreeOperationV1 {
			rows := tsMany(16385)
			rows[99].AfterKind = 0
			return TreeOperationV1{Pair: TreePairV1{Mutations: rows}}
		}, false},
		{"R9-M-before-C-cap", func() TreeOperationV1 {
			rows := tsMany(2)
			rows[1].AfterKind = 0
			return TreeOperationV1{Pair: TreePairV1{Mutations: rows, Consulted: tsConsulted(16385)}}
		}, false},
		{"R9-M-cap-before-C-shape", func() TreeOperationV1 {
			return TreeOperationV1{Pair: TreePairV1{Mutations: tsMany(16385), Consulted: []ConsultedRow{{DBI: TreeSchemaV1DBIs()[6]}}}}
		}, true},
		{"R10-G1", func() TreeOperationV1 { return TreeOperationV1{Pair: TreePairV1{Consulted: tsConsulted(16385)}} }, false},
		{"R10-C-rank8-at-cap", func() TreeOperationV1 {
			op := tsPair(1)
			op.Pair.Consulted = append(tsConsulted(16384), ConsultedRow{TreeSchemaV1DBIs()[8], testTreeNodeKey(1, 288, testKA)})
			return op
		}, false},
		{"R10-C-rank8-after-cap", func() TreeOperationV1 {
			op := tsPair(1)
			op.Pair.Consulted = append(tsConsulted(16385), ConsultedRow{TreeSchemaV1DBIs()[8], testTreeNodeKey(1, 288, testKA)})
			return op
		}, true},
		{"R10-C-shape-at-cap", func() TreeOperationV1 {
			op := tsPair(1)
			op.Pair.Consulted = append(tsConsulted(16384), ConsultedRow{DBI: TreeSchemaV1DBIs()[7], Key: []byte{1}})
			return op
		}, false},
		{"R11-overlap-after-cap", func() TreeOperationV1 {
			rows := tsConsulted(16385)
			m := tsTarget(100_000)
			return TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{m}, Consulted: rows}}
		}, true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			tsRejected(t, TreeOperation, func(*testing.T) TreeOperationV1 { return row.build() }, row.capacity)
		})
	}
	for _, consulted := range []bool{false, true} {
		t.Run(fmt.Sprintf("R9-16384-accepted-%v", consulted), func(t *testing.T) {
			s, path, o := tsNew(t)
			op := TreeOperationV1{Pair: TreePairV1{Mutations: tsMany(16384)}}
			if consulted {
				op = tsPair(1)
				op.Pair.Consulted = tsConsulted(16384)
			}
			r := tsRun(t, s, o, TreeOperation, op)
			r.tuple(t, 2, 3, -1)
			mustEnvironment(t, r.err)
			s = tsReopen(t, s, path)
			for _, m := range []Mutation{op.Pair.Mutations[0], op.Pair.Mutations[len(op.Pair.Mutations)-1]} {
				tsRead(t, s, m.DBI, m.Key, m.Literal)
			}
		})
	}
	for _, variant := range []string{"kind", "source", "height", "generation-later", "lane"} {
		t.Run("R10-P-before-cap-"+variant, func(t *testing.T) {
			kind := TreeOperation
			if variant == "lane" {
				kind = LaneOperation
			}
			tsRejected(t, kind, func(t *testing.T) TreeOperationV1 {
				op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { t.Fatal("late phase P"); return nil }))
				op.Pair.Mutations = tsMany(16385)
				switch variant {
				case "kind":
					op.Primitives[0].Kind = 0
				case "source":
					op.Primitives[0].Source = nil
				case "height":
					op.Primitives[0].Endpoint.Height++
				case "generation-later":
					p := op.Primitives[0]
					p.Kind, p.Generation = 6, 0
					op.Primitives = append(op.Primitives, p)
				}
				return op
			}, false)
		})
	}
}

func TestTreeStreamCrossRelationsV1(t *testing.T) {
	for _, relation := range []string{"own-target", "own-consulted", "root-target", "root-consulted", "disjoint"} {
		for _, over := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/over%v", relation, over), func(t *testing.T) {
				tsRejected(t, TreeOperation, func(t *testing.T) TreeOperationV1 {
					op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { t.Fatal("cross refusal Source"); return nil }))
					p := op.Primitives[0]
					rows := tsMany(1)
					if over {
						rows = tsMany(16385)
					}
					op.Pair.Mutations = rows
					own := Mutation{DBI: TreeSchemaV1DBIs()[5], Key: tdManifestKey(p.Block), AfterKind: 2, Literal: tdManifest(p.Height, [16]byte{}, 1, 0)}
					root := Mutation{DBI: TreeSchemaV1DBIs()[0], Key: tsRootKey(1), AfterKind: 2, Literal: tsRootBytes(t, p.Endpoint)}
					switch relation {
					case "own-target":
						op.Pair.Mutations = append([]Mutation{own}, rows[:len(rows)-1]...)
					case "root-target":
						op.Pair.Mutations = append([]Mutation{root}, rows[:len(rows)-1]...)
					case "own-consulted":
						op.Pair.Consulted = []ConsultedRow{{own.DBI, own.Key}}
					case "root-consulted":
						op.Pair.Consulted = []ConsultedRow{{root.DBI, root.Key}}
					case "disjoint":
						op.Pair.Consulted = []ConsultedRow{{rows[0].DBI, rows[0].Key}}
					}
					return op
				}, over)
			})
		}
	}
	t.Run("R11-pair-only", func(t *testing.T) {
		tsRejected(t, TreeOperation, func(*testing.T) TreeOperationV1 {
			op := tsPair(1)
			m := op.Pair.Mutations[0]
			op.Pair.Consulted = []ConsultedRow{{m.DBI, m.Key}}
			return op
		}, false)
	})
}

func TestTreeStreamReferencesV1(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint(reverse), func(t *testing.T) {
			calls := 0
			tsRejected(t, TreeOperation, func(t *testing.T) TreeOperationV1 {
				op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { calls++; return nil }))
				key := tdUTXOKey(1, tdTxid(0x33), 2)
				undo := tdEntryKey(tdTxid(0xff), tdTxid(0x33), 1, 0, 2)
				m := Mutation{DBI: TreeSchemaV1DBIs()[5], Key: undo, AfterKind: 3, RefDBI: TreeSchemaV1DBIs()[1], RefKey: key}
				if reverse {
					m.DBI, m.Key, m.RefDBI, m.RefKey = m.RefDBI, m.RefKey, m.DBI, m.Key
				}
				op.Pair.Mutations = []Mutation{m}
				return op
			}, false)
			if calls != 0 {
				t.Fatal("Pair reference reached Source")
			}
		})
	}
}

func TestTreeStreamDirectionRelationV1(t *testing.T) {
	for _, variant := range []string{"forward-inverse", "inverse-forward", "over-cap", "same-direction", "distinct-block"} {
		t.Run(variant, func(t *testing.T) {
			s, path, o := tsNew(t)
			calls := 0
			marker := errors.New("direction admitted")
			op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { calls++; return marker }))
			p := op.Primitives[0]
			q := p
			q.Kind = 6
			q.Generation = 2
			third := q
			third.Direction, third.Kind, third.Undo = 2, 9, 6
			third.Endpoint.Height--
			switch variant {
			case "forward-inverse", "over-cap":
				body := op.Pair.Mutations[0]
				seed := tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{body}}})
				mustEnvironment(t, seed.err)
				body.Literal = bytes.Clone(body.Literal)
				body.Literal[140] ^= 0x40
				b := sha3.Sum256(body.Literal[:148])
				body.Key = b[:]
				seed = tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{body}}})
				mustEnvironment(t, seed.err)
				q.Block, q.Endpoint.BlockHash = b, b
				third.Block = b
				op.Primitives = []TreePrimitiveV1{p, q, third}
			case "inverse-forward":
				p.Direction, p.Kind, p.Undo, p.Height = 2, 8, 5, 6
				p.Endpoint.Height = 5
				op.Primitives = []TreePrimitiveV1{p, q}
			case "same-direction":
				p.Kind = 3
				op.Primitives = []TreePrimitiveV1{p, q}
			case "distinct-block":
				third.Block, third.Undo = tdTxid(0xee), 5
				op.Primitives = []TreePrimitiveV1{p, third}
			}
			if variant == "over-cap" {
				op.Pair.Mutations = tsMany(16385)
			}
			if variant == "forward-inverse" || variant == "over-cap" {
				// The Pair body must remain outside every own-family; admission needs no body for p.
				op.Pair.Mutations = tsMany(1)
				if variant == "over-cap" {
					op.Pair.Mutations = tsMany(16385)
				}
			}
			r := tsRun(t, s, o, TreeOperation, op)
			if variant == "same-direction" || variant == "distinct-block" {
				r.tuple(t, 1, 2, 0)
				if any(r.err) != any(marker) || calls != 1 {
					t.Fatalf("accepted relation %v calls%d", r.err, calls)
				}
				tsConsumed(t, s, o, 1, marker)
			} else {
				tsRefusal(t, r, false)
				if calls != 0 || s.state != storeOPEN || s.terminalTruth != 0 {
					t.Fatal("D27 admission effects")
				}
				tsFollowing(t, s, o)
			}
			s = tsReopen(t, s, path)
			for _, m := range op.Pair.Mutations {
				tsRead(t, s, m.DBI, m.Key, nil)
			}
			for _, m := range tsEntry(t).Pair.Mutations {
				tsRead(t, s, m.DBI, m.Key, m.Literal)
			}
		})
	}
}

func TestTreeStreamPairOwnershipAndAccountingV1(t *testing.T) {
	for _, kind := range []OperationKind{LaneOperation, TreeOperation} {
		t.Run(fmt.Sprintf("pair-only-kind%d", kind), func(t *testing.T) {
			s, path, o := tsNew(t)
			op := tsPair(10)
			m := op.Pair.Mutations[0]
			// Exactly PC logical bytes remain. Any engine draw on a pair-only plan
			// would refuse; one fewer PC byte must refuse before native write.
			ceiling := uint64(154_611_183)
			if kind == TreeOperation {
				ceiling = 402_653_184
			}
			for _, short := range []uint64{1, 0} {
				mustEnvironment(t, o.WithOperation(kind, func(a *OperationAccount) error {
					filler := ceiling - uint64(len(m.Key)+len(m.Literal)) + short
					return a.WithReservation(filler, func() error {
						r := tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil })
						if short == 1 {
							r.tuple(t, 1, 1, -1)
							if any(r.err) != any(errOperationReservationCapacity) {
								t.Fatalf("PC refusal identity %v", r.err)
							}
						} else {
							r.tuple(t, 2, 3, -1)
							mustEnvironment(t, r.err)
						}
						if reservationLive(o) != filler {
							t.Fatal("Pair hold not released")
						}
						return nil
					})
				}))
			}
			s = tsReopen(t, s, path)
			tsRead(t, s, m.DBI, m.Key, m.Literal)
			m.AfterKind, m.BeforePresent, m.Literal = 1, true, nil
			r := tsRun(t, s, o, kind, TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{m}}})
			r.tuple(t, 2, 3, -1)
			mustEnvironment(t, r.err)
			tsRead(t, tsReopen(t, s, path), m.DBI, m.Key, nil)
		})
	}
	t.Run("A7-caller-buffers-and-PC", func(t *testing.T) {
		s, path, o := tsNew(t)
		tsRoots(t, s, o, 1)
		var op TreeOperationV1
		originalTarget := tsTarget(10)
		consulted := tsTarget(11)
		var targetIdentity []byte
		var sample uint64
		provider := tsSource(func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
			sample = reservationLive(o)
			for _, m := range op.Pair.Mutations {
				for i := range m.Key {
					m.Key[i] ^= 0xff
				}
				for i := range m.Literal {
					m.Literal[i] ^= 0xff
				}
			}
			for _, row := range op.Pair.Consulted {
				copy(row.Key, targetIdentity)
			}
			return sink.BeginV1(TreeBlockV1{TxCount: 1})
		})
		op = tsOperation(t, provider)
		body := op.Pair.Mutations[0]
		bodyKey, bodyValue := bytes.Clone(body.Key), bytes.Clone(body.Literal)
		op.Pair.Mutations = append(op.Pair.Mutations, originalTarget)
		op.Pair.Consulted = []ConsultedRow{{consulted.DBI, consulted.Key}}
		key, value := bytes.Clone(originalTarget.Key), bytes.Clone(originalTarget.Literal)
		targetIdentity = bytes.Clone(key)
		pc := uint64(len(body.Key) + len(body.Literal) + len(key) + len(value) + len(consulted.Key))
		r := tsRun(t, s, o, TreeOperation, op)
		r.tuple(t, 2, 3, -1)
		mustEnvironment(t, r.err)
		if sample != pc+74_872 {
			t.Fatalf("PC before primitive sample%d want%d", sample, pc+74_872)
		}
		s = tsReopen(t, s, path)
		tsRead(t, s, originalTarget.DBI, key, value)
		tsRead(t, s, body.DBI, bodyKey, bodyValue)
	})
}

func TestTreeStreamCapacityAndClosingV1(t *testing.T) {
	for _, competitor := range []bool{false, true} {
		t.Run(fmt.Sprintf("R4-competitor%v", competitor), func(t *testing.T) {
			s, _, _ := treeNativeStore(t)
			limit := uint64(805_306_367)
			if competitor {
				limit++
			}
			o := reservationOwner(t, limit)
			if competitor {
				reservationFill(t, o, limit)
			}
			calls := 0
			op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { calls++; return nil }))
			r := tsRun(t, s, o, TreeOperation, op)
			r.tuple(t, 1, 1, -1)
			if any(r.err) != any(errOperationReservationCapacity) || !IsOperationReservationCapacity(r.err) || calls != 0 || s.state != storeOPEN {
				t.Fatalf("R4 effects %v calls%d state%s", r.err, calls, s.state)
			}
			mustEnvironment(t, s.View(func(*Reader) error { return nil }))
		})
	}
	t.Run("closed-between-entry-and-hold", func(t *testing.T) {
		s, _, o := tsNew(t)
		ready, closeNow, closed := make(chan *OperationAccount), make(chan struct{}), make(chan struct{})
		go func() {
			defer close(closed)
			_ = o.WithOperation(TreeOperation, func(a *OperationAccount) error { ready <- a; <-closeNow; return nil })
		}()
		a := <-ready
		r := tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { close(closeNow); <-closed; return tsPair(51), nil })
		r.tuple(t, 1, 1, -1)
		if any(r.err) != any(errOperationReservationInput) || reservationLive(o) != 0 || s.state != storeOPEN {
			t.Fatalf("closed at hold %v/%s", r.err, s.state)
		}
		tsFollowing(t, s, o)
	})
}

func TestTreeStreamCallbackLifecycleV1(t *testing.T) {
	for _, mode := range []string{"nil", "error", "wrapped", "typed-nil", "panic", "panic-nil", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			s, path, o := tsNew(t)
			value := new(int)
			marker := errors.New("callback error")
			var kept *Reader
			application := marker
			if mode == "wrapped" {
				application = fmt.Errorf("callback context: %w", marker)
			}
			if mode == "typed-nil" {
				var e *nilPointerError
				application = e
			}
			if mode == "panic-nil" {
				application = nil
			}
			calls, post := 0, false
			run := func() {
				_ = o.WithOperation(TreeOperation, func(a *OperationAccount) error {
					r := tsInvoke(s, a, func(reader *Reader) (TreeOperationV1, error) {
						calls++
						kept = reader
						switch mode {
						case "panic":
							panic(value)
						case "panic-nil":
							panic(application)
						case "goexit":
							runtime.Goexit()
						}
						if mode == "nil" {
							return tsPair(81), nil
						}
						return TreeOperationV1{}, application
					})
					if mode == "nil" {
						r.tuple(t, 2, 3, -1)
						mustEnvironment(t, r.err)
					} else {
						r.tuple(t, 1, 1, -1)
						if any(r.err) != any(application) {
							t.Fatalf("callback identity %v want%v", r.err, application)
						}
					}
					return nil
				})
				post = true
			}
			switch mode {
			case "goexit":
				done := make(chan struct{})
				go func() { defer close(done); run() }()
				<-done
			case "panic", "panic-nil":
				var recovered any
				func() { defer func() { recovered = recover() }(); run() }()
				if mode == "panic" && recovered != value {
					t.Fatalf("panic identity %v", recovered)
				}
				if mode == "panic-nil" {
					if _, ok := recovered.(*runtime.PanicNilError); !ok {
						t.Fatalf("nil panic %T", recovered)
					}
				}
			default:
				run()
			}
			if calls != 1 || kept == nil || kept.usable() || reservationLive(o) != 0 || s.state != storeOPEN || s.terminal != nil {
				t.Fatalf("callback lifecycle calls%d state%s", calls, s.state)
			}
			tsExpiredReader(t, kept)
			if (mode == "goexit" || mode == "panic" || mode == "panic-nil") && post {
				t.Fatal("post-call statement ran")
			}
			tsFollowing(t, s, o)
			s = tsReopen(t, s, path)
			m := tsTarget(81)
			want := []byte(nil)
			if mode == "nil" {
				want = m.Literal
			}
			tsRead(t, s, m.DBI, m.Key, want)
		})
	}
}

func TestTreeStreamUnboundSinkV1(t *testing.T) {
	for _, sink := range []*TreeDeltaSinkV1{nil, {}} {
		for _, err := range []error{sink.BeginV1(TreeBlockV1{TxCount: 1}), sink.EventV1(TreeEventV1{Kind: 2})} {
			treeNativeError(t, err, "update", "InvalidInput", 22, "tree delta sink is not active", nil)
		}
		if sink.WindowV1() != nil {
			t.Fatal("unbound sink lent window")
		}
	}
	s, _, o := tsNew(t)
	tsFollowing(t, s, o)
}

func TestTreeStreamSurfaceV1(t *testing.T) {
	want := []string{"TreePositionV1", "TreeWriterV1", "TreeReadbackV1", "TreeDeltaSinkV1", "TreeOutpointV1", "TreeEventKindV1", "TreeEventSpendV1", "TreeEventCreateV1", "TreeBlockV1", "TreeEventV1", "BeginV1", "EventV1", "WindowV1", "TreeUndoEffectV1", "UndoWriteOrReuseV1", "UndoTransientV1", "UndoCompareV1", "UndoCompareDeleteV1", "UndoSourceRetainV1", "UndoSourceDeleteV1", "TreeDirectionV1", "TreeForwardV1", "TreeInverseV1", "TreePrimitiveKindV1", "TreeKindDirectApplyV1", "TreeKindConnectV1", "TreeKindReplayNextV1", "TreeKindFirstGenesisV1", "TreeKindRestoreOldV1", "TreeKindLagForwardV1", "TreeKindDisconnectV1", "TreeKindRollbackNewV1", "TreeKindLagReverseV1", "TreePairV1", "TreeSourceV1", "TreePrimitiveV1", "TreeOperationV1", "UpdateTreeV1"}
	var got []string
	for _, path := range []string{"tree_stream.go", "tree_stream_cgo.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		mustEnvironment(t, err)
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Name.IsExported() {
					got = append(got, d.Name.Name)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch v := spec.(type) {
					case *ast.TypeSpec:
						if v.Name.IsExported() {
							got = append(got, v.Name.Name)
						}
					case *ast.ValueSpec:
						for _, n := range v.Names {
							if n.IsExported() {
								got = append(got, n.Name)
							}
						}
					}
				}
			}
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("public surface %v want %v", got, want)
	}
	for i, v := range []TreeUndoEffectV1{UndoWriteOrReuseV1, UndoTransientV1, UndoCompareV1, UndoCompareDeleteV1, UndoSourceRetainV1, UndoSourceDeleteV1} {
		if int(v) != i+1 {
			t.Fatalf("Undo encoding %d=%d", i, v)
		}
	}
	for i, v := range []TreePrimitiveKindV1{TreeKindDirectApplyV1, TreeKindConnectV1, TreeKindReplayNextV1, TreeKindFirstGenesisV1, TreeKindRestoreOldV1, TreeKindLagForwardV1, TreeKindDisconnectV1, TreeKindRollbackNewV1, TreeKindLagReverseV1} {
		if int(v) != i+1 {
			t.Fatalf("Kind encoding %d=%d", i, v)
		}
	}
	if TreeForwardV1 != 1 || TreeInverseV1 != 2 || TreeWriterV1 != 1 || TreeReadbackV1 != 2 || TreeEventSpendV1 != 1 || TreeEventCreateV1 != 2 {
		t.Fatal("public identity conversion domain")
	}
	if n := uint64(unsafe.Sizeof(treeDescV1{})); n != 104 || n > 128 {
		t.Fatalf("descriptor size%d", n)
	}
}

func TestTreeStreamPairRankControlsV1(t *testing.T) {
	for _, rank := range []uint8{1, 5, 6} {
		t.Run(fmt.Sprintf("rank%d-literal-present-delete", rank), func(t *testing.T) {
			s, path, o := tsNew(t)
			m := tsTarget(56)
			switch rank {
			case 1:
				m = Mutation{DBI: TreeSchemaV1DBIs()[1], Key: tdUTXOKey(1, tdTxid(0x99), 2), AfterKind: 2, Literal: tdFormed(tdFrame(1, 0, nil), 5, 0)}
			case 5:
				m = Mutation{DBI: TreeSchemaV1DBIs()[5], Key: tdManifestKey(tdTxid(0xee)), AfterKind: 2, Literal: tdManifest(5, [16]byte{}, 1, 0)}
			}
			for _, present := range []bool{false, true} {
				if rank == 5 && present {
					continue
				}
				m.BeforePresent = present
				r := tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{m}}})
				r.tuple(t, 2, 3, -1)
				mustEnvironment(t, r.err)
			}
			s = tsReopen(t, s, path)
			tsRead(t, s, m.DBI, m.Key, m.Literal)
			m.BeforePresent, m.AfterKind, m.Literal = true, 1, nil
			r := tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{m}}})
			r.tuple(t, 2, 3, -1)
			mustEnvironment(t, r.err)
			tsRead(t, tsReopen(t, s, path), m.DBI, m.Key, nil)
		})
	}
	t.Run("canonical-ranks2-7", func(t *testing.T) {
		s, path, o := tsNew(t)
		hash := tdTxid(0x55)
		key := binary.BigEndian.AppendUint64(nil, 1)
		key = binary.BigEndian.AppendUint64(key, 23)
		value := make([]byte, 104)
		copy(value, hash[:])
		ownerKey := binary.BigEndian.AppendUint64(nil, 1)
		ownerKey = append(ownerKey, hash[:]...)
		pair := TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[2], Key: key, AfterKind: 2, Literal: value}, {DBI: TreeSchemaV1DBIs()[7], Key: ownerKey, AfterKind: 2, Literal: binary.BigEndian.AppendUint64(nil, 23)}}}
		for _, present := range []bool{false, true} {
			for i := range pair.Mutations {
				pair.Mutations[i].BeforePresent = present
			}
			r := tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: pair})
			r.tuple(t, 2, 3, -1)
			mustEnvironment(t, r.err)
		}
		s = tsReopen(t, s, path)
		for _, m := range pair.Mutations {
			tsRead(t, s, m.DBI, m.Key, m.Literal)
		}
		for i := range pair.Mutations {
			pair.Mutations[i].BeforePresent, pair.Mutations[i].AfterKind, pair.Mutations[i].Literal = true, 1, nil
		}
		r := tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: pair})
		r.tuple(t, 2, 3, -1)
		mustEnvironment(t, r.err)
		s = tsReopen(t, s, path)
		for _, m := range pair.Mutations {
			tsRead(t, s, m.DBI, m.Key, nil)
		}
	})
}

func TestTreeStreamAdmissionBeforeAccountV1(t *testing.T) {
	s, _, o := tsNew(t)
	calls := 0
	op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { calls++; return nil }))
	op.Primitives[0].Generation = 0
	mustEnvironment(t, o.WithOperation(TreeOperation, func(a *OperationAccount) error {
		return a.WithReservation(402_653_184, func() error {
			r := tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil })
			tsRefusal(t, r, false)
			if reservationLive(o) != 402_653_184 || calls != 0 || s.state != storeOPEN {
				t.Fatal("admission attempted plan-copy charge")
			}
			return nil
		})
	}))
	tsFollowing(t, s, o)
}

func TestTreeStreamUndoLiteralPayloadsV1(t *testing.T) {
	for _, entry := range []bool{false, true} {
		for _, present := range []bool{false, true} {
			if !entry && !present {
				continue
			} // accepted manifest control is PairRankControls
			t.Run(fmt.Sprintf("entry%v-present%v", entry, present), func(t *testing.T) {
				tsRejected(t, TreeOperation, func(*testing.T) TreeOperationV1 {
					key, value := tdManifestKey(tdTxid(0xfd)), tdManifest(5, [16]byte{}, 1, 0)
					if entry {
						key = tdEntryKey(tdTxid(0xfd), tdTxid(1), 1, 0, 0)
						value = tdFormed(tdFrame(1, 0, nil), 0, 0)
					}
					return TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[5], Key: key, BeforePresent: present, AfterKind: 2, Literal: value}}}}
				}, false)
			})
		}
	}
}

func TestTreeStreamMetaKeyShapesV1(t *testing.T) {
	keys := [][]byte{nil, {}, {4}, {0x10}, make([]byte, 9), binary.BigEndian.AppendUint64([]byte{0x10}, 0), tsRootKey(0), append([]byte{0x12}, make([]byte, 31)...), append([]byte{0x13}, make([]byte, 32)...)}
	for i, key := range keys {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			tsRejected(t, TreeOperation, func(*testing.T) TreeOperationV1 {
				op := tsPair(91)
				op.Pair.Consulted = []ConsultedRow{{TreeSchemaV1DBIs()[0], key}}
				return op
			}, false)
		})
	}
	t.Run("key2-literal-present", func(t *testing.T) {
		s, _, o := tsNew(t)
		m := tsEntry(t).Pair.Mutations[0]
		m.BeforePresent = true
		r := tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{m}}})
		r.tuple(t, 2, 3, -1)
		mustEnvironment(t, r.err)
	})
}
