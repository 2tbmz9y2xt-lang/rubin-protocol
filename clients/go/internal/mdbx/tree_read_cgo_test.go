//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"testing"
	"unsafe"
)

// One real Reader entry is the primary root/origin boundary. The independent
// tree fixture builder supplies expected digests and canonical node bytes.
func trRequestV1(t *testing.T, height uint64) (TreeRootReadV1, []TreeEventV1, []byte) {
	t.Helper()
	frame := tdFrame(37, 0, []byte{8, 9})
	body := append(initial148NativeLiteral(t), frame...)
	block := sha3.Sum256(body[:148])
	events := []TreeEventV1{{Kind: 2, Outpoint: TreeOutpointV1{Txid: tdTxid(37)}, FrameOffset: 148, FrameLength: uint32(len(frame))}}
	meta := TreeBlockV1{TxCount: 1, EventCount: 1}
	coverage := &TreeSourceCoverageV1{DatabaseID: [32]byte{7}, Generation: 1, Block: block, Height: height, HeaderBytes: 148, BodyKind: 1, CurrentBody: body, BlockMeta: meta}
	p := TreePrimitiveV1{Direction: 1, Kind: 1, Generation: 1, Block: block, Height: height, Undo: 2, Endpoint: TreeEndpointV1{Kind: 1, Height: height, BlockHash: block, CumulativeChainwork: [40]byte{39: 37}}, Coverage: coverage}
	p.Source = tsSource(func(pos TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
		if pos != 1 {
			return fmt.Errorf("unexpected source position %d", pos)
		}
		if err := sink.BeginV1(meta); err != nil {
			return err
		}
		for _, event := range events {
			if err := sink.EventV1(event); err != nil {
				return err
			}
		}
		return nil
	})
	parent := TreeEndpointV1{}
	if height != 0 {
		parent = TreeEndpointV1{Kind: 1, Height: height-1, BlockHash: tdTxid(5), CumulativeChainwork: [40]byte{39: 37}}
	}
	return TreeRootReadV1{Primitive: p, Parent: parent}, events, frame
}

func trReadV1(t *testing.T, s *Store, o *OperationReservationOwner, request TreeRootReadV1, use func(*Reader, *OperationAccount, [32]byte, error)) {
	t.Helper()
	mustEnvironment(t, o.WithOperation(TreeOperation, func(account *OperationAccount) error {
		_ = s.View(func(reader *Reader) error {
			root, err := reader.DeriveTreeRootV1(account, request)
			use(reader, account, root, err)
			return err
		})
		return nil
	}))
	if reservationLive(o) != 0 {
		t.Fatal("root method leaked its reservation")
	}
}

func trSeedV1(t *testing.T, s *Store, o *OperationReservationOwner, rank uint8, key, value []byte) {
	t.Helper()
	var present bool
	mustEnvironment(t, s.View(func(reader *Reader) error {
		_, found, err := reader.Get(TreeSchemaV1DBIs()[rank], key)
		present = found
		return err
	}))
	op := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[rank], Key: key, BeforePresent: present, AfterKind: 2, Literal: value}}}}
	result := tsRun(t, s, o, TreeOperation, op)
	result.tuple(t, 2, 3, -1)
	mustEnvironment(t, result.err)
}

func trEntryV1(key, value []byte) testTreeEntry {
	return testTreeEntry{k: [36]byte(key[8:]), v: value}
}

func trBindingV1(t *testing.T, generation uint64, endpoint TreeEndpointV1, entries ...testTreeEntry) []byte {
	return trBindingIDV1(t, [32]byte{7}, generation, endpoint, entries...)
}

func trBindingIDV1(t *testing.T, database [32]byte, generation uint64, endpoint TreeEndpointV1, entries ...testTreeEntry) []byte {
	t.Helper()
	var top *testTreeNode
	if len(entries) != 0 {
		root := testTreeBuild(generation, entries, map[string][]byte{})
		top = &root
	}
	binding := testTreeOldBinding(top, endpoint)
	binding.DatabaseID = database
	encoded, err := binding.Encode()
	mustEnvironment(t, err)
	return encoded
}

func trWantRootV1(t *testing.T, frame []byte, height uint64) [32]byte {
	t.Helper()
	key := tdUTXOKey(1, tdTxid(37), 0)
	value := tdFormed(frame, height, 1)
	root := testTreeBuild(1, []testTreeEntry{trEntryV1(key, value)}, map[string][]byte{})
	return root.digest
}

func TestTreeRootReadV1(t *testing.T) {
	t.Run("fresh-point-only-root", func(t *testing.T) {
		s, _, o := tsNew(t)
		request, _, frame := trRequestV1(t, 6)
		trSeedV1(t, s, o, 0, tsRootKey(1), trBindingV1(t, 1, request.Parent))
		// Malformed counters must be unconsumed by D. Covered UpdateTree keeps
		// its independent counter checks in TestTreeCoveredCountersV1.
		trSeedV1(t, s, o, 0, tsCounterKey(1), tsCounterLiteral(1, 0))
		before, err := s.Inspect()
		mustEnvironment(t, err)
		for range 2 {
			trReadV1(t, s, o, request, func(reader *Reader, _ *OperationAccount, root [32]byte, err error) {
				mustEnvironment(t, err)
				if root != trWantRootV1(t, frame, 6) || !reader.usable() {
					t.Fatalf("fresh root %x or Reader usability", root)
				}
			})
		}
		after, err := s.Inspect()
		mustEnvironment(t, err)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("noncommitting root changed persistent image")
		}
	})
	t.Run("original-input-bytes", trOriginalV1)
	t.Run("closed-input-domain", trInvalidV1)
	t.Run("single-reservation-and-width", trBoundV1)
	t.Run("trusted-unchanged-subtree", trTrustedV1)
}

func trTrustedV1(t *testing.T) {
	s, _, o := tsNew(t)
	request, _, frame := trRequestV1(t, 6)
	oldKey := tdUTXOKey(1, tdTxid(9), 0)
	oldValue := tdFormed(tdFrame(9, 0, nil), 5, 0)
	old := trEntryV1(oldKey, oldValue)
	trSeedV1(t, s, o, 0, tsRootKey(1), trBindingV1(t, 1, request.Parent, old))
	// The unused OLD subtree is trusted through its binding hash. Its missing
	// leaf row is not an extra spent-leaf authentication requirement.
	want := testTreeBuild(1, []testTreeEntry{old, trEntryV1(tdUTXOKey(1, tdTxid(37), 0), tdFormed(frame, 6, 1))}, map[string][]byte{})
	trReadV1(t, s, o, request, func(_ *Reader, _ *OperationAccount, root [32]byte, err error) {
		mustEnvironment(t, err)
		if root != want.digest { t.Fatalf("trusted unchanged subtree root %x want%x", root, want.digest) }
	})
}

func trOriginalV1(t *testing.T) {
	for _, variant := range []string{"equal", "missing-R", "absent-D", "value", "type", "data", "height", "coinbase"} {
		t.Run(variant, func(t *testing.T) {
			s, _, o := tsNew(t)
			request, _, _ := trRequestV1(t, 6)
			op := TreeOutpointV1{Txid: tdTxid(9), Vout: 3}
			key := tdUTXOKey(1, op.Txid, op.Vout)
			value := tdFormed(tdFrame(7, 0, []byte{4}), 5, 1)
			request.Inputs = []TreeResolvedInputV1{{Outpoint: op, Value: bytes.Clone(value)}}
			meta := TreeBlockV1{TxCount: 2, EventCount: 1}
			request.Primitive.Coverage.BlockMeta = meta
			request.Primitive.Source = tsSource(func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
				if err := sink.BeginV1(meta); err != nil {
					return err
				}
				return sink.EventV1(TreeEventV1{Kind: 1, Outpoint: op, TxIndex: 1})
			})
			if variant == "absent-D" {
				trSeedV1(t, s, o, 0, tsRootKey(1), trBindingV1(t, 1, request.Parent, trEntryV1(key, value)))
			} else {
				seed, _, _ := trRequestV1(t, 5)
				frame := tdFrame(7, 0, []byte{4})
				seed.Primitive.Coverage.CurrentBody = append(initial148NativeLiteral(t), frame...)
				seed.Primitive.Source = tsSource(func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
					if err := sink.BeginV1(TreeBlockV1{TxCount: 1, EventCount: 1}); err != nil { return err }
					return sink.EventV1(TreeEventV1{Kind: 2, Outpoint: op, FrameOffset: 148, FrameLength: uint32(len(frame))})
				})
				trPopulateV1(t, s, o, seed)
				request.Parent = seed.Primitive.Endpoint
			}
			switch variant {
			case "missing-R":
				request.Inputs = nil
			case "value":
				request.Inputs[0].Value[0]++
			case "type":
				request.Inputs[0].Value[8]++
			case "data":
				request.Inputs[0].Value[11]++
			case "height":
				request.Inputs[0].Value[len(value)-9]++
			case "coinbase":
				request.Inputs[0].Value[len(value)-1] = 0
			}
			trReadV1(t, s, o, request, func(reader *Reader, _ *OperationAccount, root [32]byte, err error) {
				if variant == "equal" {
					mustEnvironment(t, err)
					if root != sha3.Sum256([]byte("RUBIN_UTXO_TREE_V1\x00")) {
						t.Fatal("last original SPEND did not produce empty root")
					}
					return
				}
				var engine *EngineError
				if root != ([32]byte{}) || !errors.As(err, &engine) || engine.Class != EngineIntegrity || reader.usable() || reader.failure != err {
					t.Fatalf("original-input refusal root%x err%v active%v", root, err, reader.usable())
				}
			})
		})
	}
}

func trInvalidV1(t *testing.T) {
	variants := []string{"generation", "database", "coverage-generation", "coverage-block", "coverage-height", "header", "body-kind", "body-empty", "direction", "kind", "undo", "endpoint", "parent-height", "parent-kind", "parent-work", "meta-tx", "inputs-duplicate", "inputs-width", "inputs-count", "nil-source"}
	for _, variant := range variants {
		t.Run(variant, func(t *testing.T) {
			s, _, o := tsNew(t)
			request, _, _ := trRequestV1(t, 6)
			p, c := &request.Primitive, request.Primitive.Coverage
			switch variant {
			case "generation": p.Generation = 0
			case "database": c.DatabaseID[0]++
			case "coverage-generation": c.Generation++
			case "coverage-block": c.Block[0]++
			case "coverage-height": c.Height++
			case "header": c.HeaderBytes = 116
			case "body-kind": c.BodyKind = 2
			case "body-empty": c.CurrentBody = nil
			case "direction": p.Direction = 2
			case "kind": p.Kind = 2
			case "undo": p.Undo = 1
			case "endpoint": p.Endpoint.BlockHash[0]++
			case "parent-height": request.Parent.Height++
			case "parent-kind": request.Parent.Kind = 0
			case "parent-work": request.Parent.CumulativeChainwork = [40]byte{}
			case "meta-tx": c.BlockMeta.TxCount = 0
			case "inputs-duplicate":
				c.BlockMeta.EventCount = 2
				v := tdFormed(tdFrame(1, 0, nil), 1, 0)
				request.Inputs = []TreeResolvedInputV1{{Value: v}, {Value: v}}
			case "inputs-width": request.Inputs = []TreeResolvedInputV1{{Value: []byte{1}}}
			case "inputs-count": request.Inputs = make([]TreeResolvedInputV1, 2)
			case "nil-source": p.Source = nil
			}
			p.Source = trCountingSourceV1(p.Source, t)
			trReadV1(t, s, o, request, func(reader *Reader, _ *OperationAccount, root [32]byte, err error) {
				var engine *EngineError
				if !errors.As(err, &engine) || engine.Class != EngineInvalidInput || root != ([32]byte{}) || !reader.usable() || reservationLive(o) != 0 {
					t.Fatalf("invalid domain result root%x err%v active%v", root, err, reader.usable())
				}
			})
		})
	}
}

func trCountingSourceV1(source TreeSourceV1, t *testing.T) TreeSourceV1 {
	if source == nil {
		return nil
	}
	return tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error {
		t.Fatal("invalid request reached Source")
		return nil
	})
}

func trBoundV1(t *testing.T) {
	if unsafe.Sizeof(TreeResolvedInputV1{}) > 64 {
		t.Fatal("input descriptor exceeds captured allowance")
	}
	s, _, o := tsNew(t)
	request, _, _ := trRequestV1(t, 0)
	base := request.Primitive.Source
	request.Primitive.Source = tsSource(func(pos TreePositionV1, reader *Reader, sink *TreeDeltaSinkV1) error {
		if reservationLive(o) != 288504 {
			t.Fatalf("D reservation = %d, want 288504", reservationLive(o))
		}
		return base.TreeDeltaV1(pos, reader, sink)
	})
	trReadV1(t, s, o, request, func(_ *Reader, _ *OperationAccount, _ [32]byte, err error) { mustEnvironment(t, err) })
	mustEnvironment(t, o.WithOperation(TreeOperation, func(account *OperationAccount) error {
		return s.View(func(reader *Reader) error {
			return account.WithReservation(266480, func() error {
				request.Primitive.Source = tsSource(func(pos TreePositionV1, sourceReader *Reader, sink *TreeDeltaSinkV1) error {
					if reservationLive(o) != 554984 { t.Fatalf("simultaneous R+D backing %d, want 554984", reservationLive(o)) }
					return base.TreeDeltaV1(pos, sourceReader, sink)
				})
				_, err := reader.DeriveTreeRootV1(account, request)
				mustEnvironment(t, err)
				if reservationLive(o) != 266480 { t.Fatal("D released R or retained native backing past last use") }
				return nil
			})
		})
	}))
	for _, kind := range []OperationKind{LaneOperation, TreeOperation} {
		mustEnvironment(t, o.WithOperation(kind, func(account *OperationAccount) error {
			var old *Reader
			mustEnvironment(t, s.View(func(reader *Reader) error { old = reader; return nil }))
			root, err := old.DeriveTreeRootV1(account, request)
			if err == nil || root != ([32]byte{}) || reservationLive(o) != 0 {
				t.Fatal("expired Reader admitted/reserved")
			}
			return nil
		}))
	}
	trCapacityV1(t, s, o)
}

func trCapacityV1(t *testing.T, s *Store, o *OperationReservationOwner) {
	for _, extra := range []uint64{0, 1} {
		mustEnvironment(t, o.WithOperation(TreeOperation, func(account *OperationAccount) error {
			return s.View(func(reader *Reader) error {
				request, _, _ := trRequestV1(t, 0)
				return account.WithReservation(402653184-288504+extra, func() error {
					if extra == 1 { request.Primitive.Source = trCountingSourceV1(request.Primitive.Source, t) }
					root, err := reader.DeriveTreeRootV1(account, request)
					if extra == 0 { mustEnvironment(t, err) }
					if extra == 1 && (!sameError(err, errOperationReservationCapacity) || root != ([32]byte{}) || !reader.usable()) { t.Fatalf("D capacity-before-source %x/%v", root, err) }
					return nil
				})
			})
		}))
	}
	mustEnvironment(t, o.WithOperation(LaneOperation, func(account *OperationAccount) error {
		return s.View(func(reader *Reader) error {
			request, _, _ := trRequestV1(t, 0)
			request.Primitive.Source = trCountingSourceV1(request.Primitive.Source, t)
			root, err := reader.DeriveTreeRootV1(account, request)
			var engine *EngineError
			if root != ([32]byte{}) || !errors.As(err, &engine) || engine.Class != EngineInvalidInput || !reader.usable() { t.Fatal("wrong account kind admitted or changed Reader") }
			return nil
		})
	}))
	var closed *OperationAccount
	mustEnvironment(t, o.WithOperation(TreeOperation, func(account *OperationAccount) error { closed = account; return nil }))
	for _, account := range []*OperationAccount{nil, {}, closed} {
		mustEnvironment(t, s.View(func(reader *Reader) error {
			request, _, _ := trRequestV1(t, 0)
			request.Primitive.Source = trCountingSourceV1(request.Primitive.Source, t)
			root, err := reader.DeriveTreeRootV1(account, request)
			var engine *EngineError
			if root != ([32]byte{}) || !errors.As(err, &engine) || engine.Class != EngineInvalidInput || !reader.usable() || reservationLive(o) != 0 { t.Fatal("nil/zero/closed account reached source/reservation") }
			return nil
		}))
	}
}

func TestTreeRootReadGenesisV1(t *testing.T) {
	s, _, o := tsNew(t)
	request, _, frame := trRequestV1(t, 0)
	// Populate all parent domains through the actual mutating owner. Their
	// nonempty height-six image conflicts with the empty genesis parent.
	stored, _, _ := trRequestV1(t, 6)
	trPopulateV1(t, s, o, stored)
	trReadV1(t, s, o, request, func(reader *Reader, _ *OperationAccount, root [32]byte, err error) {
		mustEnvironment(t, err)
		if root != trWantRootV1(t, frame, 0) || root == sha3.Sum256([]byte("RUBIN_UTXO_TREE_V1\x00")) || !reader.usable() {
			t.Fatalf("genesis CREATE result %x", root)
		}
	})
}

func trPopulateV1(t *testing.T, s *Store, o *OperationReservationOwner, request TreeRootReadV1) {
	t.Helper()
	trSeedV1(t, s, o, 0, tsRootKey(1), trBindingV1(t, 1, request.Parent))
	trSeedV1(t, s, o, 0, tsCounterKey(1), make([]byte, 16))
	primitive := request.Primitive
	op := TreeOperationV1{Primitives: []TreePrimitiveV1{primitive}, Pair: TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[4], Key: primitive.Block[:], AfterKind: 2, Literal: primitive.Coverage.CurrentBody}}}}
	result := tsRun(t, s, o, TreeOperation, op)
	result.tuple(t, 2, 3, -1)
	mustEnvironment(t, result.err)
}

func TestTreeRootReadOutcomeV1(t *testing.T) {
	for _, variant := range []string{"binding-absent", "binding-endpoint", "binding-database"} {
		t.Run(variant, func(t *testing.T) {
			s, _, o := tsNew(t)
			request, _, _ := trRequestV1(t, 6)
			kind := TreeObservationAbsentV1
			if variant == "binding-endpoint" || variant == "binding-database" {
				id, endpoint := [32]byte{7}, request.Parent
				if variant == "binding-endpoint" { endpoint.BlockHash[0]++ }
				if variant == "binding-database" { id[0]++ }
				trSeedV1(t, s, o, 0, tsRootKey(1), trBindingIDV1(t, id, 1, endpoint))
				kind = TreeObservationIdentityMismatchV1
			}
			trReadV1(t, s, o, request, func(reader *Reader, account *OperationAccount, root [32]byte, err error) {
				var engine *EngineError
				if root != ([32]byte{}) || !errors.As(err, &engine) || engine.Class != EngineIntegrity || engine.TreeObservation == nil {
					t.Fatalf("localized refusal %x/%v", root, err)
				}
				want := TreeObservationV1{DatabaseID: [32]byte{7}, Generation: 1, Block: request.Primitive.Block, Height: 6, Primitive: 0, Position: 1, Rank: 0, KeyLength: 9, Kind: kind, OriginalImage: true, OriginalReference: true}
				copy(want.Key[:], tsRootKey(1))
				if *engine.TreeObservation != want || reader.usable() || reader.failure != err {
					t.Fatalf("observation %+v want %+v; active%v", engine.TreeObservation, want, reader.usable())
				}
				_, next := reader.DeriveTreeRootV1(account, request)
				if next == nil || reader.failure != err { t.Fatal("failed Reader reused") }
			})
		})
	}
	for _, delivery := range []string{"error", "panic", "goexit"} {
		t.Run(delivery, func(t *testing.T) { trUnwindV1(t, delivery) })
	}
}

func trUnwindV1(t *testing.T, delivery string) {
	s, _, o := tsNew(t)
	request, _, _ := trRequestV1(t, 0)
	primary, panicValue := errors.New("source application error"), new(int)
	var kept *TreeDeltaSinkV1
	var recovered any
	request.Primitive.Source = tsSource(func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
		kept = sink
		mustEnvironment(t, sink.BeginV1(request.Primitive.Coverage.BlockMeta))
		switch delivery {
		case "panic": panic(panicValue)
		case "goexit": runtime.Goexit()
		}
		return primary
	})
	ranAfter := false
	run := func() {
		defer func() { recovered = recover() }()
		trReadV1(t, s, o, request, func(reader *Reader, _ *OperationAccount, root [32]byte, err error) {
			if err != primary || root != ([32]byte{}) || !reader.usable() { t.Fatal("source primary changed") }
		})
		ranAfter = true
	}
	if delivery == "goexit" {
		done := make(chan struct{})
		go func() { defer close(done); run() }()
		<-done
	} else { run() }
	if delivery == "panic" && recovered != panicValue { t.Fatal("original panic changed") }
	if delivery != "error" && ranAfter { t.Fatal("unwind continued") }
	if reservationLive(o) != 0 || kept.WindowV1() != nil || kept.BeginV1(TreeBlockV1{}) == nil { t.Fatal("unwind leaked backing/sink") }
}
