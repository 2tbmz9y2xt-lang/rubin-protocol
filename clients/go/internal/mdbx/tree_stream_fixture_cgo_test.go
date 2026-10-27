//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"testing"
)

// The native fixture primary selector invokes this reached-owner check. It
// models the account window after public precheck, without a scheduler seam.
func tsClosedBeforeHoldV1(t *testing.T) {
	for _, mode := range []string{"application", "malformed", "valid", "attached", "proof-shape", "slot-invalid", "slot-cap", "panic", "panic-nil", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			s, _, o := tsNew(t)
			var closed *OperationAccount
			mustEnvironment(t, o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				closed = a
				return nil
			}))
			marker, value := errors.New("pre-hold application"), new(int)
			calls, returned := 0, false
			var result tsResult
			var recovered any
			run := func() {
				defer func() { recovered = recover() }()
				var unwind treeUnwindV1
				defer func() { unwind.resumeV1() }()
				s.operations.Lock()
				defer s.operations.Unlock()
				result.truth, result.stage, result.index, unwind, result.err = s.treeEntryLockedV1(closed, func(r *Reader) (TreeOperationV1, error) {
					calls++
					got, present, err := r.Get(TreeSchemaV1DBIs()[0], []byte{2})
					if err != nil || !present || !bytes.Equal(got, tsEntry(t).Pair.Mutations[0].Literal) {
						t.Fatal("closed pre-hold fallback lost real ORIGINAL OLD")
					}
					token, failure, err := r.PrepareEntryInventoryV1(closed, tsPair(51).Pair)
					if token.scope != nil || failure != nil || reservationLive(o) != 0 {
						t.Fatal("closed pre-hold fallback acquired ENTRY backing")
					}
					eiInput(t, err)
					switch mode {
					case "application":
						return TreeOperationV1{}, marker
					case "malformed":
						return TreeOperationV1{}, nil
					case "panic":
						panic(value)
					case "panic-nil":
						panic(treeCallNilPanicValue)
					case "goexit":
						runtime.Goexit()
					}
					if mode == "slot-cap" {
						slotCalls, slotProofs := 0, 0
						return tsSlotShape(t, &slotCalls, &slotProofs, nil, 16_383), nil
					}
					op := tsPair(51)
					if mode == "attached" {
						op.Pair.EntryInventory = &EntryInventoryV1{}
					}
					if mode == "slot-invalid" {
						op.HeaderSlot = &TreeHeaderSlotV1{}
					}
					if mode == "proof-shape" {
						op.Proof = func(*TreeDeltaReportV1) error { t.Fatal("Proof called at admission"); return nil }
					}
					return op, nil
				})
				returned = unwind.kind == 0
			}
			if mode == "goexit" {
				done := make(chan struct{})
				go func() {
					defer close(done)
					run()
				}()
				eiAwait(t, done)
			} else {
				run()
			}
			switch mode {
			case "application":
				if any(result.err) != any(marker) {
					t.Fatal("saved hold refusal replaced application")
				}
			case "malformed":
				tsRefusal(t, result, false)
			case "valid":
				if any(result.err) != any(errOperationReservationInput) {
					t.Fatal("saved original hold singleton replaced")
				}
			case "attached":
				eiInput(t, result.err)
			case "proof-shape":
				// The Proof admission row wins over the saved closed-account refusal.
				tsRefusal(t, result, false)
			case "slot-invalid":
				// The slot admission row wins over the saved closed-account refusal.
				tsRefusal(t, result, false)
			case "slot-cap":
				// The slot cap row also wins over the saved closed-account refusal.
				tsRefusal(t, result, true)
			case "panic":
				if returned || recovered != value {
					t.Fatal("fallback changed panic")
				}
			case "panic-nil":
				if returned || recovered == nil {
					t.Fatal("fallback changed panic(nil)")
				}
			case "goexit":
				if returned || recovered != nil {
					t.Fatal("fallback changed Goexit")
				}
			}
			if calls != 1 || s.state != storeOPEN || reservationLive(o) != 0 {
				t.Fatal("fallback callback/cleanup count")
			}
			tsRead(t, s, TreeSchemaV1DBIs()[6], tsTarget(51).Key, nil)
			tsFollowing(t, s, o)
		})
	}
}

// tsfProvider streams public value records; its hooks exercise only the
// explicitly listed provider refusals, accounting observations and unwinds.
type tsfProvider struct {
	block  TreeBlockV1
	events []TreeEventV1
	calls  [3]int
	before func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error
	after  func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error
	custom func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error
	reader *Reader
	sink   *TreeDeltaSinkV1
}

func (p *tsfProvider) TreeDeltaV1(pos TreePositionV1, r *Reader, sink *TreeDeltaSinkV1) error {
	p.calls[pos]++
	p.reader, p.sink = r, sink
	if p.custom != nil {
		return p.custom(pos, r, sink)
	}
	if p.before != nil {
		if err := p.before(pos, r, sink); err != nil {
			return err
		}
	}
	if err := sink.BeginV1(p.block); err != nil {
		return err
	}
	for _, event := range p.events {
		if err := sink.EventV1(event); err != nil {
			return err
		}
		// Changing the caller's local record must not alter the copied record.
		event.Outpoint.Txid = [32]byte{}
		event.FrameLength = 0
	}
	if p.after != nil {
		return p.after(pos, r, sink)
	}
	return nil
}

type tsfScene struct {
	s    *Store
	path string
	o    *OperationReservationOwner
	op   TreeOperationV1
	p    []*tsfProvider
}

func tsfCreate(txid [32]byte, offset uint64, n uint32) TreeEventV1 {
	return TreeEventV1{Kind: 2, Outpoint: TreeOutpointV1{Txid: txid}, FrameOffset: offset, FrameLength: n}
}

func tsfNew(t *testing.T) *tsfScene {
	t.Helper()
	s, path, o := tsNew(t)
	tsRoots(t, s, o, 1, 2)
	p := []*tsfProvider{
		{block: TreeBlockV1{TxCount: 1, EventCount: 1}, events: []TreeEventV1{tsfCreate(tdTxid(0x10), 148, 11)}},
		{block: TreeBlockV1{TxCount: 1, EventCount: 1}, events: []TreeEventV1{tsfCreate(tdTxid(0x20), 0, 12)}},
		{block: TreeBlockV1{TxCount: 2, EventCount: 2}, events: []TreeEventV1{tsfCreate(tdTxid(0x30), 0, 11), {Kind: 1, Outpoint: TreeOutpointV1{Txid: tdTxid(0x20)}, TxIndex: 1}}},
	}
	op := tsOperation(t, p[0])
	current := &op.Primitives[0]
	current.Height, current.Endpoint.Height = 10, 10
	op.Pair.Mutations[0].Literal = append(op.Pair.Mutations[0].Literal[:148], tdFrame(100, 0, nil)...)
	for i := 1; i < 3; i++ {
		block := tdTxid(byte(0xb0 + i))
		height := uint64(4 + i)
		prim := TreePrimitiveV1{Direction: 1, Kind: 6, Generation: 2, Block: block, Height: height, Source: p[i], Undo: 1, Endpoint: tcEndpoint(height, block)}
		op.Primitives = append(op.Primitives, prim)
		frame := tdFrame(200, 0, []byte{1})
		if i == 2 {
			frame = tdFrame(300, 0, nil)
		}
		treeNativeSeed(t, s, 4, block[:], frame)
	}
	return &tsfScene{s: s, path: path, o: o, op: op, p: p}
}

func tsfCover(t *testing.T, s *tsfScene) {
	t.Helper()
	for _, g := range []uint64{1, 2} {
		treeNativeSeed(t, s.s, 0, tsCounterKey(g), make([]byte, 16))
	}
	for j := 1; j < 3; j++ {
		frame := tdFrame(200, 0, []byte{1})
		if j == 2 {
			frame = tdFrame(300, 0, nil)
		}
		body := append(initial148NativeLiteral(t), frame...)
		body[140] ^= byte(0x80 + j)
		block := sha3.Sum256(body[:148])
		s.op.Primitives[j].Block, s.op.Primitives[j].Endpoint.BlockHash = block, block
		for i := range s.p[j].events {
			if s.p[j].events[i].Kind == 2 {
				s.p[j].events[i].FrameOffset += 148
			}
		}
		treeNativeSeed(t, s.s, 3, block[:], body[:148])
		treeNativeSeed(t, s.s, 4, block[:], body)
	}
	tsCover(&s.op, s.p[0].block, s.p[1].block, s.p[2].block)
}

// The LAG starts from two real original leaves. Modifying the first requires
// both its original branch and leaf; CURRENT remains a separate healthy tree.
func tsfOriginalLag(t *testing.T, s *tsfScene) ([][]byte, [][]byte) {
	t.Helper()
	a, b := tdUTXOKey(2, tdTxid(0x20), 0), tdUTXOKey(2, tdTxid(0x90), 0)
	va, vb := tdFormed(tdFrame(7, 0, []byte{1}), 4, 1), tdFormed(tdFrame(8, 0, nil), 4, 1)
	rows := map[string][]byte{}
	entries := []testTreeEntry{tcEntry(a, va), tcEntry(b, vb)}
	_ = testTreeBuild(2, entries, rows)
	keys, values := [][]byte{a, b}, [][]byte{va, vb}
	for name, value := range rows {
		key := testTreeRowKey(name)
		treeNativeSeed(t, s.s, 8, key, value)
		keys, values = append(keys, key), append(values, value)
	}
	treeNativeSeed(t, s.s, 1, a, va)
	treeNativeSeed(t, s.s, 1, b, vb)
	treeNativeSeed(t, s.s, 0, tsCounterKey(2), tsCounterLiteral(113, 2))
	treeNativeSeed(t, s.s, 0, tsRootKey(2), tcBinding(t, 2, tcEndpoint(4, tdTxid(0xa0)), entries...))
	s.p[1].block = TreeBlockV1{TxCount: 2, EventCount: 2}
	s.p[1].events = []TreeEventV1{tsSpend(0x20, 0, 1, 0), tsCreate(0x20, 0, 1, 148, 12)}
	tsCover(&s.op, s.p[0].block, s.p[1].block, s.p[2].block)
	return keys, values
}

func tsfUnusedArm(t *testing.T, s *tsfScene, run func()) SelectedDamageEvidence {
	t.Helper()
	evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamagePutEIO, 0, tsCounterKey(1), run)
	if err == nil || err.Error() != "selected damage fixture site was not reached exactly as armed" {
		t.Fatalf("unused keyed arm diagnostic %v evidence%+v", err, evidence)
	}
	if evidence.Faults != 0 || evidence.Deletes != 0 || evidence.Commits != 0 {
		t.Fatalf("prewrite native attempts %+v", evidence)
	}
	return evidence
}

func TestTreeCoveredPreflightFixtureV1(t *testing.T) {
	t.Run("begin-exact-readback", tsfCoveredBeginReadback)
	t.Run("late-original", tsfCoveredLate)
	t.Run("healthy-keyed-arm", func(t *testing.T) {
		s := tsfNew(t)
		tsfCover(t, s)
		_, _ = tsfOriginalLag(t, s)
		var r tsResult
		evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamagePutEIO, 0, tsCounterKey(1), func() { r = s.run(t) })
		mustEnvironment(t, err)
		r.tuple(t, 1, 2, -1)
		treeNativeError(t, r.err, "update", "IO", 5, "error 5", nil)
		if evidence.Faults != 1 || evidence.Deletes != 1 || evidence.Commits != 0 || s.p[2].calls != [3]int{0, 1, 0} {
			t.Fatalf("healthy first target arm %+v calls%v", evidence, s.p[2].calls)
		}
		tsConsumed(t, s.s, s.o, 1, r.err)
	})
	t.Run("first-source", tsfCoveredFirstSource)
	t.Run("repeated-original-presence", tsfCoveredRepeated)
	t.Run("physical-order", tsfCoveredOrder)
	t.Run("truth", tsfCoveredTruth)
	t.Run("prewrite-reserve", tsfCoveredReserve)
	t.Run("target-consulted", tsfCoveredOverlap)
	t.Run("empty-root-digest", tsfCoveredEmptyRoot)
	t.Run("postflush-domain", tsfCoveredFinalDomain)
	t.Run("observation-cleanup", tsfCoveredObservationCleanup)
	t.Run("transient-before", tsfCoveredTransient)
	t.Run("projected-capacity", tsfCoveredCapacity)
	t.Run("source-lifecycle", tsfCoveredLifecycle)
}

func tsfCoveredLate(t *testing.T) {
	for _, artifact := range []string{"counter", "root", "leaf", "branch"} {
		for _, damage := range []string{"absent", "malformed", "identity", "digest"} {
			if (artifact == "counter" || artifact == "root") && damage == "digest" {
				continue
			}
			if artifact != "root" && artifact != "branch" && damage == "identity" {
				continue
			}
			t.Run(artifact+"/"+damage, func(t *testing.T) {
				s := tsfNew(t)
				tsfCover(t, s)
				keys, values := tsfOriginalLag(t, s)
				rank, key, value, wantKind := tsfDamageTarget(t, s, artifact, damage, keys, values)
				if damage == "absent" {
					mustEnvironment(t, fixtureDeletePrefixRow(s.s, TreeSchemaV1DBIs()[rank], key))
				} else {
					treeNativeSeed(t, s.s, rank, key, value)
				}
				var r tsResult
				evidence := tsfUnusedArm(t, s, func() { r = s.run(t) })
				r.tuple(t, 1, 1, 1)
				var engine *EngineError
				if !errors.As(r.err, &engine) || any(engine) != any(r.err) || engine.Class != "Integrity" {
					t.Fatalf("late original error identity%v", r.err)
				}
				var cause error
				if damage == "malformed" || artifact == "branch" && damage == "identity" {
					cause = errSchema
				}
				treeNativeIntegrity(t, r.err, "update", cause)
				tsObservation(t, engine.TreeObservation, s.op.Primitives[1], rank, key, wantKind, 1, 1, true, true)
				if s.p[0].calls != [3]int{0, 1, 0} || s.p[1].calls != [3]int{0, 1, 0} || s.p[2].calls != [3]int{} || evidence.BeginWrite != 1 {
					t.Fatalf("late planning calls %v/%v/%v evidence%+v", s.p[0].calls, s.p[1].calls, s.p[2].calls, evidence)
				}
				tsConsumed(t, s.s, s.o, 1, r.err)
				s.s = tsReopen(t, s.s, s.path)
				tsRead(t, s.s, TreeSchemaV1DBIs()[0], tsCounterKey(1), make([]byte, 16))
				tsRead(t, s.s, TreeSchemaV1DBIs()[0], tsRootKey(1), tsRootBytes(t, TreeEndpointV1{}))
				tsRead(t, s.s, TreeSchemaV1DBIs()[4], s.op.Primitives[0].Block[:], nil)
				tsRead(t, s.s, TreeSchemaV1DBIs()[1], tdUTXOKey(1, tdTxid(0x10), 0), nil)
				tsRead(t, s.s, TreeSchemaV1DBIs()[5], tdManifestKey(s.op.Primitives[0].Block), nil)
			})
		}
	}
}

func tsfDamageTarget(t *testing.T, s *tsfScene, artifact, damage string, keys, values [][]byte) (uint8, []byte, []byte, TreeObservationKindV1) {
	t.Helper()
	rank, key, value := uint8(0), tsCounterKey(2), tsCounterLiteral(113, 2)
	if artifact == "root" {
		key = tsRootKey(2)
		mustEnvironment(t, s.s.View(func(r *Reader) error { var err error; value, _, err = r.Get(TreeSchemaV1DBIs()[0], key); return err }))
	}
	if artifact == "leaf" || artifact == "branch" {
		rank = 8
		for i := 2; i < len(keys); i++ {
			if artifact == "branch" && len(values[i]) == 140 || artifact == "leaf" && len(values[i]) == 32 && bytes.Equal(keys[i][8:44], tdUTXOKey(2, tdTxid(0x20), 0)[8:]) {
				key, value = keys[i], values[i]
			}
		}
	}
	kind := TreeObservationKindV1(1)
	if damage == "malformed" {
		value, kind = []byte{1}, 2
	}
	if damage == "digest" {
		value, kind = bytes.Clone(value), 4
		value[len(value)-1] ^= 1
	}
	if damage == "identity" {
		value, kind = bytes.Clone(value), 3
		if rank == 8 {
			value[0] ^= 0x80
		} else {
			value[1] ^= 1
		}
	}
	return rank, bytes.Clone(key), value, kind
}

func tsfCoveredEmptyRoot(t *testing.T) {
	for _, damaged := range []bool{false, true} {
		t.Run(fmt.Sprintf("damaged%v", damaged), func(t *testing.T) {
			s := tsfNew(t)
			tsfCover(t, s)
			binding, err := DecodeRootBindingV1(tsRootBytes(t, tcEndpoint(4, tdTxid(0xee))))
			mustEnvironment(t, err)
			if damaged {
				binding.RootDigest[0] ^= 1
			}
			value, err := binding.Encode()
			mustEnvironment(t, err)
			treeNativeSeed(t, s.s, 0, tsRootKey(2), value)
			var r tsResult
			if damaged {
				tsfUnusedArm(t, s, func() { r = s.run(t) })
				r.tuple(t, 1, 1, 1)
				treeNativeIntegrity(t, r.err, "update", nil)
				tsObservation(t, r.err.(*EngineError).TreeObservation, s.op.Primitives[1], 0, tsRootKey(2), 4, 1, 1, true, true)
				tsConsumed(t, s.s, s.o, 1, r.err)
			} else {
				r = s.run(t)
				r.tuple(t, 2, 3, -1)
				mustEnvironment(t, r.err)
			}
		})
	}
}

func tsObservation(t *testing.T, got *TreeObservationV1, p TreePrimitiveV1, rank uint8, key []byte, kind TreeObservationKindV1, j int, position TreePositionV1, image, reference bool) {
	t.Helper()
	want := TreeObservationV1{DatabaseID: [32]byte{7}, Generation: p.Generation, Block: p.Block, Height: p.Height, Rank: rank, KeyLength: uint8(len(key)), Kind: kind, Primitive: j, Position: position, OriginalImage: image, OriginalReference: reference}
	copy(want.Key[:], key)
	if got == nil || *got != want {
		t.Fatalf("observation got%+v want%+v", got, want)
	}
}

func tsfCoveredFirstSource(t *testing.T) {
	for _, mode := range []string{"direct", "wrapped", "caused", "typed-nil"} {
		t.Run(mode, func(t *testing.T) {
			s := tsfNew(t)
			tsfCover(t, s)
			marker := errors.New("CURRENT source")
			var primary error = marker
			switch mode {
			case "wrapped":
				primary = fmt.Errorf("source context: %w", marker)
			case "caused":
				primary = &EngineError{Class: "IO", Operation: "get", Code: 5, Diagnostic: "source", Cause: marker}
			case "typed-nil":
				var typed *nilPointerError
				primary = typed
			}
			s.p[0].before = func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { return primary }
			var r tsResult
			tsfUnusedArm(t, s, func() { r = s.run(t) })
			r.tuple(t, 1, 1, 0)
			if any(r.err) != any(primary) || s.p[0].calls != [3]int{0, 1, 0} || s.p[1].calls != [3]int{} || s.p[2].calls != [3]int{} {
				t.Fatalf("CURRENT precedence %v calls%v/%v/%v", r.err, s.p[0].calls, s.p[1].calls, s.p[2].calls)
			}
			tsConsumed(t, s.s, s.o, 1, r.err)
			s.durable(t, false)
		})
	}
}

func tsfCoveredRepeated(t *testing.T) {
	for _, original := range []bool{false, true} {
		t.Run(fmt.Sprintf("original-present%v", original), func(t *testing.T) {
			s := tsfNew(t)
			tsfCover(t, s)
			if original {
				_, _ = tsfOriginalLag(t, s)
				s.p[1].block, s.p[1].events = TreeBlockV1{TxCount: 2, EventCount: 1}, []TreeEventV1{tsSpend(0x20, 0, 1, 0)}
				s.p[2].block, s.p[2].events = TreeBlockV1{TxCount: 1, EventCount: 1}, []TreeEventV1{tsCreate(0x20, 0, 0, 148, 11)}
				tsCover(&s.op, s.p[0].block, s.p[1].block, s.p[2].block)
			}
			r := s.run(t)
			r.tuple(t, 2, 3, -1)
			mustEnvironment(t, r.err)
			for _, p := range s.p {
				if p.calls != [3]int{0, 1, 0} {
					t.Fatalf("repeated Source calls%v", p.calls)
				}
			}
			if !original {
				s.durable(t, true)
				tsRead(t, s.s, TreeSchemaV1DBIs()[0], tsCounterKey(2), mustCodecHex(t, "00000000000000380000000000000001"))
				return
			}
			s.s = tsReopen(t, s.s, s.path)
			key, value := tdUTXOKey(2, tdTxid(0x20), 0), tdFormed(tdFrame(300, 0, nil), 6, 1)
			other, unchanged := tdUTXOKey(2, tdTxid(0x90), 0), tdFormed(tdFrame(8, 0, nil), 4, 1)
			tsRead(t, s.s, TreeSchemaV1DBIs()[1], key, value)
			tsRead(t, s.s, TreeSchemaV1DBIs()[1], other, unchanged)
			tsRead(t, s.s, TreeSchemaV1DBIs()[0], tsCounterKey(2), mustCodecHex(t, "00000000000000700000000000000002"))
			tsRead(t, s.s, TreeSchemaV1DBIs()[0], tsRootKey(2), tcBinding(t, 2, s.op.Primitives[2].Endpoint, tcEntry(key, value), tcEntry(other, unchanged)))
		})
	}
}

// One existing UTXO and its leaf and branch change. Counter/UTXO delete first;
// the new undo/body are absent. The leaf delete is exactly the third delete and
// the generation root delete exactly the fifth, independent of production order.
func tsfCoveredOrder(t *testing.T) {
	for _, target := range []string{"leaf", "root", "pair-root"} {
		t.Run(target, func(t *testing.T) {
			s := tsfNew(t)
			tsfCover(t, s)
			keys, values := tsfOriginalLag(t, s)
			// The replacement becomes CURRENT with a genuinely new Pair body.
			s.op.Primitives = []TreePrimitiveV1{s.op.Primitives[1]}
			s.op.Primitives[0].Kind = 2
			body := append(initial148NativeLiteral(t), tdFrame(200, 0, []byte{1})...)
			body[140] ^= 0x74
			block := sha3.Sum256(body[:148])
			s.op.Primitives[0].Block, s.op.Primitives[0].Endpoint.BlockHash = block, block
			s.p[1].events[1].FrameOffset = 148
			s.op.Pair = TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[4], Key: block[:], AfterKind: 2, Literal: body}}}
			tsCover(&s.op, s.p[1].block)
			rank, key, wantDeletes := uint8(0), tsRootKey(2), uint64(5)
			if target == "leaf" {
				rank, wantDeletes = 8, 3
				for i := 2; i < len(keys); i++ {
					if len(values[i]) == 32 && bytes.Equal(keys[i][8:44], tdUTXOKey(2, tdTxid(0x20), 0)[8:]) {
						key = keys[i]
					}
				}
			}
			if target == "pair-root" {
				tsRoots(t, s.s, s.o, 3)
				m := Mutation{DBI: TreeSchemaV1DBIs()[0], Key: tsRootKey(3), BeforePresent: true, AfterKind: 2, Literal: tsRootBytes(t, TreeEndpointV1{})}
				s.op.Pair.Mutations = append([]Mutation{m}, s.op.Pair.Mutations...)
				key = tsRootKey(3)
			}
			var r tsResult
			evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamagePutEIO, rank, key, func() { r = s.run(t) })
			mustEnvironment(t, err)
			r.tuple(t, 1, 2, -1)
			treeNativeError(t, r.err, "update", "IO", 5, "error 5", nil)
			if evidence.Deletes != wantDeletes || evidence.Faults != 1 || evidence.Commits != 0 {
				t.Fatalf("%s delete order %+v want%d", target, evidence, wantDeletes)
			}
			tsConsumed(t, s.s, s.o, 1, r.err)
			s.s = tsReopen(t, s.s, s.path)
			tsRead(t, s.s, TreeSchemaV1DBIs()[0], tsCounterKey(2), tsCounterLiteral(113, 2))
			tsRead(t, s.s, TreeSchemaV1DBIs()[1], keys[0], values[0])
		})
	}
}

func tsfCoveredTruth(t *testing.T) {
	for _, row := range []struct {
		scenario SelectedDamageScenario
		truth    CommitTruth
	}{
		{SelectedDamageCommitOld, 1}, {SelectedDamageCommitNew, 2}, {SelectedDamageCommitUnreadable, 3}, {SelectedDamageCommitThird, 3},
	} {
		t.Run(fmt.Sprintf("scenario%d", row.scenario), func(t *testing.T) {
			s := tsfNew(t)
			tsfCover(t, s)
			s.op.Pair.Consulted = []ConsultedRow{{TreeSchemaV1DBIs()[0], []byte{2}}}
			var before, after uint64
			s.p[0].before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
				if pos == 2 {
					before = reservationLive(s.o)
				}
				return nil
			}
			s.p[2].after = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
				if pos == 2 {
					after = reservationLive(s.o)
				}
				return nil
			}
			var r tsResult
			evidence, err := FixtureSelectedDamage(s.s, s.o, row.scenario, 0, tsCounterKey(1), func() { r = s.run(t) })
			mustEnvironment(t, err)
			r.tuple(t, row.truth, 3, -1)
			var ce *CommitError
			if !errors.As(r.err, &ce) || ce.Truth != row.truth || evidence.Commits != 1 || reservationLive(s.o) != 0 {
				t.Fatalf("covered truth result%v evidence%+v", r.err, evidence)
			}
			if row.scenario != SelectedDamageCommitUnreadable {
				for _, p := range s.p {
					if p.calls != [3]int{0, 1, 1} {
						t.Fatalf("two positions %v", p.calls)
					}
				}
				if before != after {
					t.Fatalf("readback account draw %d -> %d", before, after)
				}
			}
			if row.scenario == SelectedDamageCommitOld || row.scenario == SelectedDamageCommitNew {
				s.durable(t, row.truth == 2)
			}
			if row.scenario == SelectedDamageCommitThird {
				tsConsumed(t, s.s, s.o, row.truth, r.err)
				opened, check := OpenTreeV1(s.path, environmentConfig(), [32]byte{7})
				treeNativeIntegrity(t, check, "open", errSchema)
				if opened != nil {
					t.Fatal("malformed third authority retained Store resources")
				}
			}
		})
	}
}

func TestTreeCompleteObservationV1(t *testing.T) {
	for _, mode := range []string{"planned-image", "planned-absence", "computed-edge"} {
		for _, position := range []TreePositionV1{1, 2} {
			t.Run(fmt.Sprintf("negative-node/%s/position%d", mode, position), func(t *testing.T) {
				tsfNegativeNodeObservation(t, mode, position)
			})
		}
	}
	t.Run("negative-source-height", func(t *testing.T) {
		s := tsfNew(t)
		tsfCover(t, s)
		s.op.Primitives = s.op.Primitives[:2]
		p := &s.op.Primitives[1]
		// Deliberately violates source/sequence qualification: a genesis LAG
		// cannot follow this nonempty CURRENT in the same generation. It must
		// not localize the already planned counter as ORIGINAL damage.
		p.Generation, p.Height, p.Endpoint.Height = 1, 0, 0
		p.Endpoint.CumulativeChainwork[39] = 1
		tsCover(&s.op, s.p[0].block, s.p[1].block)
		var r tsResult
		tsfUnusedArm(t, s, func() { r = s.run(t) })
		r.tuple(t, 1, 1, 1)
		treeNativeIntegrity(t, r.err, "update", nil)
		if r.err.(*EngineError).TreeObservation != nil {
			t.Fatal("planned counter/source height localized")
		}
		tsConsumed(t, s.s, s.o, 1, r.err)
	})
	for _, readback := range []bool{false, true} {
		for _, damage := range []string{"absent", "malformed", "digest"} {
			t.Run(fmt.Sprintf("planned-container/readback%v/%s", readback, damage), func(t *testing.T) {
				s := tsfNew(t)
				tsfCover(t, s)
				_, _ = tsfOriginalLag(t, s)
				s.op.Primitives = slices.Clone(s.op.Primitives[1:])
				s.op.Primitives[0].Kind = 2
				s.op.Pair = TreePairV1{}
				later := []TreeEventV1{tsSpend(0x90, 0, 1, 0), tsCreate(0x90, 0, 1, 148, 11)}
				s.p[2].events = later
				if readback {
					// Negative immutable-source probe: writer touches the healthy
					// first leaf; readback's second Source instead touches the bad
					// original child through the independently built P_r parent.
					// With immutable events writer preflight finds this damage first.
					s.p[2].events = []TreeEventV1{tsSpend(0x20, 0, 1, 0), tsCreate(0x20, 0, 1, 148, 11)}
					s.p[2].before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
						if pos == 2 {
							s.p[2].events = later
						}
						return nil
					}
				}
				tsCover(&s.op, s.p[1].block, s.p[2].block)
				key := testTreeNodeKey(2, 288, [36]byte(tdUTXOKey(2, tdTxid(0x90), 0)[8:]))
				tsDamageLeaf(t, s.s, key, damage)
				r := tsfObservationRun(t, s, readback)
				position, index := TreePositionV1(1), 1
				observed := r.err
				if readback {
					var ce *CommitError
					if !errors.As(r.err, &ce) || ce.Truth != 3 {
						t.Fatalf("readback observation result%v", r.err)
					}
					treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
					observed, position = ce.ReadbackCause, 2
				}
				var engine *EngineError
				if !errors.As(observed, &engine) || any(engine) != any(observed) {
					t.Fatalf("observed pointer%v", observed)
				}
				var cause error
				if damage == "malformed" {
					cause = errSchema
				}
				treeNativeIntegrity(t, observed, "update", cause)
				kind := map[string]TreeObservationKindV1{"absent": 1, "malformed": 2, "digest": 4}[damage]
				tsObservation(t, engine.TreeObservation, s.op.Primitives[index], 8, key, kind, index, position, true, true)
				tsConsumed(t, s.s, s.o, r.truth, r.err)
			})
		}
	}
}

func tsfCoveredBeginReadback(t *testing.T) {
	for _, field := range []string{"tx", "events", "generated"} {
		t.Run(field, func(t *testing.T) {
			s := tsfNew(t)
			tsfCover(t, s)
			actual := s.p[1].block
			switch field {
			case "tx":
				actual.TxCount++
			case "events":
				actual.EventCount++
			case "generated":
				actual.Generated[0] = 1
			}
			s.p[1].before = func(pos TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
				if pos != 2 {
					return nil
				}
				if err := sink.BeginV1(actual); err != nil {
					return err
				}
				return errors.New("mismatched readback Begin accepted")
			}
			r := tsfObservationRun(t, s, true)
			var ce *CommitError
			if !errors.As(r.err, &ce) || ce.Truth != 3 {
				t.Fatalf("readback Begin result %v", r.err)
			}
			treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
			treeNativeError(t, ce.ReadbackCause, "update", "InvalidInput", 22, "invalid tree delta", nil)
			if s.p[0].calls != [3]int{0, 1, 1} || s.p[1].calls != [3]int{0, 1, 1} || s.p[2].calls != [3]int{0, 1, 0} {
				t.Fatalf("Begin source positions %v/%v/%v", s.p[0].calls, s.p[1].calls, s.p[2].calls)
			}
			tsConsumed(t, s.s, s.o, 3, r.err)
			s.durable(t, true)
		})
	}
}

// Deliberately invalid lower-owner projections exercise the detector. Qualified
// immutable public Sources cannot manufacture these inconsistent planned rows.
func tsfNegativeNodeObservation(t *testing.T, mode string, position TreePositionV1) {
	t.Helper()
	s, _, _ := tsNew(t)
	p := TreePrimitiveV1{Generation: 2, Block: tdTxid(0xb1), Height: 5}
	utxo := tdUTXOKey(2, tdTxid(0x20), 0)
	value := tdFormed(tdFrame(7, 0, nil), 4, 1)
	route := [36]byte(utxo[8:])
	key := testTreeNodeKey(2, 288, route)
	digest := testTreeLeafPreimage(route, value)
	binding := tcBinding(t, 2, tcEndpoint(4, tdTxid(0xa0)), tcEntry(utxo, value))
	treeNativeSeed(t, s, 0, tsRootKey(2), binding)
	treeNativeSeed(t, s, 8, key, digest[:])
	target := treeTargetV1{dbi: TreeSchemaV1DBIs()[8], key: key}
	kind, image, reference := TreeObservationKindV1(1), false, true
	var cause error
	if mode == "planned-image" {
		target.after = treeImageV1{present: true, value: []byte{1}}
		kind, cause = 2, errSchema
	}
	if mode == "computed-edge" {
		// A planned binding's zero Top link is computed; the fetched node is
		// still physical ORIGINAL. Its wrong digest forces that actual read.
		target = treeTargetV1{dbi: TreeSchemaV1DBIs()[0], key: tsRootKey(2), after: treeImageV1{present: true, value: binding}}
		treeNativeSeed(t, s, 8, key, bytes.Repeat([]byte{0x7f}, 32))
		kind, image, reference = 4, true, false
	}
	context := TreeObservationV1{DatabaseID: [32]byte{7}, Generation: 2, Block: p.Block, Height: 5, Primitive: 1, Position: position}
	probe := func(old treeOldV1, emit treeEmitterV1, ledger treeLedgerV1) error {
		if err := emit.emitV1(target); err != nil {
			return err
		}
		leaves := &testTreeLeaves{items: []treeLeafV1{testTreeStreamLeaf(2, route, true, value)}, log: &testTreeLog{}}
		return treeEmitNodesV1(old, 2, tcEndpoint(5, p.Block), [32]byte{7}, leaves, emit, ledger, &context)
	}
	observed := tsfNodeOriginRun(t, s, position, probe)
	treeNativeIntegrity(t, observed, "update", cause)
	var engine *EngineError
	if !errors.As(observed, &engine) || any(engine) != any(observed) {
		t.Fatalf("node detector pointer %v", observed)
	}
	context = TreeObservationV1{}
	tsObservation(t, engine.TreeObservation, p, 8, key, kind, 1, position, image, reference)
}

func tsfNodeOriginRun(t *testing.T, s *Store, position TreePositionV1, probe func(treeOldV1, treeEmitterV1, treeLedgerV1) error) error {
	t.Helper()
	ledger := &ttLedger{}
	if position == 1 {
		outcome := fixtureTreeCommitV1(s, fixtureTreeScriptV1{ledger: ledger, write: func(section *treeSectionV1) error {
			section.covered = true
			return probe(section.oldV1(true), section.writerV1(), ledger)
		}})
		ttOutcome(t, outcome, 1, 1)
		return outcome.primary
	}
	var detected error
	calls := 0
	script := fixtureTreeScriptV1{
		ledger: ledger, calls: &calls, held: treeScratchBytesV1 + treeNodeWorkBytesV1 + treeValueBytesV1,
		write: func(section *treeSectionV1) error { return section.writerV1().emitV1(ttTarget(ttUTXO, ttZ, "z1")) },
		readback: func(read *treeReadbackStateV1) error {
			detected = probe(read.oldV1(), read.emitterV1(), read.budget.ledgerV1())
			return detected
		},
	}
	var outcome updateNativeOutcome
	evidence, err := fixtureLargeFault(s, 8, 6, ttOut, func() { outcome = fixtureTreeCommitV1(s, script) })
	mustEnvironment(t, err)
	fixtureTreeReleaseV1(outcome)
	commit := ttCommitError(t, outcome, 3)
	if calls != 1 || evidence.commits != 1 || detected == nil || any(commit.ReadbackCause) != any(detected) {
		t.Fatalf("node readback calls%d evidence%+v detector%v cause%v", calls, evidence, detected, commit.ReadbackCause)
	}
	return commit.ReadbackCause
}

func tsDamageLeaf(t *testing.T, s *Store, key []byte, damage string) {
	t.Helper()
	if damage == "absent" {
		mustEnvironment(t, fixtureDeletePrefixRow(s, TreeSchemaV1DBIs()[8], key))
		return
	}
	value := []byte{1}
	if damage == "digest" {
		value = bytes.Repeat([]byte{0x7f}, 32)
	}
	treeNativeSeed(t, s, 8, key, value)
}

func tsfObservationRun(t *testing.T, s *tsfScene, readback bool) tsResult {
	t.Helper()
	var r tsResult
	if readback {
		_, err := FixtureSelectedDamage(s.s, s.o, SelectedDamageCommitNew, 0, tsCounterKey(2), func() { r = s.run(t) })
		mustEnvironment(t, err)
		r.tuple(t, 3, 3, -1)
		return r
	}
	evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamagePutEIO, 0, tsCounterKey(2), func() { r = s.run(t) })
	if err == nil || err.Error() != "selected damage fixture site was not reached exactly as armed" || evidence.Faults != 0 || evidence.Deletes != 0 || evidence.Commits != 0 {
		t.Fatalf("planned-container prewrite evidence%+v fixture%v", evidence, err)
	}
	r.tuple(t, 1, 1, 1)
	return r
}

func (s *tsfScene) run(t *testing.T) tsResult { return tsRun(t, s.s, s.o, TreeOperation, s.op) }

func (s *tsfScene) crossed(t *testing.T) tsResult {
	t.Helper()
	var r tsResult
	evidence, err := fixtureLargeFault(s.s, 12, 0, []byte{9}, func() { r = s.run(t) })
	mustEnvironment(t, err)
	if evidence.commits != 1 {
		t.Fatalf("crossing commit count%d", evidence.commits)
	}
	return r
}

func (s *tsfScene) durable(t *testing.T, newState bool) {
	t.Helper()
	s.s = tsReopen(t, s.s, s.path)
	for i, p := range s.op.Primitives {
		txid, frame := tdTxid(0x10), tdFrame(100, 0, nil)
		if i == 1 {
			txid, frame = tdTxid(0x20), tdFrame(200, 0, []byte{1})
		}
		if i == 2 {
			txid, frame = tdTxid(0x30), tdFrame(300, 0, nil)
		}
		var value []byte
		if newState && i != 1 {
			value = tdFormed(frame, p.Height, 1)
		}
		tsRead(t, s.s, TreeSchemaV1DBIs()[1], tdUTXOKey(p.Generation, txid, 0), value)
		manifest := []byte(nil)
		if newState {
			spent := uint32(0)
			if i == 2 {
				spent = 1
			}
			manifest = tdManifest(p.Height, s.p[i].block.Generated, s.p[i].block.TxCount, spent)
		}
		tsRead(t, s.s, TreeSchemaV1DBIs()[5], tdManifestKey(p.Block), manifest)
	}
	undo := []byte(nil)
	if newState {
		undo = tdFormed(tdFrame(200, 0, []byte{1}), 5, 1)
	}
	tsRead(t, s.s, TreeSchemaV1DBIs()[5], tdEntryKey(s.op.Primitives[2].Block, tdTxid(0x20), 1, 0, 0), undo)
	current := s.op.Pair.Mutations[0]
	body := []byte(nil)
	if newState {
		body = current.Literal
	}
	tsRead(t, s.s, current.DBI, current.Key, body)
	for _, m := range tsEntry(t).Pair.Mutations {
		tsRead(t, s.s, m.DBI, m.Key, m.Literal)
	}
	for _, g := range []uint64{1, 2} {
		tsRead(t, s.s, TreeSchemaV1DBIs()[0], tsRootKey(g), s.binding(t, g, newState))
	}
}

func (s *tsfScene) binding(t *testing.T, g uint64, newState bool) []byte {
	t.Helper()
	if !newState {
		return tsRootBytes(t, TreeEndpointV1{})
	}
	entries := map[string]testTreeEntry{}
	var endpoint TreeEndpointV1
	for j, p := range s.op.Primitives {
		if p.Generation != g {
			continue
		}
		endpoint = p.Endpoint
		body := s.op.Pair.Mutations[0].Literal
		if j == 1 {
			body = tdFrame(200, 0, []byte{1})
		}
		if j == 2 {
			body = tdFrame(300, 0, nil)
		}
		if j != 0 && p.Coverage != nil {
			body = append(make([]byte, 148), body...)
		}
		for _, e := range s.p[j].events {
			key := tdUTXOKey(g, e.Outpoint.Txid, e.Outpoint.Vout)
			id := string(key)
			if e.Kind == 1 {
				delete(entries, id)
				continue
			}
			coinbase := byte(0)
			if e.TxIndex == 0 {
				coinbase = 1
			}
			entries[id] = tcEntry(key, tdFormed(body[e.FrameOffset:e.FrameOffset+uint64(e.FrameLength)], p.Height, coinbase))
		}
	}
	values := make([]testTreeEntry, 0, len(entries))
	for _, e := range entries {
		values = append(values, e)
	}
	slices.SortFunc(values, func(a, b testTreeEntry) int { return bytes.Compare(a.k[:], b.k[:]) })
	for _, e := range values {
		key := append(tdUTXOKey(g, [32]byte{}, 0)[:8], e.k[:]...)
		tsRead(t, s.s, TreeSchemaV1DBIs()[1], key, e.v)
	}
	return tcBinding(t, g, endpoint, values...)
}

// Literal P sizes follow each emitted identity in I-SEQ order. tcP is the
// existing test-owned high-water calculator, independent of the production P.
func (s *tsfScene) budgets(t *testing.T) [3]uint64 {
	t.Helper()
	p := &tcP{sizes: map[string]uint64{}}
	var out [3]uint64
	for i, prim := range s.op.Primitives {
		txid, frame := tdTxid(0x10), tdFrame(100, 0, nil)
		if i == 1 {
			txid, frame = tdTxid(0x20), tdFrame(200, 0, []byte{1})
		}
		if i == 2 {
			txid, frame = tdTxid(0x30), tdFrame(300, 0, nil)
		}
		key, value := tdUTXOKey(prim.Generation, txid, 0), tdFormed(frame, prim.Height, 1)
		if i != 0 {
			p.put(4, prim.Block[:], 0)
		}
		p.put(1, key, len(value))
		if i == 2 {
			old := tdUTXOKey(2, tdTxid(0x20), 0)
			v := tdFormed(tdFrame(200, 0, []byte{1}), 5, 1)
			p.put(5, tdEntryKey(prim.Block, tdTxid(0x20), 1, 0, 0), len(v))
			p.put(1, old, 0)
		}
		p.put(5, tdManifestKey(prim.Block), 33)
		if prim.Coverage != nil {
			p.put(0, tsCounterKey(prim.Generation), 16)
		}
		if i == 2 {
			p.put(8, testTreeNodeKey(2, 288, [36]byte(tdUTXOKey(2, tdTxid(0x20), 0)[8:])), 0)
		}
		p.put(8, testTreeNodeKey(prim.Generation, 288, [36]byte(key[8:])), 32)
		binding := tcBinding(t, prim.Generation, prim.Endpoint, tcEntry(key, value))
		p.put(0, tsRootKey(prim.Generation), len(binding))
		out[i] = p.high
	}
	return out
}

func tsfCoveredReserve(t *testing.T) {
	for _, short := range []uint64{1, 0} {
		t.Run(fmt.Sprintf("short%d", short), func(t *testing.T) {
			s := tsfNew(t)
			tsfCover(t, s)
			budgets := s.budgets(t)
			pc := uint64(128 + 32 + len(s.op.Pair.Mutations[0].Literal))
			filler := uint64(402_653_184) - pc - budgets[2] - 131_192 - 288_408 - 208 + short
			var r tsResult
			run := func() {
				mustEnvironment(t, s.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
					return a.WithReservation(filler, func() error {
						r = tsInvoke(s.s, a, func(*Reader) (TreeOperationV1, error) { return s.op, nil })
						if reservationLive(s.o) != filler {
							t.Fatal("covered reserve hold leaked")
						}
						return nil
					})
				}))
			}
			if short != 0 {
				tsfUnusedArm(t, s, run)
				r.tuple(t, 1, 1, -1)
				if any(r.err) != any(errOperationReservationCapacity) {
					t.Fatalf("prewrite H_r identity%v", r.err)
				}
				tsConsumed(t, s.s, s.o, 1, r.err)
			} else {
				run()
				r.tuple(t, 2, 3, -1)
				mustEnvironment(t, r.err)
			}
			if reservationLive(s.o) != 0 {
				t.Fatal("covered reserve operation leaked")
			}
			s.durable(t, short == 0)
		})
	}
}

func tsfCoveredOverlap(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("target%v", changed), func(t *testing.T) {
			s := tsfNew(t)
			tsfCover(t, s)
			key := tdUTXOKey(2, tdTxid(0x20), 0)
			if !changed {
				key = tdUTXOKey(2, tdTxid(0xee), 0)
			}
			s.op.Pair.Consulted = []ConsultedRow{{TreeSchemaV1DBIs()[1], key}}
			var r tsResult
			if changed {
				tsfUnusedArm(t, s, func() { r = s.run(t) })
				r.tuple(t, 1, 1, -1)
				treeNativeError(t, r.err, "update", "InvalidInput", 22, "invalid Update Batch", nil)
				tsConsumed(t, s.s, s.o, 1, r.err)
			} else {
				r = s.run(t)
				r.tuple(t, 2, 3, -1)
				mustEnvironment(t, r.err)
			}
			if s.p[2].calls != [3]int{0, 1, 0} {
				t.Fatal("final ownership checked before last source")
			}
			s.durable(t, !changed)
		})
	}
}

func tsfCoveredFinalDomain(t *testing.T) {
	s := tsfNew(t)
	tsfCover(t, s)
	m := tsTarget(0x1234)
	treeNativeSeed(t, s.s, 6, m.Key, m.Literal)
	s.op.Pair.Consulted = []ConsultedRow{{m.DBI, m.Key}}
	var r tsResult
	evidence, err := fixtureLargeFault(s.s, 13, 6, m.Key, func() { r = s.run(t) })
	mustEnvironment(t, err)
	r.tuple(t, 1, 2, -1)
	treeNativeError(t, r.err, "update", "StateMismatch", -30779, "final update image mismatch", nil)
	if evidence.drift != 1 || evidence.commits != 0 || r.err.(*EngineError).TreeObservation != nil {
		t.Fatalf("late native domain failure%v evidence%+v", r.err, evidence)
	}
	tsConsumed(t, s.s, s.o, 1, r.err)
	s.durable(t, false)
	tsRead(t, s.s, m.DBI, m.Key, m.Literal)
}

func tsfCoveredObservationCleanup(t *testing.T) {
	for _, mode := range []uint32{9, 10} {
		t.Run(fmt.Sprintf("old-abort%d", mode), func(t *testing.T) {
			s := tsfNew(t)
			tsfCover(t, s)
			mustEnvironment(t, fixtureDeletePrefixRow(s.s, TreeSchemaV1DBIs()[0], tsCounterKey(2)))
			var r tsResult
			_, err := fixtureLargeFault(s.s, mode, 0, tsCounterKey(2), func() { r = s.run(t) })
			mustEnvironment(t, err)
			r.tuple(t, 1, 1, 1)
			parts, ok := r.err.(interface{ Unwrap() []error })
			if !ok || len(parts.Unwrap()) != 2 {
				t.Fatalf("ordered observation cleanup%v", r.err)
			}
			primary, cleanup := parts.Unwrap()[0], parts.Unwrap()[1]
			treeNativeIntegrity(t, primary, "update", nil)
			var engine *EngineError
			if !errors.As(r.err, &engine) || any(engine) != any(primary) || !errors.Is(r.err, primary) {
				t.Fatal("cleanup lost primary pointer/errors.As")
			}
			tsObservation(t, engine.TreeObservation, s.op.Primitives[1], 0, tsCounterKey(2), 1, 1, 1, true, true)
			if mode == 9 {
				treeNativeError(t, cleanup, "abort", "IO", 5, "error 5", nil)
				tsConsumed(t, s.s, s.o, 1, r.err)
			} else {
				failure := requireEngineError(t, cleanup, "LocalInvariant", "abort", -30416)
				if !failure.ReopenRequired || s.s.state != storePOISONEDTHREAD || s.s.txn == nil {
					t.Fatal("retained cleanup disposition")
				}
				calls := 0
				mustEnvironment(t, s.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
					next := tsInvoke(s.s, a, func(*Reader) (TreeOperationV1, error) { calls++; return s.op, nil })
					if any(next.err) != any(s.s.terminal) || calls != 0 {
						t.Fatal("retained cleanup next operation")
					}
					return nil
				}))
				mustEnvironment(t, fixtureLargeRelease(s.s))
			}
			if reservationLive(s.o) != 0 {
				t.Fatal("observation cleanup hold leaked")
			}
		})
	}
}

func tsfCoveredTransient(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprintf("invalid-before%v", invalid), func(t *testing.T) {
			s := tsfNew(t)
			tsfCover(t, s)
			keys, values := tsfOriginalLag(t, s)
			s.op.Primitives = []TreePrimitiveV1{s.op.Primitives[1]}
			s.op.Primitives[0].Kind, s.op.Primitives[0].Undo = 1, 2
			s.op.Pair = TreePairV1{}
			if invalid {
				bad := bytes.Clone(values[0])
				bad[len(bad)-1] = 2
				treeNativeSeed(t, s.s, 1, keys[0], bad)
			}
			tsCover(&s.op, s.p[1].block)
			var r tsResult
			if invalid {
				evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamagePutEIO, 0, tsCounterKey(2), func() { r = s.run(t) })
				if err == nil || err.Error() != "selected damage fixture site was not reached exactly as armed" || evidence.Faults != 0 || evidence.Deletes != 0 {
					t.Fatalf("Transient prewrite evidence%+v fixture%v", evidence, err)
				}
				r.tuple(t, 1, 1, 0)
				treeNativeIntegrity(t, r.err, "update", errSchema)
				if r.err.(*EngineError).TreeObservation != nil {
					t.Fatal("UTXO source contradiction localized")
				}
				tsConsumed(t, s.s, s.o, 1, r.err)
			} else {
				r = s.run(t)
				r.tuple(t, 2, 3, -1)
				mustEnvironment(t, r.err)
				tsRead(t, s.s, TreeSchemaV1DBIs()[0], tsCounterKey(2), tsCounterLiteral(113, 2))
			}
		})
	}
}

func tsfCoveredCapacity(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(fmt.Sprintf("P-denied%v", denied), func(t *testing.T) {
			s, path, o := tsNew(t)
			tsRoots(t, s, o, 1)
			tsSeedCounter(t, s, o, 1, false, make([]byte, 16))
			frame := tdFrame(7, 0, bytes.Repeat([]byte{8}, 65536))
			var events []TreeEventV1
			var frames []byte
			for vout := uint32(0); vout < 3; vout++ {
				events = append(events, tsCreate(0x77, vout, 0, uint64(148+len(frames)), 65551))
				frames = append(frames, frame...)
			}
			op := tsCoveredDelta(t, 5, 0x4a, TreeBlockV1{TxCount: 1, EventCount: 3}, events, frames)
			var r tsResult
			run := func() {
				mustEnvironment(t, o.WithOperation(TreeOperation, func(a *OperationAccount) error {
					filler := uint64(0)
					if denied {
						pair := uint64(128 + 32 + len(op.Pair.Mutations[0].Literal))
						filler = 402_653_184 - pair - 74_880 - 104*3 - 65_560 - 147_968
					}
					return a.WithReservation(filler, func() error {
						r = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil })
						if reservationLive(o) != filler {
							t.Fatal("P boundary leaked hold")
						}
						return nil
					})
				}))
			}
			key := tdUTXOKey(1, tdTxid(0x77), 0)
			evidence, err := FixtureSelectedDamage(s, o, SelectedDamagePutEIO, 1, key, run)
			if denied {
				if err == nil || err.Error() != "selected damage fixture site was not reached exactly as armed" || evidence.Faults != 0 || evidence.Deletes != 0 || evidence.Commits != 0 {
					t.Fatalf("P prewrite evidence%+v fixture%v", evidence, err)
				}
				r.tuple(t, 1, 1, 0)
				if any(r.err) != any(errOperationReservationCapacity) {
					t.Fatalf("P capacity identity%v", r.err)
				}
			} else {
				mustEnvironment(t, err)
				r.tuple(t, 1, 2, -1)
				treeNativeError(t, r.err, "update", "IO", 5, "error 5", nil)
				if evidence.Faults != 1 || evidence.Deletes != 1 {
					t.Fatalf("healthy P arm%+v", evidence)
				}
			}
			tsConsumed(t, s, o, 1, r.err)
			s = tsReopen(t, s, path)
			tsRead(t, s, TreeSchemaV1DBIs()[1], key, nil)
			tsRead(t, s, TreeSchemaV1DBIs()[0], tsCounterKey(1), make([]byte, 16))
			tsRead(t, s, TreeSchemaV1DBIs()[4], op.Primitives[0].Block[:], nil)
		})
	}
}

func tsfCoveredLifecycle(t *testing.T) {
	for _, cleanup := range []uint32{0, 9, 10} {
		for _, delivery := range []string{"nil", "error", "panic", "goexit"} {
			t.Run(fmt.Sprintf("cleanup%d/%s", cleanup, delivery), func(t *testing.T) {
				s := tsfNew(t)
				tsfCover(t, s)
				marker, panicValue := errors.New("covered LAG source"), new(int)
				s.p[1].before = func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error {
					switch delivery {
					case "error":
						return marker
					case "panic":
						panic(panicValue)
					case "goexit":
						runtime.Goexit()
					}
					return nil
				}
				var r tsResult
				var recovered any
				returned := false
				run := func() {
					defer func() { recovered = recover() }()
					invoke := func() { r = s.run(t); returned = true }
					if cleanup == 0 {
						invoke()
						return
					}
					_, err := fixtureLargeFault(s.s, cleanup, 0, tsCounterKey(2), invoke)
					mustEnvironment(t, err)
				}
				if delivery == "goexit" {
					done := make(chan struct{})
					go func() { defer close(done); run() }()
					<-done
				} else {
					run()
				}
				if delivery == "panic" && recovered != panicValue {
					t.Fatalf("covered source panic identity%v", recovered)
				}
				if delivery != "panic" && recovered != nil {
					t.Fatalf("unexpected source panic%v", recovered)
				}
				wantReturn := delivery == "nil" || delivery == "error"
				if returned != wantReturn || reservationLive(s.o) != 0 {
					t.Fatal("source delivery/hold lifetime")
				}
				if delivery == "nil" {
					r.tuple(t, 2, 3, -1)
					if cleanup == 0 {
						mustEnvironment(t, r.err)
					}
				} else if delivery == "error" {
					r.tuple(t, 1, 1, 1)
					if !errors.Is(r.err, marker) {
						t.Fatal("covered source primary lost")
					}
				}
				tsExpiredReader(t, s.p[1].reader)
				if s.p[1].sink.WindowV1() != nil {
					t.Fatal("covered source retained live window")
				}
				tsCoveredLifecycleState(t, s, delivery, cleanup)
			})
		}
	}
}

func tsCoveredLifecycleState(t *testing.T, s *tsfScene, delivery string, cleanup uint32) {
	t.Helper()
	truth := CommitTruth(1)
	if delivery == "nil" {
		truth = 2
	}
	if cleanup == 0 && delivery != "error" {
		if s.s.state != storeOPEN || s.s.terminal != nil {
			t.Fatal("clean covered source state")
		}
		tsFollowing(t, s.s, s.o)
		return
	}
	if cleanup != 10 {
		tsConsumed(t, s.s, s.o, truth, s.s.terminal)
		return
	}
	if s.s.state != storePOISONEDTHREAD || s.s.txn == nil || s.s.terminalTruth != truth {
		t.Fatal("retained covered source state")
	}
	calls := 0
	mustEnvironment(t, s.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
		next := tsInvoke(s.s, a, func(*Reader) (TreeOperationV1, error) { calls++; return s.op, nil })
		if any(next.err) != any(s.s.terminal) || calls != 0 {
			t.Fatal("retained covered Source next operation")
		}
		return nil
	}))
	mustEnvironment(t, fixtureLargeRelease(s.s))
}

func TestTreeStreamComposedAndExactAccountV1(t *testing.T) {
	for _, crossed := range []bool{false, true} {
		t.Run(fmt.Sprintf("A2-A4-crossed%v", crossed), func(t *testing.T) {
			s := tsfNew(t)
			wantP := s.budgets(t)
			var sample uint64
			pc := uint64(len(s.op.Pair.Mutations[0].Key) + len(s.op.Pair.Mutations[0].Literal) + 128)
			s.p[2].before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
				if pos == 1 {
					sample = reservationLive(s.o)
				}
				return nil
			}
			r := tsResult{}
			if crossed {
				r = s.crossed(t)
			} else {
				r = s.run(t)
			}
			r.tuple(t, 2, 3, -1)
			if sample != pc+wantP[1]+74_880 {
				t.Fatalf("A4 live%d want PC%d+P%d+74880", sample, pc, wantP[1])
			}
			if crossed {
				tcCrossedCause(t, r.err, 2, nil)
				tsConsumed(t, s.s, s.o, 2, r.err)
			} else {
				mustEnvironment(t, r.err)
				tsFollowing(t, s.s, s.o)
			}
			for _, p := range s.p {
				want := 1
				if crossed {
					want = 2
				}
				if p.calls[1] != 1 || p.calls[2] != want-1 {
					t.Fatalf("positions %v", p.calls)
				}
			}
			s.durable(t, true)
		})
	}
}

func TestTreeStreamReadbackReservationV1(t *testing.T) {
	for _, short := range []uint64{1, 0} {
		t.Run(fmt.Sprintf("R7-Hr-short%d", short), func(t *testing.T) {
			s := tsfNew(t)
			budgets := s.budgets(t)
			pc := uint64(len(s.op.Pair.Mutations[0].Key) + len(s.op.Pair.Mutations[0].Literal) + 128)
			filler := uint64(402_653_184) - pc - budgets[2] - 131_192 - 288_408 - 104*2 + short
			var r tsResult
			mustEnvironment(t, s.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				return a.WithReservation(filler, func() error {
					r = tsInvoke(s.s, a, func(*Reader) (TreeOperationV1, error) { return s.op, nil })
					if reservationLive(s.o) != filler {
						t.Fatal("R7 leaked past hold exit")
					}
					return nil
				})
			}))
			stage := UpdateStage(3)
			if short != 0 {
				stage = 2
			}
			r.tuple(t, CommitTruth(2-short), stage, -1)
			if short != 0 {
				if any(r.err) != any(errOperationReservationCapacity) {
					t.Fatalf("H_r capacity identity %v", r.err)
				}
				tsConsumed(t, s.s, s.o, 1, r.err)
			} else {
				mustEnvironment(t, r.err)
			}
			s.durable(t, short == 0)
		})
	}
	t.Run("R7-P-growth", func(t *testing.T) {
		s := tsfNew(t)
		pc := uint64(len(s.op.Pair.Mutations[0].Key) + len(s.op.Pair.Mutations[0].Literal) + 128)
		// CURRENT UTXO64 + manifest(33+33) =130; its first node needs78.
		filler := uint64(402_653_184) - pc - 74_880 - 104 - 65_560 - 147_968 - 207
		var r tsResult
		mustEnvironment(t, s.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
			return a.WithReservation(filler, func() error {
				r = tsInvoke(s.s, a, func(*Reader) (TreeOperationV1, error) { return s.op, nil })
				if reservationLive(s.o) != filler {
					t.Fatal("P refusal release")
				}
				return nil
			})
		}))
		r.tuple(t, 1, 2, 0)
		if any(r.err) != any(errOperationReservationCapacity) || s.p[1].calls[1] != 0 {
			t.Fatalf("P refusal %v", r.err)
		}
		tsConsumed(t, s.s, s.o, 1, r.err)
		s.durable(t, false)
	})
}

func TestTreeStreamDescriptorCapacityV1(t *testing.T) {
	s := tsfNew(t)
	s.p[1].block.EventCount = 4_294_967_295
	r := s.run(t)
	r.tuple(t, 1, 2, 1)
	if any(r.err) != any(errOperationReservationCapacity) || !IsOperationReservationCapacity(r.err) || s.p[2].calls[1] != 0 {
		t.Fatalf("R5 %v calls%v", r.err, s.p[2].calls)
	}
	tsConsumed(t, s.s, s.o, 1, r.err)
	s.durable(t, false)
}

func TestTreeStreamBeginFailuresV1(t *testing.T) {
	for _, row := range []struct {
		scenario SelectedDamageScenario
		class    EngineClass
		code     int
	}{{SelectedDamageBeginEIO, "IO", 5}, {SelectedDamageBeginTxnFull, "Transaction", -30788}} {
		t.Run(fmt.Sprint(row.code), func(t *testing.T) {
			s, _, _ := treeNativeStore(t)
			o := reservationOwner(t, 805_306_368)
			callbacks, sources := 0, 0
			op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { sources++; return nil }))
			var r tsResult
			evidence, err := FixtureSelectedDamage(s, o, row.scenario, 0, []byte{0}, func() {
				_ = o.WithOperation(TreeOperation, func(a *OperationAccount) error {
					r = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { callbacks++; return op, nil })
					return nil
				})
			})
			mustEnvironment(t, err)
			r.tuple(t, 1, 1, -1)
			treeNativeError(t, r.err, "update", row.class, row.code, expectedNativeDiagnostic(row.code), nil)
			if callbacks != 0 || sources != 0 || reservationLive(o) != 0 || evidence.BeginOld != 1 || evidence.Faults != 1 || evidence.BeginWrite != 0 || evidence.BeginRead != 0 || evidence.OldAborts != 0 {
				t.Fatalf("begin effects %+v callbacks%d sources%d", evidence, callbacks, sources)
			}
			tsConsumed(t, s, o, 1, r.err)
		})
	}
}

func TestTreeStreamCallbackRecordedFailureV1(t *testing.T) {
	for _, mode := range []string{"ignored", "returned", "wrapped", "other", "panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			s, _, o := tsNew(t)
			key := tsTarget(71).Key
			var f, application error
			var kept *Reader
			var r tsResult
			value := new(int)
			post := false
			run := func() {
				_, fixtureErr := FixtureSelectedDamage(s, o, SelectedDamageGetEIO, 6, key, func() {
					_ = o.WithOperation(TreeOperation, func(a *OperationAccount) error {
						r = tsInvoke(s, a, func(reader *Reader) (TreeOperationV1, error) {
							kept = reader
							_, _, f = reader.Get(TreeSchemaV1DBIs()[6], key)
							switch mode {
							case "panic":
								panic(value)
							case "goexit":
								runtime.Goexit()
							case "returned":
								application = f
							case "wrapped":
								application = fmt.Errorf("callback: %w", f)
							case "other":
								application = errors.New("application")
							}
							return tsPair(19), application
						})
						return nil
					})
				})
				mustEnvironment(t, fixtureErr)
				post = true
			}
			if mode == "goexit" {
				done := make(chan struct{})
				go func() { defer close(done); run() }()
				<-done
			} else if mode == "panic" {
				var got any
				func() { defer func() { got = recover() }(); run() }()
				if got != value {
					t.Fatal("callback F panic identity")
				}
			} else {
				run()
				r.tuple(t, 1, 1, -1)
			}
			if f == nil || kept == nil || kept.usable() || reservationLive(o) != 0 {
				t.Fatal("recorded failure lifetime")
			}
			tsExpiredReader(t, kept)
			treeNativeError(t, f, "get", "IO", 5, "error 5", nil)
			if mode == "panic" || mode == "goexit" {
				if post || any(s.terminal) != any(f) {
					t.Fatal("unwind lost F")
				}
			} else if mode == "ignored" || mode == "returned" {
				if any(r.err) != any(f) {
					t.Fatalf("dedup identity %v want %v", r.err, f)
				}
			} else {
				joined, ok := r.err.(interface{ Unwrap() []error })
				if !ok || len(joined.Unwrap()) != 2 || any(joined.Unwrap()[0]) != any(application) || any(joined.Unwrap()[1]) != any(f) {
					t.Fatalf("callback primary order %v", r.err)
				}
			}
			tsConsumed(t, s, o, 1, s.terminal)
		})
	}
}

func TestTreeStreamSourceFailureAndDriftV1(t *testing.T) {
	for _, mode := range []string{"lag2-drift", "ignored-sink", "excluded-create"} {
		t.Run(mode, func(t *testing.T) {
			s := tsfNew(t)
			var r tsResult
			switch mode {
			case "lag2-drift":
				count, err := FixtureWriteSnapshotDrift(s.s, 4, bytes.Clone(s.op.Primitives[2].Block[:]), func() { r = s.run(t) })
				mustEnvironment(t, err)
				if count != 1 {
					t.Fatal("drift site not reached")
				}
				if s.p[0].calls != [3]int{0, 1, 0} || s.p[1].calls != [3]int{0, 1, 0} || s.p[2].calls != [3]int{} {
					t.Fatalf("drift Source calls CURRENT%v LAG1%v LAG2%v", s.p[0].calls, s.p[1].calls, s.p[2].calls)
				}
				r.tuple(t, 1, 2, 2)
				treeNativeError(t, r.err, "update", "StateMismatch", -30779, "OLD/write snapshot mismatch", nil)
			case "ignored-sink":
				s.p[1].custom = func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
					_ = sink.BeginV1(TreeBlockV1{TxCount: 2, EventCount: 2})
					e := TreeEventV1{Kind: 1, Outpoint: TreeOutpointV1{Txid: tdTxid(0xee)}, TxIndex: 1}
					_ = sink.EventV1(e)
					_ = sink.EventV1(e)
					return nil
				}
				// after ignored first refusal, even the regular BEGIN must retain it.
				r = s.run(t)
				r.tuple(t, 1, 2, 1)
				treeNativeError(t, r.err, "update", "InvalidInput", 22, "invalid tree delta", nil)
			case "excluded-create":
				p := s.op.Primitives[1]
				treeNativeSeed(t, s.s, 4, bytes.Clone(p.Block[:]), tdFrame(200, 2, []byte{1}))
				r = s.run(t)
				r.tuple(t, 1, 2, 1)
				treeNativeError(t, r.err, "update", "InvalidInput", 22, "invalid tree delta", nil)
			}
			tsConsumed(t, s.s, s.o, 1, r.err)
			s.durable(t, false)
			if mode == "lag2-drift" {
				if equal, err := FixtureRawRowEqual(s.s, 4, bytes.Clone(s.op.Primitives[1].Block[:]), tdFrame(200, 0, []byte{1})); err != nil || !equal {
					t.Fatalf("LAG1 raw body bytes equal%v err%v", equal, err)
				}
				if equal, err := FixtureRawRowEqual(s.s, 4, bytes.Clone(s.op.Primitives[2].Block[:]), []byte{0x7f}); err != nil || !equal {
					t.Fatalf("LAG2 raw body bytes equal%v err%v", equal, err)
				}
			}
		})
	}
}

func TestTreeStreamProviderUnwindAndLifetimeV1(t *testing.T) {
	for _, covered := range []bool{false, true} {
		for _, mode := range []string{"panic", "goexit", "reader-panic", "reader-goexit"} {
			name := mode
			if covered {
				name += "/covered"
			}
			t.Run(name, func(t *testing.T) {
				s := tsfNew(t)
				if covered {
					tsfCover(t, s)
				}
				value := new(int)
				key := tsTarget(77).Key
				var failure error
				readerFault := mode == "reader-panic" || mode == "reader-goexit"
				s.p[1].after = func(_ TreePositionV1, r *Reader, _ *TreeDeltaSinkV1) error {
					if readerFault {
						_, _, failure = r.Get(TreeSchemaV1DBIs()[6], key)
					}
					if mode == "goexit" || mode == "reader-goexit" {
						runtime.Goexit()
					}
					panic(value)
				}
				post := false
				var recovered any
				run := func() {
					done := make(chan struct{})
					go func() {
						defer close(done)
						defer func() {
							recovered = recover()
							if reservationLive(s.o) != 0 {
								t.Error("hold still live at unwind delivery")
							}
						}()
						_ = s.run(t)
						post = true
					}()
					<-done
				}
				if readerFault {
					evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamageGetEIO, 6, key, run)
					mustEnvironment(t, err)
					if failure == nil || evidence.Faults != 1 || evidence.OldGets[6] != 1 {
						t.Fatalf("provider Reader fault %v evidence%+v", failure, evidence)
					}
					treeNativeError(t, failure, "get", "IO", 5, "error 5", nil)
				} else {
					run()
				}
				if (mode == "panic" || mode == "reader-panic") && recovered != value {
					t.Fatalf("provider panic identity %v", recovered)
				}
				if (mode == "goexit" || mode == "reader-goexit") && recovered != nil {
					t.Fatalf("provider Goexit panicked %v", recovered)
				}
				if post || reservationLive(s.o) != 0 || s.p[1].reader == nil || s.p[1].reader.usable() {
					t.Fatal("provider unwind lifetime")
				}
				tsExpiredReader(t, s.p[1].reader)
				if s.p[1].sink.WindowV1() != nil {
					t.Fatal("expired sink window")
				}
				treeNativeError(t, s.p[1].sink.EventV1(TreeEventV1{Kind: 2}), "update", "InvalidInput", 22, "tree delta sink is not active", nil)
				if readerFault {
					if any(s.s.terminal) != any(failure) {
						t.Fatal("provider F was not terminal")
					}
					tsConsumed(t, s.s, s.o, 1, failure)
				} else {
					if s.s.state != storeOPEN || s.s.terminal != nil {
						t.Fatal("clean provider unwind consumed Store")
					}
					tsFollowing(t, s.s, s.o)
				}
				s.durable(t, false)
			})
		}
	}
}

func TestTreeStreamReadbackResultsV1(t *testing.T) {
	for _, mode := range []string{"error", "panic", "larger-stream"} {
		t.Run(mode, func(t *testing.T) {
			s := tsfNew(t)
			marker := errors.New("readback provider")
			value := new(int)
			var before, after uint64
			s.p[1].before = func(pos TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
				if pos != 2 {
					return nil
				}
				before = reservationLive(s.o)
				switch mode {
				case "error":
					return marker
				case "panic":
					panic(value)
				case "larger-stream":
					err := sink.BeginV1(TreeBlockV1{TxCount: 1, EventCount: 10_000})
					after = reservationLive(s.o)
					return err
				}
				return nil
			}
			if mode == "larger-stream" {
				// Writer EventCount10 is satisfied by ten distinct CREATE outputs.
				s.p[1].block.EventCount = 10
				s.p[1].events = nil
				for vout := uint32(0); vout < 10; vout++ {
					e := tsfCreate(tdTxid(0x20), 0, 12)
					e.Outpoint.Vout = vout
					s.p[1].events = append(s.p[1].events, e)
				}
			}
			var r tsResult
			if mode == "panic" {
				var got any
				func() { defer func() { got = recover() }(); r = s.crossed(t) }()
				if got != value {
					t.Fatal("readback panic identity")
				}
			} else {
				r = s.crossed(t)
				r.tuple(t, 3, 3, -1)
				var ce *CommitError
				if !errors.As(r.err, &ce) || ce.Truth != 3 {
					t.Fatalf("readback CommitError %v", r.err)
				}
				treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
				if mode == "error" && any(ce.ReadbackCause) != any(marker) {
					t.Fatalf("ReadbackCause identity %v", ce.ReadbackCause)
				}
				if mode == "larger-stream" && (any(ce.ReadbackCause) != any(errOperationReservationCapacity) || before != after) {
					t.Fatalf("readback budget %v live%d->%d", ce.ReadbackCause, before, after)
				}
			}
			if s.p[2].calls[2] != 0 || s.s.state != storeCLOSED || s.s.terminalTruth != 3 || reservationLive(s.o) != 0 {
				t.Fatal("readback result disposition")
			}
			tsConsumed(t, s.s, s.o, 3, s.s.terminal)
			s.durable(t, true)
		})
	}
}

// tsfFill starts ordinary competing operations, each bounded by TREE_LANE_MAX,
// and returns their explicit release. It never changes reservation internals.
func tsfFill(t *testing.T, o *OperationReservationOwner, n uint64) func() {
	t.Helper()
	release, entered := make(chan struct{}), make(chan error)
	var wg sync.WaitGroup
	for n != 0 {
		chunk := min(n, uint64(402_653_184))
		n -= chunk
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				return a.WithReservation(chunk, func() error { entered <- nil; <-release; return nil })
			})
			if err != nil {
				entered <- err
			}
		}()
		if err := <-entered; err != nil {
			close(release)
			wg.Wait()
			t.Fatalf("competing reserve %v", err)
		}
	}
	return func() { close(release); wg.Wait() }
}

// A7: four fixed native boundaries observe complete Pair PC through OLD cleanup.
func TestTreeStreamPairHoldNativeBoundariesV1(t *testing.T) {
	for _, short := range []uint64{1, 0} {
		t.Run(fmt.Sprintf("free-G-plus-PC-minus%d", short), func(t *testing.T) {
			s, path, o := tsNew(t)
			op := tsPair(33)
			m := op.Pair.Mutations[0]
			pc := uint64(len(m.Key) + len(m.Literal) + 128)
			filler := uint64(805_306_368) - 154_611_151 - pc + short
			reservationFill(t, o, filler)
			var r tsResult
			evidence, err := FixtureSelectedDamage(s, o, SelectedDamageProbeOnly, 6, m.Key, func() {
				r = tsRun(t, s, o, TreeOperation, op)
			})
			mustEnvironment(t, err)
			r.tuple(t, 2, 3, -1)
			mustEnvironment(t, r.err)
			if evidence.BeginOld != 1 || evidence.BeginWrite != 1 || evidence.BeginRead != 0 || evidence.Commits != 1 || evidence.OldAborts != 1 || evidence.Faults != 0 {
				t.Fatalf("pair-only native lifecycle %+v", evidence)
			}
			if evidence.Probes != 4 || evidence.ProbeDenied != 4*short || evidence.ProbeRan != 4*(1-short) {
				t.Fatalf("Pair PC native probes short%d: %+v", short, evidence)
			}
			if reservationLive(o) != filler {
				t.Fatal("Pair PC not released after OLD cleanup")
			}
			tsRead(t, tsReopen(t, s, path), m.DBI, m.Key, m.Literal)
		})
	}
}

func TestTreeStreamNoReadbackAccountDrawV1(t *testing.T) {
	s := tsfNew(t)
	var held, filler uint64
	var release func()
	s.p[0].before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
		if pos == 2 {
			held = reservationLive(s.o)
			filler = 805_306_368 - held
			release = tsfFill(t, s.o, filler)
			if reservationLive(s.o) != 805_306_368 {
				t.Error("competitor did not fill remainder")
			}
		}
		return nil
	}
	s.p[1].before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
		if pos == 2 && reservationLive(s.o) != 805_306_368 {
			t.Error("account changed during replay")
		}
		return nil
	}
	s.p[2].after = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
		if pos == 2 && reservationLive(s.o) != 805_306_368 {
			t.Error("account changed before replay completed")
		}
		return nil
	}
	var r tsResult
	evidence, err := fixtureLargeFault(s.s, 12, 0, []byte{9}, func() {
		mustEnvironment(t, s.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
			r = tsInvoke(s.s, a, func(*Reader) (TreeOperationV1, error) { return s.op, nil })
			if reservationLive(s.o) != filler {
				t.Error("engine hold not released before result")
			}
			release()
			return nil
		}))
	})
	mustEnvironment(t, err)
	r.tuple(t, 2, 3, -1)
	tcCrossedCause(t, r.err, 2, nil)
	if evidence.commits != 1 || held == 0 || reservationLive(s.o) != 0 {
		t.Fatal("readback account closure")
	}
	s.durable(t, true)
}

func TestTreeStreamNestedProviderReservationV1(t *testing.T) {
	s := tsfNew(t)
	var account *OperationAccount
	var before, during, after uint64
	s.p[0].before = func(_ TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
		before = reservationLive(s.o)
		err := account.WithReservation(17, func() error { during = reservationLive(s.o); return nil })
		after = reservationLive(s.o)
		return err
	}
	var r tsResult
	mustEnvironment(t, s.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
		account = a
		r = tsInvoke(s.s, a, func(*Reader) (TreeOperationV1, error) { return s.op, nil })
		return nil
	}))
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	if during != before+17 || after != before || reservationLive(s.o) != 0 {
		t.Fatalf("nested sums %d/%d/%d", before, during, after)
	}
	for _, p := range s.p {
		if p.reader.usable() || p.sink.WindowV1() != nil {
			t.Fatal("provider escaped active object")
		}
		tsExpiredReader(t, p.reader)
		treeNativeError(t, p.sink.BeginV1(TreeBlockV1{TxCount: 1}), "update", "InvalidInput", 22, "tree delta sink is not active", nil)
	}
	s.durable(t, true)
}

func TestTreeStreamCallbackCleanupDispositionV1(t *testing.T) {
	for _, mode := range []uint32{9, 10} {
		for _, delivery := range []string{"error", "panic", "goexit"} {
			t.Run(fmt.Sprintf("cleanup%d-%s", mode, delivery), func(t *testing.T) {
				s, path, o := tsNew(t)
				marker := errors.New("callback primary")
				value := new(int)
				var kept *Reader
				var r tsResult
				post := false
				run := func() {
					_, err := fixtureLargeFault(s, mode, 0, []byte{2}, func() {
						_ = o.WithOperation(TreeOperation, func(a *OperationAccount) error {
							r = tsInvoke(s, a, func(reader *Reader) (TreeOperationV1, error) {
								kept = reader
								switch delivery {
								case "panic":
									panic(value)
								case "goexit":
									runtime.Goexit()
								}
								return TreeOperationV1{}, marker
							})
							return nil
						})
					})
					mustEnvironment(t, err)
					post = true
				}
				if delivery == "goexit" {
					done := make(chan struct{})
					go func() { defer close(done); run() }()
					<-done
				} else if delivery == "panic" {
					var got any
					func() { defer func() { got = recover() }(); run() }()
					if got != value {
						t.Fatal("cleanup changed panic")
					}
				} else {
					run()
					r.tuple(t, 1, 1, -1)
					if !errors.Is(r.err, marker) {
						t.Fatal("cleanup lost callback primary")
					}
				}
				if delivery != "error" && post {
					t.Fatal("cleanup delivered post-call statement")
				}
				if kept == nil || kept.usable() || reservationLive(o) != 0 || s.terminal == nil || s.terminalTruth != 1 {
					t.Fatal("cleanup ownership projection")
				}
				if mode == 9 {
					tsConsumed(t, s, o, 1, s.terminal)
				} else {
					if s.state != storePOISONEDTHREAD || s.txn == nil {
						t.Fatal("retained OLD not projected")
					}
					calls := 0
					_ = o.WithOperation(TreeOperation, func(a *OperationAccount) error {
						next := tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { calls++; return tsPair(88), nil })
						if any(next.err) != any(s.terminal) || calls != 0 {
							t.Error("poisoned Store reused")
						}
						return nil
					})
					terminal := s.terminal
					_ = fixtureLargeRelease(s)
					if s.state != storeCLOSED || any(s.terminal) != any(terminal) {
						t.Fatal("retained fixture teardown")
					}
				}
				tsRead(t, tsReopen(t, s, path), TreeSchemaV1DBIs()[6], tsTarget(88).Key, nil)
			})
		}
	}
}

func TestTreeStreamLiteralRootsV1(t *testing.T) {
	s, path, o := tsNew(t)
	tsRoots(t, s, o, 1)
	block := tdTxid(0xa1)
	treeNativeSeed(t, s, 4, block[:], []byte{0})
	treeNativeSeed(t, s, 5, tdManifestKey(block), tdManifest(1, [16]byte{}, 2, 3))
	keys := [][36]byte{testKA, testKB, testKC}
	events := make([]TreeEventV1, 3)
	for i, key := range keys {
		var txid [32]byte
		copy(txid[:], key[:32])
		vout := binary.BigEndian.Uint32(key[32:])
		events[i] = TreeEventV1{Kind: 1, Outpoint: TreeOutpointV1{Txid: txid, Vout: vout}, TxIndex: 1, InputIndex: uint32(i)}
		treeNativeSeed(t, s, 5, tdEntryKey(block, txid, 1, uint32(i), vout), testTreeE())
	}
	endpoint := TreeEndpointV1{Kind: 1, Height: 0, BlockHash: tdTxid(0xa0), CumulativeChainwork: [40]byte{4: 1, 39: 37}}
	provider := &tsfProvider{block: TreeBlockV1{TxCount: 2, EventCount: 3}, events: events}
	op := TreeOperationV1{Primitives: []TreePrimitiveV1{{Direction: 2, Kind: 7, Generation: 1, Block: block, Height: 1, Source: provider, Undo: 5, Endpoint: endpoint}}}
	r := tsRun(t, s, o, TreeOperation, op)
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	s = tsReopen(t, s, path)
	c02 := testTreeHex(t, "14bd6311f35ed9534d8cd8a101bc09c5d289978e393e775271fd9e446c8cde8d")
	c03 := testTreeHex(t, "480f5e45ffbf5dbc0ec499ef7574c3379e26ab4ffb25220df9eb023b057526cc")
	tsRead(t, s, TreeSchemaV1DBIs()[8], testTreeNodeKey(1, 288, testKA), c02[:])
	tsRead(t, s, TreeSchemaV1DBIs()[8], testTreeNodeKey(1, 288, testKB), c03[:])
	mustEnvironment(t, s.View(func(reader *Reader) error {
		b, _, err := reader.Get(TreeSchemaV1DBIs()[0], tsRootKey(1))
		if err != nil {
			return err
		}
		binding, err := DecodeRootBindingV1(b)
		if err != nil {
			return err
		}
		if binding.RootDigest != testTreeHex(t, "0dbb5487445845169a856b31fe2877c6cb84df41cc170f6ae9c41d062164fd7d") || binding.Endpoint != endpoint {
			t.Fatal("C06 or endpoint changed")
		}
		node, _, err := reader.Get(TreeSchemaV1DBIs()[8], testTreeNodeKey(1, 0, [36]byte{}))
		if err != nil {
			return err
		}
		c05 := testTreeHex(t, "fc8c011e40853708f49a90759af0c9e5b738e3116dca9ed641539af0827cf9ac")
		if len(node) != 140 || !bytes.Equal(node[38:70], c05[:]) {
			t.Fatal("C05 zero-child digest")
		}
		return nil
	}))
	for i, e := range events {
		tsRead(t, s, TreeSchemaV1DBIs()[1], tdUTXOKey(1, e.Outpoint.Txid, e.Outpoint.Vout), testTreeE())
		tsRead(t, s, TreeSchemaV1DBIs()[5], tdEntryKey(block, e.Outpoint.Txid, 1, uint32(i), e.Outpoint.Vout), testTreeE())
	}
	// Remove B/C, then the last entry A, through two admitted forward operations.
	for j, group := range [][]TreeEventV1{{events[1], events[2]}, {events[0]}} {
		b := tdTxid(byte(0xd1 + j))
		treeNativeSeed(t, s, 4, b[:], []byte{0})
		for i := range group {
			group[i].InputIndex = uint32(i)
		}
		p := &tsfProvider{block: TreeBlockV1{TxCount: 2, EventCount: uint32(len(group))}, events: group}
		ep := TreeEndpointV1{Kind: 1, Height: uint64(j + 2), BlockHash: b, CumulativeChainwork: [40]byte{39: byte(j + 40)}}
		deleteOp := TreeOperationV1{Primitives: []TreePrimitiveV1{{Direction: 1, Kind: 1, Generation: 1, Block: b, Height: uint64(j + 2), Source: p, Undo: 2, Endpoint: ep}}}
		r = tsRun(t, s, o, TreeOperation, deleteOp)
		r.tuple(t, 2, 3, -1)
		mustEnvironment(t, r.err)
	}
	s = tsReopen(t, s, path)
	mustEnvironment(t, s.View(func(reader *Reader) error {
		b, _, err := reader.Get(TreeSchemaV1DBIs()[0], tsRootKey(1))
		if err != nil {
			return err
		}
		root, err := DecodeRootBindingV1(b)
		if err != nil {
			return err
		}
		if root.RootDigest != testTreeHex(t, "0a978e2cf0e03934b2ec7c369b301f8f3a687aed501227a7af76730a8e64f8bb") || root.Top.Kind != 0 {
			t.Fatal("C01 after last deletion")
		}
		return nil
	}))
}

func TestTreeStreamEvidenceTargetsV1(t *testing.T) {
	for _, after := range []AfterKind{1, 2} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			s, path, o := tsNew(t)
			evidence := TreeEvidenceV1{OriginalDatabaseID: [32]byte{7}, OriginalCurrentID: 1, OriginalLagID: 2, Payload: []byte{4, 5}}
			value, err := evidence.Encode()
			mustEnvironment(t, err)
			hash := sha3.Sum256(value)
			key := append([]byte{0x12}, hash[:]...)
			treeNativeSeed(t, s, 0, key, value)
			m := Mutation{DBI: TreeSchemaV1DBIs()[0], Key: key, BeforePresent: true, AfterKind: after}
			if after == 2 {
				m.Literal = bytes.Clone(value)
			}
			r := tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{m}}})
			tsRefusal(t, r, false)
			tsFollowing(t, s, o)
			s = tsReopen(t, s, path)
			tsRead(t, s, m.DBI, key, value)
			control := tsPair(43)
			control.Pair.Consulted = []ConsultedRow{{m.DBI, key}}
			r = tsRun(t, s, o, TreeOperation, control)
			r.tuple(t, 2, 3, -1)
			mustEnvironment(t, r.err)
		})
	}
}

func TestTreeStreamSinkFieldForwardingV1(t *testing.T) {
	s := tsfNew(t)
	s.p[0].block.Generated = [16]byte{0: 1, 15: 23}
	r := s.run(t)
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	s.durable(t, true)
}

func TestTreeStreamSinkKindRefusalsV1(t *testing.T) {
	for _, kind := range []TreeEventKindV1{0, 3, 255} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			s := tsfNew(t)
			s.p[0].custom = func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
				if err := sink.BeginV1(TreeBlockV1{TxCount: 1, EventCount: 1}); err != nil {
					return err
				}
				e := s.p[0].events[0]
				e.Kind = kind
				return sink.EventV1(e)
			}
			r := s.run(t)
			r.tuple(t, 1, 1, 0)
			treeNativeError(t, r.err, "update", "InvalidInput", 22, "invalid tree delta", nil)
			tsConsumed(t, s.s, s.o, 1, r.err)
			s.durable(t, false)
		})
	}
}

// P2/P3: CURRENT plus a stored two-block LAG burst; block 2 spends the output
// block 1 created, so it is absent from Lag After and one Undo[2] entry.
func TestTreeProofLagBurstV1(t *testing.T) {
	s := tsfNew(t)
	tsfCover(t, s)
	var log tsProofLog
	s.op.Proof = log.proof
	r := s.run(t)
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	current, spent, last := tdFormed(tdFrame(100, 0, nil), 10, 1), tdFormed(tdFrame(200, 0, []byte{1}), 5, 1), tdFormed(tdFrame(300, 0, nil), 6, 1)
	want := TreeDeltaReportV1{
		Current: TreeRoleDeltaV1{Present: true, Generation: 1, BytesAfter: tsEnvelope(current), CountAfter: 1},
		Lag:     TreeRoleDeltaV1{Present: true, Generation: 2, BytesAfter: tsEnvelope(last), CountAfter: 1},
		Undo:    []TreeUndoChargeV1{{Effect: TreeUndoFamilyWrittenV1}, {Effect: TreeUndoFamilyWrittenV1}, {Effect: TreeUndoFamilyWrittenV1, Entries: 1, Bytes: tsEnvelope(spent)}},
	}
	if log.calls != 1 || !reflect.DeepEqual(log.report, want) {
		t.Fatalf("burst report %+v want %+v", log.report, want)
	}
	s.durable(t, true)
	for _, role := range []TreeRoleDeltaV1{log.report.Current, log.report.Lag} {
		tsRead(t, s.s, TreeSchemaV1DBIs()[0], tsCounterKey(role.Generation), tsCounterLiteral(role.BytesAfter, role.CountAfter))
	}
	tsRead(t, s.s, TreeSchemaV1DBIs()[5], tdEntryKey(s.op.Primitives[2].Block, tdTxid(0x20), 1, 0, 0), spent)
}

// P8: Proof precedes the first flushV1 write.
func TestTreeProofBeforeFlushV1(t *testing.T) {
	s := tsfNew(t)
	tsfCover(t, s)
	var log tsProofLog
	s.op.Proof = log.proof
	var r tsResult
	evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamagePutEIO, 0, tsCounterKey(1), func() { r = s.run(t) })
	mustEnvironment(t, err)
	if evidence.Faults != 1 || evidence.Commits != 0 || log.calls != 1 {
		t.Fatalf("flush arm %+v Proof calls%d", evidence, log.calls)
	}
	r.tuple(t, 1, 2, -1)
}

// N3: the H_r capacity refusal precedes Proof.
func TestTreeProofAfterReserveV1(t *testing.T) {
	for _, short := range []uint64{1, 0} {
		t.Run(fmt.Sprintf("short%d", short), func(t *testing.T) {
			s := tsfNew(t)
			tsfCover(t, s)
			var log tsProofLog
			s.op.Proof = log.proof
			budgets := s.budgets(t)
			pc := uint64(128+32+len(s.op.Pair.Mutations[0].Literal)) + 152 + 3*24
			filler := uint64(402_653_184) - pc - budgets[2] - 131_192 - 288_408 - 208 + short
			var r tsResult
			mustEnvironment(t, s.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				return a.WithReservation(filler, func() error {
					r = tsInvoke(s.s, a, func(*Reader) (TreeOperationV1, error) { return s.op, nil })
					return nil
				})
			}))
			if short == 0 {
				r.tuple(t, 2, 3, -1)
				if log.calls != 1 {
					t.Fatalf("passing reserve Proof calls%d", log.calls)
				}
				return
			}
			r.tuple(t, 1, 1, -1)
			if any(r.err) != any(errOperationReservationCapacity) || log.calls != 0 {
				t.Fatalf("H_r refusal %v Proof calls%d", r.err, log.calls)
			}
			tsConsumed(t, s.s, s.o, 1, r.err)
			s.durable(t, false)
		})
	}
}

// N3: a freezeV1 drift precedes Proof. CURRENT inserts the first leaf of an
// empty generation-1 tree, so its rank-8 leaf row enters P through the unchecked
// emitter read only; the first OLD/write comparison of that row is freezeV1.
func TestTreeProofAfterFreezeDriftV1(t *testing.T) {
	s := tsfNew(t)
	tsfCover(t, s)
	var log tsProofLog
	s.op.Proof = log.proof
	leaf := testTreeNodeKey(1, 288, tcEntry(tdUTXOKey(1, tdTxid(0x10), 0), nil).k)
	var r tsResult
	count, err := FixtureWriteSnapshotDrift(s.s, 8, leaf, func() { r = s.run(t) })
	mustEnvironment(t, err)
	if count != 1 || log.calls != 0 {
		t.Fatalf("freeze drift count%d Proof calls%d", count, log.calls)
	}
	for j, p := range s.p {
		if p.calls != [3]int{0, 1, 0} {
			t.Fatalf("primitive %d Source calls%v before freeze", j, p.calls)
		}
	}
	r.tuple(t, 1, 1, -1)
	treeNativeError(t, r.err, "update", "StateMismatch", -30779, "OLD/write snapshot mismatch", nil)
	tsConsumed(t, s.s, s.o, 1, r.err)
}

// N5: a Proof panic or Goexit takes the writer unwind with index -1, no write,
// a released account and an OPEN Store.
func TestTreeProofUnwindV1(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			s := tsfNew(t)
			tsfCover(t, s)
			value, calls := new(int), 0
			s.op.Proof = func(*TreeDeltaReportV1) error {
				calls++
				if mode == "goexit" {
					runtime.Goexit()
				}
				panic(value)
			}
			var r tsResult
			var unwind treeUnwindV1
			var accountErr error
			done := make(chan struct{})
			go func() {
				defer close(done)
				accountErr = s.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
					s.s.operations.Lock()
					defer s.s.operations.Unlock()
					r.truth, r.stage, r.index, unwind, r.err = s.s.treeEntryLockedV1(a, func(*Reader) (TreeOperationV1, error) { return s.op, nil })
					return nil
				})
			}()
			<-done
			mustEnvironment(t, accountErr)
			r.tuple(t, 1, 1, -1)
			kind := uint8(1)
			if mode == "goexit" {
				kind = 2
			}
			if calls != 1 || r.err != nil || unwind.kind != kind || (kind == 1 && unwind.value != value) {
				t.Fatalf("Proof unwind calls%d err%v unwind%+v", calls, r.err, unwind)
			}
			if s.s.state != storeOPEN || s.s.terminal != nil || reservationLive(s.o) != 0 {
				t.Fatal("Proof unwind lifecycle")
			}
			tsFollowing(t, s.s, s.o)
			s.durable(t, false)
		})
	}
}

// P1 call count at readback: a commit that reaches the readback evaluator
// still calls Proof once, at the writer only.
func TestTreeProofNotAtReadbackV1(t *testing.T) {
	s := tsfNew(t)
	tsfCover(t, s)
	var log tsProofLog
	s.op.Proof = log.proof
	var r tsResult
	_, err := FixtureSelectedDamage(s.s, s.o, SelectedDamageCommitNew, 0, tsCounterKey(2), func() { r = s.run(t) })
	mustEnvironment(t, err)
	if r.stage != 3 {
		t.Fatalf("commit did not cross: %+v", r)
	}
	if log.calls != 1 || s.p[0].calls[TreeReadbackV1] != 1 {
		t.Fatalf("Proof calls%d readback Source calls%d", log.calls, s.p[0].calls[TreeReadbackV1])
	}
}

// tsfSlot is the covered LAG burst with a counting Proof that returns nil and a valid
// header slot whose row x is absent from ORIGINAL.
func tsfSlot(t *testing.T) (*tsfScene, *tsProofLog, []byte, []byte) {
	t.Helper()
	s := tsfNew(t)
	tsfCover(t, s)
	log := &tsProofLog{}
	s.op.Proof = log.proof
	s.op.HeaderSlot = tsSlot(t)
	return s, log, bytes.Clone(s.op.HeaderSlot.Hash[:]), bytes.Clone(s.op.HeaderSlot.Header[:])
}

// tsfSlotUnreached requires an armed keyed site the attempt never reached.
func tsfSlotUnreached(t *testing.T, evidence SelectedDamageEvidence, err error) {
	t.Helper()
	if err == nil || err.Error() != "selected damage fixture site was not reached exactly as armed" || evidence.Faults != 0 {
		t.Fatalf("armed slot site reached: %v evidence%+v", err, evidence)
	}
}

func tsfSlotDiffers(t *testing.T, err error) {
	t.Helper()
	treeNativeError(t, err, "update", "StateMismatch", -30779, "tree header slot differs", nil)
	if engine, _ := directTestEngineError(err); engine.TreeObservation != nil {
		t.Fatal("slot refusal carries a tree observation")
	}
}

// tsfDump is every committed row of every rank, keyed "rank/key".
func tsfDump(t *testing.T, s *Store) map[string]string {
	t.Helper()
	rows := map[string]string{}
	mustEnvironment(t, s.View(func(r *Reader) error {
		for rank := range r.dbis {
			for from := []byte{0}; ; {
				key, value, ok, err := treeReadNextV1(r.txn, r.dbis[rank], from)
				if err != nil || !ok {
					if err != nil {
						return err
					}
					break
				}
				rows[fmt.Sprintf("%d/%x", rank, key)] = string(value.value)
				from = append(bytes.Clone(key), 0)
			}
		}
		return nil
	}))
	return rows
}

// P1: an absent row x is inserted with Header; the complete committed store
// otherwise equals the same burst run with HeaderSlot nil.
func TestTreeHeaderSlotAbsentV1(t *testing.T) {
	s, log, key, header := tsfSlot(t)
	r := s.run(t)
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	if log.calls != 1 {
		t.Fatalf("Proof calls%d", log.calls)
	}
	got := tsfDump(t, s.s)
	base, _, _, _ := tsfSlot(t)
	base.op.HeaderSlot = nil
	r = base.run(t)
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	want := tsfDump(t, base.s)
	x := fmt.Sprintf("3/%x", key)
	if got[x] != string(header) {
		t.Fatal("row x is not Header")
	}
	delete(got, x)
	if !reflect.DeepEqual(got, want) || len(want) == 0 {
		t.Fatalf("slot run store differs from HeaderSlot-nil run: %d vs %d rows", len(got), len(want))
	}
	s.durable(t, true)
	tsRead(t, s.s, TreeSchemaV1DBIs()[3], key, header)
}

// P2: a byte-identical row x is reused: NEW with no put at x.
func TestTreeHeaderSlotIdenticalV1(t *testing.T) {
	s, log, key, header := tsfSlot(t)
	treeNativeSeed(t, s.s, 3, key, header)
	var r tsResult
	evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamagePutEIO, 3, key, func() { r = s.run(t) })
	tsfSlotUnreached(t, evidence, err)
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	if log.calls != 1 || evidence.Commits != 1 {
		t.Fatalf("Proof calls%d evidence%+v", log.calls, evidence)
	}
	s.durable(t, true)
	tsRead(t, s.s, TreeSchemaV1DBIs()[3], key, header)
}

// P4: the first ORIGINAL OLD read of x follows Proof and precedes every write.
func TestTreeHeaderSlotAfterProofV1(t *testing.T) {
	s, log, key, _ := tsfSlot(t)
	var r tsResult
	evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamageGetEIO, 3, key, func() { r = s.run(t) })
	mustEnvironment(t, err)
	if evidence.Faults != 1 || evidence.Deletes != 0 || evidence.Commits != 0 || log.calls != 1 {
		t.Fatalf("slot read evidence%+v Proof calls%d", evidence, log.calls)
	}
	r.tuple(t, 1, 1, -1)
	treeNativeError(t, r.err, "update", "IO", 5, "error 5", nil)
	tsConsumed(t, s.s, s.o, 1, r.err)
}

// P5: the readback compares row x for an insert and for a reuse.
func TestTreeHeaderSlotReadbackV1(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reuse%v", reuse), func(t *testing.T) {
			s, _, key, header := tsfSlot(t)
			if reuse {
				treeNativeSeed(t, s.s, 3, key, header)
			}
			var r tsResult
			evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamageCommitUnreadable, 3, key, func() { r = s.run(t) })
			mustEnvironment(t, err)
			r.tuple(t, 3, 3, -1)
			var ce *CommitError
			if !errors.As(r.err, &ce) || ce.Truth != 3 || evidence.Faults != 2 || evidence.Commits != 1 {
				t.Fatalf("slot readback %v evidence%+v", r.err, evidence)
			}
			// Position: the resolution runs once and is not repeated at readback.
			// Rank-3 ORIGINAL OLD gets: none in this scene without a slot, two
			// in the resolution (equality, classification), then two more before
			// the readback's read-transaction get of x faults. Insert: the
			// readback target image pass and the OLD side of its target
			// equality. Reuse: finalV1's Consulted match and the OLD side of the
			// readback Consulted equality.
			if evidence.OldGets[3] != 4 {
				t.Fatalf("rank-3 ORIGINAL OLD gets %d, want 4", evidence.OldGets[3])
			}
			tsConsumed(t, s.s, s.o, 3, r.err)
		})
	}
}

// P6: a writer-position Source that rewrites the caller's slot after
// admission does not reach the owned copy.
func TestTreeHeaderSlotAliasV1(t *testing.T) {
	s, _, key, header := tsfSlot(t)
	slot := s.op.HeaderSlot
	s.p[0].before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
		if pos == TreeWriterV1 {
			slot.Hash[0] ^= 1
			slot.Header[0] ^= 1
		}
		return nil
	}
	r := s.run(t)
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	s.durable(t, true)
	tsRead(t, s.s, TreeSchemaV1DBIs()[3], key, header)
	tsRead(t, s.s, TreeSchemaV1DBIs()[3], slot.Hash[:], nil)
}

// N1/N2: a differing row x, at the same width, at 116 bytes or empty, refuses
// with no write, consumes the Store and leaves the row unchanged.
func TestTreeHeaderSlotDiffersV1(t *testing.T) {
	for _, row := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"byte147", func(h []byte) []byte { h[147] ^= 1; return h }},
		{"width116", func(h []byte) []byte { return h[:116] }},
		{"empty", func([]byte) []byte { return []byte{} }},
	} {
		t.Run(row.name, func(t *testing.T) {
			s, log, key, header := tsfSlot(t)
			stored := row.edit(bytes.Clone(header))
			treeNativeSeed(t, s.s, 3, key, stored)
			var r tsResult
			evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamagePutEIO, 3, key, func() { r = s.run(t) })
			tsfSlotUnreached(t, evidence, err)
			r.tuple(t, 1, 1, -1)
			tsfSlotDiffers(t, r.err)
			if log.calls != 1 || evidence.Deletes != 0 || evidence.Commits != 0 {
				t.Fatalf("Proof calls%d evidence%+v", log.calls, evidence)
			}
			tsConsumed(t, s.s, s.o, 1, r.err)
			s.durable(t, false)
			if equal, err := FixtureRawRowEqual(s.s, 3, key, stored); err != nil || !equal {
				t.Fatalf("row x changed: equal%v %v", equal, err)
			}
		})
	}
}

// L1: an EIO from either ORIGINAL OLD read of an absent row x (mode 28: the
// OLD/write equality read; mode 1: the classification read) keeps that error
// unchanged on the Proof error route, with no write at x.
func TestTreeHeaderSlotReadFaultV1(t *testing.T) {
	for _, row := range []struct {
		name string
		mode uint32
		gets uint32
	}{{"equality", 28, 1}, {"classification", 1, 2}} {
		t.Run(row.name, func(t *testing.T) {
			s, log, key, _ := tsfSlot(t)
			var r tsResult
			evidence, err := fixtureLargeFault(s.s, row.mode, 3, key, func() { r = s.run(t) })
			mustEnvironment(t, err)
			r.tuple(t, 1, 1, -1)
			treeNativeError(t, r.err, "update", EngineIO, codeEIO, expectedNativeDiagnostic(codeEIO), nil)
			if log.calls != 1 || evidence.gets != row.gets || evidence.commits != 0 {
				t.Fatalf("Proof calls%d evidence%+v", log.calls, evidence)
			}
			tsConsumed(t, s.s, s.o, 1, r.err)
			s.durable(t, false)
			if _, present := tsfDump(t, s.s)[fmt.Sprintf("3/%x", key)]; present {
				t.Fatal("row x was written")
			}
		})
	}
}

// N6: a Proof error, a Proof panic and the H_r refusal each keep their result
// and leave row x unread.
func TestTreeHeaderSlotEarlierResultsV1(t *testing.T) {
	t.Run("proof-error", func(t *testing.T) {
		s, log, key, _ := tsfSlot(t)
		log.err = errors.New("proof refused")
		var r tsResult
		evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamageGetEIO, 3, key, func() { r = s.run(t) })
		tsfSlotUnreached(t, evidence, err)
		r.tuple(t, 1, 1, -1)
		if any(r.err) != any(log.err) || log.calls != 1 {
			t.Fatalf("Proof error %v calls%d", r.err, log.calls)
		}
		tsConsumed(t, s.s, s.o, 1, log.err)
	})
	t.Run("proof-panic", func(t *testing.T) {
		s, _, key, _ := tsfSlot(t)
		value := new(int)
		s.op.Proof = func(*TreeDeltaReportV1) error { panic(value) }
		var r tsResult
		var unwind treeUnwindV1
		evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamageGetEIO, 3, key, func() {
			mustEnvironment(t, s.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				s.s.operations.Lock()
				defer s.s.operations.Unlock()
				r.truth, r.stage, r.index, unwind, r.err = s.s.treeEntryLockedV1(a, func(*Reader) (TreeOperationV1, error) { return s.op, nil })
				return nil
			}))
		})
		tsfSlotUnreached(t, evidence, err)
		r.tuple(t, 1, 1, -1)
		if r.err != nil || unwind.kind != 1 || unwind.value != value || s.s.state != storeOPEN || reservationLive(s.o) != 0 {
			t.Fatalf("Proof panic %v unwind%+v state %s", r.err, unwind, s.s.state)
		}
	})
	t.Run("reserve", func(t *testing.T) {
		s, log, key, _ := tsfSlot(t)
		budgets := s.budgets(t)
		pc := uint64(128+32+len(s.op.Pair.Mutations[0].Literal)) + 152 + 3*24 + 128 + 32 + 148 + 48 + 32
		filler := uint64(402_653_184) - pc - budgets[2] - 131_192 - 288_408 - 208 + 1
		var r tsResult
		evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamageGetEIO, 3, key, func() {
			mustEnvironment(t, s.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				return a.WithReservation(filler, func() error {
					r = tsInvoke(s.s, a, func(*Reader) (TreeOperationV1, error) { return s.op, nil })
					return nil
				})
			}))
		})
		tsfSlotUnreached(t, evidence, err)
		r.tuple(t, 1, 1, -1)
		// The writer Source ran, so this is the H_r refusal, not the step-5 one.
		if any(r.err) != any(errOperationReservationCapacity) || log.calls != 0 || s.p[0].calls != [3]int{0, 1, 0} {
			t.Fatalf("H_r refusal %v Proof calls%d Source calls%v", r.err, log.calls, s.p[0].calls)
		}
		tsConsumed(t, s.s, s.o, 1, r.err)
	})
}

// H1: an OLD/write drift at x is the existing mismatch, checked before the
// row is classified.
func TestTreeHeaderSlotDriftV1(t *testing.T) {
	for _, differing := range []bool{false, true} {
		t.Run(fmt.Sprintf("differing%v", differing), func(t *testing.T) {
			s, log, key, header := tsfSlot(t)
			if differing {
				header[147] ^= 1
				treeNativeSeed(t, s.s, 3, key, header)
			}
			var r tsResult
			count, err := FixtureWriteSnapshotDrift(s.s, 3, key, func() { r = s.run(t) })
			mustEnvironment(t, err)
			if count != 1 || log.calls != 1 {
				t.Fatalf("drift count%d Proof calls%d", count, log.calls)
			}
			r.tuple(t, 1, 1, -1)
			treeNativeError(t, r.err, "update", "StateMismatch", -30779, "OLD/write snapshot mismatch", nil)
			tsConsumed(t, s.s, s.o, 1, r.err)
		})
	}
}

// tsfEntrySlotV1 runs one ENTRY operation on a fresh eisFixture with SelectedDamageGetEIO armed on (rank 3, x) for
// a valid slot x the ENTRY Visit does not read. build gets the completed token's Pair, the slot (nil for the
// control) and a counting Proof. It returns the result, the Proof calls and the post-run Store, account and ENTRY
// state.
func tsfEntrySlotV1(t *testing.T, withSlot bool, build func(TreePairV1, *TreeHeaderSlotV1, func(*TreeDeltaReportV1) error) TreeOperationV1) (tsResult, int, string) {
	t.Helper()
	f := eisNew(t, 3, 1, nil)
	target := eisCapture(t, f, 1, 1, false, false)
	slot := tsSlot(t)
	var r tsResult
	var token EntryInventoryV1
	proofs := 0
	proof := func(*TreeDeltaReportV1) error { proofs++; return nil }
	evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageGetEIO, 3, slot.Hash[:], func() {
		mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
			r = tsInvoke(f.s, a, func(rd *Reader) (TreeOperationV1, error) {
				token = eiPrepare(t, rd, a, target)
				failure, visitErr := rd.VisitEntryInventoryV1(token, func(EntryInventoryRowV1) error { return nil })
				if failure != nil || visitErr != nil || !token.scope.completed {
					t.Fatalf("ENTRY walk %+v/%v", failure, visitErr)
				}
				pair := target
				pair.EntryInventory = &token
				var s *TreeHeaderSlotV1
				if withSlot {
					s = slot
				}
				return build(pair, s, proof), nil
			})
			return nil
		}))
	})
	tsfSlotUnreached(t, evidence, err)
	state := fmt.Sprintf("%s/%v/%d/%v%v%v", f.s.state, f.s.terminal, reservationLive(f.o), token.scope.retired, token.scope.completed, token.scope.failed)
	for _, m := range target.Mutations {
		mustEnvironment(t, f.s.View(func(rd *Reader) error {
			value, present, err := rd.Get(m.DBI, m.Key)
			state += fmt.Sprintf("|%v%x", present, value)
			return err
		}))
	}
	return r, proofs, state
}

// N7: an ENTRY operation carrying a HeaderSlot keeps every ordinary, ENTRY and
// Proof-shape result, reaches the slot row only with zero primitives and Proof
// nil, and never resolves the slot.
func TestTreeHeaderSlotEntryV1(t *testing.T) {
	differ := func(pair TreePairV1, slot *TreeHeaderSlotV1, _ func(*TreeDeltaReportV1) error) TreeOperationV1 {
		pair.Consulted = []ConsultedRow{{DBI: TreeSchemaV1DBIs()[3], Key: bytes.Repeat([]byte{0x5a}, 32)}}
		return TreeOperationV1{Pair: pair, HeaderSlot: slot}
	}
	primitive := func(pair TreePairV1, slot *TreeHeaderSlotV1, proof func(*TreeDeltaReportV1) error) TreeOperationV1 {
		calls := 0
		p := tsProofShape(t, &calls, nil).Primitives[0]
		coverage := *p.Coverage
		coverage.BodyKind, coverage.CurrentBody = 2, nil // the ENTRY Pair stages no body
		p.Coverage = &coverage
		return TreeOperationV1{Primitives: []TreePrimitiveV1{p}, Pair: pair, Proof: proof, HeaderSlot: slot}
	}
	proofShape := func(pair TreePairV1, slot *TreeHeaderSlotV1, proof func(*TreeDeltaReportV1) error) TreeOperationV1 {
		return TreeOperationV1{Pair: pair, Proof: proof, HeaderSlot: slot}
	}
	slotRow := func(pair TreePairV1, slot *TreeHeaderSlotV1, _ func(*TreeDeltaReportV1) error) TreeOperationV1 {
		return TreeOperationV1{Pair: pair, HeaderSlot: slot}
	}
	rows := []struct {
		name  string
		build func(TreePairV1, *TreeHeaderSlotV1, func(*TreeDeltaReportV1) error) TreeOperationV1
		check func(*testing.T, tsResult)
	}{
		{"a-differing-target", differ, func(t *testing.T, r tsResult) { r.tuple(t, 1, 1, -1); eiInput(t, r.err) }},
		{"b-primitive", primitive, func(t *testing.T, r tsResult) { r.tuple(t, 1, 1, -1); eiInput(t, r.err) }},
		{"c-proof-shape", proofShape, func(t *testing.T, r tsResult) { tsRefusal(t, r, false) }},
	}
	var refusedC string
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r, proofs, state := tsfEntrySlotV1(t, true, row.build)
			control, controlProofs, controlState := tsfEntrySlotV1(t, false, row.build)
			row.check(t, r)
			row.check(t, control)
			if proofs != 0 || controlProofs != 0 || state != controlState {
				t.Fatalf("Proof calls %d/%d state %s, control %s", proofs, controlProofs, state, controlState)
			}
			refusedC = state
		})
	}
	t.Run("d-slot-row", func(t *testing.T) {
		r, proofs, state := tsfEntrySlotV1(t, true, slotRow)
		tsRefusal(t, r, false)
		if proofs != 0 || state != refusedC {
			t.Fatalf("Proof calls %d state %s, (c) refusal %s", proofs, state, refusedC)
		}
		control, _, controlState := tsfEntrySlotV1(t, false, slotRow)
		control.tuple(t, 2, 3, -1)
		mustEnvironment(t, control.err)
		if controlState == refusedC {
			t.Fatal("accepted ENTRY control left the refused state")
		}
	})
}
