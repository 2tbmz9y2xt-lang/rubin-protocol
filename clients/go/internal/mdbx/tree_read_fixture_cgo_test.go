//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"fmt"
	"testing"
)

func TestTreeRootReadFaultV1(t *testing.T) {
	t.Run("selectors-and-genesis", trSelectorsV1)
	t.Run("native-IO-and-next-Reader", trIOV1)
	t.Run("transient-complete-record", trMalformedV1)
	t.Run("application-error-is-not-native", trApplicationV1)
	t.Run("node-width-and-absence", trNodeV1)
	t.Run("Source-first-failure", trSourceFailureV1)
	t.Run("trusted-spent-leaf", trTrustedSpendV1)
	t.Run("binding-malformed", func(t *testing.T) {
		s, _, o := tsNew(t)
		request, _, _ := trRequestV1(t, 6)
		treeNativeSeed(t, s, 0, tsRootKey(1), []byte{0xff})
		trReadV1(t, s, o, request, func(reader *Reader, _ *OperationAccount, root [32]byte, err error) {
			var engine *EngineError
			if !errors.As(err, &engine) || engine.Class != EngineIntegrity || root != ([32]byte{}) || reader.usable() { t.Fatalf("malformed binding %x/%v", root, err) }
			want := TreeObservationV1{DatabaseID: [32]byte{7}, Generation: 1, Block: request.Primitive.Block, Height: 6, Primitive: 0, Position: 1, Rank: 0, KeyLength: 9, Kind: 2, OriginalImage: true, OriginalReference: true}
			copy(want.Key[:], tsRootKey(1))
			if engine.TreeObservation == nil || *engine.TreeObservation != want { t.Fatalf("binding observation %+v want %+v", engine.TreeObservation, want) }
		})
	})
}

func trTrustedSpendV1(t *testing.T) {
	s, _, o := tsNew(t)
	seed, _, frame := trRequestV1(t, 5)
	trPopulateV1(t, s, o, seed)
	op := TreeOutpointV1{Txid: tdTxid(37)}
	key := tdUTXOKey(1, op.Txid, 0)
	value := tdFormed(frame, 5, 1)
	binding := trBindingV1(t, 1, seed.Primitive.Endpoint, trEntryV1(key, value))
	leaf := sha3.Sum256(append(append([]byte("RUBIN_UTXO_TREE_V1\x01"), key[8:]...), value...))
	value[0]++ // A valid same-length field change; binding and leaf stay canonical.
	treeNativeSeed(t, s, 1, key, value)
	request, _, _ := trRequestV1(t, 6)
	request.Parent = seed.Primitive.Endpoint
	request.Inputs = []TreeResolvedInputV1{{Outpoint: op, Value: bytes.Clone(value)}}
	meta := TreeBlockV1{TxCount: 2, EventCount: 1}
	request.Primitive.Coverage.BlockMeta = meta
	request.Primitive.Source = tsSource(func(pos TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
		if pos != 1 {
			return fmt.Errorf("unexpected SPEND source position %d", pos)
		}
		if err := sink.BeginV1(meta); err != nil {
			return err
		}
		return sink.EventV1(TreeEventV1{Kind: 1, Outpoint: op, TxIndex: 1})
	})
	for range 2 {
		evidence, err := FixtureSelectedDamage(s, o, SelectedDamageProbeOnly, 0, nil, func() {
			trReadV1(t, s, o, request, func(reader *Reader, _ *OperationAccount, root [32]byte, err error) {
				mustEnvironment(t, err)
				if root != sha3.Sum256([]byte("RUBIN_UTXO_TREE_V1\x00")) {
					t.Fatalf("trusted last SPEND root %x", root)
				}
				if !reader.usable() || reader.failure != nil {
					t.Fatal("permitted local-trust SPEND disarmed Reader")
				}
			})
		})
		mustEnvironment(t, err)
		if evidence.OldGets != ([8]uint64{1, 1}) || evidence.NodeGets != 1 {
			t.Fatalf("SPEND point requests %+v", evidence)
		}
		if [6]uint64{evidence.BeginWrite, evidence.Commits, evidence.Deletes, evidence.NodePulls, evidence.Faults, reservationLive(o)} != ([6]uint64{}) || evidence.OldPulls != ([8]uint64{}) {
			t.Fatalf("SPEND range/write/resource effects %+v", evidence)
		}
	}
	for _, row := range []struct {
		rank       uint8
		key, value []byte
	}{
		{0, tsRootKey(1), binding}, {1, key, value},
		{8, testTreeNodeKey(1, 288, [36]byte(key[8:])), leaf[:]},
	} {
		equal, err := FixtureRawRowEqual(s, row.rank, row.key, row.value)
		mustEnvironment(t, err)
		if !equal {
			t.Fatalf("trusted SPEND changed canonical rank %d row", row.rank)
		}
	}
}

func trSourceFailureV1(t *testing.T) {
	for _, mode := range []string{"ignored", "returned", "wrapped", "panic"} {
		t.Run(mode, func(t *testing.T) {
			s, _, o := tsNew(t)
			request, _, _ := trRequestV1(t, 0)
			var first, returned error
			var recovered any
			panicValue := new(int)
			request.Primitive.Source = tsSource(func(_ TreePositionV1, reader *Reader, _ *TreeDeltaSinkV1) error {
				_, _, first = reader.Get(TreeSchemaV1DBIs()[0], []byte{2})
				switch mode {
				case "returned": returned = first
				case "wrapped": returned = fmt.Errorf("Source: %w", first)
				case "panic": panic(panicValue)
				}
				return returned
			})
			evidence, err := FixtureSelectedDamage(s, o, SelectedDamageGetEIO, 0, []byte{2}, func() {
				defer func() { recovered = recover() }()
				trReadV1(t, s, o, request, func(reader *Reader, _ *OperationAccount, root [32]byte, err error) {
					if root != ([32]byte{}) || reader.usable() || reader.failure != first { t.Fatal("Source native failure did not remain recorded") }
					if mode != "wrapped" && err != first { t.Fatal("Source first error identity changed") }
					if mode == "wrapped" {
						parts, ok := err.(interface{ Unwrap() []error })
						if !ok || len(parts.Unwrap()) != 2 || parts.Unwrap()[0] != returned || parts.Unwrap()[1] != first { t.Fatalf("Source primary order %v", err) }
					}
				})
			})
			mustEnvironment(t, err)
			if mode == "panic" && recovered != panicValue { t.Fatal("Source panic+failure changed") }
			if evidence.Faults != 1 || evidence.Deletes != 0 || evidence.Commits != 0 || reservationLive(o) != 0 { t.Fatalf("Source failure effects %+v", evidence) }
		})
	}
}

func trNodeV1(t *testing.T) {
	for _, variant := range []string{"absent", "width31", "width33", "digest", "identity"} {
		t.Run(variant, func(t *testing.T) {
			s, _, o := tsNew(t)
			request, _, _ := trRequestV1(t, 6)
			op := TreeOutpointV1{Txid: tdTxid(8)}
			key := tdUTXOKey(1, op.Txid, 0)
			value := tdFormed(tdFrame(7, 0, nil), 1, 0)
			treeNativeSeed(t, s, 1, key, value)
			treeNativeSeed(t, s, 0, tsRootKey(1), tcBinding(t, 1, request.Parent, tcEntry(key, value)))
			nodeKey := testTreeNodeKey(1, 288, [36]byte(key[8:]))
			kind := TreeObservationAbsentV1
			if variant != "absent" && variant != "identity" {
				n := 32
				if variant == "width31" { n = 31 }
				if variant == "width33" { n = 33 }
				treeNativeSeed(t, s, 8, nodeKey, make([]byte, n))
				kind = TreeObservationMalformedV1
				if variant == "digest" { kind = TreeObservationDigestMismatchV1 }
			}
			if variant == "identity" {
				entries := []testTreeEntry{tcEntry(key, value), tcEntry(tdUTXOKey(1, tdTxid(200), 0), tdFormed(tdFrame(8, 0, nil), 1, 0))}
				rows := map[string][]byte{}
				top := testTreeBuild(1, entries, rows)
				nodeKey = testTreeNodeKey(1, top.depth, top.key)
				branch := rows[fmt.Sprintf("8:%x", nodeKey)]
				copy(branch[70:108], branch[:38])
				treeNativeSeed(t, s, 0, tsRootKey(1), tcBinding(t, 1, request.Parent, entries...))
				treeNativeSeed(t, s, 8, nodeKey, branch)
				kind = TreeObservationIdentityMismatchV1
			}
			request.Inputs = []TreeResolvedInputV1{{Outpoint: op, Value: value}}
			meta := TreeBlockV1{TxCount: 2, EventCount: 1}
			request.Primitive.Coverage.BlockMeta = meta
			request.Primitive.Source = tsSource(func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
				if err := sink.BeginV1(meta); err != nil { return err }
				return sink.EventV1(TreeEventV1{Kind: 1, Outpoint: op, TxIndex: 1})
			})
			trReadV1(t, s, o, request, func(reader *Reader, _ *OperationAccount, root [32]byte, err error) {
				var engine *EngineError
				if !errors.As(err, &engine) || engine.Class != EngineIntegrity || root != ([32]byte{}) || reader.usable() { t.Fatalf("node result %x/%v", root, err) }
				want := TreeObservationV1{DatabaseID: [32]byte{7}, Generation: 1, Block: request.Primitive.Block, Height: 6, Primitive: 0, Position: 1, Rank: 8, KeyLength: 46, Kind: kind, OriginalImage: true, OriginalReference: true}
				copy(want.Key[:], nodeKey)
				if engine.TreeObservation == nil || *engine.TreeObservation != want { t.Fatalf("node observation %+v want %+v", engine.TreeObservation, want) }
			})
		})
	}
}

func trSelectorsV1(t *testing.T) {
	for _, height := range []uint64{0, 6} {
		t.Run(fmt.Sprint(height), func(t *testing.T) {
			s, _, o := tsNew(t)
			request, _, _ := trRequestV1(t, height)
			treeNativeSeed(t, s, 0, tsRootKey(1), tcBinding(t, 1, request.Parent))
			treeNativeSeed(t, s, 0, tsCounterKey(1), []byte{0xff})
			evidence, err := FixtureSelectedDamage(s, o, SelectedDamageProbeOnly, 0, nil, func() {
				trReadV1(t, s, o, request, func(_ *Reader, _ *OperationAccount, _ [32]byte, err error) { mustEnvironment(t, err) })
			})
			mustEnvironment(t, err)
			if evidence.BeginWrite != 0 || evidence.Commits != 0 || evidence.Deletes != 0 || evidence.NodePulls != 0 || evidence.OldPulls != ([8]uint64{}) {
				t.Fatalf("D performed range/write requests: %+v", evidence)
			}
			want := [8]uint64{}
			if height != 0 { want[0], want[1] = 1, 1 }
			if evidence.OldGets != want || evidence.NodeGets != 0 {
				t.Fatalf("parent selectors %+v, want %v and zero nodes", evidence, want)
			}
			var points uint64
			for _, n := range evidence.OldGets { points += n }
			points += evidence.NodeGets
			if height != 0 && points > 578 { t.Fatal("captured 577E+1 point ceiling exceeded") }
		})
	}
}

func trIOV1(t *testing.T) {
	s, path, o := tsNew(t)
	request, _, frame := trRequestV1(t, 6)
	binding := tcBinding(t, 1, request.Parent)
	treeNativeSeed(t, s, 0, tsRootKey(1), binding)
	var raw error
	evidence, err := FixtureSelectedDamage(s, o, SelectedDamageGetEIO, 0, tsRootKey(1), func() {
		trReadV1(t, s, o, request, func(reader *Reader, account *OperationAccount, root [32]byte, cause error) {
			raw = cause
			treeNativeError(t, cause, "update", "IO", 5, "error 5", nil)
			var engine *EngineError
			if !errors.As(cause, &engine) || engine.TreeObservation != nil || root != ([32]byte{}) || reader.usable() || reader.failure != cause {
				t.Fatal("unavailable D fabricated localization/result or lost failure")
			}
			_, next := reader.DeriveTreeRootV1(account, request)
			if next == nil || reader.failure != raw { t.Fatal("failed Reader allowed sibling") }
		})
	})
	mustEnvironment(t, err)
	if evidence.Faults != 1 || evidence.Commits != 0 || evidence.Deletes != 0 { t.Fatalf("native IO counts %+v", evidence) }
	s = tsReopen(t, s, path)
	equal, err := FixtureRawRowEqual(s, 0, tsRootKey(1), binding)
	if err != nil || !equal { t.Fatal("native IO changed canonical binding") }
	trReadV1(t, s, o, request, func(_ *Reader, _ *OperationAccount, root [32]byte, err error) {
		mustEnvironment(t, err)
		if root != trWantRootV1(t, frame, 6) { t.Fatal("fresh Reader did not derive afresh") }
	})
}

func trMalformedV1(t *testing.T) {
	good := tdFormed(tdFrame(7, 0, []byte{3}), 1, 0)
	badCoinbase := bytes.Clone(good)
	badCoinbase[len(badCoinbase)-1] = 2
	badCompact := append(bytes.Clone(good[:10]), 253, 1, 0)
	badCompact = append(badCompact, good[11:]...)
	for _, tc := range []struct { name string; value []byte }{
		{"short", good[:19]},
		{"oversized-before-copy", make([]byte, 65561)},
		{"nonminimal-length", badCompact},
		{"truncated-data", good[:len(good)-1]},
		{"coinbase-tag", badCoinbase},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, o := tsNew(t)
			request, _, _ := trRequestV1(t, 6)
			op := TreeOutpointV1{Txid: tdTxid(8)}
			key := tdUTXOKey(1, op.Txid, 0)
			treeNativeSeed(t, s, 1, key, tc.value)
			request.Inputs = []TreeResolvedInputV1{{Outpoint: op, Value: good}}
			meta := TreeBlockV1{TxCount: 2, EventCount: 1}
			request.Primitive.Coverage.BlockMeta = meta
			request.Primitive.Source = tsSource(func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
				if err := sink.BeginV1(meta); err != nil { return err }
				return sink.EventV1(TreeEventV1{Kind: 1, Outpoint: op, TxIndex: 1})
			})
			trReadV1(t, s, o, request, func(reader *Reader, _ *OperationAccount, root [32]byte, err error) {
				var engine *EngineError
				if !errors.As(err, &engine) || engine.Class != EngineIntegrity || root != ([32]byte{}) || reader.usable() { t.Fatalf("malformed D result %x/%v", root, err) }
				want := TreeObservationV1{DatabaseID: [32]byte{7}, Generation: 1, Block: request.Primitive.Block, Height: 6, Primitive: 0, Position: 1, Rank: 1, KeyLength: 44, Kind: 2, OriginalImage: true, OriginalReference: true}
				copy(want.Key[:], key)
				if engine.TreeObservation == nil || *engine.TreeObservation != want { t.Fatalf("malformed D observation %+v want %+v", engine.TreeObservation, want) }
			})
		})
	}
}

func trApplicationV1(t *testing.T) {
	for _, class := range []EngineClass{EngineCapacity, EngineIntegrity} {
		for _, wrapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wrapped-%v", class, wrapped), func(t *testing.T) {
				s, _, o := tsNew(t)
				request, _, _ := trRequestV1(t, 0)
				primary := error(&EngineError{Operation: "source", Class: class, Diagnostic: "application refusal"})
				if wrapped { primary = fmt.Errorf("source: %w", primary) }
				request.Primitive.Source = tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { return primary })
				trReadV1(t, s, o, request, func(reader *Reader, account *OperationAccount, root [32]byte, err error) {
					if err != primary || root != ([32]byte{}) || !reader.usable() || reader.failure != nil { t.Fatal("application error acquired native provenance") }
					fresh, _, _ := trRequestV1(t, 0)
					_, next := reader.DeriveTreeRootV1(account, fresh)
					mustEnvironment(t, next)
				})
			})
		}
	}
}
