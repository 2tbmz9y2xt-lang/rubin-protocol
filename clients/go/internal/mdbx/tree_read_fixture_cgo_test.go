//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"fmt"
	"reflect"
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
	t.Run("binding-malformed", trBindingMalformedV1)
	t.Run("origin-before-get", trOriginFaultV1)
	t.Run("obtained-before-later-get", trObtainedOrderV1)
	t.Run("structural-semantic-digest-order", trMixedV1)
}

func trBindingMalformedV1(t *testing.T) {
	for _, variant := range []string{"framing", "valid-import", "zero-current", "zero-lag"} {
		t.Run(variant, func(t *testing.T) {
			s, path, o := tsNew(t)
			request, _, frame := trRequestV1(t, 6)
			value := trBindingV1(t, 1, request.Parent)
			value[len(value)-1] = 2
			// Imported database 6, current 7, lag 8, role 2, evidence 9.
			value = append(value, treeImportLiteral(t, 2)...)
			switch variant {
			case "framing":
				value = []byte{0xff}
			case "zero-current":
				clear(value[len(value)-49 : len(value)-41])
			case "zero-lag":
				clear(value[len(value)-41 : len(value)-33])
			}
			treeNativeSeed(t, s, 0, tsRootKey(1), value)
			var failed *Reader
			outer := trReadV1(t, s, o, request, func(reader *Reader, account *OperationAccount, root [32]byte, err error) {
				if variant == "valid-import" {
					mustEnvironment(t, err)
					if root != trWantRootV1(t, frame, 6) || !reader.usable() {
						t.Fatalf("valid imported binding root%x active%v", root, reader.usable())
					}
					return
				}
				failed = reader
				trBindingRefusedV1(t, request, reader, account, root, err)
			})
			if variant != "valid-import" {
				trBindingConsumedV1(t, s, failed, outer)
				s = tsReopen(t, s, path)
			}
			equal, err := FixtureRawRowEqual(s, 0, tsRootKey(1), value)
			mustEnvironment(t, err)
			if !equal {
				t.Fatal("root read changed stored binding")
			}
		})
	}
}

func trBindingRefusedV1(t *testing.T, request TreeRootReadV1, reader *Reader, account *OperationAccount, root [32]byte, err error) {
	t.Helper()
	treeNativeIntegrity(t, err, operationUpdate, errSchema)
	engine := err.(*EngineError)
	if root != ([32]byte{}) || reader.usable() || any(reader.failure) != any(err) {
		t.Fatalf("malformed binding %x/%v", root, err)
	}
	want := TreeObservationV1{DatabaseID: [32]byte{7}, Generation: 1, Block: request.Primitive.Block, Height: 6, Primitive: 0, Position: 1, Rank: 0, KeyLength: 9, Kind: 2, OriginalImage: true, OriginalReference: true}
	copy(want.Key[:], tsRootKey(1))
	if engine.TreeObservation == nil || *engine.TreeObservation != want {
		t.Fatalf("binding observation %+v want %+v", engine.TreeObservation, want)
	}
	if _, next := reader.DeriveTreeRootV1(account, request); next == nil || any(reader.failure) != any(err) {
		t.Fatal("malformed binding Reader allowed sibling or lost cause")
	}
}

func trBindingConsumedV1(t *testing.T, s *Store, reader *Reader, cause error) {
	t.Helper()
	next := s.View(func(*Reader) error { t.Fatal("consumed binding Store invoked callback"); return nil })
	if any(next) != any(cause) || any(s.Close()) != any(cause) {
		t.Fatal("malformed binding lost terminal cause")
	}
	treeNativeZeroResources(t, s)
	tsExpiredReader(t, reader)
}

func trTrustedSpendV1(t *testing.T) {
	for _, row := range trRowsV1() {
		t.Run(row.name, func(t *testing.T) {
			s, path, o := tsNew(t)
			op := TreeOutpointV1{Txid: tdTxid(37)}
			key := tdUTXOKey(1, op.Txid, 0)
			request := trEventsV1(t, TreeEventV1{Kind: 1, Outpoint: op})
			request.Inputs = []TreeOutpointV1{op}
			entry := trEntryV1(key, tdFormed(tdFrame(7, 0, []byte{3}), 1, 0))
			top := trSeedNodesV1(t, s, o, request, entry)
			if row.value != nil {
				treeNativeSeed(t, s, 1, key, row.value)
			}
			for range 2 {
				evidence, err := FixtureSelectedDamage(s, o, SelectedDamageProbeOnly, 0, nil, func() {
					trReadV1(t, s, o, request, func(reader *Reader, _ *OperationAccount, root [32]byte, err error) {
						mustEnvironment(t, err)
						if root != sha3.Sum256([]byte("RUBIN_UTXO_TREE_V1\x00")) || !reader.usable() || reader.failure != nil {
							t.Fatalf("trusted last SPEND root %x active%v", root, reader.usable())
						}
					})
				})
				mustEnvironment(t, err)
				if evidence.OldGets != ([8]uint64{1, 0}) || evidence.NodeGets != 1 || evidence.Faults != 0 {
					t.Fatalf("SPEND point requests %+v", evidence)
				}
				trNoWritesV1(t, evidence, o)
			}
			s = tsReopen(t, s, path)
			for _, stored := range []struct {
				rank       uint8
				key, value []byte
			}{{0, tsRootKey(1), trBindingV1(t, 1, request.Parent, entry)}, {8, testTreeNodeKey(1, 288, entry.k), top.digest[:]}} {
				equal, err := FixtureRawRowEqual(s, stored.rank, stored.key, stored.value)
				mustEnvironment(t, err)
				if !equal {
					t.Fatalf("trusted SPEND changed canonical rank %d row", stored.rank)
				}
			}
			equal, err := FixtureRawRowEqual(s, 1, key, row.value)
			mustEnvironment(t, err)
			if !equal {
				t.Fatal("ignored SPEND row changed")
			}
		})
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
				case "returned":
					returned = first
				case "wrapped":
					returned = fmt.Errorf("Source: %w", first)
				case "panic":
					panic(panicValue)
				}
				return returned
			})
			evidence, err := FixtureSelectedDamage(s, o, SelectedDamageGetEIO, 0, []byte{2}, func() {
				defer func() { recovered = recover() }()
				trReadV1(t, s, o, request, func(reader *Reader, _ *OperationAccount, root [32]byte, err error) {
					if root != ([32]byte{}) || reader.usable() || any(reader.failure) != any(first) {
						t.Fatal("Source native failure did not remain recorded")
					}
					if mode != "wrapped" && any(err) != any(first) {
						t.Fatal("Source first error identity changed")
					}
					if mode == "wrapped" {
						parts, ok := err.(interface{ Unwrap() []error })
						if !ok || len(parts.Unwrap()) != 2 || any(parts.Unwrap()[0]) != any(returned) || any(parts.Unwrap()[1]) != any(first) {
							t.Fatalf("Source primary order %v", err)
						}
					}
				})
			})
			mustEnvironment(t, err)
			if mode == "panic" && recovered != panicValue {
				t.Fatal("Source panic+failure changed")
			}
			if evidence.Faults != 1 || evidence.Deletes != 0 || evidence.Commits != 0 || reservationLive(o) != 0 {
				t.Fatalf("Source failure effects %+v", evidence)
			}
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
				if variant == "width31" {
					n = 31
				}
				if variant == "width33" {
					n = 33
				}
				treeNativeSeed(t, s, 8, nodeKey, make([]byte, n))
				kind = TreeObservationMalformedV1
				if variant == "digest" {
					kind = TreeObservationDigestMismatchV1
				}
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
			request.Inputs = []TreeOutpointV1{op}
			meta := TreeBlockV1{TxCount: 2, EventCount: 1}
			request.Primitive.Coverage.BlockMeta = meta
			request.Primitive.Source = tsSource(func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
				if err := sink.BeginV1(meta); err != nil {
					return err
				}
				return sink.EventV1(TreeEventV1{Kind: 1, Outpoint: op, TxIndex: 1})
			})
			trReadV1(t, s, o, request, func(reader *Reader, _ *OperationAccount, root [32]byte, err error) {
				var engine *EngineError
				if !errors.As(err, &engine) || engine.Class != EngineIntegrity || root != ([32]byte{}) || reader.usable() {
					t.Fatalf("node result %x/%v", root, err)
				}
				want := TreeObservationV1{DatabaseID: [32]byte{7}, Generation: 1, Block: request.Primitive.Block, Height: 6, Primitive: 0, Position: 1, Rank: 8, KeyLength: 46, Kind: kind, OriginalImage: true, OriginalReference: true}
				copy(want.Key[:], nodeKey)
				if engine.TreeObservation == nil || *engine.TreeObservation != want {
					t.Fatalf("node observation %+v want %+v", engine.TreeObservation, want)
				}
			})
		})
	}
}

func trSelectorsV1(t *testing.T) {
	for _, variant := range []string{"descending", "duplicate", "count", "genesis"} {
		t.Run("sorted-invalid-"+variant, func(t *testing.T) {
			s, _, o := tsNew(t)
			request, _, inputs := trGroupedRequestV1(t, 6, false)
			switch variant {
			case "descending":
				inputs[0], inputs[1] = inputs[1], inputs[0]
			case "duplicate":
				inputs[1] = inputs[0]
			case "count":
				request.Primitive.Coverage.BlockMeta.EventCount = 2
			case "genesis":
				request.Primitive.Height, request.Primitive.Endpoint.Height, request.Primitive.Coverage.Height = 0, 0, 0
				request.Parent = TreeEndpointV1{}
				request.Primitive.Coverage.BlockMeta = TreeBlockV1{TxCount: 1, EventCount: 1}
				inputs = inputs[:1]
			}
			request.Inputs = inputs
			request.Primitive.Source = trCountingSourceV1(request.Primitive.Source, t)
			mustEnvironment(t, o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				return s.View(func(r *Reader) error {
					evidence, err := FixtureSelectedDamage(s, o, SelectedDamageProbeOnly, 0, nil, func() {
						trAdmissionRefusedV1(t, r, a, o, request, operationUpdate, "invalid tree delta")
						mustEnvironment(t, a.WithReservation(402653184, func() error {
							trAdmissionRefusedV1(t, r, a, o, request, operationUpdate, "invalid tree delta")
							return nil
						}))
					})
					mustEnvironment(t, err)
					if evidence != (SelectedDamageEvidence{}) {
						t.Fatalf("sorted input refusal native selectors %+v", evidence)
					}
					return nil
				})
			}))
		})
	}
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
			if height != 0 {
				want[0], want[1] = 1, 1
			}
			if evidence.OldGets != want || evidence.NodeGets != 0 {
				t.Fatalf("parent selectors %+v, want %v and zero nodes", evidence, want)
			}
			var points uint64
			for _, n := range evidence.OldGets {
				points += n
			}
			points += evidence.NodeGets
			if height != 0 && points > 578 {
				t.Fatal("captured 577E+1 point ceiling exceeded")
			}
		})
	}
}

func trIOV1(t *testing.T) {
	s, path, o := tsNew(t)
	request, _, frame := trRequestV1(t, 6)
	binding := tcBinding(t, 1, request.Parent)
	treeNativeSeed(t, s, 0, tsRootKey(1), binding)
	var raw, outer error
	var failed *Reader
	evidence, err := FixtureSelectedDamage(s, o, SelectedDamageGetEIO, 0, tsRootKey(1), func() {
		outer = trReadV1(t, s, o, request, func(reader *Reader, account *OperationAccount, root [32]byte, cause error) {
			raw, failed = cause, reader
			treeNativeError(t, cause, "update", "IO", 5, "error 5", nil)
			var engine *EngineError
			if !errors.As(cause, &engine) || engine.TreeObservation != nil || root != ([32]byte{}) || reader.usable() || any(reader.failure) != any(cause) {
				t.Fatal("unavailable D fabricated localization/result or lost failure")
			}
			_, next := reader.DeriveTreeRootV1(account, request)
			if next == nil || any(reader.failure) != any(raw) {
				t.Fatal("failed Reader allowed sibling")
			}
		})
	})
	mustEnvironment(t, err)
	next := s.View(func(*Reader) error { t.Fatal("consumed Store invoked callback"); return nil })
	_, inspectErr := s.Inspect()
	closeErr := s.Close()
	if any(outer) != any(raw) || any(next) != any(raw) || any(inspectErr) != any(raw) || any(closeErr) != any(raw) {
		t.Fatalf("native IO terminal identity changed: outer %v, View %v, Inspect %v, Close %v", outer, next, inspectErr, closeErr)
	}
	treeNativeZeroResources(t, s)
	tsExpiredReader(t, failed)
	if evidence.Faults != 1 || evidence.BeginWrite != 0 || evidence.Commits != 0 || evidence.Deletes != 0 || reservationLive(o) != 0 {
		t.Fatalf("native IO counts %+v", evidence)
	}
	s = tsReopen(t, s, path)
	equal, err := FixtureRawRowEqual(s, 0, tsRootKey(1), binding)
	if err != nil || !equal {
		t.Fatal("native IO changed canonical binding")
	}
	trReadV1(t, s, o, request, func(_ *Reader, _ *OperationAccount, root [32]byte, err error) {
		mustEnvironment(t, err)
		if root != trWantRootV1(t, frame, 6) {
			t.Fatal("fresh Reader did not derive afresh")
		}
	})
}

type trRowV1 struct {
	name      string
	value     []byte
	malformed bool
}

func trRowsV1() []trRowV1 {
	good := tdFormed(tdFrame(7, 0, []byte{3}), 1, 0)
	badCoinbase := bytes.Clone(good)
	badCoinbase[len(badCoinbase)-1] = 2
	badCompact := append(bytes.Clone(good[:10]), 253, 1, 0)
	badCompact = append(badCompact, good[11:]...)
	rows := []trRowV1{{"equal", good, false}, {"absent", nil, false}, {"short", good[:19], true}, {"oversized-before-copy", make([]byte, 65561), true}, {"nonminimal-length", badCompact, true}, {"truncated-data", good[:len(good)-1], true}, {"coinbase-tag", badCoinbase, true}}
	for i, name := range []string{"value", "type", "data", "height", "coinbase"} {
		value := bytes.Clone(good)
		value[[]int{0, 8, 11, len(value)-9, len(value)-1}[i]]++
		rows = append(rows, trRowV1{name, value, false})
	}
	return rows
}

func trNoWritesV1(t *testing.T, e SelectedDamageEvidence, owner *OperationReservationOwner) {
	t.Helper()
	if e.BeginWrite != 0 || e.Commits != 0 || e.Deletes != 0 || e.NodePulls != 0 || e.OldPulls != ([8]uint64{}) || reservationLive(owner) != 0 {
		t.Fatalf("root read range/write/resource effects %+v", e)
	}
}

func trMalformedV1(t *testing.T) {
	rows := append(trRowsV1(), trRowV1{name: "EIO"})
	for _, row := range rows {
		if !row.malformed && row.name != "equal" && row.name != "absent" && row.name != "EIO" {
			continue
		}
		for _, member := range []bool{false, true} {
			for _, cancel := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/member%v/cancel%v", row.name, member, cancel), func(t *testing.T) {
					s, _, o := tsNew(t)
					op := TreeOutpointV1{Txid: tdTxid(8)}
					key := tdUTXOKey(1, op.Txid, 0)
					events := []TreeEventV1{{Kind: 2, Outpoint: op}}
					if cancel {
						events = append(events, TreeEventV1{Kind: 1, Outpoint: op})
					}
					request := trEventsV1(t, events...)
					if member {
						request.Inputs = []TreeOutpointV1{op}
					}
					trSeedV1(t, s, o, 0, tsRootKey(1), trBindingV1(t, 1, request.Parent))
					if row.value != nil {
						treeNativeSeed(t, s, 1, key, row.value)
					}
					scenario := SelectedDamageProbeOnly
					if row.name == "EIO" {
						scenario = SelectedDamageGetEIO
					}
					evidence, fixtureErr := FixtureSelectedDamage(s, o, scenario, 1, key, func() {
						trReadV1(t, s, o, request, func(r *Reader, account *OperationAccount, root [32]byte, err error) {
							trCreateResultV1(t, request, r, account, root, err, row, member, cancel, key)
						})
					})
					mustEnvironment(t, fixtureErr)
					want, faults := [8]uint64{0, 1}, uint64(0)
					if row.name == "absent" && !member {
						want[0] = 1
					}
					if row.name == "EIO" {
						faults = 1
					}
					if evidence.OldGets != want || evidence.NodeGets != 0 || evidence.Faults != faults {
						t.Fatalf("CREATE refusal precedes binding: %+v want%v faults%d", evidence, want, faults)
					}
					trNoWritesV1(t, evidence, o)
				})
			}
		}
	}
}

func trCreateResultV1(t *testing.T, request TreeRootReadV1, reader *Reader, account *OperationAccount, root [32]byte, err error, row trRowV1, member, cancel bool, key []byte) {
	t.Helper()
	if row.name == "absent" && !member {
		mustEnvironment(t, err)
		want := sha3.Sum256([]byte("RUBIN_UTXO_TREE_V1\x00"))
		if !cancel {
			want = testTreeBuild(1, []testTreeEntry{trEntryV1(key, tdFormed(tdFrame(7, 0, nil), 6, 0))}, map[string][]byte{}).digest
		}
		if root != want || !reader.usable() || reader.failure != nil {
			t.Fatalf("coherent CREATE root%x want%x", root, want)
		}
		return
	}
	if !row.malformed && row.name != "EIO" {
		trSemanticV1(t, request, reader, account, root, err)
		return
	}
	if row.name == "EIO" {
		treeNativeError(t, err, "update", "IO", 5, "error 5", nil)
	} else {
		treeNativeIntegrity(t, err, operationUpdate, errSchema)
	}
	engine := err.(*EngineError)
	if root != ([32]byte{}) || reader.usable() || any(reader.failure) != any(err) {
		t.Fatalf("CREATE row refusal root%x error%v", root, err)
	}
	if row.malformed {
		want := TreeObservationV1{DatabaseID: [32]byte{7}, Generation: 1, Block: request.Primitive.Block, Height: 6, Primitive: 0, Position: 1, Rank: 1, KeyLength: 44, Kind: 2, OriginalImage: true, OriginalReference: true}
		copy(want.Key[:], key)
		if engine.TreeObservation == nil || *engine.TreeObservation != want {
			t.Fatalf("CREATE malformed observation %+v want%+v", engine.TreeObservation, want)
		}
	} else if engine.TreeObservation != nil {
		t.Fatal("native CREATE failure acquired an observation")
	}
	if _, next := reader.DeriveTreeRootV1(account, request); next == nil || any(reader.failure) != any(err) {
		t.Fatal("CREATE row refusal lost first cause")
	}
}

func trOriginFaultV1(t *testing.T) {
	for _, scenario := range []SelectedDamageScenario{SelectedDamageProbeOnly, SelectedDamageGetEIO} {
		t.Run(fmt.Sprint(scenario), func(t *testing.T) {
			s, path, o := tsNew(t)
			op := TreeOutpointV1{Txid: tdTxid(8)}
			key, damaged := tdUTXOKey(1, op.Txid, 0), []byte{0xff}
			request := trEventsV1(t, TreeEventV1{Kind: 1, Outpoint: op})
			treeNativeSeed(t, s, 1, key, damaged)
			var failed *Reader
			var raw, outer error
			evidence, fixtureErr := FixtureSelectedDamage(s, o, scenario, 1, key, func() {
				outer = trReadV1(t, s, o, request, func(reader *Reader, account *OperationAccount, root [32]byte, err error) {
					raw, failed = err, reader
					trSemanticV1(t, request, reader, account, root, err)
				})
			})
			if scenario == SelectedDamageProbeOnly {
				mustEnvironment(t, fixtureErr)
			} else if fixtureErr == nil || fixtureErr.Error() != "selected damage fixture site was not reached exactly as armed" {
				t.Fatalf("origin-before-get nonreach diagnostic %v", fixtureErr)
			}
			if evidence.OldGets != ([8]uint64{}) || evidence.NodeGets != 0 || evidence.Faults != 0 || any(outer) != any(raw) {
				t.Fatalf("missing SPEND origin made a later request: %+v outer%v raw%v", evidence, outer, raw)
			}
			trNoWritesV1(t, evidence, o)
			trBindingConsumedV1(t, s, failed, raw)
			s = tsReopen(t, s, path)
			equal, err := FixtureRawRowEqual(s, 1, key, damaged)
			mustEnvironment(t, err)
			if !equal {
				t.Fatal("origin refusal changed raw parent row")
			}
		})
	}
}

func trObtainedOrderV1(t *testing.T) {
	a, b, c := TreeOutpointV1{}, TreeOutpointV1{Txid: [32]byte{0: 0x80}}, TreeOutpointV1{Txid: [32]byte{0: 0xc0}}
	for _, late := range []bool{true, false} {
		t.Run(fmt.Sprintf("late-leaf-%v", late), func(t *testing.T) {
			s, path, o := tsNew(t)
			request := trEventsV1(t, TreeEventV1{Kind: 1, Outpoint: a}, TreeEventV1{Kind: 1, Outpoint: b})
			request.Inputs = []TreeOutpointV1{a, b}
			entries := []testTreeEntry{trPremiseV1(a), trPremiseV1(c)}
			top := trSeedNodesV1(t, s, o, request, entries...)
			armed := testTreeNodeKey(1, top.depth, top.key)
			if late {
				armed = testTreeNodeKey(1, 288, entries[0].k)
			}
			var raw, outer error
			var failed *Reader
			evidence, fixtureErr := FixtureSelectedDamage(s, o, SelectedDamageGetEIO, 8, armed, func() {
				outer = trReadV1(t, s, o, request, func(reader *Reader, account *OperationAccount, root [32]byte, err error) {
					raw, failed = err, reader
					if late {
						trSemanticV1(t, request, reader, account, root, err)
						return
					}
					treeNativeError(t, err, "update", "IO", 5, "error 5", nil)
					if root != ([32]byte{}) || err.(*EngineError).TreeObservation != nil || reader.usable() || any(reader.failure) != any(err) {
						t.Fatal("earlier branch EIO lost its raw no-result state")
					}
				})
			})
			faults := uint64(1)
			if late {
				faults = 0
				if fixtureErr == nil || fixtureErr.Error() != "selected damage fixture site was not reached exactly as armed" {
					t.Fatalf("obtained-before-leaf nonreach diagnostic %v", fixtureErr)
				}
			} else {
				mustEnvironment(t, fixtureErr)
			}
			if evidence.OldGets != ([8]uint64{1, 0}) || evidence.NodeGets != 1 || evidence.Faults != faults || any(outer) != any(raw) {
				t.Fatalf("obtained-order point requests %+v faults%d outer%v raw%v", evidence, faults, outer, raw)
			}
			trNoWritesV1(t, evidence, o)
			trBindingConsumedV1(t, s, failed, raw)
			s = tsReopen(t, s, path)
			trPreservedNodesV1(t, s, request, entries)
		})
	}
}

func trPreservedNodesV1(t *testing.T, s *Store, request TreeRootReadV1, entries []testTreeEntry) {
	t.Helper()
	rows := map[string][]byte{}
	top := testTreeBuild(1, entries, rows)
	equal, err := FixtureRawRowEqual(s, 0, tsRootKey(1), trBindingV1(t, 1, request.Parent, entries...))
	mustEnvironment(t, err)
	if !equal {
		t.Fatal("semantic refusal changed parent binding")
	}
	for _, entry := range entries {
		digest := testTreeLeafPreimage(entry.k, entry.v)
		equal, err := FixtureRawRowEqual(s, 8, testTreeNodeKey(1, 288, entry.k), digest[:])
		mustEnvironment(t, err)
		if !equal {
			t.Fatal("semantic refusal changed parent leaf")
		}
	}
	equal, err = FixtureRawRowEqual(s, 8, testTreeNodeKey(1, top.depth, top.key), rows[fmt.Sprintf("8:%x", testTreeNodeKey(1, top.depth, top.key))])
	mustEnvironment(t, err)
	if !equal {
		t.Fatal("semantic refusal changed parent branch")
	}
}

func trMixedV1(t *testing.T) {
	for _, variant := range []string{"branch-short", "branch-identity", "semantic-and-digest", "digest-only", "binding-endpoint", "binding-database"} {
		t.Run(variant, func(t *testing.T) {
			s, _, o := tsNew(t)
			a, b, c := TreeOutpointV1{}, TreeOutpointV1{Txid: [32]byte{0: 0x80}}, TreeOutpointV1{Txid: [32]byte{0: 0xc0}}
			if variant == "digest-only" {
				b = c
			}
			request := trEventsV1(t, TreeEventV1{Kind: 1, Outpoint: a}, TreeEventV1{Kind: 1, Outpoint: b})
			request.Inputs = []TreeOutpointV1{a, b}
			entries := []testTreeEntry{trPremiseV1(a), trPremiseV1(c)}
			top := trSeedNodesV1(t, s, o, request, entries...)
			binding, err := DecodeRootBindingV1(trBindingV1(t, 1, request.Parent, entries...))
			mustEnvironment(t, err)
			rows := map[string][]byte{}
			_ = testTreeBuild(1, entries, rows)
			key := testTreeNodeKey(1, top.depth, top.key)
			branch, rank, kind := rows[fmt.Sprintf("8:%x", key)], uint8(8), TreeObservationMalformedV1
			switch variant {
			case "branch-short":
				branch = branch[:139]
			case "branch-identity":
				copy(branch[70:108], branch[:38])
				kind = TreeObservationIdentityMismatchV1
			case "semantic-and-digest", "digest-only":
				binding.RootDigest[0] ^= 1
				kind = TreeObservationDigestMismatchV1
			case "binding-endpoint", "binding-database":
				if variant == "binding-endpoint" {
					binding.Endpoint.BlockHash[0] ^= 1
				} else {
					binding.DatabaseID[0] ^= 1
				}
				id := TreeNodeIDV1{Kind: 1, Depth: 288, RoutingKey: entries[0].k}
				binding.Top = TreeTopV1{Kind: 1, Node: &id}
				rank, kind = 0, TreeObservationIdentityMismatchV1
			}
			treeNativeSeed(t, s, 8, key, branch)
			encoded, err := binding.Encode()
			mustEnvironment(t, err)
			treeNativeSeed(t, s, 0, tsRootKey(1), encoded)
			if rank == 0 {
				key = tsRootKey(1)
			}
			evidence, fixtureErr := FixtureSelectedDamage(s, o, SelectedDamageProbeOnly, 0, nil, func() {
				trReadV1(t, s, o, request, func(reader *Reader, account *OperationAccount, root [32]byte, err error) {
					if variant == "semantic-and-digest" {
						trSemanticV1(t, request, reader, account, root, err)
						return
					}
					trMixedObservationV1(t, request, reader, root, err, rank, key, kind)
				})
			})
			mustEnvironment(t, fixtureErr)
			wantNodes := uint64(1)
			if rank == 0 {
				wantNodes = 0
			}
			if evidence.OldGets != ([8]uint64{1, 0}) || evidence.NodeGets != wantNodes || evidence.Faults != 0 {
				t.Fatalf("mixed-error request timing %+v", evidence)
			}
			trNoWritesV1(t, evidence, o)
		})
	}
}

func trMixedObservationV1(t *testing.T, request TreeRootReadV1, reader *Reader, root [32]byte, err error, rank uint8, key []byte, kind TreeObservationKindV1) {
	t.Helper()
	var cause error
	if kind == TreeObservationMalformedV1 || rank == 8 && kind == TreeObservationIdentityMismatchV1 {
		cause = errSchema
	}
	treeNativeIntegrity(t, err, operationUpdate, cause)
	engine := err.(*EngineError)
	want := TreeObservationV1{DatabaseID: [32]byte{7}, Generation: 1, Block: request.Primitive.Block, Height: 6, Primitive: 0, Position: 1, Rank: rank, KeyLength: uint8(len(key)), Kind: kind, OriginalImage: true, OriginalReference: true}
	copy(want.Key[:], key)
	if engine.TreeObservation == nil || *engine.TreeObservation != want || root != ([32]byte{}) || reader.usable() || any(reader.failure) != any(err) {
		t.Fatalf("mixed-error exact observation %+v want%+v root%x", engine.TreeObservation, want, root)
	}
}

func trApplicationV1(t *testing.T) {
	for _, class := range []EngineClass{EngineCapacity, EngineIntegrity, EngineIO} {
		for _, wrapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wrapped-%v", class, wrapped), func(t *testing.T) {
				s, _, o := tsNew(t)
				before, err := s.Inspect()
				mustEnvironment(t, err)
				request, _, _ := trRequestV1(t, 0)
				primary := error(&EngineError{Operation: "source", Class: class, Diagnostic: "application refusal"})
				if class == EngineIO {
					primary = &EngineError{Operation: "update", Class: EngineIO, Code: 5, Diagnostic: "error 5"}
				}
				if wrapped {
					primary = fmt.Errorf("source: %w", primary)
				}
				request.Primitive.Source = tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { return primary })
				outer := trReadV1(t, s, o, request, func(reader *Reader, account *OperationAccount, root [32]byte, err error) {
					if any(err) != any(primary) || root != ([32]byte{}) || !reader.usable() || reader.failure != nil {
						t.Fatal("application error acquired native provenance")
					}
					fresh, _, _ := trRequestV1(t, 0)
					_, next := reader.DeriveTreeRootV1(account, fresh)
					mustEnvironment(t, next)
				})
				if any(outer) != any(primary) {
					t.Fatal("outer View changed application error identity")
				}
				mustEnvironment(t, s.View(func(*Reader) error { return nil }))
				after, err := s.Inspect()
				mustEnvironment(t, err)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("application refusal changed Store image")
				}
			})
		}
	}
}
