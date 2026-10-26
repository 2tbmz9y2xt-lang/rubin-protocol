//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestEntryInventoryV1ControlsNativeOutcomes(t *testing.T) {
	t.Run("source-frontiers", eifSourceFrontiers)
	t.Run("positive-absence-malformation", eifPositiveFailures)
	t.Run("counter-width-root-provenance", eifControlShapes)
	t.Run("ReadAt-and-native-disposition", eifNativeProducts)
	t.Run("suspended-visitor-retirement", eifSuspended)
	t.Run("independent-Reader-failure", eifIndependentRead)
	t.Run("capacity-before-native-source", eifCapacity)
	t.Run("prepared-account-close", eifAccountClose)
	t.Run("pre-hold-close-window", tsClosedBeforeHoldV1)
}

func eifAccountClose(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(fmt.Sprintf("prepared%v", prepared), func(t *testing.T) {
			eifClosedAccountAttempt(t, prepared)
		})
	}
}

func eifClosedAccountAttempt(t *testing.T, prepared bool) {
	t.Helper()
	x := eiNew(t, 1, 1, false)
	ready, closeNow, closed := make(chan *OperationAccount, 1), make(chan struct{}), make(chan struct{})
	released := false
	release := func() {
		if !released {
			close(closeNow)
			released = true
		}
	}
	t.Cleanup(func() {
		release()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Error("operation account did not close")
		}
	})
	go func() {
		defer close(closed)
		_ = x.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
			ready <- a
			<-closeNow
			return nil
		})
	}()
	var a *OperationAccount
	select {
	case a = <-ready:
	case <-closed:
		t.Fatal("operation account closed before reaching its callback")
	case <-time.After(5 * time.Second):
		t.Fatal("operation account did not reach its callback")
	}
	var token EntryInventoryV1
	result := tsInvoke(x.s, a, func(r *Reader) (TreeOperationV1, error) {
		if prepared {
			token = eiPrepare(t, r, a, x.pair)
		}
		release()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatal("prepared operation account did not close")
		}
		if !prepared {
			// No Pair backing exists: even grow(0) must check the closed account
			// after ordinary admission and before clone/native composer entry.
			p, _ := tsPrimitive(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error {
				t.Fatal("closed zero-PC account reached Source")
				return nil
			}))
			return TreeOperationV1{Primitives: []TreePrimitiveV1{p}}, nil
		}
		f, err := r.VisitEntryInventoryV1(token, func(EntryInventoryRowV1) error {
			t.Fatal("closed prepared account emitted a source")
			return nil
		})
		if f != nil {
			t.Fatal("closed account manufactured source provenance")
		}
		eiInput(t, err)
		return TreeOperationV1{Pair: x.pair}, nil
	})
	result.tuple(t, 1, 1, -1)
	if prepared {
		eiInput(t, result.err)
		eiRetired(t, token)
	} else if any(result.err) != any(errOperationReservationInput) {
		t.Fatal("closed zero-PC account lost the original input singleton")
	}
	if reservationLive(x.o) != 0 {
		t.Fatal("closed prepared account retained its hold")
	}
	x.unchanged(t)
}

func eifControlShapes(t *testing.T) {
	for _, source := range []uint8{1, 2, 3, 4} {
		for _, variant := range []string{"empty", "short", "wide", "database", "PRE_GENESIS-digest"} {
			if source%2 == 1 && (variant == "database" || variant == "PRE_GENESIS-digest") {
				continue
			}
			t.Run(fmt.Sprintf("source%d-%s", source, variant), func(t *testing.T) {
				x := eiNew(t, 1, 1, false)
				g := uint64((source + 1) / 2)
				artifact, key := uint8(2), tsCounterKey(g)
				value := bytes.Clone(x.values[source-1])
				if source%2 == 0 {
					artifact, key = 11, tsRootKey(g)
				}
				switch variant {
				case "empty":
					value = nil
				case "short":
					value = value[:len(value)-1]
				case "wide":
					value = append(value, 0)
				case "database":
					root, err := DecodeRootBindingV1(value)
					mustEnvironment(t, err)
					root.DatabaseID = [32]byte{8}
					value, err = root.Encode()
					mustEnvironment(t, err)
				case "PRE_GENESIS-digest":
					value[99] ^= 1
				}
				treeNativeSeed(t, x.s, 0, key, value)
				calls := 0
				var failure *EntryInventoryFailureV1
				result := x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
					token := eiPrepare(t, r, a, x.pair)
					var err error
					failure, err = r.VisitEntryInventoryV1(token, func(EntryInventoryRowV1) error {
						calls++
						return nil
					})
					if err != nil {
						t.Fatal("malformed complete source acquired an error")
					}
					return TreeOperationV1{Pair: x.pair}, nil
				})
				eifFailure(t, failure, source, artifact, uint8(g), 1, 4, g, key, nil)
				if calls != int(source)-1 {
					t.Fatal("malformed control frontier changed")
				}
				eiInput(t, result.err)
				if x.s.state != storeOPEN || reservationLive(x.o) != 0 {
					t.Fatal("malformed control cleanup")
				}
			})
		}
	}
}

// Imported capsules and both canonical/owner bijections are persisted before
// StartupVerifyCanonicalV1 inspects them. No unconditional completion is used.
func eifImported(t *testing.T) (*eiScene, []byte) {
	t.Helper()
	x := eiNew(t, 1, 1, false)
	header := initial148NativeLiteral(t)
	hash := sha3.Sum256(header)
	evidence, err := (TreeEvidenceV1{OriginalDatabaseID: [32]byte{7}, OriginalCurrentID: 1, OriginalLagID: 2, Payload: []byte{0xab, 0xcd}}).Encode()
	mustEnvironment(t, err)
	id := sha3.Sum256(evidence)
	evidenceKey := append([]byte{0x12}, id[:]...)
	treeNativeSeed(t, x.s, 0, evidenceKey, evidence)
	for i, g := range []uint64{1, 2} {
		root, err := DecodeRootBindingV1(x.values[i*2+1])
		mustEnvironment(t, err)
		root.Endpoint = TreeEndpointV1{Kind: 1, BlockHash: hash, CumulativeChainwork: [40]byte{39: 1}}
		root.Assurance = TreeAssuranceV1{Kind: 2, Import: &TreeImportReferenceV1{OriginalDatabaseID: [32]byte{7}, OriginalCurrentID: 1, OriginalLagID: 2, OriginalRole: TreeOriginalRoleV1(i + 1), EvidenceID: id}}
		x.values[i*2+1], err = root.Encode()
		mustEnvironment(t, err)
		treeNativeSeed(t, x.s, 0, tsRootKey(g), x.values[i*2+1])
		key := binary.BigEndian.AppendUint64(nil, g)
		key = binary.BigEndian.AppendUint64(key, 0)
		value := append(bytes.Clone(hash[:]), make([]byte, 72)...)
		value[103] = 1
		treeNativeSeed(t, x.s, 2, key, value)
		owner := binary.BigEndian.AppendUint64(nil, g)
		owner = append(owner, hash[:]...)
		treeNativeSeed(t, x.s, 7, owner, make([]byte, 8))
	}
	err, cached := x.s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
		authority, present, failure := r.ReadTreeAuthorityV1()
		if failure != nil {
			return 0, failure
		}
		if !present || authority.Authority.ActiveGenerationID != 1 || authority.LagGenerationID != 2 || authority.Authority.Phase != 1 || authority.Authority.Lifecycle != 1 {
			return 0, errors.New("seeded authority roles not established")
		}
		for _, g := range []uint64{1, 2} {
			index, found, failure := r.StartupCanonicalNextV1(TreeSchemaV1DBIs()[2], g, nil)
			if failure != nil {
				return 0, failure
			}
			if !found || len(index.Key) != 16 || len(index.Value) != 104 || binary.BigEndian.Uint64(index.Key[8:]) != 0 || !bytes.Equal(index.Value[:32], hash[:]) || index.Value[103] != 1 {
				return 0, errors.New("seeded canonical tuple not established")
			}
			owner, present, failure := r.StartupCanonicalNextV1(TreeSchemaV1DBIs()[7], g, nil)
			if failure != nil {
				return 0, failure
			}
			if !present || len(owner.Key) != 40 || !bytes.Equal(owner.Key[8:], hash[:]) || !bytes.Equal(owner.Value, make([]byte, 8)) {
				return 0, errors.New("seeded owner bijection not established")
			}
			for _, last := range []struct {
				rank uint8
				row  PrefixRow
			}{{2, index}, {7, owner}} {
				_, extra, failure := r.StartupCanonicalNextV1(TreeSchemaV1DBIs()[last.rank], g, last.row.Key)
				if failure != nil {
					return 0, failure
				}
				if extra {
					return 0, errors.New("unexpected seeded canonical sibling")
				}
			}
			root, present, failure := r.ReadTreeRootBindingV1(g)
			if failure != nil {
				return 0, failure
			}
			if !present || root.Endpoint.Kind != 1 || root.Endpoint.Height != 0 || root.Endpoint.BlockHash != hash || root.Assurance.Import == nil {
				return 0, errors.New("seeded complete-role binding not established")
			}
			capsule, failure := r.ReadTreeEvidenceV1(*root.Assurance.Import)
			if failure != nil {
				return 0, failure
			}
			if !bytes.Equal(capsule.Payload, []byte{0xab, 0xcd}) {
				return 0, errors.New("capsule source changed")
			}
		}
		got, present, failure := r.Get(TreeSchemaV1DBIs()[3], hash[:])
		if failure != nil {
			return 0, failure
		}
		if !present || !bytes.Equal(got, header) || sha3.Sum256(got) != hash {
			return 0, errors.New("seeded canonical header not established")
		}
		return 1, nil
	})
	mustEnvironment(t, err)
	if cached || !x.s.canonicalOwnerVerified {
		t.Fatal("startup did not publish real checked role sources")
	}
	return x, evidenceKey
}

func eifFailure(t *testing.T, f *EntryInventoryFailureV1, source, artifact, role, access, observation uint8, generation uint64, key []byte, cause error) {
	t.Helper()
	if f == nil || f.Source != source || f.Artifact != artifact || f.Role != role || f.Access != access || f.Observation != observation || f.Generation != generation || !bytes.Equal(f.Key, key) || f.Prefix != nil || f.Height != 0 || f.Hash != ([32]byte{}) || any(f.SourceError) != any(cause) {
		t.Fatalf("first request tuple %+v want %d/%d/%d/%d/%d/%d/%x/%v", f, source, artifact, role, access, observation, generation, key, cause)
	}
}

func eifSourceFrontiers(t *testing.T) {
	for _, source := range []uint8{25, 1, 2, 3, 4, 26, 126, 102, 103, 104} {
		t.Run(fmt.Sprint(source), func(t *testing.T) {
			x, evidenceKey := eifImported(t)
			readAt := source >= 102 && source <= 104
			wantSource, access := source%100, uint8(1)
			if readAt {
				access = 3
			}
			key, artifact, role, generation, before := []byte{2}, uint8(1), uint8(0), uint64(0), 0
			switch source {
			case 1:
				key, artifact, role, generation, before = tsCounterKey(1), 2, 1, 1, 0
			case 2, 102:
				key, artifact, role, generation, before = tsRootKey(1), 11, 1, 1, 1
			case 3, 103:
				key, artifact, role, generation, before = tsCounterKey(2), 2, 2, 2, 2
			case 4, 104:
				key, artifact, role, generation, before = tsRootKey(2), 11, 2, 2, 3
			case 26:
				key, artifact, role, generation, before = evidenceKey, 12, 1, 1, 2
			case 126:
				key, artifact, role, generation, before = evidenceKey, 12, 2, 2, 4
			}
			var failure *EntryInventoryFailureV1
			var sourceErr, physical error
			calls := 0
			var result tsResult
			scenario := SelectedDamageGetEIO
			if readAt || source == 126 {
				scenario = SelectedDamageProbeOnly
			}
			evidence, err := FixtureSelectedDamage(x.s, x.o, scenario, 0, key, func() {
				run := func() {
					result = x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
						token, f, err := r.PrepareEntryInventoryV1(a, x.pair)
						failure, sourceErr = f, err
						if token.scope != nil {
							failure, sourceErr = r.VisitEntryInventoryV1(token, func(row EntryInventoryRowV1) error {
								if row.Source != uint8(calls+1) {
									t.Fatal("literal controls order changed")
								}
								calls++
								if readAt && row.Source == wantSource {
									_, physical = row.ReadAt(make([]byte, 17), 0)
								}
								return nil
							})
						}
						return TreeOperationV1{Pair: x.pair}, nil
					})
				}
				if readAt || source == 126 {
					large, err := fixtureLargeFault(x.s, 1, 0, key, run)
					mustEnvironment(t, err)
					if large.gets != 2 || large.commits != 0 || large.aborts != 1 {
						t.Fatalf("delayed point/ReadAt stop %+v", large)
					}
				} else {
					run()
				}
			})
			mustEnvironment(t, err)
			wantGets := map[uint8]uint64{25: 1, 1: 2, 2: 3, 3: 5, 4: 6, 26: 4, 126: 5, 102: 2, 103: 4, 104: 5}[source]
			if evidence.BeginOld != 1 || evidence.OldGets[0] != wantGets || evidence.BeginWrite != 0 || evidence.Commits != 0 || evidence.OldAborts != map[uint8]uint64{25: 1, 1: 1, 2: 1, 3: 1, 4: 1, 26: 1}[source] || evidence.NodeGets != 0 {
				t.Fatalf("source frontier native writes %+v", evidence)
			}
			if readAt && any(sourceErr) != any(physical) {
				t.Fatal("ReadAt source error interface changed")
			}
			if readAt {
				before++
			}
			eifFailure(t, failure, wantSource, artifact, role, access, 1, generation, key, sourceErr)
			treeNativeError(t, sourceErr, "get", "IO", 5, "error 5", nil)
			result.tuple(t, 1, 1, -1)
			if any(result.err) != any(sourceErr) || calls != before {
				t.Fatalf("source stop/cause %d/%d/%v", calls, before, result.err)
			}
			tsConsumed(t, x.s, x.o, 1, result.err)
		})
	}
	t.Run("four-events-and-two-assurance-reads", func(t *testing.T) {
		x, key := eifImported(t)
		var result tsResult
		calls := 0
		evidence, err := FixtureSelectedDamage(x.s, x.o, SelectedDamageProbeOnly, 0, key, func() {
			result = x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
				token := eiPrepare(t, r, a, x.pair)
				failure, err := r.VisitEntryInventoryV1(token, func(row EntryInventoryRowV1) error {
					calls++
					if row.Source != uint8(calls) || row.Role != uint8((calls+1)/2) || row.Generation != uint64((calls+1)/2) {
						t.Fatal("imported role/control order")
					}
					if calls%2 == 0 && row.IndexCount != 1 {
						t.Fatal("APPLIED index count must be height+1")
					}
					return nil
				})
				if failure != nil || token.scope.completed {
					t.Fatal("partial prefix became complete")
				}
				eiInput(t, err)
				return TreeOperationV1{Pair: x.pair}, nil
			})
		})
		mustEnvironment(t, err)
		eiInput(t, result.err)
		if calls != 4 || evidence.OldGets[0] != 7 || evidence.BeginWrite != 0 || evidence.Commits != 0 {
			t.Fatalf("actual Source25/1/2/26/3/4/26 frontier %+v", evidence)
		}
		x.unchanged(t)
	})
}

func eifPositiveFailures(t *testing.T) {
	for _, source := range []uint8{25, 1, 2, 3, 4, 26, 126} {
		for _, malformed := range []bool{false, true} {
			if (source == 26 || source == 126) && malformed {
				continue // immutable qualified capsule; no new owning decoder
			}
			t.Run(fmt.Sprintf("%d-malformed%v", source, malformed), func(t *testing.T) {
				x, assuranceKey := eifImported(t)
				key, artifact, role, generation, callsBefore := []byte{2}, uint8(1), uint8(0), uint64(0), 0
				switch source {
				case 1:
					key, artifact, role, generation, callsBefore = tsCounterKey(1), 2, 1, 1, 0
				case 2:
					key, artifact, role, generation, callsBefore = tsRootKey(1), 11, 1, 1, 1
				case 3:
					key, artifact, role, generation, callsBefore = tsCounterKey(2), 2, 2, 2, 2
				case 4:
					key, artifact, role, generation, callsBefore = tsRootKey(2), 11, 2, 2, 3
				case 26:
					key, artifact, role, generation, callsBefore = assuranceKey, 12, 1, 1, 2
				case 126:
					key, artifact, role, generation, callsBefore = assuranceKey, 12, 2, 2, 4
					root, err := DecodeRootBindingV1(x.values[1])
					mustEnvironment(t, err)
					root.Assurance = TreeAssuranceV1{Kind: 1}
					value, err := root.Encode()
					mustEnvironment(t, err)
					treeNativeSeed(t, x.s, 0, tsRootKey(1), value)
				}
				if malformed {
					treeNativeSeed(t, x.s, 0, key, []byte{0xff})
				} else {
					mustEnvironment(t, FixtureStartupDeleteRow(x.s, 0, key))
				}
				var failure *EntryInventoryFailureV1
				calls := 0
				result := x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
					token, f, err := r.PrepareEntryInventoryV1(a, x.pair)
					failure = f
					if token.scope != nil {
						failure, err = r.VisitEntryInventoryV1(token, func(EntryInventoryRowV1) error {
							calls++
							return nil
						})
					}
					if err != nil {
						t.Fatalf("positive observation manufactured source error %v", err)
					}
					return TreeOperationV1{Pair: x.pair}, nil
				})
				observation := uint8(2)
				if malformed {
					observation = 4
				}
				wantSource := source
				if source == 126 {
					wantSource = 26
				}
				eifFailure(t, failure, wantSource, artifact, role, 1, observation, generation, key, nil)
				if calls != callsBefore {
					t.Fatal("positive failure did not stop exact event frontier")
				}
				eiInput(t, result.err)
				if x.s.state != storeOPEN {
					t.Fatal("positive native observation consumed Store")
				}
				mustEnvironment(t, x.s.View(func(*Reader) error { return nil }))
			})
		}
	}
}

func eifNativeProducts(t *testing.T) {
	for _, cleanup := range []uint32{1, 2, 9, 10} {
		applications := []string{"nil", "direct", "wrapped", "typed-nil", "panic", "panic-nil", "goexit", "visitor-panic", "visitor-panic-nil", "visitor-goexit"}
		if cleanup == 1 || cleanup == 2 {
			applications = append(applications, "returned")
		}
		for _, application := range applications {
			t.Run(fmt.Sprintf("cleanup%d-%s", cleanup, application), func(t *testing.T) {
				inside := strings.HasPrefix(application, "visitor-")
				application = strings.TrimPrefix(application, "visitor-")
				x := eiNew(t, 1, 1, false)
				marker, value := errors.New("application cause"), new(int)
				var token EntryInventoryV1
				var row EntryInventoryRowV1
				var failure *EntryInventoryFailureV1
				var physical, app, visitErr error
				var result tsResult
				var recovered any
				returned := false
				calls, nativeCalls := 0, uint32(0)
				resume := func() {
					switch application {
					case "panic":
						panic(value)
					case "panic-nil":
						panic(treeCallNilPanicValue)
					case "goexit":
						runtime.Goexit()
					}
				}
				run := func() {
					defer func() { recovered = recover() }()
					large, err := fixtureLargeFault(x.s, cleanup, 0, tsCounterKey(1), func() {
						result = x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
							token = eiPrepare(t, r, a, x.pair)
							failure, visitErr = r.VisitEntryInventoryV1(token, func(v EntryInventoryRowV1) error {
								calls++
								row, nativeCalls = v, fixtureLargeNativeCalls()
								if cleanup == 1 || cleanup == 2 {
									_, physical = v.ReadAt(make([]byte, 17), 0)
									if physical == nil {
										t.Fatal("current ReadAt fault not reached")
									}
									failure = token.scope.failure
								}
								if inside {
									resume()
								}
								switch application {
								case "direct":
									app = marker
								case "returned":
									app = physical
								case "wrapped":
									cause := physical
									if cause == nil {
										cause = marker
									}
									app = fmt.Errorf("context: %w", cause)
								case "typed-nil":
									var p *nilPointerError
									app = p
								}
								return app
							})
							wantVisit := app
							if wantVisit == nil {
								wantVisit = physical
							}
							if wantVisit != nil {
								if any(visitErr) != any(wantVisit) {
									t.Fatal("visitor application/native error interface changed")
								}
							} else {
								eiInput(t, visitErr)
							}
							resume()
							if app != nil {
								return TreeOperationV1{Pair: x.pair}, visitErr
							}
							return TreeOperationV1{Pair: x.pair}, nil
						})
					})
					mustEnvironment(t, err)
					wantGets := uint32(0)
					if physical != nil {
						wantGets = 2
					}
					if large.gets != wantGets || large.commits != 0 || large.aborts != 1 {
						t.Fatalf("visitor stop native frontier %+v", large)
					}
					returned = true
				}
				if application == "goexit" {
					done := make(chan struct{})
					go func() {
						defer close(done)
						run()
					}()
					eiAwait(t, done)
				} else {
					run()
				}
				if application == "panic" && (returned || recovered != value) {
					t.Fatal("native cleanup changed panic")
				}
				if application == "panic-nil" && (returned || recovered == nil) {
					t.Fatal("native cleanup changed panic(nil)")
				}
				if application == "goexit" && (returned || recovered != nil) {
					t.Fatal("native cleanup changed Goexit")
				}
				if application != "panic" && application != "panic-nil" && application != "goexit" {
					result.tuple(t, 1, 1, -1)
					if physical != nil && !errors.Is(result.err, physical) {
						t.Fatal("native cause was lost")
					}
					if app != nil && !errors.Is(result.err, app) {
						t.Fatal("application cause was lost")
					}
				}
				wantCalls := 1
				if physical == nil && app == nil && !inside {
					wantCalls = 4
				}
				if calls != wantCalls || nativeCalls != uint32(wantCalls+2) {
					t.Fatalf("visitor stop emitted %d events", calls)
				}
				eiRetired(t, token)
				if physical != nil {
					treeNativeError(t, physical, "get", "IO", 5, "error 5", nil)
					eifFailure(t, failure, 1, 2, 1, 3, 1, 1, []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1}, physical)
				} else if failure != nil {
					t.Fatal("application/cleanup error acquired ENTRY sidecar")
				}
				eiRowInput(t, row, "ENTRY inventory row is not active")
				if reservationLive(x.o) != 0 || x.s.terminal == nil || x.s.terminalTruth != 1 {
					t.Fatal("native failure lost terminal or grant release")
				}
				unwind := application == "panic" || application == "panic-nil" || application == "goexit"
				primary := x.s.terminal
				if cleanup == 2 || cleanup == 10 {
					engine := requireEnvironmentError(t, primary, "LocalInvariant", operationAbort, -30416, "MDBX_THREAD_MISMATCH: A thread has attempted to use a not owned object, e.g. a transaction that started by another thread")
					if !engine.ReopenRequired {
						t.Fatal("retained native reopen bit changed")
					}
					primary = engine.Cause
				}
				if cleanup == 9 {
					if app == nil && unwind {
						treeNativeError(t, primary, "abort", "IO", 5, "error 5", nil)
						primary = nil
					} else {
						joined, ok := primary.(interface{ Unwrap() []error })
						if !ok || len(joined.Unwrap()) != 2 {
							t.Fatal("consumed cleanup cause order changed")
						}
						treeNativeError(t, joined.Unwrap()[1], "abort", "IO", 5, "error 5", nil)
						primary = joined.Unwrap()[0]
					}
				}
				eifPrimary(t, primary, app, physical, !unwind)
				if cleanup == 2 || cleanup == 10 {
					if x.s.state != storePOISONEDTHREAD || x.s.txn == nil {
						t.Fatal("retained OLD ownership lost")
					}
					calls := 0
					if any(x.s.View(func(*Reader) error {
						calls++
						return nil
					})) != any(x.s.terminal) || calls != 0 {
						t.Fatal("retained Store permitted next View")
					}
					mustEnvironment(t, x.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
						next := tsInvoke(x.s, a, func(*Reader) (TreeOperationV1, error) {
							calls++
							return tsPair(55), nil
						})
						next.tuple(t, 1, 1, -1)
						if any(next.err) != any(x.s.terminal) || calls != 0 {
							t.Fatal("retained Store permitted next Update")
						}
						return nil
					}))
					mustEnvironment(t, FixtureStartupRelease(x.s))
				} else {
					tsConsumed(t, x.s, x.o, 1, x.s.terminal)
				}
			})
		}
	}
}

func eifPrimary(t *testing.T, got, application, physical error, ordinary bool) {
	t.Helper()
	if physical != nil && application != nil && any(application) != any(physical) {
		joined, ok := got.(interface{ Unwrap() []error })
		if !ok || len(joined.Unwrap()) != 2 || any(joined.Unwrap()[0]) != any(application) || any(joined.Unwrap()[1]) != any(physical) {
			t.Fatal("application/native cause identity or ordering changed")
		}
		return
	}
	want := application
	if want == nil {
		want = physical
	}
	if want == nil && ordinary {
		eiInput(t, got)
		return
	}
	if any(got) != any(want) {
		t.Fatal("single original primary interface changed")
	}
}

func eifSuspended(t *testing.T) {
	for _, physical := range []bool{false, true} {
		t.Run(fmt.Sprint(physical), func(t *testing.T) {
			x := eiNew(t, 1, 1, false)
			entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			started := make(chan struct{}, 8)
			reads := make(chan struct {
				n     int
				err   error
				value []byte
			}, 8)
			drained := 0
			launched, released := false, false
			release := func() {
				if !released {
					close(finish)
					released = true
				}
			}
			t.Cleanup(func() {
				if !launched {
					return
				}
				release()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("ENTRY visitor did not exit after retirement/release")
					return
				}
				if !physical {
					select {
					case <-entered:
						for drained < 8 {
							select {
							case <-reads:
								drained++
							case <-time.After(5 * time.Second):
								t.Error("ReadAt did not exit after callback retirement")
								return
							}
						}
					default:
					}
				}
			})
			var token EntryInventoryV1
			var row EntryInventoryRowV1
			var failure *EntryInventoryFailureV1
			var sourceErr, visitErr error
			run := func() {
				result := x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
					token = eiPrepare(t, r, a, x.pair)
					launched = true
					go func() {
						defer close(done)
						failure, visitErr = r.VisitEntryInventoryV1(token, func(v EntryInventoryRowV1) error {
							row = v
							if physical {
								_, sourceErr = v.ReadAt(make([]byte, 17), 0)
							}
							if !physical {
								for range 8 {
									go func() {
										dst := bytes.Repeat([]byte{0xa5}, 17)
										started <- struct{}{}
										n, err := v.ReadAt(dst, 0)
										reads <- struct {
											n     int
											err   error
											value []byte
										}{n, err, dst}
									}()
								}
							}
							close(entered)
							<-finish
							return nil
						})
					}()
					select {
					case <-entered:
					case <-done:
						t.Fatal("Visit returned before its first actual event")
					case <-time.After(5 * time.Second):
						t.Fatal("Visit did not reach its first actual event")
					}
					if !physical {
						for range 8 {
							<-started
						}
					}
					return TreeOperationV1{Pair: x.pair}, nil
				})
				result.tuple(t, 1, 1, -1)
				if physical && any(result.err) != any(sourceErr) {
					t.Fatal("callback expiry dropped native failure")
				}
				if !physical {
					eiInput(t, result.err)
				}
			}
			if physical {
				_, err := fixtureLargeFault(x.s, 1, 0, tsCounterKey(1), run)
				mustEnvironment(t, err)
			} else {
				run()
			}
			eiRetired(t, token)
			eiRowInput(t, row, "ENTRY inventory row is not active")
			if !physical {
				for range 8 {
					select {
					case read := <-reads:
						drained++
						if read.n == 0 {
							treeNativeError(t, read.err, "get", "InvalidInput", 22, "ENTRY inventory row is not active", nil)
						} else if read.n != 16 || !treeSameErrorV1(read.err, io.EOF) || !bytes.Equal(read.value, []byte{0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 9, 0xa5}) {
							t.Fatal("ReadAt crossed retirement with partial or redirected bytes")
						}
					case <-time.After(5 * time.Second):
						t.Fatal("ReadAt did not return across callback expiry")
					}
				}
			}
			release()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Visit did not return after callback retirement")
			}
			eiInput(t, visitErr)
			if physical {
				eifFailure(t, failure, 1, 2, 1, 3, 1, 1, tsCounterKey(1), sourceErr)
				tsConsumed(t, x.s, x.o, 1, x.s.terminal)
			} else {
				if failure != nil {
					t.Fatal("retirement fabricated sidecar")
				}
				x.unchanged(t)
			}
		})
	}
}

func eifIndependentRead(t *testing.T) {
	for _, application := range []string{"nil", "direct", "returned", "wrapped", "typed-nil"} {
		t.Run(application, func(t *testing.T) {
			x := eiNew(t, 1, 1, false)
			marker := errors.New("independent application cause")
			var token EntryInventoryV1
			var row EntryInventoryRowV1
			var failure *EntryInventoryFailureV1
			var sourceErr, app error
			_, err := FixtureSelectedDamage(x.s, x.o, SelectedDamageGetEIO, 0, []byte{1}, func() {
				result := x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
					token = eiPrepare(t, r, a, x.pair)
					var visitErr error
					failure, visitErr = r.VisitEntryInventoryV1(token, func(v EntryInventoryRowV1) error {
						row = v
						_, _, sourceErr = r.Get(TreeSchemaV1DBIs()[0], []byte{1})
						switch application {
						case "direct":
							app = marker
						case "returned":
							app = sourceErr
						case "wrapped":
							app = fmt.Errorf("independent context: %w", sourceErr)
						case "typed-nil":
							var p *nilPointerError
							app = p
						}
						return app
					})
					wantVisit := app
					if wantVisit == nil {
						wantVisit = sourceErr
					}
					if failure != nil || any(visitErr) != any(wantVisit) {
						t.Fatal("independent Reader failure acquired ENTRY sidecar or replaced visitor error")
					}
					if app != nil {
						return TreeOperationV1{Pair: x.pair}, visitErr
					}
					return TreeOperationV1{Pair: x.pair}, nil
				})
				result.tuple(t, 1, 1, -1)
				treeNativeError(t, sourceErr, "get", "IO", 5, "error 5", nil)
				eifPrimary(t, result.err, app, sourceErr, false)
			})
			mustEnvironment(t, err)
			eiRetired(t, token)
			eiRowInput(t, row, "ENTRY inventory row is not active")
			tsConsumed(t, x.s, x.o, 1, x.s.terminal)
		})
	}
}

func eifCapacity(t *testing.T) {
	if treeReaderBytesV1 != 1152 || treeStepBytesV1 != 74880 || treeStepBytesV1+treeValueBytesV1+treeNodeWorkBytesV1 != 288408 {
		t.Fatal("actual sibling Reader/step/readback tariffs differ from 1152/74880/288408")
	}
	x := eiNew(t, 1, 1, false)
	var result tsResult
	evidence, err := FixtureSelectedDamage(x.s, x.o, SelectedDamageProbeOnly, 0, []byte{2}, func() {
		mustEnvironment(t, x.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
			e := uint64(8192) + 6*uint64(limitsForPage(x.s.config.PageSize).maxKey)
			return a.WithReservation(402653184-e+1, func() error {
				result = tsInvoke(x.s, a, func(r *Reader) (TreeOperationV1, error) {
					token, f, err := r.PrepareEntryInventoryV1(a, x.pair)
					if token.scope != nil || f != nil || r.entry.inventory != nil || any(err) != any(errOperationReservationCapacity) {
						t.Fatal("capacity refusal allocated ENTRY state")
					}
					return TreeOperationV1{}, err
				})
				return nil
			})
		}))
	})
	mustEnvironment(t, err)
	result.tuple(t, 1, 1, -1)
	if any(result.err) != any(errOperationReservationCapacity) {
		t.Fatal("capacity error identity changed")
	}
	if evidence.OldGets[0] != 0 || evidence.BeginWrite != 0 || evidence.Commits != 0 || evidence.OldAborts != 1 {
		t.Fatalf("E refusal reached native source %+v", evidence)
	}
	x.unchanged(t)
}
