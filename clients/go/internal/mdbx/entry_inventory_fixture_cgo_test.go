//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
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

func TestEntryInventoryV1SourcesNativeOutcomes(t *testing.T) {
	t.Run("physical-source-frontiers", eissFrontiers)
	t.Run("required-native-content", eissRequired)
	t.Run("raw-family-and-exhaustion", eissRaw)
	t.Run("late-17001st-body-fault", eissLate)
	t.Run("ReadAt-native-and-literal", eissReads)
	t.Run("registered-stream-unwind", eissUnwind)
	t.Run("parked-link-expiry", eissExpiry)
	t.Run("full-query-no-write", eissNoWrite)
	t.Run("GEN-has-zero-native-requests", eissGEN)
	t.Run("owed-required-content", eissOwedRequired)
	t.Run("raw-family-16385-spent", eissLargeFamily)
	t.Run("stream-exact-capacity", eissCapacity)
	t.Run("native-stream-unwind-disposition", eissNativeUnwind)
	t.Run("physical-link-shapes", eissLinkShapes)
	t.Run("present-hash-bound-rewrite", eissProspectiveMalformed)
}

func eissProspectiveMalformed(t *testing.T) {
	for _, owner := range []struct{ rank, index, source, artifact, last uint8 }{{3, 1, 11, 6, 9}, {4, 2, 12, 7, 11}} {
		t.Run(fmt.Sprintf("present-rank%d-rewrite-samefalse", owner.rank), func(t *testing.T) {
			f := eisNew(t, 3, 1, nil)
			pair := eisCapture(t, f, 1, 1, false, false)
			m := pair.Mutations[owner.index]
			value := bytes.Clone(m.Literal)
			value[len(value)-1] ^= 1
			mustEnvironment(t, fixtureSeedPrefixRawRow(f.s, m.DBI, m.Key, value))
			last := uint8(0)
			result, token, failure, err := eisInvoke(t, f, pair, func(row EntryInventoryRowV1) error {
				last = row.Source
				return nil
			})
			eiInput(t, result.err)
			eissFailure(t, failure, owner.source, owner.artifact, 0, 1, 4, 21, 3, [32]byte(m.Key), m.Key, nil, nil)
			if err != nil || token.scope.completed || last != owner.last || f.s.state != storeOPEN {
				t.Fatalf("differing required bytes lost positive failure %+v/%v/last%d", failure, err, last)
			}
			tsRead(t, f.s, TreeSchemaV1DBIs()[0], []byte{2}, eiEncoded(t, f.old))
			tsFollowing(t, f.s, f.o)
		})
	}
}

func eissFailure(t *testing.T, failure *EntryInventoryFailureV1, source, artifact, role, access, observation uint8, generation, height uint64, hash [32]byte, key, prefix []byte, cause error) {
	t.Helper()
	if failure == nil || failure.Source != source || failure.Artifact != artifact || failure.Role != role || failure.Access != access || failure.Observation != observation || failure.Generation != generation || failure.Height != height || failure.Hash != hash || !bytes.Equal(failure.Key, key) || !bytes.Equal(failure.Prefix, prefix) || any(failure.SourceError) != any(cause) {
		t.Fatalf("exact physical source tuple %+v, want %d/%d/%d/%d/%d/%d/%d/%x/%x/%x/%v", failure, source, artifact, role, access, observation, generation, height, hash, key, prefix, cause)
	}
}

func eissFrontiers(t *testing.T) {
	for _, site := range []string{"canonical-forward", "canonical-header", "O-manifest", "canonical-body", "captured-link", "first-cursor", "final-cursor"} {
		t.Run(site, func(t *testing.T) {
			f := eisNew(t, 3, 1, nil)
			pair := eisCapture(t, f, 1, 1, false, false)
			source, artifact, role, access, generation, height, before := uint8(27), uint8(4), uint8(1), uint8(1), uint64(11), uint64(3), 4
			hash := [32]byte{}
			rank, key := uint8(2), eisHeight(11, 3)
			var prefix []byte
			scenario := SelectedDamageGetEIO
			switch site {
			case "canonical-header":
				artifact, rank, hash, key = 6, 3, f.hashes[3], f.hashes[3][:]
			case "O-manifest":
				source, artifact, rank, hash, key = 5, 8, 5, f.hashes[3], UndoManifestKey(f.hashes[3])
			case "canonical-body":
				source, artifact, rank, height, hash, key, before = 7, 7, 4, 0, f.hashes[0], f.hashes[0][:], 6
			case "captured-link":
				source, artifact, role, generation, rank, key, before = 13, 9, 0, 21, 6, eisHeight(21, 3), 13
				hash = [32]byte(pair.Mutations[1].Key)
			case "first-cursor", "final-cursor":
				source, artifact, rank, access, hash, scenario = 5, 8, 5, 2, f.hashes[3], SelectedDamageStartupPullEIO
				prefix, key = f.hashes[3][:], bytes.Clone(f.hashes[3][:])
				if site == "final-cursor" {
					key = append(UndoManifestKey(f.hashes[3]), 0)
					before = 5
				}
			}
			calls := 0
			var result tsResult
			var failure *EntryInventoryFailureV1
			var sourceErr error
			evidence, err := FixtureSelectedDamage(f.s, f.o, scenario, rank, key, func() {
				result, _, failure, sourceErr = eisInvoke(t, f, pair, func(EntryInventoryRowV1) error {
					calls++
					return nil
				})
			})
			mustEnvironment(t, err)
			eissFailure(t, failure, source, artifact, role, access, 1, generation, height, hash, key, prefix, sourceErr)
			treeNativeError(t, sourceErr, "get", "IO", 5, "error 5", nil)
			if calls != before || any(result.err) != any(sourceErr) || evidence.Faults != 1 || evidence.BeginOld != 1 || evidence.BeginWrite != 0 || evidence.Commits != 0 || evidence.OldAborts != 1 {
				t.Fatalf("exact stop frontier %d/%d/%+v", calls, before, evidence)
			}
			tsConsumed(t, f.s, f.o, 1, sourceErr)
		})
	}
}

func eissRequired(t *testing.T) {
	// The hundreds select distinct canonical header owners; output stays Source27.
	for _, selected := range []uint16{5, 7, 9, 11, 12, 13, 14, 15, 27, 127, 227, 327} {
		source := uint8(selected % 100)
		for _, malformed := range []bool{false, true} {
			if selected >= 200 && !malformed {
				continue // absence already belongs to the same actual header key
			}
			t.Run(fmt.Sprintf("source%d-owner%d-malformed%v", source, selected/100, malformed), func(t *testing.T) {
				f := eisNew(t, 3, 1, nil)
				c, rolling := 2, false
				if source == 14 || source == 15 {
					c, rolling = 1440, true
				}
				pair := eisCapture(t, f, 1, c, rolling, false)
				hash, height, generation := f.hashes[3], uint64(3), uint64(11)
				rank, artifact, key, role := uint8(5), uint8(8), UndoManifestKey(hash), uint8(1)
				switch source {
				case 7:
					hash, height, rank, artifact = f.hashes[0], 0, 4, 7
					key = hash[:]
				case 9:
					hash, height = f.hashes[0], 0
					key = UndoManifestKey(hash)
				case 11, 12, 13, 14, 15:
					header := eisHeader(3, f.hashes[2], 9)
					hash, height, generation, role = sha3.Sum256(header), 3, 21, 0
					rank, artifact, key = 3, 6, hash[:]
					if source == 12 || source == 14 {
						rank, artifact = 4, 7
					}
					if source == 13 || source == 15 {
						rank, artifact, key = 6, 9, eisHeight(21, 3)
					}
				case 27:
					rank, artifact, key, hash = 2, 4, eisHeight(11, 3), [32]byte{}
					if selected >= 100 {
						rank, artifact, hash, key = 3, 6, f.hashes[3], f.hashes[3][:]
					}
				}
				if malformed {
					value := []byte{0xff}
					if selected == 227 {
						value = bytes.Clone(f.headers[3])
						value[140] ^= 1
					}
					if selected == 327 {
						// Header bytes/hash remain valid; only the forward parent differs.
						value = f.headers[3]
						wrong := eisChain(f.hashes[3], f.hashes[1], 3)
						mustEnvironment(t, fixtureSeedPrefixRawRow(f.s, TreeSchemaV1DBIs()[2], eisHeight(11, 3), wrong))
					}
					mustEnvironment(t, fixtureSeedPrefixRawRow(f.s, TreeSchemaV1DBIs()[rank], key, value))
				} else {
					mustEnvironment(t, FixtureStartupDeleteRow(f.s, rank, key))
				}
				last, later := uint8(0), false
				result, token, failure, err := eisInvoke(t, f, pair, func(row EntryInventoryRowV1) error {
					last = row.Source
					if row.Source == source {
						later = true
					}
					return nil
				})
				observation := uint8(2)
				if malformed {
					observation = 4
				}
				eissFailure(t, failure, source, artifact, role, 1, observation, generation, height, hash, key, nil, nil)
				if err != nil || token.scope.completed || later || last == 13 || f.s.state != storeOPEN {
					t.Fatalf("required-source refusal %+v/%v/%d/%v", failure, err, last, later)
				}
				eiInput(t, result.err)
				tsFollowing(t, f.s, f.o)
			})
		}
	}
}

func eissRaw(t *testing.T) {
	for _, variant := range []string{"zero", "one", "manifest-version", "manifest-height", "short-key", "max-key", "max-key-minus-one", "wrong-tag", "spent-value", "excess", "declared-excess", "transient-before-shape"} {
		t.Run(variant, func(t *testing.T) {
			f := eisNew(t, 3, 1, nil)
			pair := eisCapture(t, f, 1, 1, false, false)
			hash := f.hashes[3]
			manifest := UndoManifestValue(3, [16]byte{}, 0, 0)
			key := UndoEntryKey(hash, [32]byte{3}, 0, 0, 0)
			value, err := (UTXOValue{Value: 17, CovenantType: 2, CovenantData: []byte{3}, CreationHeight: 1}).Encode()
			mustEnvironment(t, err)
			switch variant {
			case "manifest-version":
				manifest[0] = 2
			case "manifest-height":
				manifest[8] = 4
			case "one", "spent-value", "declared-excess":
				manifest[32] = 1
			case "short-key":
				key = append(bytes.Clone(hash[:]), 1)
			case "max-key", "max-key-minus-one":
				width := int(limitsForPage(f.s.config.PageSize).maxKey)
				if variant == "max-key-minus-one" {
					width--
				}
				key = make([]byte, width)
				copy(key, hash[:])
				key[32] = 1
			case "wrong-tag", "transient-before-shape":
				key[32] = 2
			}
			mustEnvironment(t, fixtureSeedPrefixRawRow(f.s, TreeSchemaV1DBIs()[5], UndoManifestKey(hash), manifest))
			if variant != "zero" && variant != "manifest-version" && variant != "manifest-height" && variant != "declared-excess" {
				if variant == "spent-value" {
					value = []byte{0xff}
				}
				mustEnvironment(t, fixtureSeedPrefixRawRow(f.s, TreeSchemaV1DBIs()[5], key, value))
			}
			calls := 0
			var result tsResult
			var failure *EntryInventoryFailureV1
			var sourceErr error
			run := func() {
				result, _, failure, sourceErr = eisInvoke(t, f, pair, func(row EntryInventoryRowV1) error {
					if row.Source == 5 {
						calls++
					}
					return nil
				})
			}
			seek := append(UndoManifestKey(hash), 0)
			if variant == "transient-before-shape" {
				evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageStartupPullEIO, 5, seek, run)
				mustEnvironment(t, err)
				eissFailure(t, failure, 5, 8, 1, 2, 1, 11, 3, hash, seek, hash[:], sourceErr)
				if evidence.Faults != 1 || evidence.OldPulls[5] != 2 || calls != 1 || any(result.err) != any(sourceErr) {
					t.Fatal("transient cursor fault did not precede positive shape")
				}
				tsConsumed(t, f.s, f.o, 1, sourceErr)
				return
			}
			// Pin the native request frontier; ProbeOnly does not inject a later fault.
			evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageProbeOnly, 5, seek, run)
			mustEnvironment(t, err)
			wantGets, wantPulls, wantCalls := uint64(1), uint64(2), 1
			switch variant {
			case "zero":
				wantGets, wantPulls, wantCalls = 4, 8, 1
			case "one":
				wantGets, wantPulls, wantCalls = 4, 9, 2
			case "manifest-version", "manifest-height":
				wantGets, wantPulls, wantCalls = 1, 0, 0
			}
			if evidence.OldGets[5] != wantGets || evidence.OldPulls[5] != wantPulls || calls != wantCalls || evidence.Faults != 0 || evidence.BeginOld != 1 || evidence.BeginWrite != 0 || evidence.Commits != 0 || evidence.OldAborts != 1 {
				t.Fatalf("raw-family request frontier %+v, Source5 callbacks %d", evidence, calls)
			}
			if variant == "zero" || variant == "one" {
				if failure != nil || sourceErr != nil {
					t.Fatalf("valid zero/nonzero family %+v/%v/%d", failure, sourceErr, calls)
				}
				eiInput(t, result.err)
				tsFollowing(t, f.s, f.o)
				return
			}
			access, before := uint8(2), 1
			if variant == "manifest-version" || variant == "manifest-height" {
				key, access, before = UndoManifestKey(hash), 1, 0
			} else if variant == "declared-excess" {
				key = seek
			}
			prefix := hash[:]
			if access == 1 {
				prefix = nil
			}
			eissFailure(t, failure, 5, 8, 1, access, 4, 11, 3, hash, key, prefix, nil)
			if sourceErr != nil || calls != before {
				t.Fatalf("malformed raw row source error %v, Source5 callbacks %d", sourceErr, calls)
			}
			eiInput(t, result.err)
			tsFollowing(t, f.s, f.o)
		})
	}
}

func eissLate(t *testing.T) {
	f := eisNew(t, 17000, 2, nil)
	pair := eisCapture(t, f, 1, 1, false, false)
	var result tsResult
	var failure *EntryInventoryFailureV1
	var sourceErr error
	count := 0
	evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageGetEIO, 4, f.hashes[17000][:], func() {
		result, _, failure, sourceErr = eisInvoke(t, f, pair, func(row EntryInventoryRowV1) error {
			if row.Source == 7 {
				count++
			}
			if row.Source >= 9 {
				t.Fatal("late body fault reached a later source")
			}
			return nil
		})
	})
	mustEnvironment(t, err)
	eissFailure(t, failure, 7, 7, 1, 1, 1, 11, 17000, f.hashes[17000], f.hashes[17000][:], nil, sourceErr)
	if count != 17000 || evidence.OldGets[4] != 17001 || evidence.Faults != 1 || evidence.BeginWrite != 0 || any(result.err) != any(sourceErr) {
		t.Fatalf("17001st physical stop frontier %d/%+v", count, evidence)
	}
	tsConsumed(t, f.s, f.o, 1, sourceErr)
}

func eissReads(t *testing.T) {
	for _, literal := range []bool{false, true} {
		t.Run(fmt.Sprintf("literal%v", literal), func(t *testing.T) {
			f := eisNew(t, 3, 1, nil)
			pair := eisCapture(t, f, 1, 1, false, false)
			rank, key, source, height, generation, role := uint8(4), f.hashes[0][:], uint8(7), uint64(0), uint64(11), uint8(1)
			if literal {
				rank, key, source, height, generation, role = 3, pair.Mutations[1].Key, 11, 3, 21, 0
			}
			var physical, sourceErr error
			var result tsResult
			var failure *EntryInventoryFailureV1
			calls := 0
			evidence, err := fixtureLargeFault(f.s, 1, rank, key, func() {
				result, _, failure, sourceErr = eisInvoke(t, f, pair, func(row EntryInventoryRowV1) error {
					calls++
					if row.Source == source && row.Height == height {
						dst := bytes.Repeat([]byte{0xa5}, 17)
						n, readErr := row.ReadAt(dst, 4)
						physical = readErr
						if literal && (n != 17 || readErr != nil || !bytes.Equal(dst, pair.Mutations[1].Literal[4:21])) {
							t.Fatal("literal ReadAt made a native getter or changed its bytes")
						}
					}
					return nil // ignored actual ReadAt error must still stop
				})
			})
			mustEnvironment(t, err)
			if literal {
				if evidence.gets != 1 || failure != nil || sourceErr != nil {
					t.Fatalf("literal source performed extra native request %+v/%+v/%v", evidence, failure, sourceErr)
				}
				eiInput(t, result.err)
				return
			}
			eissFailure(t, failure, source, 7, role, 3, 1, generation, height, f.hashes[0], key, nil, physical)
			if evidence.gets != 2 || calls != 7 || any(sourceErr) != any(physical) || any(result.err) != any(physical) {
				t.Fatal("ignored native ReadAt fault lost exact stop/cause")
			}
			tsConsumed(t, f.s, f.o, 1, physical)
		})
	}
}

func eissRetired(t *testing.T, token EntryInventoryV1, stream *entryStreamV1) {
	t.Helper()
	mu := token.scope.access.mu
	if mu == nil {
		t.Fatal("retirement lost the immutable mutex locator")
	}
	mu.Lock()
	defer mu.Unlock()
	if stream == nil || stream.reader != nil || stream.seek != nil || stream.row.key != nil || stream.row.image != (updateImage{}) || stream.domain.prefix != nil || stream.domain.after != nil || stream.domain.last != nil {
		t.Fatal("actual registered stream retained source backing")
	}
	s := token.scope
	if !s.retired || s.reader != nil || s.entry != nil || s.account != nil || s.access.reader != nil || s.access.key != nil || s.access.image != (updateImage{}) || s.access.active || s.mutations != nil || s.consulted != nil || s.oldBytes != nil || s.nextBytes != nil || !reflect.ValueOf(s.authority).IsZero() || !reflect.ValueOf(s.inspection).IsZero() || !reflect.ValueOf(s.decode).IsZero() || !reflect.ValueOf(s.roots).IsZero() || !reflect.ValueOf(s.rootControl).IsZero() || !reflect.ValueOf(s.row).IsZero() {
		t.Fatal("actual source retirement retained state/access borrows")
	}
}

func eissUnwind(t *testing.T) {
	for _, site := range []uint8{5, 11} {
		for _, application := range []string{"error", "panic", "panic-nil", "goexit", "callback-panic", "callback-panic-nil", "callback-goexit"} {
			t.Run(fmt.Sprintf("source%d-%s", site, application), func(t *testing.T) {
				f := eisNew(t, 3, 1, nil)
				pair := eisCapture(t, f, 1, 2, false, false)
				marker := errors.New("visitor result")
				panicValue := new(int)
				var token EntryInventoryV1
				var stream *entryStreamV1
				var kept EntryInventoryRowV1
				var recovered any
				returned, reached := false, false
				resume := func(mode string) {
					switch mode {
					case "panic":
						panic(panicValue)
					case "panic-nil":
						panic(treeCallNilPanicValue)
					case "goexit":
						runtime.Goexit()
					}
				}
				run := func() {
					defer func() { recovered = recover() }()
					mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
						result := tsInvoke(f.s, a, func(r *Reader) (TreeOperationV1, error) {
							token = eiPrepare(t, r, a, pair)
							_, err := r.VisitEntryInventoryV1(token, func(row EntryInventoryRowV1) error {
								if row.Source != site {
									return nil
								}
								reached, kept, stream = true, row, token.scope.stream
								if reservationLive(f.o) != 8192+6*r.maxKey || stream == nil || stream.seek == nil {
									t.Fatal("real source stream/hold absent")
								}
								if site == 11 && !stream.row.image.present {
									t.Fatal("captured link was not parked through header visitor")
								}
								if !strings.HasPrefix(application, "callback-") {
									resume(application)
									return marker
								}
								return nil
							})
							resume(strings.TrimPrefix(application, "callback-"))
							return TreeOperationV1{Pair: pair}, err
						})
						result.tuple(t, 1, 1, -1)
						if any(result.err) != any(marker) {
							t.Fatal("visitor error interface changed")
						}
						return nil
					}))
					returned = true
				}
				if strings.HasSuffix(application, "goexit") {
					done := make(chan struct{})
					go func() {
						defer close(done)
						run()
					}()
					eiAwait(t, done)
				} else {
					run()
				}
				if !reached || application == "error" && !returned || strings.HasSuffix(application, "panic") && (returned || recovered != panicValue) || strings.HasSuffix(application, "panic-nil") && (returned || recovered == nil) || strings.HasSuffix(application, "goexit") && (returned || recovered != nil) {
					t.Fatal("source unwind/visitor frontier changed")
				}
				eissRetired(t, token, stream)
				eiRowInput(t, kept, "ENTRY inventory row is not active")
				if reservationLive(f.o) != 0 || f.s.state != storeOPEN || f.s.terminal != nil {
					t.Fatal("clean unwind did not release its exact hold")
				}
				tsFollowing(t, f.s, f.o)
			})
		}
	}
}

func eissExpiry(t *testing.T) {
	for _, physical := range []bool{false, true} {
		t.Run(fmt.Sprint(physical), func(t *testing.T) { eissExpiryCase(t, physical) })
	}
}

func eissExpiryCase(t *testing.T, physical bool) {
	f := eisNew(t, 3, 1, nil)
	pair := eisCapture(t, f, 1, 2, false, false)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	type reading struct {
		n     int
		err   error
		value byte
	}
	reads := make(chan reading, 4)
	var token EntryInventoryV1
	var stream *entryStreamV1
	var row EntryInventoryRowV1
	var failure *EntryInventoryFailureV1
	var visitErr, sourceErr error
	released := false
	finish := func() {
		if !released {
			close(release)
			released = true
		}
	}
	t.Cleanup(func() {
		finish()
		eiAwait(t, done)
	})
	run := func() {
		mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
			result := tsInvoke(f.s, a, func(r *Reader) (TreeOperationV1, error) {
				token = eiPrepare(t, r, a, pair)
				go func() {
					defer close(done)
					failure, visitErr = r.VisitEntryInventoryV1(token, func(v EntryInventoryRowV1) error {
						if v.Source != 11 {
							return nil
						}
						row, stream = v, token.scope.stream
						if !stream.row.image.present {
							t.Error("expiry did not suspend a real native parked link")
						}
						if physical {
							_, sourceErr = v.ReadAt(make([]byte, 1), 0)
						} else {
							for range 4 {
								go func() {
									dst := []byte{0xa5}
									n, err := v.ReadAt(dst, 0)
									reads <- reading{n, err, dst[0]}
								}()
							}
						}
						close(entered)
						<-release
						return nil
					})
				}()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("Visit did not reach actual captured header")
				}
				return TreeOperationV1{Pair: pair}, nil
			})
			result.tuple(t, 1, 1, -1)
			if physical {
				if sourceErr == nil || any(result.err) != any(sourceErr) {
					t.Fatal("callback expiry lost the original source error")
				}
			} else {
				eiInput(t, result.err)
			}
			return nil
		}))
	}
	if physical {
		hash := sha3.Sum256(eisHeader(3, f.hashes[2], 9))
		evidence, err := fixtureLargeFault(f.s, 1, 3, hash[:], run)
		mustEnvironment(t, err)
		if evidence.gets != 2 || evidence.aborts != 1 || evidence.commits != 0 {
			t.Fatalf("expiry native source frontier %+v", evidence)
		}
	} else {
		run()
	}
	eissRetired(t, token, stream)
	eiRowInput(t, row, "ENTRY inventory row is not active")
	if !physical {
		for range 4 {
			select {
			case read := <-reads:
				if read.n == 0 {
					treeNativeError(t, read.err, "get", "InvalidInput", 22, "ENTRY inventory row is not active", nil)
					if read.value != 0xa5 {
						t.Fatal("expired source read touched destination")
					}
				} else if read.n != 1 || read.err != nil || read.value != 1 {
					t.Fatal("native row read crossed retirement with changed bytes")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("source ReadAt did not return across retirement")
			}
		}
	}
	finish()
	eiAwait(t, done)
	eiInput(t, visitErr)
	if token.scope.completed || reservationLive(f.o) != 0 {
		t.Fatal("expired visitor completed or retained a hold")
	}
	if physical {
		eissFailure(t, failure, 11, 6, 0, 3, 1, 21, 3, row.Hash, row.Key, nil, sourceErr)
		tsConsumed(t, f.s, f.o, 1, sourceErr)
		return
	}
	if failure != nil || f.s.state != storeOPEN {
		t.Fatal("clean expiry acquired a source failure or terminal Store")
	}
	tsFollowing(t, f.s, f.o)
}

func eissNoWrite(t *testing.T) {
	for _, attach := range []bool{false, true} {
		t.Run(fmt.Sprintf("attach%v", attach), func(t *testing.T) {
			f := eisNew(t, 3, 1, []CleanupSpanV1{{Kind: 1, GenerationID: 5}})
			// Remove the selected GEN through the actual codec before preparing B.
			f.old.Authority.Phase, f.old.Authority.Cleanup = 1, nil
			control := eisMutation(0, []byte{2}, eiEncoded(t, f.old))
			control.BeforePresent = true
			eisSeed(t, f, []Mutation{control})
			pair := eisCapture(t, f, 1, 1, false, false)
			var result tsResult
			evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageProbeOnly, 0, []byte{2}, func() {
				mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
					result = tsInvoke(f.s, a, func(r *Reader) (TreeOperationV1, error) {
						token := eiPrepare(t, r, a, pair)
						failure, err := r.VisitEntryInventoryV1(token, func(EntryInventoryRowV1) error { return nil })
						if failure != nil || err != nil || !token.scope.completed {
							t.Fatalf("full query %+v/%v", failure, err)
						}
						if attach {
							pair.EntryInventory = &token
						}
						return TreeOperationV1{Pair: pair}, nil
					})
					return nil
				}))
			})
			mustEnvironment(t, err)
			result.tuple(t, 1, 1, -1)
			eiInput(t, result.err)
			if evidence.BeginWrite != 0 || evidence.Commits != 0 || evidence.Deletes != 0 || evidence.OldAborts != 1 || reservationLive(f.o) != 0 || evidence.OldGets[3] != 3 || evidence.OldGets[7] != 0 || evidence.NodeGets != 0 || evidence.NodePulls != 0 {
				t.Fatalf("prepared full query crossed write boundary %+v", evidence)
			}
			tsRead(t, f.s, TreeSchemaV1DBIs()[0], []byte{2}, eiEncoded(t, f.old))
			tsFollowing(t, f.s, f.o)
		})
	}
}

func eissGEN(t *testing.T) {
	f := eisNew(t, 3, 1, []CleanupSpanV1{{Kind: 1, GenerationID: 5}})
	// A real zero counter is still a selected GEN; it cannot authorize omission.
	eisSeed(t, f, []Mutation{eisMutation(0, tsCounterKey(5), make([]byte, 16))})
	pair := eisCapture(t, f, 1, 1, false, false)
	last := uint8(0)
	var result tsResult
	var failure *EntryInventoryFailureV1
	var sourceErr error
	evidence, err := fixtureLargeFault(f.s, 28, 0, tsCounterKey(5), func() {
		result, _, failure, sourceErr = eisInvoke(t, f, pair, func(row EntryInventoryRowV1) error {
			last = row.Source
			return nil
		})
	})
	mustEnvironment(t, err)
	eiInput(t, result.err)
	eiInput(t, sourceErr)
	if failure != nil || last != 13 || evidence.gets != 0 || evidence.commits != 0 || evidence.aborts != 1 || f.s.state != storeOPEN {
		t.Fatalf("GEN refusal touched its zero-counter native domain %+v/%d/%+v", failure, last, evidence)
	}
	tsFollowing(t, f.s, f.o)
}

func eissOwedRequired(t *testing.T) {
	for _, source := range []uint8{8, 10} {
		for _, malformed := range []bool{false, true} {
			t.Run(fmt.Sprintf("source%d-malformed%v", source, malformed), func(t *testing.T) {
				spans := []CleanupSpanV1{{Kind: 2, GenerationID: 11, FirstHeight: 0, NextHeight: 3, LastHeight: 4}, {Kind: 3, GenerationID: 11, FirstHeight: 0, NextHeight: 2, LastHeight: 3}}
				f := eisNew(t, 15845, 1, spans)
				for _, h := range []uint64{2, 3} {
					eisSeed(t, f, []Mutation{eisMutation(5, UndoManifestKey(f.hashes[h]), UndoManifestValue(h, [16]byte{}, 0, 0))})
				}
				pair := eisCapture(t, f, 1, 1, false, false)
				h, rank, artifact := uint64(3), uint8(4), uint8(7)
				if source == 10 {
					h, rank, artifact = 2, 5, 8
				}
				key := bytes.Clone(f.hashes[h][:])
				if source == 10 {
					key = append(key, 0)
				}
				if malformed {
					mustEnvironment(t, fixtureSeedPrefixRawRow(f.s, TreeSchemaV1DBIs()[rank], key, []byte{0xff}))
				} else {
					mustEnvironment(t, FixtureStartupDeleteRow(f.s, rank, key))
				}
				result, _, failure, err := eisInvoke(t, f, pair, func(EntryInventoryRowV1) error { return nil })
				observation := uint8(2)
				if malformed {
					observation = 4
				}
				eissFailure(t, failure, source, artifact, 1, 1, observation, 11, h, f.hashes[h], key, nil, nil)
				if err != nil || f.s.state != storeOPEN {
					t.Fatal("owed required source acquired native error")
				}
				eiInput(t, result.err)
				tsFollowing(t, f.s, f.o)
			})
		}
	}
}

func eissLargeFamily(t *testing.T) {
	f := eisNew(t, 3, 1, nil)
	pair := eisCapture(t, f, 1, 1, false, false)
	hash := f.hashes[3]
	dbi := TreeSchemaV1DBIs()[5]
	rows := []fixtureRawRow{{dbi, UndoManifestKey(hash), UndoManifestValue(3, [16]byte{}, 1, 16385)}}
	value, err := (UTXOValue{Value: 17, CovenantType: 2, CovenantData: []byte{3}, CreationHeight: 1}).Encode()
	mustEnvironment(t, err)
	for i := uint32(0); i < 16385; i++ {
		rows = append(rows, fixtureRawRow{dbi, UndoEntryKey(hash, [32]byte{3}, 0, i, 0), value})
		if len(rows) == 1000 {
			mustEnvironment(t, fixtureSeedRows(f.s, rows...))
			rows = nil
		}
	}
	if len(rows) != 0 {
		mustEnvironment(t, fixtureSeedRows(f.s, rows...))
	}
	count := 0
	eisSuccess(t, f, pair, func(row EntryInventoryRowV1) error {
		if row.Source == 5 {
			if count > 0 && !bytes.Equal(row.Key, UndoEntryKey(hash, [32]byte{3}, 0, uint32(count-1), 0)) {
				t.Fatal("raw spent order/identity changed")
			}
			if count == 16385 {
				dst := make([]byte, len(value))
				n, err := row.ReadAt(dst, 0)
				if n != len(value) || err != nil || !bytes.Equal(dst, value) {
					t.Fatal("last actual raw spent row ReadAt changed its source bytes")
				}
			}
			count++
		}
		return nil
	})
	if count != 16386 {
		t.Fatalf("uncapped manifest+16385 actual spent rows = %d", count)
	}
}

func eissCapacity(t *testing.T) {
	for _, short := range []uint64{0, 1} {
		t.Run(fmt.Sprint(short), func(t *testing.T) {
			f := eisNew(t, 3, 1, nil)
			pair := eisCapture(t, f, 1, 1, false, false)
			mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				e := uint64(8192) + 6*uint64(limitsForPage(f.s.config.PageSize).maxKey)
				filler := uint64(402653184) - e + short
				return a.WithReservation(filler, func() error {
					calls := 0
					result := tsInvoke(f.s, a, func(r *Reader) (TreeOperationV1, error) {
						token, failure, err := r.PrepareEntryInventoryV1(a, pair)
						if short == 1 {
							if any(err) != any(errOperationReservationCapacity) || token.scope != nil || failure != nil || reservationLive(f.o) != filler {
								t.Fatal("one-byte-short source capacity did not refuse before backing")
							}
							return TreeOperationV1{}, err
						}
						if err != nil || failure != nil {
							t.Fatalf("exact source E preparation %+v/%v", failure, err)
						}
						failure, err = r.VisitEntryInventoryV1(token, func(EntryInventoryRowV1) error {
							calls++
							if reservationLive(f.o) != 402653184 || token.scope.stream == nil || token.scope.stream.seek == nil {
								t.Fatal("row/stream exact funded coexistence changed")
							}
							return nil
						})
						if failure != nil || err != nil || !token.scope.completed || calls != 16 {
							t.Fatalf("exact E full source query %+v/%v/%d", failure, err, calls)
						}
						return TreeOperationV1{Pair: pair}, nil
					})
					result.tuple(t, 1, 1, -1)
					if reservationLive(f.o) != filler {
						t.Fatal("source E did not release exactly once")
					}
					return nil
				})
			}))
		})
	}
}

func eissNativeUnwind(t *testing.T) {
	for _, cleanup := range []uint32{1, 2, 9, 10} {
		for _, unwind := range []string{"panic", "panic-nil", "goexit"} {
			t.Run(fmt.Sprintf("cleanup%d-%s", cleanup, unwind), func(t *testing.T) {
				f := eisNew(t, 3, 1, nil)
				pair := eisCapture(t, f, 1, 2, false, false)
				header := eisHeader(3, f.hashes[2], 9)
				hash := sha3.Sum256(header)
				var token EntryInventoryV1
				var stream *entryStreamV1
				var physical error
				var recovered any
				marker := new(int)
				returned := false
				run := func() {
					defer func() { recovered = recover() }()
					_, err := fixtureLargeFault(f.s, cleanup, 3, hash[:], func() {
						mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
							_ = tsInvoke(f.s, a, func(r *Reader) (TreeOperationV1, error) {
								token = eiPrepare(t, r, a, pair)
								_, _ = r.VisitEntryInventoryV1(token, func(row EntryInventoryRowV1) error {
									if row.Source != 11 {
										return nil
									}
									stream = token.scope.stream
									if !stream.row.image.present {
										t.Fatal("native unwind has no parked link")
									}
									if cleanup == 1 || cleanup == 2 {
										_, physical = row.ReadAt(make([]byte, 1), 0)
										if physical == nil {
											t.Fatal("actual source11 ReadAt fault was not reached")
										}
									}
									switch unwind {
									case "panic":
										panic(marker)
									case "panic-nil":
										panic(treeCallNilPanicValue)
									default:
										runtime.Goexit()
									}
									return nil
								})
								return TreeOperationV1{}, nil
							})
							return nil
						}))
					})
					mustEnvironment(t, err)
					returned = true
				}
				if unwind == "goexit" {
					done := make(chan struct{})
					go func() {
						defer close(done)
						run()
					}()
					eiAwait(t, done)
				} else {
					run()
				}
				if returned || unwind == "panic" && recovered != marker || unwind == "panic-nil" && recovered == nil || unwind == "goexit" && recovered != nil {
					t.Fatal("native source/cleanup changed original unwind")
				}
				eissRetired(t, token, stream)
				primary := f.s.terminal
				if cleanup == 2 || cleanup == 10 {
					engine := requireEnvironmentError(t, primary, "LocalInvariant", operationAbort, -30416, "MDBX_THREAD_MISMATCH: A thread has attempted to use a not owned object, e.g. a transaction that started by another thread")
					if !engine.ReopenRequired || f.s.state != storePOISONEDTHREAD || f.s.txn == nil {
						t.Fatal("retained source cleanup lost its exact disposition")
					}
					primary = engine.Cause
				}
				if cleanup == 9 {
					treeNativeError(t, primary, "abort", "IO", 5, "error 5", nil)
				} else if any(primary) != any(physical) {
					t.Fatal("raw original source cause changed under unwind")
				}
				if physical != nil {
					eissFailure(t, token.scope.failureResultV1(), 11, 6, 0, 3, 1, 21, 3, hash, hash[:], nil, physical)
				}
				if reservationLive(f.o) != 0 || f.s.terminalTruth != 1 {
					t.Fatal("native source unwind retained its hold/truth")
				}
				if cleanup == 1 || cleanup == 9 {
					tsConsumed(t, f.s, f.o, 1, f.s.terminal)
					return
				}
				calls := 0
				mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
					next := tsInvoke(f.s, a, func(*Reader) (TreeOperationV1, error) {
						calls++
						return TreeOperationV1{}, nil
					})
					next.tuple(t, 1, 1, -1)
					if calls != 0 || any(next.err) != any(f.s.terminal) {
						t.Fatal("retained source allowed a next operation")
					}
					return nil
				}))
				mustEnvironment(t, FixtureStartupRelease(f.s))
			})
		}
	}
}

func eissLinkShapes(t *testing.T) {
	for _, field := range []string{"hash", "parent", "work"} {
		t.Run(field, func(t *testing.T) {
			f := eisNew(t, 3, 1, nil)
			pair := eisCapture(t, f, 1, 2, false, false)
			hash := sha3.Sum256(eisHeader(3, f.hashes[2], 9))
			value := eisChain(hash, f.hashes[2], 3)
			switch field {
			case "hash":
				value[0] ^= 1
			case "parent":
				value[32] ^= 1
			case "work":
				clear(value[64:])
			}
			key := eisHeight(21, 3)
			mustEnvironment(t, fixtureSeedPrefixRawRow(f.s, TreeSchemaV1DBIs()[6], key, value))
			last := uint8(0)
			result, _, failure, err := eisInvoke(t, f, pair, func(row EntryInventoryRowV1) error {
				last = row.Source
				return nil
			})
			eissFailure(t, failure, 13, 9, 0, 1, 4, 21, 3, hash, key, nil, nil)
			if err != nil || last != 9 {
				t.Fatal("physical SideLink identity was trusted before validation")
			}
			eiInput(t, result.err)
		})
	}
}
