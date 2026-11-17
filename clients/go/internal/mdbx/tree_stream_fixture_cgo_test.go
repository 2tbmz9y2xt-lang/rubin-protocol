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
	"strings"
	"sync"
	"testing"
	"unsafe"
)

// The raw native owner distinguishes metadata-only mismatches from payload use.
func TestTreePairReadNativeV1(t *testing.T) {
	t.Run("absent-OLD", pairReadAbsentNativeV1)
	t.Run("metadata-error-priority", pairReadMetadataNativeV1)
	t.Run("funded-engine-Goexit", pairReadGoexitV1)
	t.Run("closed-account-before-read-grow", pairReadClosedNativeV1)
	for _, width := range []int{0, 1, 32, 70000} {
		for _, short := range []uint64{0, 1} {
			if width == 0 && short == 1 {
				continue
			}
			t.Run(fmt.Sprintf("raw%d/short%d", width, short), func(t *testing.T) {
				s, path, o := tsNew(t)
				key := []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1}
				value := bytes.Repeat([]byte{0x56}, width)
				treeNativeSeed(t, s, 0, key, value)
				op := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[0], Key: key, BeforePresent: true, AfterKind: 1}}}}
				window := uint64(width) * 2
				var result tsResult
				var observed PairReadObservation
				mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
					return a.WithReservation(137, func() error {
						return a.WithReservation(154611183-274-window+short, func() error {
							var err error
							observed, err = FixturePairReadObservation(s, func(site uint32) {
								if site == 2 && reservationLive(o) != 154611183 {
									t.Error("ordinary read held full admitted window")
								}
							}, func() { result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) })
							mustEnvironment(t, err)
							if reservationLive(o) != 154611183-137-window+short {
								t.Fatal("engine released caller reservation")
							}
							return nil
						})
					})
				}))
				if short == 1 {
					result.tuple(t, 1, 1, -1)
					if !treeSameErrorV1(result.err, errOperationReservationCapacity) || observed.Comparisons != 0 || observed.Gets != 3 || observed.Writes != 0 || s.state != storeCLOSED {
						t.Fatalf("payload comparisons before refused coverage=0: %+v/%+v", result, observed)
					}
				} else {
					result.tuple(t, 2, 3, -1)
					mustEnvironment(t, result.err)
					wantPayload := uint64(1)
					if width == 0 {
						wantPayload = 0
					}
					if observed.Gets != 4 || observed.Comparisons != wantPayload || observed.Aliases != wantPayload || observed.Writes != 1 {
						t.Fatalf("one get per reached comparison position/identical backing: %+v", observed)
					}
				}
				s = tsReopen(t, s, path)
				var want []byte
				if short == 1 {
					want = value
				}
				equal, err := FixtureRawRowEqual(s, 0, key, want)
				if err != nil || !equal {
					t.Fatal("durable raw OLD/NEW", err)
				}
			})
		}
	}
}

// Each row reaches an existing production owner, with literal windows and
// native probes distinguishing admission from payload use and later failure.
func TestTreePrimitiveReadNativeV1(t *testing.T) {
	t.Run("Pair-before-payload", primitiveReadPairNativeV1)
	t.Run("owner-scratch", primitiveReadOwnerNativeV1)
	t.Run("owner-pre-key", primitiveReadOwnerPrekeyV1)
	t.Run("owner-disposable-and-targeted", primitiveReadOwnerDisposableV1)
	t.Run("amended-point", primitiveReadPointNativeV1)
	t.Run("fused-error-before-capacity", primitiveReadFusedErrorV1)
	t.Run("successor", primitiveReadSuccessorNativeV1)
	t.Run("future-seal", primitiveReadFutureNativeV1)
	t.Run("partial-growth", primitiveReadPartialNativeV1)
	t.Run("reached-stage", primitiveReadStagesV1)
	t.Run("late-header", primitiveReadHeaderNativeV1)
	t.Run("closed-account", func(t *testing.T) { treeReadClosedNativeV1(t, true) })
	t.Run("mutable-window-Goexit", primitiveReadGoexitV1)
	t.Run("candidate-MaxInt-before-mismatch", func(t *testing.T) { primitiveReadPointMetadataV1(t, 35, true) })
	t.Run("planned-absence-native-present", primitiveReadPointAbsentV1)
	for _, mode := range []uint32{31, 32, 33, 34, 35, 36, 37} {
		t.Run(fmt.Sprintf("point-metadata%d", mode), func(t *testing.T) {
			primitiveReadPointMetadataV1(t, mode, false)
		})
	}
}

func primitiveReadFusedErrorV1(t *testing.T) {
	s, _ := ttStore(t)
	key := []byte{0x85}
	ledger := &pairReadTestLedgerV1{err: errOperationReservationCapacity}
	var outcome updateNativeOutcome
	var counts PairReadObservation
	evidence, err := fixtureLargeFault(s, 34, 1, key, func() {
		var observeErr error
		counts, observeErr = FixturePairReadObservation(s, nil, func() {
			outcome = fixtureTreeCommitV1(s, fixtureTreeScriptV1{ledger: ledger, write: func(section *treeSectionV1) error {
				err := section.writerV1().emitV1(ttTarget(ttUTXO, key, "x"))
				if section.pairReadLimit != 0 || section.pBudgetV1() != 0 {
					t.Error("fused native error must precede window growth and P copy")
				}
				return err
			}})
		})
		mustEnvironment(t, observeErr)
	})
	mustEnvironment(t, err)
	ttOutcome(t, outcome, 1, 2)
	treeNativeError(t, outcome.primary, "update", "IO", 5, "error 5", nil)
	mustEnvironment(t, outcome.secondary)
	// fixtureTreeCommitV1 aborts OLD via rubin_fixture_txn_abort, bypassing the OLD-only counter.
	if outcome.commitAttempted || counts != (PairReadObservation{Gets: 2, Writes: 1}) || evidence != (fixtureLargeEvidence{gets: 1}) {
		t.Fatal("fused error preserves native prefix and clean abort", outcome, counts, ledger.held, evidence)
	}
	equal, err := FixtureRawRowEqual(s, 1, key, nil)
	if err != nil || !equal {
		t.Fatal("fused error abort preserves durable OLD", err)
	}
}

func primitiveReadPairNativeV1(t *testing.T) {
	for _, width := range []int{0, 1, 32, 70000} {
		for _, short := range []uint64{0, 1} {
			if width == 0 && short == 1 {
				continue
			}
			t.Run(fmt.Sprintf("width%d/short%d", width, short), func(t *testing.T) {
				s, path, o := tsNew(t)
				key, later := tsCounterKey(9), tsCounterKey(10)
				value := bytes.Repeat([]byte{0x56}, width)
				treeNativeSeed(t, s, 0, key, value)
				treeNativeSeed(t, s, 0, later, []byte{7})
				op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error {
					t.Error("Pair prefix reached Source")
					return nil
				}))
				op.Pair = TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[0], Key: key, BeforePresent: true, AfterKind: 1}}, Consulted: []ConsultedRow{{DBI: TreeSchemaV1DBIs()[0], Key: later}}}
				tsCover(&op, TreeBlockV1{TxCount: 1})
				window := uint64(2 * width)
				var result tsResult
				var counts PairReadObservation
				mustEnvironment(t, o.WithOperation(TreeOperation, func(a *OperationAccount) error {
					return a.WithReservation(402653184-194-window+short, func() error {
						before := reservationLive(o)
						var err error
						counts, err = FixturePairReadObservation(s, func(site uint32) {
							if site == 2 && reservationLive(o) != 402653184 {
								t.Error("primitive Pair before-payload coverage")
							}
						}, func() {
							_, faultErr := fixtureLargeFault(s, 34, 0, later, func() { result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) })
							mustEnvironment(t, faultErr)
						})
						mustEnvironment(t, err)
						if reservationLive(o) != before {
							t.Fatal("primitive Pair earlier window/caller cleanup")
						}
						return nil
					})
				}))
				result.tuple(t, 1, 1, -1)
				if short != 0 {
					if !treeSameErrorV1(result.err, errOperationReservationCapacity) || counts.Comparisons != 0 || counts.Gets != 3 {
						t.Fatal("primitive Pair before-payload coverage/refusal prefix", result, counts)
					}
				} else {
					treeNativeError(t, result.err, "update", "IO", 5, "error 5", nil)
					want := uint64(1)
					if width == 0 {
						want = 0
					}
					if counts.Comparisons != want || counts.Gets != 5 {
						t.Fatal("one get per reached position/later EIO", counts)
					}
				}
				if counts.Writes != 0 {
					t.Fatal("Pair refusal wrote")
				}
				tsConsumed(t, s, o, 1, result.err)
				equal, err := FixtureRawRowEqual(tsReopen(t, s, path), 0, key, value)
				if err != nil || !equal {
					t.Fatal("primitive Pair durable OLD", err)
				}
			})
		}
	}
}

func primitiveReadOwnerNativeV1(t *testing.T) {
	hash := [32]byte{0x41}
	f, o := canonicalForwardLiteral(1, 5, hash, [40]byte{39: 1}), canonicalOwnerLiteral(1, 5, hash)
	for _, row := range []struct {
		name       string
		pair, seed []Mutation
		pc, room   uint64
		capacity   bool
		gets       [8]uint64
	}{
		{"N1-39", []Mutation{f}, nil, 248, 39, true, [8]uint64{2: 1}},
		{"N1-40", []Mutation{f}, nil, 248, 40, false, [8]uint64{2: 1}},
		{"N2-39", []Mutation{o}, nil, 176, 39, true, [8]uint64{7: 1}},
		{"N2-40", []Mutation{o}, nil, 176, 40, false, [8]uint64{7: 1}},
		{"O1-false-obligation-175", []Mutation{f, o}, []Mutation{f, o}, 424, 175, true, [8]uint64{2: 2, 7: 1}},
		{"O1-partner-176", []Mutation{canonicalDelete(f)}, []Mutation{f, o}, 144, 176, false, [8]uint64{2: 2, 7: 1}},
		{"O2-partner-191", []Mutation{canonicalDelete(o)}, []Mutation{f, o}, 168, 191, true, [8]uint64{2: 1, 7: 2}},
		{"O2-partner-192", []Mutation{canonicalDelete(o)}, []Mutation{f, o}, 168, 192, false, [8]uint64{2: 1, 7: 2}},
	} {
		t.Run(row.name, func(t *testing.T) {
			s, path, reservations := tsNew(t)
			for _, m := range row.seed {
				treeNativeSeed(t, s, m.DBI.Rank, m.Key, m.Literal)
			}
			op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error {
				t.Error("owner preflight reached Source")
				return nil
			}))
			op.Pair.Mutations = row.pair
			var result tsResult
			var evidence SelectedDamageEvidence
			mustEnvironment(t, reservations.WithOperation(TreeOperation, func(a *OperationAccount) error {
				return a.WithReservation(402653184-row.pc-row.room, func() error {
					before := reservationLive(reservations)
					var err error
					evidence, err = FixtureSelectedDamage(s, reservations, SelectedDamageProbeOnly, 0, nil, func() { result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) })
					if reservationLive(reservations) != before {
						t.Fatal("owner scratch cleanup/caller hold")
					}
					return err
				})
			}))
			result.tuple(t, 1, 1, -1)
			if row.capacity {
				if !treeSameErrorV1(result.err, errOperationReservationCapacity) {
					t.Fatal("primitive owner scratch boundary", result.err)
				}
			} else {
				treeNativeError(t, result.err, "update", "InvalidInput", 22, "unpaired canonical owner mutation", nil)
			}
			if evidence.OldGets != row.gets || evidence.Deletes != 0 || evidence.Commits != 0 {
				t.Fatal("primitive owner get prefix", evidence)
			}
			tsConsumed(t, s, reservations, 1, result.err)
			s = tsReopen(t, s, path)
			for _, m := range row.seed {
				equal, err := FixtureRawRowEqual(s, m.DBI.Rank, m.Key, m.Literal)
				if err != nil || !equal {
					t.Fatal("owner scratch durable OLD", err)
				}
			}
		})
	}
}

func primitiveReadPointNativeV1(t *testing.T) {
	for _, planned := range []bool{false, true} {
		for _, distinct := range []bool{false, true} {
			for _, short := range []uint64{0, 1} {
				t.Run(fmt.Sprintf("P%v/distinct%v/short%d", planned, distinct, short), func(t *testing.T) {
					s, _ := ttStore(t)
					key, value := []byte{0x81}, bytes.Repeat([]byte{0x46}, 70000)
					treeNativeSeed(t, s, 1, key, value)
					need, p := uint64(140000), uint64(0)
					if planned {
						need, p = 70000, 70001
					}
					ledger := &pairReadTestLedgerV1{limit: p + need - short}
					var observed PairReadObservation
					var result error
					run := func() {
						var err error
						observed, err = FixturePairReadObservation(s, func(site uint32) {
							if site == 2 && ledger.held != p+need {
								t.Error("native expected and candidate140000/owned expected candidate70000", ledger.held)
							}
						}, func() {
							result = fixtureTreeSectionV1(s, ledger, func(section *treeSectionV1) error {
								if planned {
									section.covered = true
									if err := section.writerV1().emitV1(treeTargetV1{dbi: ttUTXO, key: key, after: treeImageV1{present: true, value: value}}); err != nil {
										return err
									}
									section.covered = false
								}
								image, err := section.oldV1(true).getV1(ttUTXO, key)
								if err == nil && (!image.present || !bytes.Equal(image.value, value)) {
									t.Error("amended point value")
								}
								return err
							})
						})
						mustEnvironment(t, err)
					}
					if distinct {
						_, err := fixtureLargeFault(s, 37, 1, key, run)
						mustEnvironment(t, err)
					} else {
						run()
					}
					if short != 0 {
						if !treeSameErrorV1(result, errOperationReservationCapacity) || observed.Comparisons != 0 || observed.Writes != 0 || ledger.held != p {
							t.Fatal("point/future NEW before payload refusal", result, observed, ledger.held)
						}
					} else {
						mustEnvironment(t, result)
						gets := uint64(2)
						if planned {
							gets = 1
						}
						alias := uint64(1)
						if distinct || planned {
							alias = 0
						}
						if observed.Gets != gets || observed.Comparisons != 1 || observed.Aliases != alias || ledger.held != p+need {
							t.Fatal("complete point window/one get/alias", observed, ledger.held)
						}
					}
				})
			}
		}
	}
}

func primitiveReadPointMetadataV1(t *testing.T, mode uint32, planned bool) {
	s, _ := ttStore(t)
	key, value := []byte{0x82}, bytes.Repeat([]byte{0x55}, 32)
	treeNativeSeed(t, s, 1, key, value)
	ledger := &pairReadTestLedgerV1{limit: 64}
	if planned {
		ledger.limit = 65 // P(key1+value32) and independent native candidate32.
	}
	var result error
	var counts PairReadObservation
	_, err := fixtureLargeFault(s, mode, 1, key, func() {
		var observeErr error
		counts, observeErr = FixturePairReadObservation(s, nil, func() {
			result = fixtureTreeSectionV1(s, ledger, func(section *treeSectionV1) error {
				if planned {
					if err := section.recordV1(ttUTXO, key, treeEntryImageV1, value); err != nil {
						return err
					}
				}
				_, err := section.oldV1(true).getV1(ttUTXO, key)
				return err
			})
		})
		mustEnvironment(t, observeErr)
	})
	mustEnvironment(t, err)
	switch mode {
	case 31, 32, 36:
		ttMismatch(t, result, "OLD/write snapshot mismatch")
	case 33, 35:
		treeNativeError(t, result, "update", "LocalInvariant", -30779, "mdbx_get returned invalid result shape", nil)
	case 34:
		treeNativeError(t, result, "update", "IO", 5, "error 5", nil)
	case 37:
		mustEnvironment(t, result)
	}
	wantGets, wantCompares := uint64(2), uint64(0)
	if mode == 35 {
		wantGets = 1 // representability refuses ORIGINAL metadata before exposure.
	}
	if mode == 37 {
		wantCompares = 1
	}
	if counts.Gets != wantGets || counts.Comparisons != wantCompares || counts.Aliases != 0 || counts.Writes != 0 {
		t.Fatal("native shape/rc before payload capacity", counts)
	}
}

func primitiveReadPointAbsentV1(t *testing.T) {
	s, _ := ttStore(t)
	key := []byte{0x84}
	treeNativeSeed(t, s, 1, key, bytes.Repeat([]byte{0x54}, 32))
	ledger := &pairReadTestLedgerV1{limit: 1} // P absence key1; no native payload capacity.
	var result error
	counts, err := FixturePairReadObservation(s, nil, func() {
		result = fixtureTreeSectionV1(s, ledger, func(section *treeSectionV1) error {
			if err := section.recordV1(ttUTXO, key, treeEntryAbsentV1, nil); err != nil {
				return err
			}
			_, err := section.oldV1(true).getV1(ttUTXO, key)
			if section.pairReadLimit != 0 || ledger.held != 1 {
				t.Error("absence metadata mismatch must not acquire native payload")
			}
			return err
		})
	})
	mustEnvironment(t, err)
	ttMismatch(t, result, "OLD/write snapshot mismatch")
	if counts.Gets != 1 || counts.Comparisons != 0 || counts.Writes != 0 {
		t.Fatal("planned absent/native present is metadata-only false", counts)
	}
}

func primitiveReadSuccessorNativeV1(t *testing.T) {
	t.Run("planned-key-and-value", primitiveReadPlannedNextV1)
	for _, covered := range []bool{false, true} {
		for _, variant := range []string{"exact", "short", "key-mismatch", "key-length", "value-length", "value-bytes"} {
			t.Run(fmt.Sprintf("covered%v/%s", covered, variant), func(t *testing.T) {
				s, _ := ttStore(t)
				key, value := []byte{0x81}, bytes.Repeat([]byte{0x4a}, 32)
				wantHeld := uint64(66)
				if variant == "value-bytes" {
					value, wantHeld = []byte{0x7e}, 4
				}
				treeNativeSeed(t, s, 1, key, value)
				limit := uint64(66)
				if variant == "short" {
					limit = 65
				}
				ledger := &pairReadTestLedgerV1{limit: limit}
				var result error
				var counts PairReadObservation
				var evidence SelectedDamageEvidence
				run := func() {
					var err error
					evidence, err = FixtureSelectedDamage(s, nil, SelectedDamageProbeOnly, 0, nil, func() {
						var observeErr error
						counts, observeErr = FixturePairReadObservation(s, nil, func() {
							result = fixtureTreeSectionV1(s, ledger, func(section *treeSectionV1) error {
								section.covered = covered
								got, image, ok, err := section.oldV1(true).nextV1(ttUTXO, []byte{0x80})
								if err == nil && (!ok || !bytes.Equal(got, key) || !bytes.Equal(image.value, value)) {
									t.Error("successor logical image")
								}
								return err
							})
						})
						mustEnvironment(t, observeErr)
					})
					mustEnvironment(t, err)
				}
				if variant != "exact" && variant != "short" {
					driftKey := []byte{0x80}
					if variant == "key-length" {
						driftKey = []byte{0x80, 0x01}
					}
					if variant == "value-length" || variant == "value-bytes" {
						driftKey = key
					}
					_, err := FixtureWriteSnapshotDrift(s, 1, driftKey, run)
					mustEnvironment(t, err)
				} else {
					run()
				}
				wantCompares := uint64(2)
				switch variant {
				case "short":
					wantCompares = 0
					if !treeSameErrorV1(result, errOperationReservationCapacity) || ledger.held != 0 {
						t.Fatal("complete successor extent before exposure", result, ledger.held)
					}
				case "key-mismatch":
					wantCompares = 1
					ttMismatch(t, result, "OLD/write snapshot mismatch")
				case "key-length":
					wantCompares = 0
					ttMismatch(t, result, "OLD/write snapshot mismatch")
				case "value-length":
					wantCompares = 1
					ttMismatch(t, result, "OLD/write snapshot mismatch")
				case "value-bytes":
					ttMismatch(t, result, "OLD/write snapshot mismatch")
				default:
					mustEnvironment(t, result)
				}
				if counts.Comparisons != wantCompares || counts.Writes != 0 || evidence.OldPulls[1] != 1 || variant != "short" && ledger.held != wantHeld {
					t.Fatal("successor key mismatch value payload=0/one OLD pull", counts, evidence, ledger.held)
				}
			})
		}
	}
}

func primitiveReadPlannedNextV1(t *testing.T) {
	for _, short := range []uint64{0, 1} {
		t.Run(fmt.Sprintf("short%d", short), func(t *testing.T) {
			s, _ := ttStore(t)
			key, value := []byte{0x81}, bytes.Repeat([]byte{0x4a}, 70000)
			ledger := &pairReadTestLedgerV1{limit: 140002 - short}
			var result error
			counts, err := FixturePairReadObservation(s, nil, func() {
				result = fixtureTreeSectionV1(s, ledger, func(section *treeSectionV1) error {
					if err := section.writerV1().emitV1(treeTargetV1{dbi: ttUTXO, key: key, after: treeImageV1{present: true, value: value}}); err != nil {
						return err
					}
					_, _, _, err := section.oldV1(true).nextV1(ttUTXO, key)
					if section.reached != 2 || section.pBudgetV1() != 70001 || section.pairReadLimit != 70001-short {
						t.Error("P and native successor capacity are distinct", section.reached, section.pBudgetV1(), section.pairReadLimit)
					}
					return err
				})
			})
			mustEnvironment(t, err)
			if short != 0 {
				if !treeSameErrorV1(result, errOperationReservationCapacity) || counts.Comparisons != 2 || ledger.held != 140001 {
					t.Fatal("planned successor full k+b refusal after key", result, counts, ledger.held)
				}
			} else if result != nil || counts.Comparisons != 3 || ledger.held != 140002 {
				t.Fatal("planned successor k+b complete", result, counts, ledger.held)
			}
			if counts.Writes != 1 {
				t.Fatal("raw successor producer changed native write sequence", counts)
			}
			equal, err := FixtureRawRowEqual(s, 1, key, nil)
			if err != nil || !equal {
				t.Fatal("raw successor fixture abort durable OLD", err)
			}
		})
	}
}

func primitiveReadFutureNativeV1(t *testing.T) {
	for _, mode := range []string{"raw-OLD", "covered-NEW", "reference-OLD"} {
		for _, short := range []uint64{0, 1} {
			t.Run(fmt.Sprintf("%s/short%d", mode, short), func(t *testing.T) {
				s, _ := ttStore(t)
				key := []byte{0x83}
				limit, native, p := uint64(140010), uint64(140000), uint64(10)
				if mode != "covered-NEW" {
					treeNativeSeed(t, s, 1, key, bytes.Repeat([]byte{0x61}, 70000))
				}
				if mode == "covered-NEW" {
					limit, p = 280001, 140001
				}
				if mode == "reference-OLD" {
					limit, p = 140001, 1
				}
				if short != 0 {
					limit = native + p - 1
					if mode == "raw-OLD" {
						limit = 139999
					}
				}
				ledger := &pairReadTestLedgerV1{limit: limit}
				var result error
				counts, err := FixturePairReadObservation(s, func(site uint32) {
					if site == 3 && ledger.held < native {
						t.Error("future OLD before raw write/future NEW before flush", mode, ledger.held)
					}
				}, func() {
					result = fixtureTreeSectionV1(s, ledger, func(section *treeSectionV1) error {
						if mode == "reference-OLD" {
							if err := section.writerV1().referV1(ttUTXO, key); err != nil {
								return err
							}
							return section.finalV1(nil, nil)
						}
						section.covered = mode == "covered-NEW"
						value := []byte("abc")
						if section.covered {
							value = bytes.Repeat([]byte{0x7a}, 140000)
						}
						if err := section.writerV1().emitV1(treeTargetV1{dbi: ttUTXO, key: key, after: treeImageV1{present: true, value: value}}); err != nil {
							return err
						}
						if !section.covered {
							if err := section.writerV1().emitV1(ttTarget(ttUTXO, key, "abcde")); err != nil {
								return err
							}
						} else if err := section.flushV1(nil); err != nil {
							return err
						}
						if section.pairReadLimit != native || section.pBudgetV1() != p {
							t.Error("future OLD/NEW exact native/P high-waters", section.pairReadLimit, section.pBudgetV1())
						}
						return section.finalV1(nil, nil)
					})
				})
				mustEnvironment(t, err)
				if short != 0 {
					if !treeSameErrorV1(result, errOperationReservationCapacity) || counts.Writes != 0 || counts.Comparisons != 0 {
						t.Fatal("future declaration refused before native work", result, counts)
					}
				} else if result != nil || ledger.held != native+p {
					t.Fatal("future declaration/native and P remain separate", result, ledger.held)
				}
			})
		}
	}
}

func primitiveReadPartialNativeV1(t *testing.T) {
	s, _ := ttStore(t)
	keys := [][]byte{tsCounterKey(8), tsCounterKey(9)}
	for i, width := range []int{32, 70000} {
		treeNativeSeed(t, s, 0, keys[i], bytes.Repeat([]byte{0x42}, width))
	}
	ledger := &pairReadTestLedgerV1{limit: 139999}
	var high uint64
	err := fixtureTreeSectionV1(s, ledger, func(section *treeSectionV1) error {
		pair := []ownedMutation{{dbi: schemaDBIs[0], key: keys[0], beforePresent: true, after: AfterAbsent}, {dbi: schemaDBIs[0], key: keys[1], beforePresent: true, after: AfterAbsent}}
		err := section.pairPreflightV1(pair, nil)
		high = section.pairReadLimit
		return err
	})
	if !treeSameErrorV1(err, errOperationReservationCapacity) || high != 64 || ledger.held != 64 {
		t.Fatal("earlier admitted window retained on later refusal", err, high, ledger.held)
	}
	ledger.releaseV1(64) // This seam omits the public enclosing hold.
	if ledger.held != 0 {
		t.Fatal("earlier admitted window exact release")
	}
}

func primitiveReadOwnerPrekeyV1(t *testing.T) {
	for _, room := range []uint64{87, 88} {
		t.Run(fmt.Sprint(room), func(t *testing.T) {
			s, path, o := tsNew(t)
			f, owner := canonicalForwardLiteral(1, 5, [32]byte{0x41}, [40]byte{39: 1}), canonicalOwnerLiteral(1, 5, [32]byte{0x41})
			treeNativeSeed(t, s, 7, owner.Key, owner.Literal)
			treeNativeSeed(t, s, 2, f.Key, f.Literal)
			op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { t.Error("pre-key reached Source"); return nil }))
			op.Pair.Mutations = []Mutation{canonicalDelete(owner)}
			var result tsResult
			var evidence SelectedDamageEvidence
			var faultErr error
			mustEnvironment(t, o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				return a.WithReservation(402653184-168-room, func() error {
					evidence, faultErr = FixtureSelectedDamage(s, o, SelectedDamageGetEIO, 2, f.Key, func() { result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) })
					return nil
				})
			}))
			result.tuple(t, 1, 1, -1)
			want := [8]uint64{7: 2}
			if room == 87 {
				tsfSlotUnreached(t, evidence, faultErr)
				if !treeSameErrorV1(result.err, errOperationReservationCapacity) {
					t.Fatal("primitive O2 pre-key87 before partner get", result.err)
				}
			} else {
				mustEnvironment(t, faultErr)
				want[2] = 1
				treeNativeError(t, result.err, "update", "IO", 5, "error 5", nil)
			}
			if evidence.OldGets != want || reservationLive(o) != 0 {
				t.Fatal("primitive pre-key get prefix/earlier80 cleanup", evidence)
			}
			tsConsumed(t, s, o, 1, result.err)
			equal, err := FixtureRawRowEqual(tsReopen(t, s, path), 7, owner.Key, owner.Literal)
			if err != nil || !equal {
				t.Fatal("pre-key durable OLD", err)
			}
		})
	}
}

func primitiveReadOwnerDisposableV1(t *testing.T) {
	f, o := canonicalForwardLiteral(1, 5, [32]byte{0x41}, [40]byte{39: 1}), canonicalOwnerLiteral(1, 5, [32]byte{0x41})
	badF, badO := f, o
	badF.Literal, badO.Literal = bytes.Clone(f.Literal[:103]), append(bytes.Clone(o.Literal), 0)
	for _, row := range []struct {
		name       string
		pair, seed []Mutation
		pc, room   uint64
		gets       [8]uint64
	}{
		{"wrong-target-width", []Mutation{canonicalDelete(o)}, []Mutation{badO}, 168, 18, [8]uint64{7: 3}},
		{"wrong-partner-width", []Mutation{canonicalDelete(o)}, []Mutation{badF, o}, 168, 88, [8]uint64{2: 1, 7: 3}},
		{"targeted-partner", []Mutation{canonicalDelete(f), canonicalDelete(o)}, []Mutation{f, o}, 312, 208, [8]uint64{2: 3, 7: 3}},
	} {
		t.Run(row.name, func(t *testing.T) {
			s, _, reservations := tsNew(t)
			for _, m := range row.seed {
				treeNativeSeed(t, s, m.DBI.Rank, m.Key, m.Literal)
			}
			op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error {
				t.Error("owner prefix reached Source")
				return nil
			}))
			op.Pair.Mutations = row.pair
			var result tsResult
			var evidence SelectedDamageEvidence
			mustEnvironment(t, reservations.WithOperation(TreeOperation, func(a *OperationAccount) error {
				return a.WithReservation(402653184-row.pc-row.room, func() error {
					var err error
					evidence, err = FixtureSelectedDamage(s, reservations, SelectedDamageProbeOnly, 0, nil, func() { result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) })
					return err
				})
			}))
			result.tuple(t, 1, 1, 0) // All owner checks completed; the later step needs74912.
			if !treeSameErrorV1(result.err, errOperationReservationCapacity) || evidence.OldGets != row.gets || evidence.Deletes != 0 || evidence.Commits != 0 {
				t.Fatal("metadata-only/targeted partner prefix", result, evidence)
			}
			tsConsumed(t, s, reservations, 1, result.err)
		})
	}
}

func primitiveReadGoexitV1(t *testing.T) {
	s, _, o := tsNew(t)
	key, old := tsCounterKey(9), bytes.Repeat([]byte{0x77}, 32)
	treeNativeSeed(t, s, 0, key, old)
	op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error {
		t.Error("Goexit prefix reached Source")
		return nil
	}))
	op.Pair.Mutations = []Mutation{{DBI: TreeSchemaV1DBIs()[0], Key: key, BeforePresent: true, AfterKind: 1}}
	fired, returned := false, false
	mustEnvironment(t, o.WithReservation(19, func() error {
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				return a.WithReservation(137, func() error {
					defer func() {
						if reservationLive(o) != 156 {
							t.Error("Goexit caller/source hold survived exact native cleanup")
						}
					}()
					_, err := FixturePairReadObservation(s, func(site uint32) {
						if site == 2 {
							fired = true
							if reservationLive(o) != 357 {
								t.Error("Goexit mutable window64 held before comparison")
							}
							runtime.Goexit()
						}
					}, func() { _ = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) })
					returned = true
					return err
				})
			})
		}()
		eiAwait(t, done)
		if !fired || returned || reservationLive(o) != 19 || s.state != storeOPEN {
			t.Fatal("mutable-window Goexit cleanup/lifecycle", fired, returned, reservationLive(o), s.state)
		}
		return nil
	}))
	equal, err := FixtureRawRowEqual(s, 0, key, old)
	if err != nil || !equal || reservationLive(o) != 0 {
		t.Fatal("Goexit durable OLD and foreign release", err)
	}
	tsFollowing(t, s, o)
}

func primitiveReadHeaderNativeV1(t *testing.T) {
	for _, short := range []uint64{0, 1} {
		t.Run(fmt.Sprintf("short%d", short), func(t *testing.T) {
			s, log, key, _ := tsfSlot(t)
			value := bytes.Repeat([]byte{0x69}, 70000)
			treeNativeSeed(t, s.s, 3, key, value)
			p := s.budgets(t)[2]
			// Q=body319+report152+undo72+slot/spare388; heldR=419632+104*2.
			competitor := uint64(805306368-931-419840-8808) - p + short
			proved, compared := false, false
			s.op.Proof = func(report *TreeDeltaReportV1) error {
				if err := log.proof(report); err != nil {
					return err
				}
				if reservationLive(s.o) != 931+p+419840 {
					t.Error("late HeaderSlot combined P+B_r+floor", reservationLive(s.o), p)
				}
				reservationFill(t, s.o, competitor)
				proved = true
				return nil
			}
			var result tsResult
			builders := 0
			counts, err := FixturePairReadObservation(s.s, func(site uint32) {
				if proved && site == 2 {
					compared = true
					if reservationLive(s.o) != 805306368 {
						t.Error("late HeaderSlot complete140000/floor shortfall8808")
					}
				}
			}, func() {
				mustEnvironment(t, s.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
					result = tsInvoke(s.s, a, func(*Reader) (TreeOperationV1, error) { builders++; return s.op, nil })
					return nil
				}))
			})
			mustEnvironment(t, err)
			result.tuple(t, 1, 1, -1)
			if short != 0 {
				if !treeSameErrorV1(result.err, errOperationReservationCapacity) || compared {
					t.Fatal("late HeaderSlot room-1 before payload", result)
				}
			} else {
				tsfSlotDiffers(t, result.err)
				if !compared {
					t.Fatal("funded late HeaderSlot reaches native comparison")
				}
			}
			if !proved || log.calls != 1 || builders != 1 || counts.Writes != 0 || reservationLive(s.o) != competitor {
				t.Fatal("late HeaderSlot Proof/write/own-remainder cleanup", proved, log.calls, counts, reservationLive(s.o))
			}
			tsConsumed(t, s.s, s.o, 1, result.err)
			s.durable(t, false)
			equal, err := FixtureRawRowEqual(s.s, 3, key, value)
			if err != nil || !equal {
				t.Fatal("late HeaderSlot durable OLD", err)
			}
		})
	}
}

// A disposable raw body is observed only through its resource prefix; the funded
// control stops at the Source marker before interpreting it. The second row
// reaches the same new native-window refusal after an earlier primitive wrote.
func primitiveReadStagesV1(t *testing.T) {
	for _, afterWrite := range []bool{false, true} {
		for _, short := range []uint64{0, 1} {
			t.Run(fmt.Sprintf("after-write%v/short%d", afterWrite, short), func(t *testing.T) {
				s, path, o := tsNew(t)
				marker, calls := errors.New("funded raw body Source marker"), 0
				source := tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { calls++; return marker })
				op := tsOperation(t, tsSource(func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
					return sink.BeginV1(TreeBlockV1{TxCount: 1})
				}))
				p := op.Primitives[0]
				p.Kind, p.Generation, p.Height, p.Block, p.Source = 2, 2, 6, tdTxid(0xb1), source
				p.Endpoint = tcEndpoint(6, p.Block)
				key := bytes.Clone(p.Block[:])
				value := bytes.Repeat([]byte{0x6b}, 70000)
				treeNativeSeed(t, s, 4, key, value)
				filler := uint64(402653184 - 74912 - 140000 + short)
				stage, index := UpdateStage(1), 0
				if afterWrite {
					tsRoots(t, s, o, 1)
					p.Kind = 6
					op.Primitives = append(op.Primitives, p)
					filler, stage, index = 0, 2, 1
				} else {
					op.Primitives, op.Pair = []TreePrimitiveV1{p}, TreePairV1{}
				}
				var result tsResult
				var counts PairReadObservation
				filled, ready, writes := false, false, 0
				competitor := uint64(0)
				mustEnvironment(t, o.WithOperation(TreeOperation, func(a *OperationAccount) error {
					return a.WithReservation(filler, func() error {
						var err error
						counts, err = FixturePairReadObservation(s, func(site uint32) {
							if site == 3 {
								writes++
							}
							if site == 2 && writes == 3 {
								ready = true // synchronous fused root equality completed before the next get.
							}
							if afterWrite && ready && !filled && site == 1 {
								// Q319 + P284 + prior H266 + next step74912 =75781.
								if reservationLive(o) != 75781 {
									t.Error("late native body owning prefix", reservationLive(o))
								}
								competitor = 805090853 + short // leave139734-short for H140000-H266.
								reservationFill(t, o, competitor)
								filled = true
							}
						}, func() { result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) })
						mustEnvironment(t, err)
						if reservationLive(o) != filler+competitor {
							t.Fatal("new native stage refusal releases attempt and preserves caller/competitor")
						}
						return nil
					})
				}))
				result.tuple(t, 1, stage, index)
				wantCalls := 1
				wantGets := uint64(2) // OLD exposure, then funded write-candidate equality.
				if afterWrite {
					wantGets = 12 // First primitive10, then the same two body reads.
				}
				if short != 0 {
					wantCalls = 0
					wantGets-- // Refused OLD coverage stops before the candidate get.
					if !treeSameErrorV1(result.err, errOperationReservationCapacity) {
						t.Fatal("new native window room-1 retains exact reached stage/index", result)
					}
				} else if !treeSameErrorV1(result.err, marker) {
					t.Fatal("funded native prefix reaches original Source marker", result)
				}
				if calls != wantCalls || counts.Gets != wantGets || afterWrite && (!filled || writes != 3) || !afterWrite && writes != 0 {
					t.Fatal("new native refusal source/get/write prefix", calls, counts, filled)
				}
				tsConsumed(t, s, o, 1, result.err)
				s = tsReopen(t, s, path)
				equal, err := FixtureRawRowEqual(s, 4, key, value)
				if err != nil || !equal {
					t.Fatal("native-stage refusal durable OLD body", err)
				}
				if afterWrite {
					tsRead(t, s, TreeSchemaV1DBIs()[0], tsRootKey(1), tsRootBytes(t, TreeEndpointV1{}))
					tsRead(t, s, TreeSchemaV1DBIs()[5], tdManifestKey(op.Primitives[0].Block), nil)
				}
			})
		}
	}
}

func pairReadClosedNativeV1(t *testing.T) {
	treeReadClosedNativeV1(t, false)
}

func treeReadClosedNativeV1(t *testing.T, primitive bool) {
	s, _, o := tsNew(t)
	key := []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1}
	treeNativeSeed(t, s, 0, key, bytes.Repeat([]byte{0x44}, 32))
	ready, closeNow, closed := make(chan *OperationAccount), make(chan struct{}), make(chan struct{})
	kind := LaneOperation
	if primitive {
		kind = TreeOperation
	}
	go func() {
		defer close(closed)
		_ = o.WithOperation(kind, func(a *OperationAccount) error { ready <- a; <-closeNow; return nil })
	}()
	a := <-ready
	fired := false
	op := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[0], Key: key, BeforePresent: true, AfterKind: 1}}}}
	if primitive {
		pair := op.Pair
		op = tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error {
			t.Error("closed grow reached Source")
			return nil
		}))
		op.Pair = pair
	}
	mustEnvironment(t, a.WithReservation(137, func() error {
		var result tsResult
		_, err := FixturePairReadObservation(s, func(site uint32) {
			if site == 1 && !fired {
				fired = true
				close(closeNow)
				<-closed
			}
		}, func() { result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) })
		mustEnvironment(t, err)
		result.tuple(t, 1, 1, -1)
		if !treeSameErrorV1(result.err, errOperationReservationInput) || !fired || s.state != storeCLOSED || reservationLive(o) != 137 {
			t.Fatal("closed account grow retains input/caller hold", result)
		}
		return nil
	}))
	if reservationLive(o) != 0 {
		t.Fatal("closed account retained charge after caller exit")
	}
}

func pairReadAbsentNativeV1(t *testing.T) {
	s, path, o := tsNew(t)
	key, value := []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1}, bytes.Repeat([]byte{7}, 16)
	op := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[0], Key: key, AfterKind: 2, Literal: value}}}}
	var result tsResult
	var counts PairReadObservation
	mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
		// Original input and PC each use 128+9+16=153; absent OLD needs only NEW16.
		return a.WithReservation(153, func() error {
			return a.WithReservation(154611183-322, func() error {
				var err error
				counts, err = FixturePairReadObservation(s, nil, func() { result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) })
				return err
			})
		})
	}))
	result.tuple(t, 2, 3, -1)
	mustEnvironment(t, result.err)
	if counts.Gets != 4 || counts.Comparisons != 1 || counts.Aliases != 0 || counts.Writes != 1 {
		t.Fatal("absent OLD metadata/NEW native span", counts)
	}
	s = tsReopen(t, s, path)
	equal, err := FixtureRawRowEqual(s, 0, key, value)
	if err != nil || !equal {
		t.Fatal("absent OLD durable NEW", err)
	}
}

func pairReadGoexitV1(t *testing.T) {
	s, _, o := tsNew(t)
	key := []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1}
	old := bytes.Repeat([]byte{0x77}, 32)
	treeNativeSeed(t, s, 0, key, old)
	op := TreeOperationV1{Pair: TreePairV1{PrepaidReadBytes: 17, Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[0], Key: key, BeforePresent: true, AfterKind: 1}}}}
	fired, returned := false, false
	mustEnvironment(t, o.WithReservation(19, func() error {
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = o.WithOperation(LaneOperation, func(a *OperationAccount) error {
				return a.WithReservation(154, func() error {
					defer func() {
						if reservationLive(o) != 173 {
							t.Error("caller credit remains until caller frame leaves")
						}
					}()
					_, err := FixturePairReadObservation(s, func(site uint32) {
						if site == 3 {
							fired = true
							if reservationLive(o) != 357 {
								t.Error("prepaid17 extra47 before use")
							}
							runtime.Goexit()
						}
					}, func() { _ = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) })
					returned = true
					return err
				})
			})
		}()
		eiAwait(t, done)
		if !fired || returned || reservationLive(o) != 19 || s.state != storeOPEN {
			t.Fatal("engine Goexit owner/disposition", fired, returned, reservationLive(o), s.state)
		}
		return nil
	}))
	if reservationLive(o) != 0 {
		t.Fatal("other operation release")
	}
	equal, err := FixtureRawRowEqual(s, 0, key, old)
	if err != nil || !equal {
		t.Fatal("Goexit durable OLD", err)
	}
	tsFollowing(t, s, o)
}

func pairReadMetadataNativeV1(t *testing.T) {
	for _, mode := range []uint32{31, 32, 33, 34, 35, 36, 37} {
		t.Run(fmt.Sprintf("native%d", mode), func(t *testing.T) {
			s, path, o := tsNew(t)
			key, value := []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1}, bytes.Repeat([]byte{0x55}, 32)
			treeNativeSeed(t, s, 0, key, value)
			op := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[0], Key: key, BeforePresent: true, AfterKind: 1}}}}
			window := uint64(0)
			if mode == 37 {
				window = 64
			}
			var result tsResult
			var observed PairReadObservation
			mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
				return a.WithReservation(154611183-137-window, func() error {
					var err error
					observed, err = FixturePairReadObservation(s, func(site uint32) {
						if mode == 35 && site == 2 {
							t.Error("payload comparisons before refused coverage=0")
						}
					}, func() {
						_, faultErr := fixtureLargeFault(s, mode, 0, key, func() { result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) })
						mustEnvironment(t, faultErr)
					})
					return err
				})
			}))
			if mode == 37 {
				result.tuple(t, 2, 3, -1)
				mustEnvironment(t, result.err)
				if observed.Comparisons != 1 || observed.Aliases != 0 || observed.Gets != 4 {
					t.Fatalf("distinct equal-content spans %+v", observed)
				}
				return
			}
			result.tuple(t, 1, 1, -1)
			switch mode {
			case 31, 32, 36:
				treeNativeError(t, result.err, "update", "StateMismatch", -30779, "OLD/write snapshot mismatch", nil)
			case 33:
				treeNativeError(t, result.err, "update", "LocalInvariant", -30779, "mdbx_get returned invalid result shape", nil)
			case 34:
				treeNativeError(t, result.err, "update", "IO", 5, "error 5", nil)
			case 35:
				if !treeSameErrorV1(result.err, errOperationReservationCapacity) {
					t.Fatal("native full2B overflow", result.err)
				}
			}
			if observed.Comparisons != 0 || observed.Gets != 3 || observed.Writes != 0 || s.state != storeCLOSED {
				t.Fatalf("metadata before payload/native prefix %+v", observed)
			}
			s = tsReopen(t, s, path)
			equal, err := FixtureRawRowEqual(s, 0, key, value)
			if err != nil || !equal {
				t.Fatal("metadata refusal changed durable OLD", err)
			}
		})
	}
}

// Strict readback consumes only the seal, even when other accounts fill actual R.
func TestTreePairReadCrossedV1(t *testing.T) {
	treeReadCrossedV1(t, false)
}

func TestTreePrimitiveReadCrossedV1(t *testing.T) {
	treeReadCrossedV1(t, true)
	t.Run("unexpected-seal", primitiveReadUnexpectedSealV1)
}

// Deliberately shrinking this test-only strict carrier is an unexpected-source
// probe, never a normally attainable public source or a fit counterexample.
func primitiveReadUnexpectedSealV1(t *testing.T) {
	s, _ := ttStore(t)
	key, old := tsCounterKey(9), bytes.Repeat([]byte{0x64}, 32)
	treeNativeSeed(t, s, 0, key, old)
	ledger := &pairReadTestLedgerV1{}
	var heldBefore, heldAfter uint64
	script := fixtureTreeScriptV1{
		ledger: ledger,
		write: func(section *treeSectionV1) error {
			if err := section.writerV1().referV1(schemaDBIs[0], key); err != nil {
				return err
			}
			err := section.finalV1(nil, nil)
			heldBefore = ledger.held
			return err
		},
		readback: func(r *treeReadbackStateV1) error {
			r.nativeLimit = 63 // Writer established OLD64, deliberately violate the carried seal.
			err := r.emitterV1().referV1(schemaDBIs[0], key)
			heldAfter = ledger.held
			return err
		},
	}
	var outcome updateNativeOutcome
	_, err := fixtureLargeFault(s, 12, 0, key, func() { outcome = fixtureTreeCommitV1(s, script) })
	mustEnvironment(t, err)
	commit := ttCommitError(t, outcome, 3)
	if !treeSameErrorV1(commit.ReadbackCause, errOperationReservationCapacity) || heldBefore != 73 || heldAfter != 73 || ledger.held != 73 {
		t.Fatal("unexpected sealed excess is UNKNOWN/capacity without grow", commit, heldBefore, heldAfter, ledger.held)
	}
	equal, err := FixtureRawRowEqual(s, 0, key, old)
	if err != nil || !equal {
		t.Fatal("unexpected seal durable bytes", err)
	}
}

// The same native crossing oracle covers the two production consumers. Primitive
// rows add real covered projection/floor/replay; Pair-only rows retain their seal.
func treeReadCrossedV1(t *testing.T, primitive bool) {
	for _, row := range []struct {
		name      string
		scenario  SelectedDamageScenario
		mode      uint32
		truth     CommitTruth
		readError bool
	}{
		{"OLD", SelectedDamageCommitOld, 0, 1, false},
		{"NEW", SelectedDamageCommitNew, 0, 2, false},
		{"unreadable", SelectedDamageCommitUnreadable, 0, 3, true},
		{"neither", 0, 3, 3, false},
		{"later-consulted-fault", 0, 8, 3, true},
		{"both-OLD-first", SelectedDamageCommitNew, 0, 1, false},
		{"readback-begin", 0, 23, 3, true},
		{"readback-abort-consumed", 0, 16, 2, true},
		{"readback-abort-retained-NEW", 0, 15, 2, true},
		{"readback-abort-retained-OLD", 0, 19, 1, true},
		{"reference", SelectedDamageCommitNew, 0, 2, false},
		{"projection-neither", 0, 3, 3, false},
		{"reference-neither", 0, 3, 3, false},
	} {
		if (row.name == "reference" || row.name == "projection-neither" || row.name == "reference-neither") && !primitive {
			continue
		}
		t.Run(row.name, func(t *testing.T) {
			s, path, o := tsNew(t)
			key := tdUTXOKey(1, tdTxid(0x31), 0)
			consulted := []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 2}
			old := tdFormed(tdFrame(3, 0, bytes.Repeat([]byte{0x33}, 12)), 0, 0)
			next := tdFormed(tdFrame(6, 0, bytes.Repeat([]byte{0x66}, 978)), 0, 0)
			// OLD32=10+1+12+9; NEW1000=10+3+978+9. PC=128+48+44+9+L.
			window, pc := uint64(1000), uint64(1229)
			if row.name == "both-OLD-first" {
				next = bytes.Clone(old)
				window, pc = 64, 261
			}
			if !primitive {
				treeNativeSeed(t, s, 1, key, old)
			}
			treeNativeSeed(t, s, 0, consulted, bytes.Repeat([]byte{0x44}, 32))
			op := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[1], Key: key, BeforePresent: true, AfterKind: 2, Literal: next}}, Consulted: []ConsultedRow{{DBI: TreeSchemaV1DBIs()[0], Key: consulted}}}}
			pairRank := uint8(1)
			faultKey, faultRank := key, pairRank
			ceiling, fill, engine := uint64(154611183), uint64(650695185), window
			if primitive {
				tsRoots(t, s, o, 1)
				tsSeedCounter(t, s, o, 1, false, make([]byte, 16))
				pair := op.Pair
				// Generation9 is outside this covered primitive's generation1 ownership.
				key, old, next = tsCounterKey(9), bytes.Repeat([]byte{0x33}, 32), bytes.Repeat([]byte{0x66}, 16)
				if row.name == "both-OLD-first" {
					old = bytes.Clone(next)
				}
				pairRank = 0
				treeNativeSeed(t, s, pairRank, key, old)
				pair.Mutations[0].DBI, pair.Mutations[0].Key, pair.Mutations[0].Literal = TreeSchemaV1DBIs()[0], key, next
				faultKey, faultRank = key, pairRank
				meta := TreeBlockV1{TxCount: 1}
				op = tsOperation(t, tsSource(func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error { return sink.BeginV1(meta) }))
				body := op.Pair.Mutations[0]
				// Counter PC=128+9+16, Consulted=48+9, body=128+32+159.
				pc = 529
				p := uint64(309) // counter25 + manifest66 + applied-empty root218.
				if row.name == "reference" || row.name == "reference-neither" {
					mustEnvironment(t, tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: op.Pair}).err)
					op.Pair.Mutations, pc, p = nil, pc-319, p+32
				}
				op.Pair.Mutations = append(pair.Mutations, op.Pair.Mutations...)
				op.Pair.Consulted = pair.Consulted
				tsCover(&op, meta)
				if row.name == "both-OLD-first" {
					mustEnvironment(t, tsRun(t, s, o, TreeOperation, op).err)
					op.Pair.Mutations, pc, p = pair.Mutations, 210, 308 // Body32 and manifest33 references; counter25 + root218.
					tsCover(&op, meta)                                  // Stored body, so BodyKind2 with no CurrentBody literal.
				}
				ceiling, fill, engine = 402653184, 402653184, p+419632
				if row.name == "projection-neither" {
					faultKey, faultRank = tsCounterKey(1), 0
				}
				if row.name == "reference-neither" {
					faultKey, faultRank = body.Key, 4
				}
			}
			var result tsResult
			filled := false
			kind := LaneOperation
			if primitive {
				kind = TreeOperation
			}
			mustEnvironment(t, o.WithOperation(kind, func(a *OperationAccount) error {
				return a.WithReservation(pc, func() error {
					return a.WithReservation(ceiling-2*pc-engine, func() error {
						_, err := FixturePairReadObservation(s, func(site uint32) {
							if site == 3 {
								if reservationLive(o) != 805306368 && reservationLive(o) != ceiling {
									t.Error("complete read window before first write")
								}
								if !filled {
									reservationFill(t, o, fill)
									filled = true
								}
							}
							wantLive := uint64(805306368)
							if primitive && site >= 4 {
								wantLive -= engine // P/full heldR end before ORIGINAL OLD cleanup.
							}
							if filled && reservationLive(o) != wantLive {
								t.Error("after-crossing native lifetime/cleanup release", site, reservationLive(o), wantLive)
							}
						}, func() {
							run := func() { result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) }
							if row.mode != 0 {
								selectedKey, selectedRank := faultKey, faultRank
								if row.mode == 8 {
									selectedKey = consulted
									selectedRank = 0
								}
								_, faultErr := fixtureLargeFault(s, row.mode, selectedRank, selectedKey, run)
								mustEnvironment(t, faultErr)
							} else {
								_, faultErr := FixtureSelectedDamage(s, o, row.scenario, pairRank, key, run)
								mustEnvironment(t, faultErr)
							}
						})
						mustEnvironment(t, err)
						if reservationLive(o) != 805306368-pc-engine {
							t.Fatal("crossed engine remainder/caller holds")
						}
						return nil
					})
				})
			}))
			result.tuple(t, row.truth, 3, -1)
			ce, ok := result.err.(*CommitError)
			state := storeCLOSED
			if row.mode == 15 || row.mode == 19 {
				state = storePOISONEDTHREAD
			}
			if !ok || ce.Truth != row.truth || s.state != state {
				t.Fatalf("complete crossed tuple %+v/state%s", result, s.state)
			}
			calls := 0
			mustEnvironment(t, o.WithOperation(kind, func(a *OperationAccount) error {
				next := tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { calls++; return op, nil })
				next.tuple(t, row.truth, 1, -1)
				if calls != 0 || any(next.err) != any(s.terminal) {
					t.Fatal("crossed owner next operation callback0/terminal identity", next)
				}
				return nil
			}))
			treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
			if row.mode == 15 || row.mode == 19 {
				engine := requireEnvironmentError(t, ce.ReadbackCause, "LocalInvariant", "abort", -30416, "MDBX_THREAD_MISMATCH: A thread has attempted to use a not owned object, e.g. a transaction that started by another thread")
				if engine.Cause != nil || !engine.ReopenRequired {
					t.Fatal("retained readback error cause/reopen", engine)
				}
				mustEnvironment(t, fixtureLargeRelease(s))
			} else if row.mode == 16 {
				treeNativeError(t, ce.ReadbackCause, "abort", "IO", 5, "error 5", nil)
			} else if row.readError {
				treeNativeError(t, ce.ReadbackCause, "update", "IO", 5, "error 5", nil)
			} else if ce.ReadbackCause != nil {
				t.Fatal("unexpected readback cause", ce.ReadbackCause)
			}
			s = tsReopen(t, s, path)
			want := next
			if row.truth == 1 {
				want = old
			}
			if row.name == "neither" {
				want = []byte{0x7f}
			}
			equal, err := FixtureRawRowEqual(s, pairRank, key, want)
			if err != nil || !equal {
				t.Fatal("crossed durable bytes", err)
			}
			if row.name == "projection-neither" || row.name == "reference-neither" {
				equal, err := FixtureRawRowEqual(s, faultRank, faultKey, []byte{0x7f})
				if err != nil || !equal {
					t.Fatal("independent projection/reference durable damage", err)
				}
			}
		})
	}
}

func TestTreePairReadCompatibilityNativeV1(t *testing.T) {
	t.Run("ENTRY-ordinary-seal", pairReadEntryNativeV1)
	for _, context := range []bool{false, true} {
		for _, credit := range []uint64{0, 17} {
			for _, short := range []uint64{0, 1} {
				t.Run(fmt.Sprintf("context%v/C%d/short%d", context, credit, short), func(t *testing.T) {
					s, o, w := ctxTreePairScene(t)
					if !context {
						w = nil
					}
					op := ctxTreeOp(8001, w)
					op.Pair.PrepaidReadBytes = credit
					extraContext := uint64(0)
					if context {
						extraContext = 344
					}
					var result tsResult
					mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
						return a.WithReservation(248+credit, func() error {
							return a.WithReservation(154611183-496-104-extraContext+short, func() error {
								before := reservationLive(o)
								_, err := FixturePairReadObservation(s, func(site uint32) {
									if site == 3 && reservationLive(o) != 154611183 {
										t.Error("context344/ordinary104 attribution")
									}
								}, func() { result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) })
								mustEnvironment(t, err)
								if reservationLive(o) != before {
									t.Fatal("context/ordinary caller grant changed")
								}
								return nil
							})
						})
					}))
					if short == 0 {
						result.tuple(t, 2, 3, -1)
						mustEnvironment(t, result.err)
					} else {
						result.tuple(t, 1, 1, -1)
						if !treeSameErrorV1(result.err, errOperationReservationCapacity) || s.state != storeCLOSED {
							t.Fatal("independent ordinary shortage after context", result, s.state)
						}
					}
				})
			}
		}
	}
}

func pairReadEntryNativeV1(t *testing.T) {
	for _, credit := range []uint64{0, 17} {
		t.Run(fmt.Sprint(credit), func(t *testing.T) { pairReadEntryCreditNativeV1(t, credit) })
	}
}

func pairReadEntryCreditNativeV1(t *testing.T, credit uint64) {
	f := eisNew(t, 3, 1, nil)
	pair := eisCapture(t, f, 1, 1, false, false)
	pair.PrepaidReadBytes = credit
	pc := ctxTreePC(TreeOperationV1{Pair: pair})
	if pc > 4096 {
		t.Fatal("original ENTRY Pair exceeds independently assigned input")
	}
	window := uint64(len(eiEncoded(t, f.old)) * 2)
	for _, m := range pair.Mutations {
		window = max(window, uint64(len(m.Literal)))
	}
	e := uint64(8192 + 6*limitsForPage(f.s.config.PageSize).maxKey)
	var result tsResult
	_, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageCommitNew, 0, []byte{2}, func() {
		mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
			return a.WithReservation(4096+credit, func() error {
				_, observeErr := FixturePairReadObservation(f.s, func(site uint32) {
					if site == 3 && reservationLive(f.o) != 4096+pc+window+e {
						t.Error("ENTRY ordinary/source/PC/read attribution")
					}
				}, func() {
					result = tsInvoke(f.s, a, func(r *Reader) (TreeOperationV1, error) {
						token := eiPrepare(t, r, a, pair)
						failure, visitErr := r.VisitEntryInventoryV1(token, func(EntryInventoryRowV1) error { return nil })
						if failure != nil || visitErr != nil {
							t.Fatal("ENTRY source qualification", failure, visitErr)
						}
						pair.EntryInventory = &token
						return TreeOperationV1{Pair: pair}, nil
					})
				})
				if reservationLive(f.o) != 4096+credit {
					t.Fatal("ENTRY ordinary extra leaked/borrowed source")
				}
				return observeErr
			})
		}))
	})
	mustEnvironment(t, err)
	result.tuple(t, 2, 3, -1)
	ce, ok := result.err.(*CommitError)
	if !ok || ce.Truth != 2 || ce.ReadbackCause != nil || reservationLive(f.o) != 0 {
		t.Fatal("ENTRY ordinary sealed truth projection", result)
	}
	treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
}

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
		write: func(section *treeSectionV1) error {
			if err := section.requireReadV1(treeScratchBytesV1); err != nil {
				return err
			}
			return section.writerV1().emitV1(ttTarget(ttUTXO, ttZ, "z1"))
		},
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
			filler := uint64(402_653_184) - pc - budgets[2] - 131_192 - 288_440 - 208 + short
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
						filler = 402_653_184 - pair - 74_912 - 104*3 - 65_560 - 147_968 - 196801
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
			if sample != pc+wantP[1]+74_912+266 {
				t.Fatalf("A4 live%d want PC%d+P%d+74912+native266", sample, pc, wantP[1])
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
			filler := uint64(402_653_184) - pc - budgets[2] - 131_192 - 288_440 - 104*2 + short
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
		filler := uint64(402_653_184) - pc - 74_912 - 104 - 65_560 - 147_968 - 266 - 207
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

// A7: the first probe precedes H; commit and both OLD cleanup probes retain PC+H.
func TestTreeStreamPairHoldNativeBoundariesV1(t *testing.T) {
	for _, short := range []uint64{1, 0} {
		t.Run(fmt.Sprintf("free-G-plus-PC-minus%d", short), func(t *testing.T) {
			s, path, o := tsNew(t)
			op := tsPair(33)
			m := op.Pair.Mutations[0]
			pc := uint64(len(m.Key) + len(m.Literal) + 128)
			filler := uint64(805_306_368) - 154_611_151 - pc - 104 + short
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
			if evidence.Probes != 4 || evidence.ProbeDenied != 3*short || evidence.ProbeRan != 4-3*short {
				t.Fatalf("Pair PC/H native probes short%d: %+v", short, evidence)
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
			filler := uint64(402_653_184) - pc - budgets[2] - 131_192 - 288_440 - 208 + short
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

// trSceneV1 reuses the native provider/fault surface with two independent
// same-block Sources. It does not compose any future production replay step.
func trSceneV1(t *testing.T) *tsfScene {
	t.Helper()
	s, path, owner := tsNew(t)
	meta := TreeBlockV1{TxCount: 1, EventCount: 1}
	providers := []*tsfProvider{
		{block: meta, events: []TreeEventV1{tsCreate(0x31, 0, 0, 148, 11)}},
		{block: meta, events: []TreeEventV1{tsCreate(0x31, 0, 0, 148, 11)}},
	}
	op := trOperationV1(t, providers[0], 2)
	op.Primitives[1].Source = providers[1]
	tsRoots(t, s, owner, 1, 2)
	for _, g := range []uint64{1, 2} {
		tsSeedCounter(t, s, owner, g, false, make([]byte, 16))
	}
	return &tsfScene{s: s, path: path, o: owner, op: op, p: providers}
}

// All six priority controls reach the actual selected public path. NEW-only
// node drift is invisible to pure fold and distinguishes the enclosing checker.
func TestTreeReplayBoundedPreflightV1(t *testing.T) {
	for _, name := range []string{
		"lag-new-node-checker", "current-node-drift-lag-source", "current-node-drift-success",
		"dirty-consulted-before-node", "dirty-consulted-consumer", "dirty-consulted-lag-source", "legal-reference-consulted",
	} {
		t.Run(name, func(t *testing.T) { trPreflightV1(t, name) })
	}
	for _, role := range []int{0, 1} {
		for _, phase := range []string{"finish", "resolve", "fold"} {
			t.Run(fmt.Sprintf("role%d/%s", role, phase), func(t *testing.T) { trPrefixFailureV1(t, role, phase) })
		}
		for _, domain := range []string{"UTXO", "root", "counter"} {
			t.Run(fmt.Sprintf("OLD-write/role%d/%s", role, domain), func(t *testing.T) { trOldDriftV1(t, role, domain) })
		}
	}
}

func trOldDriftV1(t *testing.T, role int, domain string) {
	t.Helper()
	f := trSceneV1(t)
	g := uint64(role + 1)
	rank, key := uint8(0), tsCounterKey(g)
	switch domain {
	case "UTXO":
		rank, key = 1, tdUTXOKey(g, tdTxid(0x31), 0)
	case "root":
		key = tsRootKey(g)
	}
	var result tsResult
	var counts PairReadObservation
	var native SelectedDamageEvidence
	n, err := FixtureWriteSnapshotDrift(f.s, rank, key, func() {
		var armErr error
		native, armErr = FixtureSelectedDamage(f.s, f.o, SelectedDamageProbeOnly, 0, nil, func() {
			var observe error
			counts, observe = FixturePairReadObservation(f.s, nil, func() { result = f.run(t) })
			mustEnvironment(t, observe)
		})
		mustEnvironment(t, armErr)
	})
	result.tuple(t, 1, 1, role)
	treeNativeError(t, result.err, "update", "StateMismatch", -30779, "OLD/write snapshot mismatch", nil)
	if result.err.(*EngineError).TreeObservation != nil || n != 1 || counts.Writes != 0 || native.Commits != 0 {
		t.Fatal("OLD/write source-owned drift tuple/effects", domain, result, n, counts, native)
	}
	mustEnvironment(t, err)
	for j, provider := range f.p {
		want := 1
		if j > role {
			want = 0
		}
		if provider.calls != [3]int{0, want, 0} {
			t.Fatal("OLD drift source priority", domain, j, provider.calls)
		}
	}
	tsConsumed(t, f.s, f.o, 1, result.err)
	f.s = tsReopen(t, f.s, f.path)
	tsFollowing(t, f.s, f.o)
}

func trPrefixFailureV1(t *testing.T, role int, phase string) {
	t.Helper()
	f := trSceneV1(t)
	switch phase {
	case "finish":
		f.p[role].events = nil // Begin promises one event; finish owns the refusal.
	case "resolve":
		treeNativeSeed(t, f.s, 0, tsCounterKey(uint64(role+1)), []byte{1})
	case "fold":
		treeNativeSeed(t, f.s, 0, tsRootKey(uint64(role+1)), []byte{1})
	}
	var result tsResult
	evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageProbeOnly, 0, nil, func() { result = f.run(t) })
	mustEnvironment(t, err)
	result.tuple(t, 1, 1, role)
	if phase == "finish" {
		treeNativeError(t, result.err, "update", "InvalidInput", 22, "invalid tree delta", nil)
	} else {
		treeNativeIntegrity(t, result.err, "update", errSchema)
		engine := result.err.(*EngineError)
		if o := engine.TreeObservation; o != nil && (o.Primitive != role || o.Generation != uint64(role+1) || o.Position != 1) {
			t.Fatal("source-prefix observation lost owning role", o)
		}
	}
	if evidence.Deletes != 0 || evidence.Commits != 0 {
		t.Fatal("source-prefix failure reached physical contribution", evidence)
	}
	for j, provider := range f.p {
		want := 1
		if j > role {
			want = 0
		}
		if provider.calls != [3]int{0, want, 0} {
			t.Fatal("source-prefix result did not suppress later Source", phase, j, provider.calls)
		}
	}
	tsConsumed(t, f.s, f.o, 1, result.err)
}

func trPreflightV1(t *testing.T, name string) {
	t.Helper()
	f := trSceneV1(t)
	marker := errors.New("LAG source owns this result")
	laterSource := strings.HasSuffix(name, "lag-source")
	if laterSource {
		f.p[1].before = func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { return marker }
	}
	conflict := strings.HasPrefix(name, "dirty-consulted")
	if conflict {
		f.op.Pair.Consulted = []ConsultedRow{{DBI: schemaDBIs[1], Key: tdUTXOKey(1, tdTxid(0x31), 0)}}
	}
	if name == "legal-reference-consulted" {
		// This group's CREATE followed by SPEND has absent/absent presence;
		// the Consulted identity must remain a legal unchanged reference.
		for j, provider := range f.p {
			provider.block = TreeBlockV1{TxCount: 2, EventCount: 2}
			provider.events = []TreeEventV1{tsCreate(0x31, 0, 0, 148, 11), tsSpend(0x31, 0, 1, 0)}
			f.op.Primitives[j].Coverage.BlockMeta = provider.block
		}
		f.op.Pair.Consulted = []ConsultedRow{{DBI: schemaDBIs[1], Key: tdUTXOKey(1, tdTxid(0x31), 0)}}
	}
	var result tsResult
	var counts PairReadObservation
	var native SelectedDamageEvidence
	run := func() {
		var err error
		native, err = FixtureSelectedDamage(f.s, f.o, SelectedDamageProbeOnly, 0, nil, func() {
			var observe error
			counts, observe = FixturePairReadObservation(f.s, nil, func() { result = f.run(t) })
			mustEnvironment(t, observe)
		})
		mustEnvironment(t, err)
	}
	drift := name == "lag-new-node-checker" || strings.HasPrefix(name, "current-node-drift") || name == "dirty-consulted-before-node"
	if drift {
		g := uint64(1)
		if name == "lag-new-node-checker" {
			g = 2
		}
		key := testTreeNodeKey(g, 288, tcEntry(tdUTXOKey(g, tdTxid(0x31), 0), nil).k)
		n, err := FixtureWriteSnapshotDrift(f.s, 8, key, run)
		mustEnvironment(t, err)
		if n != 1 {
			t.Fatal("node drift control did not install", n)
		}
	} else {
		run()
	}
	trPreflightResultV1(t, f, name, marker, result, counts, native.Commits)
}

func trPreflightResultV1(t *testing.T, f *tsfScene, name string, marker error, result tsResult, counts PairReadObservation, commits uint64) {
	t.Helper()
	if name == "legal-reference-consulted" {
		result.tuple(t, 2, 3, -1)
		mustEnvironment(t, result.err)
		if counts.Writes == 0 || commits != 1 {
			t.Fatal("legal cancellation did not reach pair/root writes")
		}
	} else {
		index := -1
		switch {
		case strings.HasSuffix(name, "lag-source"):
			index = 1
			if any(result.err) != any(marker) {
				t.Fatal("LAG source marker replaced by later enclosing check", result.err)
			}
		case strings.HasPrefix(name, "dirty-consulted"):
			treeNativeError(t, result.err, "update", "InvalidInput", 22, "invalid Update Batch", nil)
		default:
			treeNativeError(t, result.err, "update", "StateMismatch", -30779, "OLD/write snapshot mismatch", nil)
		}
		result.tuple(t, 1, 1, index)
		if engine, ok := result.err.(*EngineError); ok && engine.TreeObservation != nil {
			t.Fatal("enclosing refusal fabricated tree observation", engine.TreeObservation)
		}
		if counts.Writes != 0 || commits != 0 {
			t.Fatal("physical contribution preceded complete preflight", counts)
		}
		tsConsumed(t, f.s, f.o, 1, result.err)
	}
	for j, provider := range f.p {
		if provider.calls != [3]int{0, 1, 0} {
			t.Fatal("complete source prefixes were reordered or repeated", j, provider.calls)
		}
		tsExpiredReader(t, provider.reader)
		if provider.sink.WindowV1() != nil {
			t.Fatal("source sink lifetime survived prefix", j)
		}
	}
	if reservationLive(f.o) != 0 {
		t.Fatal("frozen role/temporary charge survived cleanup")
	}
	f.s = tsReopen(t, f.s, f.path)
	tsFollowing(t, f.s, f.o)
}

// The existing Source sink exposes the real frozen recorder to this internal
// architecture observation; no production testing API is introduced.
func TestTreeReplayBoundedOrderV1(t *testing.T) {
	f := trSceneV1(t)
	var first *treeRecorderV1
	var firstObservation *TreeObservationV1
	var order []int
	for j, provider := range f.p {
		provider.after = func(pos TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
			order = append(order, j)
			if j == 0 {
				first, firstObservation = sink.recorder, sink.recorder.observation
				return nil
			}
			if first.released || len(first.descs) != 1 || firstObservation == sink.recorder.observation {
				t.Fatal("CURRENT retired or observation aliased before LAG freeze")
			}
			for index, rec := range []*treeRecorderV1{first, sink.recorder} {
				want := TreeObservationV1{DatabaseID: [32]byte{7}, Generation: uint64(index + 1), Block: f.op.Primitives[index].Block, Height: 5, Primitive: index, Position: pos}
				if *rec.observation != want {
					t.Fatalf("role-observation%d = %+v want %+v", index, *rec.observation, want)
				}
			}
			return nil
		}
	}
	var result tsResult
	var counts PairReadObservation
	counts, err := FixturePairReadObservation(f.s, nil, func() { result = f.run(t) })
	for _, provider := range f.p {
		if provider.calls != [3]int{0, 1, 0} {
			t.Fatal("physical regeneration called Source", provider.calls)
		}
	}
	if !slices.Equal(order, []int{0, 1}) || !first.released || counts.Writes != 17 {
		t.Fatal("source/retirement/one-Pair write count", order, first.released, counts)
	}
	mustEnvironment(t, err)
	result.tuple(t, 2, 3, -1)
	mustEnvironment(t, result.err)
}

// Undo entries bind independent original values and original input order;
// CURRENT alone and paired LAG must produce exactly the same global family.
func TestTreeReplayBoundedUndoV1(t *testing.T) {
	for _, roles := range []int{1, 2} {
		for _, undo := range []TreeUndoEffectV1{1, 2, 3, 4} {
			for _, existing := range []bool{false, true} {
				if !existing && undo >= 3 {
					continue
				}
				for _, crossed := range []bool{false, true} {
					t.Run(fmt.Sprintf("roles%d/undo%d/existing%v/crossed%v", roles, undo, existing, crossed), func(t *testing.T) {
						trUndoResultV1(t, roles, undo, existing, crossed)
					})
				}
			}
		}
	}
	t.Run("cancel-and-unchanged", trUndoUnchangedV1)
}

func trUndoUnchangedV1(t *testing.T) {
	f := trSceneV1(t)
	f.op.Primitives[0].Undo = UndoWriteOrReuseV1
	value := tdFormed(f.op.Primitives[0].Coverage.CurrentBody[148:], 5, 0)
	for j, p := range f.op.Primitives {
		f.p[j].block = TreeBlockV1{TxCount: 2, EventCount: 4}
		f.p[j].events = []TreeEventV1{tsCreate(0x31, 0, 0, 148, 11), tsSpend(0x20, 0, 1, 0), tsSpend(0x31, 0, 1, 1), tsCreate(0x20, 0, 1, 148, 11)}
		p.Coverage.BlockMeta = f.p[j].block
		key := tdUTXOKey(p.Generation, tdTxid(0x20), 0)
		treeNativeSeed(t, f.s, 1, key, value)
		entry := tcEntry(key, value)
		rows := map[string][]byte{}
		_ = testTreeBuild(p.Generation, []testTreeEntry{entry}, rows)
		for name, row := range rows {
			treeNativeSeed(t, f.s, 8, testTreeRowKey(name), row)
		}
		treeNativeSeed(t, f.s, 0, tsRootKey(p.Generation), tcBinding(t, p.Generation, tcEndpoint(4, tdTxid(0xa0)), entry))
		treeNativeSeed(t, f.s, 0, tsCounterKey(p.Generation), tsCounterLiteral(56, 1))
	}
	f.op.Pair.Consulted = []ConsultedRow{
		{DBI: schemaDBIs[1], Key: tdUTXOKey(1, tdTxid(0x20), 0)},
		{DBI: schemaDBIs[1], Key: tdUTXOKey(1, tdTxid(0x31), 0)},
	}
	var frozen *treeRecorderV1
	f.p[0].after = func(pos TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
		if pos == 1 {
			frozen = sink.recorder
		}
		return nil
	}
	f.p[1].before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
		if pos == 1 && (frozen == nil || frozen.released || len(frozen.descs) != 4) {
			t.Fatal("cancel-and-unchanged frozen original events were dropped")
		}
		return nil
	}
	var result tsResult
	_, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageCommitNew, 0, tsRootKey(1), func() { result = f.run(t) })
	mustEnvironment(t, err)
	result.tuple(t, 2, 3, -1)
	ce, ok := result.err.(*CommitError)
	if !ok || ce.ReadbackCause != nil {
		t.Fatal("cancellation/unchanged groups lost strict complete NEW", result.err)
	}
	f.s = tsReopen(t, f.s, f.path)
	block := f.op.Primitives[0].Block
	tsRead(t, f.s, schemaDBIs[5], tdManifestKey(block), tdManifest(5, [16]byte{}, 2, 1))
	tsRead(t, f.s, schemaDBIs[5], tdEntryKey(block, tdTxid(0x20), 1, 0, 0), value)
	tsRead(t, f.s, schemaDBIs[5], tdEntryKey(block, tdTxid(0x31), 1, 1, 0), nil)
	for _, p := range f.op.Primitives {
		key := tdUTXOKey(p.Generation, tdTxid(0x20), 0)
		tsRead(t, f.s, schemaDBIs[1], key, value)
		tsRead(t, f.s, schemaDBIs[1], tdUTXOKey(p.Generation, tdTxid(0x31), 0), nil)
		tsRead(t, f.s, schemaDBIs[0], tsCounterKey(p.Generation), tsCounterLiteral(56, 1))
		tsRead(t, f.s, schemaDBIs[0], tsRootKey(p.Generation), tcBinding(t, p.Generation, p.Endpoint, tcEntry(key, value)))
	}
	tsFollowing(t, f.s, f.o)
}

func trUndoResultV1(t *testing.T, roles int, undo TreeUndoEffectV1, existing, crossed bool) {
	t.Helper()
	f := trSceneV1(t)
	f.op.Primitives = f.op.Primitives[:roles]
	if roles == 1 {
		rows := f.op.Pair.Mutations[:0]
		for _, m := range f.op.Pair.Mutations {
			if (m.DBI.Rank == 2 || m.DBI.Rank == 7) && binary.BigEndian.Uint64(m.Key) == 2 {
				continue
			}
			rows = append(rows, m)
		}
		f.op.Pair.Mutations = rows
	}
	meta := TreeBlockV1{TxCount: 2, EventCount: 3}
	for j := range roles {
		f.p[j].block = meta
		f.p[j].events = []TreeEventV1{tsSpend(0x20, 0, 1, 0), tsSpend(0x21, 0, 1, 1), tsCreate(0x31, 0, 1, 148, 11)}
		f.op.Primitives[j].Coverage.BlockMeta = meta
		g := uint64(j + 1)
		var entries []testTreeEntry
		for i, tag := range []byte{0x20, 0x21} {
			value := tdFormed(tdFrame(uint64(7+i), 0, []byte{tag}), 4, 0)
			key := tdUTXOKey(g, tdTxid(tag), 0)
			entries = append(entries, tcEntry(key, value))
			treeNativeSeed(t, f.s, 1, key, value)
		}
		rows := map[string][]byte{}
		_ = testTreeBuild(g, entries, rows)
		for name, value := range rows {
			treeNativeSeed(t, f.s, 8, testTreeRowKey(name), value)
		}
		treeNativeSeed(t, f.s, 0, tsRootKey(g), tcBinding(t, g, tcEndpoint(4, tdTxid(0xa0)), entries...))
		treeNativeSeed(t, f.s, 0, tsCounterKey(g), tsCounterLiteral(114, 2))
	}
	f.op.Primitives[0].Undo = undo
	block := f.op.Primitives[0].Block
	manifest := tdManifest(5, [16]byte{}, 2, 2)
	values := [][]byte{tdFormed(tdFrame(7, 0, []byte{0x20}), 4, 0), tdFormed(tdFrame(8, 0, []byte{0x21}), 4, 0)}
	if existing {
		treeNativeSeed(t, f.s, 5, tdManifestKey(block), manifest)
		for i, tag := range []byte{0x20, 0x21} {
			treeNativeSeed(t, f.s, 5, tdEntryKey(block, tdTxid(tag), 1, uint32(i), 0), values[i])
		}
	}
	var result tsResult
	if crossed {
		evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageCommitNew, 0, tsRootKey(1), func() { result = f.run(t) })
		mustEnvironment(t, err)
		ce, ok := result.err.(*CommitError)
		if !ok || ce.Truth != 2 || ce.ReadbackCause != nil || evidence.Commits != 1 {
			t.Fatal("protected ORIGINAL OLD must supply missing undo after crossed NEW", result, evidence)
		}
		treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
		tsConsumed(t, f.s, f.o, 2, result.err)
	} else {
		result = f.run(t)
		mustEnvironment(t, result.err)
	}
	result.tuple(t, 2, 3, -1)
	f.s = tsReopen(t, f.s, f.path)
	keep := undo == 1 || undo == 3 || undo == 2 && existing
	if !keep {
		manifest = nil
	}
	tsRead(t, f.s, schemaDBIs[5], tdManifestKey(block), manifest)
	for i, tag := range []byte{0x20, 0x21} {
		var want []byte
		if keep {
			want = values[i]
		}
		tsRead(t, f.s, schemaDBIs[5], tdEntryKey(block, tdTxid(tag), 1, uint32(i), 0), want)
		for g := uint64(1); g <= uint64(roles); g++ {
			tsRead(t, f.s, schemaDBIs[1], tdUTXOKey(g, tdTxid(tag), 0), nil)
		}
	}
	for j, p := range f.op.Primitives {
		readback := 0
		if crossed {
			readback = 1
		}
		if f.p[j].calls != [3]int{0, 1, readback} {
			t.Fatal("undo regeneration reinvoked Source", j, f.p[j].calls)
		}
		value := tdFormed(p.Coverage.CurrentBody[148:], 5, 0)
		tsRead(t, f.s, schemaDBIs[1], tdUTXOKey(p.Generation, tdTxid(0x31), 0), value)
		tsRead(t, f.s, schemaDBIs[0], tsRootKey(p.Generation), tcBinding(t, p.Generation, p.Endpoint, tcEntry(tdUTXOKey(p.Generation, tdTxid(0x31), 0), value)))
	}
	tsFollowing(t, f.s, f.o)
}

// A single protected body is retained under B across both frozen writer roles
// and sequential strict roles; equality of independent caller copies is separate.
func TestTreeReplayBoundedBodyV1(t *testing.T) {
	for _, kind := range []uint8{1, 2, 3} {
		for _, deleteBody := range []bool{false, true} {
			if deleteBody && kind != 2 {
				continue
			}
			t.Run(fmt.Sprintf("body%d/delete%v", kind, deleteBody), func(t *testing.T) {
				f := trSceneV1(t)
				raw := trBodyV1(&f.op, kind, deleteBody)
				original := &raw[0]
				if kind == 2 {
					treeNativeSeed(t, f.s, 4, bytes.Clone(f.op.Primitives[0].Block[:]), raw)
				}
				var backing [3][2]*byte
				for j, provider := range f.p {
					provider.after = func(pos TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
						backing[pos][j] = &sink.recorder.body.bytes[0]
						if !sink.recorder.referenceOnly || sink.recorder.rootReadOnly {
							t.Fatal("writer/readback replay mode")
						}
						return nil
					}
				}
				var result tsResult
				evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageCommitNew, 0, tsRootKey(1), func() { result = f.run(t) })
				mustEnvironment(t, err)
				result.tuple(t, 2, 3, -1)
				ce, ok := result.err.(*CommitError)
				if !ok || ce.ReadbackCause != nil || evidence.Commits != 1 {
					t.Fatal("shared body strict NEW", result.err, evidence)
				}
				for _, pos := range []int{1, 2} {
					if backing[pos][0] == nil || backing[pos][0] != backing[pos][1] {
						t.Fatal("roles did not share actual immutable backing", kind, pos, backing)
					}
					if (backing[pos][0] == original) != (kind == 3) {
						t.Fatal("Raw/clone/protected-native backing identity", kind, pos)
					}
				}
				if backing[1][0] != backing[2][0] || reservationLive(f.o) != 0 {
					t.Fatal("body last-use/grant lifetime", backing)
				}
			})
		}
	}
	t.Run("owned-Pair-original-buffers", func(t *testing.T) {
		f := trSceneV1(t)
		want := make([]Mutation, len(f.op.Pair.Mutations))
		for i, m := range f.op.Pair.Mutations {
			want[i] = m
			want[i].Key, want[i].Literal = bytes.Clone(m.Key), bytes.Clone(m.Literal)
		}
		f.p[0].before = func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error {
			for _, m := range f.op.Pair.Mutations {
				clear(m.Key)
				if m.DBI.Rank != 4 {
					clear(m.Literal)
				}
			}
			return nil
		}
		result := f.run(t)
		result.tuple(t, 2, 3, -1)
		mustEnvironment(t, result.err)
		for _, m := range want {
			tsRead(t, f.s, m.DBI, m.Key, m.Literal)
		}
		if f.p[1].calls != [3]int{0, 1, 0} {
			t.Fatal("LAG Source changed with independently owned original Pair buffers")
		}
	})
}

// The exact fixture peak simultaneously includes both A_j, future Br and the
// additional physical L. Removing any of these owners changes the minus-one row.
func TestTreeReplayBoundedFundingV1(t *testing.T) {
	for _, body := range []struct {
		kind   uint8
		delete bool
		q, b   uint64
	}{
		{1, false, 1167, 0},
		{2, false, 848, 159},
		{2, true, 1008, 159},
		{3, false, 848, 0},
	} {
		for _, short := range []uint64{0, 1} {
			t.Run(fmt.Sprintf("body%d/delete%v/short%d", body.kind, body.delete, short), func(t *testing.T) {
				f := trSceneV1(t)
				raw := trBodyV1(&f.op, body.kind, body.delete)
				if body.kind == 2 {
					treeNativeSeed(t, f.s, 4, bytes.Clone(f.op.Primitives[0].Block[:]), raw)
				}
				peak := body.q + body.b + 2*(74912+65560+104) + 131192 + 288544 + 147968
				var result tsResult
				mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
					return a.WithReservation(402653184-peak+short, func() error {
						baseline := reservationLive(f.o)
						result = tsInvoke(f.s, a, func(*Reader) (TreeOperationV1, error) { return f.op, nil })
						if reservationLive(f.o) != baseline {
							t.Fatal("both-frozen/body/native owner leaked")
						}
						return nil
					})
				}))
				if short == 0 {
					result.tuple(t, 2, 3, -1)
					mustEnvironment(t, result.err)
				} else {
					result.tuple(t, 1, 2, -1)
					if any(result.err) != any(errOperationReservationCapacity) {
						t.Fatal("physical L minus-one capacity identity", result.err)
					}
					tsConsumed(t, f.s, f.o, 1, result.err)
				}
				for _, p := range f.p {
					if p.calls != [3]int{0, 1, 0} {
						t.Fatal("both frozen Sources required", p.calls)
					}
				}
				f.s = tsReopen(t, f.s, f.path)
				for _, p := range f.op.Primitives {
					var want []byte
					if short == 0 {
						want = tdFormed(raw[148:], 5, 1)
					}
					tsRead(t, f.s, schemaDBIs[1], tdUTXOKey(p.Generation, tdTxid(0x31), 0), want)
				}
				tsFollowing(t, f.s, f.o)
			})
		}
	}
	for _, owner := range []string{"CURRENT-step", "CURRENT-descriptor", "LAG-step", "LAG-descriptor", "future-readback"} {
		for _, short := range []uint64{0, 1} {
			t.Run(fmt.Sprintf("%s/short%d", owner, short), func(t *testing.T) { trFundingOwnerV1(t, owner, short) })
		}
	}
}

func trFundingOwnerV1(t *testing.T, owner string, short uint64) {
	t.Helper()
	f := trSceneV1(t)
	plan := treeOwnPlanV1(f.op)
	ledger := &tcLedger{}
	steps, descriptors := 0, 0
	reached := false
	ledger.before = func(n uint64) {
		if reached {
			ledger.limit = 0
			return
		}
		if n == 74912 {
			steps++
		}
		if n == 65664 {
			descriptors++
		}
		match := owner == "CURRENT-step" && n == 74912 && steps == 1 ||
			owner == "CURRENT-descriptor" && n == 65664 && descriptors == 1 ||
			owner == "LAG-step" && n == 74912 && steps == 2 ||
			owner == "LAG-descriptor" && n == 65664 && descriptors == 2 ||
			owner == "future-readback" && n > 288544 && n <= 419736
		if !match {
			return
		}
		reached = true
		if owner == "LAG-descriptor" && ledger.held < 140576+74912 {
			t.Error("both-frozen CURRENT owner absent at LAG descriptor acquisition", ledger.held)
		}
		if owner == "future-readback" && ledger.held+n != 700888 {
			t.Error("future reserve excludes a frozen A_j or Sr/Br", ledger.held, n)
		}
		ledger.limit = ledger.held + n - short
	}
	var result tsResult
	var unwind treeUnwindV1
	var counts PairReadObservation
	counts, err := FixturePairReadObservation(f.s, nil, func() {
		result.truth, result.stage, result.index, unwind, result.err = fixtureTreeComposeV1(f.s, ledger, &plan, nil)
	})
	mustEnvironment(t, err)
	// The existing engine seam omits the public operation hold. Its only
	// remainder is H: initial Pair literal159, then two ORIGINAL root133 spans.
	outer := uint64(0)
	if short != 0 {
		outer = 266
		if strings.HasPrefix(owner, "CURRENT") {
			outer = 159
		}
	}
	if ledger.held != outer {
		t.Fatal("frozen owners did not retire independently of outer native H", owner, ledger.held, outer)
	}
	if outer != 0 {
		ledger.releaseV1(outer)
	}
	if !reached || unwind.kind != 0 || ledger.held != 0 || len(ledger.violations) != 0 {
		t.Fatal("capacity owner was unreachable or retained a hold", owner, reached, ledger.held, ledger.violations)
	}
	if short == 0 {
		result.tuple(t, 2, 3, -1)
		mustEnvironment(t, result.err)
		return
	}
	index := 0
	if strings.HasPrefix(owner, "LAG") {
		index = 1
	}
	if owner == "future-readback" {
		index = -1
	}
	result.tuple(t, 1, 1, index)
	if any(result.err) != any(errOperationReservationCapacity) || counts.Writes != 0 {
		t.Fatal("capacity owner lost identity or wrote before reserve", owner, result, counts)
	}
	tsConsumed(t, f.s, f.o, 1, result.err)
}

// Strict equality must finish both role folds, then the complete auxiliary
// domains, even when an earlier OLD or NEW predicate has already become false.
func TestTreeReplayBoundedReadbackV1(t *testing.T) {
	for _, row := range []struct {
		name     string
		scenario SelectedDamageScenario
		truth    CommitTruth
	}{
		{"OLD", SelectedDamageCommitOld, 1},
		{"NEW", SelectedDamageCommitNew, 2},
		{"unreadable", SelectedDamageCommitUnreadable, 3},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := trSceneV1(t)
			var samples []uint64
			for _, provider := range f.p {
				provider.before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
					if pos == 2 {
						samples = append(samples, reservationLive(f.o))
					}
					return nil
				}
			}
			var result tsResult
			evidence, err := FixtureSelectedDamage(f.s, f.o, row.scenario, 0, tsRootKey(2), func() { result = f.run(t) })
			result.tuple(t, row.truth, 3, -1)
			ce, ok := result.err.(*CommitError)
			if !ok || ce.Truth != row.truth || evidence.Commits != 1 {
				t.Fatal("complete pair strict truth", result, evidence)
			}
			treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
			if row.name == "unreadable" {
				treeNativeError(t, ce.ReadbackCause, "update", "IO", 5, "error 5", nil)
			} else {
				if ce.ReadbackCause != nil || !slices.Equal(samples, []uint64{420903, 420903}) {
					t.Fatal("readback cannot grow account or skip LAG", ce.ReadbackCause, samples)
				}
				for _, p := range f.p {
					if p.calls != [3]int{0, 1, 1} {
						t.Fatal("both strict Sources required", p.calls)
					}
				}
			}
			mustEnvironment(t, err)
			tsConsumed(t, f.s, f.o, row.truth, result.err)
		})
	}
	for _, domain := range []string{"LAG-root", "Consulted", "context"} {
		t.Run("false-then-unreadable/"+domain, func(t *testing.T) { trReadbackLateV1(t, domain) })
	}
	t.Run("both-complete-OLD-first", trReadbackOldFirstV1)
	t.Run("native-mixed-CURRENT-new-LAG-old", trReadbackMixedV1)
	t.Run("false-NEW-then-LAG-unavailable", trReadbackNewFalseLateV1)
	t.Run("neither-complete", func(t *testing.T) {
		f := trSceneV1(t)
		var result tsResult
		evidence, err := fixtureLargeFault(f.s, 3, 0, tsCounterKey(2), func() { result = f.run(t) })
		result.tuple(t, 3, 3, -1)
		ce, ok := result.err.(*CommitError)
		if !ok || ce.ReadbackCause != nil || evidence.drift != 1 || evidence.commits != 1 {
			t.Fatal("complete predicates distinguish known neither from unavailable", result, evidence)
		}
		treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
		mustEnvironment(t, err)
		for _, provider := range f.p {
			if provider.calls != [3]int{0, 1, 1} {
				t.Fatal("known neither skipped a role", provider.calls)
			}
		}
		tsConsumed(t, f.s, f.o, 3, result.err)
	})
}

func trReadbackNewFalseLateV1(t *testing.T) {
	t.Helper()
	f := trSceneV1(t)
	f.p[1].before = func(pos TreePositionV1, r *Reader, _ *TreeDeltaSinkV1) error {
		if pos != 2 {
			return nil
		}
		_, _, err := r.Get(schemaDBIs[0], []byte{2})
		return err
	}
	var result tsResult
	var late SelectedDamageEvidence
	var armErr error
	drift, err := fixtureLargeFault(f.s, 3, 1, tdUTXOKey(1, tdTxid(0x31), 0), func() {
		late, armErr = FixtureSelectedDamage(f.s, f.o, SelectedDamageGetEIO, 0, []byte{2}, func() { result = f.run(t) })
	})
	// These observations precede the fixture-enforcer: a shortened fold must
	// fail for the missing later Source/cause, rather than the unconsumed fault.
	for _, provider := range f.p {
		if provider.calls != [3]int{0, 1, 1} {
			t.Fatal("false NEW suppressed the later LAG Source", provider.calls)
		}
		tsExpiredReader(t, provider.reader)
	}
	result.tuple(t, 3, 3, -1)
	ce, ok := result.err.(*CommitError)
	if !ok || drift.drift != 1 || drift.commits != 1 || late.Faults != 1 {
		t.Fatal("false NEW lost later unavailable evidence", result, drift, late)
	}
	treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
	treeNativeError(t, ce.ReadbackCause, "get", "IO", 5, "error 5", nil)
	mustEnvironment(t, armErr)
	mustEnvironment(t, err)
	tsConsumed(t, f.s, f.o, 3, result.err)
}

// The existing native commit seam constructs a complete mixed physical image.
// Its real strict snapshot invokes the production replay scope loop/verdict;
// no test supplies the equality predicates or a requested truth result.
func trReadbackMixedV1(t *testing.T) {
	t.Helper()
	f := trSceneV1(t)
	plan := treeOwnPlanV1(f.op)
	ledger := &tcLedger{}
	var composer *treeComposeV1
	script := fixtureTreeScriptV1{ledger: ledger, pair: plan.pair, held: 419736}
	script.write = func(section *treeSectionV1) error {
		section.covered = true
		if err := section.pairPreflightV1(plan.pair, plan.consulted); err != nil {
			return err
		}
		w := newTreeScopeV1(f.s, section.old, &plan, treeWriterV1, ledger)
		w.t = section
		composer = &treeComposeV1{writer: w}
		defer w.slotV1()
		if stopped, err := w.loopV1(); stopped {
			return err
		}
		if w.dirtyConsultedV1() {
			t.Fatal("mixed fixture unexpectedly conflicts")
		}
		if err := w.boundedCheckV1(); err != nil {
			return err
		}
		if err := composer.reserveV1(); err != nil {
			return err
		}
		current := treeAdmittedPrimitiveV1(&plan.primitives[0])
		// Deliberately commit CURRENT and the complete Pair, leaving every
		// generation-2 UTXO/node/root/counter at its literal ORIGINAL OLD.
		return w.regenerateV1(w.frozen[0], &current, treeBoundedEmitterV1{section: section, pair: plan.pair, writing: true})
	}
	script.readback = func(rb *treeReadbackStateV1) error {
		rb.bounded, rb.oldImage, rb.newImage = true, true, true
		e := newTreeScopeV1(f.s, rb.old, &plan, treeReadbackV1, rb.budget.ledgerV1())
		e.rb = rb
		defer e.slotV1()
		_, err := e.loopV1()
		return err
	}
	var outcome updateNativeOutcome
	evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageCommitNew, 0, tsRootKey(1), func() {
		outcome = fixtureTreeCommitV1(f.s, script)
	})
	ce := ttCommitError(t, outcome, 3)
	if ce.ReadbackCause != nil || outcome.secondary != nil || outcome.retainedRead != nil || outcome.retainedWrite != nil || evidence.Commits != 1 {
		t.Fatal("known mixed complete image cause/handle disposition", outcome, ce, evidence)
	}
	treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
	mustEnvironment(t, err)
	if composer == nil {
		t.Fatal("mixed native contribution was not reached")
	}
	composer.releaseV1()
	if ledger.held != 0 || len(ledger.violations) != 0 {
		t.Fatal("mixed native fixture resource retirement", ledger.held, ledger.violations)
	}
	for _, provider := range f.p {
		if provider.calls != [3]int{0, 1, 1} {
			t.Fatal("mixed image strict evaluation skipped a role", provider.calls)
		}
	}
	raw := f.op.Primitives[0].Coverage.CurrentBody
	trPairRowsV1(t, f.s, f.op.Primitives[0], raw, 1)
	tsRead(t, f.s, schemaDBIs[0], tsRootKey(2), tsRootBytes(t, TreeEndpointV1{}))
	tsRead(t, f.s, schemaDBIs[0], tsCounterKey(2), make([]byte, 16))
	tsRead(t, f.s, schemaDBIs[1], tdUTXOKey(2, tdTxid(0x31), 0), nil)
	key := testTreeNodeKey(2, 288, tcEntry(tdUTXOKey(2, tdTxid(0x31), 0), nil).k)
	tsRead(t, f.s, TreeSchemaV1DBIs()[8], key, nil)
	for _, m := range f.op.Pair.Mutations {
		tsRead(t, f.s, m.DBI, m.Key, m.Literal)
	}
	tsFollowing(t, f.s, f.o)
}

func trReadbackOldFirstV1(t *testing.T) {
	t.Helper()
	f := trSceneV1(t)
	raw := trBodyV1(&f.op, 2, false)
	treeNativeSeed(t, f.s, 4, bytes.Clone(f.op.Primitives[0].Block[:]), raw)
	for j, p := range f.op.Primitives {
		f.p[j].block, f.p[j].events = TreeBlockV1{TxCount: 1}, nil
		p.Coverage.BlockMeta = f.p[j].block
		treeNativeSeed(t, f.s, 0, tsRootKey(p.Generation), tcBinding(t, p.Generation, p.Endpoint))
	}
	for i := range f.op.Pair.Mutations {
		m := &f.op.Pair.Mutations[i]
		treeNativeSeed(t, f.s, m.DBI.Rank, bytes.Clone(m.Key), m.Literal)
		m.BeforePresent = true
	}
	var result tsResult
	evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageCommitNew, 0, tsRootKey(1), func() { result = f.run(t) })
	result.tuple(t, 1, 3, -1)
	ce, ok := result.err.(*CommitError)
	if !ok || ce.Truth != 1 || ce.ReadbackCause != nil || evidence.Commits != 1 {
		t.Fatal("complete OLD must win over also-complete NEW", result, evidence)
	}
	treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
	mustEnvironment(t, err)
	for _, provider := range f.p {
		if provider.calls != [3]int{0, 1, 1} {
			t.Fatal("OLD-first selected without both complete role predicates", provider.calls)
		}
	}
	tsConsumed(t, f.s, f.o, 1, result.err)
}

func trReadbackLateV1(t *testing.T, domain string) {
	t.Helper()
	f := trSceneV1(t)
	rank, key := uint8(0), tsRootKey(2)
	if domain == "Consulted" {
		f.op.Pair.Consulted = []ConsultedRow{{DBI: schemaDBIs[0], Key: []byte{2}}}
		key = []byte{2}
	}
	if domain == "context" {
		ctxTreeSeed(t, f.s, 7, 100, 2, nil, nil)
		f.op.Pair.ContextConsulted = &CanonicalContextWindowV1{Generation: 7, FirstHeight: 100, Count: 2}
		rank, key = 2, binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, 7), 101)
	}
	var result tsResult
	evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageCommitUnreadable, rank, key, func() { result = f.run(t) })
	result.tuple(t, 3, 3, -1)
	ce, ok := result.err.(*CommitError)
	if !ok || evidence.Faults != 2 || evidence.Commits != 1 {
		t.Fatal("late unavailable domain was skipped after false predicate", result, evidence)
	}
	treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
	treeNativeError(t, ce.ReadbackCause, "update", "IO", 5, "error 5", nil)
	for _, p := range f.p {
		if p.calls != [3]int{0, 1, 1} {
			t.Fatal("late domain requires both strict Sources", domain, p.calls)
		}
	}
	mustEnvironment(t, err)
	tsConsumed(t, f.s, f.o, 3, result.err)
}

func TestTreeReplayBoundedAuxiliaryV1(t *testing.T) {
	for _, count := range []uint32{0, 1, 10080} {
		f := trSceneV1(t)
		trAuthorityV1(t, f)
		raw := trBodyV1(&f.op, 2, false)
		treeNativeSeed(t, f.s, 4, bytes.Clone(f.op.Primitives[0].Block[:]), raw)
		ctxTreeSeed(t, f.s, 8, 100, 1, nil, nil)
		header := ctxTreeHeader(t, 8, 100)
		hash := sha3.Sum256(header)
		ownerKey, keyErr := CanonicalOwnerKey(8, hash)
		mustEnvironment(t, keyErr)
		f.op.Pair.Consulted = []ConsultedRow{
			{DBI: schemaDBIs[0], Key: []byte{0}},
			{DBI: schemaDBIs[1], Key: tdUTXOKey(8, tdTxid(0x88), 0)},
			{DBI: schemaDBIs[2], Key: ctxTreeIndexKey(8, 100)},
			{DBI: schemaDBIs[3], Key: hash[:]},
			{DBI: schemaDBIs[4], Key: f.op.Primitives[0].Block[:]},
			{DBI: schemaDBIs[7], Key: ownerKey},
		}
		if count != 0 {
			ctxTreeSeed(t, f.s, 7, 100, int(count), nil, nil)
			f.op.Pair.ContextConsulted = &CanonicalContextWindowV1{Generation: 7, FirstHeight: 100, Count: count}
		}
		var result tsResult
		if count != 0 {
			_, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageCommitNew, 0, tsRootKey(1), func() { result = f.run(t) })
			ce, ok := result.err.(*CommitError)
			if !ok || ce.ReadbackCause != nil {
				t.Fatal("complete consulted/context strict NEW", count, result.err)
			}
			treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
			mustEnvironment(t, err)
			f.s = tsReopen(t, f.s, f.path)
		} else {
			result = f.run(t)
			mustEnvironment(t, result.err)
		}
		result.tuple(t, 2, 3, -1)
		tsRead(t, f.s, schemaDBIs[0], []byte{2}, f.op.Pair.Mutations[0].Literal)
		tsFollowing(t, f.s, f.o)
	}
	for _, domain := range []string{"Consulted", "context"} {
		t.Run("final-last-domain/"+domain, func(t *testing.T) {
			f := trSceneV1(t)
			rank, key := uint8(0), []byte{2}
			if domain == "context" {
				ctxTreeSeed(t, f.s, 7, 100, 2, nil, nil)
				f.op.Pair.ContextConsulted = &CanonicalContextWindowV1{Generation: 7, FirstHeight: 100, Count: 2}
				rank, key = 2, ctxTreeIndexKey(7, 101)
			} else {
				f.op.Pair.Consulted = []ConsultedRow{{DBI: schemaDBIs[0], Key: key}}
			}
			var result tsResult
			evidence, err := fixtureLargeFault(f.s, 13, rank, key, func() { result = f.run(t) })
			mustEnvironment(t, err)
			result.tuple(t, 1, 2, -1)
			treeNativeError(t, result.err, "update", "StateMismatch", -30779, "final update image mismatch", nil)
			if evidence.drift != 1 || evidence.commits != 0 {
				t.Fatal("enclosing final auxiliary domain was skipped", evidence)
			}
			tsConsumed(t, f.s, f.o, 1, result.err)
			f.s = tsReopen(t, f.s, f.path)
			tsFollowing(t, f.s, f.o)
		})
	}
}

func trAuthorityV1(t *testing.T, f *tsfScene) {
	t.Helper()
	for _, m := range tsEntry(t).Pair.Mutations {
		if m.DBI.Rank == 0 && bytes.Equal(m.Key, []byte{2}) {
			m.BeforePresent = true
			f.op.Pair.Mutations = append(f.op.Pair.Mutations, m)
		}
	}
	slices.SortFunc(f.op.Pair.Mutations, func(a, b Mutation) int { return treeMutationCmpV1(a, treeRowKeyV1{rank: b.DBI.Rank, key: b.Key}) })
}

// Each literal Source outcome is crossed with each real cleanup disposition at
// both Source positions and roles; next-call state is part of the observation.
func TestTreeReplayBoundedLifecycleV1(t *testing.T) {
	for _, position := range []TreePositionV1{1, 2} {
		for _, role := range []int{0, 1} {
			for _, mode := range []string{"nil", "direct", "wrapped", "caused", "typed-nil", "panic", "goexit"} {
				for _, cleanup := range []uint32{0, 9, 10} {
					t.Run(fmt.Sprintf("position%d/role%d/%s/cleanup%d", position, role, mode, cleanup), func(t *testing.T) {
						trLifecycleV1(t, position, role, mode, cleanup, 1)
					})
				}
			}
		}
	}
	for _, position := range []TreePositionV1{1, 2} {
		for _, mode := range []string{"direct", "panic", "goexit"} {
			for _, cleanup := range []uint32{0, 9, 10} {
				t.Run(fmt.Sprintf("stored-body/position%d/LAG/%s/cleanup%d", position, mode, cleanup), func(t *testing.T) {
					trLifecycleV1(t, position, 1, mode, cleanup, 2)
				})
			}
		}
	}
}

func trLifecycleV1(t *testing.T, position TreePositionV1, role int, mode string, cleanup uint32, body uint8) {
	t.Helper()
	f := trSceneV1(t)
	if body == 2 {
		raw := trBodyV1(&f.op, 2, false)
		treeNativeSeed(t, f.s, 4, bytes.Clone(f.op.Primitives[0].Block[:]), raw)
	}
	marker, panicValue := errors.New("replay Source marker"), new(int)
	primary := error(marker)
	switch mode {
	case "wrapped":
		primary = fmt.Errorf("exact replay wrapper: %w", marker)
	case "caused":
		primary = &EngineError{Class: "IO", Operation: "get", Code: 5, Diagnostic: "existing replay cause", Cause: marker}
	case "typed-nil":
		var typed *nilPointerError
		primary = typed
	case "nil", "panic", "goexit":
		primary = nil
	}
	f.p[role].before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
		if pos != position {
			return nil
		}
		switch mode {
		case "direct", "wrapped", "caused", "typed-nil":
			return primary
		case "panic":
			panic(panicValue)
		case "goexit":
			runtime.Goexit()
		}
		return nil
	}
	var result tsResult
	var recovered any
	returned := false
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { recovered = recover() }()
		invoke := func() { result = f.run(t); returned = true }
		if position == 1 && cleanup == 0 {
			invoke()
			return
		}
		if position == 2 && cleanup == 0 {
			_, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageCommitNew, 0, tsRootKey(1), invoke)
			if err != nil {
				t.Error(err)
			}
			return
		}
		nativeMode := cleanup
		if position == 2 {
			nativeMode = 16
			if cleanup == 10 {
				nativeMode = 15
			}
		}
		_, err := fixtureLargeFault(f.s, nativeMode, 0, tsRootKey(1), invoke)
		if err != nil {
			t.Error(err)
		}
	}()
	eiAwait(t, done)
	unwound := mode == "panic" || mode == "goexit"
	if returned == unwound || mode == "panic" && recovered != panicValue || mode != "panic" && recovered != nil {
		t.Fatal("Source return/error/panic/Goexit disposition", returned, recovered)
	}
	if reservationLive(f.o) != 0 {
		t.Fatal("frozen slots/step/temporary loan retained after Source result")
	}
	for j, provider := range f.p {
		writer, readback := 1, 0
		if position == 1 && mode != "nil" && j > role {
			writer = 0
		}
		if position == 2 && (mode == "nil" || j <= role) {
			readback = 1
		}
		if position == 1 && mode == "nil" && cleanup != 0 {
			readback = 1
		}
		if provider.calls != [3]int{0, writer, readback} {
			t.Fatal("Source prefix suppression/position", j, provider.calls)
		}
		if writer != 0 {
			tsExpiredReader(t, provider.reader)
			if provider.sink.WindowV1() != nil {
				t.Fatal("Source sink remains active", j)
			}
			rec := provider.sink.recorder
			if rec.charged && (!rec.released || rec.descs != nil || rec.value != nil) {
				t.Fatal("charged frozen recorder survived outer account cleanup", j, rec.released)
			}
		}
	}
	trLifecycleResultV1(t, f, position, role, mode, cleanup, primary, result)
}

func trLifecycleResultV1(t *testing.T, f *tsfScene, position TreePositionV1, role int, mode string, cleanup uint32, primary error, result tsResult) {
	t.Helper()
	application := mode != "nil" && mode != "panic" && mode != "goexit"
	if mode == "nil" {
		result.tuple(t, 2, 3, -1)
		if position == 1 && cleanup == 0 {
			mustEnvironment(t, result.err)
		} else {
			ce, ok := result.err.(*CommitError)
			if !ok || ce.Truth != 2 {
				t.Fatal("nil Source complete NEW infrastructure tuple", result.err)
			}
			if position == 1 {
				treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
				tsHeldCausesV1(t, ce.ReadbackCause, nil, cleanup)
			}
		}
	}
	if application {
		if position == 1 {
			result.tuple(t, 1, 1, role)
			if cleanup == 0 && any(result.err) != any(primary) {
				t.Fatal("Source primary identity/wrapper changed", result.err)
			}
		} else {
			result.tuple(t, 3, 3, -1)
			ce, ok := result.err.(*CommitError)
			if !ok {
				t.Fatal("strict Source primary missing", result.err)
			}
			treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
		}
	}
	if position == 1 && cleanup == 0 && !application {
		if f.s.state != storeOPEN || f.s.terminal != nil {
			t.Fatal("clean nil-primary Source unwind must leave OPEN", f.s.state)
		}
		tsFollowing(t, f.s, f.o)
		return
	}
	if position == 1 && mode != "nil" {
		tsHeldCausesV1(t, f.s.terminal, primary, cleanup)
	}
	if position == 2 {
		ce, ok := f.s.terminal.(*CommitError)
		if !ok {
			t.Fatal("strict terminal error lost initiating cause", f.s.terminal)
		}
		nativeMode := uint32(12)
		if cleanup == 9 {
			nativeMode = 16
		}
		if cleanup == 10 {
			nativeMode = 15
		}
		tsHeldCausesV1(t, ce.ReadbackCause, primary, nativeMode)
		treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
	}
	state := storeCLOSED
	if cleanup == 10 {
		state = storePOISONEDTHREAD
	}
	if f.s.state != state || f.s.terminal == nil {
		t.Fatal("Source/native cleanup state", f.s.state, state, f.s.terminal)
	}
	wantTruth := CommitTruthOld
	if mode == "nil" {
		wantTruth = CommitTruthNew
	} else if position == 2 {
		wantTruth = CommitTruthUnknown
	}
	if f.s.terminalTruth != wantTruth {
		t.Fatal("native cleanup changed complete operation truth", f.s.terminalTruth, wantTruth)
	}
	calls := 0
	accountRun(t, "replay Source next operation", f.o, TreeOperation, func(a *OperationAccount) {
		next := tsInvoke(f.s, a, func(*Reader) (TreeOperationV1, error) { calls++; return f.op, nil })
		if calls != 0 || any(next.err) != any(f.s.terminal) || next.truth != f.s.terminalTruth || next.stage != 1 || next.index != -1 {
			t.Fatal("Source cleanup did not reach Store/next operation", next)
		}
	})
	if cleanup == 10 {
		if f.s.txn == nil {
			t.Fatal("retained native cleanup lost handle")
		}
		mustEnvironment(t, fixtureLargeRelease(f.s))
	}
}

// This is a codec/store representation fixture, not a Section-25 valid-block
// maximum. Its quota is fixed from independently known fixture row widths.
func TestTreeReplayBoundedStressV1(t *testing.T) {
	const groups = 1024
	const events = 2 * groups
	for _, projection := range []bool{false, true} {
		t.Run(fmt.Sprintf("projection%v", projection), func(t *testing.T) {
			f := trSceneV1(t)
			raw := trStressSeedV1(t, f, groups)
			if projection {
				f.op.Proof = func(*TreeDeltaReportV1) error { return nil }
			}
			// Q=5*128+2*168+32+n; each A=140472+104E;
			// H of these fixed rows is below Sr (all node values <=140).
			q := uint64(1008 + len(raw))
			quota := q + 2*(74912+65560+104*events) + 131192 + (288440 + 104*events) + 147968
			var result tsResult
			mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				return a.WithReservation(402653184-quota, func() error {
					result = tsInvoke(f.s, a, func(*Reader) (TreeOperationV1, error) { return f.op, nil })
					return nil
				})
			}))
			if projection {
				if any(result.err) != any(errOperationReservationCapacity) || result.truth != 1 {
					t.Fatal("full-P regression control must refuse the native envelope", result)
				}
			} else {
				result.tuple(t, 2, 3, -1)
				mustEnvironment(t, result.err)
			}
			f.s = tsReopen(t, f.s, f.path)
			for _, p := range f.op.Primitives {
				entries := trStressEntriesV1(p.Generation, groups, !projection, raw)
				rows := map[string][]byte{}
				_ = testTreeBuild(p.Generation, entries, rows)
				for name, value := range rows {
					tsRead(t, f.s, TreeSchemaV1DBIs()[8], testTreeRowKey(name), value)
				}
				for i := range groups {
					old, next := trStressKeyV1(i, false), trStressKeyV1(i, true)
					wantOld, wantNext := tdFormed(tdFrame(7, 0, nil), 4, 0), []byte(nil)
					if !projection {
						wantOld, wantNext = nil, tdFormed(raw[148+11*i:148+11*(i+1)], 5, 0)
					}
					tsRead(t, f.s, schemaDBIs[1], tdUTXOKey(p.Generation, old, uint32(i)), wantOld)
					tsRead(t, f.s, schemaDBIs[1], tdUTXOKey(p.Generation, next, uint32(i)), wantNext)
				}
				if !projection {
					tsRead(t, f.s, schemaDBIs[0], tsRootKey(p.Generation), tcBinding(t, p.Generation, p.Endpoint, entries...))
				}
			}
			tsFollowing(t, f.s, f.o)
		})
	}
}

func trStressKeyV1(i int, next bool) [32]byte {
	var literal [9]byte
	binary.BigEndian.PutUint64(literal[:8], uint64(i))
	if next {
		literal[8] = 1
	}
	return sha3.Sum256(literal[:])
}

func trStressEntriesV1(g uint64, n int, next bool, raw []byte) []testTreeEntry {
	entries := make([]testTreeEntry, n)
	for i := range n {
		value := tdFormed(tdFrame(7, 0, nil), 4, 0)
		if next {
			value = tdFormed(raw[148+11*i:148+11*(i+1)], 5, 0)
		}
		entries[i] = tcEntry(tdUTXOKey(g, trStressKeyV1(i, next), uint32(i)), value)
	}
	slices.SortFunc(entries, func(a, b testTreeEntry) int { return bytes.Compare(a.k[:], b.k[:]) })
	return entries
}

func trStressSeedV1(t *testing.T, f *tsfScene, n int) []byte {
	t.Helper()
	var raw []byte
	for i := range f.op.Pair.Mutations {
		m := &f.op.Pair.Mutations[i]
		if m.DBI.Rank == 4 {
			raw = append(bytes.Clone(m.Literal[:148]), bytes.Repeat(tdFrame(1, 0, nil), n)...)
			m.Literal = raw
		}
	}
	var events []TreeEventV1
	for i := range n {
		events = append(events, TreeEventV1{Kind: 1, Outpoint: TreeOutpointV1{Txid: trStressKeyV1(i, false), Vout: uint32(i)}, TxIndex: 1, InputIndex: uint32(i)})
	}
	for i := range n {
		events = append(events, TreeEventV1{Kind: 2, Outpoint: TreeOutpointV1{Txid: trStressKeyV1(i, true), Vout: uint32(i)}, TxIndex: 1, FrameOffset: uint64(148 + 11*i), FrameLength: 11})
	}
	for j, p := range f.op.Primitives {
		f.p[j].block, f.p[j].events = TreeBlockV1{TxCount: 2, EventCount: uint32(2 * n)}, events
		p.Coverage.CurrentBody, p.Coverage.BlockMeta = raw, f.p[j].block
		entries := trStressEntriesV1(p.Generation, n, false, raw)
		rows := map[string][]byte{}
		_ = testTreeBuild(p.Generation, entries, rows)
		for name, value := range rows {
			treeNativeSeed(t, f.s, 8, testTreeRowKey(name), value)
		}
		for _, e := range entries {
			treeNativeSeed(t, f.s, 1, append(binary.BigEndian.AppendUint64(nil, p.Generation), e.k[:]...), e.v)
		}
		treeNativeSeed(t, f.s, 0, tsCounterKey(p.Generation), tsCounterLiteral(uint64(56*n), uint64(n)))
		treeNativeSeed(t, f.s, 0, tsRootKey(p.Generation), tcBinding(t, p.Generation, tcEndpoint(4, tdTxid(0xa0)), entries...))
	}
	return raw
}

func TestTreeReplayBoundedModeIsolationV1(t *testing.T) {
	for _, shape := range []string{"independent-held", "Proof", "slot", "LAG-WriteOrReuse"} {
		t.Run("fallback/"+shape, func(t *testing.T) {
			f := trSceneV1(t)
			proofs := 0
			switch shape {
			case "independent-held":
				raw := trBodyV1(&f.op, 3, false)
				f.op.Primitives[1].Coverage.CurrentBody = bytes.Clone(raw)
			case "Proof", "slot":
				f.op.Proof = func(*TreeDeltaReportV1) error { proofs++; return nil }
				if shape == "slot" {
					var header [148]byte
					copy(header[:], f.op.Primitives[0].Coverage.CurrentBody)
					f.op.HeaderSlot = &TreeHeaderSlotV1{Hash: f.op.Primitives[0].Block, Header: header}
				}
			case "LAG-WriteOrReuse":
				f.op.Primitives[1].Undo = UndoWriteOrReuseV1
			}
			plan := treeOwnPlanV1(f.op)
			if treeBoundedPlanV1(&plan) {
				t.Fatal("legal excluded ownership profile selected", shape)
			}
			for _, provider := range f.p {
				provider.after = func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error {
					if sink.recorder.referenceOnly {
						t.Fatal("full-P fallback acquired selected replay mode")
					}
					return nil
				}
			}
			result := f.run(t)
			result.tuple(t, 2, 3, -1)
			mustEnvironment(t, result.err)
			if (proofs == 1) != (shape == "Proof" || shape == "slot") {
				t.Fatal("fallback Proof cardinality", shape, proofs)
			}
			tsFollowing(t, f.s, f.o)
		})
	}
	f := trSceneV1(t)
	parent := tcEndpoint(4, tdTxid(0xa0))
	treeNativeSeed(t, f.s, 0, tsRootKey(1), tcBinding(t, 1, parent))
	p := f.op.Primitives[0]
	p.Kind, p.Undo = TreeKindDirectApplyV1, UndoTransientV1
	called := 0
	p.Source = tsSource(func(pos TreePositionV1, r *Reader, sink *TreeDeltaSinkV1) error {
		called++
		if !sink.recorder.rootReadOnly || sink.recorder.referenceOnly {
			t.Fatal("F3 rootReadOnly acquired replay reference-only mode")
		}
		return f.p[0].TreeDeltaV1(pos, r, sink)
	})
	accountRun(t, "separate F3 root derivation", f.o, TreeOperation, func(a *OperationAccount) {
		mustEnvironment(t, f.s.View(func(r *Reader) error {
			root, err := r.DeriveTreeRootV1(a, TreeRootReadV1{Primitive: p, Parent: parent})
			value := tdFormed(p.Coverage.CurrentBody[148:], 5, 1)
			want := testTreeBuild(1, []testTreeEntry{tcEntry(tdUTXOKey(1, tdTxid(0x31), 0), value)}, map[string][]byte{})
			if err != nil || root != want.digest || called != 1 {
				t.Fatal("F3 independent root/source observation", root, want.digest, called, err)
			}
			return nil
		}))
	})
	c, old := tdAllocCase(5)
	r, d := c.delta(t, treeWriterV1, &tdLedger{})
	defer r.releaseV1()
	if r.referenceOnly || r.rootReadOnly {
		t.Fatal("inverse recorder acquired selected replay mode")
	}
	tdOK(t, d.resolveV1(old))
	retained := 0
	for _, g := range r.descs {
		if g.img != nil {
			retained++
		}
	}
	if retained == 0 {
		t.Fatal("inverse original undo images unexpectedly retired")
	}
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
	return tsHeldDumpV1(t, s)
}

// tsHeldSceneV1 keeps the existing real three-primitive scene, borrowing each
// complete qualified body before removing its stored row and Pair target.
func tsHeldSceneV1(t *testing.T) *tsfScene {
	t.Helper()
	s := tsfNew(t)
	tsfCover(t, s)
	for j := 1; j < len(s.op.Primitives); j++ {
		p := &s.op.Primitives[j]
		mustEnvironment(t, s.s.View(func(r *Reader) error {
			value, present, err := r.Get(TreeSchemaV1DBIs()[4], p.Block[:])
			if err == nil && !present {
				t.Fatal("held fixture body missing")
			}
			p.Coverage.CurrentBody = bytes.Clone(value)
			return err
		}))
		mustEnvironment(t, fixtureDeletePrefixRow(s.s, TreeSchemaV1DBIs()[4], p.Block[:]))
	}
	tsHeldV1(&s.op)
	return s
}

func TestTreeHeldBodyReadbackV1(t *testing.T) {
	for _, row := range []struct {
		name     string
		scenario SelectedDamageScenario
		truth    CommitTruth
	}{
		{"OLD", SelectedDamageCommitOld, 1},
		{"NEW", SelectedDamageCommitNew, 2},
		{"UNKNOWN", SelectedDamageCommitUnreadable, 3},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := tbNewV1(t)
			tsHeldV1(&f.op)
			before := tsHeldDumpV1(t, f.s)
			oracle := tbNewV1(t)
			mustEnvironment(t, oracle.run(t).err)
			after := tsHeldDumpV1(t, oracle.s)
			block := f.op.Primitives[0].Block
			delete(after, fmt.Sprintf("4/%x", block))
			var r tsResult
			evidence, err := FixtureSelectedDamage(f.s, f.o, row.scenario, 0, tsRootKey(1), func() { r = f.run(t) })
			mustEnvironment(t, err)
			r.tuple(t, row.truth, 3, -1)
			ce, ok := r.err.(*CommitError)
			if !ok || ce.Truth != row.truth || evidence.Commits != 1 || reservationLive(f.o) != 0 {
				t.Fatal("held readback disposition", r, evidence)
			}
			treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
			if row.truth == 3 {
				treeNativeError(t, ce.ReadbackCause, "update", "IO", 5, "error 5", nil)
			} else if ce.ReadbackCause != nil || f.source.calls != [3]int{0, 1, 1} {
				t.Fatal("held bytes not checked at both positions", ce, f.source.calls)
			}
			tsConsumed(t, f.s, f.o, row.truth, r.err)
			clear(f.op.Primitives[0].Coverage.CurrentBody)
			want := after
			if row.truth == 1 {
				want = before
			}
			if got := tsHeldDumpV1(t, tsReopen(t, f.s, f.path)); !reflect.DeepEqual(got, want) {
				t.Fatal("held readback durable image differs from oracle")
			}
		})
	}
	t.Run("absent-reference", func(t *testing.T) {
		f := tbNewV1(t)
		tsHeldV1(&f.op)
		var r tsResult
		block := f.op.Primitives[0].Block
		drift, err := FixtureCleanupReadbackDrift(f.s, 4, block[:], func() { r = f.run(t) })
		mustEnvironment(t, err)
		r.tuple(t, 3, 3, -1)
		ce, ok := r.err.(*CommitError)
		if !ok || ce.Truth != 3 || ce.ReadbackCause != nil || drift != 1 || f.source.calls != [3]int{0, 1, 1} {
			t.Fatal("strict equality omitted absent blocks-v1 reference", r, drift, f.source.calls)
		}
		tsConsumed(t, f.s, f.o, 3, r.err)
	})
}

// Every refusal occurs at LAG1 (j=1), after CURRENT planning and before Proof,
// its header slot, the LAG1 Source or the later LAG2 primitive.
func TestTreeHeldBodyBindingRefusalsV1(t *testing.T) {
	for _, mode := range []string{"identical", "different", "drift", "read-error"} {
		t.Run(mode, func(t *testing.T) {
			s := tsHeldSceneV1(t)
			p := &s.op.Primitives[1]
			key, body := bytes.Clone(p.Block[:]), bytes.Clone(p.Coverage.CurrentBody)
			if mode == "identical" || mode == "different" {
				if mode == "different" {
					body[148] ^= 1
				}
				treeNativeSeed(t, s.s, 4, key, body)
			}
			before := tsHeldDumpV1(t, s.s)
			proofs := 0
			s.op.Proof = func(*TreeDeltaReportV1) error { proofs++; return nil }
			s.op.HeaderSlot = tsSlot(t)
			var r tsResult
			switch mode {
			case "drift":
				count, err := FixtureWriteSnapshotDrift(s.s, 4, key, func() { r = s.run(t) })
				mustEnvironment(t, err)
				if count != 1 {
					t.Fatal("held presence drift not reached")
				}
				before[fmt.Sprintf("4/%x", key)] = string([]byte{0x7f})
			case "read-error":
				evidence, err := FixtureSelectedDamage(s.s, s.o, SelectedDamageGetEIO, 4, key, func() { r = s.run(t) })
				mustEnvironment(t, err)
				if evidence.Faults != 1 {
					t.Fatal("held presence read fault not reached", evidence)
				}
			default:
				r = s.run(t)
			}
			r.tuple(t, 1, 1, 1)
			switch mode {
			case "drift":
				treeNativeError(t, r.err, "update", "StateMismatch", -30779, "OLD/write snapshot mismatch", nil)
			case "read-error":
				treeNativeError(t, r.err, "update", "IO", 5, "error 5", nil)
			default:
				tsHeldPresentV1(t, r.err)
			}
			if proofs != 0 || s.p[0].calls != [3]int{0, 1, 0} || s.p[1].calls != [3]int{} || s.p[2].calls != [3]int{} {
				t.Fatal("held binding refusal order", proofs, s.p[0].calls, s.p[1].calls, s.p[2].calls)
			}
			tsConsumed(t, s.s, s.o, 1, r.err)
			if got := tsHeldDumpV1(t, tsReopen(t, s.s, s.path)); !reflect.DeepEqual(got, before) {
				t.Fatal("held binding refusal changed durable OLD")
			}
		})
	}
}

func TestTreeHeldBodySourceResultsV1(t *testing.T) {
	for _, position := range []TreePositionV1{1, 2} {
		cleanups := []uint32{0, 9, 10}
		if position == 2 {
			cleanups = []uint32{12, 15, 16}
		}
		for _, cleanup := range cleanups {
			for _, mode := range []string{"direct", "wrapped", "caused", "typed-nil", "panic", "goexit"} {
				t.Run(fmt.Sprintf("position%d/cleanup%d/%s", position, cleanup, mode), func(t *testing.T) {
					tsHeldSourceResultV1(t, position, cleanup, mode, "clean")
				})
			}
		}
		for _, recorded := range []string{"reader", "sink"} {
			for _, mode := range []string{"panic", "goexit"} {
				cleanup := uint32(0)
				if position == 2 {
					cleanup = 12
				}
				t.Run(fmt.Sprintf("position%d/%s/%s", position, recorded, mode), func(t *testing.T) {
					tsHeldSourceResultV1(t, position, cleanup, mode, recorded)
				})
			}
		}
	}
}

func tsHeldSourceResultV1(t *testing.T, position TreePositionV1, cleanup uint32, mode, recorded string) {
	t.Helper()
	s := tsHeldSceneV1(t)
	before := tsHeldDumpV1(t, s.s)
	if position == 2 {
		oracle := tsHeldSceneV1(t)
		mustEnvironment(t, oracle.run(t).err)
		before = tsHeldDumpV1(t, oracle.s)
	}
	marker, value := errors.New("held source failure"), new(int)
	var primary error = marker
	switch mode {
	case "wrapped":
		primary = fmt.Errorf("held source context: %w", marker)
	case "caused":
		primary = &EngineError{Class: "IO", Operation: "get", Code: 5, Diagnostic: "held source", Cause: marker}
	case "typed-nil":
		var typed *nilPointerError
		primary = typed
	case "panic", "goexit":
		primary = nil
	}
	s.p[1].before = func(pos TreePositionV1, r *Reader, sink *TreeDeltaSinkV1) error {
		if pos != position {
			return nil
		}
		if recorded == "reader" {
			_, _, primary = r.Get(TreeSchemaV1DBIs()[6], tsTarget(77).Key)
		} else if recorded == "sink" {
			primary = sink.BeginV1(TreeBlockV1{})
		}
		if mode == "panic" {
			panic(value)
		}
		if mode == "goexit" {
			runtime.Goexit()
		}
		return primary
	}
	var r tsResult
	var recovered any
	returned := false
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			recovered = recover()
			if reservationLive(s.o) != 0 {
				t.Error("held consumers still charged at unwind delivery")
			}
		}()
		run := func() {
			invoke := func() { r = s.run(t); returned = true }
			if cleanup == 0 {
				invoke()
				return
			}
			_, err := fixtureLargeFault(s.s, cleanup, 0, tsCounterKey(2), invoke)
			mustEnvironment(t, err)
		}
		if recorded == "reader" {
			_, err := FixtureSelectedDamage(s.s, s.o, SelectedDamageGetEIO, 6, tsTarget(77).Key, run)
			mustEnvironment(t, err)
		} else {
			run()
		}
	}()
	eiAwait(t, done)
	if mode == "panic" && recovered != value || mode != "panic" && recovered != nil || returned != (mode != "panic" && mode != "goexit") {
		t.Fatal("held original source delivery", mode, recovered, returned)
	}
	if recorded == "reader" {
		treeNativeError(t, primary, "get", "IO", 5, "error 5", nil)
	} else if recorded == "sink" {
		treeNativeError(t, primary, "update", "InvalidInput", 22, "invalid tree delta", nil)
	}
	tsHeldSourceOutcomeV1(t, s, position, cleanup, primary, r, returned)
	tsExpiredReader(t, s.p[1].reader)
	if s.p[1].sink.WindowV1() != nil || s.p[2].calls[position] != 0 || reservationLive(s.o) != 0 {
		t.Fatal("held source retained consumers or reached later primitive")
	}
	for _, p := range s.op.Primitives {
		clear(p.Coverage.CurrentBody)
	}
	if position == 1 && cleanup == 0 && primary == nil {
		m := tsTarget(900_000)
		before[fmt.Sprintf("6/%x", m.Key)] = string(m.Literal)
	}
	if !reflect.DeepEqual(tsHeldDumpV1(t, tsReopen(t, s.s, s.path)), before) {
		t.Fatal("held source failure changed the expected durable image")
	}
}

func tsHeldSourceOutcomeV1(t *testing.T, s *tsfScene, position TreePositionV1, cleanup uint32, primary error, r tsResult, returned bool) {
	t.Helper()
	if position == 1 && cleanup == 0 && primary == nil {
		if s.s.state != storeOPEN || s.s.terminal != nil {
			t.Fatal("clean held writer unwind consumed Store")
		}
		tsFollowing(t, s.s, s.o)
		return
	}
	truth := CommitTruth(1)
	if position == 2 {
		truth = 3
		ce, ok := s.s.terminal.(*CommitError)
		if !ok || ce.Truth != 3 {
			t.Fatal("held readback cause identity", s.s.terminal, primary)
		}
		tsHeldCausesV1(t, ce.ReadbackCause, primary, cleanup)
		treeNativeError(t, ce.Cause, "update", "Capacity", 28, "error 28", nil)
	} else {
		tsHeldCausesV1(t, s.s.terminal, primary, cleanup)
	}
	if returned {
		index, stage := 1, UpdateStage(1)
		if position == 2 {
			index, stage = -1, 3
		}
		r.tuple(t, truth, stage, index)
		if any(r.err) != any(s.s.terminal) {
			t.Fatal("returned failure differs from terminal")
		}
	}
	if cleanup != 10 && cleanup != 15 {
		tsConsumed(t, s.s, s.o, truth, s.s.terminal)
		return
	}
	if s.s.state != storePOISONEDTHREAD || s.s.txn == nil || s.s.terminalTruth != truth {
		t.Fatal("held retained cleanup disposition", s.s.state)
	}
	calls := 0
	accountRun(t, "held retained next operation", s.o, TreeOperation, func(a *OperationAccount) {
		next := tsInvoke(s.s, a, func(*Reader) (TreeOperationV1, error) { calls++; return s.op, nil })
		next.tuple(t, truth, 1, -1)
		if calls != 0 || any(next.err) != any(s.s.terminal) {
			t.Fatal("held retained instance ran next callback")
		}
	})
	mustEnvironment(t, fixtureLargeRelease(s.s))
}

// tsHeldCausesV1 pins provider identity before the optional cleanup failure.
func tsHeldCausesV1(t *testing.T, got, primary error, cleanup uint32) {
	t.Helper()
	if cleanup == 0 || cleanup == 12 {
		if any(got) != any(primary) {
			t.Fatal("held primary identity", got, primary)
		}
		return
	}
	if primary != nil {
		joined, ok := got.(interface{ Unwrap() []error })
		if !ok {
			t.Fatal("held primary/cleanup causes not retained", got)
		}
		parts := joined.Unwrap()
		if len(parts) != 2 || any(parts[0]) != any(primary) {
			t.Fatal("held primary/cleanup cause order", parts)
		}
		got = parts[1]
	}
	if cleanup == 10 || cleanup == 15 {
		engine := requireEnvironmentError(t, got, "LocalInvariant", "abort", -30416, "MDBX_THREAD_MISMATCH: A thread has attempted to use a not owned object, e.g. a transaction that started by another thread")
		if !engine.ReopenRequired || engine.Cause != nil {
			t.Fatal("held retained abort error", engine)
		}
		return
	}
	treeNativeError(t, got, "abort", "IO", 5, "error 5", nil)
}

func TestTreeHeldBodyStepChargeV1(t *testing.T) {
	s, path, o := tsNew(t)
	op := tsOperation(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { t.Fatal("uncharged Source"); return nil }))
	tsCover(&op, TreeBlockV1{TxCount: 1})
	body := op.Pair.Mutations[0]
	mustEnvironment(t, tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: op.Pair}).err)
	tsHeldV1(&op)
	var r tsResult
	mustEnvironment(t, o.WithOperation(TreeOperation, func(a *OperationAccount) error {
		return a.WithReservation(402653184-74912+1, func() error {
			r = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil })
			if reservationLive(o) != 402653184-74912+1 {
				t.Fatal("step refusal changed caller hold")
			}
			return nil
		})
	}))
	r.tuple(t, 1, 1, 0)
	if any(r.err) != any(errOperationReservationCapacity) {
		t.Fatal("step charge did not precede held presence", r.err)
	}
	tsConsumed(t, s, o, 1, r.err)
	tsRead(t, tsReopen(t, s, path), body.DBI, body.Key, body.Literal)
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
		filler := uint64(402_653_184) - pc - budgets[2] - 131_192 - 288_440 - 208 + 1
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

// tbSceneV1 owns OLD {20,90}, selected NEW {30,90} and their independent nodes.
// The unchanged 90 child is deliberately unread by the pure fold.
type tbSceneV1 struct {
	s             *Store
	path          string
	o             *OperationReservationOwner
	op            TreeOperationV1
	source        *tsfProvider
	old, next     map[string][]byte
	kept, created []byte
}

func tbNewV1(t *testing.T) *tbSceneV1 {
	t.Helper()
	s, path, owner := tsNew(t)
	p := &tsfProvider{block: TreeBlockV1{TxCount: 2, EventCount: 2}, events: []TreeEventV1{tsSpend(0x20, 0, 1, 0), tsCreate(0x30, 0, 1, 148, 11)}}
	op := tbOperationV1(t, p)
	tsCover(&op, p.block)
	treeNativeSeed(t, s, 3, op.Pair.Mutations[1].Key, op.Pair.Mutations[1].Literal[:148])
	a, b := tdUTXOKey(1, tdTxid(0x20), 0), tdUTXOKey(1, tdTxid(0x90), 0)
	va, vb := tdFormed(tdFrame(7, 0, nil), 4, 0), tdFormed(tdFrame(8, 0, nil), 4, 0)
	c := tdUTXOKey(1, tdTxid(0x30), 0)
	vc := tdFormed(op.Pair.Mutations[1].Literal[148:], 5, 0)
	old, next := map[string][]byte{}, map[string][]byte{}
	_ = testTreeBuild(1, []testTreeEntry{tcEntry(a, va), tcEntry(b, vb)}, old)
	_ = testTreeBuild(1, []testTreeEntry{tcEntry(c, vc), tcEntry(b, vb)}, next)
	for name, value := range old {
		treeNativeSeed(t, s, 8, testTreeRowKey(name), value)
	}
	treeNativeSeed(t, s, 1, a, va)
	treeNativeSeed(t, s, 1, b, vb)
	treeNativeSeed(t, s, 0, tsCounterKey(1), tsCounterLiteral(112, 2))
	treeNativeSeed(t, s, 0, tsRootKey(1), tcBinding(t, 1, tcEndpoint(4, tdTxid(0xa0)), tcEntry(a, va), tcEntry(b, vb)))
	return &tbSceneV1{
		s: s, path: path, o: owner, op: op, source: p, old: old, next: next,
		kept: testTreeNodeKey(1, 288, tcEntry(b, vb).k), created: testTreeNodeKey(1, 288, tcEntry(c, vc).k),
	}
}

func (f *tbSceneV1) run(t *testing.T) tsResult {
	t.Helper()
	return tsRun(t, f.s, f.o, TreeOperation, f.op)
}

func (f *tbSceneV1) durable(t *testing.T, next bool) {
	t.Helper()
	f.s = tsReopen(t, f.s, f.path)
	rows := f.old
	if next {
		rows = f.next
	}
	for _, domain := range []map[string][]byte{f.old, f.next} {
		for name := range domain {
			tsRead(t, f.s, TreeSchemaV1DBIs()[8], testTreeRowKey(name), rows[name])
		}
	}
	var absent []byte
	newValue := absent
	oldValue := tdFormed(tdFrame(7, 0, nil), 4, 0)
	if next {
		newValue, oldValue = tdFormed(f.op.Pair.Mutations[1].Literal[148:], 5, 0), nil
	}
	tsRead(t, f.s, schemaDBIs[1], tdUTXOKey(1, tdTxid(0x20), 0), oldValue)
	tsRead(t, f.s, schemaDBIs[1], tdUTXOKey(1, tdTxid(0x30), 0), newValue)
}

// TestTreeBoundedPreflightV1 separates the newly complete checker domains
// from earlier Source and pure-fold ownership, with exact consumed lifecycle.
func TestTreeBoundedPreflightV1(t *testing.T) {
	for _, domain := range []string{"NEW-only", "kept"} {
		for _, earlier := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/source%v", domain, earlier), func(t *testing.T) {
				f := tbNewV1(t)
				key := f.created
				if domain == "kept" {
					key = f.kept
				}
				marker := errors.New("source precedes selected checker")
				if earlier {
					f.source.before = func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { return marker }
				}
				var result tsResult
				var counts PairReadObservation
				drift, err := FixtureWriteSnapshotDrift(f.s, 8, key, func() {
					var observe error
					counts, observe = FixturePairReadObservation(f.s, nil, func() { result = f.run(t) })
					mustEnvironment(t, observe)
				})
				mustEnvironment(t, err)
				index := -1
				if earlier {
					index = 0
					if any(result.err) != any(marker) {
						t.Fatal("selected checker replaced Source", result.err)
					}
				} else {
					ttMismatch(t, result.err, "OLD/write snapshot mismatch")
				}
				result.tuple(t, 1, 1, index)
				if drift != 1 || counts.Writes != 0 || f.source.calls != [3]int{0, 1, 0} || reservationLive(f.o) != 0 {
					t.Fatal("preflight order/no-write/source/account", drift, counts, f.source.calls)
				}
				tsConsumed(t, f.s, f.o, 1, result.err)
			})
		}
	}
	t.Run("native-checker", tbCheckerNativeV1)
	t.Run("earlier-original-work", tbEarlierV1)
}

func tbCheckerNativeV1(t *testing.T) {
	for _, domain := range []string{"NEW-only", "kept-reference"} {
		f := tbNewV1(t)
		key := f.created
		if domain == "kept-reference" {
			key = f.kept
		}
		var result tsResult
		evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageGetEIO, 8, key, func() { result = f.run(t) })
		mustEnvironment(t, err)
		result.tuple(t, 1, 1, -1)
		treeNativeError(t, result.err, "update", EngineIO, 5, "error 5", nil)
		if evidence.Faults != 1 || evidence.Commits != 0 || evidence.Deletes != 0 || f.source.calls != [3]int{0, 1, 0} {
			t.Fatal("checker native failure substituted or reordered", domain, result, evidence)
		}
		tsConsumed(t, f.s, f.o, 1, result.err)
	}
}

func tbEarlierV1(t *testing.T) {
	for _, stage := range []string{"Source", "finish", "resolve", "pure-fold"} {
		f := tbNewV1(t)
		marker := errors.New("original Source primary")
		switch stage {
		case "Source":
			f.source.before = func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error { return marker }
		case "finish":
			f.source.custom = func(_ TreePositionV1, _ *Reader, sink *TreeDeltaSinkV1) error { return sink.BeginV1(f.source.block) }
		case "resolve":
			f.source.events[0].Outpoint.Txid = tdTxid(0x21)
		case "pure-fold":
			treeNativeSeed(t, f.s, 0, tsRootKey(1), []byte{0xff})
		}
		var result tsResult
		evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageGetEIO, 8, f.created, func() { result = f.run(t) })
		if err == nil || err.Error() != "selected damage fixture site was not reached exactly as armed" || evidence.Faults != 0 || evidence.Deletes != 0 || evidence.Commits != 0 {
			t.Fatal("new checker preceded original work", stage, evidence, err)
		}
		result.tuple(t, 1, 1, 0)
		if stage == "Source" {
			if any(result.err) != any(marker) {
				t.Fatal("original Source identity", result.err)
			}
		} else if stage == "finish" {
			treeNativeError(t, result.err, "update", EngineInvalidInput, 22, "invalid tree delta", nil)
		} else {
			cause := error(nil)
			if stage == "pure-fold" {
				cause = errSchema
			}
			treeNativeError(t, result.err, "update", EngineIntegrity, -30796, "invalid tree native representation", cause)
		}
		tsConsumed(t, f.s, f.o, 1, result.err)
	}
}

// TestTreeBoundedWriterV1 observes Pair before root and one native write per
// streamed target. Faults pin reached-stage and fused equality independently.
func TestTreeBoundedWriterV1(t *testing.T) {
	for _, domain := range []string{"success", "UTXO", "counter", "node", "Pair", "root"} {
		t.Run(domain, func(t *testing.T) {
			f := tbNewV1(t)
			rank, key := uint8(0), tsRootKey(1)
			switch domain {
			case "UTXO":
				rank, key = 1, tdUTXOKey(1, tdTxid(0x30), 0)
			case "counter":
				key = tsCounterKey(1)
			case "node":
				rank, key = 8, f.created
			case "Pair":
				rank, key = 4, f.op.Pair.Mutations[1].Key
			}
			var result tsResult
			scenario := SelectedDamagePutEIO
			if domain == "success" {
				scenario = SelectedDamageProbeOnly
			}
			var counts PairReadObservation
			evidence, err := FixtureSelectedDamage(f.s, f.o, scenario, rank, key, func() {
				var observe error
				counts, observe = FixturePairReadObservation(f.s, nil, func() { result = f.run(t) })
				mustEnvironment(t, observe)
			})
			mustEnvironment(t, err)
			if domain == "success" {
				result.tuple(t, 2, 3, -1)
				mustEnvironment(t, result.err)
				if evidence.Commits != 1 || evidence.Deletes != 5 || counts.Writes != 13 || f.source.calls != [3]int{0, 1, 0} {
					t.Fatal("writer success/unique targets", evidence, counts)
				}
				f.durable(t, true)
				return
			}
			result.tuple(t, 1, 2, -1)
			treeNativeError(t, result.err, "update", EngineIO, 5, "error 5", nil)
			if evidence.Faults != 1 || evidence.Commits != 0 {
				t.Fatal("writer fault", evidence)
			}
			// One old UTXO, counter, OLD-only leaf and common branch delete.
			// Pair inserts add no deletes; final root adds exactly one.
			if domain == "Pair" && evidence.Deletes != 4 || domain == "root" && evidence.Deletes != 5 {
				t.Fatal("Pair/root order or target rewritten", domain, evidence)
			}
			tsConsumed(t, f.s, f.o, 1, result.err)
			f.durable(t, false)
			tsFollowing(t, f.s, f.o)
		})
	}
}

// TestTreeBoundedReadbackV1 exercises complete native OLD/NEW/UNKNOWN results
// plus source error/panic/Goexit after crossing. The native observer in
// tbReadbackNewFalseV1 checks the account throughout regenerated comparisons.
func TestTreeBoundedReadbackV1(t *testing.T) {
	for _, row := range []struct {
		name     string
		scenario SelectedDamageScenario
		truth    CommitTruth
	}{
		{"OLD", SelectedDamageCommitOld, 1},
		{"NEW", SelectedDamageCommitNew, 2},
		{"unreadable", SelectedDamageCommitUnreadable, 3},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := tbNewV1(t)
			var result tsResult
			var counts PairReadObservation
			var before, after uint64
			f.source.before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
				if pos == 2 {
					before = reservationLive(f.o)
				}
				return nil
			}
			f.source.after = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
				if pos == 2 {
					after = reservationLive(f.o)
				}
				return nil
			}
			evidence, err := FixtureSelectedDamage(f.s, f.o, row.scenario, 0, tsRootKey(1), func() {
				var observe error
				counts, observe = FixturePairReadObservation(f.s, nil, func() { result = f.run(t) })
				mustEnvironment(t, observe)
			})
			mustEnvironment(t, err)
			result.tuple(t, row.truth, 3, -1)
			ce, ok := result.err.(*CommitError)
			if !ok || ce.Truth != row.truth || evidence.Commits != 1 || reservationLive(f.o) != 0 {
				t.Fatal("bounded truth", result, evidence)
			}
			if row.name == "unreadable" {
				if ce.ReadbackCause == nil {
					t.Fatal("unreadable normalized to OLD")
				}
			} else if ce.ReadbackCause != nil || f.source.calls != [3]int{0, 1, 1} || before != 420583 || before != after {
				t.Fatal("strict complete Source/stable account", ce.ReadbackCause, f.source.calls, before, after)
			}
			if row.name == "NEW" && (evidence.ReadGets == 0 || counts.Comparisons == 0) {
				t.Fatal("strict comparisons missing", counts)
			}
			tsConsumed(t, f.s, f.o, row.truth, result.err)
			if row.truth != 3 {
				f.durable(t, row.truth == 2)
			}
		})
	}
	t.Run("complete-after-false", tbReadbackCompleteV1)
	t.Run("NEW-false-complete-domain", tbReadbackNewFalseV1)
	t.Run("fused-final-and-reference", tbFusedV1)
	t.Run("source-results", tbReadbackSourceV1)
	t.Run("retained-cleanup", tbReadbackCleanupV1)
	t.Run("nil-primary-writer-unwind", tbWriterUnwindV1)
}

func tbReadbackCleanupV1(t *testing.T) {
	for _, mode := range []uint32{15, 16, 19, 23} {
		f := tbNewV1(t)
		var result tsResult
		_, err := fixtureLargeFault(f.s, mode, 0, tsRootKey(1), func() { result = f.run(t) })
		mustEnvironment(t, err)
		truth, state := CommitTruthNew, storeCLOSED
		if mode == 19 {
			truth = CommitTruthOld
		}
		if mode == 23 {
			truth = CommitTruthUnknown
		}
		if mode == 15 || mode == 19 {
			state = storePOISONEDTHREAD
		}
		result.tuple(t, truth, 3, -1)
		ce, ok := result.err.(*CommitError)
		if !ok || ce.Truth != truth || ce.ReadbackCause == nil || f.s.state != state || any(f.s.terminal) != any(result.err) || f.s.terminalTruth != truth || reservationLive(f.o) != 0 {
			t.Fatal("selected cleanup disposition", mode, result, f.s.state)
		}
		treeNativeError(t, ce.Cause, "update", EngineCapacity, 28, "error 28", nil)
		if mode == 15 || mode == 19 {
			engine := requireEnvironmentError(t, ce.ReadbackCause, "LocalInvariant", "abort", -30416, "MDBX_THREAD_MISMATCH: A thread has attempted to use a not owned object, e.g. a transaction that started by another thread")
			if !engine.ReopenRequired || engine.Cause != nil {
				t.Fatal("retained cleanup identity", engine)
			}
		} else {
			operation := operationAbort
			if mode == 23 {
				operation = operationUpdate
			}
			treeNativeError(t, ce.ReadbackCause, operation, EngineIO, 5, "error 5", nil)
		}
		calls := 0
		accountRun(t, "selected cleanup next operation", f.o, TreeOperation, func(a *OperationAccount) {
			next := tsInvoke(f.s, a, func(*Reader) (TreeOperationV1, error) { calls++; return f.op, nil })
			next.tuple(t, truth, 1, -1)
			if calls != 0 || any(next.err) != any(result.err) {
				t.Fatal("retained cleanup next callback")
			}
		})
		if mode == 15 || mode == 19 {
			mustEnvironment(t, fixtureLargeRelease(f.s))
		}
	}
}

func tbWriterUnwindV1(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		f := tbNewV1(t)
		value := new(int)
		f.source.before = func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error {
			if mode == "panic" {
				panic(value)
			}
			runtime.Goexit()
			return nil
		}
		var recovered any
		returned := false
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() { recovered = recover() }()
			_ = f.run(t)
			returned = true
		}()
		eiAwait(t, done)
		if returned || mode == "panic" && recovered != value || mode == "goexit" && recovered != nil || f.s.state != storeOPEN || f.s.terminal != nil || reservationLive(f.o) != 0 {
			t.Fatal("nil-primary clean abort must stay OPEN", mode, returned, recovered, f.s.state)
		}
		tsFollowing(t, f.s, f.o)
	}
}

func tbReadbackCompleteV1(t *testing.T) {
	for _, domain := range []string{"root", "Pair-owner"} {
		f := tbNewV1(t)
		rank, key := uint8(0), tsRootKey(1)
		if domain == "Pair-owner" {
			rank, key = 7, f.op.Pair.Mutations[2].Key
		}
		var result tsResult
		evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageCommitUnreadable, rank, key, func() { result = f.run(t) })
		mustEnvironment(t, err)
		result.tuple(t, 3, 3, -1)
		ce, ok := result.err.(*CommitError)
		if !ok || ce.ReadbackCause == nil || evidence.Faults != 2 || evidence.ReadGets == 0 || f.source.calls != [3]int{0, 1, 1} {
			t.Fatal("late domain skipped after false OLD predicate", domain, result, evidence, f.source.calls)
		}
		treeNativeError(t, ce.ReadbackCause, "update", EngineIO, 5, "error 5", nil)
		tsConsumed(t, f.s, f.o, 3, result.err)
	}
}

// tbReadbackNewFalseV1 drifts only the physical committed image. The complete
// immutable Source remains unchanged. Strict Gets=41: resolve3, apply9,
// walker original reads3 plus target/reference comparisons14, Pair12.
// Strict hold is Q(159+584) + Br(288440+104*2) + H(131192) = 420583.
func tbReadbackNewFalseV1(t *testing.T) {
	for _, domain := range []string{"early-UTXO", "kept-reference", "Pair-owner"} {
		f := tbNewV1(t)
		rank, key := uint8(1), tdUTXOKey(1, tdTxid(0x30), 0)
		switch domain {
		case "kept-reference":
			rank, key = 8, f.kept
		case "Pair-owner":
			rank, key = 7, f.op.Pair.Mutations[2].Key
		}
		inReadback, strictGets := false, uint64(0)
		var sealed uint64
		f.source.before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
			inReadback = pos == 2
			if inReadback {
				sealed = reservationLive(f.o)
				if sealed != 420583 {
					t.Error("strict account before Source", sealed, "want 420583")
				}
			}
			return nil
		}
		var result tsResult
		var evidence fixtureLargeEvidence
		_, err := FixturePairReadObservation(f.s, func(site uint32) {
			if inReadback && site == 1 {
				strictGets++
			}
			if inReadback && (site == 1 || site == 2) && reservationLive(f.o) != sealed {
				t.Error("strict account grew after Source at native comparison", site, reservationLive(f.o), sealed)
			}
		}, func() {
			var fault error
			evidence, fault = fixtureLargeFault(f.s, 3, rank, key, func() { result = f.run(t) })
			mustEnvironment(t, fault)
		})
		mustEnvironment(t, err)
		result.tuple(t, 3, 3, -1)
		ce, ok := result.err.(*CommitError)
		if !ok || ce.ReadbackCause != nil || evidence.drift != 1 || evidence.commits != 1 || strictGets != 41 || f.source.calls != [3]int{0, 1, 1} {
			t.Fatal("physical false NEW skipped complete domain", domain, result, evidence, strictGets, f.source.calls)
		}
		tsConsumed(t, f.s, f.o, 3, result.err)
	}
}

func tbFusedV1(t *testing.T) {
	for _, domain := range []string{"target", "kept-reference"} {
		f := tbNewV1(t)
		rank, key := uint8(1), tdUTXOKey(1, tdTxid(0x30), 0)
		if domain == "kept-reference" {
			rank, key = 8, f.kept
		}
		var result tsResult
		evidence, err := fixtureLargeFault(f.s, 13, rank, key, func() { result = f.run(t) })
		mustEnvironment(t, err)
		result.tuple(t, 1, 2, -1)
		ttMismatch(t, result.err, "final update image mismatch")
		if evidence.drift != 1 || evidence.commits != 0 || reservationLive(f.o) != 0 {
			t.Fatal("fused/reference final", evidence)
		}
		tsConsumed(t, f.s, f.o, 1, result.err)
		f.durable(t, false)
	}
}

func tbReadbackSourceV1(t *testing.T) {
	for _, mode := range []string{"direct", "wrapped", "panic", "goexit"} {
		f := tbNewV1(t)
		marker, value := errors.New("bounded readback source"), new(int)
		primary := error(marker)
		if mode == "wrapped" {
			primary = fmt.Errorf("readback wrapper: %w", marker)
		}
		f.source.before = func(pos TreePositionV1, _ *Reader, _ *TreeDeltaSinkV1) error {
			if pos != 2 {
				return nil
			}
			switch mode {
			case "panic":
				panic(value)
			case "goexit":
				runtime.Goexit()
			}
			return primary
		}
		var result tsResult
		var recovered any
		returned := false
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() { recovered = recover() }()
			_, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageCommitNew, 0, tsRootKey(1), func() { result = f.run(t) })
			if err != nil {
				t.Error(err)
			}
			returned = true
		}()
		eiAwait(t, done)
		if f.source.calls != [3]int{0, 1, 1} || reservationLive(f.o) != 0 {
			t.Fatal("readback source release", mode, f.source.calls)
		}
		if mode == "panic" || mode == "goexit" {
			if returned || mode == "panic" && recovered != value || mode == "goexit" && recovered != nil {
				t.Fatal("source unwind changed", mode, recovered)
			}
			if f.s.state != storeCLOSED || f.s.terminalTruth != 3 {
				t.Fatal("readback unwind lifecycle", f.s.state, f.s.terminalTruth)
			}
			continue
		}
		result.tuple(t, 3, 3, -1)
		ce, ok := result.err.(*CommitError)
		if !ok || any(ce.ReadbackCause) != any(primary) || !returned || recovered != nil {
			t.Fatal("readback source cause identity", result)
		}
		tsConsumed(t, f.s, f.o, 3, result.err)
	}
}

// TestTreeBoundedFallbackV1 keeps legal adjacent ownership profiles executable.
func TestTreeBoundedFallbackV1(t *testing.T) {
	for _, shape := range []string{"connect", "no-index-pair", "Proof", "slot", "consulted", "stored-body", "held-body"} {
		f := tbNewV1(t)
		switch shape {
		case "connect":
			f.op.Primitives[0].Kind, f.op.Primitives[0].Undo = TreeKindConnectV1, UndoWriteOrReuseV1
		case "no-index-pair":
			f.op.Pair.Mutations = f.op.Pair.Mutations[1:2]
		case "Proof":
			f.op.Proof = func(*TreeDeltaReportV1) error { return nil }
		case "slot":
			var header [148]byte
			copy(header[:], f.op.Pair.Mutations[1].Literal[:148])
			f.op.Proof = func(*TreeDeltaReportV1) error { return nil }
			f.op.HeaderSlot = &TreeHeaderSlotV1{Hash: f.op.Primitives[0].Block, Header: header}
		case "consulted":
			f.op.Pair.Consulted = []ConsultedRow{{DBI: schemaDBIs[0], Key: []byte{2}}}
		case "stored-body":
			treeNativeSeed(t, f.s, 4, f.op.Pair.Mutations[1].Key, f.op.Pair.Mutations[1].Literal)
			f.op.Pair.Mutations = append(f.op.Pair.Mutations[:1], f.op.Pair.Mutations[2])
			f.op.Primitives[0].Coverage.BodyKind, f.op.Primitives[0].Coverage.CurrentBody = 2, nil
		case "held-body":
			tsHeldV1(&f.op)
		}
		plan := treeOwnPlanV1(f.op)
		if treeBoundedPlanV1(&plan) {
			t.Fatal("legal fallback selected", shape)
		}
		result := f.run(t)
		result.tuple(t, 2, 3, -1)
		mustEnvironment(t, result.err)
		if f.source.calls != [3]int{0, 1, 0} || reservationLive(f.o) != 0 {
			t.Fatal("fallback Source/account", shape)
		}
		tsFollowing(t, f.s, f.o)
	}
}

// TestTreeBoundedIdentityV1 distinguishes unchanged present UTXOs from
// created-then-spent absent groups through strict NEW with immutable Sources.
func TestTreeBoundedIdentityV1(t *testing.T) {
	for _, shape := range []string{"unchanged", "cancellation"} {
		f := tbNewV1(t)
		a, b := tdUTXOKey(1, tdTxid(0x20), 0), tdUTXOKey(1, tdTxid(0x90), 0)
		va, vb := tdFormed(tdFrame(7, 0, nil), 4, 0), tdFormed(tdFrame(8, 0, nil), 4, 0)
		if shape == "unchanged" {
			va = tdFormed(tdFrame(1, 0, nil), 5, 0)
			f.source.events = []TreeEventV1{tsSpend(0x20, 0, 1, 0), tsCreate(0x20, 0, 1, 148, 11)}
			f.old = map[string][]byte{}
			_ = testTreeBuild(1, []testTreeEntry{tcEntry(a, va), tcEntry(b, vb)}, f.old)
			for name, value := range f.old {
				treeNativeSeed(t, f.s, 8, testTreeRowKey(name), value)
			}
			treeNativeSeed(t, f.s, 1, a, va)
			treeNativeSeed(t, f.s, 0, tsRootKey(1), tcBinding(t, 1, tcEndpoint(4, tdTxid(0xa0)), tcEntry(a, va), tcEntry(b, vb)))
		} else {
			f.source.events = []TreeEventV1{tsCreate(0x30, 0, 0, 148, 11), tsSpend(0x30, 0, 1, 0)}
		}
		var result tsResult
		var counts PairReadObservation
		evidence, err := FixtureSelectedDamage(f.s, f.o, SelectedDamageCommitNew, 0, tsRootKey(1), func() {
			var observe error
			counts, observe = FixturePairReadObservation(f.s, nil, func() { result = f.run(t) })
			mustEnvironment(t, observe)
		})
		mustEnvironment(t, err)
		result.tuple(t, 2, 3, -1)
		ce, ok := result.err.(*CommitError)
		if !ok || ce.ReadbackCause != nil || evidence.Deletes != 2 || counts.Writes != 7 || f.source.calls != [3]int{0, 1, 1} || reservationLive(f.o) != 0 {
			t.Fatal("unchanged/cancelled identity emitted or dropped", shape, result, evidence, counts, f.source.calls)
		}
		tsConsumed(t, f.s, f.o, 2, result.err)
		f.s = tsReopen(t, f.s, f.path)
		for name, value := range f.old {
			tsRead(t, f.s, TreeSchemaV1DBIs()[8], testTreeRowKey(name), value)
		}
		tsRead(t, f.s, schemaDBIs[1], a, va)
		tsRead(t, f.s, schemaDBIs[1], b, vb)
		tsRead(t, f.s, schemaDBIs[1], tdUTXOKey(1, tdTxid(0x30), 0), nil)
		tsRead(t, f.s, schemaDBIs[0], tsRootKey(1), tcBinding(t, 1, f.op.Primitives[0].Endpoint, tcEntry(a, va), tcEntry(b, vb)))
	}
}

// RUB-1733 context window rows through the public entry under native fixture faults.

func ctxTreeIndexKey(gen, h uint64) []byte {
	return binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, gen), h)
}

func ctxTreeHeaderKey(t *testing.T, gen, h uint64) []byte {
	hash := sha3.Sum256(ctxTreeHeader(t, gen, h))
	return hash[:]
}

// ctxTreePairScene is a format-3 Store with a complete generation-7 window at heights 100..102.
func ctxTreePairScene(t *testing.T) (*Store, *OperationReservationOwner, *CanonicalContextWindowV1) {
	t.Helper()
	s, path, o := tsNew(t)
	ctxTreePaths[s] = path
	ctxTreeSeed(t, s, 7, 100, 3, nil, nil)
	return s, o, &CanonicalContextWindowV1{Generation: 7, FirstHeight: 100, Count: 3}
}

var ctxTreePaths = map[*Store]string{}

func ctxTreeFault(t *testing.T, s *Store, mode uint32, rank uint8, key []byte, run func()) fixtureLargeEvidence {
	t.Helper()
	evidence, err := fixtureLargeFault(s, mode, rank, key, run)
	mustEnvironment(t, err)
	return evidence
}

func TestCtxTreePairFixtureV1(t *testing.T) {
	t.Run("A8a-crossed-clean", func(t *testing.T) {
		s, o, w := ctxTreePairScene(t)
		var r tsResult
		evidence := ctxTreeFault(t, s, 12, 0, []byte{9}, func() { r = tsRun(t, s, o, TreeOperation, ctxTreeOp(60, w)) })
		r.tuple(t, 2, 3, -1)
		if evidence.commits != 1 || evidence.drift != 0 {
			t.Fatalf("A8a evidence%+v err%v", evidence, r.err)
		}
		tsConsumed(t, s, o, 2, r.err)
		tsRead(t, tsReopen(t, s, ctxTreePaths[s]), tsTarget(60).DBI, tsTarget(60).Key, tsTarget(60).Literal)
	})
	t.Run("R8a-crossed-drift", func(t *testing.T) {
		var calls [2]uint32
		for i, h := range []uint64{100, 102} {
			s, o, w := ctxTreePairScene(t)
			var r tsResult
			evidence := ctxTreeFault(t, s, 3, 3, ctxTreeHeaderKey(t, 7, h), func() {
				r = tsRun(t, s, o, TreeOperation, ctxTreeOp(61, w))
				calls[i] = fixtureLargeNativeCalls()
			})
			r.tuple(t, 3, 3, -1)
			if evidence.commits != 1 || evidence.drift != 1 {
				t.Fatalf("R8a evidence%+v", evidence)
			}
			tsConsumed(t, s, o, 3, r.err)
		}
		if calls[0] != calls[1] || calls[0] == 0 {
			t.Fatalf("R8a native calls offset0 %d, last %d", calls[0], calls[1])
		}
	})
	for _, c := range []struct {
		rank uint8
		key  func(*testing.T) []byte
	}{{2, func(*testing.T) []byte { return ctxTreeIndexKey(7, 101) }}, {3, func(t *testing.T) []byte { return ctxTreeHeaderKey(t, 7, 101) }}} {
		t.Run(fmt.Sprintf("R6-write-snapshot-rank%d", c.rank), func(t *testing.T) {
			s, o, w := ctxTreePairScene(t)
			var r tsResult
			evidence := ctxTreeFault(t, s, 14, c.rank, c.key(t), func() { r = tsRun(t, s, o, TreeOperation, ctxTreeOp(62, w)) })
			r.tuple(t, 1, 1, -1)
			treeNativeError(t, r.err, "update", "StateMismatch", -30779, "OLD/write snapshot mismatch", nil)
			if evidence.drift != 1 || evidence.commits != 0 {
				t.Fatalf("R6 evidence%+v", evidence)
			}
			ctxTreeConsulted(t, s, o, r)
		})
		t.Run(fmt.Sprintf("R7-final-rank%d", c.rank), func(t *testing.T) {
			s, o, w := ctxTreePairScene(t)
			var r tsResult
			evidence := ctxTreeFault(t, s, 13, c.rank, c.key(t), func() { r = tsRun(t, s, o, TreeOperation, ctxTreeOp(63, w)) })
			r.tuple(t, 1, 2, -1)
			treeNativeError(t, r.err, "update", "StateMismatch", -30779, "final update image mismatch", nil)
			if evidence.drift != 1 || evidence.commits != 0 {
				t.Fatalf("R7 evidence%+v", evidence)
			}
			tsConsumed(t, s, o, 1, r.err)
			tsRead(t, tsReopen(t, s, ctxTreePaths[s]), tsTarget(63).DBI, tsTarget(63).Key, nil)
		})
		t.Run(fmt.Sprintf("H2-native-read-rank%d", c.rank), func(t *testing.T) {
			s, o, w := ctxTreePairScene(t)
			var r tsResult
			evidence := ctxTreeFault(t, s, 28, c.rank, c.key(t), func() { r = tsRun(t, s, o, TreeOperation, ctxTreeOp(64, w)) })
			r.tuple(t, 1, 1, -1)
			var engine *EngineError
			if evidence.gets == 0 || !errors.As(r.err, &engine) || engine.Class != EngineIO {
				t.Fatalf("H2 %v evidence%+v", r.err, evidence)
			}
			if _, wrapped := r.err.(*contextTreeInfrastructureV1); wrapped {
				t.Fatal("H2 leaked the infrastructure wrapper")
			}
			tsConsumed(t, s, o, 1, r.err)
		})
	}
	t.Run("H2s-invalid-shape", func(t *testing.T) {
		s, o, w := ctxTreePairScene(t)
		var r tsResult
		evidence := ctxTreeFault(t, s, 17, 2, ctxTreeIndexKey(7, 100), func() { r = tsRun(t, s, o, TreeOperation, ctxTreeOp(65, w)) })
		r.tuple(t, 1, 1, -1)
		if evidence.gets == 0 || r.err == nil || !strings.Contains(r.err.Error(), "mdbx_get returned invalid result shape") {
			t.Fatalf("H2s %v evidence%+v", r.err, evidence)
		}
		tsConsumed(t, s, o, 1, r.err)
	})
	t.Run("no-native-read", func(t *testing.T) {
		s, o, w := ctxTreePairScene(t)
		mutation, consulted := ctxTreeOverlaps(t, 66, w)
		for _, op := range []TreeOperationV1{
			ctxTreeOp(66, &CanonicalContextWindowV1{Generation: 7, FirstHeight: 100, Count: 10081}),
			ctxTreeOp(66, &CanonicalContextWindowV1{FirstHeight: 100, Count: 1}),
			ctxTreeOp(66, &CanonicalContextWindowV1{Generation: 7, FirstHeight: 0x1_0000_0000, Count: 1}),
			ctxTreeOp(66, &CanonicalContextWindowV1{Generation: 7, FirstHeight: 100}),
			ctxTreeOp(66, &CanonicalContextWindowV1{Generation: 7, FirstHeight: 0xffffffff, Count: 2}),
			mutation, consulted,
		} {
			ctxTreeNoRead(t, s, o, op)
		}
	})
	t.Run("R5c-no-native-read", func(t *testing.T) {
		s, _, w := ctxTreePairScene(t)
		mutation, consulted := ctxTreeOverlaps(t, 67, w)
		for _, op := range []TreeOperationV1{ctxTreeOp(67, &CanonicalContextWindowV1{Generation: 8, FirstHeight: 100, Count: 1}), mutation, consulted} {
			ctxTreeNoRead(t, s, reservationFilled(t, 343), op)
		}
	})
	t.Run("R5-no-write-transaction", func(t *testing.T) {
		s, o, _ := ctxTreePairScene(t)
		ctxTreeSeed(t, s, 9, 100, 3, map[uint64]bool{101: true}, nil)
		ctxTreeSeed(t, s, 10, 100, 3, nil, map[uint64]bool{101: true})
		for _, gen := range []uint64{9, 10} {
			var r tsResult
			evidence := ctxTreeFault(t, s, 14, 2, ctxTreeIndexKey(7, 101), func() {
				r = tsRun(t, s, o, TreeOperation, ctxTreeOp(68, &CanonicalContextWindowV1{Generation: gen, FirstHeight: 100, Count: 3}))
			})
			ctxTreeIncomplete(t, r)
			if evidence.drift != 0 || evidence.commits != 0 {
				t.Fatalf("R5 generation %d began a write transaction: evidence%+v", gen, evidence)
			}
			ctxTreeOpen(t, s)
		}
	})
}

// ctxTreeNoRead runs an admission-refused op with mode 28 armed on its own offset-0 index key, wants no get of
// that key and no commit, and wants the Store OPEN.
func ctxTreeNoRead(t *testing.T, s *Store, o *OperationReservationOwner, op TreeOperationV1) {
	t.Helper()
	w := op.Pair.ContextConsulted
	var r tsResult
	evidence := ctxTreeFault(t, s, 28, 2, ctxTreeIndexKey(w.Generation, w.FirstHeight), func() { r = tsRun(t, s, o, LaneOperation, op) })
	r.tuple(t, 1, 1, -1)
	if evidence.gets != 0 || evidence.commits != 0 {
		t.Fatalf("admission row read context: %v evidence%+v", r.err, evidence)
	}
	ctxTreeOpen(t, s)
}

// ctxTreeConsulted pins the lifecycle that a drifted Consulted row takes at the write snapshot.
func ctxTreeConsulted(t *testing.T, s *Store, o *OperationReservationOwner, r tsResult) {
	t.Helper()
	tsConsumed(t, s, o, 1, r.err)
}

func ctxTreeScene(t *testing.T) *tsfScene {
	t.Helper()
	s := tsfNew(t)
	ctxTreeSeed(t, s.s, 7, 100, 3, nil, nil)
	s.op.Pair.ContextConsulted = &CanonicalContextWindowV1{Generation: 7, FirstHeight: 100, Count: 3}
	return s
}

func TestCtxTreePrimitiveFixtureV1(t *testing.T) {
	t.Run("A8b-crossed-clean", func(t *testing.T) {
		s := ctxTreeScene(t)
		r := s.crossed(t)
		r.tuple(t, 2, 3, -1)
		tsConsumed(t, s.s, s.o, 2, r.err)
	})
	t.Run("R8b-crossed-drift", func(t *testing.T) {
		var calls [2]uint32
		for i, h := range []uint64{100, 102} {
			s := ctxTreeScene(t)
			var r tsResult
			evidence := ctxTreeFault(t, s.s, 3, 3, ctxTreeHeaderKey(t, 7, h), func() {
				r = s.run(t)
				calls[i] = fixtureLargeNativeCalls()
			})
			r.tuple(t, 3, 3, -1)
			if evidence.commits != 1 || evidence.drift != 1 {
				t.Fatalf("R8b evidence%+v", evidence)
			}
			tsConsumed(t, s.s, s.o, 3, r.err)
		}
		if calls[0] != calls[1] || calls[0] == 0 {
			t.Fatalf("R8b native calls offset0 %d, last %d", calls[0], calls[1])
		}
	})
	for _, crossed := range []bool{false, true} {
		t.Run(fmt.Sprintf("H1-mutated-after-first-source-crossed%v", crossed), func(t *testing.T) {
			s := ctxTreeScene(t)
			window := s.op.Pair.ContextConsulted
			s.p[1].before = func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error {
				window.Generation = 99
				return nil
			}
			var r tsResult
			if crossed {
				r = s.crossed(t)
				r.tuple(t, 2, 3, -1)
				tsConsumed(t, s.s, s.o, 2, r.err)
			} else {
				r = s.run(t)
				r.tuple(t, 2, 3, -1)
				mustEnvironment(t, r.err)
			}
			if window.Generation != 99 || s.p[1].calls == [3]int{} {
				t.Fatal("H1 mutation did not run")
			}
		})
	}
}

func TestCtxTreeClosedBeforeHoldV1(t *testing.T) {
	for _, count := range []uint32{1, 10081} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			s, o, _ := ctxTreePairScene(t)
			var closed *OperationAccount
			mustEnvironment(t, o.WithOperation(TreeOperation, func(a *OperationAccount) error { closed = a; return nil }))
			window := &CanonicalContextWindowV1{Generation: 8, FirstHeight: 100, Count: count}
			var r tsResult
			calls := 0
			evidence := ctxTreeFault(t, s, 28, 2, ctxTreeIndexKey(8, 100), func() {
				s.operations.Lock()
				defer s.operations.Unlock()
				var unwind treeUnwindV1
				r.truth, r.stage, r.index, unwind, r.err = s.treeEntryLockedV1(closed, func(*Reader) (TreeOperationV1, error) {
					calls++
					return ctxTreeOp(80, window), nil
				})
				if unwind.kind != 0 {
					t.Fatal("closed-before-hold unwind")
				}
			})
			if count > 10080 {
				tsRefusal(t, r, true)
			} else {
				r.tuple(t, 1, 1, -1)
				if any(r.err) != any(errOperationReservationInput) {
					t.Fatalf("closed before hold = %v", r.err)
				}
			}
			if calls != 1 || evidence.gets != 0 || reservationLive(o) != 0 {
				t.Fatalf("closed before hold calls%d evidence%+v", calls, evidence)
			}
			ctxTreeOpen(t, s)
		})
	}
}

func TestCtxTreeSlotOverlapV1(t *testing.T) {
	for _, identical := range []bool{true, false} {
		t.Run(fmt.Sprintf("identical%v", identical), func(t *testing.T) {
			s, _, o := tsNew(t)
			calls, proofs := 0, 0
			op := tsSlotShape(t, &calls, &proofs, nil, 0)
			x := op.HeaderSlot.Hash
			forward := canonicalForwardLiteral(7, 100, x, [40]byte{39: 0x41})
			owner := canonicalOwnerPairOf(forward)
			forward.DBI, owner.DBI = TreeSchemaV1DBIs()[2], TreeSchemaV1DBIs()[7]
			seed := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{forward, owner}}}
			if identical {
				header := Mutation{DBI: TreeSchemaV1DBIs()[3], Key: x[:], AfterKind: 2, Literal: bytes.Clone(op.HeaderSlot.Header[:])}
				seed.Pair.Mutations = []Mutation{forward, header, owner}
			} else {
				stored := bytes.Repeat([]byte{0x5a}, 148)
				treeNativeSeed(t, s, 3, x[:], stored)
			}
			r := tsRun(t, s, o, TreeOperation, seed)
			r.tuple(t, 2, 3, -1)
			mustEnvironment(t, r.err)
			op.Pair.ContextConsulted = &CanonicalContextWindowV1{Generation: 7, FirstHeight: 100, Count: 1}
			evidence := ctxTreeFault(t, s, 28, 3, x[:], func() { r = tsRun(t, s, o, TreeOperation, op) })
			tsRefusal(t, r, false)
			if proofs != 0 || evidence.gets != 0 {
				t.Fatalf("R4b proofs%d evidence%+v", proofs, evidence)
			}
			ctxTreeOpen(t, s)
		})
	}
}

// psfScene is a format-3 Store with generation 9 and 8 node families, both root bindings and one stored body.
type psfScene struct {
	s    *Store
	path string
	o    *OperationReservationOwner
	body [32]byte
}

// key is an independent copy: the scene struct holds Go pointers and cannot back a cgo argument.
func (sc *psfScene) key() []byte { return bytes.Clone(sc.body[:]) }

var psfBodyValue = bytes.Repeat([]byte{0xb7}, 1000)

func psfNew(t *testing.T) *psfScene {
	t.Helper()
	s, path, o := tsNew(t)
	for _, g := range []uint64{8, 9} {
		for _, row := range obsoleteTreeFamily(g) {
			treeNativeSeed(t, s, 8, row.key, row.value)
		}
		treeNativeSeed(t, s, 0, tsRootKey(g), []byte{0xee, byte(g)})
	}
	scene := &psfScene{s: s, path: path, o: o, body: [32]byte{0xb0, 1}}
	treeNativeSeed(t, s, 4, scene.key(), psfBodyValue)
	return scene
}

// psfAuthority is the complete TreeAuthority literal target committed with the raw deletes.
func psfAuthority(t *testing.T) Mutation {
	t.Helper()
	a := TreeAuthorityV1{Authority: StorageAuthorityV1{Version: 1, ActiveProfile: 1, ActiveGenerationID: 1, NextGenerationID: 6, Phase: 1, Lifecycle: 1}, LagGenerationID: 2}
	authority, err := a.Encode()
	mustEnvironment(t, err)
	return Mutation{DBI: TreeSchemaV1DBIs()[0], Key: []byte{2}, BeforePresent: true, AfterKind: 2, Literal: authority}
}

// psfBuild deletes generation 9's nodes and root binding under their witnesses with the body selector.
func (sc *psfScene) build(t *testing.T) func(*Reader) TreeOperationV1 {
	return func(r *Reader) TreeOperationV1 {
		nodes, err := r.ObsoleteGenerationPageV1(9, ObsoleteNodeV1, nil, 1440)
		mustEnvironment(t, err)
		root, err := r.ObsoleteGenerationPageV1(9, ObsoleteRootV1, nil, 1)
		mustEnvironment(t, err)
		if len(nodes.Rows) != 3 || len(root.Rows) != 1 {
			t.Fatalf("scene pages nodes%d root%d", len(nodes.Rows), len(root.Rows))
		}
		return TreeOperationV1{Pair: TreePairV1{
			Mutations:         []Mutation{psfAuthority(t)},
			ObsoleteDeletes:   append(append([]ObsoleteRowV1(nil), root.Rows...), nodes.Rows...),
			ObsoleteConsulted: []ObsoletePageWitnessV1{nodes.Witness, root.Witness},
			LargeConsulted:    []LargeImageSelectorV1{{Kind: LargeImageBlockBodyV1, Hash: sc.body}},
		}}
	}
}

func (sc *psfScene) run(t *testing.T, o *OperationReservationOwner) tsResult {
	t.Helper()
	return psRun(t, sc.s, o, LaneOperation, sc.build(t))
}

// image asserts the generation-9 raw rows (absent when deleted), the untouched generation-8 rows and the body.
func (sc *psfScene) image(t *testing.T, s *Store, deleted bool) {
	t.Helper()
	for _, row := range obsoleteTreeFamily(9) {
		want := row.value
		if deleted {
			want = nil
		}
		psfRaw(t, s, 8, row.key, want)
	}
	for _, row := range obsoleteTreeFamily(8) {
		psfRaw(t, s, 8, row.key, row.value)
	}
	root9 := []byte{0xee, 9}
	if deleted {
		root9 = nil
	}
	psfRaw(t, s, 0, tsRootKey(9), root9)
	psfRaw(t, s, 0, tsRootKey(8), []byte{0xee, 8})
	psfRaw(t, s, 4, sc.key(), psfBodyValue)
}

func psfRaw(t *testing.T, s *Store, rank uint8, key, want []byte) {
	t.Helper()
	equal, err := FixtureRawRowEqual(s, rank, key, want)
	if err != nil || !equal {
		t.Fatalf("scope persisted image differs: rank%d %x want %x: %v", rank, key, want, err)
	}
}

// psfF is F for the scene: M=1, D=4, W=2, P=0, L=1 with K and U from the literal row widths.
func psfF(t *testing.T) uint64 {
	auth := psfAuthority(t)
	nodes := obsoleteTreeFamily(9)
	k := uint64(len(auth.Key)+len(auth.Literal)) + 9
	for _, row := range nodes {
		k += uint64(len(row.key))
	}
	u := uint64(8+len(nodes[2].key)) + 9 // node prefix + last, root point prefix
	return psF(1, 0, 4, 2, 0, 1, k, u)
}

func psfWindow(t *testing.T, s *Store) uint64 {
	var maxKey uint64
	mustEnvironment(t, s.View(func(r *Reader) error { maxKey = r.maxKey; return nil }))
	return 4 * (maxKey + 1)
}

// psfDelete deletes generation g's nodes and root under their witnesses with the given mutations and selectors.
func psfDelete(t *testing.T, g uint64, mutations []Mutation, selectors []LargeImageSelectorV1) func(*Reader) TreeOperationV1 {
	return func(r *Reader) TreeOperationV1 {
		nodes, err := r.ObsoleteGenerationPageV1(g, ObsoleteNodeV1, nil, 1440)
		mustEnvironment(t, err)
		root, err := r.ObsoleteGenerationPageV1(g, ObsoleteRootV1, nil, 1)
		mustEnvironment(t, err)
		return TreeOperationV1{Pair: TreePairV1{
			Mutations:         mutations,
			ObsoleteDeletes:   append(append([]ObsoleteRowV1(nil), root.Rows...), nodes.Rows...),
			ObsoleteConsulted: []ObsoletePageWitnessV1{nodes.Witness, root.Witness},
			LargeConsulted:    selectors,
		}}
	}
}

// N1: classes 1 (UTXO, malformed disposable value), 2 (index) and 4 (derived owner) are deleted by the
// typed raw path from their own literal rows next to the untouched tree scene; no value is decoded.
func psfClassDeletes(t *testing.T) {
	sc := psfNew(t)
	utxo := append(obsoleteGenerationLiteral(9), 0x44)
	treeNativeSeed(t, sc.s, 1, utxo, []byte{0xde})
	hash := [32]byte{0x41}
	forward, derived := canonicalForwardKeyLiteral(9, 1), canonicalOwnerKeyLiteral(9, hash)
	treeNativeSeed(t, sc.s, 2, forward, canonicalForwardValueLiteral(hash, [40]byte{}))
	treeNativeSeed(t, sc.s, 7, derived, binary.BigEndian.AppendUint64(nil, 1))
	r := psRun(t, sc.s, sc.o, LaneOperation, func(reader *Reader) TreeOperationV1 {
		var op TreeOperationV1
		for _, class := range []ObsoleteClassV1{ObsoleteUTXOV1, ObsoleteIndexV1, ObsoleteDerivedV1} {
			page, err := reader.ObsoleteGenerationPageV1(9, class, nil, 1)
			mustEnvironment(t, err)
			if len(page.Rows) != 1 {
				t.Fatalf("class %d page rows%d, want1", class, len(page.Rows))
			}
			op.Pair.ObsoleteDeletes = append(op.Pair.ObsoleteDeletes, page.Rows...)
			op.Pair.ObsoleteConsulted = append(op.Pair.ObsoleteConsulted, page.Witness)
		}
		return op
	})
	r.tuple(t, 2, 3, -1)
	if r.err != nil {
		t.Fatalf("scope persisted image differs: classes 1, 2, 4 %v", r.err)
	}
	reopened := tsReopen(t, sc.s, sc.path)
	psfRaw(t, reopened, 1, utxo, nil)
	psfRaw(t, reopened, 2, forward, nil)
	psfRaw(t, reopened, 7, derived, nil)
	sc.image(t, reopened, false)
}

// N3: node page bounds 1 and 7 (default scene pages use 1440) delete exactly the rows their page returned.
func psfPageBounds(t *testing.T) {
	family := obsoleteTreeFamily(9)
	for _, bound := range []uint32{1, 7} {
		sc := psfNew(t)
		var deleted [][]byte
		r := psRun(t, sc.s, sc.o, LaneOperation, func(reader *Reader) TreeOperationV1 {
			nodes, err := reader.ObsoleteGenerationPageV1(9, ObsoleteNodeV1, nil, bound)
			mustEnvironment(t, err)
			for _, row := range nodes.Rows {
				deleted = append(deleted, row.Key())
			}
			return TreeOperationV1{Pair: TreePairV1{ObsoleteDeletes: nodes.Rows, ObsoleteConsulted: []ObsoletePageWitnessV1{nodes.Witness}}}
		})
		r.tuple(t, 2, 3, -1)
		mustEnvironment(t, r.err)
		if want := min(int(bound), len(family)); len(deleted) != want {
			t.Fatalf("page bound %d rows%d, want%d", bound, len(deleted), want)
		}
		for i, row := range family {
			want := row.value
			if i < len(deleted) {
				if !bytes.Equal(deleted[i], row.key) {
					t.Fatalf("page bound %d row%d key %x, want %x", bound, i, deleted[i], row.key)
				}
				want = nil
			}
			psfRaw(t, sc.s, 8, row.key, want)
		}
		psfRaw(t, sc.s, 0, tsRootKey(9), []byte{0xee, 9})
	}
}

// psfUndo seeds generation 9's proven format-3 own index projection (148-byte header) and a three-member undo family under its hash.
func psfUndo(t *testing.T, s *Store) ([32]byte, [][]byte) {
	header := make([]byte, obsoleteHeaderWidth(3))
	header[0], header[len(header)-1] = 3, 7
	hash := sha3.Sum256(header)
	entry := append(append(bytes.Clone(hash[:]), make([]byte, 32)...), make([]byte, 40)...)
	entry[103] = 1
	treeNativeSeed(t, s, 2, binary.BigEndian.AppendUint64(obsoleteGenerationLiteral(9), 1), entry)
	treeNativeSeed(t, s, 3, hash[:], header)
	undo := [][]byte{bytes.Clone(hash[:]), append(bytes.Clone(hash[:]), 0), append(bytes.Clone(hash[:]), 2, 0xff)}
	for i, k := range undo {
		treeNativeSeed(t, s, 5, k, []byte{byte(i)})
	}
	return hash, undo
}

// N2: present and empty undo families plus an absent body are valid physical domains.
func psfLargeDomains(t *testing.T) {
	sc := psfNew(t)
	hash, undo := psfUndo(t, sc.s)
	empty := hash
	empty[31] ^= 1
	families := []LargeImageSelectorV1{{Kind: LargeImageUndoFamilyV1, Hash: hash}, {Kind: LargeImageUndoFamilyV1, Hash: empty}}
	if bytes.Compare(empty[:], hash[:]) < 0 {
		families[0], families[1] = families[1], families[0]
	}
	selectors := append([]LargeImageSelectorV1{
		{Kind: LargeImageBlockBodyV1, Hash: sc.body},
		{Kind: LargeImageBlockBodyV1, Hash: [32]byte{0xb0, 2}},
	}, families...)
	r := psRun(t, sc.s, sc.o, LaneOperation, psfDelete(t, 9, nil, selectors))
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	reopened := tsReopen(t, sc.s, sc.path)
	sc.image(t, reopened, true)
	for i, k := range undo {
		psfRaw(t, reopened, 5, k, []byte{byte(i)})
	}
	psfRaw(t, reopened, 4, []byte{0xb0, 2}, nil)
	psfRaw(t, reopened, 5, empty[:], nil)
}

// N2: a raw undo target inside the selected family disappears once; every nontarget member stays equal.
func psfTargetInFamily(t *testing.T) {
	sc := psfNew(t)
	hash, undo := psfUndo(t, sc.s)
	r := psRun(t, sc.s, sc.o, LaneOperation, func(reader *Reader) TreeOperationV1 {
		index, err := reader.ObsoleteGenerationPageV1(9, 2, nil, 1440)
		mustEnvironment(t, err)
		page, err := reader.ObsoleteUndoPageV1(index.Rows[0], nil, 1)
		mustEnvironment(t, err)
		if len(page.Rows) != 1 {
			t.Fatalf("scene undo page rows %d projection %d stop %d", len(page.Rows), page.Projection, page.Stop)
		}
		return TreeOperationV1{Pair: TreePairV1{
			ObsoleteDeletes:   page.Rows,
			ObsoleteConsulted: []ObsoletePageWitnessV1{page.Witness},
			LargeConsulted:    []LargeImageSelectorV1{{Kind: LargeImageUndoFamilyV1, Hash: hash}},
		}}
	})
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	reopened := tsReopen(t, sc.s, sc.path)
	psfRaw(t, reopened, 5, undo[0], nil)
	psfRaw(t, reopened, 5, undo[1], []byte{1})
	psfRaw(t, reopened, 5, undo[2], []byte{2})
	sc.image(t, reopened, false)
}

// N7: an identical ordinary put under a witnessed scope satisfies both predicates after a possibly
// crossed commit; OLD is selected first.
func psfBothIdentical(t *testing.T) {
	sc := psfNew(t)
	r := sc.run(t, sc.o)
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	same := func(reader *Reader) TreeOperationV1 {
		nodes, err := reader.ObsoleteGenerationPageV1(8, ObsoleteNodeV1, nil, 1440)
		mustEnvironment(t, err)
		return TreeOperationV1{Pair: TreePairV1{
			Mutations:         []Mutation{psfAuthority(t)},
			ObsoleteConsulted: []ObsoletePageWitnessV1{nodes.Witness},
			LargeConsulted:    []LargeImageSelectorV1{{Kind: LargeImageBlockBodyV1, Hash: sc.body}},
		}}
	}
	evidence := ctxTreeFault(t, sc.s, 12, 0, []byte{9}, func() { r = psRun(t, sc.s, sc.o, LaneOperation, same) })
	if evidence.commits != 1 || evidence.drift != 0 || r.truth != 1 || r.stage != 3 {
		t.Fatalf("scope strict truth differs: %+v (%d,%d) %v", evidence, r.truth, r.stage, r.err)
	}
	r.tuple(t, 1, 3, -1)
	tsConsumed(t, sc.s, sc.o, 1, r.err)
	reopened := tsReopen(t, sc.s, sc.path)
	sc.image(t, reopened, true)
	tsRead(t, reopened, TreeSchemaV1DBIs()[0], []byte{2}, psfAuthority(t).Literal)
}

// N9: raw authority does not consult generation roles: the committed active generation's physical rows
// are deleted exactly as tokens name them; eligibility stays the caller's responsibility.
func psfDormant(t *testing.T) {
	sc := psfNew(t)
	for _, row := range obsoleteTreeFamily(1) {
		treeNativeSeed(t, sc.s, 8, row.key, row.value)
	}
	treeNativeSeed(t, sc.s, 0, tsRootKey(1), []byte{0xee, 1})
	r := sc.run(t, sc.o)
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	r = psRun(t, sc.s, sc.o, LaneOperation, psfDelete(t, 1, nil, nil))
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	reopened := tsReopen(t, sc.s, sc.path)
	for _, row := range obsoleteTreeFamily(1) {
		psfRaw(t, reopened, 8, row.key, nil)
	}
	psfRaw(t, reopened, 0, tsRootKey(1), nil)
	sc.image(t, reopened, true)
	tsRead(t, reopened, TreeSchemaV1DBIs()[0], []byte{2}, psfAuthority(t).Literal)
}

func TestTreeStreamPhysicalScopeNativeV1(t *testing.T) {
	t.Run("N2-large-domains", psfLargeDomains)
	t.Run("N2-target-in-family", psfTargetInFamily)
	t.Run("N7-both-identical-OLD-first", psfBothIdentical)
	t.Run("N9-dormant", psfDormant)
	t.Run("N1-classes-1-2-4", psfClassDeletes)
	t.Run("N3-page-bounds", psfPageBounds)
	t.Run("N1-commit", func(t *testing.T) {
		sc := psfNew(t)
		r := sc.run(t, sc.o)
		r.tuple(t, 2, 3, -1)
		if r.err != nil {
			t.Fatalf("rank8 typed page did not commit: %v", r.err)
		}
		sc.image(t, sc.s, true)
		psfRaw(t, sc.s, 0, []byte{2}, psfAuthority(t).Literal)
		tsFollowing(t, sc.s, sc.o)
		sc.image(t, tsReopen(t, sc.s, sc.path), true)
	})
	t.Run("R6-write-snapshot", func(t *testing.T) {
		sc := psfNew(t)
		var r tsResult
		evidence := ctxTreeFault(t, sc.s, 14, 4, sc.key(), func() { r = sc.run(t, sc.o) })
		// The drifted body is a nontarget residual: only preflight (stage 1) may refuse it.
		if evidence.drift != 1 || evidence.commits != 0 || r.stage != 1 {
			t.Fatalf("scope preflight mismatch committed: %+v stage%d %v", evidence, r.stage, r.err)
		}
		r.tuple(t, 1, 1, -1)
		treeNativeError(t, r.err, "update", "StateMismatch", -30779, "OLD/write snapshot mismatch", nil)
		tsConsumed(t, sc.s, sc.o, 1, r.err)
		// The fixture's drift of the body is itself durable; the raw targets must survive.
		reopened := tsReopen(t, sc.s, sc.path)
		for _, row := range obsoleteTreeFamily(9) {
			psfRaw(t, reopened, 8, row.key, row.value)
		}
		psfRaw(t, reopened, 0, tsRootKey(9), []byte{0xee, 9})
	})
	t.Run("R7-final", func(t *testing.T) {
		sc := psfNew(t)
		var r tsResult
		evidence := ctxTreeFault(t, sc.s, 13, 4, sc.key(), func() { r = sc.run(t, sc.o) })
		if evidence.drift != 1 || evidence.commits != 0 || r.stage != 2 {
			t.Fatalf("scope final mismatch committed: %+v stage%d %v", evidence, r.stage, r.err)
		}
		r.tuple(t, 1, 2, -1)
		treeNativeError(t, r.err, "update", "StateMismatch", -30779, "final update image mismatch", nil)
		tsConsumed(t, sc.s, sc.o, 1, r.err)
		sc.image(t, tsReopen(t, sc.s, sc.path), false)
	})
	t.Run("N7-crossed-clean", func(t *testing.T) {
		sc := psfNew(t)
		var r tsResult
		evidence := ctxTreeFault(t, sc.s, 12, 0, []byte{9}, func() { r = sc.run(t, sc.o) })
		if evidence.commits != 1 || evidence.drift != 0 || r.truth != 2 || r.stage != 3 {
			t.Fatalf("scope strict truth differs: %+v (%d,%d) %v", evidence, r.truth, r.stage, r.err)
		}
		r.tuple(t, 2, 3, -1)
		tsConsumed(t, sc.s, sc.o, 2, r.err)
		sc.image(t, tsReopen(t, sc.s, sc.path), true)
	})
	t.Run("N7-crossed-complete-OLD", func(t *testing.T) {
		// Mode 7 breaks the write transaction before a commit reported as possibly crossed: the strict
		// readback finds the complete OLD image (targets and every residual unchanged), so OLD wins.
		sc := psfNew(t)
		var r tsResult
		evidence := ctxTreeFault(t, sc.s, 7, 0, []byte{9}, func() { r = sc.run(t, sc.o) })
		if evidence.commits != 1 || evidence.drift != 0 || r.truth != 1 || r.stage != 3 {
			t.Fatalf("scope strict truth differs: %+v (%d,%d) %v", evidence, r.truth, r.stage, r.err)
		}
		r.tuple(t, 1, 3, -1)
		if _, ok := r.err.(*CommitError); !ok {
			t.Fatalf("scope strict truth differs: cause %T %v", r.err, r.err)
		}
		tsConsumed(t, sc.s, sc.o, 1, r.err)
		sc.image(t, tsReopen(t, sc.s, sc.path), false)
	})
	// After a possibly crossed commit one durable change defeats both predicates: an extra member inside
	// the witnessed node domain, the missing nontarget body, or the deleted raw root point re-appearing.
	var extra [36]byte
	for i := range extra {
		extra[i] = 0x11
	}
	for _, c := range []struct {
		name string
		mode uint32
		rank uint8
		key  func(*psfScene) []byte
	}{
		{"extra-member", 3, 8, func(*psfScene) []byte { return obsoleteTreeNodeLiteral(9, extra, 0) }},
		{"missing-member", 4, 4, func(sc *psfScene) []byte { return sc.key() }},
		{"changed-root-point", 3, 0, func(*psfScene) []byte { return tsRootKey(9) }},
	} {
		t.Run("N7-neither/"+c.name, func(t *testing.T) {
			sc := psfNew(t)
			var r tsResult
			evidence := ctxTreeFault(t, sc.s, c.mode, c.rank, c.key(sc), func() { r = sc.run(t, sc.o) })
			if evidence.commits != 1 || evidence.drift != 1 || r.truth != 3 || r.stage != 3 {
				t.Fatalf("scope strict truth differs: %+v (%d,%d) %v", evidence, r.truth, r.stage, r.err)
			}
			r.tuple(t, 3, 3, -1)
			if _, ok := r.err.(*CommitError); !ok {
				t.Fatalf("scope strict truth differs: cause %T %v", r.err, r.err)
			}
			tsConsumed(t, sc.s, sc.o, 3, r.err)
		})
	}
	t.Run("N7-crossed-drift", func(t *testing.T) {
		sc := psfNew(t)
		var r tsResult
		evidence := ctxTreeFault(t, sc.s, 3, 4, sc.key(), func() { r = sc.run(t, sc.o) })
		if evidence.commits != 1 || evidence.drift != 1 || r.truth != 3 || r.stage != 3 {
			t.Fatalf("scope strict truth differs: %+v (%d,%d) %v", evidence, r.truth, r.stage, r.err)
		}
		r.tuple(t, 3, 3, -1)
		tsConsumed(t, sc.s, sc.o, 3, r.err)
	})
	t.Run("H1-native-read", func(t *testing.T) {
		sc := psfNew(t)
		var r tsResult
		evidence := ctxTreeFault(t, sc.s, 28, 4, sc.key(), func() { r = sc.run(t, sc.o) })
		var engine *EngineError
		if evidence.gets == 0 || !errors.As(r.err, &engine) || engine.Class != EngineIO || r.stage != 1 {
			t.Fatalf("later scope error lost: %v %+v", r.err, evidence)
		}
		r.tuple(t, 1, 1, -1)
		tsConsumed(t, sc.s, sc.o, 1, r.err)
	})
	t.Run("H1-mismatch-then-read-error", func(t *testing.T) {
		// Mode 29 drifts the body at commit, then fails every later readback prefix read of another DBI:
		// the large body mismatch comes first and the raw domain traversal must still reach its EIO.
		sc := psfNew(t)
		var r tsResult
		evidence := ctxTreeFault(t, sc.s, 29, 4, sc.key(), func() { r = sc.run(t, sc.o) })
		ce, ok := r.err.(*CommitError)
		if !ok || evidence.drift != 1 || evidence.commits != 1 || evidence.gets == 0 || r.truth != 3 {
			t.Fatalf("later scope error lost: %v %+v", r.err, evidence)
		}
		var engine *EngineError
		if !errors.As(ce.ReadbackCause, &engine) || engine.Class != EngineIO {
			t.Fatalf("later scope error lost: %v", ce.ReadbackCause)
		}
		r.tuple(t, 3, 3, -1)
		tsConsumed(t, sc.s, sc.o, 3, r.err)
	})
	t.Run("H1-domain-mismatch-then-read-error", psfDomainMismatchThenError)
	t.Run("H1-point-mismatch-then-capacity", psfPointMismatchThenCapacity)
	t.Run("M14-retained", psfRetained)
	t.Run("N4-selector-alias", func(t *testing.T) {
		// At write site 3 the caller rewrites its own LargeConsulted value to an absent body; the body then
		// drifts after the first write. The owned selector copy still compares the drifted body at final.
		sc := psfNew(t)
		build := sc.build(t)
		var selectors []LargeImageSelectorV1
		op := func(r *Reader) TreeOperationV1 {
			out := build(r)
			selectors = out.Pair.LargeConsulted
			return out
		}
		var r tsResult
		var evidence fixtureLargeEvidence
		observed, err := FixturePairReadObservation(sc.s, func(site uint32) {
			if site == 3 && selectors != nil {
				selectors[0].Hash = [32]byte{0xb0, 2}
				selectors = nil
			}
		}, func() {
			evidence = ctxTreeFault(t, sc.s, 13, 4, sc.key(), func() { r = psRun(t, sc.s, sc.o, LaneOperation, op) })
		})
		mustEnvironment(t, err)
		if observed.Writes == 0 || evidence.drift != 1 || evidence.commits != 0 || r.stage != 2 {
			t.Fatalf("owned scope changed with input: %+v %+v stage%d %v", observed, evidence, r.stage, r.err)
		}
		r.tuple(t, 1, 2, -1)
		treeNativeError(t, r.err, "update", "StateMismatch", -30779, "final update image mismatch", nil)
		tsConsumed(t, sc.s, sc.o, 1, r.err)
		sc.image(t, tsReopen(t, sc.s, sc.path), false)
	})
	t.Run("M15-same-prefix-sibling", func(t *testing.T) {
		// Only the generation-9 one-leaf is a target; its same-generation-prefix sibling, ordered before it,
		// drifts at the write snapshot. Generation 8 holds byte-equal values under another prefix.
		sc := psfNew(t)
		build := sc.build(t)
		target, sibling := obsoleteTreeFamily(9)[1], obsoleteTreeFamily(9)[0]
		one := func(r *Reader) TreeOperationV1 {
			op := build(r)
			op.Pair.ObsoleteDeletes = slices.DeleteFunc(op.Pair.ObsoleteDeletes, func(row ObsoleteRowV1) bool { return !bytes.Equal(row.Key(), target.key) })
			if len(op.Pair.ObsoleteDeletes) != 1 {
				t.Fatal("scene target row missing")
			}
			return op
		}
		var r tsResult
		evidence := ctxTreeFault(t, sc.s, 14, 8, sibling.key, func() { r = psRun(t, sc.s, sc.o, LaneOperation, one) })
		if evidence.drift != 1 || evidence.commits != 0 || r.stage != 1 {
			t.Fatalf("independent residual changed: %+v stage%d %v", evidence, r.stage, r.err)
		}
		r.tuple(t, 1, 1, -1)
		treeNativeError(t, r.err, "update", "StateMismatch", -30779, "OLD/write snapshot mismatch", nil)
		tsConsumed(t, sc.s, sc.o, 1, r.err)
		reopened := tsReopen(t, sc.s, sc.path)
		psfRaw(t, reopened, 8, target.key, target.value)
		for _, row := range obsoleteTreeFamily(8) {
			psfRaw(t, reopened, 8, row.key, row.value)
		}
	})
	t.Run("N8-larger-candidate-preflight", func(t *testing.T) {
		// The first write-snapshot get reports the body one byte longer than ORIGINAL OLD. The length
		// mismatch is inequality, not a funded payload comparison (which would refuse with capacity).
		// Fixture mode 31 fires at preflight, the first write_txn get; it does not reach final/readback.
		sc := psfNew(t)
		var r tsResult
		evidence := ctxTreeFault(t, sc.s, 31, 4, sc.key(), func() { r = sc.run(t, sc.o) })
		if evidence.gets != 1 || evidence.commits != 0 || r.stage != 1 {
			t.Fatalf("scope sealed window grew: %+v stage%d %v", evidence, r.stage, r.err)
		}
		r.tuple(t, 1, 1, -1)
		treeNativeError(t, r.err, "update", "StateMismatch", -30779, "OLD/write snapshot mismatch", nil)
		tsConsumed(t, sc.s, sc.o, 1, r.err)
		sc.image(t, tsReopen(t, sc.s, sc.path), false)
	})
	t.Run("M15-equal-digest-other-generation", func(t *testing.T) {
		// Only the generation-9 one-leaf is a target; the generation-8 node domain is also compared and its
		// one-leaf holds a byte-equal value under another generation key. That row drifts at the write snapshot.
		sc := psfNew(t)
		build := sc.build(t)
		target, other := obsoleteTreeFamily(9)[1], obsoleteTreeFamily(8)[1]
		one := func(r *Reader) TreeOperationV1 {
			op := build(r)
			op.Pair.ObsoleteDeletes = slices.DeleteFunc(op.Pair.ObsoleteDeletes, func(row ObsoleteRowV1) bool { return !bytes.Equal(row.Key(), target.key) })
			nodes8, err := r.ObsoleteGenerationPageV1(8, ObsoleteNodeV1, nil, 1440)
			mustEnvironment(t, err)
			if len(op.Pair.ObsoleteDeletes) != 1 || len(nodes8.Rows) != 3 || !bytes.Equal(target.value, other.value) {
				t.Fatal("scene equal-digest rows missing")
			}
			op.Pair.ObsoleteConsulted = append(op.Pair.ObsoleteConsulted, nodes8.Witness)
			return op
		}
		var r tsResult
		evidence := ctxTreeFault(t, sc.s, 14, 8, other.key, func() { r = psRun(t, sc.s, sc.o, LaneOperation, one) })
		if evidence.drift != 1 || evidence.commits != 0 || r.stage != 1 {
			t.Fatalf("independent residual changed: %+v stage%d %v", evidence, r.stage, r.err)
		}
		r.tuple(t, 1, 1, -1)
		treeNativeError(t, r.err, "update", "StateMismatch", -30779, "OLD/write snapshot mismatch", nil)
		tsConsumed(t, sc.s, sc.o, 1, r.err)
		reopened := tsReopen(t, sc.s, sc.path)
		psfRaw(t, reopened, 8, target.key, target.value)
	})
	t.Run("N8-operand-window", func(t *testing.T) {
		sc := psfNew(t)
		f, window := psfF(t), psfWindow(t, sc.s)
		var r tsResult
		evidence := ctxTreeFault(t, sc.s, 12, 0, []byte{9}, func() { r = sc.run(t, reservationFilled(t, psPageGrant+f-1)) })
		if any(r.err) != any(errOperationReservationCapacity) || sc.s.state != storeOPEN {
			t.Fatalf("scope metadata high-water differs: %v %s", r.err, sc.s.state)
		}
		// The prewrite refusal aborts ORIGINAL OLD exactly once and never reaches a commit.
		if evidence.aborts != 1 || evidence.commits != 0 {
			t.Fatalf("scope next operation differs: OLD abort %+v", evidence)
		}
		sc.image(t, sc.s, false)
		// One byte less than F plus S and both body operands refuses the funded two-span comparison.
		r = sc.run(t, reservationFilled(t, psPageGrant+f+window+2*uint64(len(psfBodyValue))-1))
		if any(r.err) != any(errOperationReservationCapacity) {
			t.Fatalf("scope operand window not funded: %v", r.err)
		}
		r.tuple(t, 1, 1, -1)
		tsConsumed(t, sc.s, sc.o, 1, r.err)
		sc2 := psfNew(t)
		r = sc2.run(t, reservationFilled(t, psPageGrant+f+window+2*uint64(len(psfBodyValue))))
		// Omitting the preflight budget forwarding or the final/readback seal while the captured context
		// stays typed turns this funded commit into the typed nil-budget capacity refusal.
		if r.err != nil || r.truth != 2 {
			t.Fatalf("scope missing budget admitted: %v truth%d", r.err, r.truth)
		}
		r.tuple(t, 2, 3, -1)
		mustEnvironment(t, r.err)
		sc2.image(t, sc2.s, true)
	})
	t.Run("N8-sealed-helper", func(t *testing.T) {
		left, right := bytes.Repeat([]byte{1}, 64), bytes.Repeat([]byte{1}, 64)
		a := updateImage{present: true, bytes: unsafe.Pointer(&left[0]), length: 64}
		b := updateImage{present: true, bytes: unsafe.Pointer(&right[0]), length: 64}
		scope := largeImageScope{databaseID: [32]byte{7}, maxKey: 1, pairLimit: 8 + 127}
		_, err := scope.rowsEqualV1(largeNativeRow{image: a}, largeNativeRow{image: b})
		if any(err) != any(errOperationReservationCapacity) {
			t.Fatalf("scope sealed window grew: %v", err)
		}
		scope.pairLimit = 8 + 128
		equal, err := scope.rowsEqualV1(largeNativeRow{image: a}, largeNativeRow{image: b})
		if err != nil || !equal {
			t.Fatalf("sealed equal-length comparison: %v %v", equal, err)
		}
		runtime.KeepAlive(left)
		runtime.KeepAlive(right)
		// Typed nil budget with a zero seal refuses before acquisition; legacy zero databaseID does not fund.
		typed := largeImageScope{databaseID: [32]byte{7}}
		if err := typed.fundV1(); any(err) != any(errOperationReservationCapacity) {
			t.Fatalf("scope missing budget admitted: %v", err)
		}
		if err := (&largeImageScope{}).fundV1(); err != nil {
			t.Fatal("legacy scope funded", err)
		}
	})
}

// H1/M16: mode 29 adds an extra member to the rank-5 undo domain at commit, then fails every later
// readback prefix read of another DBI: the raw-domain mismatch comes first and the rank-8 node domain
// traversal must still reach its EIO.
func psfDomainMismatchThenError(t *testing.T) {
	sc := psfNew(t)
	hash, _ := psfUndo(t, sc.s)
	var r tsResult
	evidence := ctxTreeFault(t, sc.s, 29, 5, append(bytes.Clone(hash[:]), 1), func() { r = psRun(t, sc.s, sc.o, LaneOperation, psfUndoScopeOp(t)) })
	ce, ok := r.err.(*CommitError)
	if !ok || evidence.drift != 1 || evidence.commits != 1 || evidence.gets == 0 || r.truth != 3 {
		t.Fatalf("later scope error lost: %v %+v", r.err, evidence)
	}
	var engine *EngineError
	if !errors.As(ce.ReadbackCause, &engine) || engine.Class != EngineIO {
		t.Fatalf("later scope error lost: %v", ce.ReadbackCause)
	}
	r.tuple(t, 3, 3, -1)
	tsConsumed(t, sc.s, sc.o, 3, r.err)
}

// psfUndoScopeOp deletes generation 9's nodes under their witness with the authority target and also
// consults the undo witness, whose rank-2 index and rank-3 header points follow the raw domains.
func psfUndoScopeOp(t *testing.T) func(*Reader) TreeOperationV1 {
	return func(reader *Reader) TreeOperationV1 {
		nodes, err := reader.ObsoleteGenerationPageV1(9, ObsoleteNodeV1, nil, 1440)
		mustEnvironment(t, err)
		index, err := reader.ObsoleteGenerationPageV1(9, 2, nil, 1440)
		mustEnvironment(t, err)
		undo, err := reader.ObsoleteUndoPageV1(index.Rows[0], nil, 1440)
		mustEnvironment(t, err)
		return TreeOperationV1{Pair: TreePairV1{
			Mutations:         []Mutation{psfAuthority(t)},
			ObsoleteDeletes:   nodes.Rows,
			ObsoleteConsulted: []ObsoletePageWitnessV1{nodes.Witness, undo.Witness},
		}}
	}
}

// H1/M16 point loop: mode 36 makes the rank-2 index point differ in length (unfunded inequality); the
// later rank-3 header point needs S plus two 148-byte operands, but the account holds F + S + one
// operand + 64, so its preflight comparison must still refuse with the capacity singleton.
func psfPointMismatchThenCapacity(t *testing.T) {
	index := binary.BigEndian.AppendUint64(obsoleteGenerationLiteral(9), 1)
	run := func(mode uint32, remaining func(f, window uint64) uint64) (*psfScene, tsResult, fixtureLargeEvidence) {
		sc := psfNew(t)
		psfUndo(t, sc.s)
		o := reservationFilled(t, psPageGrant+remaining(psfUndoScopeF(t), psfWindow(t, sc.s)))
		sc.o = o
		if mode == 0 {
			return sc, psRun(t, sc.s, o, LaneOperation, psfUndoScopeOp(t)), fixtureLargeEvidence{}
		}
		var r tsResult
		evidence := ctxTreeFault(t, sc.s, mode, 2, index, func() { r = psRun(t, sc.s, o, LaneOperation, psfUndoScopeOp(t)) })
		return sc, r, evidence
	}
	short := func(f, window uint64) uint64 { return f + window + obsoleteHeaderWidth(3) + 64 }
	sc, r, evidence := run(36, short)
	if any(r.err) != any(errOperationReservationCapacity) || evidence.gets != 1 || evidence.aborts != 1 || evidence.commits != 0 {
		t.Fatalf("later scope error lost: %v %+v", r.err, evidence)
	}
	r.tuple(t, 1, 1, -1)
	tsConsumed(t, sc.s, sc.o, 1, r.err)
	sc.image(t, tsReopen(t, sc.s, sc.path), false)
	// Attribution: without the fault the same account refuses at the header point; with ample capacity
	// the index-point mismatch alone is the OLD/write refusal.
	if _, r, _ = run(0, short); any(r.err) != any(errOperationReservationCapacity) {
		t.Fatalf("scope operand window not funded: %v", r.err)
	}
	_, r, _ = run(36, func(f, window uint64) uint64 { return f + window + 2*obsoleteHeaderWidth(3) + 4096 })
	r.tuple(t, 1, 1, -1)
	treeNativeError(t, r.err, "update", "StateMismatch", -30779, "OLD/write snapshot mismatch", nil)
}

// psfUndoScopeF is F for psfUndoScopeOp: M=1, D=3, W=2, P=2 (index and header points), L=0.
func psfUndoScopeF(t *testing.T) uint64 {
	auth := psfAuthority(t)
	nodes := obsoleteTreeFamily(9)
	k := uint64(len(auth.Key) + len(auth.Literal))
	for _, row := range nodes {
		k += uint64(len(row.key))
	}
	// Node witness: prefix 8 + last; undo witness: hash prefix 32 + last family key 34 + points 16 + 32.
	u := uint64(8+len(nodes[2].key)) + 32 + 34 + 16 + 32
	return psF(1, 0, 3, 2, 2, 0, k, u)
}

// N5/M14: mode 15 retains the readback abort (thread mismatch); the scope operation keeps that retained
// ownership, releases its grant and the next operation reuses the terminal refusal without a callback.
func psfRetained(t *testing.T) {
	sc := psfNew(t)
	var r tsResult
	_, err := fixtureLargeFault(sc.s, 15, 0, tsRootKey(9), func() { r = sc.run(t, sc.o) })
	mustEnvironment(t, err)
	if sc.s.state != storePOISONEDTHREAD || sc.s.txn == nil || any(sc.s.terminal) != any(r.err) || r.err == nil {
		t.Fatalf("scope next operation differs: retained %s %v", sc.s.state, r.err)
	}
	if reservationLive(sc.o) != 0 {
		t.Fatalf("scope grant leaked: retained live%d", reservationLive(sc.o))
	}
	calls := 0
	mustEnvironment(t, sc.o.WithOperation(LaneOperation, func(a *OperationAccount) error {
		next := tsInvoke(sc.s, a, func(*Reader) (TreeOperationV1, error) { calls++; return tsPair(9), nil })
		if any(next.err) != any(r.err) || calls != 0 || sc.s.state != storePOISONEDTHREAD {
			t.Fatalf("scope next operation differs: %v calls%d %s", next.err, calls, sc.s.state)
		}
		return nil
	}))
}
