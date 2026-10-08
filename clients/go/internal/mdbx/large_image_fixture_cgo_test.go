//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestLargeImageV1Native(t *testing.T) {
	for _, row := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"A1 malformed physical data and empty values", largeNativePhysical},
		{"A2 complete legal family and aggregate bodies", largeNativeScale},
		{"A3 family targets and reference overlays", largeNativeOverlay},
		{"A5 A6 A7 A8 residual and target truth", largeNativeTruth},
		{"A8 independent legacy and reference predicates", largeNativeJointPredicates},
		{"A2 A5 H4 ORIGINAL OLD reference effects and readback", largeNativeOriginalReferences},
		{"R7 current OLD proof native failures and resources", largeNativeProofReadErrors},
		{"H2 native callback lifecycle", largeNativeCallbacks},
		{"H3 final and preflight residual drift", largeNativePrecommit},
		{"H4 cleanup after proven NEW", largeNativeCleanup},
		{"R2 native shape refusal", largeNativeShapes},
		{"R1 legacy value/native admission before large controls", largeNativeLegacyPriority},
	} {
		t.Run(row.name, row.run)
	}
}

func largeNativeProofReadErrors(t *testing.T) {
	for _, site := range []string{"target", "target-reference", "reference", "consulted"} {
		for _, mode := range []uint32{1, 2, 24} {
			t.Run(fmt.Sprintf("%s/mode%d", site, mode), func(t *testing.T) {
				store, path, cfg := consultedStore(t)
				counter := consultedCounter(t, 1)
				batch := Batch{Mutations: []Mutation{counter}}
				rank, key, before := uint8(0), counter.Key, []byte(nil)
				if site == "consulted" {
					rank, key = 2, canonicalForwardKeyLiteral(9, 1)
					before = canonicalForwardValueLiteral([32]byte{0x31}, [40]byte{39: 1})
					batch.Consulted = []ConsultedRow{{DBI: readDBIsLiteral()[2], Key: key}}
				}
				if site == "reference" || site == "target-reference" {
					target, source := reverseKeys(t, 9, 1)
					ref := forwardRefRow(source, target)
					rank, key, before = 1, target, []byte{0x31}
					batch.Mutations = []Mutation{ref}
					if site == "target-reference" {
						batch.Mutations = []Mutation{{DBI: ref.RefDBI, Key: target, BeforePresent: true, AfterKind: AfterKind(1)}, ref}
					}
				}
				if before != nil {
					mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[rank], key, before))
				}
				truth, stage, result, evidence := largeFaultCommit(t, store, mode, rank, key, batch)
				primary, wantState := result, "CLOSED"
				if mode == 2 {
					joined, ok := result.(interface{ Unwrap() []error })
					if !ok || len(joined.Unwrap()) != 2 {
						t.Fatalf("current OLD fault lost ordered primary and cleanup: %v", result)
					}
					parts := joined.Unwrap()
					primary = parts[0]
					cleanup := requireEnvironmentError(t, parts[1], EngineClass("LocalInvariant"), operationAbort, -30416, expectedNativeDiagnostic(-30416))
					if cleanup.Cause != nil {
						t.Fatal("current OLD cleanup manufactured a cause", cleanup)
					}
					wantState = "POISONED_THREAD"
				}
				if mode == 24 {
					primary = requireEnvironmentError(t, result, EngineClass("Concurrency"), operationClose, -30778, expectedNativeDiagnostic(-30778)).Cause
					wantState = "CLOSE_BLOCKED"
				}
				engine := requireEnvironmentError(t, primary, EngineClass("IO"), operationUpdate, 5, expectedNativeDiagnostic(5))
				if engine.Cause != nil || result != store.terminal || truth != 1 || stage != 1 || evidence.gets != 2 || evidence.commits != 0 || evidence.aborts != 1 || string(store.state) != wantState {
					t.Fatalf("current OLD fault ownership %d/%d/%v/%+v/%s", truth, stage, result, evidence, store.state)
				}
				if mode == 2 && store.txn == nil || mode == 24 && (store.env == nil || store.txn != nil) || mode == 1 && (store.env != nil || store.txn != nil) {
					t.Fatal("current OLD fault lost retained/consumed owner")
				}
				mustEnvironment(t, fixtureLargeRelease(store))
				reopened, openErr := Open(path, cfg)
				consultedTrack(t, reopened, openErr)
				obsoleteRawImage(t, reopened, rank, key, before)
				for _, mutation := range batch.Mutations {
					if mutation.DBI.Rank != rank || !bytes.Equal(mutation.Key, key) {
						obsoleteRawImage(t, reopened, mutation.DBI.Rank, mutation.Key, nil)
					}
				}
			})
		}
	}
}

// These public plans distinguish source identity from both the write and readback candidates.
func largeNativeOriginalReferences(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, sourceEffect := range []string{"untouched", "deleted", "replaced"} {
			if reverse && sourceEffect == "replaced" {
				continue // Reverse's admitted transport grammar forbids an undo literal.
			}
			for _, mode := range []uint32{0, 7, 12, 5, 6} {
				t.Run(fmt.Sprintf("reverse=%v source=%s mode=%d", reverse, sourceEffect, mode), func(t *testing.T) {
					store, path, cfg := consultedStore(t)
					utxo, undo := reverseKeys(t, 9, 1)
					ref := forwardRefRow(undo, utxo)
					if reverse {
						ref = reverseRefRow(utxo, undo)
					}
					old := []byte{0x71} // Opaque legacy source bytes are transported without a new width refusal.
					replacement := append([]byte{0x51}, make([]byte, 19)...)
					mustEnvironment(t, fixtureSeedPrefixRawRow(store, ref.RefDBI, ref.RefKey, old))
					second := ref
					second.Key = bytes.Clone(ref.Key)
					if reverse {
						second.Key[7] = 10
					} else {
						second.Key[36] = 1 // distinct undo transaction index, same original source
					}
					batch := Batch{Reverse: reverse, Mutations: []Mutation{ref, second}}
					wantSource := old
					if sourceEffect != "untouched" {
						source := Mutation{DBI: ref.RefDBI, Key: ref.RefKey, BeforePresent: true, AfterKind: AfterKind(1)}
						wantSource = nil
						if sourceEffect == "replaced" {
							source.AfterKind, source.Literal, wantSource = AfterKind(2), replacement, replacement
						}
						batch.Mutations = append(batch.Mutations, source)
						sort.Slice(batch.Mutations, func(i, j int) bool {
							a, b := batch.Mutations[i], batch.Mutations[j]
							return a.DBI.Rank < b.DBI.Rank || a.DBI.Rank == b.DBI.Rank && bytes.Compare(a.Key, b.Key) < 0
						})
					}
					faultRank, faultKey := ref.DBI.Rank, ref.Key
					if mode == 5 {
						faultRank, faultKey = ref.RefDBI.Rank, ref.RefKey
					}
					var truth CommitTruth
					var stage UpdateStage
					var result error
					var saved *Reader
					run := func() {
						truth, stage, result = store.Update(func(reader *Reader) (Batch, error) { saved = reader; return batch, nil })
						if result != nil {
							largeNativeCached(t, store)
						}
					}
					evidence := fixtureLargeEvidence{}
					if mode == 0 {
						run()
					} else {
						var fixtureErr error
						evidence, fixtureErr = fixtureLargeFault(store, mode, faultRank, faultKey, run)
						mustEnvironment(t, fixtureErr)
					}
					wantTruth := CommitTruth(2)
					if mode == 7 {
						wantTruth, wantSource = 1, old
					}
					if mode == 5 || mode == 6 {
						wantTruth = 3
					}
					if truth != wantTruth || stage != 3 || saved == nil || saved.usable() {
						t.Fatalf("ORIGINAL OLD proof tuple %d/%d/%v, want %d/3 expired Reader", truth, stage, result, wantTruth)
					}
					if mode == 0 {
						if result != nil || string(store.state) != "OPEN" {
							t.Fatalf("reference success resources %s/%v", store.state, result)
						}
						mustEnvironment(t, store.Close())
					} else {
						commit, ok := result.(*CommitError)
						if !ok || commit.Truth != wantTruth || commit.ReadbackCause != nil || evidence.commits != 1 || string(store.state) != "CLOSED" {
							t.Fatalf("reference crossed cause/resources %v/%+v/%s", result, evidence, store.state)
						}
						requireEnvironmentError(t, commit.Cause, EngineClass("Capacity"), operationUpdate, 28, expectedNativeDiagnostic(28))
					}
					reopened, openErr := Open(path, cfg)
					consultedTrack(t, reopened, openErr)
					if mode == 5 {
						wantSource = []byte{0x7f}
					}
					obsoleteRawImage(t, reopened, ref.RefDBI.Rank, ref.RefKey, wantSource)
					wantFirst, wantSecond := old, old
					if mode == 7 {
						wantFirst, wantSecond = nil, nil
					}
					if mode == 6 {
						wantFirst = []byte{0x7f}
					}
					obsoleteRawImage(t, reopened, ref.DBI.Rank, ref.Key, wantFirst)
					obsoleteRawImage(t, reopened, second.DBI.Rank, second.Key, wantSecond)
				})
			}
		}
	}
}

func largeNativePhysical(t *testing.T) {
	store, _, _ := consultedStore(t)
	dbis := readDBIsLiteral()
	body := LargeImageSelectorV1{Kind: 1}
	mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbis[4], make([]byte, 32), []byte{}))
	keys := [][]byte{make([]byte, 32), append(make([]byte, 32), 0), append(make([]byte, 32), 0xff), append(make([]byte, 32), 1, 0)}
	keys[2] = append(keys[2], bytes.Repeat([]byte{0xfe}, 300)...)
	// Literal order: prefix itself, tag 00, tag 01, tag ff, regardless of schema.
	keys[2], keys[3] = keys[3], keys[2]
	values := [][]byte{{}, {0x21}, {0x22, 0x23}, {0x24}}
	for i := range keys {
		mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbis[5], keys[i], values[i]))
	}
	mustEnvironment(t, store.View(func(reader *Reader) error {
		if err := reader.VisitLargeImageV1(body, func(row LargeImageRowV1) error {
			largeWindow(t, row, []byte{}, true)
			n, err := row.ReadAt(make([]byte, 1), 0)
			if n != 0 || err != io.EOF {
				t.Fatalf("present-empty read %d/%v", n, err)
			}
			return nil
		}); err != nil {
			return err
		}
		seen := 0
		err := reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 2}, func(row LargeImageRowV1) error {
			if seen >= len(keys) || !bytes.Equal(row.Key(), keys[seen]) {
				t.Fatalf("physical order at %d: %x", seen, row.Key())
			}
			largeWindow(t, row, values[seen], true)
			seen++
			return nil
		})
		if seen != 4 {
			t.Fatalf("malformed complete family=%d", seen)
		}
		return err
	}))
	// Manifest-only exclusion must leave both malformed suffixes in the residual image.
	largeCommit(t, store, Batch{Mutations: []Mutation{{DBI: dbis[5], Key: keys[1], BeforePresent: true, AfterKind: AfterKind(1)}}, LargeConsulted: []LargeImageSelectorV1{{Kind: 2}}})
	largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 1)}, LargeConsulted: []LargeImageSelectorV1{{Kind: 2}}})
	// The pinned native 4096-byte page has K=2022 (20-byte page/8-byte node/2-byte index).
	maximumKey := bytes.Repeat([]byte{0xff}, 2022)
	maximumHash := [32]byte{}
	copy(maximumHash[:], maximumKey)
	mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbis[5], maximumKey, []byte{0x42}))
	selector := LargeImageSelectorV1{Kind: 2, Hash: maximumHash}
	mustEnvironment(t, store.View(func(reader *Reader) error {
		seen := 0
		err := reader.VisitLargeImageV1(selector, func(row LargeImageRowV1) error {
			seen++
			if !bytes.Equal(row.Key(), maximumKey) {
				t.Fatal("maximum native key was truncated")
			}
			largeWindow(t, row, []byte{0x42}, true)
			return nil
		})
		if seen != 1 {
			t.Fatalf("maximum native key exhaustion %d", seen)
		}
		return err
	}))
	largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 2)}, LargeConsulted: []LargeImageSelectorV1{selector}})
}

func largeNativeScale(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	cfg.Upper = 512 << 20
	store, err := Create(path, cfg)
	consultedTrack(t, store, err)
	mustEnvironment(t, fixtureLargeBulk(store, 2, 414_634, 20))
	manifestKey := append(make([]byte, 32), 0)
	manifest := make([]byte, 33)
	manifest[0] = 1
	binary.BigEndian.PutUint32(manifest[25:], 414_634)
	binary.BigEndian.PutUint32(manifest[29:], 414_634)
	mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[5], manifestKey, manifest))
	// A maximum compact undo value spans a full 65536-byte window and a 24-byte tail.
	chunkKey := make([]byte, 77)
	chunkKey[32] = 1
	binary.BigEndian.PutUint32(chunkKey[33:], 414_633)
	chunk := make([]byte, 65_560)
	chunk[0] = 0x5a
	chunk[10] = 0xfe
	chunk[13] = 1
	copy(chunk[15:65_551], bytes.Repeat([]byte{0x6b}, 65_536))
	mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[5], chunkKey, chunk))
	mustEnvironment(t, fixtureLargeBulk(store, 1, 1440, 108_000))
	maximumKey, maximum := largeBodyLiteral(0x4c, 68_000_125)
	mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[4], maximumKey[:], maximum))
	selectors := largeSelectors(1440, 1)
	indices := make(map[[32]byte]uint32, 1440)
	header := bytes.Repeat([]byte{0x5a}, 116)
	for i := range selectors {
		binary.BigEndian.PutUint32(header, uint32(i))
		selectors[i].Hash = sha3.Sum256(header)
		indices[selectors[i].Hash] = uint32(i)
	}
	sort.Slice(selectors, func(i, j int) bool { return bytes.Compare(selectors[i].Hash[:], selectors[j].Hash[:]) < 0 })
	selectors = append(selectors, LargeImageSelectorV1{Kind: 2})
	largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 1)}, LargeConsulted: selectors})
	mustEnvironment(t, store.View(func(reader *Reader) error {
		count := 0
		buffer := make([]byte, 20)
		var previous LargeImageRowV1
		if err := reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 2}, func(row LargeImageRowV1) error {
			if count != 0 {
				n, err := previous.ReadAt(nil, 0)
				if n != 0 {
					t.Fatal("prior family row copied bytes")
				}
				largeRequireError(t, err, "InvalidInput", 22, "large image row is not active")
			}
			previous = row
			key := row.Key()
			if count == 0 {
				if !bytes.Equal(key, manifestKey) {
					t.Fatal("family manifest order")
				}
				largeWindow(t, row, manifest, true)
			} else if count <= 414_634 {
				if len(key) != 77 || key[32] != 1 || binary.BigEndian.Uint32(key[33:37]) != uint32(count-1) {
					t.Fatalf("legal family order %d/%x", count, key)
				}
				if count == 414_634 {
					largeWindow(t, row, chunk, true)
				} else {
					n, err := row.ReadAt(buffer, 0)
					want := make([]byte, 20)
					want[0] = 0x5a
					if n != 20 || err != nil || !bytes.Equal(buffer, want) {
						t.Fatalf("family bytes %d/%v/%x", n, err, buffer)
					}
				}
			} else {
				t.Fatal("extra legal family member")
			}
			count++
			return nil
		}); err != nil {
			return err
		}
		if count != 414_635 {
			t.Fatalf("legal family complete exhaustion=%d", count)
		}
		var total uint64
		wantBody := bytes.Repeat([]byte{0x5a}, 108_000)
		for _, selector := range selectors[:1440] {
			binary.BigEndian.PutUint32(wantBody, indices[selector.Hash])
			if err := reader.VisitLargeImageV1(selector, func(row LargeImageRowV1) error {
				if !row.Present() || row.Length() != 108_000 {
					t.Fatal("aggregate body metadata")
				}
				largeWindow(t, row, wantBody, true)
				total += row.Length()
				return nil
			}); err != nil {
				return err
			}
		}
		if total != 155_520_000 || total <= 154_611_151 {
			t.Fatalf("aggregate capacity witness %d", total)
		}
		return reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 1, Hash: maximumKey}, func(row LargeImageRowV1) error {
			largeWindow(t, row, maximum, true)
			return nil
		})
	}))
	largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 2)}, LargeConsulted: []LargeImageSelectorV1{{Kind: 1, Hash: maximumKey}}})
}

func largeNativeOverlay(t *testing.T) {
	store, _, _ := consultedStore(t)
	dbis := readDBIsLiteral()
	family := LargeImageSelectorV1{Kind: 2}
	manifestKey := append(make([]byte, 32), 0)
	residual := append(make([]byte, 32), 2)
	mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbis[5], manifestKey, []byte{0x13}))
	mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbis[5], residual, []byte{0x31}))
	spent := [32]byte{1}
	utxoKey := make([]byte, 44)
	utxoKey[7] = 1
	copy(utxoKey[8:40], spent[:])
	entryKey := make([]byte, 77)
	entryKey[32] = 1
	copy(entryKey[41:73], spent[:])
	value := make([]byte, 20)
	value[0] = 7
	mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbis[1], utxoKey, value))
	largeCommit(t, store, Batch{Mutations: []Mutation{
		{DBI: dbis[1], Key: utxoKey, BeforePresent: true, AfterKind: AfterKind(1)},
		{DBI: dbis[5], Key: manifestKey, BeforePresent: true, AfterKind: AfterKind(1)},
		{DBI: dbis[5], Key: entryKey, AfterKind: AfterKind(3), RefDBI: dbis[1], RefKey: utxoKey},
	}, LargeConsulted: []LargeImageSelectorV1{family}})
	consultedRequireImage(t, store, dbis[5], entryKey, value, true, "forward reference bytes")
	// Reference source is also inside the selected family; it is deleted as a target.
	largeCommit(t, store, Batch{Reverse: true, Mutations: []Mutation{
		{DBI: dbis[1], Key: utxoKey, AfterKind: AfterKind(3), RefDBI: dbis[5], RefKey: entryKey},
		{DBI: dbis[5], Key: entryKey, BeforePresent: true, AfterKind: AfterKind(1)},
	}, LargeConsulted: []LargeImageSelectorV1{family}})
	consultedRequireImage(t, store, dbis[1], utxoKey, value, true, "reverse reference targeted source")
	mustEnvironment(t, store.View(func(reader *Reader) error {
		seen := 0
		err := reader.VisitLargeImageV1(family, func(row LargeImageRowV1) error {
			seen++
			if !bytes.Equal(row.Key(), residual) {
				t.Fatalf("untouched residual %x", row.Key())
			}
			largeWindow(t, row, []byte{0x31}, true)
			return nil
		})
		if seen != 1 {
			t.Fatalf("overlay family exhaustion=%d", seen)
		}
		return err
	}))
}

func largeFaultCommit(t *testing.T, store *Store, mode uint32, rank uint8, faultKey []byte, batch Batch) (CommitTruth, UpdateStage, error, fixtureLargeEvidence) {
	t.Helper()
	var truth CommitTruth
	var stage UpdateStage
	var result error
	var saved *Reader
	evidence, fixtureErr := fixtureLargeFault(store, mode, rank, faultKey, func() {
		truth, stage, result = store.Update(func(reader *Reader) (Batch, error) {
			saved = reader
			return batch, nil
		})
		largeNativeCached(t, store)
	})
	mustEnvironment(t, fixtureErr)
	if saved == nil || saved.usable() {
		t.Fatal("public Reader remained usable through private comparison/readback")
	}
	largeRequireError(t, saved.VisitLargeImageV1(LargeImageSelectorV1{Kind: 1}, nil), "InvalidInput", 22, "Reader is not active")
	return truth, stage, result, evidence
}

func largeNativeCached(t *testing.T, store *Store) {
	t.Helper()
	before := fixtureLargeNativeCalls()
	terminal := store.terminal
	wantTruth := CommitTruth(1)
	if store.terminalTruth != 0 {
		wantTruth = store.terminalTruth
	}
	truth, stage, result := store.Update(func(*Reader) (Batch, error) {
		t.Fatal("cached terminal callback ran")
		return Batch{}, nil
	})
	if truth != wantTruth || int(stage) != 1 || result != terminal {
		t.Fatal("cached terminal update changed result")
	}
	if result = store.View(func(*Reader) error {
		t.Fatal("cached terminal View callback ran")
		return nil
	}); result != terminal {
		t.Fatal("cached terminal View changed error identity")
	}
	if fixtureLargeNativeCalls() != before {
		t.Fatal("cached terminal result reused native handles")
	}
}

func largeNativeTruth(t *testing.T) {
	for _, row := range []struct {
		name   string
		mode   uint32
		target bool
		want   string
	}{
		{"extra residual", 3, false, "UNKNOWN"},
		{"missing residual", 4, false, "UNKNOWN"},
		{"manifest target plus extra residual", 3, true, "UNKNOWN"},
		{"same-length residual byte", 5, false, "UNKNOWN"},
		{"neither target", 6, true, "UNKNOWN"},
		{"OLD", 7, false, "OLD"},
		{"NEW", 12, false, "NEW"},
		{"readback error", 8, false, "UNKNOWN"},
		{"readback begin error", 23, false, "UNKNOWN"},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			key := append(make([]byte, 32), 2)
			if row.mode != 3 {
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[5], key, []byte{0x31}))
			}
			batch := Batch{Mutations: []Mutation{consultedCounter(t, 1)}, LargeConsulted: []LargeImageSelectorV1{{Kind: 2}}}
			rank := uint8(5)
			if row.target {
				targetKey := append(make([]byte, 32), 0)
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[5], targetKey, []byte{0x41}))
				batch.Mutations = []Mutation{{DBI: readDBIsLiteral()[5], Key: targetKey, BeforePresent: true, AfterKind: AfterKind(1)}}
				if row.mode == 6 {
					key = targetKey
				}
			}
			if row.mode == 8 {
				rank = 0
				key = consultedCounter(t, 1).Key
			}
			truth, stage, err, evidence := largeFaultCommit(t, store, row.mode, rank, key, batch)
			commit, ok := err.(*CommitError)
			if !ok || truth.String() != row.want || commit.Truth.String() != row.want || int(stage) != 3 || string(store.state) != "CLOSED" || store.env != nil || store.writer != nil || store.txn != nil || evidence.commits != 1 || evidence.aborts != 1 {
				t.Fatalf("readback %s: %s/%d/%v/%s/%+v", row.name, truth, stage, err, store.state, evidence)
			}
			requireEnvironmentError(t, commit.Cause, EngineClass("Capacity"), operationUpdate, 28, expectedNativeDiagnostic(28))
			if row.mode == 8 || row.mode == 23 {
				requireEnvironmentError(t, commit.ReadbackCause, EngineClass("IO"), operationUpdate, 5, expectedNativeDiagnostic(5))
			} else if commit.ReadbackCause != nil {
				t.Fatalf("unexpected readback cause: %v", commit.ReadbackCause)
			}
			if store.terminalTruth.String() != row.want {
				t.Fatal("terminal truth differs")
			}
			nextTruth, nextStage, nextErr := store.Update(func(*Reader) (Batch, error) {
				t.Fatal("cached terminal callback ran")
				return Batch{}, nil
			})
			if nextTruth.String() != row.want || int(nextStage) != 1 || nextErr != store.terminal {
				t.Fatal("cached terminal result")
			}
			reopened, openErr := Open(path, cfg)
			consultedTrack(t, reopened, openErr)
			if row.mode >= 3 && row.mode <= 6 {
				want := []byte{0x7f}
				if row.mode == 4 {
					want = nil
				}
				found, readErr := FixtureRawRowEqual(reopened, rank, key, want)
				if readErr != nil || !found || evidence.drift != 1 {
					t.Fatalf("actual drift %v/%v/%+v", found, readErr, evidence)
				}
			}
		})
	}
	// Both predicates match in the direct finite-domain case; OLD wins.
	largeNativeBoth(t)
}

func largeNativeBoth(t *testing.T) {
	store, _, _ := consultedStore(t)
	key := append(make([]byte, 32), 2)
	mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[5], key, []byte{0x31}))
	// Direct readback is necessary to reach both=true: the public grammar admits no no-op target.
	var truth CommitTruth
	mustEnvironment(t, store.View(func(reader *Reader) error {
		var err error
		scope := largeImageScope{selectors: []LargeImageSelectorV1{{Kind: 2}}, maxKey: reader.maxKey}
		truth, err = updateNativeReadbackTruth(reader.txn, reader.txn, store.dbis, nil, nil, scope)
		return err
	}))
	if truth.String() != "OLD" {
		t.Fatalf("both-equal precedence %s", truth)
	}
}

func largeNativeJointPredicates(t *testing.T) {
	for _, which := range []string{"legacy", "reference", "point-later-Large", "legacy-later-Large"} {
		t.Run(which, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			dbis := readDBIsLiteral()
			batch := Batch{Mutations: []Mutation{consultedCounter(t, 1)}, LargeConsulted: []LargeImageSelectorV1{{Kind: 2}}}
			key, rank := consultedCounter(t, 33).Key, uint8(0)
			before := []byte{0, 0, 0, 0, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 33}
			if which == "legacy" || which == "legacy-later-Large" {
				batch.Consulted = []ConsultedRow{{DBI: dbis[0], Key: key}}
			} else if which == "reference" {
				rank = 1
				key = make([]byte, 44)
				key[7] = 1
				key[8] = 1
				before = make([]byte, 20)
				before[0] = 7
				entry := make([]byte, 77)
				entry[32] = 1
				entry[41] = 1
				batch.Mutations = []Mutation{{DBI: dbis[5], Key: entry, AfterKind: AfterKind(3), RefDBI: dbis[1], RefKey: key}}
			}
			if which == "point-later-Large" {
				key, before = consultedCounter(t, 1).Key, nil
			} else {
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbis[rank], key, before))
			}
			mode := uint32(5)
			laterFault := strings.HasSuffix(which, "-later-Large")
			if laterFault {
				mode = 29
			}
			truth, stage, err, evidence := largeFaultCommit(t, store, mode, rank, key, batch)
			commit, ok := err.(*CommitError)
			if !ok || truth.String() != "UNKNOWN" || commit.Truth.String() != "UNKNOWN" || int(stage) != 3 || evidence.drift != 1 || evidence.commits != 1 || string(store.state) != "CLOSED" {
				t.Fatalf("%s predicate omitted: %s/%d/%v/%+v", which, truth, stage, err, evidence)
			}
			requireEnvironmentError(t, commit.Cause, EngineClass("Capacity"), operationUpdate, 28, expectedNativeDiagnostic(28))
			if laterFault {
				later := requireEnvironmentError(t, commit.ReadbackCause, EngineClass("IO"), operationGet, 5, expectedNativeDiagnostic(5))
				if later.Cause != nil {
					t.Fatal("later Large native failure manufactured a cause", later)
				}
				if evidence.gets != 1 {
					t.Fatal("later Large native failure was not reached exactly once")
				}
			} else if commit.ReadbackCause != nil {
				t.Fatal("predicate-only mismatch manufactured a readback cause")
			}
			reopened, openErr := Open(path, cfg)
			consultedTrack(t, reopened, openErr)
			obsoleteRawImage(t, reopened, rank, key, []byte{0x7f})
			if which == "legacy-later-Large" {
				counter := consultedCounter(t, 1)
				obsoleteRawImage(t, reopened, 0, counter.Key, counter.Literal)
			}
		})
	}
}

func largeNativeCallbacks(t *testing.T) {
	for _, fault := range []uint32{1, 2, 24} {
		for _, mode := range []string{"nil", "ignored", "exact", "wrapped", "joined", "distinct", "typed-nil", "panic"} {
			t.Run(fmt.Sprintf("%d/%s", fault, mode), func(t *testing.T) {
				store, _, _ := consultedStore(t)
				key := make([]byte, 32)
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[4], key, []byte{0x31}))
				var recorded, application, visitResult, result error
				if mode == "distinct" {
					application = errors.New("large distinct application")
				}
				if mode == "typed-nil" {
					application = (*largeTypedNil)(nil)
				}
				panicValue := &struct{ text string }{"native callback panic"}
				var recovered any
				var truth CommitTruth
				var stage UpdateStage
				var saved LargeImageRowV1
				var evidence fixtureLargeEvidence
				func() {
					defer func() { recovered = recover() }()
					var fixtureErr error
					evidence, fixtureErr = fixtureLargeFault(store, fault, 4, key, func() {
						truth, stage, result = store.Update(func(reader *Reader) (Batch, error) {
							visitErr := reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 1}, func(row LargeImageRowV1) error {
								saved = row
								beforeInput := fixtureLargeNativeCalls()
								largeRequireError(t, reader.VisitLargeImageV1(LargeImageSelectorV1{}, nil), "InvalidInput", 22, "nil large image visitor")
								largeRequireError(t, reader.VisitLargeImageV1(LargeImageSelectorV1{}, func(LargeImageRowV1) error {
									t.Fatal("invalid nested callback ran")
									return nil
								}), "InvalidInput", 22, "invalid large image selector")
								if n, err := row.ReadAt(make([]byte, 65_537), 0); n != 0 {
									t.Fatal("input refusal copied bytes")
								} else {
									largeRequireError(t, err, "InvalidInput", 22, "ReadAt buffer exceeds 65536 bytes")
								}
								if n, err := row.ReadAt(nil, math.MaxUint64); n != 0 || err != nil {
									t.Fatal("zero ReadAt input/native precedence")
								}
								if n, err := row.ReadAt(make([]byte, 1), 1); n != 0 || err != io.EOF {
									t.Fatal("end ReadAt input/native precedence")
								}
								if fixtureLargeNativeCalls() != beforeInput || !reader.usable() || reader.failure != nil {
									t.Fatal("input/EOF refusal called native or disarmed Reader")
								}
								n, err := row.ReadAt(make([]byte, 1), 0)
								if n != 0 {
									t.Fatal("native fault copied bytes")
								}
								recorded = err
								requireEnvironmentError(t, recorded, EngineClass("IO"), operationGet, 5, expectedNativeDiagnostic(5))
								switch mode {
								case "exact":
									return recorded
								case "wrapped":
									application = fmt.Errorf("large wrapped: %w", recorded)
									return application
								case "joined":
									application = errors.Join(errors.New("large application first"), recorded)
									return application
								case "panic":
									panic(panicValue)
								default:
									return application
								}
							})
							visitResult = visitErr
							if mode == "ignored" {
								return Batch{Mutations: []Mutation{consultedCounter(t, 1)}}, nil
							}
							return Batch{}, visitErr
						})
						largeNativeCached(t, store)
					})
					mustEnvironment(t, fixtureErr)
				}()
				// Panic still executes fixture disarm; native ownership is asserted from Store itself.
				if fault == 1 {
					if string(store.state) != "CLOSED" || store.env != nil || store.writer != nil || store.txn != nil {
						t.Fatal("consumed infrastructure resource projection")
					}
				} else if fault == 2 {
					if string(store.state) != "POISONED_THREAD" || store.env == nil || store.writer == nil || store.txn == nil || store.config != (ConfigV1{}) || store.dbis != (Store{}).dbis {
						t.Fatal("retained infrastructure resource projection")
					}
				} else if string(store.state) != "CLOSE_BLOCKED" || store.env == nil || store.writer == nil || store.txn != nil || store.config == (ConfigV1{}) || store.dbis == (Store{}).dbis {
					t.Fatal("retained close resource projection")
				}
				if mode == "panic" {
					if recovered != panicValue || result != nil {
						t.Fatalf("original native panic %v/%v", recovered, result)
					}
					largeCallbackCauses(t, store.terminal, nil, recorded, fault)
				} else {
					if truth.String() != "OLD" || int(stage) != 1 || evidence.gets != 2 || evidence.aborts != 1 || evidence.commits != 0 {
						t.Fatalf("native callback disposition %s/%d/%+v", truth, stage, evidence)
					}
					largeCallbackCauses(t, visitResult, application, recorded, 1)
					outerApplication := visitResult
					if mode == "ignored" {
						outerApplication = nil
					}
					largeCallbackCauses(t, result, outerApplication, recorded, fault)
				}
				_, expiredErr := saved.ReadAt(make([]byte, 65_537), math.MaxUint64)
				largeRequireError(t, expiredErr, "InvalidInput", 22, "Reader is not active")
				terminal := store.terminal
				if next := store.View(func(*Reader) error {
					t.Fatal("terminal native callback ran")
					return nil
				}); next != terminal {
					t.Fatalf("cached terminal identity %v/%v", next, terminal)
				}
				mustEnvironment(t, fixtureLargeRelease(store))
			})
		}
	}
}

func largeCallbackCauses(t *testing.T, result, application, recorded error, fault uint32) {
	t.Helper()
	if fault == 24 {
		engine := requireEnvironmentError(t, result, EngineClass("Concurrency"), operationClose, -30778, expectedNativeDiagnostic(-30778))
		if engine.Cause == nil || engine.ReopenRequired {
			t.Fatal("retained close cause/reopen")
		}
		result = engine.Cause
	}
	if fault == 2 {
		engine := requireEnvironmentError(t, result, EngineClass("LocalInvariant"), operationAbort, -30416, expectedNativeDiagnostic(-30416))
		if engine.Cause == nil || !engine.ReopenRequired {
			t.Fatal("retained cleanup cause/reopen")
		}
		result = engine.Cause
	}
	if application == nil || application == recorded {
		if result != recorded {
			t.Fatalf("recorded error duplicated/replaced %v/%v", result, recorded)
		}
		return
	}
	parts, ok := result.(interface{ Unwrap() []error })
	if !ok || len(parts.Unwrap()) != 2 || parts.Unwrap()[0] != application || parts.Unwrap()[1] != recorded {
		t.Fatalf("application then infrastructure causes %v", result)
	}
}

func largeNativePrecommit(t *testing.T) {
	for _, domain := range []string{"target", "residual", "consulted", "reference"} {
		for _, mode := range []uint32{13, 14} {
			t.Run(fmt.Sprintf("%s/mode%d", domain, mode), func(t *testing.T) {
				store, path, cfg := consultedStore(t)
				key := append(make([]byte, 32), 2)
				batch := Batch{Mutations: []Mutation{consultedCounter(t, 1)}, LargeConsulted: []LargeImageSelectorV1{{Kind: 2}}}
				rank, before := uint8(5), []byte(nil)
				if domain == "target" {
					rank, key = 0, consultedCounter(t, 1).Key
					batch.LargeConsulted = nil
				}
				if domain == "consulted" {
					rank, key = 2, canonicalForwardKeyLiteral(9, 1)
					before = canonicalForwardValueLiteral([32]byte{0x51}, [40]byte{39: 1})
					batch.LargeConsulted = nil
					batch.Consulted = []ConsultedRow{{DBI: readDBIsLiteral()[2], Key: key}}
				}
				if domain == "reference" {
					target, source := reverseKeys(t, 9, 1)
					ref := forwardRefRow(source, target)
					rank, key, before = 1, ref.RefKey, []byte{0x31}
					batch.Mutations, batch.LargeConsulted = []Mutation{ref}, nil
				}
				if before != nil {
					mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[rank], key, before))
				}
				truth, stage, err, evidence := largeFaultCommit(t, store, mode, rank, key, batch)
				diagnostic, wantStage := "final update image mismatch", 2
				if mode == 14 {
					diagnostic, wantStage = "OLD/write snapshot mismatch", 1
				}
				requireEnvironmentError(t, err, EngineClass("StateMismatch"), operationUpdate, -30779, diagnostic)
				if truth.String() != "OLD" || int(stage) != wantStage || string(store.state) != "CLOSED" || evidence.commits != 0 || evidence.drift != 1 {
					t.Fatalf("precommit residual %d: %s/%d/%v/%+v", mode, truth, stage, err, evidence)
				}
				reopened, openErr := Open(path, cfg)
				consultedTrack(t, reopened, openErr)
				target := batch.Mutations[0]
				wantTarget := []byte(nil)
				if domain == "target" && mode == 14 {
					wantTarget = []byte{0x7f}
				}
				obsoleteRawImage(t, reopened, target.DBI.Rank, target.Key, wantTarget)
				want := before
				if mode == 14 {
					want = []byte{0x7f}
				}
				equal, readErr := FixtureRawRowEqual(reopened, rank, key, want)
				if readErr != nil || !equal {
					t.Fatal("precommit physical residual disposition")
				}
			})
		}
	}
}

func largeNativeCleanup(t *testing.T) {
	for _, mode := range []uint32{9, 10, 11, 15, 16, 19} {
		store, path, cfg := consultedStore(t)
		key := make([]byte, 32)
		mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[4], key, []byte{0x31}))
		batch := Batch{Mutations: []Mutation{consultedCounter(t, 1)}, LargeConsulted: []LargeImageSelectorV1{{Kind: 1}}}
		truth, stage, err, _ := largeFaultCommit(t, store, mode, 4, key, batch)
		wantTruth := "NEW"
		if mode == 19 {
			wantTruth = "OLD"
		}
		if truth.String() != wantTruth || int(stage) != 3 || store.terminalTruth.String() != wantTruth {
			t.Fatalf("cleanup downgraded proven truth mode%d: %s/%d/%v", mode, truth, stage, err)
		}
		var commit *CommitError
		if !errors.As(err, &commit) || commit.Truth.String() != wantTruth {
			t.Fatalf("cleanup CommitError: %v", err)
		}
		if mode == 11 {
			closeError := requireEnvironmentError(t, err, EngineClass("Concurrency"), operationClose, -30778, expectedNativeDiagnostic(-30778))
			if closeError.Cause != commit {
				t.Fatal("close failure lost exact CommitError cause")
			}
		} else {
			code, class := 5, "IO"
			if mode == 10 || mode == 15 || mode == 19 {
				code, class = -30416, "LocalInvariant"
			}
			requireEnvironmentError(t, commit.ReadbackCause, EngineClass(class), operationAbort, code, expectedNativeDiagnostic(code))
		}
		wantState := "CLOSED"
		if mode == 10 || mode == 15 || mode == 19 {
			wantState = "POISONED_THREAD"
		}
		if mode == 11 {
			wantState = "CLOSE_BLOCKED"
		}
		if string(store.state) != wantState {
			t.Fatalf("cleanup resource state mode%d=%s", mode, store.state)
		}
		mustEnvironment(t, fixtureLargeRelease(store))
		reopened, openErr := Open(path, cfg)
		consultedTrack(t, reopened, openErr)
		want := []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1}
		if mode == 19 {
			want = nil
		}
		consultedRequireImage(t, reopened, readDBIsLiteral()[0], consultedCounter(t, 1).Key, want, mode != 19, "proven truth persisted after cleanup")
	}
}

func largeNativeShapes(t *testing.T) {
	for _, mode := range []uint32{17, 18, 20, 21, 22, 25, 26} {
		store, _, _ := consultedStore(t)
		key := make([]byte, 32)
		rank, kind := uint8(4), LargeImageKindV1(1)
		if mode >= 20 {
			rank, kind = 5, 2
			key = append(key, 2)
		}
		mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[rank], key, []byte{1}))
		var result error
		evidence, err := fixtureLargeFault(store, mode, rank, key, func() {
			result = store.View(func(reader *Reader) error {
				return reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: kind}, func(LargeImageRowV1) error {
					t.Fatal("malformed native span exposed")
					return nil
				})
			})
		})
		mustEnvironment(t, err)
		largeRequireError(t, result, "LocalInvariant", -30779, "invalid native large image result")
		if evidence.gets != 1 || evidence.aborts != 1 || string(store.state) != "CLOSED" || store.env != nil || store.writer != nil {
			t.Fatal("shape failure infrastructure disposition")
		}
	}
}

func largeNativeLegacyPriority(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	cfg.Upper = 512 << 20
	store, err := Create(path, cfg)
	consultedTrack(t, store, err)
	mustEnvironment(t, fixtureLargeBulk(store, 1, 3, 68_000_125))
	header := bytes.Repeat([]byte{0x5a}, 116)
	rows := make([]ConsultedRow, 3)
	for i := range rows {
		binary.BigEndian.PutUint32(header, uint32(i))
		hash := sha3.Sum256(header)
		rows[i] = ConsultedRow{DBI: readDBIsLiteral()[4], Key: bytes.Clone(hash[:])}
	}
	sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i].Key, rows[j].Key) < 0 })
	batch := Batch{Mutations: []Mutation{consultedCounter(t, 1)}, Consulted: rows, LargeConsulted: []LargeImageSelectorV1{{Kind: 9}}}
	truth, stage, result := store.Update(func(*Reader) (Batch, error) { return batch, nil })
	requireEnvironmentError(t, result, EngineClass("Capacity"), operationUpdate, -30417, "Update Batch exceeds bound")
	if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "OPEN" {
		t.Fatal("legacy captured-value admission priority")
	}
	batch.LargeConsulted = make([]LargeImageSelectorV1, 2881)
	var nativeResult error
	evidence, fixtureErr := fixtureLargeFault(store, 28, 4, rows[0].Key, func() {
		truth, stage, nativeResult = store.Update(func(*Reader) (Batch, error) { return batch, nil })
	})
	mustEnvironment(t, fixtureErr)
	requireEnvironmentError(t, nativeResult, EngineClass("IO"), operationUpdate, 5, expectedNativeDiagnostic(5))
	if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "CLOSED" || evidence.gets != 1 || evidence.aborts != 1 {
		t.Fatal("legacy native capture priority before scalar selector count")
	}
}

// Joint cases distinguish shared physical scopes from independent target,
// reference, proof and body predicates on the actual Store.Update path.
func TestLargeImageV1ObsoleteJoint(t *testing.T) {
	for _, variant := range []string{"overlay", "proof-target", "proof-target-third", "shared-family-sibling", "shared-proof-drift", "shared-index-drift", "later-failure", "retained-match", "retained-residual", "retained-body", "retained-family", "retained-reference", "retained-third-target"} {
		t.Run(variant, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			indexKey, indexValue, hash, header := obsoleteProjectionSeed(t, store, 9, 1)
			first, second := append(bytes.Clone(hash[:]), 1, 1), append(bytes.Clone(hash[:]), 2, 2)
			obsoleteSeed(t, store, 5, first, []byte{0x41})
			obsoleteSeed(t, store, 5, second, []byte{0x51})
			mode, rank, faultKey := uint32(5), uint8(3), hash[:]
			if variant == "proof-target-third" {
				mode = 6
			}
			if variant == "shared-family-sibling" {
				rank, faultKey = 5, second
			}
			if variant == "shared-index-drift" {
				rank, faultKey = 2, indexKey
			}
			if variant == "later-failure" {
				mode, rank = 29, 4
				obsoleteSeed(t, store, 4, hash[:], []byte{0x61})
			}
			retained := strings.HasPrefix(variant, "retained-")
			var source, destination, sourceValue, rawTarget, rawResidual []byte
			if variant == "overlay" || retained {
				source = make([]byte, 44)
				source[7], source[8] = 9, 0x31
				if retained {
					source[7] = 10
					rawTarget, rawResidual = append(obsoleteGenerationLiteral(9), 1), append(obsoleteGenerationLiteral(9), 2)
					obsoleteSeed(t, store, 1, rawTarget, []byte{0x21})
					obsoleteSeed(t, store, 1, rawResidual, []byte{0x31})
					obsoleteSeed(t, store, 4, hash[:], []byte{0x61})
				}
				destination = make([]byte, 77)
				copy(destination, hash[:])
				destination[32] = 1
				copy(destination[41:], source[8:])
				sourceValue = append([]byte{0x71}, make([]byte, 19)...)
				obsoleteSeed(t, store, 1, source, sourceValue)
			}
			if retained {
				switch variant {
				case "retained-residual":
					rank, faultKey = 1, rawResidual
				case "retained-body":
					rank, faultKey = 4, hash[:]
				case "retained-family":
					rank, faultKey = 5, second
				case "retained-reference":
					rank, faultKey = 1, source
				case "retained-third-target":
					rank, faultKey = 5, destination
				}
			}
			var truth CommitTruth
			var stage UpdateStage
			var result error
			run := func() {
				truth, stage, result = store.Update(func(reader *Reader) (Batch, error) {
					batch := Batch{LargeConsulted: []LargeImageSelectorV1{{Kind: 2, Hash: hash}}}
					if variant == "overlay" || retained {
						page, err := reader.ObsoleteGenerationPageV1(9, 1, nil, 1)
						mustEnvironment(t, err)
						batch.ObsoleteDeletes, batch.ObsoleteConsulted = page.Rows, []ObsoletePageWitnessV1{page.Witness}
						batch.Mutations = []Mutation{{DBI: readDBIsLiteral()[5], Key: destination, AfterKind: AfterKind(3), RefDBI: readDBIsLiteral()[1], RefKey: source}}
						if variant == "overlay" {
							owned, err := updateOwnedBatch(batch, reader)
							mustEnvironment(t, err)
							if len(owned) != 2 || !bytes.Equal(owned[0].key, source) || &owned[1].refKey[0] != &owned[0].key[0] || &owned[1].refKey[0] == &source[0] {
								t.Fatal("reference did not share the obsolete-added owned target")
							}
						}
						if retained {
							obsoleteRequirePage(t, page, 2, 1, rawTarget)
							residual, err := reader.ObsoleteGenerationPageV1(9, 1, page.Next, 7)
							mustEnvironment(t, err)
							obsoleteRequirePage(t, residual, 1, 1, rawResidual)
							batch.ObsoleteConsulted = append(batch.ObsoleteConsulted, residual.Witness)
							batch.LargeConsulted = []LargeImageSelectorV1{{Kind: 1, Hash: hash}, {Kind: 2, Hash: hash}}
						}
						return batch, nil
					}
					if variant == "later-failure" {
						page, err := reader.ObsoleteGenerationPageV1(9, 1, nil, 1)
						mustEnvironment(t, err)
						obsoleteRequirePage(t, page, 1, 1)
						batch.ObsoleteConsulted = []ObsoletePageWitnessV1{page.Witness}
						batch.LargeConsulted = []LargeImageSelectorV1{{Kind: 1, Hash: hash}}
						batch.Mutations = []Mutation{consultedCounter(t, 1)}
						return batch, nil
					}
					index := obsoleteIndexPage(t, reader, 9)
					page, err := reader.ObsoleteUndoPageV1(index.Rows[0], nil, 1)
					mustEnvironment(t, err)
					obsoleteRequirePage(t, page, 2, 3, first)
					// Same OLD proof points and intervals from distinct observations coalesce.
					repeated, err := reader.ObsoleteUndoPageV1(index.Rows[0], nil, 7)
					mustEnvironment(t, err)
					batch.ObsoleteDeletes = page.Rows
					batch.ObsoleteConsulted = []ObsoletePageWitnessV1{page.Witness, repeated.Witness}
					if variant == "proof-target" || variant == "proof-target-third" {
						batch.Mutations = []Mutation{{DBI: readDBIsLiteral()[3], Key: hash[:], BeforePresent: true, AfterKind: AfterKind(1)}}
					}
					return batch, nil
				})
				if result != nil {
					largeNativeCached(t, store)
				}
			}
			evidence := fixtureLargeEvidence{}
			if variant == "overlay" || variant == "proof-target" || variant == "retained-match" {
				run()
			} else {
				var fixtureErr error
				evidence, fixtureErr = fixtureLargeFault(store, mode, rank, faultKey, run)
				mustEnvironment(t, fixtureErr)
			}
			if variant == "overlay" || variant == "proof-target" || variant == "retained-match" {
				if truth.String() != "NEW" || int(stage) != 3 || result != nil || string(store.state) != "OPEN" {
					t.Fatal("joint overlay lost a predicate", variant, truth, stage, result, store.state)
				}
				if variant == "retained-match" {
					obsoleteRawImage(t, store, 1, rawTarget, nil)
					obsoleteRawImage(t, store, 1, rawResidual, []byte{0x31})
					obsoleteRawImage(t, store, 1, source, sourceValue)
					obsoleteRawImage(t, store, 5, destination, sourceValue)
					obsoleteRawImage(t, store, 4, hash[:], []byte{0x61})
					obsoleteRawImage(t, store, 5, first, []byte{0x41})
					obsoleteRawImage(t, store, 5, second, []byte{0x51})
				} else if variant == "overlay" {
					obsoleteRawImage(t, store, 1, source, nil)
					obsoleteRawImage(t, store, 5, destination, sourceValue)
				} else {
					obsoleteRawImage(t, store, 3, hash[:], nil)
					obsoleteRawImage(t, store, 5, first, nil)
					obsoleteRawImage(t, store, 5, second, []byte{0x51})
				}
				return
			}
			commit, ok := result.(*CommitError)
			if !ok || truth.String() != "UNKNOWN" || int(stage) != 3 || commit.Truth.String() != "UNKNOWN" || string(store.state) != "CLOSED" || evidence.commits != 1 {
				t.Fatal("joint mismatch hidden", variant, truth, stage, result, evidence)
			}
			obsoleteRequireError(t, commit.Cause, "update", "Capacity", 28, expectedNativeDiagnostic(28))
			if variant == "later-failure" {
				obsoleteRequireError(t, commit.ReadbackCause, "update", "IO", 5, expectedNativeDiagnostic(5))
				if evidence.gets != 1 || evidence.drift != 1 {
					t.Fatal("later admitted failure not reached", evidence)
				}
			} else if commit.ReadbackCause != nil {
				t.Fatal("unexpected joint readback cause", commit.ReadbackCause)
			}
			reopened, err := Open(path, cfg)
			consultedTrack(t, reopened, err)
			if retained {
				for _, image := range []struct {
					rank       uint8
					key, value []byte
				}{{1, rawTarget, nil}, {1, rawResidual, []byte{0x31}}, {1, source, sourceValue}, {4, hash[:], []byte{0x61}}, {5, first, []byte{0x41}}, {5, second, []byte{0x51}}, {5, destination, sourceValue}, {2, indexKey, indexValue}, {3, hash[:], header}} {
					want := image.value
					if image.rank == rank && bytes.Equal(image.key, faultKey) {
						want = []byte{0x7f}
					}
					obsoleteRawImage(t, reopened, image.rank, image.key, want)
				}
			} else if variant == "shared-index-drift" {
				obsoleteRawImage(t, reopened, 2, indexKey, []byte{0x7f})
				obsoleteRawImage(t, reopened, 3, hash[:], header)
				obsoleteRawImage(t, reopened, 5, first, nil)
				obsoleteRawImage(t, reopened, 5, second, []byte{0x51})
			} else if variant == "shared-family-sibling" {
				obsoleteRawImage(t, reopened, 5, second, []byte{0x7f})
				obsoleteRawImage(t, reopened, 3, hash[:], header)
			} else {
				obsoleteRawImage(t, reopened, rank, faultKey, []byte{0x7f})
			}
			if variant == "later-failure" {
				counter := consultedCounter(t, 1)
				obsoleteRawImage(t, reopened, 0, counter.Key, counter.Literal)
			}
		})
	}
}

func TestLargeImageV1ObsoleteLegacyPriority(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	cfg.Upper = 512 << 20
	store, err := Create(path, cfg)
	consultedTrack(t, store, err)
	seed := consultedCounter(t, 9)
	largeCommit(t, store, Batch{Mutations: []Mutation{seed}})
	mustEnvironment(t, fixtureLargeBulk(store, 1, 3, 68_000_125))
	header := bytes.Repeat([]byte{0x5a}, 116)
	rows := make([]ConsultedRow, 3)
	for i := range rows {
		binary.BigEndian.PutUint32(header, uint32(i))
		hash := sha3.Sum256(header)
		rows[i] = ConsultedRow{DBI: readDBIsLiteral()[4], Key: bytes.Clone(hash[:])}
	}
	sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i].Key, rows[j].Key) < 0 })
	batch := Batch{Consulted: rows, LargeConsulted: []LargeImageSelectorV1{{Kind: 9}}}
	callback := func(reader *Reader) (Batch, error) {
		page, err := reader.ObsoleteGenerationPageV1(9, 3, nil, 1)
		mustEnvironment(t, err)
		batch.ObsoleteDeletes = page.Rows
		batch.ObsoleteConsulted = []ObsoletePageWitnessV1{page.Witness}
		return batch, nil
	}
	truth, stage, result := store.Update(callback)
	obsoleteRequireError(t, result, "update", "Capacity", -30417, "Update Batch exceeds bound")
	if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "OPEN" {
		t.Fatal("raw merged plan changed captured-value priority", truth, stage, result, store.state)
	}
	obsoleteRawImage(t, store, 0, seed.Key, seed.Literal)
	batch.LargeConsulted = make([]LargeImageSelectorV1, 2881)
	evidence, fixtureErr := fixtureLargeFault(store, 28, 4, rows[0].Key, func() {
		truth, stage, result = store.Update(callback)
		largeNativeCached(t, store)
	})
	mustEnvironment(t, fixtureErr)
	obsoleteRequireError(t, result, "update", "IO", 5, expectedNativeDiagnostic(5))
	if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "CLOSED" || evidence.gets != 1 || evidence.aborts != 1 {
		t.Fatal("raw merged plan hid capture error behind large count", truth, stage, result, evidence, store.state)
	}
	reopened, err := Open(path, cfg)
	consultedTrack(t, reopened, err)
	obsoleteRawImage(t, reopened, 0, seed.Key, seed.Literal)
}

func TestCanonicalContextWindowV1Native(t *testing.T) {
	for _, row := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"B01 B04 B05 B09-B15 admission and query order", contextNativeOrder},
		{"B14 exact incomplete source and native proofs", contextNativeWidths},
		{"B16 B25 source cause and cleanup", contextNativeSource},
		{"B17 B20 B21 B24 crossed and write drift", contextNativeTruth},
		{"B19 B23 original header and late faults", contextNativeOriginal},
		{"B06 B23 B27 joint scopes", contextNativeJoint},
		{"B26 callback arbitration", contextNativeCallbacks},
		{"B15 legacy source precedence", contextNativeLegacyPriority},
		{"B25 Q and close busy at existing projection owner", contextNativeQClose},
	} {
		t.Run(row.name, row.run)
	}
}

func contextProbe(t *testing.T, store *Store, run func()) SelectedDamageEvidence {
	t.Helper()
	owner, err := NewOperationReservationOwner(154_611_151)
	mustEnvironment(t, err)
	evidence, err := FixtureSelectedDamage(store, owner, SelectedDamageScenario(1), 0, nil, run)
	mustEnvironment(t, err)
	return evidence
}

func contextNativeOrder(t *testing.T) {
	for _, variant := range []string{"nil", "nil reverse", "one", "eleven", "retarget", "clone", "scalar", "zero count", "bad height", "generation before capacity", "height before capacity", "over count", "maximum count", "capacity before overflow", "overflow", "legacy", "Large", "Obsolete", "static later index", "obsolete index", "derived header", "early missing"} {
		t.Run(variant, func(t *testing.T) {
			store, _, _ := consultedStore(t)
			window := CanonicalContextWindowV1{9, 0, 3}
			if variant == "one" {
				window.Count = 1
			}
			if variant == "eleven" {
				window.FirstHeight, window.Count = 1, 11
			}
			if variant == "retarget" {
				window.Count = 10_080
			}
			rows := contextSeed(t, store, window)
			batch := Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &window}
			wantIndex, wantHeader := uint64(window.Count), uint64(window.Count)
			refusal := false
			evidence := contextProbe(t, store, func() {
				truth, stage, err := store.Update(func(reader *Reader) (Batch, error) {
					switch variant {
					case "nil", "nil reverse":
						batch.ContextConsulted, batch.Reverse = nil, variant == "nil reverse"
						wantIndex, wantHeader = 0, 0
					case "clone":
						plan, err := updateOwnedBatch(batch, reader)
						mustEnvironment(t, err)
						before := fixtureLargeNativeCalls()
						_, err = updateOwnedContext(&window, plan, largeImageScope{})
						mustEnvironment(t, err)
						if fixtureLargeNativeCalls() != before {
							t.Fatal("descriptor clone queried data")
						}
					case "scalar":
						window.Generation = 0
						refusal, wantIndex, wantHeader = true, 0, 0
					case "zero count", "bad height", "generation before capacity", "height before capacity", "over count", "maximum count", "capacity before overflow", "overflow":
						refusal, wantIndex, wantHeader = true, 0, 0
						switch variant {
						case "zero count":
							window.Count = 0
						case "bad height":
							window.FirstHeight = 0x100000000
						case "generation before capacity":
							window.Generation, window.Count = 0, 10_081
						case "height before capacity":
							window.FirstHeight, window.Count = 0x100000000, 10_081
						case "over count":
							window.Count = 10_081
						case "maximum count":
							window.Count = 0xffffffff
						case "capacity before overflow":
							window.FirstHeight, window.Count = 0xffffffff, 10_081
						case "overflow":
							window.FirstHeight, window.Count = 0xffffffff, 2
						}
					case "legacy":
						batch.Consulted = []ConsultedRow{{}}
						refusal, wantIndex, wantHeader = true, 0, 0
					case "Large":
						batch.LargeConsulted = []LargeImageSelectorV1{{Kind: 99}}
						refusal, wantIndex, wantHeader = true, 0, 0
					case "Obsolete":
						batch.ObsoleteConsulted = []ObsoletePageWitnessV1{{}}
						refusal, wantIndex, wantHeader = true, 0, 0
					case "static later index":
						window.Generation = 10
						batch.Consulted = []ConsultedRow{{DBI: rows[6].DBI, Key: canonicalForwardKeyLiteral(10, 2)}}
						refusal, wantIndex, wantHeader = true, 1, 0
						// The one index query belongs to legacy qualification, never context.
					case "obsolete index":
						page, err := reader.ObsoleteGenerationPageV1(9, 2, nil, 1)
						mustEnvironment(t, err)
						batch.ObsoleteDeletes, batch.ObsoleteConsulted = page.Rows, []ObsoletePageWitnessV1{page.Witness}
						refusal, wantIndex, wantHeader = true, 0, 0
					case "derived header":
						batch.Mutations = append(batch.Mutations, canonicalDelete(rows[1]))
						refusal, wantIndex, wantHeader = true, 1, 0
					case "early missing":
						window.Generation = 10
						batch.Consulted = []ConsultedRow{{DBI: rows[7].DBI, Key: rows[7].Key}}
						refusal, wantIndex, wantHeader = true, 1, 1
					}
					contextSort(batch.Mutations)
					return batch, nil
				})
				if refusal {
					diagnostic, class, code := "invalid Update Batch", "InvalidInput", 22
					if variant == "early missing" {
						diagnostic, class, code = "canonical context OLD image is incomplete", "StateMismatch", -30779
					}
					if variant == "over count" || variant == "maximum count" || variant == "capacity before overflow" {
						diagnostic, class, code = "Update Batch exceeds bound", "Capacity", -30417
					}
					contextError(t, err, class, code, diagnostic)
					if truth != 1 || stage != 1 || string(store.state) != "OPEN" {
						t.Fatal("admission tuple", truth, stage, err)
					}
				} else if truth != 2 || stage != 3 || err != nil || string(store.state) != "OPEN" {
					t.Fatal("context success tuple", truth, stage, err)
				}
			})
			if refusal {
				if evidence.BeginWrite != 0 || evidence.Deletes != 0 || evidence.Commits != 0 {
					t.Fatal("refusal reached write", evidence)
				}
				if variant != "obsolete index" && (evidence.OldGets[2] != wantIndex || evidence.OldGets[3] != wantHeader) {
					t.Fatal("admission exact source query order", variant, evidence)
				}
				consultedRequireImage(t, store, readDBIsLiteral()[0], consultedCounter(t, 900).Key, nil, false, "query refusal target absent")
				valid := CanonicalContextWindowV1{9, 0, 3}
				largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &valid})
			} else {
				// Qualification, prewrite, final: one ascending pair walk apiece.
				if evidence.OldGets[2] != 3*wantIndex || evidence.OldGets[3] != 3*wantHeader || evidence.BeginWrite != 1 || evidence.Commits != 1 {
					t.Fatal("complete pair visits", evidence)
				}
			}
			contextImages(t, store, rows)
		})
	}
}

func contextNativeWidths(t *testing.T) {
	for _, rank := range []uint8{2, 3} {
		width := 104
		if rank == 3 {
			width = 116
		}
		for _, size := range []int{-1, 0, width - 1, width + 1} {
			t.Run(fmt.Sprintf("rank%d/size%d", rank, size), func(t *testing.T) {
				store, _, _ := consultedStore(t)
				window := CanonicalContextWindowV1{9, 0, 1}
				rows := contextRows(window)
				for i, row := range rows[:2] {
					value := row.Literal
					if uint8(i+2) == rank {
						if size == -1 {
							continue
						}
						value = make([]byte, size)
						copy(value, row.Literal)
					}
					mustEnvironment(t, fixtureSeedPrefixRawRow(store, row.DBI, row.Key, value))
				}
				batch := Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &window}
				if rank == 2 {
					batch.Mutations = append(batch.Mutations, canonicalDelete(rows[1]))
				}
				evidence := contextProbe(t, store, func() {
					contextRefusal(t, store, batch, "StateMismatch", -30779, "canonical context OLD image is incomplete")
				})
				if evidence.BeginWrite != 0 || evidence.Commits != 0 || evidence.Deletes != 0 {
					t.Fatal("Q reached write", evidence)
				}
				// Direct proof must report Q, rather than derive an unsafe header or call inequality equal.
				mustEnvironment(t, store.View(func(reader *Reader) error {
					scope := largeImageScope{context: window, contextPresent: true, maxKey: 2022, selectors: []LargeImageSelectorV1{{Kind: 1}}}
					handles := store.dbis
					handles[4] = ^handles[4]
					_, err := updateNativeLargeEqual(reader.txn, reader.txn, handles, nil, scope)
					contextError(t, err, "StateMismatch", -30779, "canonical context OLD image is incomplete")
					// An Obsolete point has its own later native error, without a Large selector masking order.
					obsoleteScope := largeImageScope{context: window, contextPresent: true, maxKey: 2022, points: []obsoletePoint{{rank: 1, key: append(obsoleteGenerationLiteral(9), 1)}}}
					handles = store.dbis
					handles[1] = ^handles[1]
					_, err = updateNativeLargeEqual(reader.txn, reader.txn, handles, nil, obsoleteScope)
					contextError(t, err, "StateMismatch", -30779, "canonical context OLD image is incomplete")
					obsoleteScope.contextPresent = false
					_, err = updateNativeLargeEqual(reader.txn, reader.txn, handles, nil, obsoleteScope)
					contextError(t, err, "LocalInvariant", -30780, "MDBX_BAD_DBI: The specified DBI-handle is invalid or changed by another thread/transaction")
					outcome := store.updateNative(updateNativePlan(t, consultedCounter(t, 900)), nil, reader.txn, scope)
					contextError(t, outcome.primary, "StateMismatch", -30779, "canonical context OLD image is incomplete")
					requireUpdateTruth(t, outcome, 1, false, outcome.primary, nil)
					if outcome.stage != 1 {
						t.Fatal("unqualified prewrite Q stage")
					}
					outcome = updateNativeReadback(store.env, store.dbis, nil, nil, reader.txn, nativeError(operationUpdate, 28), scope)
					contextError(t, outcome.secondary, "StateMismatch", -30779, "canonical context OLD image is incomplete")
					requireUpdateTruth(t, outcome, 3, true, outcome.primary, outcome.secondary)
					return nil
				}))
				want := []byte(nil)
				if size >= 0 {
					want = make([]byte, size)
					copy(want, rows[int(rank)-2].Literal)
				}
				obsoleteRawImage(t, store, rank, rows[int(rank)-2].Key, want)
				other := rows[3-int(rank)]
				obsoleteRawImage(t, store, other.DBI.Rank, other.Key, other.Literal)
				for _, row := range rows[:2] {
					mustEnvironment(t, fixtureSeedPrefixRawRow(store, row.DBI, row.Key, row.Literal))
				}
				batch.Mutations = batch.Mutations[:1]
				largeCommit(t, store, batch)
				contextImages(t, store, rows[:2])
			})
		}
	}
	t.Run("zero hash and repeated header physical observations", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		window := CanonicalContextWindowV1{9, 0, 2}
		index, header, hash := make([]byte, 104), make([]byte, 116), make([]byte, 32)
		for _, height := range []uint64{0, 1} {
			mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[2], canonicalForwardKeyLiteral(9, height), index))
		}
		mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[3], hash, header))
		evidence := contextProbe(t, store, func() {
			largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &window})
		})
		if evidence.OldGets[2] != 6 || evidence.OldGets[3] != 6 {
			t.Fatal("repeated OLD header was omitted", evidence)
		}
		obsoleteRawImage(t, store, 2, canonicalForwardKeyLiteral(9, 0), index)
		obsoleteRawImage(t, store, 2, canonicalForwardKeyLiteral(9, 1), index)
		obsoleteRawImage(t, store, 3, hash, header)
	})
}

func contextNativeSource(t *testing.T) {
	for _, variant := range []string{"index first", "header first", "last index", "last header", "early Q", "early fault", "shape pointer", "shape length", "EIO consumed abort", "EIO retained", "EIO close", "Q consumed abort", "Q retained"} {
		t.Run(variant, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			window := CanonicalContextWindowV1{9, 0, 3}
			rows := contextSeed(t, store, window)
			rank, key, mode := uint8(2), rows[0].Key, uint32(28)
			if variant == "header first" {
				rank, key = 3, rows[1].Key
			}
			if variant == "last index" {
				key = rows[6].Key
			}
			if variant == "last header" || variant == "early Q" {
				rank, key = 3, rows[7].Key
			}
			if variant == "early Q" {
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, rows[0].DBI, rows[0].Key, rows[0].Literal[:103]))
			}
			if variant == "shape pointer" {
				mode = 17
			}
			if variant == "shape length" {
				mode = 18
			}
			if variant == "EIO retained" || variant == "Q retained" {
				mode = 2
			}
			if variant == "EIO close" {
				mode = 24
			}
			if variant == "Q consumed abort" {
				mode = 9
			}
			if strings.HasPrefix(variant, "Q ") {
				window.Generation = 10
			}
			batch := Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &window}
			if variant == "early fault" {
				batch.Mutations = append(batch.Mutations, canonicalDelete(rows[7]))
			}
			var truth CommitTruth
			var stage UpdateStage
			var result error
			var saved *Reader
			var evidence fixtureLargeEvidence
			run := func() {
				truth, stage, result = store.Update(func(reader *Reader) (Batch, error) {
					saved = reader
					if variant == "EIO retained" || variant == "EIO close" {
						_, _, err := reader.Get(rows[0].DBI, rows[0].Key)
						mustEnvironment(t, err)
					}
					return batch, nil
				})
			}
			var probe SelectedDamageEvidence
			if variant == "EIO consumed abort" {
				owner, err := NewOperationReservationOwner(154_611_151)
				mustEnvironment(t, err)
				probe, err = FixtureSelectedDamage(store, owner, SelectedDamageScenario(5), rank, key, run)
				mustEnvironment(t, err)
			} else {
				probe = contextProbe(t, store, func() {
					var err error
					evidence, err = fixtureLargeFault(store, mode, rank, key, run)
					mustEnvironment(t, err)
				})
			}
			primary, state := result, "CLOSED"
			if variant == "EIO consumed abort" || variant == "Q consumed abort" {
				parts, ok := result.(interface{ Unwrap() []error })
				if !ok || len(parts.Unwrap()) != 2 {
					t.Fatal("source/abort ordered causes", result)
				}
				primary = parts.Unwrap()[0]
				engine := requireEnvironmentError(t, parts.Unwrap()[1], EngineClass("IO"), operationAbort, 5, "error 5")
				if engine.Cause != nil {
					t.Fatal("abort cause identity")
				}
			}
			if variant == "EIO retained" || variant == "Q retained" {
				engine := requireEnvironmentError(t, result, EngineClass("LocalInvariant"), operationAbort, -30416, "MDBX_THREAD_MISMATCH: A thread has attempted to use a not owned object, e.g. a transaction that started by another thread")
				if engine.Cause == nil || !engine.ReopenRequired {
					t.Fatal("retained abort lost source cause/reopen")
				}
				primary, state = engine.Cause, "POISONED_THREAD"
			}
			if variant == "EIO close" {
				engine := requireEnvironmentError(t, result, EngineClass("Concurrency"), operationClose, -30778, "MDBX_BUSY: Another write transaction is running, or environment is already used while opening with MDBX_EXCLUSIVE flag")
				primary, state = engine.Cause, "CLOSE_BLOCKED"
			}
			if variant == "early Q" || strings.HasPrefix(variant, "Q ") {
				contextError(t, primary, "StateMismatch", -30779, "canonical context OLD image is incomplete")
			} else if strings.HasPrefix(variant, "shape") {
				contextError(t, primary, "LocalInvariant", -30779, "mdbx_get returned invalid result shape")
			} else {
				contextError(t, primary, "IO", 5, "error 5")
			}
			if variant == "early Q" {
				state = "OPEN"
			}
			if truth != 1 || stage != 1 || string(store.state) != state || saved == nil || saved.usable() || probe.BeginWrite != 0 || probe.Commits != 0 || probe.Deletes != 0 {
				t.Fatal("source refusal stage/resource/no-write", truth, stage, result, store.state, probe)
			}
			if state == "OPEN" {
				if evidence.gets != 0 || probe.OldGets[2] != 1 || probe.OldGets[3] != 0 {
					t.Fatal("earlier Q lost first-error order", evidence)
				}
				if store.env == nil || store.writer == nil || store.txn != nil || store.terminal != nil {
					t.Fatal("earlier Q reusable resource tuple")
				}
				obsoleteRawImage(t, store, 2, rows[0].Key, rows[0].Literal[:103])
				contextImages(t, store, rows[1:])
				consultedRequireImage(t, store, readDBIsLiteral()[0], consultedCounter(t, 900).Key, nil, false, "earlier Q durable target")
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, rows[0].DBI, rows[0].Key, rows[0].Literal))
				largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &window})
				contextImages(t, store, rows)
				return
			}
			if result != store.terminal {
				t.Fatal("source terminal identity")
			}
			contextNativeResources(t, store, state)
			largeNativeCached(t, store)
			mustEnvironment(t, fixtureLargeRelease(store))
			reopened, err := Open(path, cfg)
			consultedTrack(t, reopened, err)
			contextImages(t, reopened, rows)
			consultedRequireImage(t, reopened, readDBIsLiteral()[0], consultedCounter(t, 900).Key, nil, false, "source refusal durable target")
			window.Generation = 9
			largeCommit(t, reopened, Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &window})
		})
	}
}

func contextNativeTruth(t *testing.T) {
	t.Run("unchanged context and third target", func(t *testing.T) {
		store, path, cfg := consultedStore(t)
		window := CanonicalContextWindowV1{9, 0, 3}
		rows := contextSeed(t, store, window)
		target := consultedCounter(t, 900)
		truth, stage, result, evidence := largeFaultCommit(t, store, 6, 0, target.Key, Batch{Mutations: []Mutation{target}, ContextConsulted: &window})
		commit, ok := result.(*CommitError)
		if !ok || truth != 3 || stage != 3 || commit.Truth != 3 || commit.ReadbackCause != nil || store.terminalTruth != 3 || evidence.commits != 1 {
			t.Fatal("unchanged context third target complete tuple", truth, stage, result, evidence)
		}
		contextError(t, commit.Cause, "Capacity", 28, "error 28")
		contextNativeResources(t, store, "CLOSED")
		reopened, err := Open(path, cfg)
		consultedTrack(t, reopened, err)
		contextImages(t, reopened, rows)
		obsoleteRawImage(t, reopened, 0, target.Key, []byte{0x7f})
	})
	for _, rank := range []uint8{2, 3} {
		for _, mode := range []uint32{4, 5, 7, 12, 23, 6, 13, 14, 9, 10, 11, 15, 16} {
			t.Run(fmt.Sprintf("rank%d/mode%d", rank, mode), func(t *testing.T) {
				store, path, cfg := consultedStore(t)
				window := CanonicalContextWindowV1{9, 0, 3}
				rows := contextSeed(t, store, window)
				selected := rows[6+int(rank)-2]
				batch := Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &window}
				truth, stage, result, evidence := largeFaultCommit(t, store, mode, rank, selected.Key, batch)
				if mode == 13 || mode == 14 {
					diagnostic, wantStage := "final update image mismatch", UpdateStage(2)
					if mode == 14 {
						diagnostic, wantStage = "OLD/write snapshot mismatch", 1
					}
					contextError(t, result, "StateMismatch", -30779, diagnostic)
					if truth != 1 || stage != wantStage || evidence.commits != 0 || string(store.state) != "CLOSED" {
						t.Fatal("public drift phase", truth, stage, result, evidence)
					}
				} else {
					want := CommitTruth(3)
					if mode == 7 {
						want = 1
					}
					if mode == 12 || mode >= 9 && mode <= 11 || mode == 15 || mode == 16 {
						want = 2
					}
					var commit *CommitError
					if !errors.As(result, &commit) || truth != want || stage != 3 || commit.Truth != want || store.terminalTruth != want || evidence.commits != 1 {
						t.Fatal("crossed context complete tuple", truth, stage, result, evidence)
					}
					contextError(t, commit.Cause, "Capacity", 28, "error 28")
					if mode == 23 {
						contextError(t, commit.ReadbackCause, "IO", 5, "error 5")
					} else if mode == 9 || mode == 16 {
						requireEnvironmentError(t, commit.ReadbackCause, EngineClass("IO"), operationAbort, 5, "error 5")
					} else if mode == 10 || mode == 15 {
						requireEnvironmentError(t, commit.ReadbackCause, EngineClass("LocalInvariant"), operationAbort, -30416, "MDBX_THREAD_MISMATCH: A thread has attempted to use a not owned object, e.g. a transaction that started by another thread")
					} else if mode != 11 && commit.ReadbackCause != nil {
						t.Fatal("mismatch invented readback cause", commit.ReadbackCause)
					}
				}
				state := "CLOSED"
				if mode == 10 || mode == 15 {
					state = "POISONED_THREAD"
				}
				if mode == 11 {
					state = "CLOSE_BLOCKED"
					closeErr := requireEnvironmentError(t, result, EngineClass("Concurrency"), operationClose, -30778, "MDBX_BUSY: Another write transaction is running, or environment is already used while opening with MDBX_EXCLUSIVE flag")
					commit, ok := closeErr.Cause.(*CommitError)
					if !ok || commit.Truth != truth || commit.ReadbackCause != nil {
						t.Fatal("close lost exact commit cause", closeErr.Cause)
					}
				}
				if string(store.state) != state {
					t.Fatal("crossed resource state", store.state)
				}
				contextNativeResources(t, store, state)
				mustEnvironment(t, fixtureLargeRelease(store))
				reopened, err := Open(path, cfg)
				consultedTrack(t, reopened, err)
				wantRow := selected.Literal
				if mode == 4 {
					wantRow = nil
				}
				if mode == 5 || mode == 6 || mode == 14 {
					wantRow = []byte{0x7f}
				}
				obsoleteRawImage(t, reopened, rank, selected.Key, wantRow)
				counter := batch.Mutations[0]
				wantCounter := counter.Literal
				if mode == 7 || mode == 13 || mode == 14 {
					wantCounter = nil
				}
				obsoleteRawImage(t, reopened, 0, counter.Key, wantCounter)
			})
		}
	}
}

func contextNativeOriginal(t *testing.T) {
	for _, variant := range []string{"candidate hash", "both false", "later context", "following Large", "following Obsolete"} {
		t.Run(variant, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			window := CanonicalContextWindowV1{9, 0, 3}
			rows := contextSeed(t, store, window)
			alternate := contextRows(CanonicalContextWindowV1{10, 0, 1})[1]
			largeCommit(t, store, Batch{Mutations: []Mutation{alternate}})
			plan := updateNativePlan(t, consultedCounter(t, 900))
			scope, err := updateOwnedContext(&window, plan, largeImageScope{maxKey: 2022})
			mustEnvironment(t, err)
			wantTarget := plan[0].literal
			if variant == "both false" {
				wantTarget = bytes.Repeat([]byte{0x31}, 16)
			}
			mode, faultRank, faultKey := uint32(8), uint8(3), rows[7].Key
			if variant == "candidate hash" {
				faultKey = rows[1].Key
			}
			if variant == "following Large" {
				faultRank, faultKey = 4, rows[1].Key
				scope.selectors = []LargeImageSelectorV1{{Kind: 1}}
				copy(scope.selectors[0].Hash[:], faultKey)
			}
			if variant == "following Obsolete" {
				faultRank, faultKey = 1, append(obsoleteGenerationLiteral(9), 1)
				scope.points = []obsoletePoint{{rank: 1, key: faultKey}}
			}
			var outcome updateNativeOutcome
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			_, fixtureErr := fixtureLargeFault(store, mode, faultRank, faultKey, func() {
				mustEnvironment(t, store.View(func(reader *Reader) error {
					if infrastructure, err := contextQualify(reader, plan, scope); infrastructure || err != nil {
						t.Fatal("original source qualification", infrastructure, err)
					}
					change := contextChange(rows, 0, 2)
					if variant == "candidate hash" {
						change[0].literal = bytes.Clone(rows[0].Literal)
						copy(change[0].literal[:32], alternate.Key)
						change = append(change, ownedMutation{dbi: readDBIsLiteral()[7], key: canonicalOwnerKeyLiteral(9, sha3.Sum256(alternate.Literal)), after: AfterKind(2), literal: rows[0].Key[8:]})
						change[1].after, change[1].literal = AfterKind(1), nil
					}
					sort.Slice(change, func(i, j int) bool {
						return updateKeyOrdered(change[i].dbi.Rank, change[i].key, change[j].dbi.Rank, change[j].key)
					})
					if variant != "both false" {
						changed := store.updateNative(change, nil, reader.txn)
						requireUpdateTruth(t, changed, 2, true, changed.primary, nil)
						contextError(t, changed.primary, "Capacity", 28, "error 28")
					}
					third := append([]ownedMutation(nil), plan...)
					third[0].literal = wantTarget
					changed := store.updateNative(third, nil, reader.txn)
					requireUpdateTruth(t, changed, 2, true, changed.primary, nil)
					contextError(t, changed.primary, "Capacity", 28, "error 28")
					outcome = updateNativeReadback(store.env, store.dbis, plan, nil, reader.txn, nativeError(operationUpdate, 28), scope)
					return nil
				}))
			})
			mustEnvironment(t, fixtureErr)
			if outcome.truth != 3 || outcome.stage != 3 || !outcome.commitAttempted {
				t.Fatal("late context fault truth", outcome)
			}
			contextError(t, outcome.primary, "Capacity", 28, "error 28")
			if variant == "following Large" {
				requireEnvironmentError(t, outcome.secondary, EngineClass("IO"), operationGet, 5, "error 5")
			} else {
				contextError(t, outcome.secondary, "IO", 5, "error 5")
			}
			truth, stage, result := store.applyUpdateOutcome(outcome, nil, nil, false)
			commit, ok := result.(*CommitError)
			if !ok || truth != 3 || stage != 3 || commit.Truth != 3 || commit.Cause != outcome.primary || commit.ReadbackCause != outcome.secondary || store.terminalTruth != 3 {
				t.Fatal("original-header/late-fault CommitError tuple", truth, stage, result)
			}
			contextNativeResources(t, store, "CLOSED")
			largeNativeCached(t, store)
			reopened, err := Open(path, cfg)
			consultedTrack(t, reopened, err)
			obsoleteRawImage(t, reopened, 3, rows[1].Key, rows[1].Literal)
			obsoleteRawImage(t, reopened, 3, alternate.Key, alternate.Literal)
			obsoleteRawImage(t, reopened, 0, plan[0].key, wantTarget)
		})
	}
}

func contextNativeJoint(t *testing.T) {
	for _, variant := range []string{"unchanged", "repeat header", "legacy", "context", "Large", "Obsolete", "later fault"} {
		t.Run(variant, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			indexKey, indexValue, hash, header := obsoleteProjectionSeed(t, store, 9, 1)
			window := CanonicalContextWindowV1{9, 1, 1}
			if variant == "repeat header" {
				window.Count = 2
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[2], canonicalForwardKeyLiteral(9, 2), indexValue))
			}
			legacy := consultedCounter(t, 901)
			largeCommit(t, store, Batch{Mutations: []Mutation{legacy}})
			familyKey := append(bytes.Clone(hash[:]), 2)
			obsoleteSeed(t, store, 4, hash[:], []byte{0x61})
			obsoleteSeed(t, store, 5, familyKey, []byte{0x51})
			var truth CommitTruth
			var stage UpdateStage
			var result error
			run := func() {
				truth, stage, result = store.Update(func(reader *Reader) (Batch, error) {
					page, err := reader.ObsoleteGenerationPageV1(9, 2, nil, 1440)
					mustEnvironment(t, err)
					wantRows := 1
					if variant == "repeat header" {
						wantRows = 2
					}
					if len(page.Rows) != wantRows || !bytes.Equal(page.Rows[0].Key(), canonicalForwardKeyLiteral(9, 1)) {
						t.Fatal("joint physical index count/first key", len(page.Rows))
					}
					if wantRows == 2 && !bytes.Equal(page.Rows[1].Key(), canonicalForwardKeyLiteral(9, 2)) {
						t.Fatal("joint repeated-header second index key")
					}
					undo, err := reader.ObsoleteUndoPageV1(page.Rows[0], nil, 7)
					mustEnvironment(t, err)
					return Batch{Mutations: []Mutation{consultedCounter(t, 900)}, Consulted: []ConsultedRow{{DBI: legacy.DBI, Key: legacy.Key}}, ContextConsulted: &window, LargeConsulted: []LargeImageSelectorV1{{Kind: 1, Hash: hash}}, ObsoleteConsulted: []ObsoletePageWitnessV1{undo.Witness}}, nil
				})
			}
			rank, key, mode := uint8(0), legacy.Key, uint32(5)
			switch variant {
			case "context":
				rank, key = 2, indexKey
			case "Large":
				rank, key = 4, hash[:]
			case "Obsolete":
				rank, key = 5, familyKey
			case "later fault":
				rank, key, mode = 2, indexKey, 29
			}
			var evidence fixtureLargeEvidence
			if variant == "unchanged" || variant == "repeat header" {
				run()
			} else {
				var err error
				evidence, err = fixtureLargeFault(store, mode, rank, key, run)
				mustEnvironment(t, err)
			}
			if variant == "unchanged" || variant == "repeat header" {
				if truth != 2 || stage != 3 || result != nil || string(store.state) != "OPEN" {
					t.Fatal("joint unchanged/repeated header", truth, stage, result)
				}
				obsoleteRawImage(t, store, 2, indexKey, indexValue)
				obsoleteRawImage(t, store, 3, hash[:], header)
				if variant == "repeat header" {
					obsoleteRawImage(t, store, 2, canonicalForwardKeyLiteral(9, 2), indexValue)
				}
				return
			}
			commit, ok := result.(*CommitError)
			if !ok || truth != 3 || stage != 3 || commit.Truth != 3 || store.terminalTruth != 3 || string(store.state) != "CLOSED" || evidence.commits != 1 {
				t.Fatal("joint predicate independently failed", variant, truth, stage, result)
			}
			contextError(t, commit.Cause, "Capacity", 28, "error 28")
			if variant == "later fault" {
				requireEnvironmentError(t, commit.ReadbackCause, EngineClass("IO"), operationGet, 5, "error 5")
			} else if commit.ReadbackCause != nil {
				t.Fatal("joint mismatch cause", commit.ReadbackCause)
			}
			reopened, err := Open(path, cfg)
			consultedTrack(t, reopened, err)
			obsoleteRawImage(t, reopened, rank, key, []byte{0x7f})
		})
	}
}

func contextNativeCallbacks(t *testing.T) {
	for _, variant := range []string{"nil", "exact", "wrapped", "distinct", "typed-nil", "panic"} {
		t.Run(variant, func(t *testing.T) {
			store, _, _ := consultedStore(t)
			window := CanonicalContextWindowV1{0, 0, 10_081}
			key := consultedCounter(t, 901).Key
			var saved *Reader
			var recorded, application, result error
			var truth CommitTruth
			var stage UpdateStage
			panicValue := &struct{ value string }{"context callback"}
			var recovered any
			evidence := contextProbe(t, store, func() {
				func() {
					defer func() { recovered = recover() }()
					_, err := fixtureLargeFault(store, 28, 0, key, func() {
						truth, stage, result = store.Update(func(reader *Reader) (Batch, error) {
							saved = reader
							_, _, recorded = reader.Get(readDBIsLiteral()[0], key)
							switch variant {
							case "exact":
								application = recorded
							case "wrapped":
								application = fmt.Errorf("context wrapped: %w", recorded)
							case "distinct":
								application = errors.New("context distinct")
							case "typed-nil":
								application = (*largeTypedNil)(nil)
							case "panic":
								panic(panicValue)
							}
							return Batch{Mutations: []Mutation{consultedCounter(t, 900)}, ContextConsulted: &window}, application
						})
					})
					mustEnvironment(t, err)
				}()
			})
			if saved == nil || saved.usable() || string(store.state) != "CLOSED" || evidence.BeginWrite != 0 || evidence.OldGets[2] != 0 || evidence.OldGets[3] != 0 || store.env != nil || store.writer != nil || store.txn != nil {
				t.Fatal("callback arbitration queried context or lost cleanup", evidence)
			}
			if variant == "panic" {
				if recovered != panicValue {
					t.Fatal("original callback panic")
				}
				result = store.terminal
			} else if truth != 1 || stage != 1 {
				t.Fatal("callback phase")
			}
			largeCallbackCauses(t, result, application, recorded, 1)
			largeNativeCached(t, store)
		})
	}
}

func contextNativeResources(t *testing.T, store *Store, state string) {
	t.Helper()
	if string(store.state) != state || store.terminal == nil {
		t.Fatal("native terminal state/error", store.state)
	}
	switch state {
	case "CLOSED":
		if store.env != nil || store.writer != nil || store.txn != nil || store.config != (ConfigV1{}) || store.dbis != (Store{}).dbis {
			t.Fatal("consumed native resource tuple")
		}
	case "POISONED_THREAD":
		if store.env == nil || store.writer == nil || store.txn == nil || store.config != (ConfigV1{}) || store.dbis != (Store{}).dbis {
			t.Fatal("retained transaction native resource tuple")
		}
	case "CLOSE_BLOCKED":
		if store.env == nil || store.writer == nil || store.txn != nil || store.config == (ConfigV1{}) || store.dbis == (Store{}).dbis {
			t.Fatal("retained environment native resource tuple")
		}
	}
}

func contextNativeLegacyPriority(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	cfg.Upper = 512 << 20
	store, err := Create(path, cfg)
	consultedTrack(t, store, err)
	mustEnvironment(t, fixtureLargeBulk(store, 1, 3, 68_000_125))
	header := bytes.Repeat([]byte{0x5a}, 116)
	rows := make([]ConsultedRow, 3)
	for i := range rows {
		binary.BigEndian.PutUint32(header, uint32(i))
		hash := sha3.Sum256(header)
		rows[i] = ConsultedRow{DBI: readDBIsLiteral()[4], Key: bytes.Clone(hash[:])}
	}
	sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i].Key, rows[j].Key) < 0 })
	window := CanonicalContextWindowV1{0, 0, 10_081}
	batch := Batch{Mutations: []Mutation{consultedCounter(t, 900)}, Consulted: rows, ContextConsulted: &window}
	evidence := contextProbe(t, store, func() {
		contextRefusal(t, store, batch, "Capacity", -30417, "Update Batch exceeds bound")
	})
	if evidence.OldGets[2] != 0 || evidence.OldGets[3] != 0 || evidence.BeginWrite != 0 || evidence.Commits != 0 {
		t.Fatal("legacy present-length cap lost context precedence", evidence)
	}
	var truth CommitTruth
	var stage UpdateStage
	var result error
	evidence = contextProbe(t, store, func() {
		_, fixtureErr := fixtureLargeFault(store, 28, 4, rows[0].Key, func() {
			truth, stage, result = store.Update(func(*Reader) (Batch, error) { return batch, nil })
		})
		mustEnvironment(t, fixtureErr)
	})
	contextError(t, result, "IO", 5, "error 5")
	if truth != 1 || stage != 1 || evidence.OldGets[2] != 0 || evidence.OldGets[3] != 0 || evidence.BeginWrite != 0 || evidence.Commits != 0 {
		t.Fatal("legacy source fault lost context precedence", evidence)
	}
	contextNativeResources(t, store, "CLOSED")
	largeNativeCached(t, store)
	reopened, openErr := Open(path, cfg)
	consultedTrack(t, reopened, openErr)
	consultedRequireImage(t, reopened, readDBIsLiteral()[0], batch.Mutations[0].Key, nil, false, "legacy source refusal preserved target")
}

// Fixed fixture interceptors cannot simultaneously inject consumed OLD abort
// and close BUSY: the Large owner intercepts OLD abort before the Selected owner.
// The real public Q and consumed-abort cases are above; this composes their
// literal disposition at the existing applyReadAbort consumer, without a seam.
func contextNativeQClose(t *testing.T) {
	store, path, cfg := consultedStore(t)
	window := CanonicalContextWindowV1{10, 0, 1}
	target := consultedCounter(t, 900)
	truth, stage, source := store.Update(func(*Reader) (Batch, error) {
		return Batch{Mutations: []Mutation{target}, ContextConsulted: &window}, nil
	})
	contextError(t, source, "StateMismatch", -30779, "canonical context OLD image is incomplete")
	if truth != 1 || stage != 1 || string(store.state) != "OPEN" {
		t.Fatal("public Q before direct projection")
	}
	var result error
	_, err := fixtureLargeFault(store, 11, 0, target.Key, func() {
		result = store.applyReadAbort(nil, source, false, 5)
	})
	mustEnvironment(t, err)
	closeErr := requireEnvironmentError(t, result, EngineClass("Concurrency"), operationClose, -30778, "MDBX_BUSY: Another write transaction is running, or environment is already used while opening with MDBX_EXCLUSIVE flag")
	parts, ok := closeErr.Cause.(interface{ Unwrap() []error })
	if !ok || len(parts.Unwrap()) != 2 || parts.Unwrap()[0] != source {
		t.Fatal("close lost exact Q then consumed abort cause", result)
	}
	abortErr := requireEnvironmentError(t, parts.Unwrap()[1], EngineClass("IO"), operationAbort, 5, "error 5")
	if abortErr.Cause != nil || abortErr.ReopenRequired || result != store.terminal {
		t.Fatal("Q/abort/close cause tuple")
	}
	contextNativeResources(t, store, "CLOSE_BLOCKED")
	largeNativeCached(t, store)
	mustEnvironment(t, fixtureLargeRelease(store))
	reopened, openErr := Open(path, cfg)
	consultedTrack(t, reopened, openErr)
	consultedRequireImage(t, reopened, target.DBI, target.Key, nil, false, "Q/abort/close no effects")
}
