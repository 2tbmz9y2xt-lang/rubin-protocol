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
	"sort"
	"testing"
)

func TestLargeImageV1Native(t *testing.T) {
	for _, row := range []struct { name string; run func(*testing.T) }{
		{"A1 malformed physical data and empty values", largeNativePhysical},
		{"A2 complete legal family and aggregate bodies", largeNativeScale},
		{"A3 family targets and reference overlays", largeNativeOverlay},
		{"A5 A6 A7 A8 residual and target truth", largeNativeTruth},
		{"A8 independent legacy and reference predicates", largeNativeJointPredicates},
		{"H2 native callback lifecycle", largeNativeCallbacks},
		{"H3 final and preflight residual drift", largeNativePrecommit},
		{"H4 cleanup after proven NEW", largeNativeCleanup},
		{"R2 native shape refusal", largeNativeShapes},
		{"R1 legacy value/native admission before large controls", largeNativeLegacyPriority},
	} { t.Run(row.name, row.run) }
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
	for i := range keys { mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbis[5], keys[i], values[i])) }
	mustEnvironment(t, store.View(func(reader *Reader) error {
		if err := reader.VisitLargeImageV1(body, func(row LargeImageRowV1) error {
			largeWindow(t, row, []byte{}, true)
			n, err := row.ReadAt(make([]byte, 1), 0)
			if n != 0 || err != io.EOF { t.Fatalf("present-empty read %d/%v", n, err) }
			return nil
		}); err != nil { return err }
		seen := 0
		err := reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 2}, func(row LargeImageRowV1) error {
			if seen >= len(keys) || !bytes.Equal(row.Key(), keys[seen]) { t.Fatalf("physical order at %d: %x", seen, row.Key()) }
			largeWindow(t, row, values[seen], true)
			seen++
			return nil
		})
		if seen != 4 { t.Fatalf("malformed complete family=%d", seen) }
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
			if !bytes.Equal(row.Key(), maximumKey) { t.Fatal("maximum native key was truncated") }
			largeWindow(t, row, []byte{0x42}, true)
			return nil
		})
		if seen != 1 { t.Fatalf("maximum native key exhaustion %d", seen) }
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
	manifest := make([]byte, 33); manifest[0] = 1
	binary.BigEndian.PutUint32(manifest[25:], 414_634)
	binary.BigEndian.PutUint32(manifest[29:], 414_634)
	mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[5], manifestKey, manifest))
	// A maximum compact undo value spans a full 65536-byte window and a 24-byte tail.
	chunkKey := make([]byte, 77); chunkKey[32] = 1
	binary.BigEndian.PutUint32(chunkKey[33:], 414_633)
	chunk := make([]byte, 65_560); chunk[0] = 0x5a; chunk[10] = 0xfe; chunk[13] = 1
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
				if n != 0 { t.Fatal("prior family row copied bytes") }
				largeRequireError(t, err, "InvalidInput", 22, "large image row is not active")
			}
			previous = row
			key := row.Key()
			if count == 0 {
				if !bytes.Equal(key, manifestKey) { t.Fatal("family manifest order") }
				largeWindow(t, row, manifest, true)
			} else if count <= 414_634 {
				if len(key) != 77 || key[32] != 1 || binary.BigEndian.Uint32(key[33:37]) != uint32(count-1) { t.Fatalf("legal family order %d/%x", count, key) }
				if count == 414_634 { largeWindow(t, row, chunk, true) } else {
					n, err := row.ReadAt(buffer, 0)
					want := make([]byte, 20); want[0] = 0x5a
					if n != 20 || err != nil || !bytes.Equal(buffer, want) { t.Fatalf("family bytes %d/%v/%x", n, err, buffer) }
				}
			} else { t.Fatal("extra legal family member") }
			count++
			return nil
		}); err != nil { return err }
		if count != 414_635 { t.Fatalf("legal family complete exhaustion=%d", count) }
		var total uint64
		wantBody := bytes.Repeat([]byte{0x5a}, 108_000)
		for _, selector := range selectors[:1440] {
			binary.BigEndian.PutUint32(wantBody, indices[selector.Hash])
			if err := reader.VisitLargeImageV1(selector, func(row LargeImageRowV1) error {
				if !row.Present() || row.Length() != 108_000 { t.Fatal("aggregate body metadata") }
				largeWindow(t, row, wantBody, true)
				total += row.Length()
				return nil
			}); err != nil { return err }
		}
		if total != 155_520_000 || total <= 154_611_151 { t.Fatalf("aggregate capacity witness %d", total) }
		return reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 1, Hash: maximumKey}, func(row LargeImageRowV1) error { largeWindow(t, row, maximum, true); return nil })
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
	utxoKey := make([]byte, 44); utxoKey[7] = 1; copy(utxoKey[8:40], spent[:])
	entryKey := make([]byte, 77); entryKey[32] = 1; copy(entryKey[41:73], spent[:])
	value := make([]byte, 20); value[0] = 7
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
			if !bytes.Equal(row.Key(), residual) { t.Fatalf("untouched residual %x", row.Key()) }
			largeWindow(t, row, []byte{0x31}, true)
			return nil
		})
		if seen != 1 { t.Fatalf("overlay family exhaustion=%d", seen) }
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
		truth, stage, result = store.Update(func(reader *Reader) (Batch, error) { saved = reader; return batch, nil })
		largeNativeCached(t, store)
	})
	mustEnvironment(t, fixtureErr)
	if saved == nil || saved.usable() { t.Fatal("public Reader remained usable through private comparison/readback") }
	largeRequireError(t, saved.VisitLargeImageV1(LargeImageSelectorV1{Kind: 1}, nil), "InvalidInput", 22, "Reader is not active")
	return truth, stage, result, evidence
}

func largeNativeCached(t *testing.T, store *Store) {
	t.Helper()
	before := fixtureLargeNativeCalls()
	terminal := store.terminal
	truth, stage, result := store.Update(func(*Reader) (Batch, error) { t.Fatal("cached terminal callback ran"); return Batch{}, nil })
	if truth != store.terminalTruth || int(stage) != 1 || result != terminal { t.Fatal("cached terminal update changed result") }
	if result = store.View(func(*Reader) error { t.Fatal("cached terminal View callback ran"); return nil }); result != terminal { t.Fatal("cached terminal View changed error identity") }
	if fixtureLargeNativeCalls() != before { t.Fatal("cached terminal result reused native handles") }
}

func largeNativeTruth(t *testing.T) {
	for _, row := range []struct { name string; mode uint32; target bool; want string }{
		{"extra residual", 3, false, "UNKNOWN"}, {"missing residual", 4, false, "UNKNOWN"},
		{"manifest target plus extra residual", 3, true, "UNKNOWN"},
		{"same-length residual byte", 5, false, "UNKNOWN"}, {"neither target", 6, true, "UNKNOWN"},
		{"OLD", 7, false, "OLD"}, {"NEW", 12, false, "NEW"}, {"readback error", 8, false, "UNKNOWN"}, {"readback begin error", 23, false, "UNKNOWN"},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			key := append(make([]byte, 32), 2)
			if row.mode != 3 { mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[5], key, []byte{0x31})) }
			batch := Batch{Mutations: []Mutation{consultedCounter(t, 1)}, LargeConsulted: []LargeImageSelectorV1{{Kind: 2}}}
			rank := uint8(5)
			if row.target {
				targetKey := append(make([]byte, 32), 0)
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[5], targetKey, []byte{0x41}))
				batch.Mutations = []Mutation{{DBI: readDBIsLiteral()[5], Key: targetKey, BeforePresent: true, AfterKind: AfterKind(1)}}
				if row.mode == 6 { key = targetKey }
			}
			if row.mode == 8 { rank = 0; key = consultedCounter(t, 1).Key }
			truth, stage, err, evidence := largeFaultCommit(t, store, row.mode, rank, key, batch)
			commit, ok := err.(*CommitError)
			if !ok || truth.String() != row.want || commit.Truth.String() != row.want || int(stage) != 3 || string(store.state) != "CLOSED" || store.env != nil || store.writer != nil || store.txn != nil || evidence.commits != 1 || evidence.aborts != 1 { t.Fatalf("readback %s: %s/%d/%v/%s/%+v", row.name, truth, stage, err, store.state, evidence) }
			requireEnvironmentError(t, commit.Cause, EngineClass("Capacity"), operationUpdate, 28, expectedNativeDiagnostic(28))
			if row.mode == 8 || row.mode == 23 { requireEnvironmentError(t, commit.ReadbackCause, EngineClass("IO"), operationUpdate, 5, expectedNativeDiagnostic(5)) } else if commit.ReadbackCause != nil { t.Fatalf("unexpected readback cause: %v", commit.ReadbackCause) }
			if store.terminalTruth.String() != row.want { t.Fatal("terminal truth differs") }
			nextTruth, nextStage, nextErr := store.Update(func(*Reader) (Batch, error) { t.Fatal("cached terminal callback ran"); return Batch{}, nil })
			if nextTruth.String() != row.want || int(nextStage) != 1 || nextErr != store.terminal { t.Fatal("cached terminal result") }
			reopened, openErr := Open(path, cfg); consultedTrack(t, reopened, openErr)
			if row.mode >= 3 && row.mode <= 6 {
				want := []byte{0x7f}; if row.mode == 4 { want = nil }
				found, readErr := FixtureRawRowEqual(reopened, rank, key, want)
				if readErr != nil || !found || evidence.drift != 1 { t.Fatalf("actual drift %v/%v/%+v", found, readErr, evidence) }
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
	if truth.String() != "OLD" { t.Fatalf("both-equal precedence %s", truth) }
}

func largeNativeJointPredicates(t *testing.T) {
	for _, which := range []string{"legacy", "reference"} {
		t.Run(which, func(t *testing.T) {
			store, _, _ := consultedStore(t)
			dbis := readDBIsLiteral()
			batch := Batch{Mutations: []Mutation{consultedCounter(t, 1)}, LargeConsulted: []LargeImageSelectorV1{{Kind: 2}}}
			key, rank := consultedCounter(t, 33).Key, uint8(0)
			before := []byte{0,0,0,0,0,0,0,33,0,0,0,0,0,0,0,33}
			if which == "legacy" {
				batch.Consulted = []ConsultedRow{{DBI: dbis[0], Key: key}}
			} else {
				rank = 1
				key = make([]byte, 44); key[7] = 1; key[8] = 1
				before = make([]byte, 20); before[0] = 7
				entry := make([]byte, 77); entry[32] = 1; entry[41] = 1
				batch.Mutations = []Mutation{{DBI: dbis[5], Key: entry, AfterKind: AfterKind(3), RefDBI: dbis[1], RefKey: key}}
			}
			mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbis[rank], key, before))
			truth, stage, err, evidence := largeFaultCommit(t, store, 5, rank, key, batch)
			commit, ok := err.(*CommitError)
			if !ok || truth.String() != "UNKNOWN" || commit.Truth.String() != "UNKNOWN" || int(stage) != 3 || commit.ReadbackCause != nil || evidence.drift != 1 { t.Fatalf("%s predicate omitted: %s/%d/%v/%+v", which, truth, stage, err, evidence) }
			requireEnvironmentError(t, commit.Cause, EngineClass("Capacity"), operationUpdate, 28, expectedNativeDiagnostic(28))
		})
	}
}

func largeNativeCallbacks(t *testing.T) {
	for _, fault := range []uint32{1, 2, 24} {
		for _, mode := range []string{"nil", "ignored", "exact", "wrapped", "distinct", "typed-nil", "panic"} {
			t.Run(fmt.Sprintf("%d/%s", fault, mode), func(t *testing.T) {
				store, _, _ := consultedStore(t)
				key := make([]byte, 32)
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[4], key, []byte{0x31}))
				var recorded, application, visitResult, result error
				if mode == "distinct" { application = errors.New("large distinct application") }
				if mode == "typed-nil" { application = (*largeTypedNil)(nil) }
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
								largeRequireError(t, reader.VisitLargeImageV1(LargeImageSelectorV1{}, func(LargeImageRowV1) error { t.Fatal("invalid nested callback ran"); return nil }), "InvalidInput", 22, "invalid large image selector")
								if n, err := row.ReadAt(make([]byte, 65_537), 0); n != 0 { t.Fatal("input refusal copied bytes") } else { largeRequireError(t, err, "InvalidInput", 22, "ReadAt buffer exceeds 65536 bytes") }
								if n, err := row.ReadAt(nil, math.MaxUint64); n != 0 || err != nil { t.Fatal("zero ReadAt input/native precedence") }
								if n, err := row.ReadAt(make([]byte, 1), 1); n != 0 || err != io.EOF { t.Fatal("end ReadAt input/native precedence") }
								if fixtureLargeNativeCalls() != beforeInput || !reader.usable() || reader.failure != nil { t.Fatal("input/EOF refusal called native or disarmed Reader") }
								n, err := row.ReadAt(make([]byte, 1), 0)
								if n != 0 { t.Fatal("native fault copied bytes") }
								recorded = err
								requireEnvironmentError(t, recorded, EngineClass("IO"), operationGet, 5, expectedNativeDiagnostic(5))
								switch mode {
								case "exact": return recorded
								case "wrapped": application = fmt.Errorf("large wrapped: %w", recorded); return application
								case "panic": panic(panicValue)
								default: return application
								}
							})
							visitResult = visitErr
							if mode == "ignored" { return Batch{Mutations: []Mutation{consultedCounter(t, 1)}}, nil }
							return Batch{}, visitErr
						})
						largeNativeCached(t, store)
					})
					mustEnvironment(t, fixtureErr)
				}()
				// Panic still executes fixture disarm; native ownership is asserted from Store itself.
				if fault == 1 {
					if string(store.state) != "CLOSED" || store.env != nil || store.writer != nil || store.txn != nil { t.Fatal("consumed infrastructure resource projection") }
				} else if fault == 2 {
					if string(store.state) != "POISONED_THREAD" || store.env == nil || store.writer == nil || store.txn == nil || store.config != (ConfigV1{}) || store.dbis != (Store{}).dbis { t.Fatal("retained infrastructure resource projection") }
				} else if string(store.state) != "CLOSE_BLOCKED" || store.env == nil || store.writer == nil || store.txn != nil || store.config == (ConfigV1{}) || store.dbis == (Store{}).dbis { t.Fatal("retained close resource projection") }
				if mode == "panic" {
					if recovered != panicValue || result != nil { t.Fatalf("original native panic %v/%v", recovered, result) }
					largeCallbackCauses(t, store.terminal, nil, recorded, fault)
				} else {
					if truth.String() != "OLD" || int(stage) != 1 || evidence.gets != 2 || evidence.aborts != 1 || evidence.commits != 0 { t.Fatalf("native callback disposition %s/%d/%+v", truth, stage, evidence) }
					largeCallbackCauses(t, visitResult, application, recorded, 1)
					outerApplication := visitResult
					if mode == "ignored" { outerApplication = nil }
					largeCallbackCauses(t, result, outerApplication, recorded, fault)
				}
				_, expiredErr := saved.ReadAt(make([]byte, 65_537), math.MaxUint64)
				largeRequireError(t, expiredErr, "InvalidInput", 22, "Reader is not active")
				terminal := store.terminal
				if next := store.View(func(*Reader) error { t.Fatal("terminal native callback ran"); return nil }); next != terminal { t.Fatalf("cached terminal identity %v/%v", next, terminal) }
				mustEnvironment(t, fixtureLargeRelease(store))
			})
		}
	}
}

func largeCallbackCauses(t *testing.T, result, application, recorded error, fault uint32) {
	t.Helper()
	if fault == 24 {
		engine := requireEnvironmentError(t, result, EngineClass("Concurrency"), operationClose, 16, expectedNativeDiagnostic(16))
		if engine.Cause == nil || engine.ReopenRequired { t.Fatal("retained close cause/reopen") }
		result = engine.Cause
	}
	if fault == 2 {
		engine := requireEnvironmentError(t, result, EngineClass("LocalInvariant"), operationAbort, -30416, expectedNativeDiagnostic(-30416))
		if engine.Cause == nil || !engine.ReopenRequired { t.Fatal("retained cleanup cause/reopen") }
		result = engine.Cause
	}
	if application == nil || application == recorded {
		if result != recorded { t.Fatalf("recorded error duplicated/replaced %v/%v", result, recorded) }
		return
	}
	parts, ok := result.(interface{ Unwrap() []error })
	if !ok || len(parts.Unwrap()) != 2 || parts.Unwrap()[0] != application || parts.Unwrap()[1] != recorded { t.Fatalf("application then infrastructure causes %v", result) }
}

func largeNativePrecommit(t *testing.T) {
	for _, mode := range []uint32{13, 14} {
		store, path, cfg := consultedStore(t)
		key := append(make([]byte, 32), 2)
		batch := Batch{Mutations: []Mutation{consultedCounter(t, 1)}, LargeConsulted: []LargeImageSelectorV1{{Kind: 2}}}
		truth, stage, err, evidence := largeFaultCommit(t, store, mode, 5, key, batch)
		diagnostic, wantStage := "final update image mismatch", 2
		if mode == 14 { diagnostic, wantStage = "OLD/write snapshot mismatch", 1 }
		requireEnvironmentError(t, err, EngineClass("StateMismatch"), operationUpdate, -30779, diagnostic)
		if truth.String() != "OLD" || int(stage) != wantStage || string(store.state) != "CLOSED" || evidence.commits != 0 || evidence.drift != 1 { t.Fatalf("precommit residual %d: %s/%d/%v/%+v", mode, truth, stage, err, evidence) }
		reopened, openErr := Open(path, cfg); consultedTrack(t, reopened, openErr)
		consultedRequireImage(t, reopened, readDBIsLiteral()[0], consultedCounter(t, 1).Key, nil, false, "no target survived aborted residual check")
		want := []byte(nil); if mode == 14 { want = []byte{0x7f} }
		equal, readErr := FixtureRawRowEqual(reopened, 5, key, want)
		if readErr != nil || !equal { t.Fatal("precommit physical residual disposition") }
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
		if mode == 19 { wantTruth = "OLD" }
		if truth.String() != wantTruth || int(stage) != 3 || store.terminalTruth.String() != wantTruth { t.Fatalf("cleanup downgraded proven truth mode%d: %s/%d/%v", mode, truth, stage, err) }
		var commit *CommitError
		if !errors.As(err, &commit) || commit.Truth.String() != wantTruth { t.Fatalf("cleanup CommitError: %v", err) }
		if mode == 11 {
			closeError := requireEnvironmentError(t, err, EngineClass("Concurrency"), operationClose, 16, expectedNativeDiagnostic(16))
			if closeError.Cause != commit { t.Fatal("close failure lost exact CommitError cause") }
		} else {
			code, class := 5, "IO"
			if mode == 10 || mode == 15 || mode == 19 { code, class = -30416, "LocalInvariant" }
			requireEnvironmentError(t, commit.ReadbackCause, EngineClass(class), operationAbort, code, expectedNativeDiagnostic(code))
		}
		wantState := "CLOSED"
		if mode == 10 || mode == 15 || mode == 19 { wantState = "POISONED_THREAD" }
		if mode == 11 { wantState = "CLOSE_BLOCKED" }
		if string(store.state) != wantState { t.Fatalf("cleanup resource state mode%d=%s", mode, store.state) }
		mustEnvironment(t, fixtureLargeRelease(store))
		reopened, openErr := Open(path, cfg); consultedTrack(t, reopened, openErr)
		want := []byte{0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1}
		if mode == 19 { want = nil }
		consultedRequireImage(t, reopened, readDBIsLiteral()[0], consultedCounter(t, 1).Key, want, mode != 19, "proven truth persisted after cleanup")
	}
}

func largeNativeShapes(t *testing.T) {
	for _, mode := range []uint32{17, 18, 20, 21, 22, 25, 26} {
		store, _, _ := consultedStore(t)
		key := make([]byte, 32)
		rank, kind := uint8(4), LargeImageKindV1(1)
		if mode >= 20 { rank, kind = 5, 2; key = append(key, 2) }
		mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[rank], key, []byte{1}))
		var result error
		evidence, err := fixtureLargeFault(store, mode, rank, key, func() {
			result = store.View(func(reader *Reader) error {
				return reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: kind}, func(LargeImageRowV1) error { t.Fatal("malformed native span exposed"); return nil })
			})
		})
		mustEnvironment(t, err)
		largeRequireError(t, result, "LocalInvariant", -30779, "invalid native large image result")
		if evidence.gets != 1 || evidence.aborts != 1 || string(store.state) != "CLOSED" || store.env != nil || store.writer != nil { t.Fatal("shape failure infrastructure disposition") }
	}
}

func largeNativeLegacyPriority(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	cfg.Upper = 512 << 20
	store, err := Create(path, cfg); consultedTrack(t, store, err)
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
	if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "OPEN" { t.Fatal("legacy captured-value admission priority") }
	batch.LargeConsulted = make([]LargeImageSelectorV1, 2881)
	var nativeResult error
	evidence, fixtureErr := fixtureLargeFault(store, 28, 4, rows[0].Key, func() {
		truth, stage, nativeResult = store.Update(func(*Reader) (Batch, error) { return batch, nil })
	})
	mustEnvironment(t, fixtureErr)
	requireEnvironmentError(t, nativeResult, EngineClass("IO"), operationUpdate, 5, expectedNativeDiagnostic(5))
	if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "CLOSED" || evidence.gets != 1 || evidence.aborts != 1 { t.Fatal("legacy native capture priority before scalar selector count") }
}
