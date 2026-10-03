//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"runtime"
	"testing"
)

func largeRequireError(t *testing.T, err error, class string, code int, diagnostic string) {
	t.Helper()
	var engine *EngineError
	if !errors.As(err, &engine) || !sameError(err, engine) || engine == nil || string(engine.Class) != class || engine.Operation != "get" || engine.Code != code || engine.Diagnostic != diagnostic || engine.Cause != nil || engine.ReopenRequired {
		t.Fatalf("large-image exact error: %#v; want get/%s/%d/%q/nil", err, class, code, diagnostic)
	}
}

func largeBodyLiteral(id byte, size int) ([32]byte, []byte) {
	value := bytes.Repeat([]byte{0x5a}, size)
	value[0] = id
	return sha3.Sum256(value[:116]), value
}

func largeCommit(t *testing.T, store *Store, batch Batch) {
	t.Helper()
	truth, stage, err := store.Update(func(*Reader) (Batch, error) { return batch, nil })
	if truth.String() != "NEW" || int(stage) != 3 || err != nil || string(store.state) != "OPEN" {
		t.Fatalf("large update: %s/%d/%v/%s", truth, stage, err, store.state)
	}
}

func largeWindow(t *testing.T, row LargeImageRowV1, want []byte, present bool) {
	t.Helper()
	if row.Present() != present || row.Length() != uint64(len(want)) {
		t.Fatalf("metadata: %v/%d want %v/%d", row.Present(), row.Length(), present, len(want))
	}
	buffer := make([]byte, 65_536)
	for offset := uint64(0); offset < row.Length(); {
		n, err := row.ReadAt(buffer, offset)
		count := min(len(buffer), len(want)-int(offset))
		wantErr := error(nil)
		if count < len(buffer) {
			wantErr = io.EOF
		}
		if n != count || !sameError(err, wantErr) || !bytes.Equal(buffer[:n], want[int(offset):int(offset)+n]) {
			t.Fatalf("bytes at %d: %d/%v want %d/%v", offset, n, err, count, wantErr)
		}
		offset += uint64(n)
	}
}

func TestLargeImageV1(t *testing.T) {
	for _, row := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"A1 physical bodies and empty family", largeTestBodies},
		{"A2 sequential visits and admission bounds", largeTestCounts},
		{"A3 exact overlay and source overlap", largeTestOverlay},
		{"A4 metadata copies expiry and windows", largeTestWindows},
		{"R1 selector admission and precedence", largeTestAdmission},
		{"H1 active visit ordinary reads and draining", largeTestConcurrency},
		{"H2 application result lifecycle", largeTestApplications},
	} {
		t.Run(row.name, row.run)
	}
}

func largeTestBodies(t *testing.T) {
	store, _, _ := consultedStore(t)
	hash, body := largeBodyLiteral(7, 131_073)
	largeCommit(t, store, Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[4], Key: hash[:], AfterKind: AfterKind(2), Literal: body}}})
	for _, selector := range []LargeImageSelectorV1{{Kind: 1}, {Kind: 1, Hash: hash}, {Kind: 2}, {Kind: 2, Hash: hash}} {
		mustEnvironment(t, store.View(func(reader *Reader) error {
			count := 0
			err := reader.VisitLargeImageV1(selector, func(row LargeImageRowV1) error {
				count++
				if !bytes.Equal(row.Key(), selector.Hash[:]) {
					t.Fatalf("body key: %x", row.Key())
				}
				want := []byte(nil)
				present := selector.Hash == hash
				if present {
					want = body
				}
				largeWindow(t, row, want, present)
				return nil
			})
			wantCount := 0
			if selector.Kind == 1 {
				wantCount = 1
			}
			if count != wantCount {
				t.Fatalf("complete domain visit count=%d want %d", count, wantCount)
			}
			return err
		}))
	}
}

func largeSelectors(count int, kind LargeImageKindV1) []LargeImageSelectorV1 {
	rows := make([]LargeImageSelectorV1, count)
	for i := range rows {
		rows[i].Kind = kind
		binary.BigEndian.PutUint32(rows[i].Hash[28:], uint32(i))
	}
	return rows
}

func largeTestCounts(t *testing.T) {
	store, _, _ := consultedStore(t)
	selectors := largeSelectors(1440, 1)
	selectors = append(selectors, largeSelectors(1440, 2)...)
	largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 1)}, LargeConsulted: selectors})
	mustEnvironment(t, store.View(func(reader *Reader) error {
		visits := 0
		for _, selector := range selectors[:1440] {
			if err := reader.VisitLargeImageV1(selector, func(row LargeImageRowV1) error {
				visits++
				if row.Present() || row.Length() != 0 {
					t.Fatal("absent sequential body became present")
				}
				return nil
			}); err != nil {
				return err
			}
		}
		if visits != 1440 {
			t.Fatalf("sequential exhaustion=%d", visits)
		}
		return nil
	}))
	for _, kind := range []LargeImageKindV1{1, 2} {
		countBeforeShape := append([]LargeImageSelectorV1{{Kind: 9}}, largeSelectors(1441, kind)...)
		for _, over := range [][]LargeImageSelectorV1{largeSelectors(1441, kind), append(largeSelectors(1440, 1), largeSelectors(1441, 2)...), countBeforeShape, make([]LargeImageSelectorV1, 2881)} {
			truth, stage, err := store.Update(func(*Reader) (Batch, error) {
				return Batch{Mutations: []Mutation{consultedCounter(t, 2)}, LargeConsulted: over}, nil
			})
			engine := requireEnvironmentError(t, err, EngineClass("Capacity"), operationUpdate, -30417, "Update Batch exceeds bound")
			if truth.String() != "OLD" || int(stage) != 1 || engine.Cause != nil || string(store.state) != "OPEN" {
				t.Fatalf("count refusal lifecycle: %s/%d/%v/%s", truth, stage, err, store.state)
			}
			consultedRequireImage(t, store, readDBIsLiteral()[0], consultedCounter(t, 2).Key, nil, false, "scalar count refusal preserved absent target")
			consultedRequireImage(t, store, readDBIsLiteral()[0], consultedCounter(t, 1).Key, []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1}, true, "scalar count refusal preserved existing image")
		}
	}
}

func largeTestOverlay(t *testing.T) {
	store, _, _ := consultedStore(t)
	hash, body := largeBodyLiteral(8, 131_073)
	wantBody := bytes.Clone(body)
	selector := LargeImageSelectorV1{Kind: 1, Hash: hash}
	largeCommit(t, store, Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[4], Key: hash[:], AfterKind: AfterKind(2), Literal: body}}, LargeConsulted: []LargeImageSelectorV1{selector}})
	largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 1)}, LargeConsulted: []LargeImageSelectorV1{selector}})
	consultedRequireImage(t, store, readDBIsLiteral()[4], hash[:], wantBody, true, "selected body retained through counter update")
	largeCommit(t, store, Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[4], Key: hash[:], BeforePresent: true, AfterKind: AfterKind(1)}}, LargeConsulted: []LargeImageSelectorV1{selector}})
	largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 2)}, LargeConsulted: []LargeImageSelectorV1{selector}})
	consultedRequireImage(t, store, readDBIsLiteral()[4], hash[:], nil, false, "selected body deletion")
	dbis := readDBIsLiteral()
	manifestKey := append(make([]byte, 32), 0)
	manifest := make([]byte, 33)
	manifest[0], manifest[28], manifest[32] = 1, 2, 2
	family := LargeImageSelectorV1{Kind: 2}
	largeCommit(t, store, Batch{Mutations: []Mutation{{DBI: dbis[5], Key: manifestKey, AfterKind: AfterKind(2), Literal: bytes.Clone(manifest)}}, LargeConsulted: []LargeImageSelectorV1{family}})
	sourceA, entryA := reverseLiteralKeys(1, [32]byte{}, [32]byte{0xff}, 0, 0, 0)
	sourceB, entryB := reverseLiteralKeys(1, [32]byte{}, [32]byte{0x80}, 1, 0, 0)
	valueA, valueB := [20]byte{0x31}, [20]byte{0x72}
	largeCommit(t, store, Batch{Mutations: []Mutation{
		{DBI: dbis[1], Key: sourceB, AfterKind: AfterKind(2), Literal: bytes.Clone(valueB[:])},
		{DBI: dbis[1], Key: sourceA, AfterKind: AfterKind(2), Literal: bytes.Clone(valueA[:])},
	}})
	laterKey := make([]byte, 33)
	laterKey[0] = 1
	laterManifest := bytes.Clone(manifest)
	laterManifest[8] = 9
	largeCommit(t, store, Batch{Mutations: []Mutation{
		{DBI: dbis[1], Key: sourceB, BeforePresent: true, AfterKind: AfterKind(1)},
		{DBI: dbis[1], Key: sourceA, BeforePresent: true, AfterKind: AfterKind(1)},
		{DBI: dbis[5], Key: entryA, AfterKind: AfterKind(3), RefDBI: dbis[1], RefKey: sourceA},
		{DBI: dbis[5], Key: entryB, AfterKind: AfterKind(3), RefDBI: dbis[1], RefKey: sourceB},
		{DBI: dbis[5], Key: laterKey, AfterKind: AfterKind(2), Literal: bytes.Clone(laterManifest)},
	}, LargeConsulted: []LargeImageSelectorV1{family}})
	for _, phase := range []struct {
		name      string
		reverse   bool
		mutations []Mutation
		keys      [][]byte
		values    [][]byte
	}{
		{"retained family", false, []Mutation{consultedCounter(t, 3)}, [][]byte{manifestKey, entryA, entryB}, [][]byte{manifest, valueA[:], valueB[:]}},
		{"manifest deletion", false, []Mutation{{DBI: dbis[5], Key: manifestKey, BeforePresent: true, AfterKind: AfterKind(1)}}, [][]byte{entryA, entryB}, [][]byte{valueA[:], valueB[:]}},
		{"targeted reference source", true, []Mutation{
			{DBI: dbis[1], Key: sourceA, AfterKind: AfterKind(3), RefDBI: dbis[5], RefKey: entryA},
			{DBI: dbis[5], Key: entryA, BeforePresent: true, AfterKind: AfterKind(1)},
		}, [][]byte{entryB}, [][]byte{valueB[:]}},
	} {
		largeCommit(t, store, Batch{Reverse: phase.reverse, Mutations: phase.mutations, LargeConsulted: []LargeImageSelectorV1{family}})
		mustEnvironment(t, store.View(func(reader *Reader) error {
			for _, application := range []error{errors.New("large family application"), nil} {
				seen := 0
				var previous LargeImageRowV1
				err := reader.VisitLargeImageV1(family, func(row LargeImageRowV1) error {
					if seen >= len(phase.keys) || !bytes.Equal(row.Key(), phase.keys[seen]) {
						t.Fatalf("%s physical order at %d: %x", phase.name, seen, row.Key())
					}
					if seen != 0 {
						n, expired := previous.ReadAt(nil, 0)
						if n != 0 {
							t.Fatal("prior family row copied bytes")
						}
						largeRequireError(t, expired, "InvalidInput", 22, "large image row is not active")
					}
					largeWindow(t, row, phase.values[seen], true)
					previous = row
					seen++
					return application
				})
				wantCount := len(phase.keys)
				if application != nil {
					wantCount = 1
				}
				if !sameError(err, application) || seen != wantCount {
					t.Fatalf("%s visitor outcome: %d/%v want %d/%v", phase.name, seen, err, wantCount, application)
				}
				n, expired := previous.ReadAt(nil, 0)
				if n != 0 {
					t.Fatal("completed family row copied bytes")
				}
				largeRequireError(t, expired, "InvalidInput", 22, "large image row is not active")
			}
			return nil
		}))
		consultedRequireImage(t, store, dbis[5], laterKey, laterManifest, true, "later prefix preserved outside selected family")
	}
	consultedRequireImage(t, store, dbis[1], sourceA, valueA[:], true, "selected targeted source restored exact OLD bytes")
}

func largeTestWindows(t *testing.T) {
	store, _, _ := consultedStore(t)
	hash, body := largeBodyLiteral(9, 131_073)
	largeCommit(t, store, Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[4], Key: hash[:], AfterKind: AfterKind(2), Literal: body}}})
	var saved LargeImageRowV1
	mustEnvironment(t, store.View(func(reader *Reader) error {
		if err := reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 1, Hash: hash}, func(row LargeImageRowV1) error {
			saved = row
			key := row.Key()
			key[0] ^= 255
			if !bytes.Equal(row.Key(), hash[:]) {
				t.Fatal("Key aliases native metadata")
			}
			for _, span := range []struct {
				size   int
				offset uint64
				n      int
				err    error
			}{
				{0, 0, 0, nil},
				{0, math.MaxUint64, 0, nil},
				{1, 131_073, 0, io.EOF},
				{1, math.MaxUint64, 0, io.EOF},
				{65_536, 65_536, 65_536, nil},
				{2, 131_072, 1, io.EOF},
			} {
				dst := make([]byte, span.size)
				n, err := row.ReadAt(dst, span.offset)
				if n != span.n || !sameError(err, span.err) || n > 0 && !bytes.Equal(dst[:n], body[int(span.offset):int(span.offset)+n]) {
					t.Fatalf("window %d/%d: %d/%v", span.size, span.offset, n, err)
				}
			}
			if n, err := row.ReadAt(make([]byte, 65_537), 0); n != 0 {
				t.Fatal("over-window copied bytes")
			} else {
				largeRequireError(t, err, "InvalidInput", 22, "ReadAt buffer exceeds 65536 bytes")
			}
			return nil
		}); err != nil {
			return err
		}
		for _, dst := range [][]byte{nil, make([]byte, 65_537)} {
			n, err := saved.ReadAt(dst, 0)
			if n != 0 {
				t.Fatal("expired span copied bytes")
			}
			largeRequireError(t, err, "InvalidInput", 22, "large image row is not active")
		}
		return nil
	}))
	if n, err := saved.ReadAt(make([]byte, 65_537), 0); n != 0 {
		t.Fatal("expired Reader copied bytes")
	} else {
		largeRequireError(t, err, "InvalidInput", 22, "Reader is not active")
	}
	if !saved.Present() || saved.Length() != 131_073 || !bytes.Equal(saved.Key(), hash[:]) {
		t.Fatal("expiry changed metadata")
	}
	expiredKey := saved.Key()
	expiredKey[0] ^= 255
	if !bytes.Equal(saved.Key(), hash[:]) {
		t.Fatal("Key after expiry aliases immutable metadata")
	}
	zero := LargeImageRowV1{}
	if zero.Key() != nil || zero.Present() || zero.Length() != 0 {
		t.Fatal("zero metadata")
	}
	n, err := zero.ReadAt(make([]byte, 65_537), math.MaxUint64)
	if n != 0 {
		t.Fatal("zero row copied bytes")
	}
	largeRequireError(t, err, "InvalidInput", 22, "invalid large image row")
}

func largeTestAdmission(t *testing.T) {
	store, _, _ := consultedStore(t)
	truth, stage, err := store.Update(func(*Reader) (Batch, error) {
		return Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[0], Key: []byte{2}}}, LargeConsulted: make([]LargeImageSelectorV1, 2881)}, nil
	})
	requireEnvironmentError(t, err, EngineClass("InvalidInput"), operationUpdate, 22, "invalid Update Batch")
	if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "OPEN" {
		t.Fatal("legacy admission lost priority over large count")
	}
	for _, selectors := range [][]LargeImageSelectorV1{{{Kind: 0}}, {{Kind: 3}}, {{Kind: 2}, {Kind: 1}}, {{Kind: 1}, {Kind: 1}}, {{Kind: 1, Hash: [32]byte{1}}, {Kind: 1}}} {
		truth, stage, err := store.Update(func(*Reader) (Batch, error) {
			return Batch{Mutations: []Mutation{consultedCounter(t, 1)}, LargeConsulted: selectors}, nil
		})
		engine := requireEnvironmentError(t, err, EngineClass("InvalidInput"), operationUpdate, 22, "invalid Update Batch")
		if truth.String() != "OLD" || int(stage) != 1 || engine.Cause != nil || string(store.state) != "OPEN" {
			t.Fatal("selector admission disposition")
		}
		consultedRequireImage(t, store, readDBIsLiteral()[0], consultedCounter(t, 1).Key, nil, false, "invalid selector refusal preserved absent target")
	}
	for _, kind := range []LargeImageKindV1{1, 2} {
		key := make([]byte, 32)
		rank := 4
		if kind == 2 {
			key = make([]byte, 33)
			rank = 5
		}
		truth, stage, err := store.Update(func(*Reader) (Batch, error) {
			return Batch{Mutations: []Mutation{consultedCounter(t, 1)}, Consulted: []ConsultedRow{{DBI: readDBIsLiteral()[rank], Key: key}}, LargeConsulted: []LargeImageSelectorV1{{Kind: kind}}}, nil
		})
		requireEnvironmentError(t, err, EngineClass("InvalidInput"), operationUpdate, 22, "invalid Update Batch")
		if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "OPEN" {
			t.Fatal("legacy overlap disposition")
		}
		consultedRequireImage(t, store, readDBIsLiteral()[0], consultedCounter(t, 1).Key, nil, false, "legacy overlap refusal preserved absent target")
	}
	var expired *Reader
	mustEnvironment(t, store.View(func(reader *Reader) error {
		expired = reader
		largeRequireError(t, reader.VisitLargeImageV1(LargeImageSelectorV1{}, nil), "InvalidInput", 22, "nil large image visitor")
		largeRequireError(t, reader.VisitLargeImageV1(LargeImageSelectorV1{}, func(LargeImageRowV1) error {
			t.Fatal("bad kind callback")
			return nil
		}), "InvalidInput", 22, "invalid large image selector")
		if !reader.usable() || reader.failure != nil {
			t.Fatal("input refusal disarmed Reader")
		}
		return nil
	}))
	largeRequireError(t, expired.VisitLargeImageV1(LargeImageSelectorV1{}, nil), "InvalidInput", 22, "Reader is not active")
	for _, selectors := range [][]LargeImageSelectorV1{nil, {}} {
		largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, uint64(10+len(selectors)))}, LargeConsulted: selectors})
		// Use a new Store for the next nil/empty invocation, so both have the same independent precondition.
		store, _, _ = consultedStore(t)
	}
}

func largeTestConcurrency(t *testing.T) {
	store, _, _ := consultedStore(t)
	mustEnvironment(t, store.View(func(reader *Reader) error {
		return reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 1}, func(row LargeImageRowV1) error {
			largeRequireError(t, reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 1}, func(LargeImageRowV1) error {
				t.Fatal("nested visitor ran")
				return nil
			}), "Concurrency", -30778, "large image visit in progress")
			largeRequireError(t, reader.VisitLargeImageV1(LargeImageSelectorV1{}, nil), "InvalidInput", 22, "nil large image visitor")
			largeRequireError(t, reader.VisitLargeImageV1(LargeImageSelectorV1{}, func(LargeImageRowV1) error {
				t.Fatal("invalid nested kind callback")
				return nil
			}), "InvalidInput", 22, "invalid large image selector")
			concurrent := make(chan error)
			go func() {
				concurrent <- reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 2}, func(LargeImageRowV1) error { return errors.New("concurrent visitor ran") })
			}()
			largeRequireError(t, <-concurrent, "Concurrency", -30778, "large image visit in progress")
			if _, _, err := reader.Get(readDBIsLiteral()[0], []byte{0}); err != nil {
				return err
			}
			if n, err := row.ReadAt(nil, math.MaxUint64); n != 0 || err != nil {
				t.Fatalf("in-visitor read: %d/%v", n, err)
			}
			busy := store.View(func(*Reader) error {
				t.Fatal("busy Store callback ran")
				return nil
			})
			requireEnvironmentError(t, busy, EngineClass("Concurrency"), operationView, -30778, "store operation in progress")
			return nil
		})
	}))
	hash, body := largeBodyLiteral(19, 131_073)
	largeCommit(t, store, Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[4], Key: hash[:], AfterKind: AfterKind(2), Literal: body}}})
	mustEnvironment(t, store.View(func(reader *Reader) error {
		type result struct {
			n     int
			err   error
			bytes []byte
		}
		results, started := make(chan result, 8), make(chan struct{}, 8)
		err := reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 1, Hash: hash}, func(row LargeImageRowV1) error {
			for range 8 {
				go func(copyOfRow LargeImageRowV1) {
					buffer := make([]byte, 65_536)
					started <- struct{}{}
					n, readErr := copyOfRow.ReadAt(buffer, 0)
					results <- result{n, readErr, buffer}
				}(row)
			}
			for range 8 {
				<-started
			}
			return nil
		})
		for range 8 {
			outcome := <-results
			if outcome.n == 0 {
				largeRequireError(t, outcome.err, "InvalidInput", 22, "large image row is not active")
			} else if outcome.n != 65_536 || outcome.err != nil || !bytes.Equal(outcome.bytes, body[:65_536]) {
				t.Fatalf("concurrent row copy across expiry: %d/%v", outcome.n, outcome.err)
			}
		}
		if !reader.usable() || reader.failure != nil {
			t.Fatal("expiry/input race became infrastructure failure")
		}
		return err
	}))
	drainStore, _, _ := consultedStore(t)
	inFlight := nativeError(operationGet, codeEIO)
	var visitResult error
	truth, stage, result := drainStore.Update(func(reader *Reader) (Batch, error) {
		visitResult = reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 1}, func(row LargeImageRowV1) error {
			// Model the same getMu ownership as an in-flight native ReadAt.
			reader.getMu.Lock()
			ready := make(chan struct{})
			go func() {
				close(ready)
				for row.span.active.Load() {
					runtime.Gosched()
				}
				reader.largeFailure(inFlight)
				reader.getMu.Unlock()
			}()
			<-ready
			return nil
		})
		if !sameError(visitResult, inFlight) {
			t.Fatalf("row expiry failed to drain its recorded native failure: %v", visitResult)
		}
		return Batch{Mutations: []Mutation{consultedCounter(t, 1)}}, nil
	})
	if truth.String() != "OLD" || int(stage) != 1 || !sameError(result, inFlight) || string(drainStore.state) != "CLOSED" || drainStore.env != nil || drainStore.writer != nil || drainStore.txn != nil {
		t.Fatal("drained row failure did not prevent writes and consume resources")
	}
}

type largeTypedNil struct{}

func (*largeTypedNil) Error() string { return "typed-nil large application" }

func largeTestApplications(t *testing.T) {
	for _, mode := range []string{"nil", "error", "typed-nil", "panic"} {
		t.Run(mode, func(t *testing.T) {
			store, _, _ := consultedStore(t)
			application := error(errors.New("large application"))
			if mode == "typed-nil" {
				application = (*largeTypedNil)(nil)
			}
			panicValue := &struct{ literal string }{"large panic"}
			var saved LargeImageRowV1
			var recovered any
			var truth CommitTruth
			var stage UpdateStage
			var returned error
			func() {
				defer func() { recovered = recover() }()
				truth, stage, returned = store.Update(func(reader *Reader) (Batch, error) {
					err := reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 1}, func(row LargeImageRowV1) error {
						saved = row
						if mode == "panic" {
							panic(panicValue)
						}
						if mode == "nil" {
							return nil
						}
						return application
					})
					if err != nil {
						if !reader.usable() || reader.failure != nil {
							t.Fatal("application error disarmed Reader")
						}
						if next := reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 1}, func(LargeImageRowV1) error { return nil }); next != nil {
							t.Fatalf("application error left active visit: %v", next)
						}
						return Batch{}, err
					}
					if err = reader.VisitLargeImageV1(LargeImageSelectorV1{Kind: 1}, func(LargeImageRowV1) error { return nil }); err != nil {
						return Batch{}, err
					}
					return Batch{Mutations: []Mutation{consultedCounter(t, 1)}, LargeConsulted: []LargeImageSelectorV1{{Kind: 1}}}, nil
				})
			}()
			if string(store.state) != "OPEN" || store.env == nil || store.writer == nil || store.txn != nil {
				t.Fatal("application result resource shape")
			}
			switch mode {
			case "nil":
				if truth.String() != "NEW" || int(stage) != 3 || returned != nil {
					t.Fatalf("nil outcome: %s/%d/%v", truth, stage, returned)
				}
			case "panic":
				if recovered != panicValue || returned != nil {
					t.Fatalf("panic identity: %v/%v", recovered, returned)
				}
			default:
				if truth.String() != "OLD" || int(stage) != 1 || !sameError(returned, application) {
					t.Fatalf("application identity: %s/%d/%v", truth, stage, returned)
				}
			}
			_, err := saved.ReadAt(nil, 0)
			largeRequireError(t, err, "InvalidInput", 22, "Reader is not active")
			largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 2)}})
		})
	}
}
