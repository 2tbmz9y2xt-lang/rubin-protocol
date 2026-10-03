//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"
	"testing"
)

func obsoleteRequireError(t *testing.T, err error, operation, class string, code int, diagnostic string) {
	t.Helper()
	engine, direct := err.(*EngineError)
	if !direct || engine == nil || string(engine.Operation) != operation || string(engine.Class) != class || engine.Code != code || engine.Diagnostic != diagnostic || engine.Cause != nil || engine.ReopenRequired {
		t.Fatalf("obsolete exact error: %#v want %s/%s/%d/%q/nil/false", err, operation, class, code, diagnostic)
	}
}

func obsoleteRequireZero(t *testing.T, page ObsoletePageV1) {
	t.Helper()
	if page.Rows != nil || page.Next != nil || page.Stop != 0 || page.Projection != 0 || page.Witness != (ObsoletePageWitnessV1{}) {
		t.Fatalf("error returned partial obsolete page: %#v", page)
	}
}

func obsoleteRequirePage(t *testing.T, page ObsoletePageV1, stop, projection uint8, keys ...[]byte) {
	t.Helper()
	if uint8(page.Stop) != stop || uint8(page.Projection) != projection || page.Witness == (ObsoletePageWitnessV1{}) || len(page.Rows) != len(keys) {
		t.Fatalf("obsolete page result: stop=%d projection=%d rows=%d witness=%v", page.Stop, page.Projection, len(page.Rows), page.Witness)
	}
	if stop == 1 && page.Next != nil {
		t.Fatal("exhaustion retained continuation")
	}
	for i, row := range page.Rows {
		if !bytes.Equal(row.Key(), keys[i]) {
			t.Fatalf("obsolete ordered key %d: %x want %x", i, row.Key(), keys[i])
		}
	}
	if stop != 1 && !bytes.Equal(page.Next, keys[len(keys)-1]) {
		t.Fatalf("obsolete limited continuation %x", page.Next)
	}
}

func obsoleteGenerationLiteral(g uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, g)
}

func obsoleteBatch(page ObsoletePageV1) Batch {
	return Batch{ObsoleteDeletes: page.Rows, ObsoleteConsulted: []ObsoletePageWitnessV1{page.Witness}}
}

// These ordinary tests exercise API refusals, alias ownership and admission through
// actual View/Update, rather than calling private validators with fabricated tokens.
func TestObsoleteGenerationV1Inputs(t *testing.T) {
	for _, reader := range []*Reader{nil, {}} {
		page, err := reader.ObsoleteGenerationPageV1(0, 0, []byte{}, 0)
		obsoleteRequireZero(t, page)
		obsoleteRequireError(t, err, "prefix-page", "InvalidInput", 22, "Reader is not active")
		page, err = reader.ObsoleteUndoPageV1(ObsoleteRowV1{}, []byte{}, 0)
		obsoleteRequireZero(t, page)
		obsoleteRequireError(t, err, "prefix-page", "InvalidInput", 22, "Reader is not active")
	}
	row := ObsoleteRowV1{}
	if row.Key() != nil || row.Length() != 0 {
		t.Fatal("zero row metadata")
	}
	n, err := row.ReadAt(make([]byte, 65_537), math.MaxUint64)
	if n != 0 {
		t.Fatal("zero row copied bytes")
	}
	obsoleteRequireError(t, err, "get", "InvalidInput", 22, "invalid obsolete generation row")
	store, _, _ := consultedStore(t)
	mustEnvironment(t, store.View(func(reader *Reader) error {
		for _, selector := range []struct {
			g     uint64
			class ObsoleteClassV1
		}{{0, 1}, {0, 2}, {0, 3}, {0, 4}, {1, 0}, {1, 5}, {1, 255}} {
			page, err := reader.ObsoleteGenerationPageV1(selector.g, selector.class, []byte{}, 0)
			obsoleteRequireZero(t, page)
			obsoleteRequireError(t, err, "prefix-page", "InvalidInput", 22, "invalid obsolete generation selector")
		}
		for _, class := range []ObsoleteClassV1{1, 2, 3, 4} {
			for _, count := range []uint32{0, 1441, math.MaxUint32} {
				page, err := reader.ObsoleteGenerationPageV1(1, class, nil, count)
				obsoleteRequireZero(t, page)
				obsoleteRequireError(t, err, "prefix-page", "InvalidInput", 22, "invalid obsolete generation page bounds")
			}
			for _, after := range [][]byte{{}, {0}, obsoleteGenerationLiteral(2), bytes.Repeat([]byte{1}, 2023)} {
				page, err := reader.ObsoleteGenerationPageV1(1, class, after, 1)
				obsoleteRequireZero(t, page)
				obsoleteRequireError(t, err, "prefix-page", "InvalidInput", 22, "invalid obsolete generation page bounds")
			}
			for _, count := range []uint32{1, 7, 1440} {
				page, err := reader.ObsoleteGenerationPageV1(math.MaxUint64, class, nil, count)
				mustEnvironment(t, err)
				obsoleteRequirePage(t, page, 1, 1)
			}
		}
		page, err := reader.ObsoleteUndoPageV1(ObsoleteRowV1{}, []byte{}, 0)
		obsoleteRequireZero(t, page)
		obsoleteRequireError(t, err, "prefix-page", "InvalidInput", 22, "invalid or foreign obsolete generation index")
		if !reader.usable() || reader.failure != nil {
			t.Fatal("cheap input refusal disarmed Reader")
		}
		return nil
	}))
}

func TestObsoleteGenerationV1CounterLifetime(t *testing.T) {
	store, _, _ := consultedStore(t)
	seed := consultedCounter(t, 9)
	largeCommit(t, store, Batch{Mutations: []Mutation{seed}})
	var saved ObsoleteRowV1
	truth, stage, err := store.Update(func(reader *Reader) (Batch, error) {
		page, err := reader.ObsoleteGenerationPageV1(9, 3, nil, 1)
		mustEnvironment(t, err)
		obsoleteRequirePage(t, page, 1, 1, seed.Key)
		saved = page.Rows[0]
		if saved.Length() != 16 {
			t.Fatalf("counter raw length=%d", saved.Length())
		}
		for _, query := range []struct {
			size   int
			offset uint64
			n      int
			eof    bool
		}{{0, 0, 0, false}, {0, math.MaxUint64, 0, false}, {16, 0, 16, false}, {1, 15, 1, false}, {2, 15, 1, true}, {1, 16, 0, true}, {1, math.MaxUint64, 0, true}, {65_536, 0, 16, true}} {
			buffer := make([]byte, query.size)
			n, readErr := saved.ReadAt(buffer, query.offset)
			wantErr := error(nil)
			if query.eof {
				wantErr = io.EOF
			}
			if n != query.n || readErr != wantErr {
				t.Fatalf("ReadAt(%d,%d)=%d/%v want %d/%v", query.size, query.offset, n, readErr, query.n, wantErr)
			}
			if n != 0 && !bytes.Equal(buffer[:n], seed.Literal[int(query.offset):int(query.offset)+n]) {
				t.Fatal("counter raw bytes changed")
			}
		}
		n, readErr := saved.ReadAt(make([]byte, 65_537), 16)
		if n != 0 {
			t.Fatal("over-window copied bytes")
		}
		obsoleteRequireError(t, readErr, "get", "InvalidInput", 22, "ReadAt buffer exceeds 65536 bytes")
		key := saved.Key()
		key[0], key[8] = 0xff, 0xff
		if !bytes.Equal(saved.Key(), seed.Key) {
			t.Fatal("Key exposed private key alias")
		}
		passed, err := reader.ObsoleteGenerationPageV1(9, 3, seed.Key, 7)
		mustEnvironment(t, err)
		obsoleteRequirePage(t, passed, 1, 1)
		// Sequential pages do not expire earlier rows.
		buffer := make([]byte, 16)
		if n, err := saved.ReadAt(buffer, 0); n != 16 || err != nil || !bytes.Equal(buffer, seed.Literal) {
			t.Fatal("sequential counter page expired prior row")
		}
		return Batch{ObsoleteDeletes: []ObsoleteRowV1{saved}, ObsoleteConsulted: []ObsoletePageWitnessV1{passed.Witness}}, nil
	})
	if truth.String() != "NEW" || int(stage) != 3 || err != nil || string(store.state) != "OPEN" {
		t.Fatalf("raw-only private OLD admission %s/%d/%v/%s", truth, stage, err, store.state)
	}
	_, err = saved.ReadAt(make([]byte, 65_537), math.MaxUint64)
	obsoleteRequireError(t, err, "get", "InvalidInput", 22, "Reader is not active")
	consultedRequireImage(t, store, seed.DBI, seed.Key, nil, false, "raw-only delete")
}

func TestObsoleteGenerationV1Admission(t *testing.T) {
	for _, variant := range []string{"zero-row", "zero-witness", "missing-witness", "wrong-scope", "duplicate-row", "duplicate-witness", "legacy-collision", "ordinary-target", "Reverse", "witness-only", "View", "previous-Update", "foreign-Store"} {
		t.Run(variant, func(t *testing.T) {
			store, _, _ := consultedStore(t)
			seed := consultedCounter(t, 9)
			largeCommit(t, store, Batch{Mutations: []Mutation{seed}})
			var foreign ObsoletePageV1
			if variant == "View" || variant == "foreign-Store" {
				owner := store
				if variant == "foreign-Store" {
					owner, _, _ = consultedStore(t)
					largeCommit(t, owner, Batch{Mutations: []Mutation{seed}})
				}
				mustEnvironment(t, owner.View(func(reader *Reader) error {
					var err error
					foreign, err = reader.ObsoleteGenerationPageV1(9, 3, nil, 1)
					return err
				}))
			}
			if variant == "previous-Update" {
				truth, _, err := store.Update(func(reader *Reader) (Batch, error) {
					var err error
					foreign, err = reader.ObsoleteGenerationPageV1(9, 3, nil, 1)
					return Batch{Mutations: []Mutation{consultedCounter(t, 10)}}, err
				})
				if truth.String() != "NEW" || err != nil {
					t.Fatal("previous Update seed", truth, err)
				}
			}
			truth, stage, err := store.Update(func(reader *Reader) (Batch, error) {
				page, err := reader.ObsoleteGenerationPageV1(9, 3, nil, 1)
				mustEnvironment(t, err)
				batch := obsoleteBatch(page)
				switch variant {
				case "zero-row":
					batch.ObsoleteDeletes[0] = ObsoleteRowV1{}
				case "zero-witness":
					batch.ObsoleteConsulted[0] = ObsoletePageWitnessV1{}
				case "missing-witness":
					batch.ObsoleteConsulted = nil
				case "wrong-scope":
					other, err := reader.ObsoleteGenerationPageV1(10, 3, nil, 1)
					mustEnvironment(t, err)
					batch.ObsoleteConsulted = []ObsoletePageWitnessV1{other.Witness}
				case "duplicate-row":
					batch.ObsoleteDeletes = append(batch.ObsoleteDeletes, page.Rows[0])
				case "duplicate-witness":
					batch.ObsoleteConsulted = append(batch.ObsoleteConsulted, page.Witness)
				case "legacy-collision":
					batch.Mutations = []Mutation{{DBI: seed.DBI, Key: seed.Key, BeforePresent: true, AfterKind: AfterKind(1)}}
				case "ordinary-target":
					batch.Consulted = []ConsultedRow{{DBI: seed.DBI, Key: seed.Key}}
				case "Reverse":
					batch.Reverse = true
				case "witness-only":
					batch.ObsoleteDeletes = nil
				default:
					batch = obsoleteBatch(foreign)
				}
				return batch, nil
			})
			obsoleteRequireError(t, err, "update", "InvalidInput", 22, "invalid Update Batch")
			if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "OPEN" {
				t.Fatal("admission refusal disposition", truth, stage, store.state)
			}
			consultedRequireImage(t, store, seed.DBI, seed.Key, seed.Literal, true, variant+" OLD")
			largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 11)}})
		})
	}
}

func TestObsoleteGenerationV1Applications(t *testing.T) {
	for _, variant := range []string{"nil", "error", "typed-nil", "direct", "wrapped", "cause-bearing", "panic"} {
		t.Run(variant, func(t *testing.T) {
			store, _, _ := consultedStore(t)
			seed := consultedCounter(t, 9)
			largeCommit(t, store, Batch{Mutations: []Mutation{seed}})
			application := error(errors.New("obsolete application"))
			originalCause := errors.New("existing cause")
			if variant == "typed-nil" {
				application = (*largeTypedNil)(nil)
			}
			if variant == "direct" || variant == "wrapped" {
				application = &EngineError{Operation: "get", Class: EngineIO, Code: 5, Diagnostic: "application direct"}
				if variant == "wrapped" {
					application = fmt.Errorf("application wrapper: %w", application)
				}
			}
			if variant == "cause-bearing" {
				application = &EngineError{Operation: "get", Class: EngineIO, Code: 5, Diagnostic: "application cause", Cause: originalCause}
			}
			payload := &struct{ value string }{"obsolete panic"}
			var recovered any
			var saved ObsoleteRowV1
			var truth CommitTruth
			var stage UpdateStage
			var result error
			func() {
				defer func() { recovered = recover() }()
				truth, stage, result = store.Update(func(reader *Reader) (Batch, error) {
					page, err := reader.ObsoleteGenerationPageV1(9, 3, nil, 1)
					mustEnvironment(t, err)
					saved = page.Rows[0]
					if variant == "panic" {
						panic(payload)
					}
					if variant == "nil" {
						return obsoleteBatch(page), nil
					}
					return obsoleteBatch(page), application
				})
			}()
			if variant == "panic" {
				if recovered != payload || result != nil {
					t.Fatal("application panic changed", recovered, result)
				}
			} else if variant == "nil" {
				if truth.String() != "NEW" || int(stage) != 3 || result != nil {
					t.Fatal("nil callback result", truth, stage, result)
				}
			} else if truth.String() != "OLD" || int(stage) != 1 || result != application {
				t.Fatal("application identity", truth, stage, result)
			}
			if variant == "cause-bearing" && application.(*EngineError).Cause != originalCause {
				t.Fatal("original application Cause changed")
			}
			if string(store.state) != "OPEN" || store.terminal != nil {
				t.Fatal("application outcome changed owner state")
			}
			_, expired := saved.ReadAt(nil, 0)
			obsoleteRequireError(t, expired, "get", "InvalidInput", 22, "Reader is not active")
			want := seed.Literal
			if variant == "nil" {
				want = nil
			}
			consultedRequireImage(t, store, seed.DBI, seed.Key, want, variant != "nil", variant)
			largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 11)}})
		})
	}
}

func TestObsoleteGenerationV1ConcurrentExpiry(t *testing.T) {
	store, _, _ := consultedStore(t)
	seed := consultedCounter(t, 9)
	largeCommit(t, store, Batch{Mutations: []Mutation{seed}})
	started, done := make(chan struct{}), make(chan error, 1)
	truth, stage, err := store.Update(func(reader *Reader) (Batch, error) {
		page, err := reader.ObsoleteGenerationPageV1(9, 3, nil, 1)
		mustEnvironment(t, err)
		row := page.Rows[0]
		go func() {
			close(started)
			for {
				buffer := make([]byte, 16)
				n, err := row.ReadAt(buffer, 0)
				if err != nil {
					done <- err
					return
				}
				if n != 16 || !bytes.Equal(buffer, seed.Literal) {
					done <- fmt.Errorf("concurrent row bytes %d/%x", n, buffer)
					return
				}
				runtime.Gosched()
			}
		}()
		<-started
		return obsoleteBatch(page), nil
	})
	if truth.String() != "NEW" || int(stage) != 3 || err != nil {
		t.Fatal("expiry Update", truth, stage, err)
	}
	obsoleteRequireError(t, <-done, "get", "InvalidInput", 22, "Reader is not active")
	consultedRequireImage(t, store, seed.DBI, seed.Key, nil, false, "expiry committed delete")
}

func TestObsoleteGenerationV1JointBounds(t *testing.T) {
	for _, variant := range []string{"raw-count", "witness-count", "Reverse-first", "legacy-first", "aux-exact", "aux-over"} {
		t.Run(variant, func(t *testing.T) {
			store, _, _ := consultedStore(t)
			seed := consultedCounter(t, 9)
			largeCommit(t, store, Batch{Mutations: []Mutation{seed}})
			truth, stage, result := store.Update(func(reader *Reader) (Batch, error) {
				page, err := reader.ObsoleteGenerationPageV1(9, 3, nil, 1)
				mustEnvironment(t, err)
				batch := obsoleteBatch(page)
				switch variant {
				case "raw-count":
					batch.ObsoleteDeletes = make([]ObsoleteRowV1, 2_391_107)
				case "witness-count":
					batch.ObsoleteConsulted = make([]ObsoletePageWitnessV1, 2_391_106)
				case "Reverse-first":
					batch.ObsoleteDeletes = make([]ObsoleteRowV1, 2_391_107)
					batch.Reverse = true
				case "legacy-first":
					batch.Mutations = []Mutation{{DBI: readDBIsLiteral()[0], Key: []byte{2}}}
					batch.ObsoleteDeletes = make([]ObsoleteRowV1, 2_391_107)
					batch.Reverse = true
				default:
					count := 16_383
					if variant == "aux-over" {
						count = 16_384
					}
					batch.Mutations = updatePlanAuxBatch(t, count).Mutations
					for i := range batch.Mutations {
						batch.Mutations[i].DBI = readDBIsLiteral()[6]
					}
				}
				return batch, nil
			})
			if variant == "aux-exact" {
				if truth.String() != "NEW" || int(stage) != 3 || result != nil {
					t.Fatal("joint exact16384 aux", truth, stage, result)
				}
				consultedRequireImage(t, store, seed.DBI, seed.Key, nil, false, "joint aux exact raw target")
			} else {
				class, code, diagnostic := "Capacity", -30417, "Update Batch exceeds bound"
				if variant == "Reverse-first" || variant == "legacy-first" {
					class, code, diagnostic = "InvalidInput", 22, "invalid Update Batch"
				}
				obsoleteRequireError(t, result, "update", class, code, diagnostic)
				if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "OPEN" {
					t.Fatal("joint bound before effect", truth, stage, store.state)
				}
				consultedRequireImage(t, store, seed.DBI, seed.Key, seed.Literal, true, "joint bound preserves OLD")
			}
		})
	}
}

func TestObsoleteGenerationV1UndoTokens(t *testing.T) {
	store, _, _ := consultedStore(t)
	work := [40]byte{}
	work[39] = 1
	forward := canonicalForwardLiteral(9, 1, [32]byte{1}, work)
	largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 9), forward, canonicalOwnerPairOf(forward)}})
	var foreign ObsoleteRowV1
	mustEnvironment(t, store.View(func(reader *Reader) error {
		page, err := reader.ObsoleteGenerationPageV1(9, 2, nil, 1)
		mustEnvironment(t, err)
		foreign = page.Rows[0]
		return nil
	}))
	mustEnvironment(t, store.View(func(reader *Reader) error {
		counter, err := reader.ObsoleteGenerationPageV1(9, 3, nil, 1)
		mustEnvironment(t, err)
		for _, row := range []ObsoleteRowV1{{}, foreign, counter.Rows[0]} {
			page, err := reader.ObsoleteUndoPageV1(row, []byte{}, 0)
			obsoleteRequireZero(t, page)
			obsoleteRequireError(t, err, "prefix-page", "InvalidInput", 22, "invalid or foreign obsolete generation index")
		}
		if !reader.usable() || reader.failure != nil {
			t.Fatal("invalid token disarmed Reader")
		}
		return nil
	}))
}
