//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
)

// canonicalForwardDBILiteral and canonicalOwnerDBILiteral are the SchemaV2 rank-2 and rank-7 DBIs, written out
// independently of the production schema table.
var canonicalForwardDBILiteral, canonicalOwnerDBILiteral = DBI{Name: "canonical-v1", Rank: 2}, DBI{Name: "canonical-owner-v1", Rank: 7}

// canonicalForwardKeyLiteral is BE64(generation) || BE64(height), independent of HeightKey.
func canonicalForwardKeyLiteral(generation, height uint64) []byte {
	return binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, generation), height)
}

// canonicalOwnerKeyLiteral is BE64(generation) || hash, independent of CanonicalOwnerKey.
func canonicalOwnerKeyLiteral(generation uint64, hash [32]byte) []byte {
	return append(binary.BigEndian.AppendUint64(nil, generation), hash[:]...)
}

// canonicalForwardValueLiteral is hash || 32 zero parent bytes || work, independent of ChainValue.
func canonicalForwardValueLiteral(hash [32]byte, work [40]byte) []byte {
	return append(append(append([]byte(nil), hash[:]...), make([]byte, 32)...), work[:]...)
}

func canonicalForwardLiteral(generation, height uint64, hash [32]byte, work [40]byte) Mutation {
	return Mutation{DBI: canonicalForwardDBILiteral, Key: canonicalForwardKeyLiteral(generation, height), AfterKind: AfterLiteral, Literal: canonicalForwardValueLiteral(hash, work)}
}

// canonicalOwnerLiteral inserts owner (generation, hash) holding BE64(height), independent of CanonicalOwnerValue.
func canonicalOwnerLiteral(generation, height uint64, hash [32]byte) Mutation {
	return Mutation{DBI: canonicalOwnerDBILiteral, Key: canonicalOwnerKeyLiteral(generation, hash), AfterKind: AfterLiteral, Literal: binary.BigEndian.AppendUint64(nil, height)}
}

// canonicalOwnerPairOf is the owner insert paired with a forward literal, derived from the forward bytes alone.
func canonicalOwnerPairOf(forward Mutation) Mutation {
	key := append(append([]byte(nil), forward.Key[:8]...), forward.Literal[:32]...)
	return Mutation{DBI: canonicalOwnerDBILiteral, Key: key, AfterKind: AfterLiteral, Literal: append([]byte(nil), forward.Key[8:16]...)}
}

func canonicalDelete(m Mutation) Mutation {
	return Mutation{DBI: m.DBI, Key: m.Key, BeforePresent: true, AfterKind: AfterAbsent}
}

func canonicalReplace(m Mutation) Mutation {
	m.BeforePresent = true
	return m
}

// canonicalLookup runs one CanonicalOwnerV1 inside View and requires the View itself to succeed.
func canonicalLookup(t *testing.T, store *Store, generation uint64, hash [32]byte) (CanonicalOwnerResultV1, error) {
	t.Helper()
	var result CanonicalOwnerResultV1
	var lookupErr error
	mustEnvironment(t, store.View(func(reader *Reader) error {
		result, lookupErr = reader.CanonicalOwnerV1(generation, hash)
		return nil
	}))
	return result, lookupErr
}

func canonicalRequireNone(t *testing.T, result CanonicalOwnerResultV1, err error, generation uint64, hash [32]byte, marker string) {
	t.Helper()
	want := []ConsultedRow{{DBI: canonicalOwnerDBILiteral, Key: canonicalOwnerKeyLiteral(generation, hash)}}
	if err != nil || result.Owned || result.Height != 0 || result.Entry != nil || !reflect.DeepEqual(result.Rows, want) {
		t.Fatalf("%s: none observation drifted: %+v/%v", marker, result, err)
	}
}

func canonicalRequireOwned(t *testing.T, result CanonicalOwnerResultV1, err error, height uint64, entry []byte, rows []ConsultedRow, marker string) {
	t.Helper()
	if err != nil || !result.Owned || result.Height != height || !bytes.Equal(result.Entry, entry) || !reflect.DeepEqual(result.Rows, rows) {
		t.Fatalf("%s: owned observation drifted: %+v/%v", marker, result, err)
	}
}

// canonicalRequireUnverified proves the unverified refusal tuple, no recorded failure and a Reader that still reads.
func canonicalRequireUnverified(t *testing.T, reader *Reader, result CanonicalOwnerResultV1, err error, marker string) {
	t.Helper()
	engine, direct := directTestEngineError(err)
	if !direct || engine.Class != EngineInvalidInput || engine.Operation != "get" || engine.Code != 22 || engine.Diagnostic != "canonical owner index is not verified" || engine.Cause != nil || engine.ReopenRequired ||
		!reflect.DeepEqual(result, CanonicalOwnerResultV1{}) || reader.failure != nil || !reader.active.Load() {
		t.Fatalf("%s: unverified refusal drifted: %+v/%v/%v", marker, result, err, reader.failure)
	}
	value, present, getErr := reader.Get(DBI{Name: "meta-v1"}, []byte{0})
	if getErr != nil || !present || !bytes.Equal(value, []byte{0, 0, 0, 2}) {
		t.Fatalf("%s: unverified refusal disabled the Reader: %x/%v/%v", marker, value, present, getErr)
	}
}

// canonicalRequireRecorded runs prepare and one lookup inside an Update callback that returns the lookup error, then
// proves the exact recorded error, its Reader provenance, the consumed Store and the cached refusal of the next
// Update and View.
func canonicalRequireRecorded(t *testing.T, store *Store, prepare func(*Reader), generation uint64, hash [32]byte, class EngineClass, code int, diagnostic, marker string) {
	t.Helper()
	var reader *Reader
	var result CanonicalOwnerResultV1
	var lookupErr error
	truth, stage, err := store.Update(func(observed *Reader) (Batch, error) {
		reader = observed
		if prepare != nil {
			prepare(observed)
		}
		result, lookupErr = observed.CanonicalOwnerV1(generation, hash)
		return Batch{}, lookupErr
	})
	engine := requireEnvironmentError(t, lookupErr, class, operationGet, code, diagnostic)
	if engine.Cause != nil || !reflect.DeepEqual(result, CanonicalOwnerResultV1{}) || !sameError(reader.failure, lookupErr) || reader.active.Load() {
		t.Fatalf("%s: recorded lookup failure drifted: %+v/%v", marker, result, reader.failure)
	}
	if truth != CommitTruthOld || stage != UpdateStagePrewrite || !sameError(err, lookupErr) || store.state != storeCLOSED || store.terminalTruth != CommitTruthOld || !sameError(store.terminal, lookupErr) {
		t.Fatalf("%s: enclosing Update disposition drifted: %s/%d/%v/%s", marker, truth, stage, err, store.state)
	}
	again, againStage, cached := store.Update(func(*Reader) (Batch, error) {
		t.Fatalf("%s: consumed Store entered Update", marker)
		return Batch{}, nil
	})
	viewErr := store.View(func(*Reader) error { t.Fatalf("%s: consumed Store entered View", marker); return nil })
	if again != CommitTruthOld || againStage != UpdateStagePrewrite || !sameError(cached, lookupErr) || !sameError(viewErr, lookupErr) {
		t.Fatalf("%s: consumed Store accepted the next operation: %s/%d/%v/%v", marker, again, againStage, cached, viewErr)
	}
}

// canonicalRequireImage proves every kept row reads back exactly and every other listed key is absent.
func canonicalRequireImage(t *testing.T, store *Store, kept, others []Mutation) {
	t.Helper()
	for _, row := range kept {
		requireUpdateValue(t, store, row.DBI, row.Key, row.Literal, true)
	}
	for _, row := range others {
		if !canonicalKeptKey(kept, row) {
			requireUpdateValue(t, store, row.DBI, row.Key, nil, false)
		}
	}
}

func canonicalKeptKey(kept []Mutation, row Mutation) bool {
	for _, candidate := range kept {
		if candidate.DBI == row.DBI && bytes.Equal(candidate.Key, row.Key) {
			return true
		}
	}
	return false
}

// canonicalFormat proves the eight SchemaV2 DBIs in rank order with meta 2 and every other count 0, and version row
// 00000002; it returns the (DBI, Entries) projection for a reopen comparison.
func canonicalFormat(t *testing.T, store *Store, marker string) [8]DBIInspection {
	t.Helper()
	want := [8]DBI{{Name: "meta-v1", Rank: 0}, {Name: "utxo-v1", Rank: 1}, {Name: "canonical-v1", Rank: 2}, {Name: "headers-v1", Rank: 3}, {Name: "blocks-v1", Rank: 4}, {Name: "undo-v1", Rank: 5}, {Name: "staged-v1", Rank: 6}, {Name: "canonical-owner-v1", Rank: 7}}
	inspection, err := store.Inspect()
	mustEnvironment(t, err)
	var projection [8]DBIInspection
	for i, row := range inspection.DBIs {
		entries := uint64(0)
		if i == 0 {
			entries = 2
		}
		if row.DBI != want[i] || row.Entries != entries {
			t.Fatalf("%s: SchemaV2 DBI %d drifted: %+v", marker, i, row)
		}
		projection[i] = DBIInspection{DBI: row.DBI, Entries: row.Entries}
	}
	requireUpdateValue(t, store, want[0], []byte{0}, []byte{0, 0, 0, 2}, true)
	return projection
}

func TestCanonicalOwnerSchemaV2Format(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	store, err := Create(path, cfg)
	mustEnvironment(t, err)
	created := canonicalFormat(t, store, "created")
	mustEnvironment(t, store.Close())
	reopened, err := Open(path, cfg)
	mustEnvironment(t, err)
	defer func() { mustEnvironment(t, reopened.Close()) }()
	if got := canonicalFormat(t, reopened, "reopened"); got != created {
		t.Fatalf("reopened SchemaV2 inspection drifted: %+v / %+v", got, created)
	}
}

func TestCanonicalOwnerPrefixPage(t *testing.T) {
	store := newUpdateStore(t)
	defer func() { mustEnvironment(t, store.Close()) }()
	work := [40]byte{39: 1}
	first, second, third, other := [32]byte{0x30}, [32]byte{0x10}, [32]byte{0x20}, [32]byte{0x05}
	requireUpdateCommit(t, store, "owner prefix seed",
		canonicalForwardLiteral(5, 1, first, work), canonicalForwardLiteral(5, 2, second, work), canonicalForwardLiteral(5, 3, third, work), canonicalForwardLiteral(6, 1, other, work),
		canonicalOwnerLiteral(5, 2, second), canonicalOwnerLiteral(5, 3, third), canonicalOwnerLiteral(5, 1, first), canonicalOwnerLiteral(6, 1, other))
	want := []PrefixRow{
		{Key: canonicalOwnerKeyLiteral(5, second), Value: []byte{0, 0, 0, 0, 0, 0, 0, 2}},
		{Key: canonicalOwnerKeyLiteral(5, third), Value: []byte{0, 0, 0, 0, 0, 0, 0, 3}},
		{Key: canonicalOwnerKeyLiteral(5, first), Value: []byte{0, 0, 0, 0, 0, 0, 0, 1}},
	}
	prefix := []byte{0, 0, 0, 0, 0, 0, 0, 5}
	mustEnvironment(t, store.View(func(reader *Reader) error {
		for _, row := range []struct {
			after    []byte
			maxBytes uint64
			rows     []PrefixRow
			stop     PrefixPageStop
		}{
			{nil, MaxPrefixPageBytes, want, PrefixPageStop(1)},
			{nil, 48, want[:1], PrefixPageStop(3)},
			{want[0].Key, 48, want[1:2], PrefixPageStop(3)},
			{want[1].Key, 1_000, want[2:], PrefixPageStop(1)},
		} {
			page, err := reader.PrefixPage(canonicalOwnerDBILiteral, prefix, row.after, 1_440, row.maxBytes)
			if err != nil || page.Stop != row.stop || !reflect.DeepEqual(page.Rows, row.rows) {
				t.Fatalf("canonical owner prefix page drifted: after %x bytes %d: %+v/%v", row.after, row.maxBytes, page, err)
			}
		}
		page, err := reader.PrefixPage(canonicalOwnerDBILiteral, prefix, nil, 1_440, 47)
		requirePrefixPageError(t, page, err, "invalid prefix-page byte limit", nil)
		page, err = reader.PrefixPage(canonicalOwnerDBILiteral, make([]byte, 8), nil, 1_440, 48)
		requirePrefixPageError(t, page, err, "invalid prefix-page prefix", nil)
		page, err = reader.PrefixPage(canonicalOwnerDBILiteral, prefix, want[0].Key[:39], 1_440, 48)
		requirePrefixPageError(t, page, err, "invalid prefix-page continuation", nil)
		return nil
	}))
}

func TestCanonicalOwnerPairedCommit(t *testing.T) {
	a, b, work := [32]byte{0xa1}, [32]byte{0xb2}, [40]byte{39: 1}
	t.Run("insert and delete", func(t *testing.T) {
		store := newUpdateStore(t)
		defer func() { mustEnvironment(t, store.Close()) }()
		forward, owner := canonicalForwardLiteral(2, 10, a, work), canonicalOwnerLiteral(2, 10, a)
		requireUpdateCommit(t, store, "paired insert", forward, owner)
		requireUpdateValue(t, store, canonicalForwardDBILiteral, []byte{0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 10}, canonicalForwardValueLiteral(a, work), true)
		requireUpdateValue(t, store, canonicalOwnerDBILiteral, append([]byte{0, 0, 0, 0, 0, 0, 0, 2}, a[:]...), []byte{0, 0, 0, 0, 0, 0, 0, 10}, true)
		requireUpdateCommit(t, store, "paired delete", canonicalDelete(forward), canonicalDelete(owner))
		canonicalRequireImage(t, store, nil, []Mutation{forward, owner})
	})
	t.Run("hash replacement", func(t *testing.T) {
		store := newUpdateStore(t)
		defer func() { mustEnvironment(t, store.Close()) }()
		requireUpdateCommit(t, store, "replacement seed", canonicalForwardLiteral(2, 10, a, work), canonicalOwnerLiteral(2, 10, a))
		replacement, owner := canonicalReplace(canonicalForwardLiteral(2, 10, b, work)), canonicalOwnerLiteral(2, 10, b)
		requireUpdateCommit(t, store, "hash replacement", replacement, canonicalDelete(canonicalOwnerLiteral(2, 10, a)), owner)
		canonicalRequireImage(t, store, []Mutation{replacement, owner}, []Mutation{canonicalOwnerLiteral(2, 10, a)})
	})
	t.Run("height swap", func(t *testing.T) {
		store := newUpdateStore(t)
		defer func() { mustEnvironment(t, store.Close()) }()
		requireUpdateCommit(t, store, "swap seed", canonicalForwardLiteral(2, 10, a, work), canonicalForwardLiteral(2, 11, b, work), canonicalOwnerLiteral(2, 10, a), canonicalOwnerLiteral(2, 11, b))
		swapped := []Mutation{
			canonicalReplace(canonicalForwardLiteral(2, 10, b, work)), canonicalReplace(canonicalForwardLiteral(2, 11, a, work)),
			canonicalReplace(canonicalOwnerLiteral(2, 11, a)), canonicalReplace(canonicalOwnerLiteral(2, 10, b)),
		}
		requireUpdateCommit(t, store, "height swap", swapped...)
		canonicalRequireImage(t, store, swapped, nil)
	})
	t.Run("reverse delete", func(t *testing.T) {
		store := newUpdateStore(t)
		defer func() { mustEnvironment(t, store.Close()) }()
		forward, owner := canonicalForwardLiteral(2, 10, a, work), canonicalOwnerLiteral(2, 10, a)
		requireUpdateCommit(t, store, "reverse seed", forward, owner)
		reverseBatchCommit(t, store, "reverse paired delete", canonicalDelete(forward), canonicalDelete(owner))
		canonicalRequireImage(t, store, nil, []Mutation{forward, owner})
	})
}

func TestCanonicalOwnerPairingRefusals(t *testing.T) {
	x, y, z, work := [32]byte{0x10}, [32]byte{0x20}, [32]byte{0x30}, [40]byte{39: 1}
	seed := []Mutation{canonicalForwardLiteral(3, 7, x, work), canonicalOwnerLiteral(3, 7, x)}
	for _, row := range []struct {
		name   string
		seeded bool
		batch  []Mutation
	}{
		{"N1 forward insert without owner", false, []Mutation{canonicalForwardLiteral(3, 7, x, work)}},
		{"N2 owner insert without forward", false, []Mutation{canonicalOwnerLiteral(3, 7, x)}},
		{"N1 owner literal holds h+1", false, []Mutation{canonicalForwardLiteral(3, 7, x, work), canonicalForwardLiteral(3, 8, x, work), canonicalOwnerLiteral(3, 8, x)}},
		{"N2 owner names a forward of another hash", false, []Mutation{canonicalForwardLiteral(3, 7, x, work), canonicalOwnerLiteral(3, 7, x), canonicalOwnerLiteral(3, 7, z)}},
		{"N1 two forwards name one hash", false, []Mutation{canonicalForwardLiteral(3, 7, x, work), canonicalForwardLiteral(3, 8, x, work), canonicalOwnerLiteral(3, 7, x)}},
		{"O1 forward delete keeps its owner", true, []Mutation{canonicalDelete(seed[0])}},
		{"O1 forward replacement keeps its owner", true, []Mutation{canonicalReplace(canonicalForwardLiteral(3, 7, y, work)), canonicalOwnerLiteral(3, 7, y)}},
		{"O2 owner delete keeps its forward", true, []Mutation{canonicalDelete(seed[1])}},
		{"O2 owner replacement keeps its forward", true, []Mutation{canonicalForwardLiteral(3, 8, x, work), canonicalReplace(canonicalOwnerLiteral(3, 8, x))}},
		{"N1 owner partner is deleted", true, []Mutation{canonicalReplace(canonicalForwardLiteral(3, 7, x, [40]byte{39: 2})), canonicalDelete(seed[1])}},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			var kept []Mutation
			if row.seeded {
				requireUpdateCommit(t, store, row.name+": seed", seed...)
				kept = seed
			}
			var reader *Reader
			truth, stage, err := store.Update(func(observed *Reader) (Batch, error) { reader = observed; return Batch{Mutations: row.batch}, nil })
			if stage != UpdateStagePrewrite {
				t.Fatalf("%s: stage %d", row.name, stage)
			}
			consultedRequireOutcome(t, store, reader, truth, err, EngineInvalidInput, 22, "unpaired canonical owner mutation", row.name, true)
			reopened, openErr := Open(path, cfg)
			reopened = consultedTrack(t, reopened, openErr)
			canonicalRequireImage(t, reopened, kept, row.batch)
		})
	}
}

func TestCanonicalOwnerPairingOrder(t *testing.T) {
	x, y, work := [32]byte{0x61}, [32]byte{0x62}, [40]byte{39: 1}
	for _, missingRef := range []bool{false, true} {
		t.Run(fmt.Sprintf("late target fault precedes pairing and reference=%v", missingRef), func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			forward, owner := canonicalForwardLiteral(5, 1, x, work), canonicalOwnerLiteral(5, 2, y)
			seed := []Mutation{canonicalForwardLiteral(5, 2, y, work), owner}
			requireUpdateCommit(t, store, "late target fault seed", seed...)
			batch := Batch{Mutations: []Mutation{forward}}
			if missingRef {
				target, source := reverseKeys(t, 1, 3)
				batch.Mutations = append(batch.Mutations, forwardRefRow(source, target))
			}
			batch.Mutations = append(batch.Mutations, canonicalDelete(owner))
			var reader *Reader
			truth, stage, err := store.Update(func(observed *Reader) (Batch, error) {
				reader = observed
				store.dbis[7] = ^store.dbis[7]
				return batch, nil
			})
			if stage != 1 {
				t.Fatal("target qualification fault advanced stage")
			}
			consultedRequireOutcome(t, store, reader, truth, err, EngineClass("LocalInvariant"), -30780, expectedNativeDiagnostic(-30780), "complete target qualification first", true)
			reopened, openErr := Open(path, cfg)
			consultedTrack(t, reopened, openErr)
			canonicalRequireImage(t, reopened, seed, batch.Mutations)
		})
	}
	t.Run("capture precedes pairing", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		target, source := reverseKeys(t, 1, 3)
		reader, truth, err := consultedUpdate(store, func(*Reader) {}, Batch{Mutations: []Mutation{canonicalForwardLiteral(5, 1, x, work), forwardRefRow(source, target)}})
		consultedRequireOutcome(t, store, reader, truth, err, EngineStateMismatch, -30779, "OLD_VALUE_REF is absent from OLD", "capture precedes pairing", true)
	})
	t.Run("pairing precedes the OLD/write comparison", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		counter := consultedCounter(t, 1)
		requireUpdateCommit(t, store, "order seed", counter)
		drift, replacement := canonicalReplace(consultedCounter(t, 1)), canonicalReplace(consultedCounter(t, 1))
		drift.Literal, replacement.Literal = LogicalCounterValue(9, 9), LogicalCounterValue(2, 2)
		reader, truth, err := consultedUpdate(store, func(observed *Reader) {
			requireUpdateTruth(t, store.updateNative(updateNativePlan(t, drift), nil, observed.txn), CommitTruthNew, true, nil, nil)
		}, Batch{Mutations: []Mutation{replacement, canonicalForwardLiteral(5, 1, x, work)}})
		consultedRequireOutcome(t, store, reader, truth, err, EngineInvalidInput, 22, "unpaired canonical owner mutation", "pairing precedes the OLD/write comparison", true)
	})
	t.Run("one refusal for N1 and O2", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		owner := canonicalOwnerLiteral(5, 2, y)
		requireUpdateCommit(t, store, "mixed seed", canonicalForwardLiteral(5, 2, y, work), owner)
		reader, truth, err := consultedUpdate(store, func(*Reader) {}, Batch{Mutations: []Mutation{canonicalForwardLiteral(5, 9, x, work), canonicalDelete(owner)}})
		consultedRequireOutcome(t, store, reader, truth, err, EngineInvalidInput, 22, "unpaired canonical owner mutation", "one refusal for N1 and O2", true)
	})
}

func TestCanonicalOwnerPairingPartnerRead(t *testing.T) {
	x, work := [32]byte{0x81}, [40]byte{39: 1}
	for _, rank := range []uint8{2, 7} {
		t.Run(fmt.Sprintf("O%d target partner performs no partner query", rank/7+1), func(t *testing.T) {
			store, _, _ := consultedStore(t)
			forward, owner := canonicalForwardLiteral(3, 7, x, work), canonicalOwnerLiteral(3, 7, x)
			requireUpdateCommit(t, store, "target partner seed", forward, owner)
			plan := updateNativePlan(t, canonicalDelete(forward), canonicalDelete(owner))
			side := canonicalSide{rank: 2, partner: 7, width: 104, partnerWidth: 8, field: 32}
			if rank == 7 {
				side = canonicalSide{rank: 7, partner: 2, width: 8, partnerWidth: 104, field: 8}
			}
			handles := store.dbis
			handles[side.partner] = ^handles[side.partner]
			mustEnvironment(t, store.View(func(reader *Reader) error {
				return canonicalOldPaired(reader.txn, handles, plan, side)
			}))
			requireUpdateCommit(t, store, "target partner paired deletion", canonicalDelete(forward), canonicalDelete(owner))
			canonicalRequireImage(t, store, nil, []Mutation{forward, owner})
		})
	}
	t.Run("O2 partner read keeps its native error", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		owner := canonicalOwnerLiteral(3, 7, x)
		requireUpdateCommit(t, store, "O2 partner read seed", canonicalForwardLiteral(3, 7, x, work), owner)
		reader, truth, err := consultedUpdate(store, func(*Reader) { store.dbis[2] = ^store.dbis[2] }, Batch{Mutations: []Mutation{canonicalDelete(owner)}})
		consultedRequireOutcome(t, store, reader, truth, err, EngineLocalInvariant, -30780, expectedNativeDiagnostic(-30780), "O2 partner read", true)
	})
	t.Run("O1 partner read keeps its native error", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		forward := canonicalForwardLiteral(3, 7, x, work)
		requireUpdateCommit(t, store, "partner read seed", forward, canonicalOwnerLiteral(3, 7, x))
		reader, truth, err := consultedUpdate(store, func(*Reader) { store.dbis[7] = ^store.dbis[7] }, Batch{Mutations: []Mutation{canonicalDelete(forward)}})
		consultedRequireOutcome(t, store, reader, truth, err, EngineLocalInvariant, -30780, expectedNativeDiagnostic(-30780), "O1 partner read", true)
	})
	t.Run("N1 precedes the partner read", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		forward := canonicalForwardLiteral(3, 7, x, work)
		requireUpdateCommit(t, store, "partner order seed", forward, canonicalOwnerLiteral(3, 7, x))
		reader, truth, err := consultedUpdate(store, func(*Reader) { store.dbis[7] = ^store.dbis[7] }, Batch{Mutations: []Mutation{canonicalDelete(forward), canonicalForwardLiteral(3, 8, [32]byte{0x82}, work)}})
		consultedRequireOutcome(t, store, reader, truth, err, EngineInvalidInput, 22, "unpaired canonical owner mutation", "N1 precedes the partner read", true)
	})
}

func TestCanonicalOwnerPairingNoCanonicalTarget(t *testing.T) {
	store, _, _ := consultedStore(t)
	hash := [32]byte{0x71}
	forward, owner := canonicalForwardLiteral(6, 2, hash, [40]byte{39: 1}), canonicalOwnerLiteral(6, 2, hash)
	requireUpdateCommit(t, store, "no-target seed", forward, owner)
	counter, handles := consultedCounter(t, 3), store.dbis
	truth, _, err := store.Update(func(*Reader) (Batch, error) {
		// Both canonical handles are unreadable for the native phase: any pairing read would fail the commit.
		store.dbis[2], store.dbis[7] = ^handles[2], ^handles[7]
		return Batch{Mutations: []Mutation{counter}}, nil
	})
	store.dbis = handles
	if truth != CommitTruthNew || err != nil {
		t.Fatalf("plan without canonical target read a canonical row: %s/%v", truth, err)
	}
	requireUpdateValue(t, store, counter.DBI, counter.Key, counter.Literal, true)
	consultedRequireCommit(t, store, "consulted-only canonical rows", Batch{Mutations: []Mutation{consultedCounter(t, 4)}, Consulted: []ConsultedRow{{DBI: forward.DBI, Key: forward.Key}, {DBI: owner.DBI, Key: owner.Key}}})
	canonicalRequireImage(t, store, []Mutation{forward, owner}, nil)
}

func TestCanonicalOwnerLookupAfterCreate(t *testing.T) {
	store := newUpdateStore(t)
	defer func() { mustEnvironment(t, store.Close()) }()
	hash := [32]byte{0xaa, 31: 0x55}
	result, err := canonicalLookup(t, store, 1, hash)
	canonicalRequireNone(t, result, err, 1, hash, "lookup immediately after Create")
}

func TestCanonicalOwnerLookupOwned(t *testing.T) {
	for name, work := range map[string][40]byte{"work one": {39: 1}, "interior work": {4: 0x12, 20: 0x34, 39: 0x56}, "work exactly 2^288": {3: 1}} {
		t.Run(name, func(t *testing.T) {
			store := newUpdateStore(t)
			defer func() { mustEnvironment(t, store.Close()) }()
			hash, other := [32]byte{0x11, 31: 0x22}, [32]byte{0x33}
			requireUpdateCommit(t, store, name, canonicalForwardLiteral(9, 41, hash, work), canonicalOwnerLiteral(9, 41, hash))
			rows := []ConsultedRow{{DBI: canonicalForwardDBILiteral, Key: canonicalForwardKeyLiteral(9, 41)}, {DBI: canonicalOwnerDBILiteral, Key: canonicalOwnerKeyLiteral(9, hash)}}
			entry := canonicalForwardValueLiteral(hash, work)
			result, err := canonicalLookup(t, store, 9, hash)
			canonicalRequireOwned(t, result, err, 41, entry, rows, name+" in View")
			result.Entry[0], result.Rows[0].Key[0], result.Rows[1].Key[0] = ^result.Entry[0], ^result.Rows[0].Key[0], ^result.Rows[1].Key[0]
			var inside CanonicalOwnerResultV1
			var insideErr error
			truth, _, updateErr := store.Update(func(reader *Reader) (Batch, error) {
				inside, insideErr = reader.CanonicalOwnerV1(9, hash)
				return Batch{Mutations: []Mutation{consultedCounter(t, 1)}}, nil
			})
			if truth != CommitTruthNew || updateErr != nil {
				t.Fatalf("%s: lookup inside Update: %s/%v", name, truth, updateErr)
			}
			canonicalRequireOwned(t, inside, insideErr, 41, entry, rows, name+" in Update after caller mutation")
			none, noneErr := canonicalLookup(t, store, 9, other)
			canonicalRequireNone(t, none, noneErr, 9, other, name+" other hash")
		})
	}
}

func TestCanonicalOwnerLookupIllegalWork(t *testing.T) {
	for name, work := range map[string][40]byte{"work zero": {}, "work 2^288+1": {3: 1, 39: 1}, "higher-order work byte": {0: 1, 39: 1}} {
		t.Run(name, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			hash := [32]byte{0x44}
			rows := []Mutation{canonicalForwardLiteral(3, 5, hash, work), canonicalOwnerLiteral(3, 5, hash)}
			requireUpdateCommit(t, store, name+": seed", rows...)
			canonicalRequireRecorded(t, store, nil, 3, hash, EngineIntegrity, codeInvalid, "canonical owner index inconsistency", name)
			reopened, err := Open(path, cfg)
			reopened = consultedTrack(t, reopened, err)
			canonicalRequireImage(t, reopened, rows, nil)
		})
	}
}

func TestCanonicalOwnerLookupNativeFailure(t *testing.T) {
	for _, rank := range []uint8{7, 2} {
		store, _, _ := consultedStore(t)
		hash := [32]byte{0x45}
		requireUpdateCommit(t, store, "native failure seed", canonicalForwardLiteral(3, 5, hash, [40]byte{39: 1}), canonicalOwnerLiteral(3, 5, hash))
		canonicalRequireRecorded(t, store, func(reader *Reader) { reader.dbis[rank] = ^reader.dbis[rank] }, 3, hash, EngineLocalInvariant, -30780, expectedNativeDiagnostic(-30780), "native failure")
	}
}

func TestCanonicalOwnerLookupUnverifiedAfterOpen(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	mustEnvironment(t, createAndClose(path, cfg))
	store, err := Open(path, cfg)
	store = consultedTrack(t, store, err)
	counter := consultedCounter(t, 4)
	truth, _, updateErr := store.Update(func(reader *Reader) (Batch, error) {
		result, lookupErr := reader.CanonicalOwnerV1(1, [32]byte{7})
		canonicalRequireUnverified(t, reader, result, lookupErr, "unverified in Update")
		return Batch{Mutations: []Mutation{counter}}, nil
	})
	if truth != CommitTruthNew || updateErr != nil {
		t.Fatalf("unverified Reader blocked its Batch: %s/%v", truth, updateErr)
	}
	requireUpdateValue(t, store, counter.DBI, counter.Key, counter.Literal, true)
	mustEnvironment(t, store.View(func(reader *Reader) error {
		result, lookupErr := reader.CanonicalOwnerV1(1, [32]byte{7})
		canonicalRequireUnverified(t, reader, result, lookupErr, "unverified in View")
		return nil
	}))
}

func TestCanonicalOwnerLookupBootstrapEstablishes(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	mustEnvironment(t, createAndClose(path, cfg))
	store, err := Open(path, cfg)
	store = consultedTrack(t, store, err)
	truth, stage, err := store.BootstrapStorageV1(StorageProfilePrunedV1, bootstrapOwner(t))
	if truth != CommitTruthNew || stage != UpdateStageCommitMayHaveCrossed || err != nil {
		t.Fatalf("bootstrap after Open: %s/%d/%v", truth, stage, err)
	}
	hash := [32]byte{9}
	result, lookupErr := canonicalLookup(t, store, 1, hash)
	canonicalRequireNone(t, result, lookupErr, 1, hash, "lookup after exact-empty bootstrap of an Open'd store")
}

func TestCanonicalOwnerLookupReaderRefusals(t *testing.T) {
	var nilReader *Reader
	result, err := nilReader.CanonicalOwnerV1(1, [32]byte{1})
	if engine := requireEnvironmentError(t, err, EngineInvalidInput, operationGet, 22, "Reader is not active"); engine.Cause != nil || !reflect.DeepEqual(result, CanonicalOwnerResultV1{}) {
		t.Fatalf("inactive Reader lookup drifted: %+v", result)
	}
	store := newUpdateStore(t)
	defer func() { mustEnvironment(t, store.Close()) }()
	var escaped *Reader
	mustEnvironment(t, store.View(func(reader *Reader) error {
		escaped = reader
		result, err := reader.CanonicalOwnerV1(0, [32]byte{1})
		engine := requireEnvironmentError(t, err, EngineInvalidInput, operationGet, 22, "invalid SchemaV2 key")
		if engine.Cause != nil || !reflect.DeepEqual(result, CanonicalOwnerResultV1{}) || reader.failure != nil || !reader.active.Load() {
			t.Fatalf("zero-generation lookup recorded a failure: %+v/%v", result, reader.failure)
		}
		value, present, getErr := reader.Get(DBI{Name: "meta-v1"}, []byte{0})
		if getErr != nil || !present || !bytes.Equal(value, []byte{0, 0, 0, 2}) {
			t.Fatalf("zero-generation lookup disabled the Reader: %x/%v/%v", value, present, getErr)
		}
		return nil
	}))
	result, err = escaped.CanonicalOwnerV1(1, [32]byte{1})
	if engine := requireEnvironmentError(t, err, EngineInvalidInput, operationGet, 22, "Reader is not active"); engine.Cause != nil || !reflect.DeepEqual(result, CanonicalOwnerResultV1{}) || escaped.failure != nil {
		t.Fatalf("expired Reader lookup drifted: %+v", result)
	}
}

func TestCanonicalOwnerLookupConsulted(t *testing.T) {
	hash, work := [32]byte{0x5c}, [40]byte{39: 1}
	t.Run("unchanged", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		counter := consultedCounter(t, 2)
		truth, _, err := store.Update(func(reader *Reader) (Batch, error) {
			result, lookupErr := reader.CanonicalOwnerV1(4, hash)
			if lookupErr != nil {
				return Batch{}, lookupErr
			}
			return Batch{Mutations: []Mutation{counter}, Consulted: result.Rows}, nil
		})
		if truth != CommitTruthNew || err != nil {
			t.Fatalf("consulted lookup rows refused an unchanged image: %s/%v", truth, err)
		}
		requireUpdateValue(t, store, counter.DBI, counter.Key, counter.Literal, true)
	})
	t.Run("sibling inserts the queried pair", func(t *testing.T) {
		store, path, cfg := consultedStore(t)
		pair := []Mutation{canonicalForwardLiteral(4, 6, hash, work), canonicalOwnerLiteral(4, 6, hash)}
		var reader *Reader
		truth, _, err := store.Update(func(observed *Reader) (Batch, error) {
			reader = observed
			result, lookupErr := observed.CanonicalOwnerV1(4, hash)
			if lookupErr != nil || result.Owned {
				return Batch{}, errors.New("consulted drift lookup was not none")
			}
			requireUpdateTruth(t, store.updateNative(updateNativePlan(t, pair...), nil, observed.txn), CommitTruthNew, true, nil, nil)
			return Batch{Mutations: []Mutation{consultedCounter(t, 2)}, Consulted: result.Rows}, nil
		})
		consultedRequireOutcome(t, store, reader, truth, err, EngineStateMismatch, -30779, "OLD/write snapshot mismatch", "consulted owner drift", true)
		reopened, openErr := Open(path, cfg)
		reopened = consultedTrack(t, reopened, openErr)
		canonicalRequireImage(t, reopened, pair, []Mutation{consultedCounter(t, 2)})
	})
}

// TestCanonicalOwnerFailureRecorderLifetime proves the sole failure recorder keeps Reader.Get's lifetime rule at the
// real callback boundary: an escaped Reader after View returned, and a live Reader already disarmed by a first native
// failure, each refuse "Reader is not active" without recording, so the first failure and the Store disposition stand.
func TestCanonicalOwnerFailureRecorderLifetime(t *testing.T) {
	late := errors.New("late canonical owner inconsistency")
	for _, row := range []struct {
		name     string
		disarmed bool
	}{{"escaped Reader after View", false}, {"disarmed Reader inside Update", true}} {
		t.Run(row.name, func(t *testing.T) {
			store, _, _ := consultedStore(t)
			var reader *Reader
			var first, refused error
			truth, stage, err := CommitTruthNew, UpdateStageCommitMayHaveCrossed, store.View(func(observed *Reader) error { reader = observed; return nil })
			if row.disarmed {
				truth, stage, err = store.Update(func(observed *Reader) (Batch, error) {
					reader = observed
					observed.dbis[0] = ^observed.dbis[0]
					_, _, first = observed.Get(DBI{Name: "meta-v1"}, []byte{0})
					refused = bootstrapFailure(observed, late)
					return Batch{}, first
				})
			} else {
				refused = bootstrapFailure(reader, late)
			}
			engine := requireEnvironmentError(t, refused, EngineInvalidInput, operationGet, 22, "Reader is not active")
			if engine.Cause != nil || !sameError(reader.failure, first) || reader.active.Load() {
				t.Fatalf("%s: recorder changed the Reader: %v/%v", row.name, reader.failure, reader.active.Load())
			}
			if !row.disarmed {
				if err != nil || store.state != storeOPEN || store.terminalTruth != 0 {
					t.Fatalf("%s: escaped record reached the Store: %v/%s", row.name, err, store.state)
				}
				mustEnvironment(t, store.View(func(*Reader) error { return nil }))
				return
			}
			requireEngineError(t, first, EngineLocalInvariant, operationGet, -30780)
			if truth != CommitTruthOld || stage != UpdateStagePrewrite || !sameError(err, first) || store.state != storeCLOSED || !sameError(store.terminal, first) {
				t.Fatalf("%s: first failure lost its disposition: %s/%d/%v/%s", row.name, truth, stage, err, store.state)
			}
			_, _, cached := store.Update(func(*Reader) (Batch, error) {
				t.Fatalf("%s: consumed Store entered Update", row.name)
				return Batch{}, nil
			})
			if !sameError(cached, first) {
				t.Fatalf("%s: next operation lost the first failure: %v", row.name, cached)
			}
		})
	}
}
