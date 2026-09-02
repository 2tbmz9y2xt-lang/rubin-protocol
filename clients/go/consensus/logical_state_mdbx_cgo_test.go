//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"cmp"
	"crypto/sha3"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

const (
	logicalMDBXImage      = 7
	logicalMDBXConstraint = "cgo && (darwin || linux) && (amd64 || arm64)"
	logicalMDBXBytesA     = 56
	logicalMDBXBytesB     = 311
	logicalMDBXBytesC     = 65_596
	logicalMDBXTotal      = logicalMDBXBytesA + logicalMDBXBytesB + logicalMDBXBytesC
)

var (
	logicalMDBXDBIs = mdbx.SchemaV1DBIs()
	logicalMDBXOpA  = Outpoint{Txid: filled32(0x11)}
	logicalMDBXOpB  = Outpoint{Txid: filled32(0x22), Vout: 1}
	logicalMDBXOpC  = Outpoint{Txid: filled32(0x33), Vout: 2}
	logicalMDBXOpD  = Outpoint{Txid: filled32(0x44), Vout: 3}
	logicalMDBXBase = logicalStateCounters{bytes: logicalMDBXTotal, entries: 3}
)

// logicalMDBXMust unwraps a SchemaV1 constructor over constant test inputs.
func logicalMDBXMust(value []byte, err error) []byte {
	if err != nil {
		panic("SchemaV1 test helper: " + err.Error())
	}
	return value
}

func logicalMDBXAssert(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

func logicalMDBXEntry(dataLen int, marker byte) UtxoEntry {
	// append over an empty repeat yields nil, exactly as mdbx.DecodeUTXOValue does.
	return UtxoEntry{CovenantData: append([]byte(nil), bytes.Repeat([]byte{marker}, dataLen)...), Value: uint64(marker) + 1, CreationHeight: uint64(marker) + 2, CovenantType: uint16(marker), CreatedByCoinbase: marker&1 == 1}
}

// logicalMDBXValue is the independent oracle for the projected utxo-v1 value.
func logicalMDBXValue(e UtxoEntry) []byte {
	return logicalMDBXMust(mdbx.UTXOValue{Value: e.Value, CovenantType: e.CovenantType, CovenantData: e.CovenantData, CreationHeight: e.CreationHeight, Coinbase: e.CreatedByCoinbase}.Encode())
}

func logicalMDBXKey(op Outpoint) []byte {
	return logicalMDBXMust(mdbx.UTXOKey(logicalMDBXImage, op.Txid, op.Vout))
}

func logicalMDBXCounterKey() []byte { return logicalMDBXMust(mdbx.MetaKey(0x10, logicalMDBXImage)) }

func logicalMDBXCounterRow(before bool, total, entries uint64) mdbx.Mutation {
	return mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: logicalMDBXCounterKey(), BeforePresent: before, AfterKind: mdbx.AfterLiteral, Literal: mdbx.LogicalCounterValue(total, entries)}
}

func logicalMDBXUTXORow(op Outpoint, e UtxoEntry) mdbx.Mutation {
	return mdbx.Mutation{DBI: logicalMDBXDBIs[1], Key: logicalMDBXKey(op), AfterKind: mdbx.AfterLiteral, Literal: logicalMDBXValue(e)}
}

func logicalMDBXHashRow(marker byte) ([]byte, []byte) {
	value := bytes.Repeat([]byte{marker}, 116)
	key := sha3.Sum256(value)
	return key[:], value
}

func logicalMDBXStore(t *testing.T) *mdbx.Store {
	t.Helper()
	store, err := mdbx.Create(filepath.Join(t.TempDir(), "db"), mdbx.ConfigV1{Lower: 1 << 20, Now: 2 << 20, Upper: 256 << 20, Growth: 1 << 20, Shrink: 2 << 20, PageSize: 4096, MaxReaders: 492})
	logicalMDBXAssert(t, err == nil, "create store: %v", err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// logicalMDBXSeed writes rows using an ordering independent of the converter.
func logicalMDBXSeed(t *testing.T, store *mdbx.Store, mutations ...mdbx.Mutation) {
	t.Helper()
	slices.SortFunc(mutations, func(a, b mdbx.Mutation) int {
		return cmp.Or(cmp.Compare(a.DBI.Rank, b.DBI.Rank), bytes.Compare(a.Key, b.Key))
	})
	truth, err := store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { return mdbx.Batch{Mutations: mutations}, nil })
	logicalMDBXAssert(t, err == nil && truth == mdbx.CommitTruthNew, "seed: truth=%v err=%v", truth, err)
}

func logicalMDBXSeeded(t *testing.T) *mdbx.Store {
	t.Helper()
	store := logicalMDBXStore(t)
	logicalMDBXSeed(t, store, logicalMDBXCounterRow(false, logicalMDBXTotal, 3), logicalMDBXUTXORow(logicalMDBXOpA, logicalMDBXEntry(0, 0xa1)), logicalMDBXUTXORow(logicalMDBXOpB, logicalMDBXEntry(253, 0xb2)), logicalMDBXUTXORow(logicalMDBXOpC, logicalMDBXEntry(65_536, 0xc3)))
	return store
}

func logicalMDBXView(t *testing.T, store *mdbx.Store, height uint64, body func(*logicalMDBXStateView)) {
	t.Helper()
	err := store.View(func(r *mdbx.Reader) error { body(newLogicalMDBXStateView(r, logicalMDBXImage, height)); return nil })
	logicalMDBXAssert(t, err == nil, "view: %v", err)
}

// logicalMDBXConvert reproduces the required composition: one snapshot, one view,
// the declared observations and the conversion, all inside a single callback.
func logicalMDBXConvert(t *testing.T, store *mdbx.Store, height uint64, lookups []Outpoint, build func(*logicalMDBXStateView) logicalStatePlan[logicalMDBXMetadata]) (batch mdbx.Batch, failure *logicalStateFailure) {
	t.Helper()
	logicalMDBXView(t, store, height, func(view *logicalMDBXStateView) {
		if height > 0 {
			view.Counters()
		}
		for _, op := range lookups {
			view.Lookup(op)
		}
		batch, failure = logicalMDBXPlanToBatch(build(view))
	})
	return batch, failure
}

func logicalMDBXBuild(view *logicalMDBXStateView, parent, result logicalStateCounters, deletes []logicalStateDelete, puts []logicalStatePut, extras ...mdbx.Mutation) logicalStatePlan[logicalMDBXMetadata] {
	return logicalStatePlan[logicalMDBXMetadata]{Deletes: deletes, Puts: puts, Parent: parent, Result: result, Metadata: newLogicalMDBXMetadata(view, extras)}
}

func logicalMDBXWantFailure(t *testing.T, label string, batch mdbx.Batch, failure *logicalStateFailure, kind logicalStateFailureKind, cause ...string) {
	t.Helper()
	logicalMDBXAssert(t, failure != nil && failure.kind == kind && failure.cause != nil && batch.Mutations == nil, "%s: failure=%+v mutations=%d", label, failure, len(batch.Mutations))
	logicalMDBXAssert(t, len(cause) == 0 || cause[0] == "" || strings.Contains(failure.cause.Error(), cause[0]), "%s: cause %v does not name %q", label, failure.cause, cause)
}

func logicalMDBXWantBatch(t *testing.T, label string, batch mdbx.Batch, failure *logicalStateFailure, want ...mdbx.Mutation) {
	t.Helper()
	logicalMDBXAssert(t, failure == nil, "%s: unexpected failure %+v", label, failure)
	logicalMDBXAssert(t, reflect.DeepEqual(batch.Mutations, want), "%s: got %d mutations %+v, want %d %+v", label, len(batch.Mutations), batch.Mutations, len(want), want)
}

func TestLogicalMDBXViewReads(t *testing.T) {
	store := logicalMDBXSeeded(t)
	logicalMDBXView(t, store, 1, func(view *logicalMDBXStateView) {
		read := view.Counters()
		logicalMDBXAssert(t, read.kind == logicalStateCountersPresent && read.counters == logicalMDBXBase && read.cause == nil, "counter read drifted: %+v", read)
		for _, tc := range []struct {
			op         Outpoint
			data       int
			mark       byte
			entryBytes uint64
		}{{logicalMDBXOpA, 0, 0xa1, logicalMDBXBytesA}, {logicalMDBXOpB, 253, 0xb2, logicalMDBXBytesB}, {logicalMDBXOpC, 65_536, 0xc3, logicalMDBXBytesC}} {
			row, want := view.Lookup(tc.op), logicalMDBXEntry(tc.data, tc.mark)
			logicalMDBXAssert(t, row.kind == logicalStateRowPresent && row.cause == nil && reflect.DeepEqual(row.entry, want), "row read drifted at %x: %+v", tc.op.Txid[0], row.kind)
			got := view.rows[tc.op]
			logicalMDBXAssert(t, got.present && got.entryBytes == tc.entryBytes && got.entryBytes == uint64(len(logicalStateEntryBytes(tc.op, want))), "row observation drifted at %x: %+v", tc.op.Txid[0], got)
			row.entry.CovenantData = bytes.Repeat([]byte{0xff}, tc.data)
		}
		second := view.Lookup(logicalMDBXOpB)
		logicalMDBXAssert(t, reflect.DeepEqual(second.entry, logicalMDBXEntry(253, 0xb2)), "bridge retained caller bytes: a decoded entry aliased the snapshot")
		absent := view.Lookup(logicalMDBXOpD)
		got, recorded := view.rows[logicalMDBXOpD]
		logicalMDBXAssert(t, absent.kind == logicalStateRowAbsent && absent.cause == nil && recorded && !got.present && got.entryBytes == 0, "absent row drifted: %+v %+v", absent, got)
	})
	for i := range reflect.TypeOf(logicalMDBXRowObservation{}).NumField() {
		logicalMDBXAssert(t, reflect.TypeOf(logicalMDBXRowObservation{}).Field(i).Type.Kind() != reflect.Slice, "bridge retained caller bytes: observation field %d holds bytes", i)
	}
	// Malformed persisted bytes are decoder/validator-owned: the decode arms of Counters and Lookup, plus the
	// create-once ValidateRow arm, are reachable only through these three calls, not a Store.Update-written row.
	badKey, badValue := logicalMDBXHashRow(0x71)
	_, _, counterErr := mdbx.DecodeLogicalCounterValue(make([]byte, 15))
	_, utxoErr := mdbx.DecodeUTXOValue(make([]byte, 19))
	logicalMDBXAssert(t, counterErr != nil && utxoErr != nil && mdbx.ValidateRow(logicalMDBXDBIs[3], badKey, badValue[:115]) != nil, "malformed persisted bytes accepted: %v %v", counterErr, utxoErr)
	t.Run("absent counter above genesis", func(t *testing.T) {
		fresh := logicalMDBXStore(t)
		logicalMDBXSeed(t, fresh, logicalMDBXUTXORow(logicalMDBXOpA, logicalMDBXEntry(0, 0xa1)))
		logicalMDBXView(t, fresh, 1, func(view *logicalMDBXStateView) {
			read := view.Counters()
			logicalMDBXAssert(t, read.kind == logicalStateCountersStoreIntegrity && read.cause != nil && read.cause.Error() == "logical counter absent above genesis" && !view.counterPresent, "absent counter accepted: %+v", read)
			counters, failure := readLogicalStateCounters(1, view)
			logicalMDBXAssert(t, failure != nil && failure.kind == logicalStateFailureStoreIntegrity && counters == logicalStateCounters{}, "absent counter accepted: plan failure %+v", failure)
		})
	})
	t.Run("inconsistent counter envelope", func(t *testing.T) {
		odd := logicalMDBXStore(t)
		logicalMDBXSeed(t, odd, logicalMDBXCounterRow(false, 0, 1))
		logicalMDBXView(t, odd, 1, func(view *logicalMDBXStateView) {
			read := view.Counters()
			logicalMDBXAssert(t, read.kind == logicalStateCountersPresent && read.counters == logicalStateCounters{bytes: 0, entries: 1}, "counter read drifted: %+v", read)
			_, failure := readLogicalStateCounters(1, view)
			logicalMDBXAssert(t, failure != nil && failure.kind == logicalStateFailureStoreIntegrity, "counter read drifted: envelope failure %+v", failure)
		})
	})
	t.Run("expired reader records nothing", func(t *testing.T) {
		var escaped *mdbx.Reader
		logicalMDBXAssert(t, store.View(func(reader *mdbx.Reader) error { escaped = reader; return nil }) == nil, "view: escaped reader")
		view := newLogicalMDBXStateView(escaped, logicalMDBXImage, 1)
		counter := view.Counters()
		logicalMDBXAssert(t, counter.kind == logicalStateCountersLocalInvariant && counter.cause != nil && !view.counterPresent, "expired counter read drifted: %+v", counter)
		row := view.Lookup(logicalMDBXOpA)
		logicalMDBXAssert(t, row.kind == logicalStateRowLocalInvariant && row.cause != nil && len(view.rows) == 0, "expired row read drifted: %+v", row)
		zero := newLogicalMDBXStateView(escaped, 0, 1)
		logicalMDBXAssert(t, zero.Counters().kind == logicalStateCountersLocalInvariant && zero.Lookup(logicalMDBXOpA).kind == logicalStateRowLocalInvariant, "unbuildable key read drifted")
	})
}

func TestLogicalMDBXErrorClassifier(t *testing.T) {
	integrity := &mdbx.EngineError{Class: mdbx.EngineIntegrity, Operation: "get", Code: 1, Diagnostic: "integrity"}
	plain, wrapped := errors.New("plain"), fmt.Errorf("wrapped: %w", integrity)
	for _, tc := range []struct {
		name  string
		err   error
		kind  logicalStateFailureKind
		cause error
	}{
		{"integrity", integrity, logicalStateFailureStoreIntegrity, integrity},
		{"capacity", &mdbx.EngineError{Class: mdbx.EngineCapacity}, logicalStateFailureUnavailable, nil},
		{"concurrency", &mdbx.EngineError{Class: mdbx.EngineConcurrency}, logicalStateFailureUnavailable, nil},
		{"io", &mdbx.EngineError{Class: mdbx.EngineIO}, logicalStateFailureUnavailable, nil},
		{"invalid input", &mdbx.EngineError{Class: mdbx.EngineInvalidInput}, logicalStateFailureLocalInvariant, nil},
		{"transaction", &mdbx.EngineError{Class: mdbx.EngineTransaction}, logicalStateFailureLocalInvariant, nil},
		{"state mismatch", &mdbx.EngineError{Class: mdbx.EngineStateMismatch}, logicalStateFailureLocalInvariant, nil},
		{"local invariant", &mdbx.EngineError{Class: mdbx.EngineLocalInvariant}, logicalStateFailureLocalInvariant, nil},
		{"unknown class", &mdbx.EngineError{Class: mdbx.EngineClass("Nonesuch")}, logicalStateFailureLocalInvariant, nil},
		{"typed nil", (*mdbx.EngineError)(nil), logicalStateFailureLocalInvariant, errLogicalMDBXUnclassifiedRead},
		{"wrapped", wrapped, logicalStateFailureLocalInvariant, wrapped},
		{"foreign", plain, logicalStateFailureLocalInvariant, plain},
		{"nil", nil, logicalStateFailureLocalInvariant, errLogicalMDBXUnclassifiedRead},
	} {
		kind, cause := classifyLogicalMDBXReadError(tc.err)
		counterKind, rowKind := logicalMDBXReadKinds(kind)
		logicalMDBXAssert(t, kind == tc.kind && cause == cmp.Or(tc.cause, tc.err), "logical read class drifted: %s kind=%d want=%d cause=%v", tc.name, kind, tc.kind, cause) //nolint:errorlint // The contract pins the exact cause pointer, not an errors.Is relation.
		logicalMDBXAssert(t, counterKind == logicalStateCounterReadKind(tc.kind)+1 && rowKind == logicalStateRowReadKind(tc.kind)+2, "logical read class drifted: %s names counter %d row %d", tc.name, counterKind, rowKind)
	}
}

func TestLogicalMDBXPlanToBatch(t *testing.T) {
	store := logicalMDBXSeeded(t)
	entryD, entryE := logicalMDBXEntry(7, 0xd4), logicalMDBXEntry(9, 0xe5)
	bytesD, bytesE := uint64(len(logicalStateEntryBytes(logicalMDBXOpD, entryD))), uint64(len(logicalStateEntryBytes(logicalMDBXOpB, entryE)))
	delA, delB := []logicalStateDelete{{Outpoint: logicalMDBXOpA, EntryBytes: logicalMDBXBytesA}}, []logicalStateDelete{{Outpoint: logicalMDBXOpB, EntryBytes: logicalMDBXBytesB}}
	putD, counterOnly := []logicalStatePut{{Outpoint: logicalMDBXOpD, Entry: entryD}}, []mdbx.Mutation{logicalMDBXCounterRow(true, logicalMDBXTotal, 3)}
	deleteRowA, opE := mdbx.Mutation{DBI: logicalMDBXDBIs[1], Key: logicalMDBXKey(logicalMDBXOpA), BeforePresent: true, AfterKind: mdbx.AfterAbsent}, Outpoint{Txid: filled32(0x22), Vout: 9}
	replaceRowB := logicalMDBXUTXORow(logicalMDBXOpB, entryE)
	replaceRowB.BeforePresent = true
	afterA, afterE, afterD := logicalStateCounters{bytes: logicalMDBXTotal - logicalMDBXBytesA, entries: 2}, logicalStateCounters{bytes: logicalMDBXTotal - logicalMDBXBytesB + bytesE, entries: 3}, logicalStateCounters{bytes: logicalMDBXTotal + bytesD, entries: 4}

	for _, tc := range []struct {
		name, label    string
		cause          string
		counters       bool
		height         uint64
		lookups        []Outpoint
		parent, result logicalStateCounters
		deletes        []logicalStateDelete
		puts           []logicalStatePut
		kind           logicalStateFailureKind
		want           []mdbx.Mutation
	}{
		{name: "counter only no-op", label: "counter mutation missing", height: 1, parent: logicalMDBXBase, result: logicalMDBXBase, want: counterOnly},
		{name: "unused observation emits nothing", label: "counter mutation missing", height: 1, lookups: []Outpoint{logicalMDBXOpA, logicalMDBXOpD}, parent: logicalMDBXBase, result: logicalMDBXBase, want: counterOnly},
		{name: "delete only", label: "DELETE observation drifted", height: 1, lookups: []Outpoint{logicalMDBXOpA}, parent: logicalMDBXBase, result: afterA, deletes: delA, want: []mdbx.Mutation{logicalMDBXCounterRow(true, afterA.bytes, 2), deleteRowA}},
		{name: "put only", label: "StateEntryBytes projection drifted", height: 1, lookups: []Outpoint{logicalMDBXOpD}, parent: logicalMDBXBase, result: afterD, puts: putD, want: []mdbx.Mutation{logicalMDBXCounterRow(true, afterD.bytes, 4), logicalMDBXUTXORow(logicalMDBXOpD, entryD)}},
		{name: "replacement coalesces", label: "replacement coalescing drifted", height: 1, lookups: []Outpoint{logicalMDBXOpB}, parent: logicalMDBXBase, result: afterE, deletes: delB, puts: []logicalStatePut{{Outpoint: logicalMDBXOpB, Entry: entryE}}, want: []mdbx.Mutation{logicalMDBXCounterRow(true, afterE.bytes, 3), replaceRowB}},
		{name: "put sorts before a delete", label: "replacement coalescing drifted", height: 1, lookups: []Outpoint{opE, logicalMDBXOpC}, parent: logicalMDBXBase, result: logicalStateCounters{bytes: logicalMDBXTotal - logicalMDBXBytesC + bytesD, entries: 3}, deletes: []logicalStateDelete{{Outpoint: logicalMDBXOpC, EntryBytes: logicalMDBXBytesC}}, puts: []logicalStatePut{{Outpoint: opE, Entry: entryD}}, want: []mdbx.Mutation{logicalMDBXCounterRow(true, logicalMDBXTotal-logicalMDBXBytesC+bytesD, 3), logicalMDBXUTXORow(opE, entryD), {DBI: logicalMDBXDBIs[1], Key: logicalMDBXKey(logicalMDBXOpC), BeforePresent: true, AfterKind: mdbx.AfterAbsent}}},
		{name: "counter observation mismatch", label: "DELETE observation drifted", height: 1, lookups: []Outpoint{logicalMDBXOpA}, parent: logicalStateCounters{bytes: logicalMDBXTotal + 100, entries: 3}, result: logicalStateCounters{bytes: logicalMDBXTotal + 100 - logicalMDBXBytesA, entries: 2}, deletes: delA, kind: logicalStateFailureLocalInvariant},
		{name: "genesis put", label: "counter mutation missing", height: 0, result: logicalStateCounters{bytes: bytesD, entries: 1}, puts: putD, want: []mdbx.Mutation{logicalMDBXCounterRow(false, bytesD, 1), logicalMDBXUTXORow(logicalMDBXOpD, entryD)}},
		{name: "genesis with parent counters", label: "genesis form accepted", height: 0, parent: logicalStateCounters{bytes: 56, entries: 1}, result: logicalStateCounters{bytes: 56 + bytesD, entries: 2}, puts: putD, kind: logicalStateFailureLocalInvariant},
		{name: "genesis with delete", label: "genesis form accepted", height: 0, deletes: delA, kind: logicalStateFailureLocalInvariant, cause: "underflow"},
		{name: "genesis with a counter observation", label: "genesis form accepted", height: 0, counters: true, result: logicalStateCounters{bytes: bytesD, entries: 1}, puts: putD, kind: logicalStateFailureLocalInvariant, cause: "genesis"},
		{name: "genesis with observation", label: "genesis form accepted", height: 0, lookups: []Outpoint{logicalMDBXOpA}, result: logicalStateCounters{bytes: bytesD, entries: 1}, puts: putD, kind: logicalStateFailureLocalInvariant},
		{name: "non-genesis without observations", label: "DELETE observation drifted", height: 1, parent: logicalMDBXBase, result: afterA, deletes: delA, kind: logicalStateFailureLocalInvariant},
		{name: "delete length mismatch", label: "DELETE observation drifted", height: 1, lookups: []Outpoint{logicalMDBXOpA}, parent: logicalMDBXBase, result: logicalStateCounters{bytes: afterA.bytes + 1, entries: 2}, deletes: []logicalStateDelete{{Outpoint: logicalMDBXOpA, EntryBytes: logicalMDBXBytesA - 1}}, kind: logicalStateFailureLocalInvariant},
		{name: "put over a present row", label: "DELETE observation drifted", height: 1, lookups: []Outpoint{logicalMDBXOpA}, parent: logicalMDBXBase, result: logicalStateCounters{bytes: logicalMDBXTotal + logicalMDBXBytesA, entries: 4}, puts: []logicalStatePut{{Outpoint: logicalMDBXOpA, Entry: logicalMDBXEntry(0, 0xa1)}}, kind: logicalStateFailureLocalInvariant},
		{name: "delete over an absent row", label: "DELETE observation drifted", height: 1, lookups: []Outpoint{logicalMDBXOpD}, parent: logicalMDBXBase, result: afterA, deletes: []logicalStateDelete{{Outpoint: logicalMDBXOpD, EntryBytes: logicalMDBXBytesA}}, kind: logicalStateFailureLocalInvariant},
		{name: "unsorted plan rows without observations", label: "unsorted rows accepted", height: 1, parent: logicalMDBXBase, result: logicalStateCounters{bytes: afterA.bytes - logicalMDBXBytesB, entries: 1}, deletes: []logicalStateDelete{delB[0], delA[0]}, kind: logicalStateFailureLocalInvariant, cause: "unordered"},
		{name: "unsorted plan rows", label: "unsorted rows accepted", height: 1, lookups: []Outpoint{logicalMDBXOpA, logicalMDBXOpB}, parent: logicalMDBXBase, result: logicalStateCounters{bytes: afterA.bytes - logicalMDBXBytesB, entries: 1}, deletes: []logicalStateDelete{delB[0], delA[0]}, kind: logicalStateFailureLocalInvariant},
		{name: "duplicate plan rows", label: "duplicate rows accepted", height: 1, lookups: []Outpoint{logicalMDBXOpA}, parent: logicalMDBXBase, result: logicalStateCounters{bytes: logicalMDBXTotal - 2*logicalMDBXBytesA, entries: 1}, deletes: []logicalStateDelete{delA[0], delA[0]}, kind: logicalStateFailureLocalInvariant},
		{name: "entry count mismatch", label: "counter arithmetic accepted", height: 1, lookups: []Outpoint{logicalMDBXOpA}, parent: logicalMDBXBase, result: logicalStateCounters{bytes: afterA.bytes, entries: 3}, deletes: delA, kind: logicalStateFailureLocalInvariant},
		{name: "byte total mismatch", label: "counter arithmetic accepted", height: 1, lookups: []Outpoint{logicalMDBXOpD}, parent: logicalMDBXBase, result: logicalStateCounters{bytes: afterD.bytes - 1, entries: 4}, puts: putD, kind: logicalStateFailureLocalInvariant},
		{name: "parent underflow", label: "counter arithmetic accepted", height: 1, lookups: []Outpoint{logicalMDBXOpA}, parent: logicalStateCounters{bytes: 1, entries: 1}, deletes: delA, kind: logicalStateFailureLocalInvariant, cause: "underflow"},
		{name: "delete past the parent with a wrap-consistent result", label: "counter arithmetic accepted", height: 1, lookups: []Outpoint{logicalMDBXOpA}, parent: logicalStateCounters{bytes: 1, entries: 1}, result: logicalStateCounters{bytes: ^uint64(0) - 54}, deletes: delA, kind: logicalStateFailureLocalInvariant, cause: "underflow"},
		{name: "entry count carries past uint64", label: "counter arithmetic accepted", height: 1, lookups: []Outpoint{logicalMDBXOpD}, parent: logicalStateCounters{bytes: 0, entries: ^uint64(0)}, result: logicalStateCounters{bytes: bytesD, entries: 0}, puts: putD, kind: logicalStateFailureLocalInvariant, cause: "match the plan rows"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, failure := logicalMDBXConvert(t, store, tc.height, tc.lookups, func(view *logicalMDBXStateView) logicalStatePlan[logicalMDBXMetadata] {
				if tc.counters {
					view.Counters()
				}
				return logicalMDBXBuild(view, tc.parent, tc.result, tc.deletes, tc.puts)
			})
			if tc.kind != 0 {
				logicalMDBXWantFailure(t, tc.label, batch, failure, tc.kind, tc.cause)
				return
			}
			logicalMDBXWantBatch(t, tc.label, batch, failure, tc.want...)
		})
	}

	t.Run("view preconditions precede plan shape", func(t *testing.T) {
		unsorted := []logicalStateDelete{{Outpoint: logicalMDBXOpB}, {Outpoint: logicalMDBXOpA}}
		for _, plan := range []logicalStatePlan[logicalMDBXMetadata]{{}, {Deletes: unsorted}, logicalMDBXBuild(newLogicalMDBXStateView(nil, 0, 0), logicalStateCounters{}, logicalStateCounters{}, unsorted, nil)} {
			batch, failure := logicalMDBXPlanToBatch(plan)
			logicalMDBXWantFailure(t, "view precondition accepted", batch, failure, logicalStateFailureLocalInvariant)
			logicalMDBXAssert(t, strings.Contains(failure.cause.Error(), "view") || strings.Contains(failure.cause.Error(), "image"), "view precondition accepted: reported %v", failure.cause)
		}
	})

	t.Run("StateEntryBytes projection", func(t *testing.T) {
		for _, size := range []int{0, 1, 252, 253, 65_535, 65_536} {
			entry := logicalMDBXEntry(size, 0x5a)
			total := uint64(len(logicalStateEntryBytes(logicalMDBXOpD, entry)))
			batch, failure := logicalMDBXConvert(t, store, 0, nil, func(view *logicalMDBXStateView) logicalStatePlan[logicalMDBXMetadata] {
				return logicalMDBXBuild(view, logicalStateCounters{}, logicalStateCounters{bytes: total, entries: 1}, nil, []logicalStatePut{{Outpoint: logicalMDBXOpD, Entry: entry}})
			})
			logicalMDBXWantBatch(t, "StateEntryBytes projection drifted", batch, failure, logicalMDBXCounterRow(false, total, 1), logicalMDBXUTXORow(logicalMDBXOpD, entry))
			logicalMDBXAssert(t, uint64(len(batch.Mutations[1].Literal))+logicalMDBXEntryPrefix == total, "StateEntryBytes projection drifted: literal %d, entry %d", len(batch.Mutations[1].Literal), total)
		}
	})
}

// logicalMDBXExtraOutcome enumerates every classification an extra can receive.
type logicalMDBXExtraOutcome uint8

const (
	logicalMDBXEmit logicalMDBXExtraOutcome = iota
	logicalMDBXOmit
	logicalMDBXLocal
	logicalMDBXIntegrity
	logicalMDBXAdapterInvalid
)

func TestLogicalMDBXExtraMatrix(t *testing.T) {
	store := logicalMDBXSeeded(t)
	headerKey, headerValue := logicalMDBXHashRow(0x71)
	blockKey, blockValue := logicalMDBXHashRow(0x72)
	manifestKey, manifestValue := mdbx.UndoManifestKey(filled32(0x73)), mdbx.UndoManifestValue(1, [16]byte{1}, 1, 1)
	freshKey, freshValue := logicalMDBXHashRow(0x81)
	blockDiffering := append(slices.Clone(blockValue), 0x82)
	chain := mdbx.ChainValue(filled32(1), filled32(2), [40]byte{3})
	sameImage, seededImage := logicalMDBXMust(mdbx.HeightKey(logicalMDBXImage, 5)), logicalMDBXMust(mdbx.HeightKey(logicalMDBXImage, 4))
	crossImage := logicalMDBXMust(mdbx.HeightKey(logicalMDBXImage+1, 5))
	metaKey, counterKey := logicalMDBXMust(mdbx.MetaKey(0x02, 0)), logicalMDBXCounterKey()
	literal := func(rank uint8, key, value []byte) mdbx.Mutation {
		return mdbx.Mutation{DBI: logicalMDBXDBIs[rank], Key: key, AfterKind: mdbx.AfterLiteral, Literal: value}
	}
	absent := func(rank uint8, key []byte) mdbx.Mutation {
		return mdbx.Mutation{DBI: logicalMDBXDBIs[rank], Key: key, BeforePresent: true, AfterKind: mdbx.AfterAbsent}
	}
	ref := func(op Outpoint, image uint64) mdbx.Mutation {
		return mdbx.Mutation{DBI: logicalMDBXDBIs[5], Key: mdbx.UndoEntryKey(filled32(0x74), op.Txid, 0, 0, op.Vout), AfterKind: mdbx.AfterOldValueRef, RefDBI: logicalMDBXDBIs[1], RefKey: logicalMDBXMust(mdbx.UTXOKey(image, op.Txid, op.Vout))}
	}
	entryKey := ref(logicalMDBXOpB, logicalMDBXImage).Key
	// One present row per extra family, so every deletion row targets a row the adapter can delete; an undo entry exists only through a reference.
	image := []mdbx.Mutation{literal(3, headerKey, headerValue), literal(4, blockKey, blockValue), literal(5, manifestKey, manifestValue), literal(2, seededImage, chain), literal(6, seededImage, chain), ref(logicalMDBXOpB, logicalMDBXImage)}
	logicalMDBXSeed(t, store, image...)
	logicalMDBXAssert(t, mdbx.ValidateRow(logicalMDBXDBIs[4], blockKey, blockDiffering) == nil, "differing create-once literal is adapter-invalid")
	for _, tc := range []struct {
		name, label, cause string
		extras             []mdbx.Mutation
		outcome            logicalMDBXExtraOutcome
	}{
		{"rank0 metadata literal", "extra target policy drifted", "", []mdbx.Mutation{literal(0, metaKey, []byte{9})}, logicalMDBXEmit},
		{"rank0 counter literal", "extra target policy drifted", "", []mdbx.Mutation{literal(0, counterKey, mdbx.LogicalCounterValue(1, 1))}, logicalMDBXLocal},
		{"rank0 counter deletion", "extra target policy drifted", "", []mdbx.Mutation{absent(0, counterKey)}, logicalMDBXLocal},
		{"rank0 metadata deletion", "extra target policy drifted", "", []mdbx.Mutation{absent(0, metaKey)}, logicalMDBXAdapterInvalid},
		{"rank0 reference", "extra target policy drifted", "", []mdbx.Mutation{{DBI: logicalMDBXDBIs[0], Key: metaKey, AfterKind: mdbx.AfterOldValueRef}}, logicalMDBXAdapterInvalid},
		{"rank1 literal", "extra target policy drifted", "", []mdbx.Mutation{literal(1, logicalMDBXKey(logicalMDBXOpD), logicalMDBXValue(logicalMDBXEntry(1, 0x91)))}, logicalMDBXLocal},
		{"rank1 deletion", "extra target policy drifted", "", []mdbx.Mutation{absent(1, logicalMDBXKey(logicalMDBXOpC))}, logicalMDBXLocal},
		{"rank1 reference", "extra target policy drifted", "", []mdbx.Mutation{{DBI: logicalMDBXDBIs[1], Key: logicalMDBXKey(logicalMDBXOpD), AfterKind: mdbx.AfterOldValueRef}}, logicalMDBXLocal},
		{"rank2 literal same image", "extra target policy drifted", "", []mdbx.Mutation{literal(2, sameImage, chain)}, logicalMDBXEmit},
		{"rank2 literal cross image", "extra target policy drifted", "", []mdbx.Mutation{literal(2, crossImage, chain)}, logicalMDBXLocal},
		{"rank2 deletion", "extra target policy drifted", "", []mdbx.Mutation{absent(2, seededImage)}, logicalMDBXEmit},
		{"rank2 deletion cross image", "extra target policy drifted", "", []mdbx.Mutation{absent(2, crossImage)}, logicalMDBXLocal},
		{"rank2 reference", "extra target policy drifted", "", []mdbx.Mutation{{DBI: logicalMDBXDBIs[2], Key: sameImage, AfterKind: mdbx.AfterOldValueRef}}, logicalMDBXAdapterInvalid},
		{"rank6 literal same image", "extra target policy drifted", "", []mdbx.Mutation{literal(6, sameImage, chain)}, logicalMDBXEmit},
		{"rank6 literal cross image", "extra target policy drifted", "", []mdbx.Mutation{literal(6, crossImage, chain)}, logicalMDBXLocal},
		{"rank6 deletion", "extra target policy drifted", "", []mdbx.Mutation{absent(6, seededImage)}, logicalMDBXEmit},
		{"rank6 reference", "extra target policy drifted", "", []mdbx.Mutation{{DBI: logicalMDBXDBIs[6], Key: sameImage, AfterKind: mdbx.AfterOldValueRef}}, logicalMDBXAdapterInvalid},
		{"rank3 create absent", "create-once policy drifted", "", []mdbx.Mutation{literal(3, freshKey, freshValue)}, logicalMDBXEmit},
		{"rank3 create identical", "create-once policy drifted", "", []mdbx.Mutation{literal(3, headerKey, headerValue)}, logicalMDBXOmit},
		{"rank3 deletion", "create-once policy drifted", "", []mdbx.Mutation{absent(3, headerKey)}, logicalMDBXEmit},
		{"rank3 reference", "create-once policy drifted", "", []mdbx.Mutation{{DBI: logicalMDBXDBIs[3], Key: headerKey, AfterKind: mdbx.AfterOldValueRef}}, logicalMDBXAdapterInvalid},
		{"rank4 create identical", "create-once policy drifted", "", []mdbx.Mutation{literal(4, blockKey, blockValue)}, logicalMDBXOmit},
		{"rank4 create absent", "create-once policy drifted", "", []mdbx.Mutation{literal(4, freshKey, freshValue)}, logicalMDBXEmit},
		{"rank4 create differing", "create-once policy drifted", "", []mdbx.Mutation{literal(4, blockKey, blockDiffering)}, logicalMDBXIntegrity},
		{"rank4 deletion", "create-once policy drifted", "", []mdbx.Mutation{absent(4, blockKey)}, logicalMDBXEmit},
		{"rank4 reference", "create-once policy drifted", "", []mdbx.Mutation{{DBI: logicalMDBXDBIs[4], Key: blockKey, AfterKind: mdbx.AfterOldValueRef}}, logicalMDBXAdapterInvalid},
		{"rank5 manifest identical", "create-once policy drifted", "", []mdbx.Mutation{literal(5, manifestKey, manifestValue)}, logicalMDBXOmit},
		{"rank5 manifest differing", "create-once policy drifted", "", []mdbx.Mutation{literal(5, manifestKey, mdbx.UndoManifestValue(2, [16]byte{2}, 2, 2))}, logicalMDBXIntegrity},
		{"rank5 manifest deletion", "create-once policy drifted", "", []mdbx.Mutation{absent(5, manifestKey)}, logicalMDBXEmit},
		{"rank5 entry deletion", "undo provenance drifted", "", []mdbx.Mutation{absent(5, entryKey)}, logicalMDBXEmit},
		{"rank5 entry reference to the plan target", "undo provenance drifted", "", []mdbx.Mutation{ref(logicalMDBXOpA, logicalMDBXImage)}, logicalMDBXEmit},
		{"rank5 entry reference off plan", "undo provenance drifted", "", []mdbx.Mutation{ref(logicalMDBXOpC, logicalMDBXImage)}, logicalMDBXLocal},
		{"rank5 entry reference cross image", "undo provenance drifted", "", []mdbx.Mutation{ref(logicalMDBXOpA, logicalMDBXImage+1)}, logicalMDBXLocal},
		{"rank5 entry literal", "undo provenance drifted", "", []mdbx.Mutation{literal(5, entryKey, logicalMDBXValue(logicalMDBXEntry(1, 0x92)))}, logicalMDBXAdapterInvalid},
		{"forbidden extra precedes a differing create-once read", "extra target policy drifted", "", []mdbx.Mutation{literal(1, logicalMDBXKey(logicalMDBXOpD), logicalMDBXValue(logicalMDBXEntry(1, 0x93))), literal(4, blockKey, blockDiffering)}, logicalMDBXLocal},
		{"duplicate extra target", "duplicate extra accepted", "", []mdbx.Mutation{literal(2, sameImage, chain), literal(2, sameImage, chain)}, logicalMDBXLocal},
		{"create-once reads stop at the lowest target", "create-once policy drifted", "rank 4", []mdbx.Mutation{literal(5, manifestKey, mdbx.UndoManifestValue(2, [16]byte{2}, 2, 2)), literal(4, blockKey, blockDiffering)}, logicalMDBXIntegrity},
		{"shuffled extras sort", "final Batch order drifted", "", []mdbx.Mutation{literal(6, sameImage, chain), literal(0, metaKey, []byte{9}), literal(3, freshKey, freshValue)}, logicalMDBXEmit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.outcome == logicalMDBXAdapterInvalid {
				// A cell the bridge never classifies: the adapter itself refuses it.
				truth, updateErr := store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { return mdbx.Batch{Mutations: tc.extras}, nil })
				var engine *mdbx.EngineError
				logicalMDBXAssert(t, errors.As(updateErr, &engine) && engine.Class == mdbx.EngineInvalidInput && truth == mdbx.CommitTruthOld, "%s: adapter accepted a precondition-invalid extra: truth=%v err=%v", tc.label, truth, updateErr)
				return
			}
			batch, failure := logicalMDBXConvert(t, store, 1, []Outpoint{logicalMDBXOpA}, func(view *logicalMDBXStateView) logicalStatePlan[logicalMDBXMetadata] {
				return logicalMDBXBuild(view, logicalMDBXBase, logicalStateCounters{bytes: logicalMDBXTotal - logicalMDBXBytesA, entries: 2}, []logicalStateDelete{{Outpoint: logicalMDBXOpA, EntryBytes: logicalMDBXBytesA}}, nil, tc.extras...)
			})
			logicalMDBXCheckExtra(t, tc.label, tc.cause, tc.outcome, tc.extras, image, batch, failure)
		})
	}
	t.Run("rank5 entry reference to the counter row", func(t *testing.T) {
		// Image 0x1010101010101010 makes the counter key's leading bytes equal the image, so only the RefDBI clause can refuse it.
		view := &logicalMDBXStateView{imageID: 0x1010101010101010, height: 1, counterPresent: true, counters: logicalMDBXBase}
		batch, failure := logicalMDBXPlanToBatch(logicalMDBXBuild(view, logicalMDBXBase, logicalMDBXBase, nil, nil, mdbx.Mutation{DBI: logicalMDBXDBIs[5], Key: entryKey, AfterKind: mdbx.AfterOldValueRef, RefDBI: logicalMDBXDBIs[0], RefKey: logicalMDBXMust(mdbx.MetaKey(0x10, view.imageID))}))
		logicalMDBXWantFailure(t, "undo provenance drifted", batch, failure, logicalStateFailureLocalInvariant, "utxo-v1")
	})
	t.Run("rank5 entry reference to a replacement target", func(t *testing.T) {
		entry, extras := logicalMDBXEntry(3, 0xa9), []mdbx.Mutation{ref(logicalMDBXOpA, logicalMDBXImage)}
		batch, failure := logicalMDBXConvert(t, store, 1, []Outpoint{logicalMDBXOpA}, func(view *logicalMDBXStateView) logicalStatePlan[logicalMDBXMetadata] {
			return logicalMDBXBuild(view, logicalMDBXBase, logicalStateCounters{bytes: logicalMDBXTotal - logicalMDBXBytesA + uint64(len(logicalStateEntryBytes(logicalMDBXOpA, entry))), entries: 3}, []logicalStateDelete{{Outpoint: logicalMDBXOpA, EntryBytes: logicalMDBXBytesA}}, []logicalStatePut{{Outpoint: logicalMDBXOpA, Entry: entry}}, extras...)
		})
		logicalMDBXCheckExtra(t, "undo provenance drifted", "", logicalMDBXEmit, extras, image, batch, failure)
		logicalMDBXAssert(t, batch.Mutations[1].BeforePresent && batch.Mutations[1].AfterKind == mdbx.AfterLiteral && bytes.Equal(batch.Mutations[1].Key, logicalMDBXKey(logicalMDBXOpA)) && bytes.Equal(batch.Mutations[1].Literal, logicalMDBXValue(entry)), "undo provenance drifted: replacement row %+v", batch.Mutations[1])
	})
	t.Run("create-once read failure routes through the classifier", func(t *testing.T) {
		var escaped *mdbx.Reader
		logicalMDBXAssert(t, store.View(func(reader *mdbx.Reader) error { escaped = reader; return nil }) == nil, "view: escaped reader")
		view := newLogicalMDBXStateView(escaped, logicalMDBXImage, 0)
		batch, failure := logicalMDBXPlanToBatch(logicalMDBXBuild(view, logicalStateCounters{}, logicalStateCounters{}, nil, nil, literal(3, freshKey, freshValue)))
		logicalMDBXWantFailure(t, "create-once policy drifted", batch, failure, logicalStateFailureLocalInvariant)
		var engine *mdbx.EngineError
		logicalMDBXAssert(t, errors.As(failure.cause, &engine) && engine.Class == mdbx.EngineInvalidInput, "create-once policy drifted: cause %v is not the direct engine error", failure.cause)
	})
	t.Run("observation check preempts create-once reads", func(t *testing.T) {
		batch, failure := logicalMDBXConvert(t, store, 1, nil, func(view *logicalMDBXStateView) logicalStatePlan[logicalMDBXMetadata] {
			return logicalMDBXBuild(view, logicalMDBXBase, logicalStateCounters{bytes: logicalMDBXTotal - logicalMDBXBytesA, entries: 2}, []logicalStateDelete{{Outpoint: logicalMDBXOpA, EntryBytes: logicalMDBXBytesA}}, nil, literal(4, blockKey, blockDiffering))
		})
		logicalMDBXWantFailure(t, "create-once policy drifted", batch, failure, logicalStateFailureLocalInvariant, "observation")
	})
}

// logicalMDBXCheckExtra checks one matrix row; an accepted Batch is also applied through Store.Update on a fresh copy of the matrix image.
func logicalMDBXCheckExtra(t *testing.T, label, cause string, outcome logicalMDBXExtraOutcome, extras, image []mdbx.Mutation, batch mdbx.Batch, failure *logicalStateFailure) {
	t.Helper()
	if kind, rejected := map[logicalMDBXExtraOutcome]logicalStateFailureKind{logicalMDBXLocal: logicalStateFailureLocalInvariant, logicalMDBXIntegrity: logicalStateFailureStoreIntegrity}[outcome]; rejected {
		logicalMDBXWantFailure(t, label, batch, failure, kind, cause)
		return
	}
	logicalMDBXAssert(t, failure == nil, "%s: unexpected failure %+v", label, failure)
	fresh := logicalMDBXSeeded(t)
	logicalMDBXSeed(t, fresh, image...)
	truth, err := fresh.Update(func(*mdbx.Reader) (mdbx.Batch, error) { return batch, nil })
	logicalMDBXAssert(t, truth == mdbx.CommitTruthNew && err == nil, "%s: adapter refused the bridge Batch: truth=%v err=%v", label, truth, err)
	want := map[bool]int{false: 2 + len(extras), true: 2}[outcome == logicalMDBXOmit]
	logicalMDBXAssert(t, len(batch.Mutations) == want, "%s: got %d mutations, want %d", label, len(batch.Mutations), want)
	for i := 1; i < len(batch.Mutations); i++ {
		logicalMDBXAssert(t, cmp.Or(cmp.Compare(batch.Mutations[i-1].DBI.Rank, batch.Mutations[i].DBI.Rank), bytes.Compare(batch.Mutations[i-1].Key, batch.Mutations[i].Key)) < 0, "final Batch order drifted: rank %d key %x then rank %d key %x", batch.Mutations[i-1].DBI.Rank, batch.Mutations[i-1].Key, batch.Mutations[i].DBI.Rank, batch.Mutations[i].Key)
	}
	for _, extra := range extras {
		present := slices.ContainsFunc(batch.Mutations, func(m mdbx.Mutation) bool { return reflect.DeepEqual(m, extra) })
		logicalMDBXAssert(t, present == (outcome == logicalMDBXEmit), "%s: extra present=%v in the Batch", label, present)
	}
}

func TestLogicalMDBXStoreUpdateComposition(t *testing.T) {
	store := logicalMDBXStore(t)
	entryA, entryD := logicalMDBXEntry(0, 0xa1), logicalMDBXEntry(7, 0xd4)
	headerKey, headerValue := logicalMDBXHashRow(0x61)
	header := mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: headerKey, AfterKind: mdbx.AfterLiteral, Literal: headerValue}
	bytesD := uint64(len(logicalStateEntryBytes(logicalMDBXOpD, entryD)))
	// One Reader, one view, one declared height, Batch returned in-callback.
	run := func(height uint64, touched []logicalTouchedState, extras ...mdbx.Mutation) (mdbx.CommitTruth, error) {
		return store.Update(func(reader *mdbx.Reader) (mdbx.Batch, error) {
			view := newLogicalMDBXStateView(reader, logicalMDBXImage, height)
			plan, failure := buildLogicalStatePlan(height, view, touched, newLogicalMDBXMetadata(view, extras))
			if failure != nil {
				return mdbx.Batch{}, failure
			}
			batch, convertFailure := logicalMDBXPlanToBatch(plan)
			if convertFailure != nil {
				return mdbx.Batch{}, convertFailure
			}
			return batch, nil
		})
	}
	truth, err := run(0, []logicalTouchedState{{Outpoint: logicalMDBXOpA, FinalPresent: true, Final: entryA}}, header)
	logicalMDBXAssert(t, truth == mdbx.CommitTruthNew && err == nil, "genesis composition failed: truth=%v err=%v", truth, err)
	logicalMDBXWantImage(t, store, [3][]byte{{0}, logicalMDBXCounterKey(), mdbx.LogicalCounterValue(logicalMDBXBytesA, 1)}, [3][]byte{{1}, logicalMDBXKey(logicalMDBXOpA), logicalMDBXValue(entryA)}, [3][]byte{{3}, headerKey, headerValue})

	truth, err = run(1, []logicalTouchedState{{Outpoint: logicalMDBXOpA}, {Outpoint: logicalMDBXOpD, FinalPresent: true, Final: entryD}}, header)
	logicalMDBXAssert(t, truth == mdbx.CommitTruthNew && err == nil, "height-1 composition failed: truth=%v err=%v", truth, err)
	logicalMDBXWantImage(t, store, [3][]byte{{0}, logicalMDBXCounterKey(), mdbx.LogicalCounterValue(bytesD, 1)}, [3][]byte{{1}, logicalMDBXKey(logicalMDBXOpD), logicalMDBXValue(entryD)}, [3][]byte{{1}, logicalMDBXKey(logicalMDBXOpA), nil}, [3][]byte{{3}, headerKey, headerValue})

	t.Run("converter rejection keeps the old image", func(t *testing.T) {
		var inner *logicalStateFailure
		truth, err := store.Update(func(reader *mdbx.Reader) (mdbx.Batch, error) {
			view := newLogicalMDBXStateView(reader, logicalMDBXImage, 1)
			view.Counters()
			batch, failure := logicalMDBXPlanToBatch(logicalMDBXBuild(view, logicalStateCounters{bytes: bytesD, entries: 1}, logicalStateCounters{bytes: bytesD, entries: 9}, nil, nil))
			if failure != nil {
				inner = failure
				return mdbx.Batch{}, failure
			}
			return batch, nil
		})
		var rejected *logicalStateFailure
		logicalMDBXAssert(t, truth == mdbx.CommitTruthOld && errors.As(err, &rejected) && rejected == inner && rejected.kind == logicalStateFailureLocalInvariant, "converter rejection drifted: truth=%v err=%v identity=%v", truth, err, rejected == inner)
		logicalMDBXWantImage(t, store, [3][]byte{{0}, logicalMDBXCounterKey(), mdbx.LogicalCounterValue(bytesD, 1)})
	})

	t.Run("adapter-invalid extra reaches the adapter", func(t *testing.T) {
		truth, err := run(1, nil, mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: []byte{0x00}, AfterKind: mdbx.AfterLiteral, Literal: mdbx.SchemaVersionValue()})
		var engine *mdbx.EngineError
		logicalMDBXAssert(t, truth == mdbx.CommitTruthOld && errors.As(err, &engine) && engine.Class == mdbx.EngineInvalidInput, "adapter precondition drifted: truth=%v err=%v", truth, err)
	})

	t.Run("repeated genesis is a targeted Store mismatch", func(t *testing.T) {
		truth, err := run(0, []logicalTouchedState{{Outpoint: logicalMDBXOpB, FinalPresent: true, Final: entryA}})
		var engine *mdbx.EngineError
		logicalMDBXAssert(t, truth == mdbx.CommitTruthOld && errors.As(err, &engine) && engine.Class == mdbx.EngineStateMismatch, "repeated genesis drifted: truth=%v err=%v", truth, err)
	})
}

// logicalMDBXWantImage checks {rank, key, value} rows; a nil value means absent.
func logicalMDBXWantImage(t *testing.T, store *mdbx.Store, rows ...[3][]byte) {
	t.Helper()
	err := store.View(func(reader *mdbx.Reader) error {
		for _, row := range rows {
			value, present, readErr := reader.Get(logicalMDBXDBIs[row[0][0]], row[1])
			logicalMDBXAssert(t, readErr == nil, "database image read failed at %x: %v", row[1], readErr)
			logicalMDBXAssert(t, present == (row[2] != nil) && (!present || bytes.Equal(value, row[2])), "database image drifted at %x: present=%v value=%x", row[1], present, value)
		}
		return nil
	})
	logicalMDBXAssert(t, err == nil, "view: %v", err)
}

func TestLogicalMDBXOwnership(t *testing.T) {
	store := logicalMDBXSeeded(t)
	extra := mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(logicalMDBXImage, 5)), AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(filled32(1), filled32(2), [40]byte{3})}
	undo := mdbx.Mutation{DBI: logicalMDBXDBIs[5], Key: mdbx.UndoEntryKey(filled32(0x74), logicalMDBXOpA.Txid, 0, 0, logicalMDBXOpA.Vout), AfterKind: mdbx.AfterOldValueRef, RefDBI: logicalMDBXDBIs[1], RefKey: logicalMDBXKey(logicalMDBXOpA)}
	put := logicalStatePut{Outpoint: logicalMDBXOpD, Entry: logicalMDBXEntry(9, 0xd4)}
	bytesD := uint64(len(logicalStateEntryBytes(put.Outpoint, put.Entry)))
	extras := []mdbx.Mutation{extra, undo}
	var metadata logicalMDBXMetadata
	batch, failure := logicalMDBXConvert(t, store, 1, []Outpoint{logicalMDBXOpA, logicalMDBXOpD}, func(view *logicalMDBXStateView) logicalStatePlan[logicalMDBXMetadata] {
		metadata = newLogicalMDBXMetadata(view, extras)
		return logicalStatePlan[logicalMDBXMetadata]{Deletes: []logicalStateDelete{{Outpoint: logicalMDBXOpA, EntryBytes: logicalMDBXBytesA}}, Puts: []logicalStatePut{put}, Parent: logicalMDBXBase, Result: logicalStateCounters{bytes: logicalMDBXTotal - logicalMDBXBytesA + bytesD, entries: 3}, Metadata: metadata}
	})
	logicalMDBXAssert(t, failure == nil && metadata.view != nil, "bridge retained caller bytes: conversion failed %+v", failure)
	before, metadataBefore := logicalMDBXSnapshot(batch.Mutations), logicalMDBXSnapshot(metadata.extras)
	logicalMDBXFlip(extra.Key, extra.Literal, undo.Key, undo.RefKey, put.Entry.CovenantData)
	extras[0] = mdbx.Mutation{}
	logicalMDBXAssert(t, reflect.DeepEqual(logicalMDBXSnapshot(batch.Mutations), before), "bridge retained caller bytes: caller mutation changed the Batch")
	for i := range batch.Mutations {
		logicalMDBXFlip(batch.Mutations[i].Key, batch.Mutations[i].Literal, batch.Mutations[i].RefKey)
	}
	logicalMDBXAssert(t, reflect.DeepEqual(logicalMDBXSnapshot(metadata.extras), metadataBefore), "bridge retained caller bytes: Batch mutation changed the owned metadata")
}

func logicalMDBXFlip(targets ...[]byte) {
	for _, target := range targets {
		for i := range target {
			target[i] ^= 0xff
		}
	}
}

func logicalMDBXSnapshot(mutations []mdbx.Mutation) [][]byte {
	snapshot := make([][]byte, 0, 3*len(mutations))
	for _, mutation := range mutations {
		snapshot = append(snapshot, bytes.Clone(mutation.Key), bytes.Clone(mutation.Literal), bytes.Clone(mutation.RefKey))
	}
	return snapshot
}

// TestLogicalMDBXBridgeDormantCensus is a type-aware structural census: it proves
// only the dormancy and build rows, never a behavioral assertion.
func TestLogicalMDBXBridgeDormantCensus(t *testing.T) {
	var listed struct{ GoFiles, CgoFiles, IgnoredGoFiles []string }
	out, err := exec.CommandContext(t.Context(), "go", "list", "-e", "-json", ".").Output()
	logicalMDBXAssert(t, err == nil && json.Unmarshal(out, &listed) == nil, "go list: %v", err)
	for _, name := range []string{"logical_state_mdbx_cgo.go", "logical_state_mdbx_cgo_test.go"} {
		source, readErr := os.ReadFile(name)
		logicalMDBXAssert(t, readErr == nil, "read %s: %v", name, readErr)
		expression, parseErr := constraint.Parse(strings.SplitN(string(source), "\n", 2)[0])
		logicalMDBXAssert(t, parseErr == nil && expression.String() == logicalMDBXConstraint, "bridge entered unsupported build: %s declares %v (%v)", name, expression, parseErr)
	}
	// go list's non-test source set is GoFiles+CgoFiles+IgnoredGoFiles: a file ignored on this platform may still compile, and call the bridge, elsewhere.
	sources := slices.Concat(listed.GoFiles, listed.CgoFiles, listed.IgnoredGoFiles)
	fset, imports, files := token.NewFileSet(), 0, make([]*ast.File, 0, len(sources))
	for _, name := range sources {
		parsed, parseErr := parser.ParseFile(fset, name, nil, 0)
		logicalMDBXAssert(t, parseErr == nil, "parse %s: %v", name, parseErr)
		for _, spec := range parsed.Imports {
			if strings.HasSuffix(spec.Path.Value, `/internal/mdbx"`) {
				imports++
				logicalMDBXAssert(t, name == "logical_state_mdbx_cgo.go", "bridge lost dormancy: %s imports internal/mdbx", name)
			}
		}
		files = append(files, parsed)
	}
	logicalMDBXAssert(t, imports == 1, "bridge lost dormancy: %d non-test internal/mdbx imports, want 1", imports)
	info, config := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}}, &types.Config{FakeImportC: true, DisableUnusedImportCheck: true, Error: func(error) {}, Importer: logicalMDBXStubImporter{}}
	_, _ = config.Check("consensus", fset, files, info)
	names, declared, resolved := map[string]bool{"newLogicalMDBXStateView": true, "newLogicalMDBXMetadata": true, "logicalMDBXPlanToBatch": true, "Counters": true, "Lookup": true}, map[types.Object]bool{}, map[string]bool{}
	for ident, object := range info.Defs {
		if names[ident.Name] && object != nil && strings.HasSuffix(fset.Position(ident.Pos()).Filename, "logical_state_mdbx_cgo.go") {
			declared[object] = true
		}
	}
	logicalMDBXAssert(t, len(declared) == len(names), "bridge lost dormancy: resolved %d of %d bridge entrypoints", len(declared), len(names))
	for ident, object := range info.Uses {
		logicalMDBXAssert(t, !declared[object], "bridge lost dormancy: non-test use of %s at %s", ident.Name, fset.Position(ident.Pos()))
		resolved[fset.Position(ident.Pos()).Filename] = true
	}
	// The checker swallows its errors, so a vacuous Uses graph would pass the loop above: every parsed file must have resolved a use, and every entrypoint-named identifier outside a declaration must carry a type object.
	logicalMDBXAssert(t, len(resolved) == len(sources), "bridge census resolved no uses: %d of %d files resolved, unresolved %v", len(resolved), len(sources), slices.DeleteFunc(slices.Clone(sources), func(name string) bool { return resolved[name] }))
	for _, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok && names[ident.Name] && info.Defs[ident] == nil {
				logicalMDBXAssert(t, info.Uses[ident] != nil, "bridge census resolved no uses: %s at %s lacks a type object", ident.Name, fset.Position(ident.Pos()))
			}
			return true
		})
	}
}

type logicalMDBXStubImporter struct{}

func (logicalMDBXStubImporter) Import(path string) (*types.Package, error) {
	pkg := types.NewPackage(path, path[strings.LastIndex(path, "/")+1:])
	pkg.MarkComplete()
	return pkg, nil
}
