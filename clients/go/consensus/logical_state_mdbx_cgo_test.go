//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"cmp"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/format"
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
	logicalMDBXDBIs = mdbx.SchemaV2DBIs()
	logicalMDBXOpA  = Outpoint{Txid: filled32(0x11)}
	logicalMDBXOpB  = Outpoint{Txid: filled32(0x22), Vout: 1}
	logicalMDBXOpC  = Outpoint{Txid: filled32(0x33), Vout: 2}
	logicalMDBXOpD  = Outpoint{Txid: filled32(0x44), Vout: 3}
	logicalMDBXBase = logicalStateCounters{bytes: logicalMDBXTotal, entries: 3}
)

// logicalMDBXMust unwraps a SchemaV2 constructor over constant test inputs.
func logicalMDBXMust(value []byte, err error) []byte {
	if err != nil {
		panic("SchemaV2 test helper: " + err.Error())
	}
	return value
}

func logicalMDBXAssert(t testing.TB, ok bool, format string, args ...any) {
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
	truth, _, err := store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { return mdbx.Batch{Mutations: mutations}, nil })
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
	entryD, entryE, entryX := logicalMDBXEntry(7, 0xd4), logicalMDBXEntry(9, 0xe5), logicalMDBXEntry(MAX_COVENANT_DATA_PER_OUTPUT+1, 0x5b)
	bytesD, bytesE, bytesX := uint64(len(logicalStateEntryBytes(logicalMDBXOpD, entryD))), uint64(len(logicalStateEntryBytes(logicalMDBXOpB, entryE))), uint64(len(logicalStateEntryBytes(logicalMDBXOpD, entryX)))
	delA, delB := []logicalStateDelete{{Outpoint: logicalMDBXOpA, EntryBytes: logicalMDBXBytesA}}, []logicalStateDelete{{Outpoint: logicalMDBXOpB, EntryBytes: logicalMDBXBytesB}}
	putD, counterOnly := []logicalStatePut{{Outpoint: logicalMDBXOpD, Entry: entryD}}, []mdbx.Mutation{logicalMDBXCounterRow(true, logicalMDBXTotal, 3)}
	deleteRowA, opE := mdbx.Mutation{DBI: logicalMDBXDBIs[1], Key: logicalMDBXKey(logicalMDBXOpA), BeforePresent: true, AfterKind: mdbx.AfterAbsent}, Outpoint{Txid: filled32(0x22), Vout: 9}
	replaceRowB := logicalMDBXUTXORow(logicalMDBXOpB, entryE)
	replaceRowB.BeforePresent = true
	afterA, afterE, afterD := logicalStateCounters{bytes: logicalMDBXTotal - logicalMDBXBytesA, entries: 2}, logicalStateCounters{bytes: logicalMDBXTotal - logicalMDBXBytesB + bytesE, entries: 3}, logicalStateCounters{bytes: logicalMDBXTotal + bytesD, entries: 4}
	for _, tc := range []struct {
		name, label    string
		counters       bool
		height         uint64
		lookups        []Outpoint
		parent, result logicalStateCounters
		cause          string
		deletes        []logicalStateDelete
		puts           []logicalStatePut
		extras         []mdbx.Mutation
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
		{name: "genesis with parent counters", label: "genesis form accepted", height: 0, parent: logicalStateCounters{bytes: 56, entries: 1}, result: logicalStateCounters{bytes: 56 + bytesD, entries: 2}, puts: putD, kind: logicalStateFailureLocalInvariant, cause: "genesis"},
		{name: "genesis with delete", label: "genesis form accepted", height: 0, deletes: delA, kind: logicalStateFailureLocalInvariant, cause: "genesis"},
		{name: "genesis with delete precedes a cross-image extra", label: "genesis form accepted", height: 0, parent: logicalStateCounters{bytes: 56, entries: 1}, deletes: delA, extras: []mdbx.Mutation{{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(logicalMDBXImage+1, 5)), AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(filled32(1), filled32(2), [40]byte{3})}}, kind: logicalStateFailureLocalInvariant, cause: "genesis"},
		{name: "genesis with parent counters precedes an arithmetic contradiction", label: "genesis form accepted", height: 0, parent: logicalStateCounters{bytes: 56, entries: 1}, result: logicalStateCounters{bytes: 56 + bytesD, entries: 5}, puts: putD, kind: logicalStateFailureLocalInvariant, cause: "genesis"},
		{name: "genesis with a counter observation", label: "genesis form accepted", height: 0, counters: true, result: logicalStateCounters{bytes: bytesD, entries: 1}, puts: putD, kind: logicalStateFailureLocalInvariant, cause: "genesis"},
		{name: "genesis with observation", label: "genesis form accepted", height: 0, lookups: []Outpoint{logicalMDBXOpA}, result: logicalStateCounters{bytes: bytesD, entries: 1}, puts: putD, kind: logicalStateFailureLocalInvariant, cause: "genesis"},
		{name: "put over the covenant data bound", label: "covenant bound accepted", height: 0, result: logicalStateCounters{bytes: bytesX, entries: 1}, puts: []logicalStatePut{{Outpoint: logicalMDBXOpD, Entry: entryX}}, kind: logicalStateFailureLocalInvariant, cause: "covenant"},
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
				return logicalMDBXBuild(view, tc.parent, tc.result, tc.deletes, tc.puts, tc.extras...)
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

const logicalMDBXEmit, logicalMDBXOmit, logicalMDBXLocal, logicalMDBXIntegrity, logicalMDBXAdapterInvalid logicalMDBXExtraOutcome = 0, 1, 2, 3, 4

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
	// Owner rows pair the seeded (image, 4) forward entry naming filled32(1) and the same-image (image, 5) extra naming filled32(5).
	ownerKey := func(hash [32]byte) []byte {
		return append(binary.BigEndian.AppendUint64(nil, logicalMDBXImage), hash[:]...)
	}
	sameChain := mdbx.ChainValue(filled32(5), filled32(2), [40]byte{3})
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
	image := []mdbx.Mutation{literal(3, headerKey, headerValue), literal(4, blockKey, blockValue), literal(5, manifestKey, manifestValue), literal(2, seededImage, chain), literal(6, seededImage, chain), ref(logicalMDBXOpB, logicalMDBXImage), literal(7, ownerKey(filled32(1)), binary.BigEndian.AppendUint64(nil, 4))}
	logicalMDBXSeed(t, store, image...)
	logicalMDBXAssert(t, mdbx.ValidateRow(logicalMDBXDBIs[4], blockKey, blockDiffering) == nil, "differing create-once literal is adapter-invalid")
	for _, tc := range []struct {
		name, label, cause string
		extras             []mdbx.Mutation
		outcome            logicalMDBXExtraOutcome
	}{
		{"rank0 metadata literal", "extra target policy drifted", "", []mdbx.Mutation{literal(0, metaKey, logicalMDBXAuthorityLiteral())}, logicalMDBXEmit},
		{"rank0 counter literal", "extra target policy drifted", "", []mdbx.Mutation{literal(0, counterKey, mdbx.LogicalCounterValue(1, 1))}, logicalMDBXLocal},
		{"rank0 counter deletion", "extra target policy drifted", "", []mdbx.Mutation{absent(0, counterKey)}, logicalMDBXLocal},
		{"rank0 metadata deletion", "extra target policy drifted", "", []mdbx.Mutation{absent(0, metaKey)}, logicalMDBXAdapterInvalid},
		{"rank0 reference", "extra target policy drifted", "", []mdbx.Mutation{{DBI: logicalMDBXDBIs[0], Key: metaKey, AfterKind: mdbx.AfterOldValueRef}}, logicalMDBXAdapterInvalid},
		{"rank1 literal", "extra target policy drifted", "", []mdbx.Mutation{literal(1, logicalMDBXKey(logicalMDBXOpD), logicalMDBXValue(logicalMDBXEntry(1, 0x91)))}, logicalMDBXLocal},
		{"rank1 deletion", "extra target policy drifted", "", []mdbx.Mutation{absent(1, logicalMDBXKey(logicalMDBXOpC))}, logicalMDBXLocal},
		{"rank1 reference", "extra target policy drifted", "", []mdbx.Mutation{{DBI: logicalMDBXDBIs[1], Key: logicalMDBXKey(logicalMDBXOpD), AfterKind: mdbx.AfterOldValueRef}}, logicalMDBXLocal},
		{"rank2 literal same image", "extra target policy drifted", "", []mdbx.Mutation{literal(2, sameImage, sameChain), literal(7, ownerKey(filled32(5)), binary.BigEndian.AppendUint64(nil, 5))}, logicalMDBXEmit},
		{"rank2 literal cross image", "extra target policy drifted", "", []mdbx.Mutation{literal(2, crossImage, chain)}, logicalMDBXLocal},
		{"rank2 deletion", "extra target policy drifted", "", []mdbx.Mutation{absent(2, seededImage), absent(7, ownerKey(filled32(1)))}, logicalMDBXEmit},
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
		{"shuffled extras sort", "final Batch order drifted", "", []mdbx.Mutation{literal(6, sameImage, chain), literal(0, metaKey, logicalMDBXAuthorityLiteral()), literal(3, freshKey, freshValue)}, logicalMDBXEmit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.outcome == logicalMDBXAdapterInvalid {
				// A cell the bridge never classifies: the adapter itself refuses it.
				truth, _, updateErr := store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { return mdbx.Batch{Mutations: tc.extras}, nil })
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
	truth, _, err := fresh.Update(func(*mdbx.Reader) (mdbx.Batch, error) { return batch, nil })
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
		truth, _, err := store.Update(func(reader *mdbx.Reader) (mdbx.Batch, error) {
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
		return truth, err
	}
	truth, err := run(0, []logicalTouchedState{{Outpoint: logicalMDBXOpA, FinalPresent: true, Final: entryA}}, header)
	logicalMDBXAssert(t, truth == mdbx.CommitTruthNew && err == nil, "genesis composition failed: truth=%v err=%v", truth, err)
	logicalMDBXWantImage(t, store, [3][]byte{{0}, logicalMDBXCounterKey(), mdbx.LogicalCounterValue(logicalMDBXBytesA, 1)}, [3][]byte{{1}, logicalMDBXKey(logicalMDBXOpA), logicalMDBXValue(entryA)}, [3][]byte{{3}, headerKey, headerValue})
	truth, err = run(1, []logicalTouchedState{{Outpoint: logicalMDBXOpA}, {Outpoint: logicalMDBXOpD, FinalPresent: true, Final: entryD}}, header)
	logicalMDBXAssert(t, truth == mdbx.CommitTruthNew && err == nil, "height-1 composition failed: truth=%v err=%v", truth, err)
	logicalMDBXWantImage(t, store, [3][]byte{{0}, logicalMDBXCounterKey(), mdbx.LogicalCounterValue(bytesD, 1)}, [3][]byte{{1}, logicalMDBXKey(logicalMDBXOpD), logicalMDBXValue(entryD)}, [3][]byte{{1}, logicalMDBXKey(logicalMDBXOpA), nil}, [3][]byte{{3}, headerKey, headerValue})
	t.Run("converter rejection keeps the old image", func(t *testing.T) {
		var inner *logicalStateFailure
		truth, _, err := store.Update(func(reader *mdbx.Reader) (mdbx.Batch, error) {
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

func TestLogicalMDBXGenesisCounterAdmission(t *testing.T) {
	const genesisCause = "genesis logical state form contradicts the view"
	for _, tc := range []struct {
		name, label string
		counter     logicalStateCounters
		parent      logicalStateCounters
		result      logicalStateCounters
		deletes     []logicalStateDelete
		lookup      *Outpoint
		extras      []mdbx.Mutation
	}{
		{name: "bytes only", label: "nonzero genesis counter accepted", counter: logicalStateCounters{bytes: 1}},
		{name: "entries only", label: "nonzero genesis counter accepted", counter: logicalStateCounters{entries: 1}},
		{name: "both nonzero", label: "nonzero genesis counter accepted", counter: logicalStateCounters{bytes: 56, entries: 1}},
		{name: "maximum bytes", label: "nonzero genesis counter accepted", counter: logicalStateCounters{bytes: ^uint64(0)}},
		{name: "maximum entries", label: "nonzero genesis counter accepted", counter: logicalStateCounters{entries: ^uint64(0)}},
		{name: "parent bytes", label: "genesis parent admitted", parent: logicalStateCounters{bytes: 1}, result: logicalStateCounters{bytes: 1}},
		{name: "parent entries", label: "genesis parent admitted", parent: logicalStateCounters{entries: 1}, result: logicalStateCounters{entries: 1}},
		{name: "delete", label: "genesis delete diagnostic drifted", deletes: []logicalStateDelete{{Outpoint: logicalMDBXOpA, EntryBytes: 56}}},
		{name: "present row", label: "genesis row observation admitted", lookup: &logicalMDBXOpA},
		{name: "absent row", label: "genesis row observation admitted", lookup: &logicalMDBXOpD},
		{name: "arithmetic precedence", label: "genesis arithmetic precedence drifted", counter: logicalStateCounters{bytes: 56, entries: 1}, result: logicalStateCounters{entries: 1}},
		{name: "extra precedence", label: "genesis extra precedence drifted", counter: logicalStateCounters{bytes: 56, entries: 1}, extras: []mdbx.Mutation{{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(8, 5)), AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(filled32(1), filled32(2), [40]byte{3})}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := logicalMDBXStore(t)
			counter, row := logicalMDBXCounterRow(false, tc.counter.bytes, tc.counter.entries), logicalMDBXUTXORow(logicalMDBXOpA, logicalMDBXEntry(0, 0xa1))
			logicalMDBXSeed(t, store, counter, row)
			old := [][3][]byte{{{0}, slices.Clone(counter.Key), slices.Clone(counter.Literal)}, {{1}, slices.Clone(row.Key), slices.Clone(row.Literal)}, {{1}, logicalMDBXKey(logicalMDBXOpD), nil}}
			for _, extra := range tc.extras {
				old = append(old, [3][]byte{{extra.DBI.Rank}, slices.Clone(extra.Key), nil})
			}
			var inner *logicalStateFailure
			truth, _, err := store.Update(func(reader *mdbx.Reader) (mdbx.Batch, error) {
				view := newLogicalMDBXStateView(reader, 7, 0)
				read := view.Counters()
				logicalMDBXAssert(t, read.kind == logicalStateCountersPresent && read.counters == tc.counter && read.cause == nil && view.counterPresent, "counter observation failed: %+v", read)
				if tc.lookup != nil {
					got := view.Lookup(*tc.lookup)
					want := logicalStateRowAbsent
					if *tc.lookup == logicalMDBXOpA {
						want = logicalStateRowPresent
					}
					logicalMDBXAssert(t, got.kind == want && got.cause == nil && len(view.rows) == 1, "row observation failed: %+v", got)
				}
				batch, failure := logicalMDBXPlanToBatch(logicalMDBXBuild(view, tc.parent, tc.result, tc.deletes, nil, tc.extras...))
				logicalMDBXWantFailure(t, tc.label, batch, failure, logicalStateFailureLocalInvariant)
				logicalMDBXAssert(t, failure.cause.Error() == genesisCause && reflect.DeepEqual(batch, mdbx.Batch{}), "%s: cause=%v batch=%+v", tc.label, failure.cause, batch)
				inner = failure
				return batch, failure
			})
			var rejected *logicalStateFailure
			logicalMDBXAssert(t, truth == mdbx.CommitTruthOld && errors.As(err, &rejected) && rejected == inner && rejected.kind == logicalStateFailureLocalInvariant && rejected.cause.Error() == genesisCause, "genesis rejection identity drifted: truth=%v err=%v", truth, err)
			logicalMDBXWantImage(t, store, old...)
		})
	}
	for _, tc := range []struct {
		name string
		view *logicalMDBXStateView
	}{{"nil view", nil}, {"zero image", newLogicalMDBXStateView(nil, 0, 0)}} {
		t.Run(tc.name, func(t *testing.T) {
			batch, failure := logicalMDBXPlanToBatch(logicalMDBXBuild(tc.view, logicalStateCounters{bytes: 1}, logicalStateCounters{bytes: 1}, nil, nil))
			logicalMDBXWantFailure(t, "view precedence drifted", batch, failure, logicalStateFailureLocalInvariant)
			logicalMDBXAssert(t, failure.cause.Error() == "nil logical MDBX metadata view or zero image identifier" && reflect.DeepEqual(batch, mdbx.Batch{}), "view precedence drifted: %v", failure)
		})
	}
	for _, height := range []uint64{0, 1} {
		t.Run(fmt.Sprintf("absent counter height %d", height), func(t *testing.T) {
			logicalMDBXView(t, logicalMDBXStore(t), height, func(view *logicalMDBXStateView) {
				read := view.Counters()
				logicalMDBXAssert(t, read.kind == logicalStateCountersStoreIntegrity && read.cause != nil && read.cause.Error() == "logical counter absent above genesis" && !view.counterPresent, "absent counter accepted: %+v", read)
				// A failed explicit read never continues to planning or conversion.
			})
		})
	}
}

func TestLogicalMDBXGenesisCounterBootstrapComposition(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile mdbx.StorageProfileV1
		image   uint64
		put     bool
	}{
		{"PRUNED", mdbx.StorageProfilePrunedV1, 1, true},
		{"ARCHIVE", mdbx.StorageProfileArchiveV1, 1, true},
		{"generation 7 empty", 0, 7, false},
		{"generation 7 put", 0, 7, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := logicalMDBXStore(t)
			counterKey := []byte{0x10, 0, 0, 0, 0, 0, 0, 0, byte(tc.image)}
			var authority []byte
			if tc.profile != 0 {
				owner, err := mdbx.NewOperationReservationOwner(mdbx.MaxOperationDataBytes)
				logicalMDBXAssert(t, err == nil, "reservation owner: %v", err)
				truth, _, err := store.BootstrapStorageV1(tc.profile, owner)
				logicalMDBXAssert(t, truth == mdbx.CommitTruthNew && err == nil, "bootstrap producer: truth=%v err=%v", truth, err)
				authority = logicalMDBXAuthorityLiteral()
				authority[1] = byte(tc.profile)
				logicalMDBXWantImage(t, store, [3][]byte{{0}, {2}, authority}, [3][]byte{{0}, counterKey, make([]byte, 16)})
			} else {
				logicalMDBXSeed(t, store, logicalMDBXCounterRow(false, 0, 0))
			}
			entry := logicalMDBXEntry(0, 0xa1)
			// Independent SchemaV2 literals: BE generation, txid, BE vout; value/type/length/height/coinbase.
			utxoKey := append([]byte{0, 0, 0, 0, 0, 0, 0, byte(tc.image)}, bytes.Repeat([]byte{0x11}, 32)...)
			utxoKey = append(utxoKey, 0, 0, 0, 0)
			utxoValue := []byte{0xa2, 0, 0, 0, 0, 0, 0, 0, 0xa1, 0, 0, 0xa3, 0, 0, 0, 0, 0, 0, 0, 1}
			counterValue, result := make([]byte, 16), logicalStateCounters{}
			var touched []logicalTouchedState
			if tc.put {
				counterValue[7], counterValue[15] = 56, 1
				result = logicalStateCounters{bytes: 56, entries: 1}
				touched = []logicalTouchedState{{Outpoint: logicalMDBXOpA, FinalPresent: true, Final: entry}}
			}
			truth, _, err := store.Update(func(reader *mdbx.Reader) (mdbx.Batch, error) {
				view := newLogicalMDBXStateView(reader, tc.image, 0)
				read := view.Counters()
				logicalMDBXAssert(t, read.kind == logicalStateCountersPresent && read.counters == (logicalStateCounters{}) && read.cause == nil && view.counterPresent, "zero counter observation failed: %+v", read)
				plan, failure := buildLogicalStatePlan(0, view, touched, newLogicalMDBXMetadata(view, nil))
				logicalMDBXAssert(t, failure == nil && plan.Parent == (logicalStateCounters{}) && len(plan.Deletes) == 0 && plan.Result == result && len(view.rows) == 0, "zero-parent plan drifted: plan=%+v failure=%v", plan, failure)
				batch, failure := logicalMDBXPlanToBatch(plan)
				logicalMDBXAssert(t, failure == nil, "bootstrap zero counter rejected: %v", failure)
				logicalMDBXAssert(t, len(batch.Mutations) == 1+len(touched), "genesis mutation count drifted: %+v", batch)
				logicalMDBXAssert(t, batch.Mutations[0].BeforePresent, "counter before-presence drifted")
				want := []mdbx.Mutation{{DBI: logicalMDBXDBIs[0], Key: counterKey, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: counterValue}}
				if tc.put {
					want = append(want, mdbx.Mutation{DBI: logicalMDBXDBIs[1], Key: utxoKey, AfterKind: mdbx.AfterLiteral, Literal: utxoValue})
				}
				logicalMDBXWantBatch(t, "genesis exact batch drifted", batch, failure, want...)
				return batch, nil
			})
			logicalMDBXAssert(t, truth == mdbx.CommitTruthNew && err == nil, "observed-zero composition failed: truth=%v err=%v", truth, err)
			if !tc.put {
				utxoValue = nil
			}
			// This partial adapter composition leaves P04 authority unchanged; it is not canonical genesis.
			logicalMDBXWantImage(t, store, [3][]byte{{0}, counterKey, counterValue}, [3][]byte{{1}, utxoKey, utxoValue}, [3][]byte{{0}, {2}, authority})
		})
	}
}

func logicalMDBXAuthorityLiteral() []byte {
	// Independent NONE/STABLE authority: pruned, active generation 1, next 2.
	return []byte{1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 1, 1, 0, 0, 0, 0}
}

func TestLogicalMDBXAuthorityAdmissionBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	cfg := mdbx.ConfigV1{Lower: 1 << 20, Now: 2 << 20, Upper: 256 << 20, Growth: 1 << 20, Shrink: 2 << 20, PageSize: 4096, MaxReaders: 492}
	store, err := mdbx.Create(path, cfg)
	logicalMDBXAssert(t, err == nil, "authority bridge store: %v", err)
	authority := logicalMDBXAuthorityLiteral()
	entry := logicalMDBXEntry(0, 0xa1)
	logicalMDBXSeed(t, store, mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: []byte{2}, AfterKind: mdbx.AfterLiteral, Literal: authority}, logicalMDBXCounterRow(false, logicalMDBXBytesA, 1), logicalMDBXUTXORow(logicalMDBXOpA, entry))
	old := [][3][]byte{{{0}, {2}, slices.Clone(authority)}, {{0}, logicalMDBXCounterKey(), mdbx.LogicalCounterValue(logicalMDBXBytesA, 1)}, {{1}, logicalMDBXKey(logicalMDBXOpA), logicalMDBXValue(entry)}}
	logicalMDBXWantImage(t, store, old...)
	run := func(value []byte) (mdbx.CommitTruth, error) {
		truth, _, err := store.Update(func(reader *mdbx.Reader) (mdbx.Batch, error) {
			view := newLogicalMDBXStateView(reader, logicalMDBXImage, 1)
			extra := mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: value}
			plan, failure := buildLogicalStatePlan(1, view, []logicalTouchedState{{Outpoint: logicalMDBXOpA}}, newLogicalMDBXMetadata(view, []mdbx.Mutation{extra}))
			logicalMDBXAssert(t, failure == nil, "authority bridge plan: %v", failure)
			batch, failure := logicalMDBXPlanToBatch(plan)
			logicalMDBXAssert(t, failure == nil && len(batch.Mutations) == 3, "authority bridge domain narrowed: failure=%v rows=%d", failure, len(batch.Mutations))
			logicalMDBXAssert(t, reflect.DeepEqual(batch.Mutations[0], extra), "authority bridge domain narrowed: extra changed")
			return batch, nil
		})
		return truth, err
	}
	truth, err := run([]byte{9})
	var engine *mdbx.EngineError
	direct := reflect.TypeOf(err) == reflect.TypeFor[*mdbx.EngineError]() && errors.As(err, &engine)
	logicalMDBXAssert(t, truth.String() == "OLD" && direct && engine != nil && string(engine.Class) == "InvalidInput" && engine.Operation == "update" && engine.Code == 22 && engine.Diagnostic == "invalid Update Batch" && engine.Cause == nil && !engine.ReopenRequired, "authority bridge schema rejection tuple: truth=%v err=%v", truth, err)
	logicalMDBXWantImage(t, store, old...)
	logicalMDBXAssert(t, store.Close() == nil, "authority bridge close")
	store, err = mdbx.Open(path, cfg)
	logicalMDBXAssert(t, err == nil, "authority bridge reopen: %v", err)
	logicalMDBXWantImage(t, store, old...)
	authority[1] = 2
	truth, err = run(authority)
	logicalMDBXAssert(t, truth.String() == "NEW" && err == nil, "authority bridge valid composition: truth=%v err=%v", truth, err)
	current := [][3][]byte{{{0}, {2}, authority}, {{0}, logicalMDBXCounterKey(), mdbx.LogicalCounterValue(0, 0)}, {{1}, logicalMDBXKey(logicalMDBXOpA), nil}}
	logicalMDBXWantImage(t, store, current...)
	logicalMDBXAssert(t, store.Close() == nil, "authority bridge close")
	store, err = mdbx.Open(path, cfg)
	logicalMDBXAssert(t, err == nil, "authority bridge reopen: %v", err)
	logicalMDBXWantImage(t, store, current...)
	logicalMDBXAssert(t, store.Close() == nil, "authority bridge close")
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
	for _, name := range []string{"logical_state_mdbx_cgo.go", "logical_state_mdbx_cgo_test.go", "genesis_mdbx_cgo_external_test.go", "selected_side_damage_mdbx_cgo.go", "selected_side_damage_mdbx_cgo_test.go", "archive_profile_mdbx_cgo.go", "archive_profile_mdbx_cgo_test.go", "stored_block_commitments_stream_test.go", "cleanup_generation_mdbx_cgo.go", "cleanup_generation_mdbx_cgo_test.go", "detached_drain_mdbx_cgo.go", "detached_drain_mdbx_cgo_test.go", "replay_entry_mdbx_cgo.go", "replay_entry_mdbx_cgo_test.go", "replay_recovery_mdbx_cgo.go", "replay_recovery_mdbx_cgo_test.go", "replay_path_mdbx_cgo.go", "replay_path_mdbx_cgo_test.go", "canonical_undo_mdbx_cgo.go", "canonical_undo_mdbx_cgo_test.go", "startup_mdbx_cgo.go", "startup_mdbx_cgo_test.go"} {
		source, readErr := os.ReadFile(name)
		logicalMDBXAssert(t, readErr == nil, "read %s: %v", name, readErr)
		expression, parseErr := constraint.Parse(strings.SplitN(string(source), "\n", 2)[0])
		logicalMDBXAssert(t, parseErr == nil && expression.String() == logicalMDBXConstraint, "bridge entered unsupported build: %s declares %v (%v)", name, expression, parseErr)
	}
	// The ordinary commitment stream is shared with the untagged steps 1-12 entry: it must be a GoFiles member and carry
	// no build constraint of either syntax before its package clause.
	stream, readErr := os.ReadFile("stored_block_commitments_stream.go")
	logicalMDBXAssert(t, readErr == nil && slices.Contains(listed.GoFiles, "stored_block_commitments_stream.go"), "ordinary stream left GoFiles: %v", readErr)
	preamble, _, _ := strings.Cut(string(stream), "package consensus")
	for _, line := range strings.Split(preamble, "\n") {
		logicalMDBXAssert(t, !constraint.IsGoBuild(line) && !constraint.IsPlusBuild(line), "ordinary stream declares a build constraint: %q", line)
	}
	// go list's non-test source set is GoFiles+CgoFiles+IgnoredGoFiles: a file ignored on this platform may still compile, and call the bridge, elsewhere.
	sources := slices.Concat(listed.GoFiles, listed.CgoFiles, listed.IgnoredGoFiles)
	// IgnoredGoFiles also lists these exact rubin_mdbx_fixture-tagged test files; they are test code, not non-test sources.
	sources = slices.DeleteFunc(sources, func(name string) bool {
		return name == "selected_side_damage_mdbx_fixture_cgo_test.go" || name == "archive_profile_mdbx_fixture_cgo_test.go" || name == "cleanup_drains_mdbx_fixture_cgo_test.go" || name == "replay_entry_mdbx_fixture_cgo_test.go" || name == "replay_recovery_mdbx_fixture_cgo_test.go" || name == "replay_path_mdbx_fixture_cgo_test.go" || name == "canonical_undo_mdbx_fixture_cgo_test.go" || name == "startup_mdbx_fixture_cgo_test.go"
	})
	fset, imports, files := token.NewFileSet(), 0, make([]*ast.File, 0, len(sources))
	for _, name := range sources {
		parsed, parseErr := parser.ParseFile(fset, name, nil, 0)
		logicalMDBXAssert(t, parseErr == nil, "parse %s: %v", name, parseErr)
		for _, spec := range parsed.Imports {
			if strings.HasSuffix(spec.Path.Value, `/internal/mdbx"`) {
				imports++
				logicalMDBXAssert(t, name == "logical_state_mdbx_cgo.go" || name == "selected_side_damage_mdbx_cgo.go" || name == "archive_profile_mdbx_cgo.go" || name == "cleanup_generation_mdbx_cgo.go" || name == "detached_drain_mdbx_cgo.go" || name == "replay_entry_mdbx_cgo.go" || name == "replay_recovery_mdbx_cgo.go" || name == "replay_path_mdbx_cgo.go" || name == "canonical_undo_mdbx_cgo.go" || name == "startup_mdbx_cgo.go", "bridge lost dormancy: %s imports internal/mdbx", name)
			}
		}
		files = append(files, parsed)
	}
	logicalMDBXAssert(t, imports == 10, "bridge lost dormancy: %d non-test internal/mdbx imports, want 10", imports)
	native := startupCensusNative(t)
	info, config := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}}, &types.Config{FakeImportC: true, DisableUnusedImportCheck: true, Error: func(error) {}, Importer: logicalMDBXStubImporter{native: native}}
	consensusPackage, _ := config.Check("consensus", fset, files, info)
	names, declared, resolved := map[string]bool{"newLogicalMDBXStateView": true, "newLogicalMDBXMetadata": true, "logicalMDBXPlanToBatch": true, "genesisMDBXBatch": true, "Counters": true, "Lookup": true}, map[types.Object]bool{}, map[string]bool{}
	for ident, object := range info.Defs {
		if names[ident.Name] && object != nil && strings.HasSuffix(fset.Position(ident.Pos()).Filename, "logical_state_mdbx_cgo.go") {
			declared[object] = true
		}
	}
	logicalMDBXAssert(t, len(declared) == len(names), "bridge lost dormancy: resolved %d of %d bridge entrypoints", len(declared), len(names))
	parents := map[ast.Node]ast.Node{}
	for _, file := range files {
		var stack []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			if len(stack) != 0 {
				parents[n] = stack[len(stack)-1]
			}
			stack = append(stack, n)
			return true
		})
	}
	approved := map[string]int{}
	recheck := 0
	enclosing := func(n ast.Node) string {
		for n = parents[n]; n != nil; n = parents[n] {
			if fn, ok := n.(*ast.FuncDecl); ok {
				return fn.Name.Name
			}
		}
		return ""
	}
	for ident, object := range info.Uses {
		if declared[object] {
			var owner string
			var literal bool
			for n := parents[ident]; n != nil; n = parents[n] {
				if _, ok := n.(*ast.FuncLit); ok {
					literal = true
				}
				if fn, ok := n.(*ast.FuncDecl); ok {
					owner = fn.Name.Name
					break
				}
			}
			var callee ast.Node = ident
			if selector, ok := parents[ident].(*ast.SelectorExpr); ok {
				callee = selector
			}
			call, direct := parents[callee].(*ast.CallExpr)
			logicalMDBXAssert(t, (owner == "genesisMDBXBatch" && !literal && ident.Name != "Lookup" || owner == "ConnectPublishedGenesisMDBX" && ident.Name == "genesisMDBXBatch") && direct && call.Fun == callee, "bridge lost dormancy: non-test use of %s at %s", ident.Name, fset.Position(ident.Pos()))
			approved[ident.Name]++
		}
		logicalMDBXAssert(t, ident.Name != "ConnectPublishedGenesisMDBX", "bridge lost dormancy: genesis production consumer at %s", fset.Position(ident.Pos()))
		if ident.Name == "selectedSideDamageMDBX" {
			// The sole non-test reference is the direct same-file call inside the exported recheck adapter.
			call, direct := parents[ident].(*ast.CallExpr)
			recheck++
			logicalMDBXAssert(t, direct && call.Fun == ident && enclosing(ident) == "RecheckSelectedSideMDBX" && strings.HasSuffix(fset.Position(ident.Pos()).Filename, "selected_side_damage_mdbx_cgo.go"), "selected side damage lost dormancy: production consumer at %s", fset.Position(ident.Pos()))
		}
		resolved[fset.Position(ident.Pos()).Filename] = true
	}
	logicalMDBXAssert(t, recheck == 1, "selected side damage lost dormancy: %d recheck adapter references, want 1", recheck)
	logicalMDBXAssert(t, reflect.DeepEqual(approved, map[string]int{"newLogicalMDBXStateView": 1, "Counters": 1, "newLogicalMDBXMetadata": 1, "logicalMDBXPlanToBatch": 1, "genesisMDBXBatch": 1}), "bridge lost dormancy: exact owner census %v", approved)
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
	startupCensusUses(t, fset, files, info, parents, native)
	// Resolve dormant public uses in the actual node and command packages too.
	// The existing incomplete-import checker remains deliberately tolerant of
	// unrelated types, while every protected spelling must resolve nonvacuously.
	commandDirs, err := filepath.Glob("../cmd/*")
	logicalMDBXAssert(t, err == nil && consensusPackage != nil, "startup consumer census source")
	for _, dir := range append([]string{"../node"}, commandDirs...) {
		entries, readErr := os.ReadDir(dir)
		logicalMDBXAssert(t, readErr == nil, "startup consumer census read %s: %v", dir, readErr)
		packages := map[string][]*ast.File{}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			file, parseErr := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, 0)
			logicalMDBXAssert(t, parseErr == nil, "startup consumer census parse %s: %v", entry.Name(), parseErr)
			packages[file.Name.Name] = append(packages[file.Name.Name], file)
		}
		for name, parsed := range packages {
			uses := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}}
			checker := &types.Config{FakeImportC: true, DisableUnusedImportCheck: true, Error: func(error) {}, Importer: logicalMDBXStubImporter{native: native, consensus: consensusPackage}}
			_, _ = checker.Check(name, fset, parsed, uses)
			public := consensusPackage.Scope().Lookup("VerifyPersistedReplayStartupMDBX")
			nativeMethod := types.NewMethodSet(types.NewPointer(native.Scope().Lookup("Store").Type())).Lookup(native, "StartupVerifyCanonicalV1").Obj()
			logicalMDBXAssert(t, public != nil, "startup consumer census unresolved producer")
			for _, file := range parsed {
				ast.Inspect(file, func(node ast.Node) bool {
					id, ok := node.(*ast.Ident)
					if !ok {
						return true
					}
					if uses.Uses[id] == public {
						t.Fatalf("startup lost dormancy: node/cmd public consumer at %s", fset.Position(id.Pos()))
					}
					logicalMDBXAssert(t, uses.Uses[id] != nativeMethod && uses.Uses[id] != native.Scope().Lookup("StartupCanonicalActiveAndReplayCompleteV1"), "unapproved external startup owner at %s", fset.Position(id.Pos()))
					if id.Name == "VerifyPersistedReplayStartupMDBX" || id.Name == "StartupVerifyCanonicalV1" || id.Name == "StartupCanonicalActiveAndReplayCompleteV1" {
						logicalMDBXAssert(t, uses.Defs[id] != nil || uses.Uses[id] != nil, "startup census resolved no uses: external %s at %s", id.Name, fset.Position(id.Pos()))
					}
					return true
				})
			}
		}
	}
}

// The exact declarations supply object identity despite the existing deliberate
// incomplete-import checker. They are type evidence only, never an executable seam.
func startupCensusNative(t *testing.T) *types.Package {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "native-startup-type-evidence.go", `package mdbx
type Reader struct{}
type Store struct{}
type OperationReservationOwner struct{}
type StartupCanonicalCompletionV1 uint8
const StartupCanonicalNotCompleteV1 StartupCanonicalCompletionV1 = 0
const StartupCanonicalActiveAndReplayCompleteV1 StartupCanonicalCompletionV1 = 1
func (*Store) StartupVerifyCanonicalV1(func(*Reader) (StartupCanonicalCompletionV1,error)) error { return nil }
`, 0)
	logicalMDBXAssert(t, err == nil, "startup type evidence: %v", err)
	pkg, err := (&types.Config{}).Check("github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx", fset, []*ast.File{file}, nil)
	logicalMDBXAssert(t, err == nil, "startup type evidence check: %v", err)
	return pkg
}

func startupCensusUses(t *testing.T, fset *token.FileSet, files []*ast.File, info *types.Info, parents map[ast.Node]ast.Node, native *types.Package) {
	t.Helper()
	storeType := native.Scope().Lookup("Store").Type()
	nativeMethod := types.NewMethodSet(types.NewPointer(storeType)).Lookup(native, "StartupVerifyCanonicalV1").Obj()
	completionType := native.Scope().Lookup("StartupCanonicalCompletionV1").Type()
	completion := native.Scope().Lookup("StartupCanonicalActiveAndReplayCompleteV1")
	var verify, public types.Object
	var finalVerifyReturn *ast.ReturnStmt
	for _, file := range files {
		if !strings.HasSuffix(fset.Position(file.Pos()).Filename, "startup_mdbx_cgo.go") {
			continue
		}
		for _, declaration := range file.Decls {
			if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Name.Name == "verify" && len(fn.Body.List) != 0 {
				finalVerifyReturn, _ = fn.Body.List[len(fn.Body.List)-1].(*ast.ReturnStmt)
			}
		}
	}
	for id, object := range info.Defs {
		if !strings.HasSuffix(fset.Position(id.Pos()).Filename, "startup_mdbx_cgo.go") {
			continue
		}
		if id.Name == "verify" {
			verify = object
		}
		if id.Name == "VerifyPersistedReplayStartupMDBX" {
			public = object
		}
	}
	logicalMDBXAssert(t, verify != nil && public != nil && finalVerifyReturn != nil, "startup census resolved no uses: producer definitions")
	owner := func(node ast.Node) string {
		for node = parents[node]; node != nil; node = parents[node] {
			if fn, ok := node.(*ast.FuncDecl); ok {
				return fn.Name.Name
			}
		}
		return ""
	}
	uses, producers := 0, 0
	for id, object := range info.Uses {
		if object == public {
			t.Fatalf("startup lost dormancy: public consumer at %s", fset.Position(id.Pos()))
		}
		if object == nativeMethod {
			selector, selected := parents[id].(*ast.SelectorExpr)
			call, direct := parents[selector].(*ast.CallExpr)
			logicalMDBXAssert(t, selected && direct && call.Fun == selector && len(call.Args) == 1 && owner(id) == "VerifyPersistedReplayStartupMDBX", "unapproved startup caller at %s", fset.Position(id.Pos()))
			callback, ok := call.Args[0].(*ast.SelectorExpr)
			logicalMDBXAssert(t, ok && info.Uses[callback.Sel] == verify, "unapproved startup checker at %s", fset.Position(id.Pos()))
			uses++
		}
		if object == completion {
			producers++
		}
	}
	logicalMDBXAssert(t, uses == 1 && producers == 1, "startup census resolved no uses: callers%d/completion%d", uses, producers)
	for _, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			if id, ok := node.(*ast.Ident); ok && (id.Name == "StartupVerifyCanonicalV1" || id.Name == "StartupCanonicalActiveAndReplayCompleteV1" || id.Name == "VerifyPersistedReplayStartupMDBX") && info.Defs[id] == nil {
				logicalMDBXAssert(t, info.Uses[id] != nil, "startup census resolved no uses: %s at %s", id.Name, fset.Position(id.Pos()))
			}
			if expr, ok := node.(ast.Expr); ok {
				value := info.Types[expr]
				// A helper/conversion with a nonconstant typed outcome must not
				// bypass the sole final producer by hiding its numeric literal.
				if value.IsValue() && types.Identical(value.Type, completionType) && (value.Value == nil || value.Value.ExactString() != "0") {
					ret, returning := parents[expr].(*ast.ReturnStmt)
					logicalMDBXAssert(t, returning && ret == finalVerifyReturn && len(ret.Results) == 2 && ret.Results[0] == expr && owner(expr) == "verify", "unapproved completion producer at %s", fset.Position(expr.Pos()))
				}
			}
			return true
		})
	}
}

type logicalMDBXStubImporter struct{ native, consensus *types.Package }

func (i logicalMDBXStubImporter) Import(path string) (*types.Package, error) {
	if i.consensus != nil && path == "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus" {
		return i.consensus, nil
	}
	if i.native != nil && path == i.native.Path() {
		return i.native, nil
	}
	pkg := types.NewPackage(path, path[strings.LastIndex(path, "/")+1:])
	pkg.MarkComplete()
	return pkg, nil
}

const genesisMDBXPublishedHex = "0100000000000000000000000000000000000000000000000000000000000000000000006f732e615e2f43337a53e9884adba7da32257d5bb5701adc7ed0bd406f2df91340e49e6900000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000101000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0200407a10f35a0000000021018448b91b88d1a6fbb65e872b72c381b2a9f3ce286a232f56309667f639dd72790000000000000000020020b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34cf37071a8000000000000"

func genesisMDBXHex(text string) []byte { return logicalMDBXMust(hex.DecodeString(text)) }

func genesisMDBXFixture() ([]byte, [32]byte, [32]byte) {
	return genesisMDBXHex(genesisMDBXPublishedHex), [32]byte(genesisMDBXHex("88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103")), [32]byte(genesisMDBXHex("8d48b863805b96e5fcb79ee9652cd6257ae352b2f52088af921212039f9e8aff"))
}

func genesisMDBXBoot(t *testing.T, profile mdbx.StorageProfileV1) (*mdbx.Store, *mdbx.OperationReservationOwner, func() *mdbx.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db")
	cfg := mdbx.ConfigV1{Lower: 1 << 20, Now: 2 << 20, Upper: 256 << 20, Growth: 1 << 20, Shrink: 2 << 20, PageSize: 4096, MaxReaders: 492}
	store, err := mdbx.Create(path, cfg)
	logicalMDBXAssert(t, err == nil, "genesis store: %v", err)
	t.Cleanup(func() { _ = store.Close() })
	owner, err := mdbx.NewOperationReservationOwner(154_611_151)
	logicalMDBXAssert(t, err == nil, "genesis owner: %v", err)
	truth, stage, err := store.BootstrapStorageV1(profile, owner)
	logicalMDBXAssert(t, err == nil && truth == 2 && stage == 3, "genesis bootstrap: %v/%v/%v", truth, stage, err)
	return store, owner, func() *mdbx.Store {
		logicalMDBXAssert(t, store.Close() == nil, "genesis close")
		store, err = mdbx.Open(path, cfg)
		logicalMDBXAssert(t, err == nil, "genesis reopen: %v", err)
		return store
	}
}

func genesisMDBXRun(store *mdbx.Store, owner *mdbx.OperationReservationOwner) GenesisMDBXOutcome {
	block, chain, hash := genesisMDBXFixture()
	return ConnectPublishedGenesisMDBX(store, owner, block, block, chain, hash)
}

func genesisMDBXReturned(t testing.TB, out GenesisMDBXOutcome, result string, truth, stage uint8, label string) {
	t.Helper()
	logicalMDBXAssert(t, out.Result == result && uint8(out.Truth) == truth && uint8(out.Stage) == stage, "%s: %+v", label, out)
	if result == "ACCEPTED" {
		logicalMDBXAssert(t, out.Err == nil && out.State != nil && out.Summary != nil, "%s: missing validated payload: %+v", label, out)
	} else {
		logicalMDBXAssert(t, out.Err != nil && out.State == nil && out.Summary == nil, "%s: refusal payload: %+v", label, out)
	}
}

// Each snapshot owns independent bytes of the complete active image, including undo and staged rows.
func genesisMDBXSnapshot(t *testing.T, store *mdbx.Store, g uint64) (rows []mdbx.PrefixRow) {
	t.Helper()
	_, _, hash := genesisMDBXFixture()
	err := store.View(func(reader *mdbx.Reader) error {
		for _, item := range []struct {
			rank uint8
			key  []byte
		}{{0, []byte{0}}, {0, []byte{1}}, {0, []byte{2}}, {0, binary.BigEndian.AppendUint64([]byte{0x10}, g)}, {3, hash[:]}, {4, hash[:]}} {
			value, present, err := reader.Get(logicalMDBXDBIs[item.rank], item.key)
			if err != nil {
				return err
			}
			if present {
				rows = append(rows, mdbx.PrefixRow{Key: append([]byte{item.rank}, item.key...), Value: value})
			}
		}
		for _, rank := range []uint8{1, 2, 5, 6} {
			prefix := binary.BigEndian.AppendUint64(nil, g)
			if rank == 5 {
				prefix = hash[:]
			}
			page, err := reader.PrefixPage(logicalMDBXDBIs[rank], prefix, nil, 1440, 154_611_151)
			if err != nil {
				return err
			}
			logicalMDBXAssert(t, page.Stop == 1, "genesis snapshot incomplete: %d", page.Stop)
			for _, row := range page.Rows {
				rows = append(rows, mdbx.PrefixRow{Key: append([]byte{rank}, row.Key...), Value: row.Value})
			}
		}
		return nil
	})
	logicalMDBXAssert(t, err == nil, "genesis snapshot: %v", err)
	return rows
}

func genesisMDBXExpected(t *testing.T, store *mdbx.Store, g uint64, authority []byte, label string) {
	t.Helper()
	block, _, hash := genesisMDBXFixture()
	key := binary.BigEndian.AppendUint64(nil, g)
	utxoKey := append(append(bytes.Clone(key), genesisMDBXHex("f726016007c9e0c47c2ed35f66dcace4e5a2b6fd39a97bec14e8e1967850854f")...), 0, 0, 0, 0)
	utxo := genesisMDBXHex("00407a10f35a0000000021018448b91b88d1a6fbb65e872b72c381b2a9f3ce286a232f56309667f639dd7279000000000000000001")
	index := append(hash[:32:32], make([]byte, 72)...)
	index[103] = 1
	manifest := make([]byte, 33)
	manifest[0], manifest[28] = 1, 1
	rows := genesisMDBXSnapshot(t, store, g)
	logicalMDBXAssert(t, len(rows) == 9, "%s: got %d finite rows", label, len(rows))
	logicalMDBXWantImage(t, store, [3][]byte{{0}, {2}, authority}, [3][]byte{{0}, append([]byte{0x10}, key...), genesisMDBXHex("00000000000000590000000000000001")}, [3][]byte{{1}, utxoKey, utxo}, [3][]byte{{2}, append(bytes.Clone(key), make([]byte, 8)...), index}, [3][]byte{{3}, hash[:], block[:116]}, [3][]byte{{4}, hash[:], block}, [3][]byte{{5}, append(hash[:32:32], 0), manifest})
	// The genesis owner row: BE64(g) || genesis hash holding height zero.
	logicalMDBXWantImage(t, store, [3][]byte{{7}, append(bytes.Clone(key), hash[:]...), make([]byte, 8)})
}

func genesisMDBXReadmission(t *testing.T, owner *mdbx.OperationReservationOwner) {
	t.Helper()
	entered := false
	err := owner.WithReservation(154_611_151, func() error { entered = true; return nil })
	logicalMDBXAssert(t, entered && err == nil, "genesis reservation boundary drifted: released=%v err=%v", entered, err)
}

func TestGenesisMDBX(t *testing.T) {
	for _, profile := range []mdbx.StorageProfileV1{1, 2} {
		name := map[mdbx.StorageProfileV1]string{1: "fresh_pruned", 2: "fresh_archive"}[profile]
		t.Run(name, func(t *testing.T) {
			store, owner, _ := genesisMDBXBoot(t, profile)
			out := genesisMDBXRun(store, owner)
			genesisMDBXReturned(t, out, "ACCEPTED", 2, 3, "genesis complete image drifted")
			authority := logicalMDBXAuthorityLiteral()
			authority[1] = byte(profile)
			genesisMDBXExpected(t, store, 1, authority, "genesis complete image drifted")
			logicalMDBXAssert(t, len(out.State.Utxos) == 1 && out.State.AlreadyGenerated.Sign() == 0 && out.Summary.UtxoCount == 1 && out.Summary.AlreadyGenerated == (Uint128{}) && out.Summary.AlreadyGeneratedN1 == (Uint128{}), "genesis complete image drifted: %+v", out.Summary)
			genesisMDBXReadmission(t, owner)
		})
	}
	t.Run("context", genesisMDBXTestContext)
	t.Run("identity", genesisMDBXTestIdentity)
	t.Run("validation_context", func(t *testing.T) {
		store, owner, _ := genesisMDBXBoot(t, 1)
		out := genesisMDBXRun(store, owner)
		genesisMDBXReturned(t, out, "ACCEPTED", 2, 3, "genesis validation context drifted")
		logicalMDBXAssert(t, out.Summary.SumFees == (Uint128{}) && out.Summary.SigTaskCount == 0 && out.Summary.WorkerPanics == 0 && out.State.AlreadyGenerated.Sign() == 0 && len(out.State.Utxos) == 1, "genesis validation context drifted: %+v", out.Summary)
	})
	t.Run("prestate", genesisMDBXTestPrestate)
	t.Run("nondefault", genesisMDBXTestNondefault)
	t.Run("reuse_mask", genesisMDBXTestReuse)
	t.Run("artifact_order", genesisMDBXTestArtifacts)
	t.Run("budget", genesisMDBXTestBudget)
	t.Run("image_payload", genesisMDBXTestProjection)
	t.Run("reopen", func(t *testing.T) {
		for _, reuse := range []bool{false, true} {
			store, owner, reopen := genesisMDBXBoot(t, 1)
			if reuse {
				logicalMDBXSeed(t, store, genesisMDBXTestArtifactsRows()...)
			}
			genesisMDBXReturned(t, genesisMDBXRun(store, owner), "ACCEPTED", 2, 3, "genesis reopen image drifted")
			old := genesisMDBXSnapshot(t, store, 1)
			store = reopen()
			genesisMDBXExpected(t, store, 1, logicalMDBXAuthorityLiteral(), "genesis reopen image drifted")
			genesisMDBXReturned(t, genesisMDBXRun(store, owner), "STALE_LOCAL_PLAN", 1, 1, "genesis reopen image drifted")
			logicalMDBXAssert(t, reflect.DeepEqual(old, genesisMDBXSnapshot(t, store, 1)), "genesis reopen image drifted: second call changed OLD")
			genesisMDBXReadmission(t, owner)
		}
	})
	t.Run("isolation", func(t *testing.T) {
		store, owner, reopen := genesisMDBXBoot(t, 1)
		block, chain, hash := genesisMDBXFixture()
		published := bytes.Clone(block)
		out := ConnectPublishedGenesisMDBX(store, owner, block, published, chain, hash)
		genesisMDBXReturned(t, out, "ACCEPTED", 2, 3, "genesis output alias drifted")
		logicalMDBXFlip(block, published)
		for _, entry := range out.State.Utxos {
			logicalMDBXAssert(t, bytes.Equal(entry.CovenantData, genesisMDBXHex("018448b91b88d1a6fbb65e872b72c381b2a9f3ce286a232f56309667f639dd7279")), "genesis output alias drifted")
			logicalMDBXFlip(entry.CovenantData)
		}
		genesisMDBXExpected(t, reopen(), 1, logicalMDBXAuthorityLiteral(), "genesis output alias drifted")
	})
	t.Run("cached_terminal", genesisMDBXTestCached)
}

func genesisMDBXTestContext(t *testing.T) {
	block, chain, hash := genesisMDBXFixture()
	wrongChain, wrongHash := chain, hash
	wrongChain[0], wrongHash[0] = wrongChain[0]^1, wrongHash[0]^1
	for _, row := range []struct {
		name        string
		published   []byte
		chain, hash [32]byte
	}{
		{"chain-zero", block, [32]byte{}, hash},
		{"chain-wrong", block, wrongChain, hash},
		{"hash-zero", block, chain, [32]byte{}},
		{"hash-wrong", block, chain, wrongHash},
		{"length-short", block[:265], chain, hash},
		{"length-long", append(bytes.Clone(block), 0), chain, hash},
	} {
		t.Run(row.name, func(t *testing.T) {
			store, owner, _ := genesisMDBXBoot(t, 1)
			old := genesisMDBXSnapshot(t, store, 1)
			out := ConnectPublishedGenesisMDBX(store, owner, block, row.published, row.chain, row.hash)
			genesisMDBXReturned(t, out, "TERMINAL_LOCAL_INVARIANT(evidence)", 1, 1, "genesis context binding drifted")
			logicalMDBXAssert(t, reflect.DeepEqual(old, genesisMDBXSnapshot(t, store, 1)), "genesis context binding drifted: OLD changed")
			genesisMDBXReadmission(t, owner)
		})
	}
}

func genesisMDBXTestIdentity(t *testing.T) {
	block, chain, hash := genesisMDBXFixture()
	changed, nonGenesis := bytes.Clone(block), bytes.Clone(block)
	changed[190] ^= 1
	nonGenesis[4] = 1
	for i, candidate := range [][]byte{nil, {}, block[:116], block[:265], append(bytes.Clone(block), 0), changed, nonGenesis} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			store, owner, _ := genesisMDBXBoot(t, 1)
			old := genesisMDBXSnapshot(t, store, 1)
			out := ConnectPublishedGenesisMDBX(store, owner, candidate, block, chain, hash)
			genesisMDBXReturned(t, out, "CONSENSUS_INVALID", 1, 1, "genesis identity refusal drifted")
			e, ok := out.Err.(*TxError) //nolint:errorlint // Identity refusal must retain the direct consensus error.
			logicalMDBXAssert(t, ok && e.Code == "BLOCK_ERR_LINKAGE_INVALID" && e.Error() == "BLOCK_ERR_LINKAGE_INVALID: block does not match published genesis", "genesis identity refusal drifted: %v", out.Err)
			logicalMDBXAssert(t, reflect.DeepEqual(old, genesisMDBXSnapshot(t, store, 1)), "genesis identity refusal drifted: OLD changed")
			genesisMDBXReadmission(t, owner)
		})
	}
}

func genesisMDBXTestPrestate(t *testing.T) {
	for _, variant := range []string{"authority-absent", "phase", "canonical-zero", "canonical-one", "counter-absent", "counter-bytes", "counter-entries", "ghost-utxo"} {
		t.Run(variant, func(t *testing.T) {
			store, owner, _ := genesisMDBXBoot(t, 1)
			_, _, hash := genesisMDBXFixture()
			row := mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterAbsent}
			result := "TERMINAL_STORE_INTEGRITY(canonical)"
			var pair []mdbx.Mutation
			switch variant {
			case "authority-absent":
				store, row = logicalMDBXStore(t), mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1}, AfterKind: mdbx.AfterLiteral, Literal: make([]byte, 16)}
			case "phase":
				a := mdbx.StorageAuthorityV1{Version: 1, ActiveProfile: 1, ActiveGenerationID: 1, NextGenerationID: 3, Phase: 2, Lifecycle: 1, Cleanup: &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: 2}}}}
				row.AfterKind, row.Literal, result = mdbx.AfterLiteral, logicalMDBXMust(a.Encode()), "STALE_LOCAL_PLAN"
			case "canonical-zero", "canonical-one":
				height := uint64(0)
				if variant == "canonical-one" {
					height = 1
				}
				row = mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(1, height)), AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(hash, [32]byte{}, [40]byte{39: 1})}
				pair = []mdbx.Mutation{{DBI: logicalMDBXDBIs[7], Key: append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, hash[:]...), AfterKind: mdbx.AfterLiteral, Literal: binary.BigEndian.AppendUint64(nil, height)}}
				result = "STALE_LOCAL_PLAN"
			case "counter-absent", "counter-bytes", "counter-entries":
				row.Key = []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1}
				if variant != "counter-absent" {
					row.AfterKind, row.Literal = mdbx.AfterLiteral, make([]byte, 16)
					if variant == "counter-bytes" {
						row.Literal[7] = 1
					} else {
						row.Literal[15] = 1
					}
				}
			case "ghost-utxo":
				row = mdbx.Mutation{DBI: logicalMDBXDBIs[1], Key: logicalMDBXMust(mdbx.UTXOKey(1, [32]byte{1}, 2)), AfterKind: mdbx.AfterLiteral, Literal: logicalMDBXValue(UtxoEntry{Value: 1})}
			}
			logicalMDBXSeed(t, store, append(pair, row)...)
			old := genesisMDBXSnapshot(t, store, 1)
			genesisMDBXReturned(t, genesisMDBXRun(store, owner), result, 1, 1, "genesis prestate admission drifted")
			logicalMDBXAssert(t, reflect.DeepEqual(old, genesisMDBXSnapshot(t, store, 1)), "genesis prestate admission drifted: OLD changed")
			genesisMDBXReadmission(t, owner)
		})
	}
}

func genesisMDBXNondefault(t *testing.T, store *mdbx.Store, profile mdbx.StorageProfileV1, options bool) []byte {
	t.Helper()
	a := mdbx.StorageAuthorityV1{Version: 1, ActiveProfile: profile, ActiveGenerationID: 7, NextGenerationID: 9, Phase: 1, Lifecycle: 1}
	if options {
		a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 1, FirstInvalidBlockHash: [32]byte{2}, ExactConsensusError: []byte("BLOCK_ERR_PARSE")}
		a.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 8, F: 0, TipHeight: 1, TipHash: [32]byte{3}, CumulativeChainwork: [40]byte{39: 1}, RowCount: 1, LogicalBytes: 1}
	}
	authority := logicalMDBXMust(a.Encode())
	logicalMDBXSeed(t, store, mdbx.Mutation{DBI: logicalMDBXDBIs[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: authority}, logicalMDBXCounterRow(false, 0, 0), mdbx.Mutation{DBI: logicalMDBXDBIs[2], Key: logicalMDBXMust(mdbx.HeightKey(6, 3)), AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue([32]byte{3}, [32]byte{2}, [40]byte{39: 4})},
		mdbx.Mutation{DBI: logicalMDBXDBIs[7], Key: append([]byte{0, 0, 0, 0, 0, 0, 0, 6, 3}, make([]byte, 31)...), AfterKind: mdbx.AfterLiteral, Literal: []byte{0, 0, 0, 0, 0, 0, 0, 3}})
	return authority
}

func genesisMDBXTestNondefault(t *testing.T) {
	for _, profile := range []mdbx.StorageProfileV1{1, 2} {
		for _, options := range []bool{false, true} {
			store, owner, reopen := genesisMDBXBoot(t, profile)
			authority := genesisMDBXNondefault(t, store, profile, options)
			other := genesisMDBXSnapshot(t, store, 6)
			genesisMDBXReturned(t, genesisMDBXRun(store, owner), "ACCEPTED", 2, 3, "genesis preserved authority drifted")
			genesisMDBXExpected(t, store, 7, authority, "genesis preserved authority drifted")
			logicalMDBXWantImage(t, store, [3][]byte{{0}, {0x10, 0, 0, 0, 0, 0, 0, 0, 1}, make([]byte, 16)}, [3][]byte{{2}, other[len(other)-1].Key[1:], other[len(other)-1].Value})
			genesisMDBXExpected(t, reopen(), 7, authority, "genesis preserved authority drifted")
		}
	}
}

func genesisMDBXTestArtifactsRows() []mdbx.Mutation {
	block, _, hash := genesisMDBXFixture()
	manifest := make([]byte, 33)
	manifest[0], manifest[28] = 1, 1
	return []mdbx.Mutation{{DBI: logicalMDBXDBIs[3], Key: hash[:], AfterKind: mdbx.AfterLiteral, Literal: block[:116]}, {DBI: logicalMDBXDBIs[4], Key: hash[:], AfterKind: mdbx.AfterLiteral, Literal: block}, {DBI: logicalMDBXDBIs[5], Key: append(hash[:32:32], 0), AfterKind: mdbx.AfterLiteral, Literal: manifest}}
}

func genesisMDBXTestReuse(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			store, owner, _ := genesisMDBXBoot(t, 1)
			var seeds []mdbx.Mutation
			for i, row := range genesisMDBXTestArtifactsRows() {
				if mask&(1<<i) != 0 {
					seeds = append(seeds, row)
				}
			}
			if len(seeds) != 0 {
				logicalMDBXSeed(t, store, seeds...)
			}
			block, chain, hash := genesisMDBXFixture()
			var out GenesisMDBXOutcome
			old, inspected := genesisMDBXSnapshot(t, store, 1), errors.New("genesis Batch inspected")
			truth, stage, err := store.Update(func(reader *mdbx.Reader) (mdbx.Batch, error) {
				batch, err := genesisMDBXBatch(reader, block, chain, hash, &out)
				logicalMDBXAssert(t, err == nil && len(batch.Consulted) == 3+len(seeds) && len(batch.Mutations) == 7-len(seeds), "genesis consulted image incomplete: %+v/%v", batch, err)
				seen := make(map[string]bool)
				for _, row := range batch.Mutations {
					id := fmt.Sprintf("%d/%x", row.DBI.Rank, row.Key)
					logicalMDBXAssert(t, !seen[id], "genesis consulted image incomplete: duplicate mutation")
					seen[id] = true
				}
				for i, row := range batch.Consulted {
					id := fmt.Sprintf("%d/%x", row.DBI.Rank, row.Key)
					logicalMDBXAssert(t, !seen[id] && (i == 0 || batch.Consulted[i-1].DBI.Rank < row.DBI.Rank || batch.Consulted[i-1].DBI == row.DBI && bytes.Compare(batch.Consulted[i-1].Key, row.Key) < 0), "genesis consulted image incomplete: duplicate/unordered consulted")
					seen[id] = true
				}
				logicalMDBXAssert(t, len(seen) == 10, "genesis consulted image incomplete: union=%d", len(seen))
				return mdbx.Batch{}, inspected
			})
			logicalMDBXAssert(t, truth == 1 && stage == 1 && err == inspected && reflect.DeepEqual(old, genesisMDBXSnapshot(t, store, 1)), "genesis consulted image incomplete: inspection changed OLD") //nolint:errorlint // Preserve the exact callback sentinel.
			genesisMDBXReturned(t, genesisMDBXRun(store, owner), "ACCEPTED", 2, 3, "genesis consulted image incomplete")
			genesisMDBXExpected(t, store, 1, logicalMDBXAuthorityLiteral(), "genesis consulted image incomplete")
			genesisMDBXReadmission(t, owner)
		})
	}
}

func genesisMDBXTestArtifacts(t *testing.T) {
	for name, length := range map[string]int{"116": 116, "265": 265, "266": 266, "267": 267, "68000125": 68_000_125, "manifest": 33} {
		t.Run(name, func(t *testing.T) {
			store, owner, _ := genesisMDBXBoot(t, 1)
			rows := genesisMDBXTestArtifactsRows()
			artifact := "undo-v1"
			rows[2].Literal[28] = 2
			if name != "manifest" {
				bad := make([]byte, length)
				copy(bad, rows[1].Literal)
				if length == 266 {
					bad[190] ^= 1
				}
				rows[1].Literal, artifact = bad, "blocks-v1"
			}
			logicalMDBXSeed(t, store, rows...)
			old := genesisMDBXSnapshot(t, store, 1)
			out := genesisMDBXRun(store, owner)
			genesisMDBXReturned(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", 1, 1, "genesis first artifact drifted")
			logicalMDBXAssert(t, out.Err.Error() == "genesis "+artifact+" differs from published artifact", "genesis first artifact drifted: %v", out.Err)
			logicalMDBXAssert(t, reflect.DeepEqual(old, genesisMDBXSnapshot(t, store, 1)), "genesis first artifact drifted: OLD changed")
			genesisMDBXReadmission(t, owner)
		})
	}
}

func genesisMDBXTestBudget(t *testing.T) {
	for _, outer := range []uint64{86_540_275, 86_540_276, 85_611_151} {
		for _, options := range []bool{false, true} {
			store, owner, _ := genesisMDBXBoot(t, 1)
			g := uint64(1)
			if options {
				genesisMDBXNondefault(t, store, 1, true)
				g = 7
			}
			old := genesisMDBXSnapshot(t, store, g)
			err := owner.WithReservation(outer, func() error {
				out := genesisMDBXRun(store, owner)
				if outer == 86_540_276 {
					genesisMDBXReturned(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", 1, 1, "genesis reservation boundary drifted")
					logicalMDBXAssert(t, reflect.DeepEqual(old, genesisMDBXSnapshot(t, store, g)), "genesis reservation boundary drifted: OLD changed")
				} else {
					genesisMDBXReturned(t, out, "ACCEPTED", 2, 3, "genesis reservation boundary drifted")
				}
				return nil
			})
			logicalMDBXAssert(t, err == nil, "genesis reservation boundary drifted: %v", err)
			genesisMDBXReadmission(t, owner)
		}
	}
	store, _, _ := genesisMDBXBoot(t, 1)
	for _, owner := range []*mdbx.OperationReservationOwner{nil, {}} {
		old := genesisMDBXSnapshot(t, store, 1)
		genesisMDBXReturned(t, genesisMDBXRun(store, owner), "TERMINAL_LOCAL_INVARIANT(evidence)", 1, 1, "genesis reservation boundary drifted")
		logicalMDBXAssert(t, reflect.DeepEqual(old, genesisMDBXSnapshot(t, store, 1)), "genesis reservation boundary drifted: OLD changed")
	}
	block, chain, hash := genesisMDBXFixture()
	genesisMDBXReturned(t, ConnectPublishedGenesisMDBX(nil, nil, nil, nil, chain, hash), "TERMINAL_LOCAL_INVARIANT(evidence)", 1, 1, "genesis reservation boundary drifted")
	// Identity wins over owner validity and context shape wins over identity.
	genesisMDBXReturned(t, ConnectPublishedGenesisMDBX(store, nil, nil, block, chain, hash), "CONSENSUS_INVALID", 1, 1, "genesis reservation boundary drifted")
	genesisMDBXReturned(t, ConnectPublishedGenesisMDBX(store, nil, nil, block, [32]byte{}, hash), "TERMINAL_LOCAL_INVARIANT(evidence)", 1, 1, "genesis reservation boundary drifted")
}

func genesisMDBXTestProjection(t *testing.T) {
	store, owner, _ := genesisMDBXBoot(t, 1)
	validated := genesisMDBXRun(store, owner)
	genesisMDBXReturned(t, validated, "ACCEPTED", 2, 3, "genesis image handoff drifted")
	engine := func(class string) *mdbx.EngineError {
		return &mdbx.EngineError{Class: mdbx.EngineClass(class), Operation: "update", Code: 28, Diagnostic: "pinned input"}
	}
	capacity, invariant, integrity := engine("Capacity"), engine("LocalInvariant"), engine("Integrity")
	committed := &mdbx.CommitError{Truth: 1, Cause: capacity}
	invalid := txerr(BLOCK_ERR_LINKAGE_INVALID, "block does not match published genesis")
	check := func(raw GenesisMDBXOutcome, entered, complete bool, result, label string, payload bool) {
		t.Helper()
		out := genesisMDBXProject(raw, entered, complete)
		logicalMDBXAssert(t, out.Result == result && out.Truth == raw.Truth && out.Stage == raw.Stage && out.Err == raw.Err, "%s: got %+v raw %+v", label, out, raw) //nolint:errorlint // Projection must preserve the raw error object.
		logicalMDBXAssert(t, payload && out.State == validated.State && out.Summary == validated.Summary || !payload && out.State == nil && out.Summary == nil, "genesis image handoff drifted: %+v", out)
	}
	for _, class := range []string{"Capacity", "Concurrency", "Transaction", "IO"} {
		err := engine(class)
		suffix := map[string]string{"Capacity": "storage_capacity", "Concurrency": "storage_concurrency", "Transaction": "storage_transaction", "IO": "storage_io"}[class]
		for _, row := range []struct {
			stage  mdbx.UpdateStage
			result string
		}{{1, "LOCAL_RESOURCE_UNAVAILABLE(" + suffix + ")"}, {2, "LOCAL_PERSISTENCE_ERROR(precommit)"}, {3, "TERMINAL_PERSISTENCE(old)"}} {
			raw := GenesisMDBXOutcome{Truth: 1, Stage: row.stage, Err: err, State: validated.State, Summary: validated.Summary}
			check(raw, true, true, row.result, "genesis stage mapping drifted", false)
			if class == "Capacity" {
				check(GenesisMDBXOutcome{Truth: 1, Stage: row.stage, Err: committed, State: validated.State, Summary: validated.Summary}, true, true, row.result, "genesis stage mapping drifted", false)
			}
		}
		kind := logicalStateCountersUnavailable
		if class == "Transaction" {
			kind = logicalStateCountersLocalInvariant
		}
		observed := genesisMDBXZeroCounter(logicalStateCounterRead{kind: kind, cause: err})
		logicalMDBXAssert(t, observed == err, "genesis image handoff drifted: counter cause identity") //nolint:errorlint // The counter must retain the original required-read error.
		check(GenesisMDBXOutcome{Truth: 1, Stage: 1, Err: observed, Result: "LOCAL_RESOURCE_UNAVAILABLE(state_view_read)"}, true, false, "LOCAL_RESOURCE_UNAVAILABLE(state_view_read)", "genesis image handoff drifted", false)
		for _, step := range []string{"state_view_read", "canonical_artifact_read"} {
			result := "LOCAL_RESOURCE_UNAVAILABLE(" + step + ")"
			check(GenesisMDBXOutcome{Truth: 1, Stage: 1, Err: err, Result: result}, true, false, result, "genesis image handoff drifted", false)
		}
	}
	for _, class := range []string{"Integrity", "StateMismatch", "InvalidInput", "LocalInvariant"} {
		result := "TERMINAL_LOCAL_INVARIANT(evidence)"
		if class == "Integrity" {
			result = "TERMINAL_STORE_INTEGRITY(canonical)"
		}
		for _, stage := range []mdbx.UpdateStage{1, 2} {
			check(GenesisMDBXOutcome{Truth: 1, Stage: stage, Err: engine(class)}, true, true, result, "genesis stage mapping drifted", false)
		}
	}
	for _, read := range []logicalStateCounterRead{{kind: 0}, {kind: 5}, {kind: 1, cause: capacity}, {kind: 2}, {kind: 3}, {kind: 4}, {kind: 4, cause: (*mdbx.EngineError)(nil)}} {
		err := genesisMDBXZeroCounter(read)
		check(GenesisMDBXOutcome{Truth: 1, Stage: 1, Err: err, Result: "LOCAL_RESOURCE_UNAVAILABLE(state_view_read)"}, true, false, "TERMINAL_LOCAL_INVARIANT(evidence)", "genesis image handoff drifted", false)
	}
	for _, row := range []struct {
		truth   mdbx.CommitTruth
		err     error
		result  string
		payload bool
	}{
		{2, nil, "ACCEPTED", true},
		{1, capacity, "TERMINAL_PERSISTENCE(old)", false},
		{2, capacity, "TERMINAL_PERSISTENCE(new)", true},
		{3, capacity, "TERMINAL_PERSISTENCE(neither_or_unreadable)", false},
		{2, &mdbx.CommitError{Truth: 2, Cause: capacity, ReadbackCause: integrity}, "TERMINAL_PERSISTENCE(new)", true},
		{3, &mdbx.CommitError{Truth: 3, Cause: capacity, ReadbackCause: invariant}, "TERMINAL_PERSISTENCE(neither_or_unreadable)", false},
	} {
		check(GenesisMDBXOutcome{Truth: row.truth, Stage: 3, State: validated.State, Summary: validated.Summary, Err: row.err}, true, true, row.result, "genesis image handoff drifted", row.payload)
	}
	for _, row := range []struct {
		cause        error
		step, result string
	}{
		{engine("Transaction"), "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)", "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)"},
		{engine("Transaction"), "", "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{invariant, "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)", "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{invariant, "", "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{capacity, "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)", "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{capacity, "", "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{fmt.Errorf("outer: %w", engine("Transaction")), "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)", "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{fmt.Errorf("outer: %w", engine("Transaction")), "", "TERMINAL_LOCAL_INVARIANT(evidence)"},
	} {
		wrapped := &logicalStateFailure{kind: logicalStateFailureLocalInvariant, cause: row.cause}
		check(GenesisMDBXOutcome{Truth: 1, Stage: 1, Err: wrapped, Result: row.step}, true, false, row.result, "genesis bridge read cause drifted", false)
	}
	for _, row := range []struct {
		err    error
		result string
	}{
		{invalid, "CONSENSUS_INVALID"},
		{fmt.Errorf("outer: %w", invalid), "CONSENSUS_INVALID"},
		{errors.Join(invalid, capacity), "CONSENSUS_INVALID"},
		{errors.Join(invalid, integrity), "TERMINAL_STORE_INTEGRITY(canonical)"},
		{errors.Join(capacity, invariant), "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{errors.Join(integrity, invariant), "TERMINAL_STORE_INTEGRITY(canonical)"},
		{errors.Join(invariant, integrity), "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{fmt.Errorf("outer: %w", capacity), "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)"},
		{&mdbx.CommitError{Truth: 1, Cause: capacity, ReadbackCause: integrity}, "TERMINAL_STORE_INTEGRITY(canonical)"},
		{engine("InvalidInput"), "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{engine("StateMismatch"), "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{engine("unknown"), "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{(*mdbx.EngineError)(nil), "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{(*mdbx.CommitError)(nil), "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{(*logicalStateFailure)(nil), "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{(*TxError)(nil), "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{fmt.Errorf("outer: %w", (*mdbx.EngineError)(nil)), "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{&logicalStateFailure{kind: logicalStateFailureStoreIntegrity}, "TERMINAL_LOCAL_INVARIANT(evidence)"},
		{&logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: errors.New("schema")}, "TERMINAL_STORE_INTEGRITY(canonical)"},
		{&logicalStateFailure{kind: logicalStateFailureUnavailable, cause: capacity}, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)"},
	} {
		check(GenesisMDBXOutcome{Truth: 1, Stage: 1, Err: row.err}, true, false, row.result, "genesis image handoff drifted", false)
	}
	for _, row := range []struct {
		truth             mdbx.CommitTruth
		stage             mdbx.UpdateStage
		entered, complete bool
		state             *InMemoryChainState
		summary           *ConnectBlockBasicSummary
		err               error
	}{
		{0, 1, true, true, validated.State, validated.Summary, capacity},
		{4, 1, true, true, validated.State, validated.Summary, capacity},
		{1, 0, true, true, validated.State, validated.Summary, capacity},
		{1, 4, true, true, validated.State, validated.Summary, capacity},
		{2, 2, true, true, validated.State, validated.Summary, capacity},
		{2, 3, false, true, validated.State, validated.Summary, capacity},
		{2, 3, true, false, validated.State, validated.Summary, capacity},
		{2, 3, true, true, nil, validated.Summary, capacity},
		{2, 3, true, true, validated.State, nil, capacity},
		{2, 3, true, true, validated.State, validated.Summary, (*mdbx.EngineError)(nil)},
		{1, 1, true, false, nil, nil, nil},
		{2, 3, true, true, validated.State, validated.Summary, fmt.Errorf("outer: %w", (*mdbx.EngineError)(nil))},
		{2, 3, true, true, validated.State, validated.Summary, &mdbx.CommitError{Truth: 2}},
		{2, 1, false, false, nil, nil, nil},
		{3, 1, false, false, nil, nil, nil},
		{2, 1, false, false, nil, nil, (*mdbx.EngineError)(nil)},
	} {
		check(GenesisMDBXOutcome{Truth: row.truth, Stage: row.stage, State: row.state, Summary: row.summary, Err: row.err}, row.entered, row.complete, "TERMINAL_LOCAL_INVARIANT(evidence)", "genesis image handoff drifted", false)
	}
}

func genesisMDBXTestCached(t *testing.T) {
	for _, truth := range []mdbx.CommitTruth{1, 2, 3} {
		for _, commit := range []bool{false, true} {
			var err error = &mdbx.EngineError{Class: mdbx.EngineCapacity, Operation: "update", Code: 28, Diagnostic: "cached"}
			if commit {
				err = &mdbx.CommitError{Truth: truth, Cause: err}
			}
			raw := GenesisMDBXOutcome{Truth: truth, Stage: 1, Err: err, State: &InMemoryChainState{}, Summary: &ConnectBlockBasicSummary{}}
			out := genesisMDBXProject(raw, false, false)
			want := ""
			if truth == 1 {
				want = "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)"
			}
			logicalMDBXAssert(t, out.Result == want && out.Truth == truth && out.Stage == 1 && out.Err == err && out.State == nil && out.Summary == nil, "genesis cached attempt drifted: %+v", out) //nolint:errorlint // A cached attempt returns the same error object.
		}
	}
	store, owner, _ := genesisMDBXBoot(t, 1)
	logicalMDBXAssert(t, store.Close() == nil, "close cached store")
	first, second := genesisMDBXRun(store, owner), genesisMDBXRun(store, owner)
	logicalMDBXAssert(t, first.Truth == 1 && first.Stage == 1 && first.Result == "TERMINAL_LOCAL_INVARIANT(evidence)" && first.State == nil && first.Summary == nil && first.Err != nil && second.Truth == first.Truth && second.Stage == first.Stage && second.Result == first.Result, "genesis cached attempt drifted: %+v/%+v", first, second)
	genesisMDBXReadmission(t, owner)
}

func TestGenesisMDBXSourceOwnership(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "logical_state_mdbx_cgo.go", nil, 0)
	logicalMDBXAssert(t, err == nil, "genesis source parse: %v", err)
	var nativeFiles []*ast.File
	for _, name := range []string{"mdbx_cgo.go", "operation_reservation.go"} {
		parsed, parseErr := parser.ParseFile(fset, filepath.Join("../internal/mdbx", name), nil, 0)
		logicalMDBXAssert(t, parseErr == nil, "genesis native owner parse: %v", parseErr)
		nativeFiles = append(nativeFiles, parsed)
	}
	nativeConfig := &types.Config{IgnoreFuncBodies: true, FakeImportC: true, Error: func(error) {}, Importer: logicalMDBXStubImporter{}}
	native, _ := nativeConfig.Check("github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx", fset, nativeFiles, nil)
	protected := map[types.Object]string{}
	for owner, method := range map[string]string{"OperationReservationOwner": "WithReservation", "Store": "Update"} {
		object, _, _ := types.LookupFieldOrMethod(types.NewPointer(native.Scope().Lookup(owner).Type()), true, native, method)
		logicalMDBXAssert(t, object != nil, "genesis reservation ownership drifted: unresolved %s.%s", owner, method)
		protected[object] = method
	}
	files := []*ast.File{file}
	for _, name := range []string{"connect_block_inmem.go", "block_parse.go", "block_basic.go", "hash.go", "errors.go", "logical_state.go"} {
		parsed, parseErr := parser.ParseFile(fset, name, nil, 0)
		logicalMDBXAssert(t, parseErr == nil, "genesis production parse: %v", parseErr)
		files = append(files, parsed)
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}}
	config := &types.Config{FakeImportC: true, Error: func(error) {}, Importer: logicalMDBXStubImporter{native: native}}
	pkg, _ := config.Check("consensus", fset, files, info)
	dependencies := map[types.Object]string{}
	for name, owners := range map[string]string{"BlockHash": "ConnectPublishedGenesisMDBX", "sha3_256": "ConnectPublishedGenesisMDBX", "txerr": "genesisMDBXInput", "newLogicalMDBXStateView": "genesisMDBXBatch", "newLogicalMDBXMetadata": "genesisMDBXBatch", "logicalMDBXPlanToBatch": "genesisMDBXBatch", "logicalMDBXBefore": "genesisMDBXBatch", "buildLogicalStatePlan": "genesisMDBXBatch", "localLogicalStateFailure": "genesisMDBXZeroCounter genesisMDBXValidate", "ConnectBlockBasicInMemoryAtHeightAndSuiteContext": "genesisMDBXValidate", "ParseBlockBytes": "genesisMDBXValidate"} {
		object := pkg.Scope().Lookup(name)
		logicalMDBXAssert(t, object != nil, "genesis reservation ownership drifted: unresolved dependency %s", name)
		dependencies[object] = owners
	}
	counter, _, _ := types.LookupFieldOrMethod(types.NewPointer(pkg.Scope().Lookup("logicalMDBXStateView").Type()), true, pkg, "Counters")
	logicalMDBXAssert(t, counter != nil, "genesis reservation ownership drifted: unresolved Counters")
	dependencies[counter] = "genesisMDBXBatch"
	validatorObject := pkg.Scope().Lookup("ConnectBlockBasicInMemoryAtHeightAndSuiteContext")
	logicalMDBXAssert(t, validatorObject != nil && fset.Position(validatorObject.Pos()).Filename == "connect_block_inmem.go", "genesis full validator owner drifted: unresolved definition")
	text := func(n ast.Node) string {
		var b bytes.Buffer
		logicalMDBXAssert(t, format.Node(&b, fset, n) == nil, "genesis AST format")
		return b.String()
	}
	want := map[string][]string{
		"ConnectPublishedGenesisMDBX": {"genesisMDBXInput", "genesisMDBXBatch", "genesisMDBXProject"}, "genesisMDBXInput": nil,
		"genesisMDBXBatch": {"genesisMDBXPrestate", "genesisMDBXArtifacts", "genesisMDBXEmptyUTXO", "genesisMDBXZeroCounter", "genesisMDBXValidate"}, "genesisMDBXPrestate": {"genesisMDBXEligible", "genesisMDBXControl"},
		"genesisMDBXEligible": nil, "genesisMDBXControl": nil, "genesisMDBXArtifacts": nil, "genesisMDBXEmptyUTXO": nil, "genesisMDBXZeroCounter": nil, "genesisMDBXValidate": nil,
		"genesisMDBXProject": {"genesisMDBXTupleValid", "genesisMDBXCached", "genesisMDBXCrossed", "genesisMDBXUncrossed"}, "genesisMDBXCached": {"genesisMDBXNilError"}, "genesisMDBXTupleValid": {"genesisMDBXPlanValid"}, "genesisMDBXPlanValid": {"genesisMDBXNilError"}, "genesisMDBXCrossed": nil,
		"genesisMDBXUncrossed": {"genesisMDBXCauses", "genesisMDBXErrorResult"}, "genesisMDBXCauses": {"genesisMDBXCauses", "genesisMDBXCauses", "genesisMDBXCauses"}, "genesisMDBXNilError": {"genesisMDBXCauses", "genesisMDBXNilError"},
		"genesisMDBXErrorResult": {"genesisMDBXLogicalResult", "genesisMDBXEngineResult", "genesisMDBXUncrossed"}, "genesisMDBXLogicalResult": {"genesisMDBXUncrossed", "genesisMDBXNilError", "genesisMDBXBridgeReadResult"}, "genesisMDBXBridgeReadResult": nil, "genesisMDBXEngineResult": nil,
	}
	functions, objects, parents := map[string]*ast.FuncDecl{}, map[types.Object]string{}, map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if len(stack) != 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		if fn, ok := n.(*ast.FuncDecl); ok && (strings.HasPrefix(fn.Name.Name, "genesisMDBX") || fn.Name.Name == "ConnectPublishedGenesisMDBX") {
			functions[fn.Name.Name] = fn
			logicalMDBXAssert(t, info.Defs[fn.Name] != nil, "genesis call closure unresolved: %s", fn.Name.Name)
			objects[info.Defs[fn.Name]] = fn.Name.Name
		}
		return true
	})
	logicalMDBXAssert(t, len(functions) == len(want), "genesis call closure drifted: %d declarations", len(functions))
	for name := range want {
		logicalMDBXAssert(t, functions[name] != nil, "genesis call closure missing %s", name)
	}
	edges, covered := map[string][]string{}, map[*ast.Ident]bool{}
	var reservation, update, clone, validator *ast.CallExpr
	inside := func(n, owner ast.Node) bool {
		for n != nil {
			if n == owner {
				return true
			}
			n = parents[n]
		}
		return false
	}
	for name, fn := range functions {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			_, asynchronous := n.(*ast.GoStmt)
			logicalMDBXAssert(t, !asynchronous, "genesis reservation ownership drifted: asynchronous work")
			if id, ok := n.(*ast.Ident); ok && objects[info.Uses[id]] != "" {
				call, direct := parents[id].(*ast.CallExpr)
				logicalMDBXAssert(t, direct && call.Fun == id, "genesis call closure drifted: alias of %s", id.Name)
				edges[name] = append(edges[name], id.Name)
				covered[id] = true
			}
			if selector, ok := n.(*ast.SelectorExpr); ok {
				method := protected[info.Uses[selector.Sel]]
				if id, ok := selector.X.(*ast.Ident); ok {
					if imported, ok := info.Uses[id].(*types.PkgName); ok && imported.Imported().Path() == "bytes" && selector.Sel.Name == "Clone" {
						method = "Clone"
					}
				}
				if method != "" {
					call, direct := parents[selector].(*ast.CallExpr)
					logicalMDBXAssert(t, direct && call.Fun == selector, "genesis reservation ownership drifted: aliased %s", method)
					switch method {
					case "WithReservation":
						logicalMDBXAssert(t, reservation == nil && name == "ConnectPublishedGenesisMDBX" && text(call.Args[0]) == "genesisMDBXOperationBytes", "genesis reservation ownership drifted")
						reservation = call
					case "Update":
						logicalMDBXAssert(t, update == nil && name == "ConnectPublishedGenesisMDBX", "genesis reservation ownership drifted")
						update = call
					case "Clone":
						logicalMDBXAssert(t, clone == nil && name == "ConnectPublishedGenesisMDBX" && text(call.Args[0]) == "candidate", "genesis reservation ownership drifted")
						clone = call
					}
				}
				if object, ok := info.Uses[selector.Sel].(*types.Func); ok {
					logicalMDBXAssert(t, object.Pkg() != pkg || dependencies[object] == name || map[string]string{"genesisMDBXCauses": "e.Unwrap", "genesisMDBXNilError": "wrapped.Unwrap", "genesisMDBXErrorResult": "e.Unwrap"}[name] == text(selector), "genesis reservation ownership drifted: unowned method")
					logicalMDBXAssert(t, object.Pkg() != native || !slices.Contains([]string{"View", "Inspect", "Put", "Delete", "BootstrapStorageV1", "Lookup"}, selector.Sel.Name), "genesis call closure acquired another storage route")
				}
			}
			if call, ok := n.(*ast.CallExpr); ok {
				logicalMDBXAssert(t, slices.Contains([]reflect.Type{reflect.TypeFor[*ast.Ident](), reflect.TypeFor[*ast.SelectorExpr](), reflect.TypeFor[*ast.FuncLit]()}, reflect.TypeOf(ast.Unparen(call.Fun))), "genesis reservation ownership drifted: indirect call")
				if name == "genesisMDBXInput" {
					logicalMDBXAssert(t, slices.Contains([]string{"len", "bytes.Equal", "errors.New", "txerr"}, text(call.Fun)), "genesis reservation ownership drifted: allocating input owner")
				}
				if name == "ConnectPublishedGenesisMDBX" && text(call.Fun) != "genesisMDBXInput" && text(call.Fun) != "reservations.WithReservation" {
					logicalMDBXAssert(t, inside(call, reservation), "genesis reservation ownership drifted: entry work before acquisition")
				}
				if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
					object := info.Uses[id]
					_, builtin := object.(*types.Builtin)
					_, conversion := object.(*types.TypeName)
					logicalMDBXAssert(t, builtin || conversion || objects[object] != "" || slices.Contains(strings.Fields(dependencies[object]), name), "genesis reservation ownership drifted: unowned call %s", id.Name)
					if object == validatorObject {
						logicalMDBXAssert(t, validator == nil && name == "genesisMDBXValidate" && text(call) == "ConnectBlockBasicInMemoryAtHeightAndSuiteContext(owned, &previous, &target, 0, nil, out.State, chainID, nil, nil)", "genesis full validator owner drifted")
						validator = call
					}
				}
			}
			return true
		})
		logicalMDBXAssert(t, reflect.DeepEqual(edges[name], want[name]), "genesis reservation ownership drifted: helper edges %s/%v", name, edges[name])
	}
	for ident, object := range info.Uses {
		logicalMDBXAssert(t, objects[object] == "" || covered[ident], "genesis reservation ownership drifted: helper use outside owned closure")
	}
	logicalMDBXAssert(t, reservation != nil && update != nil && clone != nil, "genesis reservation ownership drifted")
	logicalMDBXAssert(t, validator != nil, "genesis full validator owner drifted")
	logicalMDBXAssert(t, inside(update, reservation) && inside(clone, reservation) && clone.Pos() < update.Pos(), "genesis reservation ownership drifted")
	logicalMDBXAssert(t, reflect.DeepEqual(edges["genesisMDBXBatch"], []string{"genesisMDBXPrestate", "genesisMDBXArtifacts", "genesisMDBXEmptyUTXO", "genesisMDBXZeroCounter", "genesisMDBXValidate"}), "genesis first artifact drifted: worklist %v", edges["genesisMDBXBatch"])
	visited := map[string]bool{}
	var visit func(string)
	visit = func(name string) {
		if visited[name] {
			return
		}
		visited[name] = true
		for _, child := range edges[name] {
			visit(child)
		}
	}
	visit("ConnectPublishedGenesisMDBX")
	logicalMDBXAssert(t, len(visited) == len(functions), "genesis call closure contains an unreachable owner: %v", visited)
	artifacts := functions["genesisMDBXArtifacts"]
	var order []string
	var reads int
	ast.Inspect(artifacts.Body, func(n ast.Node) bool {
		if guard, ok := n.(*ast.IfStmt); ok && strings.Contains(text(guard.Cond), "!bytes.Equal") {
			_, returns := guard.Body.List[0].(*ast.ReturnStmt)
			logicalMDBXAssert(t, returns && len(guard.Body.List) == 1, "genesis first artifact drifted: mismatching artifact continued")
		}
		if key, ok := n.(*ast.KeyValueExpr); ok && text(key.Key) == "DBI" {
			order = append(order, text(key.Value))
		}
		if call, ok := n.(*ast.CallExpr); ok && text(call.Fun) == "reader.Get" {
			reads++
			logicalMDBXAssert(t, text(call) == "reader.Get(row.DBI, row.Key)", "genesis first artifact drifted")
		}
		if loop, ok := n.(*ast.RangeStmt); ok {
			logicalMDBXAssert(t, text(loop.X) == "extras" && text(loop.Body.List[1]) == "if err != nil {\n\treturn nil, nil, err\n}", "genesis first artifact drifted: failure continuation")
		}
		return true
	})
	logicalMDBXAssert(t, reads == 1 && len(order) >= 3 && reflect.DeepEqual(order[:3], []string{"dbis[3]", "dbis[4]", "dbis[5]"}), "genesis first artifact drifted: %v", order)
	// Immediate worklist refusals compose with the native raw-byte witnesses.
	for _, owner := range []string{"genesisMDBXBatch", "genesisMDBXPrestate"} {
		body := functions[owner].Body.List
		for i, statement := range body {
			assign, ok := statement.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) < 2 {
				continue
			}
			last := text(assign.Lhs[len(assign.Lhs)-1])
			if last != "err" && last != "failure" {
				continue
			}
			if returned, ok := body[i+1].(*ast.ReturnStmt); ok {
				logicalMDBXAssert(t, i+2 == len(body) && text(returned.Results[len(returned.Results)-1]) == last, "genesis first artifact drifted: %s terminal propagation", owner)
				continue
			}
			guard, ok := body[i+1].(*ast.IfStmt)
			logicalMDBXAssert(t, ok && text(guard.Cond) == last+" != nil" && len(guard.Body.List) == 1, "genesis first artifact drifted: %s immediate refusal", owner)
			_, returns := guard.Body.List[0].(*ast.ReturnStmt)
			logicalMDBXAssert(t, returns, "genesis first artifact drifted: %s falls through", owner)
		}
	}
	prestate := text(functions["genesisMDBXPrestate"])
	logicalMDBXAssert(t, strings.Contains(prestate, "reader.Get(dbis[0], key)") && strings.Contains(prestate, "mdbx.DecodeStorageAuthorityV1(value)"), "genesis first artifact drifted: authority owner")
	for _, statement := range functions["genesisMDBXBatch"].Body.List {
		if guard, ok := statement.(*ast.IfStmt); ok && guard.Init != nil {
			logicalMDBXAssert(t, text(guard.Cond) == "err != nil" && len(guard.Body.List) == 1 && text(guard.Body.List[0]) == "return mdbx.Batch{}, err", "genesis first artifact drifted: required state read continued")
		}
	}
	logicalMDBXAssert(t, strings.Contains(text(artifacts), "Literal: owned[:116]") && strings.Contains(text(artifacts), "Literal: owned}"), "genesis reservation ownership drifted: independent artifact copies")
}
