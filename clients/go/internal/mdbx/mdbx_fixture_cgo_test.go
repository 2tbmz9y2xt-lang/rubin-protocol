//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

func TestFixtureModesAndFixedOperations(t *testing.T) {
	for _, tc := range []struct {
		name, diagnostic string
		mode             fixtureMode
		operation        engineOperation
	}{
		{"unexpected DBI", "SchemaV1 main cardinality mismatch", fixtureUnexpectedDBI, operationInit},
		{"third meta row", "SchemaV1 metadata cardinality mismatch", fixtureThirdMetaRow, operationInit},
		{"unnamed main row", "SchemaV1 main cardinality mismatch", fixtureUnnamedMainRow, operationOpen},
		{"wrong schema version", "invalid SchemaV1 version row", fixtureWrongSchemaVersion, operationOpen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "db")
			var store *Store
			var err error
			if tc.mode <= fixtureThirdMetaRow {
				store, err = fixtureCreate(path, environmentConfig(), tc.mode)
			} else {
				path = closedEnvironment(t)
				store, err = fixtureOpen(path, environmentConfig(), tc.mode)
			}
			engine := requireEnvironmentError(t, err, EngineIntegrity, tc.operation, -30793, tc.diagnostic)
			fixtureOwner.Lock()
			active := fixtureOwner.active
			fixtureOwner.Unlock()
			if store != nil || active || tc.mode == fixtureWrongSchemaVersion && engine.Cause != errSchema || tc.mode != fixtureWrongSchemaVersion && engine.Cause != nil {
				t.Fatalf("fixture retained state or Cause: %v/%v/%v", store, active, engine.Cause)
			}
			requireArtifact(t, path, 0o700, false)
			for _, name := range []string{"rubin-writer.lock", "mdbx.dat", "mdbx.lck"} {
				requireArtifact(t, filepath.Join(path, name), 0o600, name == "rubin-writer.lock")
			}
			handle, result, lockErr := filelock.AcquireDirectory(path)
			if lockErr != nil || result != "" || handle == nil {
				t.Fatalf("writer retained: %q %v", result, lockErr)
			}
			mustEnvironment(t, handle.Release())
		})
	}
	for _, mode := range []fixtureMode{0, 5} {
		if err := armFixture(filepath.Join(t.TempDir(), "db"), mode); err == nil {
			t.Fatalf("invalid fixture mode %d accepted", mode)
		}
	}
	t.Run("target-bound owner", func(t *testing.T) {
		target, sibling := filepath.Join(t.TempDir(), "target"), filepath.Join(t.TempDir(), "sibling")
		mustEnvironment(t, armFixture(target, fixtureUnexpectedDBI))
		defer clearFixture()
		if armFixture(sibling, fixtureThirdMetaRow) == nil || claimFixturePath(sibling) != 0 || claimFixturePath(target) != fixtureUnexpectedDBI || claimFixturePath(target) != 0 {
			t.Fatal("fixture owner was retargeted, prematurely consumed or reused")
		}
	})
	for _, mode := range []fixtureMode{fixtureUnnamedMainRow, fixtureWrongSchemaVersion} {
		if store, err := fixtureCreate(filepath.Join(t.TempDir(), "db"), environmentConfig(), mode); store != nil || err == nil {
			t.Fatalf("Create phase accepted mode %d", mode)
		}
	}
	for _, mode := range []fixtureMode{fixtureUnexpectedDBI, fixtureThirdMetaRow} {
		if store, err := fixtureOpen(filepath.Join(t.TempDir(), "db"), environmentConfig(), mode); store != nil || err == nil {
			t.Fatalf("Open phase accepted mode %d", mode)
		}
	}
	store, copied, err := fixtureOpenReverseUTXO(filepath.Join(t.TempDir(), "db"))
	requireNoStore(t, store, err, EngineIntegrity, operationOpen, -30793, "SchemaV1 DBI flags mismatch")
	if string(copied) != string(configBytes(environmentConfig())) {
		t.Fatalf("copied metadata changed: %x", copied)
	}
	store, err = fixtureOpenStoredReadersMismatch(filepath.Join(t.TempDir(), "db"))
	effective := requireNoStore(t, store, err, EngineIntegrity, operationOpen, -30793, "effective environment mismatch")
	if effective.Cause == nil || effective.Cause.Error() != "MaxReaders: got 493, want 492" {
		t.Fatalf("effective mismatch cause=%v", effective.Cause)
	}
	path := filepath.Join(t.TempDir(), "db")
	store, err = Create(path, environmentConfig())
	mustEnvironment(t, err)
	busy, abortErr, closeErr := fixtureCloseBusy(path, store)
	requireEnvironmentError(t, busy, EngineConcurrency, operationClose, -30778, expectedNativeDiagnostic(-30778))
	if abortErr != nil || closeErr != nil || store.state != storeCLOSED {
		t.Fatalf("Close-BUSY cleanup: %v/%v/%s", abortErr, closeErr, store.state)
	}
	store, err = Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	if rc, cleanup := fixtureWriteOwnerMismatch(store); rc != -30416 || cleanup != nil || store.state != storeOPEN {
		t.Fatalf("owner mismatch=%d cleanup=%v state=%s", rc, cleanup, store.state)
	}
	mustEnvironment(t, store.Close())
}

func fixturePrefixKey(rank uint8, id, tail byte, undoEntry bool) []byte {
	var width int
	switch rank {
	case 1:
		width = 44
	case 2, 6:
		width = 16
	case 5:
		width = 33
		if undoEntry {
			width = 77
		}
	}
	key := make([]byte, width)
	key[7] = id
	if rank == 5 {
		key[0], key[7] = id, 0
		if undoEntry {
			key[32] = 1
		}
	}
	key[len(key)-1] = tail
	return key
}

func fixturePrefixValue(rank uint8, undoEntry bool, maximum bool) []byte {
	switch rank {
	case 1:
		if maximum {
			return make([]byte, 65_560)
		}
		return make([]byte, 20)
	case 2, 6:
		return make([]byte, 104)
	default:
		if undoEntry {
			if maximum {
				return make([]byte, 65_560)
			}
			return make([]byte, 20)
		}
		value := make([]byte, 33)
		value[0] = 1
		return value
	}
}

func fixtureMalformedCanonicalKey(id, tail byte) []byte {
	key := make([]byte, 17)
	key[7], key[15] = id, tail
	return key
}

func readFixturePrefixPage(t *testing.T, store *Store, dbi DBI, prefix, after []byte, maxRows uint32, maxBytes uint64) PrefixPage {
	t.Helper()
	var page PrefixPage
	mustEnvironment(t, store.View(func(reader *Reader) error {
		var err error
		page, err = reader.PrefixPage(dbi, prefix, after, maxRows, maxBytes)
		return err
	}))
	return page
}

func requireFixturePage(t *testing.T, page PrefixPage, stop PrefixPageStop, keys ...[]byte) {
	t.Helper()
	if page.Stop != stop || len(page.Rows) != len(keys) {
		t.Fatalf("PrefixPage result=%#v, want stop=%d rows=%d", page, stop, len(keys))
	}
	for i, key := range keys {
		if !bytes.Equal(page.Rows[i].Key, key) {
			t.Fatalf("PrefixPage key[%d]=%x, want %x", i, page.Rows[i].Key, key)
		}
	}
}

func TestReaderPrefixPageNativeFixtures(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	dbis := readDBIsLiteral()
	before := make(map[uint8][]byte)
	wants := make(map[uint8][][]byte)
	wantValues := make(map[uint8][][]byte)
	rows := make([]fixtureRawRow, 0, 10)
	for _, rank := range []uint8{1, 2, 6} {
		before[rank] = fixturePrefixKey(rank, 2, 1, false)
		rows = append(rows, fixtureRawRow{dbi: dbis[rank], key: before[rank], value: fixturePrefixValue(rank, false, false)})
		for _, tail := range []byte{1, 2} {
			key := fixturePrefixKey(rank, 3, tail, false)
			value := fixturePrefixValue(rank, false, false)
			for i := range value {
				value[i] = byte(int(rank) + int(tail) + i)
			}
			wants[rank] = append(wants[rank], key)
			wantValues[rank] = append(wantValues[rank], value)
			rows = append(rows, fixtureRawRow{dbi: dbis[rank], key: key, value: value})
		}
		rows = append(rows, fixtureRawRow{dbi: dbis[rank], key: fixturePrefixKey(rank, 4, 1, false), value: fixturePrefixValue(rank, false, false)})
	}
	manifest := fixturePrefixKey(5, 3, 0, false)
	entry := fixturePrefixKey(5, 3, 1, true)
	before[5] = fixturePrefixKey(5, 2, 0, false)
	manifestValue := fixturePrefixValue(5, false, false)
	entryValue := fixturePrefixValue(5, true, false)
	for i := range manifestValue {
		manifestValue[i] = byte(31 + i)
	}
	for i := range entryValue {
		entryValue[i] = byte(63 + i)
	}
	wants[5] = [][]byte{manifest, entry}
	wantValues[5] = [][]byte{manifestValue, entryValue}
	rows = append(rows,
		fixtureRawRow{dbi: dbis[5], key: before[5], value: fixturePrefixValue(5, false, false)},
		fixtureRawRow{dbi: dbis[5], key: manifest, value: manifestValue},
		fixtureRawRow{dbi: dbis[5], key: entry, value: entryValue},
		fixtureRawRow{dbi: dbis[5], key: fixturePrefixKey(5, 4, 0, false), value: fixturePrefixValue(5, false, false)},
	)
	mustEnvironment(t, fixtureSeedRows(store, rows...))

	for _, rank := range []uint8{1, 2, 5, 6} {
		prefix, _, minimum := prefixPageRequest(rank, 3)
		if rank == 2 || rank == 6 {
			minimum = 1_000
		}
		page := readFixturePrefixPage(t, store, dbis[rank], prefix, nil, 10, minimum)
		for _, row := range page.Rows {
			if bytes.Equal(row.Key, before[rank]) {
				t.Fatalf("rank %d page included before-prefix sibling", rank)
			}
		}
		requireFixturePage(t, page, PrefixPageStop(1), wants[rank]...)
		for i, row := range page.Rows {
			if !bytes.Equal(row.Value, wantValues[rank][i]) {
				t.Fatalf("rank %d value[%d]=%x, want %x", rank, i, row.Value, wantValues[rank][i])
			}
		}
		emptyPrefix, _, emptyMinimum := prefixPageRequest(rank, 9)
		empty := readFixturePrefixPage(t, store, dbis[rank], emptyPrefix, nil, 10, emptyMinimum)
		if empty.Rows != nil || empty.Stop != PrefixPageStop(1) {
			t.Fatalf("rank %d empty page=%#v", rank, empty)
		}
	}

	maximumRows := []fixtureRawRow{
		{dbi: dbis[1], key: fixturePrefixKey(1, 8, 255, false), value: fixturePrefixValue(1, false, true)},
		{dbi: dbis[5], key: fixturePrefixKey(5, 8, 255, true), value: fixturePrefixValue(5, true, true)},
	}
	mustEnvironment(t, fixtureSeedRows(store, maximumRows...))
	for _, rank := range []uint8{1, 5} {
		prefix, _, minimum := prefixPageRequest(rank, 8)
		page := readFixturePrefixPage(t, store, dbis[rank], prefix, nil, 1, minimum)
		if len(page.Rows) != 1 || page.Stop != PrefixPageStop(1) || len(page.Rows[0].Key) != map[uint8]int{1: 44, 5: 77}[rank] || len(page.Rows[0].Value) != 65_560 {
			t.Fatalf("maximum rank %d page=%#v", rank, page)
		}
	}
}

func TestReaderPrefixPageResultMatrix(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	dbi := readDBIsLiteral()[2]
	keys := [][]byte{
		fixturePrefixKey(2, 5, 1, false),
		fixturePrefixKey(2, 5, 2, false),
		fixturePrefixKey(2, 5, 3, false),
	}
	rows := make([]fixtureRawRow, 0, len(keys)+1)
	for _, key := range keys {
		rows = append(rows, fixtureRawRow{dbi: dbi, key: key, value: fixturePrefixValue(2, false, false)})
	}
	oneKey := fixturePrefixKey(2, 6, 1, false)
	rows = append(rows, fixtureRawRow{dbi: dbi, key: oneKey, value: fixturePrefixValue(2, false, false)})
	mustEnvironment(t, fixtureSeedRows(store, rows...))
	prefix, _, _ := prefixPageRequest(2, 5)

	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, nil, 1, 1_000), PrefixPageStop(2), keys[0])
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, nil, 10, 120), PrefixPageStop(3), keys[0])
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, nil, 10, 224), PrefixPageStop(3), keys[0])
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, nil, 1, 120), PrefixPageStop(2), keys[0])
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, nil, 2, 1_000), PrefixPageStop(2), keys[0], keys[1])
	onePrefix, _, _ := prefixPageRequest(2, 6)
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, onePrefix, nil, 1, 120), PrefixPageStop(1), oneKey)
}

func TestReaderPrefixPageContinuation(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	dbi := readDBIsLiteral()[2]
	keys := [][]byte{
		fixturePrefixKey(2, 11, 10, false),
		fixturePrefixKey(2, 11, 11, false),
		fixturePrefixKey(2, 11, 20, false),
	}
	for _, key := range keys {
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: dbi, key: key, value: fixturePrefixValue(2, false, false)}))
	}
	prefix, _, _ := prefixPageRequest(2, 11)
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, nil, 10, 1_000), PrefixPageStop(1), keys...)
	var got [][]byte
	var after []byte
	exhausted := false
	for range 4 {
		page := readFixturePrefixPage(t, store, dbi, prefix, after, 1, 1_000)
		for _, row := range page.Rows {
			got = append(got, append([]byte(nil), row.Key...))
		}
		if page.Stop == PrefixPageStop(1) {
			exhausted = true
			break
		}
		if page.Stop != PrefixPageStop(2) || len(page.Rows) != 1 {
			t.Fatalf("continuation page=%#v", page)
		}
		after = page.Rows[0].Key
	}
	if !exhausted || len(got) != len(keys) {
		t.Fatalf("concatenated page exhausted/count=%v/%d", exhausted, len(got))
	}
	for i := range keys {
		if !bytes.Equal(got[i], keys[i]) {
			t.Fatalf("concatenated key[%d]=%x", i, got[i])
		}
	}
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, keys[0], 10, 1_000), PrefixPageStop(1), keys[1], keys[2])
	absent := fixturePrefixKey(2, 11, 15, false)
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, absent, 10, 1_000), PrefixPageStop(1), keys[2])
	mustEnvironment(t, fixtureDeletePrefixRow(store, dbi, keys[1]))
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, keys[1], 10, 1_000), PrefixPageStop(1), keys[2])
}

func TestReaderPrefixPageMixedUndoContinuation(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	undoDBI := readDBIsLiteral()[5]
	undoPrefix, _, undoMinimum := prefixPageRequest(5, 16)
	manifest := fixturePrefixKey(5, 16, 0, false)
	entry := fixturePrefixKey(5, 16, 1, true)
	absentEntry := fixturePrefixKey(5, 16, 0, true)
	mustEnvironment(t, fixtureSeedRows(store,
		fixtureRawRow{dbi: undoDBI, key: manifest, value: fixturePrefixValue(5, false, false)},
		fixtureRawRow{dbi: undoDBI, key: entry, value: fixturePrefixValue(5, true, false)},
	))
	requireFixturePage(t, readFixturePrefixPage(t, store, undoDBI, undoPrefix, nil, 1, undoMinimum), PrefixPageStop(2), manifest)
	requireFixturePage(t, readFixturePrefixPage(t, store, undoDBI, undoPrefix, manifest, 1, undoMinimum), PrefixPageStop(1), entry)
	requireFixturePage(t, readFixturePrefixPage(t, store, undoDBI, undoPrefix, entry, 1, undoMinimum), PrefixPageStop(1))
	requireFixturePage(t, readFixturePrefixPage(t, store, undoDBI, undoPrefix, absentEntry, 1, undoMinimum), PrefixPageStop(1), entry)
	mustEnvironment(t, fixtureDeletePrefixRow(store, undoDBI, entry))
	requireFixturePage(t, readFixturePrefixPage(t, store, undoDBI, undoPrefix, absentEntry, 1, undoMinimum), PrefixPageStop(1))
}

func TestReaderPrefixPageMaximumRows(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	dbi := readDBIsLiteral()[2]
	prefix, _, _ := prefixPageRequest(2, 22)
	keys := make([][]byte, int(MaxPrefixPageRows)+1)
	rows := make([]fixtureRawRow, len(keys))
	for i := range keys {
		keys[i] = make([]byte, 16)
		copy(keys[i], prefix)
		binary.BigEndian.PutUint64(keys[i][8:], uint64(i+1))
		rows[i] = fixtureRawRow{dbi: dbi, key: keys[i], value: fixturePrefixValue(2, false, false)}
	}
	mustEnvironment(t, fixtureSeedRows(store, rows...))
	first := readFixturePrefixPage(t, store, dbi, prefix, nil, MaxPrefixPageRows, 1_000_000)
	if first.Stop != PrefixPageRowLimit || len(first.Rows) != int(MaxPrefixPageRows) {
		t.Fatalf("maximum-row first page=%d/%d", first.Stop, len(first.Rows))
	}
	for i, row := range first.Rows {
		if !bytes.Equal(row.Key, keys[i]) {
			t.Fatalf("maximum-row key[%d]=%x, want %x", i, row.Key, keys[i])
		}
	}
	last := readFixturePrefixPage(t, store, dbi, prefix, first.Rows[len(first.Rows)-1].Key, MaxPrefixPageRows, 1_000_000)
	requireFixturePage(t, last, PrefixPageExhausted, keys[len(keys)-1])
}

func TestReaderPrefixPageOwnership(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	dbi := readDBIsLiteral()[2]
	keys := [][]byte{fixturePrefixKey(2, 12, 1, false), fixturePrefixKey(2, 12, 2, false)}
	values := [][]byte{fixturePrefixValue(2, false, false), fixturePrefixValue(2, false, false)}
	values[0][0], values[1][0] = 31, 32
	mustEnvironment(t, fixtureSeedRows(store,
		fixtureRawRow{dbi: dbi, key: keys[0], value: values[0]},
		fixtureRawRow{dbi: dbi, key: keys[1], value: values[1]},
	))
	prefix, after, _ := prefixPageRequest(2, 12)
	after[len(after)-1] = 0
	var page PrefixPage
	mustEnvironment(t, store.View(func(reader *Reader) error {
		var pageErr error
		page, pageErr = reader.PrefixPage(dbi, prefix, after, 10, 1_000)
		if pageErr != nil {
			return pageErr
		}
		requireFixturePage(t, page, PrefixPageExhausted, keys...)
		nativeKey, nativeValue, addressErr := fixturePrefixNativeAddresses(reader, dbi, page.Rows[0].Key, len(page.Rows[0].Value))
		if addressErr != nil {
			return addressErr
		}
		if unsafe.Pointer(unsafe.SliceData(page.Rows[0].Key)) == nativeKey {
			t.Fatal("PrefixPage key aliases native backing")
		}
		if unsafe.Pointer(unsafe.SliceData(page.Rows[0].Value)) == nativeValue {
			t.Fatal("PrefixPage value aliases native backing")
		}
		return nil
	}))
	prefix[0], after[0] = 255, 255
	page.Rows[0].Key[0], page.Rows[0].Value[0] = 254, 253
	if page.Rows[1].Key[0] == 254 || page.Rows[1].Value[0] == 253 {
		t.Fatal("PrefixPage rows share backing storage")
	}
	freshPrefix, _, _ := prefixPageRequest(2, 12)
	fresh := readFixturePrefixPage(t, store, dbi, freshPrefix, nil, 10, 1_000)
	if len(fresh.Rows) != 2 || !bytes.Equal(fresh.Rows[0].Key, keys[0]) || !bytes.Equal(fresh.Rows[1].Key, keys[1]) || !bytes.Equal(fresh.Rows[0].Value, values[0]) || !bytes.Equal(fresh.Rows[1].Value, values[1]) {
		t.Fatal("PrefixPage returned borrowed or input-aliased bytes")
	}
}

func TestReaderPrefixPageMalformedDisposition(t *testing.T) {
	dbis := readDBIsLiteral()
	for mode := uint32(1); mode <= 5; mode++ {
		prefix, _, _ := prefixPageRequest(2, 1)
		var err error
		var recovered any
		func() {
			defer func() { recovered = recover() }()
			err = fixturePrefixNativeShape(dbis[2], prefix, prefix, mode)
		}()
		if recovered != nil {
			t.Fatalf("native shape mode %d panicked: %v", mode, recovered)
		}
		if err == nil {
			t.Fatalf("native shape mode %d accepted", mode)
		} else {
			engine := requireEnvironmentError(t, err, EngineLocalInvariant, engineOperation("prefix-page"), codeProblem, "mdbx_get_equal_or_great returned invalid result shape")
			if engine.Cause != nil || engine.ReopenRequired {
				t.Fatalf("native shape mode %d Cause/Reopen=%v/%v", mode, engine.Cause, engine.ReopenRequired)
			}
		}
	}

	type malformedCase struct {
		name, diagnostic string
		class            EngineClass
		code             int
		reopen           bool
		rows             []fixtureRawRow
	}
	stored := func(name string, rank uint8, key, value []byte, diagnostic string) malformedCase {
		return malformedCase{name, diagnostic, EngineIntegrity, codeInvalid, true, []fixtureRawRow{{dbi: dbis[rank], key: key, value: value}}}
	}
	const keyDiagnostic = "stored key outside SchemaV1 prefix-page domain"
	const valueDiagnostic = "stored value width outside SchemaV1 bound"
	utxo, staged := fixturePrefixKey(1, 13, 1, false), fixturePrefixKey(6, 13, 1, false)
	manifest, entry := fixturePrefixKey(5, 13, 0, false), fixturePrefixKey(5, 13, 1, true)
	invalidManifest := append(append([]byte(nil), manifest...), 0)
	invalidEntry := append([]byte(nil), entry[:76]...)
	for _, tc := range []malformedCase{
		{
			name:       "native envelope key",
			diagnostic: "mdbx_get_equal_or_great returned invalid result shape",
			class:      EngineLocalInvariant,
			code:       codeProblem,
			rows:       []fixtureRawRow{{dbi: dbis[2], key: append(fixturePrefixKey(2, 13, 1, false), make([]byte, 62)...), value: make([]byte, 104)}},
		},
		stored("equal malformed key", 2, []byte{0, 0, 0, 0, 0, 0, 0, 13}, make([]byte, 104), keyDiagnostic),
		stored("invalid key", 2, fixtureMalformedCanonicalKey(13, 1), make([]byte, 104), keyDiagnostic),
		stored("invalid value", 2, fixturePrefixKey(2, 13, 1, false), make([]byte, 103), valueDiagnostic),
		stored("oversize value", 2, fixturePrefixKey(2, 13, 1, false), make([]byte, 105), valueDiagnostic),
		stored("utxo invalid key", 1, utxo[:43], make([]byte, 20), keyDiagnostic),
		stored("utxo value below minimum", 1, utxo, make([]byte, 19), valueDiagnostic),
		stored("utxo value above maximum", 1, utxo, make([]byte, 65_561), valueDiagnostic),
		stored("staged invalid key", 6, staged[:15], make([]byte, 104), keyDiagnostic),
		stored("staged value below minimum", 6, staged, make([]byte, 103), valueDiagnostic),
		stored("staged value above maximum", 6, staged, make([]byte, 105), valueDiagnostic),
		stored("undo manifest invalid key", 5, invalidManifest, fixturePrefixValue(5, false, false), keyDiagnostic),
		stored("undo manifest value below minimum", 5, manifest, make([]byte, 32), valueDiagnostic),
		stored("undo manifest value above maximum", 5, manifest, make([]byte, 34), valueDiagnostic),
		stored("undo entry invalid key", 5, invalidEntry, make([]byte, 20), keyDiagnostic),
		stored("undo entry value below minimum", 5, entry, make([]byte, 19), valueDiagnostic),
		stored("undo entry value above maximum", 5, entry, make([]byte, 65_561), valueDiagnostic),
		{
			name:       "lookahead discards rows",
			diagnostic: keyDiagnostic,
			class:      EngineIntegrity,
			code:       codeInvalid,
			reopen:     true,
			rows: []fixtureRawRow{
				{dbi: dbis[2], key: fixturePrefixKey(2, 13, 1, false), value: make([]byte, 104)},
				{dbi: dbis[2], key: fixtureMalformedCanonicalKey(13, 2), value: make([]byte, 104)},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rank := tc.rows[0].dbi.Rank
			path := filepath.Join(t.TempDir(), "db")
			store, err := Create(path, environmentConfig())
			mustEnvironment(t, err)
			for _, row := range tc.rows {
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, row.dbi, row.key, row.value))
			}
			prefix, _, minimum := prefixPageRequest(rank, 13)
			var page PrefixPage
			var recorded error
			returned := store.View(func(reader *Reader) error {
				page, recorded = reader.PrefixPage(dbis[rank], prefix, nil, 1, minimum)
				if page.Rows != nil || page.Stop != 0 {
					t.Fatalf("malformed PrefixPage returned partial rows: %#v", page)
				}
				engine := requireEnvironmentError(t, recorded, tc.class, engineOperation("prefix-page"), tc.code, tc.diagnostic)
				if engine.Cause != nil || engine.ReopenRequired != tc.reopen || reader.failure != recorded || reader.active.Load() {
					t.Fatal("PrefixPage failure was not latched exactly")
				}
				again, againErr := reader.PrefixPage(dbis[rank], prefix, nil, 1, minimum)
				requirePrefixPageError(t, again, againErr, "Reader is not active", nil)
				if reader.failure != recorded {
					t.Fatal("inactive PrefixPage replaced recorded failure")
				}
				_, _, getErr := reader.Get(dbis[0], []byte{1})
				requireEnvironmentError(t, getErr, EngineInvalidInput, operationGet, codeEINVAL, "Reader is not active")
				if reader.failure != recorded {
					t.Fatal("inactive Get replaced PrefixPage failure")
				}
				return nil
			})
			if returned != recorded || store.state != storeCLOSED || !sameError(store.terminal, recorded) || !validStoreShape(store) {
				t.Fatalf("malformed PrefixPage disposition=%v/%s", returned, store.state)
			}
			if next := store.View(func(*Reader) error { t.Fatal("terminal callback invoked"); return nil }); !sameError(next, recorded) {
				t.Fatal("PrefixPage terminal was not reusable")
			}
			if truth, next := store.Update(func(*Reader) (Batch, error) { t.Fatal("terminal callback invoked"); return Batch{}, nil }); truth != CommitTruthOld || !sameError(next, recorded) {
				t.Fatal("PrefixPage consumed-read token was rejected")
			}
		})
	}

	t.Run("outside prefix ignores value", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, store.Close()) }()
		mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbis[2], fixturePrefixKey(2, 15, 1, false), make([]byte, 103)))
		prefix, _, minimum := prefixPageRequest(2, 14)
		page := readFixturePrefixPage(t, store, dbis[2], prefix, nil, 1, minimum)
		if page.Rows != nil || page.Stop != PrefixPageStop(1) {
			t.Fatalf("outside-prefix value was decoded: %#v", page)
		}
	})

	t.Run("native error latches", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		prefix, _, minimum := prefixPageRequest(2, 1)
		var recorded error
		returned := store.View(func(reader *Reader) error {
			mustEnvironment(t, fixtureBreakPrefixReader(reader))
			page, pageErr := reader.PrefixPage(dbis[2], prefix, nil, 1, minimum)
			if page.Rows != nil || page.Stop != 0 {
				t.Fatalf("native PrefixPage error returned rows: %#v", page)
			}
			recorded = pageErr
			engine := requireEnvironmentError(t, recorded, EngineLocalInvariant, engineOperation("prefix-page"), codeBadTxn, expectedNativeDiagnostic(codeBadTxn))
			if engine.Cause != nil || engine.ReopenRequired {
				t.Fatalf("native PrefixPage Cause/Reopen=%v/%v", engine.Cause, engine.ReopenRequired)
			}
			return nil
		})
		if returned != recorded || store.state != storeCLOSED || !sameError(store.terminal, recorded) || !validStoreShape(store) {
			t.Fatalf("native PrefixPage disposition=%v/%s", returned, store.state)
		}
	})
}

//nolint:errorlint // Exact callback, infrastructure and panic identities are required.
func TestReaderPrefixPageCallbackLifecycle(t *testing.T) {
	dbi := readDBIsLiteral()[2]
	prefix, _, minimum := prefixPageRequest(2, 21)
	callbackErr, panicValue := errors.New("callback"), &struct{ name string }{"prefix-page"}
	for _, mode := range []string{"ignored", "exact", "wrapped", "distinct", "typed-nil", "panic"} {
		t.Run(mode, func(t *testing.T) {
			store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
			mustEnvironment(t, err)
			mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbi, fixturePrefixKey(2, 21, 1, false), make([]byte, 103)))
			var recorded, returned error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				returned = store.View(func(reader *Reader) error {
					page, pageErr := reader.PrefixPage(dbi, prefix, nil, 1, minimum)
					if page.Rows != nil || page.Stop != 0 {
						t.Fatalf("callback failure returned page: %#v", page)
					}
					recorded = pageErr
					switch mode {
					case "ignored":
						return nil
					case "exact":
						return recorded
					case "wrapped":
						return fmt.Errorf("wrapped: %w", recorded)
					case "distinct":
						return callbackErr
					case "typed-nil":
						var typed *nilPointerError
						return typed
					default:
						panic(panicValue)
					}
				})
			}()
			if store.state != storeCLOSED || !validStoreShape(store) {
				t.Fatalf("callback PrefixPage state=%s", store.state)
			}
			switch mode {
			case "ignored", "exact":
				if returned != recorded || !sameError(store.terminal, recorded) {
					t.Fatal("PrefixPage infrastructure identity was duplicated")
				}
			case "wrapped", "distinct", "typed-nil":
				parts, ok := returned.(interface{ Unwrap() []error })
				if !ok || len(parts.Unwrap()) != 2 || parts.Unwrap()[1] != recorded {
					t.Fatalf("PrefixPage callback order=%v", returned)
				}
				if mode == "distinct" && parts.Unwrap()[0] != callbackErr || mode == "wrapped" && !errors.Is(parts.Unwrap()[0], recorded) {
					t.Fatalf("PrefixPage callback identity=%v", returned)
				}
				if mode == "typed-nil" {
					_, ok := parts.Unwrap()[0].(*nilPointerError)
					if !ok || parts.Unwrap()[0] == nil {
						t.Fatal("PrefixPage typed-nil behavior changed")
					}
				}
			case "panic":
				if recovered != panicValue || returned != nil || !sameError(store.terminal, recorded) {
					t.Fatalf("PrefixPage panic disposition=%v/%v", recovered, returned)
				}
			}
		})
	}

	t.Run("Goexit", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbi, fixturePrefixKey(2, 21, 1, false), make([]byte, 103)))
		var recorded error
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = store.View(func(reader *Reader) error {
				_, recorded = reader.PrefixPage(dbi, prefix, nil, 1, minimum)
				runtime.Goexit()
				return nil
			})
		}()
		<-done
		if recorded == nil || store.state != storeCLOSED || !sameError(store.terminal, recorded) || !validStoreShape(store) {
			t.Fatalf("PrefixPage Goexit disposition=%v/%s", recorded, store.state)
		}
	})

	t.Run("Update infrastructure matrix", func(t *testing.T) {
		for _, mode := range []string{"ignored", "exact", "wrapped", "distinct", "typed-nil", "panic"} {
			t.Run(mode, func(t *testing.T) {
				store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
				mustEnvironment(t, err)
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbi, fixturePrefixKey(2, 21, 1, false), make([]byte, 103)))
				var recorded, returned error
				var recovered any
				truth := CommitTruthOld
				func() {
					defer func() { recovered = recover() }()
					truth, returned = store.Update(func(reader *Reader) (Batch, error) {
						page, pageErr := reader.PrefixPage(dbi, prefix, nil, 1, minimum)
						if page.Rows != nil || page.Stop != 0 {
							t.Fatalf("Update callback failure returned page: %#v", page)
						}
						recorded = pageErr
						switch mode {
						case "ignored":
							return updateLifecycleBatch(), nil
						case "exact":
							return updateLifecycleBatch(), recorded
						case "wrapped":
							return updateLifecycleBatch(), fmt.Errorf("wrapped: %w", recorded)
						case "distinct":
							return updateLifecycleBatch(), callbackErr
						case "typed-nil":
							var typed *nilPointerError
							return updateLifecycleBatch(), typed
						default:
							panic(panicValue)
						}
					})
				}()
				if store.state != storeCLOSED || store.terminalTruth != CommitTruthOld || !validStoreShape(store) {
					t.Fatalf("Update PrefixPage state=%s/%s", store.state, store.terminalTruth)
				}
				switch mode {
				case "ignored", "exact":
					if truth != CommitTruthOld || returned != recorded || !sameError(store.terminal, recorded) {
						t.Fatal("Update PrefixPage infrastructure identity was duplicated")
					}
				case "wrapped", "distinct", "typed-nil":
					parts, ok := returned.(interface{ Unwrap() []error })
					if truth != CommitTruthOld || !ok || len(parts.Unwrap()) != 2 || parts.Unwrap()[1] != recorded || !sameError(store.terminal, returned) {
						t.Fatalf("Update PrefixPage callback order=%v", returned)
					}
					if mode == "distinct" && parts.Unwrap()[0] != callbackErr || mode == "wrapped" && !errors.Is(parts.Unwrap()[0], recorded) {
						t.Fatalf("Update PrefixPage callback identity=%v", returned)
					}
					if mode == "typed-nil" {
						_, ok := parts.Unwrap()[0].(*nilPointerError)
						if !ok || parts.Unwrap()[0] == nil {
							t.Fatal("Update PrefixPage typed-nil behavior changed")
						}
					}
				case "panic":
					if recovered != panicValue || returned != nil || !sameError(store.terminal, recorded) {
						t.Fatalf("Update PrefixPage panic disposition=%v/%v", recovered, returned)
					}
				}
				if nextTruth, next := store.Update(func(*Reader) (Batch, error) { t.Fatal("closed Update callback invoked"); return Batch{}, nil }); nextTruth != CommitTruthOld || !sameError(next, store.terminal) {
					t.Fatal("Update PrefixPage terminal next operation drifted")
				}
			})
		}
	})

	t.Run("Update Goexit", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbi, fixturePrefixKey(2, 21, 1, false), make([]byte, 103)))
		var recorded error
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = store.Update(func(reader *Reader) (Batch, error) {
				_, recorded = reader.PrefixPage(dbi, prefix, nil, 1, minimum)
				runtime.Goexit()
				return Batch{}, nil
			})
		}()
		<-done
		if recorded == nil || store.state != storeCLOSED || store.terminalTruth != CommitTruthOld || !sameError(store.terminal, recorded) || !validStoreShape(store) {
			t.Fatalf("Update PrefixPage Goexit disposition=%v/%s", recorded, store.state)
		}
		if nextTruth, next := store.Update(func(*Reader) (Batch, error) { t.Fatal("closed Update callback invoked"); return Batch{}, nil }); nextTruth != CommitTruthOld || !sameError(next, recorded) {
			t.Fatal("Update PrefixPage Goexit next operation drifted")
		}
	})

	t.Run("application-only", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, store.Close()) }()
		key := fixturePrefixKey(2, 21, 1, false)
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: dbi, key: key, value: make([]byte, 104)}))
		for _, mode := range []string{"nil", "direct", "typed-nil", "panic"} {
			var returned error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				returned = store.View(func(reader *Reader) error {
					page, pageErr := reader.PrefixPage(dbi, prefix, nil, 1, minimum)
					if pageErr != nil || len(page.Rows) != 1 || page.Stop != PrefixPageStop(1) {
						return fmt.Errorf("successful PrefixPage callback=%#v/%w", page, pageErr)
					}
					switch mode {
					case "nil":
						return nil
					case "direct":
						return callbackErr
					case "typed-nil":
						var typed *nilPointerError
						return typed
					default:
						panic(panicValue)
					}
				})
			}()
			if mode == "nil" && returned != nil || mode == "direct" && returned != callbackErr || mode == "panic" && recovered != panicValue || store.state != storeOPEN || store.terminal != nil {
				t.Fatalf("application-only PrefixPage=%s/%v/%v/%s", mode, returned, recovered, store.state)
			}
			if mode == "typed-nil" {
				_, ok := returned.(*nilPointerError)
				if !ok || returned == nil {
					t.Fatal("application-only typed nil changed")
				}
			}
		}
		truth, updateErr := store.Update(func(reader *Reader) (Batch, error) {
			page, pageErr := reader.PrefixPage(dbi, prefix, nil, 1, minimum)
			if pageErr != nil || len(page.Rows) != 1 {
				return Batch{}, fmt.Errorf("Update PrefixPage=%#v/%w", page, pageErr)
			}
			return updateLifecycleBatch(), callbackErr
		})
		if truth != CommitTruthOld || updateErr != callbackErr || store.state != storeOPEN {
			t.Fatalf("application-only Update=%s/%v", truth, updateErr)
		}
	})

	t.Run("Update infrastructure rejects batch", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "db")
		store, err := Create(path, environmentConfig())
		mustEnvironment(t, err)
		mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbi, fixturePrefixKey(2, 21, 1, false), make([]byte, 103)))
		var recorded error
		truth, returned := store.Update(func(reader *Reader) (Batch, error) {
			page, pageErr := reader.PrefixPage(dbi, prefix, nil, 1, minimum)
			if page.Rows != nil || page.Stop != 0 {
				t.Fatalf("Update infrastructure returned page: %#v", page)
			}
			recorded = pageErr
			return updateLifecycleBatch(), nil
		})
		if truth != CommitTruthOld || returned != recorded || store.state != storeCLOSED || store.terminalTruth != CommitTruthOld || !sameError(store.terminal, recorded) || !validStoreShape(store) {
			t.Fatalf("Update infrastructure disposition=%s/%v/%s", truth, returned, store.state)
		}
		if nextTruth, next := store.Update(func(*Reader) (Batch, error) { t.Fatal("closed Update callback invoked"); return Batch{}, nil }); nextTruth != CommitTruthOld || !sameError(next, recorded) {
			t.Fatal("Update terminal operation rejected PrefixPage")
		}
		reopened, openErr := Open(path, environmentConfig())
		mustEnvironment(t, openErr)
		defer func() { mustEnvironment(t, reopened.Close()) }()
		mustEnvironment(t, reopened.View(func(reader *Reader) error {
			value, present, getErr := reader.Get(readDBIsLiteral()[0], []byte{2})
			if getErr != nil || present || value != nil {
				t.Fatalf("ignored PrefixPage failure committed batch: %x/%v/%v", value, present, getErr)
			}
			return nil
		}))
	})

	t.Run("Update successful page commits batch", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, store.Close()) }()
		key := fixturePrefixKey(2, 21, 1, false)
		value := fixturePrefixValue(2, false, false)
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: dbi, key: key, value: value}))
		truth, updateErr := store.Update(func(reader *Reader) (Batch, error) {
			page, pageErr := reader.PrefixPage(dbi, prefix, nil, 1, minimum)
			if pageErr != nil || page.Stop != PrefixPageExhausted || len(page.Rows) != 1 || !bytes.Equal(page.Rows[0].Key, key) || !bytes.Equal(page.Rows[0].Value, value) {
				return Batch{}, fmt.Errorf("successful Update PrefixPage=%#v/%w", page, pageErr)
			}
			return updateLifecycleBatch(), nil
		})
		if truth != CommitTruthNew || updateErr != nil || store.state != storeOPEN || store.terminal != nil {
			t.Fatalf("successful Update PrefixPage disposition=%s/%v/%s", truth, updateErr, store.state)
		}
		mustEnvironment(t, store.View(func(reader *Reader) error {
			persisted, present, getErr := reader.Get(readDBIsLiteral()[0], []byte{2})
			if getErr != nil || !present || persisted == nil || len(persisted) != 0 {
				t.Fatalf("successful Update PrefixPage mutation=%x/%v/%v", persisted, present, getErr)
			}
			return nil
		}))
	})
}

func TestReaderGetNativeFixtures(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	dbis := readDBIsLiteral()
	emptyKey := []byte{2}
	counterKey := []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1}
	counterValue := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	blockKey := make([]byte, 32)
	blockValue := make([]byte, 68_000_125)
	blockValue[0], blockValue[len(blockValue)-1] = 0x7a, 0x5c
	if err := fixtureSeedRows(store,
		fixtureRawRow{dbi: dbis[0], key: emptyKey, value: []byte{}},
		fixtureRawRow{dbi: dbis[0], key: counterKey, value: counterValue},
		fixtureRawRow{dbi: dbis[4], key: blockKey, value: blockValue},
	); err != nil {
		t.Fatal(err)
	}
	if err := fixtureSeedRows(store, fixtureRawRow{dbi: dbis[0], key: []byte{0}, value: make([]byte, 3)}); err == nil {
		t.Fatal("fixture accepted an overbound raw row")
	}
	panicValue := &struct{ name string }{"maximum"}
	var maximum []byte
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		viewErr := store.View(func(reader *Reader) error {
			value, present, getErr := reader.Get(dbis[4], blockKey)
			if getErr != nil || !present || len(value) != 68_000_125 {
				return fmt.Errorf("maximum native copy drifted: %d/%v/%w", len(value), present, getErr)
			}
			maximum = value
			panic(panicValue)
		})
		if viewErr != nil {
			t.Fatal(viewErr)
		}
	}()
	if recovered != panicValue || len(maximum) != 68_000_125 || maximum[0] != 0x7a || maximum[len(maximum)-1] != 0x5c {
		t.Fatalf("maximum panic cleanup drifted: %v/%d", recovered, len(maximum))
	}
	mustEnvironment(t, store.View(func(reader *Reader) error {
		empty, present, getErr := reader.Get(dbis[0], emptyKey)
		if getErr != nil || !present || empty == nil || len(empty) != 0 {
			return fmt.Errorf("present-empty identity drifted: %#v/%v/%w", empty, present, getErr)
		}
		first, present, getErr := reader.Get(dbis[0], counterKey)
		if getErr != nil || !present || len(first) != 16 {
			return fmt.Errorf("independent copy setup drifted: %x/%v/%w", first, present, getErr)
		}
		first[0] = 0xff
		second, present, getErr := reader.Get(dbis[0], counterKey)
		if getErr != nil || !present || len(second) != 16 || second[0] != 1 {
			return fmt.Errorf("returned bytes alias MDBX: %x/%v/%w", second, present, getErr)
		}
		absentKey := []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 2}
		absent, present, getErr := reader.Get(dbis[0], absentKey)
		if getErr != nil || present || absent != nil {
			return fmt.Errorf("absence identity drifted: %#v/%v/%w", absent, present, getErr)
		}
		return nil
	}))
	inspection, err := store.Inspect()
	mustEnvironment(t, err)
	if inspection.DBIs[0].Entries != 4 || inspection.DBIs[4].Entries != 1 || inspection.ReaderTableLength == 0 {
		t.Fatalf("Inspection provenance drifted: %+v", inspection)
	}
	mustEnvironment(t, store.Close())
}

//nolint:errorlint // Exact callback, infrastructure and panic identities are required.
func TestReaderGetMalformedDisposition(t *testing.T) {
	dbis, key := readDBIsLiteral(), []byte{0}
	callbackErr, panicValue := errors.New("callback"), &struct{ name string }{"panic"}
	for _, mode := range []string{"ignored", "exact", "wrapped", "distinct", "panic"} {
		t.Run(mode, func(t *testing.T) {
			store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
			mustEnvironment(t, err)
			mustEnvironment(t, fixtureSeedMalformedStoredWidth(store))
			var recorded, returned error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				returned = store.View(func(reader *Reader) error {
					_, _, recorded = reader.Get(dbis[0], key)
					requireEnvironmentError(t, recorded, EngineIntegrity, operationGet, codeInvalid, "stored value width outside SchemaV1 bound")
					if _, _, again := reader.Get(dbis[0], key); requireEnvironmentError(t, again, EngineInvalidInput, operationGet, codeEINVAL, "Reader is not active").Cause != nil {
						t.Fatal("failed Reader remained active")
					}
					switch mode {
					case "ignored":
						return nil
					case "exact":
						return recorded
					case "wrapped":
						return fmt.Errorf("wrapped: %w", recorded)
					case "distinct":
						return callbackErr
					default:
						panic(panicValue)
					}
				})
			}()
			if store.state != storeCLOSED || store.env != nil || store.writer != nil || store.txn != nil || store.config != (ConfigV1{}) || !sameError(store.terminal, returned) && mode != "panic" {
				t.Fatalf("post-native Get disposition drifted: %s/%v", store.state, returned)
			}
			switch mode {
			case "ignored", "exact":
				if returned != recorded {
					t.Fatalf("recorded failure identity/duplication drifted: %v", returned)
				}
			case "wrapped", "distinct":
				parts, ok := returned.(interface{ Unwrap() []error })
				if !ok || len(parts.Unwrap()) != 2 || parts.Unwrap()[1] != recorded || mode == "distinct" && parts.Unwrap()[0] != callbackErr || mode == "wrapped" && !errors.Is(parts.Unwrap()[0], recorded) {
					t.Fatalf("callback/recorded order drifted: %v", returned)
				}
			case "panic":
				if recovered != panicValue || returned != nil || store.terminal != recorded {
					t.Fatalf("panic disposition drifted: %v/%v/%v", recovered, returned, store.terminal)
				}
			}
			terminal := store.terminal
			if !sameError(store.View(func(*Reader) error { t.Fatal("closed callback invoked"); return nil }), terminal) {
				t.Fatal("closed View legality drifted")
			}
			if inspection, next := store.Inspect(); inspection != (Inspection{}) || !sameError(next, terminal) || !sameError(store.Close(), terminal) {
				t.Fatal("closed Inspect/Close legality drifted")
			}
		})
	}
}

func TestNativeUpdateFixtures(t *testing.T) {
	source, err := os.ReadFile("mdbx_cgo.go")
	mustEnvironment(t, err)
	abort, commit := updateNativeBody(t, source, "updateNativeAbort"), updateNativeBody(t, source, "updateNativeCommit")
	if !strings.Contains(abort, "if rc == codeThreadMismatch {") || !strings.Contains(abort, "updateNativeRetainedWrite(false") || strings.Count(abort, "updateNativeRetainedWrite") != 1 {
		t.Fatal("abort ownership drifted")
	}
	if !strings.Contains(commit, "case codeThreadMismatch:") || !strings.Contains(commit, "updateNativeRetainedWrite(true") || strings.Count(commit, "updateNativeRetainedWrite") != 1 || !strings.Contains(commit, "case codePanic, codeEPerm, codeBadSignature, codeEINVAL, codeBadTxn, codeProblem:\n\t\treturn updateNativeConsumed(CommitTruthOld, true, commitErr, nil)") {
		t.Fatal("commit ownership drifted")
	}
	truth := updateNativeBody(t, source, "updateNativeReadbackTruth")
	oldAt, newAt := strings.Index(truth, "if oldImage"), strings.Index(truth, "if newImage")
	if oldAt < 0 || newAt < 0 || oldAt > newAt {
		t.Fatal("readback tie-break drifted")
	}
	fixture, err := os.ReadFile("mdbx_fixture_cgo.go")
	mustEnvironment(t, err)
	post, unreadable := updateNativeBody(t, fixture, "fixtureUpdatePostCommitENOSPC"), updateNativeBody(t, fixture, "fixtureUpdatePostCommitENOSPCUnreadable")
	if strings.Count(post, "updateNativeReadback") != 1 || strings.Count(unreadable, "updateNativeReadback") != 1 {
		t.Fatal("readback truth drifted")
	}
	t.Run("wrong-thread retained write", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, store.Close()) }()
		outcome, release, err := fixtureUpdateWrongThread(store)
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, release()) }()
		engine := requireEngineError(t, outcome.primary, EngineLocalInvariant, operationUpdate, codeThreadMismatch)
		if engine.Diagnostic != expectedNativeDiagnostic(codeThreadMismatch) || outcome.truth != CommitTruthOld || !outcome.commitAttempted || outcome.secondary != nil || outcome.retainedWrite == nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("commit ownership drifted: %+v", outcome)
		}
		if locked := outcome.lockedOutcome(); !locked.poisoned || locked.err != nil {
			t.Fatalf("commit ownership drifted: %+v", locked)
		}
		both := outcome
		both.retainedRead = outcome.retainedWrite
		if both.valid() == nil {
			t.Fatal("commit ownership drifted")
		}
		wrongTruth := outcome
		wrongTruth.truth = CommitTruthNew
		if wrongTruth.valid() == nil {
			t.Fatal("commit ownership drifted")
		}
		retainedRead := updateNativeRetainedRead(outcome.primary, errors.New("cleanup"), outcome.retainedWrite)
		if retainedRead.valid() != nil {
			t.Fatalf("commit ownership drifted: %+v", retainedRead)
		}
		retainedRead.secondary = nil
		if retainedRead.valid() == nil {
			t.Fatal("commit ownership drifted")
		}
		retainedRead.secondary = errors.New("cleanup")
		retainedRead.commitAttempted = false
		if retainedRead.valid() == nil {
			t.Fatal("commit stage drifted")
		}
		committed := outcome
		committed.secondary = errors.New("cleanup")
		if committed.valid() == nil {
			t.Fatal("commit ownership drifted")
		}
	})

	t.Run("wrong-thread abort retains write", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, store.Close()) }()
		outcome, release, err := fixtureUpdateAbortWrongThread(store)
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, release()) }()
		primary := requireEngineError(t, outcome.primary, EngineLocalInvariant, operationUpdate, codeNotFound)
		secondary := requireEngineError(t, outcome.secondary, EngineLocalInvariant, operationAbort, codeThreadMismatch)
		if primary.Diagnostic != expectedNativeDiagnostic(codeNotFound) || secondary.Diagnostic != expectedNativeDiagnostic(codeThreadMismatch) || outcome.truth != CommitTruthOld || outcome.commitAttempted || outcome.retainedWrite == nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("abort ownership drifted: %+v", outcome)
		}
	})

	t.Run("break then real commit", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		plan := updateNativePlan(t, updatePlanBatch(t).Mutations[8])
		outcome := fixtureUpdateResultTrue(store, plan)
		engine := requireEngineError(t, outcome.primary, EngineTransaction, operationUpdate, codeResultTrue)
		if engine.Diagnostic != expectedNativeDiagnostic(codeResultTrue) {
			t.Fatalf("RESULT_TRUE disposition drifted: %+v", engine)
		}
		if outcome.truth != CommitTruthOld || !outcome.commitAttempted || outcome.secondary != nil || outcome.retainedWrite != nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("RESULT_TRUE disposition drifted: %+v", outcome)
		}
		mustEnvironment(t, store.Close())
	})

	t.Run("post-commit ENOSPC OLD", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		mutation := Mutation{DBI: readDBIsLiteral()[0], Key: []byte{2}, BeforePresent: true, AfterKind: planAfterLiteral, Literal: []byte{}}
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: mutation.DBI, key: mutation.Key, value: mutation.Literal}))
		outcome, cleanup := fixtureUpdatePostCommitENOSPC(store, updateNativePlan(t, mutation))
		mustEnvironment(t, cleanup)
		engine := requireEngineError(t, outcome.primary, EngineCapacity, operationUpdate, codeENOSPC)
		if engine.Diagnostic != expectedNativeDiagnostic(codeENOSPC) {
			t.Fatalf("readback truth drifted: %+v", engine)
		}
		if outcome.truth != CommitTruthOld || !outcome.commitAttempted || outcome.secondary != nil || outcome.retainedWrite != nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("readback truth drifted: %+v", outcome)
		}
		requireUpdateValue(t, store, mutation.DBI, mutation.Key, mutation.Literal, true)
		mustEnvironment(t, store.Close())
	})

	t.Run("post-commit ENOSPC unreadable", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		mutation := Mutation{DBI: readDBIsLiteral()[0], Key: []byte{2}, BeforePresent: true, AfterKind: planAfterLiteral, Literal: []byte{}}
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: mutation.DBI, key: mutation.Key, value: mutation.Literal}))
		outcome, cleanup := fixtureUpdatePostCommitENOSPCUnreadable(store, updateNativePlan(t, mutation))
		mustEnvironment(t, cleanup)
		if outcome.truth != CommitTruthUnknown || !outcome.commitAttempted || outcome.primary == nil || outcome.secondary == nil || outcome.retainedWrite != nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("readback truth drifted: %+v", outcome)
		}
		_ = requireEngineError(t, outcome.primary, EngineCapacity, operationUpdate, codeENOSPC)
		mustEnvironment(t, store.Close())
	})
}

func TestNativeUpdateImageFamilies(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(map[bool]string{false: "non-target reference", true: "target reference alias"}[alias], func(t *testing.T) {
			batch := updatePlanBatch(t)
			oldMeta := append([]byte(nil), batch.Mutations[1].Literal...)
			oldDelete := append([]byte(nil), batch.Mutations[3].Literal...)
			oldReference := append([]byte(nil), batch.Mutations[3].Literal...)
			oldMeta[len(oldMeta)-1], oldDelete[0], oldReference[len(oldReference)-1] = 1, 2, 3
			if alias {
				batch.Mutations[3].BeforePresent = true
				batch.Mutations[8].RefKey = append([]byte(nil), batch.Mutations[3].Key...)
				copy(batch.Mutations[8].Key[41:77], batch.Mutations[3].Key[8:44])
			}
			plan := updateNativePlan(t, batch.Mutations...)
			store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
			mustEnvironment(t, err)
			rows := []fixtureRawRow{
				{dbi: batch.Mutations[1].DBI, key: batch.Mutations[1].Key, value: oldMeta},
				{dbi: batch.Mutations[2].DBI, key: batch.Mutations[2].Key, value: oldDelete},
			}
			if alias {
				rows = append(rows, fixtureRawRow{dbi: batch.Mutations[3].DBI, key: batch.Mutations[3].Key, value: oldReference})
			} else {
				rows = append(rows, fixtureRawRow{dbi: batch.Mutations[8].RefDBI, key: batch.Mutations[8].RefKey, value: oldReference})
			}
			mustEnvironment(t, fixtureSeedRows(store, rows...))
			outcome, cleanup := fixtureUpdatePostCommitENOSPC(store, plan)
			mustEnvironment(t, cleanup)
			_ = requireEngineError(t, outcome.primary, EngineCapacity, operationUpdate, codeENOSPC)
			requireUpdateTruth(t, outcome, CommitTruthNew, true, outcome.primary, nil)
			for i, mutation := range batch.Mutations {
				want, present := mutation.Literal, mutation.AfterKind != planAfterAbsent
				if mutation.AfterKind == planAfterOldValueRef {
					want = oldReference
				}
				requireUpdateValue(t, store, mutation.DBI, mutation.Key, want, present)
				if i == 8 && !alias {
					requireUpdateValue(t, store, mutation.RefDBI, mutation.RefKey, oldReference, true)
				}
			}
			mustEnvironment(t, store.Close())
		})
	}
}

func TestNativeUpdateUnknownImages(t *testing.T) {
	newPlan := func(t *testing.T, extra bool) ([]ownedMutation, []Mutation) {
		t.Helper()
		rows := []Mutation{{DBI: readDBIsLiteral()[0], Key: []byte{2}, AfterKind: planAfterLiteral, Literal: []byte{}}}
		if extra {
			key, err := MetaKey(0x10, 1)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, Mutation{DBI: readDBIsLiteral()[0], Key: key, AfterKind: planAfterLiteral, Literal: LogicalCounterValue(0, 0)})
		}
		return updateNativePlan(t, rows...), rows
	}
	requireUnknown := func(t *testing.T, outcome updateNativeOutcome) {
		t.Helper()
		engine := requireEngineError(t, outcome.primary, EngineCapacity, operationUpdate, codeENOSPC)
		if engine.Diagnostic != expectedNativeDiagnostic(codeENOSPC) {
			t.Fatalf("UNKNOWN primary=%+v", engine)
		}
		requireUpdateTruth(t, outcome, CommitTruthUnknown, true, outcome.primary, nil)
	}
	t.Run("third image", func(t *testing.T) {
		plan, rows := newPlan(t, false)
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		outcome, cleanup := fixtureUpdatePostCommitENOSPCThird(store, plan)
		mustEnvironment(t, cleanup)
		requireUnknown(t, outcome)
		requireUpdateValue(t, store, rows[0].DBI, rows[0].Key, []byte{0x7f}, true)
		mustEnvironment(t, store.Close())
	})
	t.Run("mixed image", func(t *testing.T) {
		plan, rows := newPlan(t, true)
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		outcome, cleanup := fixtureUpdatePostCommitENOSPCThird(store, plan)
		mustEnvironment(t, cleanup)
		requireUnknown(t, outcome)
		requireUpdateValue(t, store, rows[0].DBI, rows[0].Key, []byte{0x7f}, true)
		requireUpdateValue(t, store, rows[1].DBI, rows[1].Key, rows[1].Literal, true)
		mustEnvironment(t, store.Close())
	})
	t.Run("missing image", func(t *testing.T) {
		rows := []Mutation{{DBI: readDBIsLiteral()[0], Key: []byte{2}, BeforePresent: true, AfterKind: planAfterLiteral, Literal: []byte{}}}
		plan := updateNativePlan(t, rows...)
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: rows[0].DBI, key: rows[0].Key, value: []byte{0x42}}))
		outcome, cleanup := fixtureUpdatePostCommitENOSPCMissing(store, plan)
		mustEnvironment(t, cleanup)
		requireUnknown(t, outcome)
		requireUpdateValue(t, store, rows[0].DBI, rows[0].Key, nil, false)
		mustEnvironment(t, store.Close())
	})
}
