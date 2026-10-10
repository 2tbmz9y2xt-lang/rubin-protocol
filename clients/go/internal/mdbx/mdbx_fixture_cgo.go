//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

/*
#cgo CFLAGS: -std=c11
#cgo CFLAGS: -DRUBIN_SELECTED_DAMAGE_FIXTURE=1
#include "../../../../third_party/libmdbx/mdbx.h"
#include <string.h>
typedef struct { unsigned mode, calls, gets, commits, aborts, closes, drift; MDBX_env *env; MDBX_txn *old_txn, *write_txn, *read_txn; MDBX_dbi dbi; unsigned char key[65536]; size_t key_len; } rubin_li_state;
extern int rubin_li_arm(MDBX_env *, MDBX_dbi, unsigned, const void *, size_t);
extern void rubin_li_disarm(rubin_li_state *);
extern unsigned rubin_li_calls(void);
typedef struct { unsigned opens, gets, closes, queries, faults; } rubin_tip_counts;
extern int rubin_tip_arm(MDBX_env *, MDBX_dbi, unsigned, unsigned, unsigned, int);
extern void rubin_tip_disarm(rubin_tip_counts *);
extern void rubin_tip_wait(void);
extern void rubin_tip_release(void);
extern int rubin_tip_drift_arm(const void *, size_t, const void *, size_t, int);
extern int rubin_tip_close_fault(int);
static int rubin_fixture_large_bulk(MDBX_txn *txn, MDBX_dbi dbi, unsigned kind, unsigned count, size_t width, const unsigned char *hashes) {
	unsigned char key_bytes[2022] = {0};
	size_t key_len = kind == 1 ? 32 : (kind == 3 ? 333 : (kind == 4 ? 2022 : (kind == 5 ? 44 : (kind == 6 ? 37 : 77))));
	for (unsigned i = 0; i < count; i++) {
		unsigned offset = kind == 1 ? 28 : (kind == 5 ? 8 : 33);
		key_bytes[offset] = (unsigned char)(i >> 24); key_bytes[offset+1] = (unsigned char)(i >> 16);
		key_bytes[offset+2] = (unsigned char)(i >> 8); key_bytes[offset+3] = (unsigned char)i;
		if (kind == 1) memcpy(key_bytes, hashes + (size_t)i * 32, 32);
		else if (kind == 5) key_bytes[7] = 9;
		else if (kind == 4) {
			unsigned long long generation = (unsigned long long)(i / 2) + 1;
			memset(key_bytes, 0, sizeof(key_bytes));
			for (unsigned j = 0; j < 8; j++) key_bytes[7-j] = (unsigned char)(generation >> (j * 8));
			key_bytes[2021] = (unsigned char)(1 + i % 2);
		} else { if (hashes != NULL) memcpy(key_bytes, hashes, 32); key_bytes[32] = 1; }
		MDBX_val key = {key_bytes, key_len}, value = {NULL, width};
		int rc = mdbx_put(txn, dbi, &key, &value, MDBX_RESERVE | MDBX_NOOVERWRITE);
		if (rc != MDBX_SUCCESS) return rc;
		if (kind == 1) {
			memset(value.iov_base, 0x5a, width);
			unsigned char *bytes = value.iov_base;
			bytes[0] = (unsigned char)(i >> 24); bytes[1] = (unsigned char)(i >> 16);
			bytes[2] = (unsigned char)(i >> 8); bytes[3] = (unsigned char)i;
		} else {
			memset(value.iov_base, 0, width);
			((unsigned char *)value.iov_base)[0] = 0x5a;
		}
	}
	return MDBX_SUCCESS;
}
typedef struct { unsigned long long begin_old, begin_write, begin_read, old_gets[8], old_pulls[8], read_gets, faults, dels, commits, old_aborts, bridge_error; } rubin_sd_counts;
int rubin_sd_arm(MDBX_env *env, unsigned scenario, const MDBX_dbi *dbis, MDBX_dbi fault_dbi, const void *key, size_t key_len, uintptr_t probe);
void rubin_sd_disarm(rubin_sd_counts *out);
static int rubin_fixture_row_equal(MDBX_env *env, MDBX_dbi dbi, const void *key_bytes, size_t key_len, int want_present, const void *want_bytes, size_t want_len, int *equal) {
	MDBX_txn *txn = NULL;
	MDBX_val key = {(void *)key_bytes, key_len}, value = {NULL, 0};
	int rc = mdbx_txn_begin(env, NULL, MDBX_TXN_RDONLY, &txn);
	if (rc != MDBX_SUCCESS) return rc;
	rc = mdbx_get(txn, dbi, &key, &value);
	*equal = rc == MDBX_NOTFOUND ? !want_present : (rc == MDBX_SUCCESS && want_present && value.iov_len == want_len && (want_len == 0 || memcmp(value.iov_base, want_bytes, want_len) == 0));
	int abort_rc = mdbx_txn_abort(txn);
	if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) return rc;
	return abort_rc;
}
typedef struct { int rc; MDBX_txn *txn; } rubin_fixture_txn_result;
static rubin_fixture_txn_result rubin_fixture_txn_begin(MDBX_env *env, MDBX_txn_flags_t flags) { rubin_fixture_txn_result result = {0, NULL}; result.rc = mdbx_txn_begin(env, NULL, flags, &result.txn); return result; }
static int rubin_fixture_txn_abort(MDBX_txn *txn) { return mdbx_txn_abort(txn); }
static int rubin_fixture_txn_commit(MDBX_txn *txn) { return mdbx_txn_commit(txn); }
typedef struct { int rc; const char *path; } rubin_fixture_path_result;
static rubin_fixture_path_result rubin_fixture_txn_path(MDBX_txn *txn) { rubin_fixture_path_result result = {MDBX_INVALID, NULL}; MDBX_env *env = mdbx_txn_env(txn); if (env) result.rc = mdbx_env_get_path(env, &result.path); return result; }
static int rubin_fixture_named(MDBX_txn *txn) { MDBX_dbi dbi; return mdbx_dbi_open(txn, "fixture-v1", MDBX_DB_DEFAULTS | MDBX_CREATE, &dbi); }
static int rubin_fixture_meta(MDBX_txn *txn, MDBX_dbi meta) { const unsigned char key = 2; MDBX_val k = {(void *)&key, 1}, v = {NULL, 0}; return mdbx_put(txn, meta, &k, &v, MDBX_NOOVERWRITE); }
static int rubin_fixture_main_row(MDBX_txn *txn) { MDBX_dbi main; const char key[] = "fixture-main-row", value[] = "ordinary"; MDBX_val k = {(void *)key, sizeof(key) - 1}, v = {(void *)value, sizeof(value) - 1}; int rc = mdbx_dbi_open(txn, NULL, MDBX_DB_DEFAULTS, &main); return rc == MDBX_SUCCESS ? mdbx_put(txn, main, &k, &v, MDBX_UPSERT) : rc; }
static int rubin_fixture_schema_version(MDBX_txn *txn, MDBX_dbi meta) { const unsigned char key = 0, value[4] = {0, 0, 0, 1}; MDBX_val k = {(void *)&key, 1}, v = {(void *)value, 4}; return mdbx_put(txn, meta, &k, &v, MDBX_UPSERT); }
static int rubin_fixture_schema_v1(MDBX_txn *txn, MDBX_dbi meta) { MDBX_dbi dbi; int rc = mdbx_dbi_open(txn, "canonical-owner-v1", MDBX_DB_DEFAULTS, &dbi); if (rc == MDBX_SUCCESS) rc = mdbx_drop(txn, dbi, true); return rc == MDBX_SUCCESS ? rubin_fixture_schema_version(txn, meta) : rc; }
static int rubin_fixture_reverse_utxo(MDBX_txn *txn) { MDBX_dbi dbi; int rc = mdbx_dbi_open(txn, "utxo-v1", MDBX_DB_DEFAULTS, &dbi); if (rc == MDBX_SUCCESS) rc = mdbx_drop(txn, dbi, true); return rc == MDBX_SUCCESS ? mdbx_dbi_open(txn, "utxo-v1", MDBX_REVERSEKEY | MDBX_CREATE, &dbi) : rc; }
static int rubin_fixture_add_rows(MDBX_txn *txn, MDBX_dbi meta, MDBX_dbi canonical) { const unsigned char mk = 2, mv = 0x42, ak[16] = {1}, av[104] = {1}; MDBX_val mkey = {(void *)&mk, 1}, mval = {(void *)&mv, 1}, akey = {(void *)ak, 16}, aval = {(void *)av, 104}; int rc = mdbx_put(txn, meta, &mkey, &mval, MDBX_NOOVERWRITE); return rc == MDBX_SUCCESS ? mdbx_put(txn, canonical, &akey, &aval, MDBX_NOOVERWRITE) : rc; }
static int rubin_fixture_check_rows(MDBX_txn *txn, MDBX_dbi meta, MDBX_dbi canonical) { const unsigned char mk = 2, mv = 0x42, ak[16] = {1}, av[104] = {1}; MDBX_val mkey = {(void *)&mk, 1}, akey = {(void *)ak, 16}, got; int rc = mdbx_get(txn, meta, &mkey, &got); if (rc == MDBX_SUCCESS && (got.iov_len != 1 || memcmp(got.iov_base, &mv, 1))) rc = MDBX_INVALID; if (rc == MDBX_SUCCESS) rc = mdbx_get(txn, canonical, &akey, &got); return rc == MDBX_SUCCESS && (got.iov_len != 104 || memcmp(got.iov_base, av, 104)) ? MDBX_INVALID : rc; }
static int rubin_fixture_readers_493(MDBX_txn *txn, MDBX_dbi meta) { const unsigned char key = 1, value[48] = {0,0,0,0,0,0x10,0,0, 0,0,0,0,0,0x20,0,0, 0,0,0,0,0x10,0,0,0, 0,0,0,0,0,0x10,0,0, 0,0,0,0,0,0x20,0,0, 0,0,0x10,0, 0,0,1,0xed}; MDBX_val k = {(void *)&key, 1}, v = {(void *)value, 48}; return mdbx_put(txn, meta, &k, &v, MDBX_UPSERT); }
static int rubin_fixture_check_and_reconfigure(MDBX_txn *txn, MDBX_dbi meta, MDBX_dbi canonical) { int rc = rubin_fixture_check_rows(txn, meta, canonical); return rc == MDBX_SUCCESS ? rubin_fixture_readers_493(txn, meta) : rc; }
static int rubin_fixture_put(MDBX_txn *txn, MDBX_dbi dbi, const void *key_bytes, size_t key_len, const void *value_bytes, size_t value_len) { MDBX_val key = {(void *)key_bytes, key_len}, value = {(void *)value_bytes, value_len}; return mdbx_put(txn, dbi, &key, &value, MDBX_UPSERT); }
static int rubin_fixture_del(MDBX_txn *txn, MDBX_dbi dbi, const void *key_bytes, size_t key_len) { MDBX_val key = {(void *)key_bytes, key_len}; return mdbx_del(txn, dbi, &key, NULL); }
typedef struct { int rc; const void *key_bytes; size_t key_len; const void *value_bytes; size_t value_len; } rubin_fixture_prefix_result;
static rubin_fixture_prefix_result rubin_fixture_prefix_shape(unsigned mode) {
	static const unsigned char key[78] = {0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,1};
	static const unsigned char below[16] = {0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1};
	static const unsigned char value[104] = {1};
	rubin_fixture_prefix_result result = {MDBX_RESULT_TRUE, key, 16, value, 104};
	if (mode == 1) result.key_bytes = NULL;
	else if (mode == 2) result.key_len = 0;
	else if (mode == 3) result.key_len = 78;
	else if (mode == 4) result.value_bytes = NULL;
	else if (mode == 5) result.key_bytes = below;
	return result;
}
static rubin_fixture_prefix_result rubin_fixture_prefix_address(const MDBX_txn *txn, MDBX_dbi dbi, const void *key_bytes, size_t key_len) {
	MDBX_val key = {(void *)key_bytes, key_len}, value = {NULL, 0};
	rubin_fixture_prefix_result result = {MDBX_EINVAL, NULL, 0, NULL, 0};
	result.rc = mdbx_get_equal_or_great(txn, dbi, &key, &value);
	if (result.rc == MDBX_SUCCESS || result.rc == MDBX_RESULT_TRUE) {
		result.key_bytes = key.iov_base;
		result.key_len = key.iov_len;
		result.value_bytes = value.iov_base;
		result.value_len = value.iov_len;
	}
	return result;
}
*/
import "C"

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/cgo"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

type fixtureMode uint32

const (
	fixtureUnexpectedDBI fixtureMode = iota + 1
	fixtureThirdMetaRow
	fixtureUnnamedMainRow
	fixtureWrongSchemaVersion
)

type fixtureOwnerState struct {
	sync.Mutex
	active, consumed bool
	path             string
	mode             fixtureMode
}

var fixtureOwner fixtureOwnerState

func init() {
	fixtureCreateExtraDBI = fixtureWantsExtraDBI
	fixtureBeforeInitCensus = fixtureCreateMutation
}

func fixtureWantsExtraDBI(path string) bool {
	fixtureOwner.Lock()
	defer fixtureOwner.Unlock()
	return fixtureOwner.active && fixtureOwner.path == path && fixtureOwner.mode == fixtureUnexpectedDBI
}

func claimFixturePath(path string) fixtureMode {
	fixtureOwner.Lock()
	defer fixtureOwner.Unlock()
	if !fixtureOwner.active || fixtureOwner.consumed || fixtureOwner.path != path {
		return 0
	}
	fixtureOwner.consumed = true
	return fixtureOwner.mode
}

func claimFixture(txn *C.MDBX_txn, operation engineOperation) (fixtureMode, error) {
	result := C.rubin_fixture_txn_path(txn)
	if err := nativePointerResultError(operation, "mdbx_env_get_path returned invalid result shape", int(result.rc), result.path != nil); err != nil {
		return 0, err
	}
	return claimFixturePath(C.GoString(result.path)), nil
}

func fixtureCreateMutation(txn *C.MDBX_txn, meta C.MDBX_dbi) error {
	mode, err := claimFixture(txn, operationInit)
	if err != nil {
		return err
	}
	var rc int
	switch mode {
	case 0:
		return nil
	case fixtureUnexpectedDBI:
		rc = int(C.rubin_fixture_named(txn))
	case fixtureThirdMetaRow:
		rc = int(C.rubin_fixture_meta(txn, meta))
	default:
		return errors.New("invalid Create fixture mode")
	}
	return fixtureResult(operationInit, rc)
}

func fixtureResult(operation engineOperation, rc int) error {
	if err := nativeError(operation, rc); err != nil {
		return err
	}
	return nil
}

func armFixture(path string, mode fixtureMode) error {
	rel, err := filepath.Rel(os.TempDir(), path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || mode < fixtureUnexpectedDBI || mode > fixtureWrongSchemaVersion {
		return errors.New("fixture path, mode or ownership is invalid")
	}
	fixtureOwner.Lock()
	defer fixtureOwner.Unlock()
	if fixtureOwner.active {
		return errors.New("fixture path, mode or ownership is invalid")
	}
	fixtureOwner.active, fixtureOwner.consumed, fixtureOwner.path, fixtureOwner.mode = true, false, path, mode
	return nil
}

func clearFixture() {
	fixtureOwner.Lock()
	fixtureOwner.active, fixtureOwner.consumed, fixtureOwner.path, fixtureOwner.mode = false, false, "", 0
	fixtureOwner.Unlock()
}

func fixtureCreate(path string, cfg ConfigV1, mode fixtureMode) (*Store, error) {
	if mode != fixtureUnexpectedDBI && mode != fixtureThirdMetaRow {
		return nil, errors.New("fixture mode is not a Create mode")
	}
	if err := armFixture(path, mode); err != nil {
		return nil, err
	}
	defer clearFixture()
	return Create(path, cfg)
}

func fixtureOpen(path string, cfg ConfigV1, mode fixtureMode) (*Store, error) {
	if mode != fixtureUnnamedMainRow && mode != fixtureWrongSchemaVersion {
		return nil, errors.New("fixture mode is not an Open mode")
	}
	if err := armFixture(path, mode); err != nil {
		return nil, err
	}
	defer clearFixture()
	store, err := Open(path, cfg)
	if err != nil {
		return store, err
	}
	err = fixtureWrite(store, operationOpen, func(txn *C.MDBX_txn) error {
		claimed, claimErr := claimFixture(txn, operationOpen)
		if claimErr != nil {
			return claimErr
		}
		switch claimed {
		case fixtureUnnamedMainRow:
			return fixtureResult(operationOpen, int(C.rubin_fixture_main_row(txn)))
		case fixtureWrongSchemaVersion:
			return fixtureResult(operationOpen, int(C.rubin_fixture_schema_version(txn, store.dbis[0])))
		default:
			return errors.New("invalid Open fixture claim")
		}
	})
	return reopenAfterFixture(path, cfg, store, err)
}

func fixtureWrite(store *Store, operation engineOperation, mutate func(*C.MDBX_txn) error) error {
	store.operations.Lock()
	defer store.operations.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	begun := C.rubin_fixture_txn_begin(store.env, C.MDBX_TXN_READWRITE)
	if err := nativePointerResultError(operation, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil); err != nil {
		return err
	}
	if primary := mutate(begun.txn); primary != nil {
		abortRC := int(C.rubin_fixture_txn_abort(begun.txn))
		return joinErrors(primary, fixtureResult(operationAbort, abortRC))
	}
	return fixtureResult(operation, int(C.rubin_fixture_txn_commit(begun.txn)))
}

type fixtureRawRow struct {
	dbi        DBI
	key, value []byte
}

func fixtureSeedRows(store *Store, rows ...fixtureRawRow) error {
	for _, row := range rows {
		if ValidateDBI(row.dbi) != nil || !validKey(row.dbi.Rank, row.key) {
			return errors.New("fixture raw row is outside SchemaV2")
		}
		minimum, maximum := rawValueBounds(row.dbi, row.key)
		if uint64(len(row.value)) < minimum || uint64(len(row.value)) > maximum {
			return errors.New("fixture raw row is outside SchemaV2")
		}
	}
	return fixtureWrite(store, operationInit, func(txn *C.MDBX_txn) error {
		for _, row := range rows {
			var value unsafe.Pointer
			if len(row.value) != 0 {
				value = unsafe.Pointer(&row.value[0])
			}
			rc := int(C.rubin_fixture_put(txn, store.dbis[row.dbi.Rank], unsafe.Pointer(&row.key[0]), C.size_t(len(row.key)), value, C.size_t(len(row.value))))
			runtime.KeepAlive(row)
			if err := fixtureResult(operationInit, rc); err != nil {
				return err
			}
		}
		return nil
	})
}

func fixtureSeedMalformedStoredWidth(store *Store) error {
	key, value := []byte{0}, []byte{0, 0, 1}
	return fixtureWrite(store, operationInit, func(txn *C.MDBX_txn) error {
		rc := int(C.rubin_fixture_put(txn, store.dbis[0], unsafe.Pointer(&key[0]), C.size_t(len(key)), unsafe.Pointer(&value[0]), C.size_t(len(value))))
		runtime.KeepAlive(key)
		runtime.KeepAlive(value)
		return fixtureResult(operationInit, rc)
	})
}

func fixtureSeedPrefixRawRow(store *Store, dbi DBI, key, value []byte) error {
	return fixtureWrite(store, operationInit, func(txn *C.MDBX_txn) error {
		var keyBytes, valueBytes unsafe.Pointer
		if len(key) != 0 {
			keyBytes = unsafe.Pointer(&key[0])
		}
		if len(value) != 0 {
			valueBytes = unsafe.Pointer(&value[0])
		}
		rc := int(C.rubin_fixture_put(txn, store.dbis[dbi.Rank], keyBytes, C.size_t(len(key)), valueBytes, C.size_t(len(value))))
		runtime.KeepAlive(key)
		runtime.KeepAlive(value)
		return fixtureResult(operationInit, rc)
	})
}

func fixtureLargeBulk(store *Store, kind, count, width uint32, prefix ...[32]byte) error {
	rank := 4
	var hashes []byte
	if kind == 1 {
		hashes = make([]byte, int(count)*32)
		header := bytes.Repeat([]byte{0x5a}, 116)
		for i := uint32(0); i < count; i++ {
			binary.BigEndian.PutUint32(header, i)
			hash := sha3.Sum256(header)
			copy(hashes[int(i)*32:], hash[:])
		}
	}
	if kind != 1 {
		rank = 5
		if kind == 4 || kind == 5 {
			rank = 1
		}
		if len(prefix) == 1 {
			hashes = prefix[0][:]
		}
	}
	var pointer *C.uchar
	if len(hashes) > 0 {
		pointer = (*C.uchar)(unsafe.Pointer(&hashes[0]))
	}
	return fixtureWrite(store, operationInit, func(txn *C.MDBX_txn) error {
		rc := int(C.rubin_fixture_large_bulk(txn, store.dbis[rank], C.uint(kind), C.uint(count), C.size_t(width), pointer))
		runtime.KeepAlive(hashes)
		return fixtureResult(operationInit, rc)
	})
}

type fixtureLargeEvidence struct {
	gets, commits, aborts, closes, drift uint32
}

var fixtureLargeMu sync.Mutex

type fixtureTipEvidence struct {
	opens, gets, closes, queries, faults uint32
}

var fixtureTipMu sync.Mutex

func fixtureTipCursor(store *Store, mode, query, get uint32, code int, run func()) (evidence fixtureTipEvidence, err error) {
	fixtureTipMu.Lock()
	defer fixtureTipMu.Unlock()
	if store == nil || store.env == nil || run == nil {
		return evidence, errors.New("invalid endpoint cursor fixture")
	}
	if rc := int(C.rubin_tip_arm(store.env, store.dbis[2], C.uint(mode), C.uint(query), C.uint(get), C.int(code))); rc != codeSuccess {
		return evidence, fixtureResult(operationInit, rc)
	}
	defer func() {
		var counts C.rubin_tip_counts
		C.rubin_tip_disarm(&counts)
		evidence = fixtureTipEvidence{uint32(counts.opens), uint32(counts.gets), uint32(counts.closes), uint32(counts.queries), uint32(counts.faults)}
	}()
	run()
	return evidence, nil
}

func fixtureTipWait() { C.rubin_tip_wait() }

func fixtureTipRelease() { C.rubin_tip_release() }

func fixtureTipDrift(key, value []byte, present bool) error {
	var keyBytes, valueBytes unsafe.Pointer
	if len(key) != 0 {
		keyBytes = unsafe.Pointer(&key[0])
	}
	if len(value) != 0 {
		valueBytes = unsafe.Pointer(&value[0])
	}
	flag := C.int(0)
	if present {
		flag = 1
	}
	rc := int(C.rubin_tip_drift_arm(keyBytes, C.size_t(len(key)), valueBytes, C.size_t(len(value)), flag))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return fixtureResult(operationInit, rc)
}

func fixtureTipCloseFault() error {
	return fixtureResult(operationInit, int(C.rubin_tip_close_fault(C.MDBX_EIO)))
}

// Dispose the real descriptor once, then install a positive Go sentinel whose
// low 32 bits cannot name a native signed-int descriptor. Release reaches the
// real close syscall with an invalid argument, never a reused original fd.
func fixtureTipWriterReleaseFault(store *Store) error {
	if store == nil || store.writer == nil {
		return errors.New("missing endpoint fixture writer")
	}
	field := reflect.ValueOf(store.writer).Elem().FieldByName("fd")
	if field.Kind() != reflect.Int || !field.CanAddr() {
		return errors.New("invalid endpoint fixture writer descriptor")
	}
	if err := syscall.Close(int(field.Int())); err != nil {
		return err
	}
	*(*int)(unsafe.Pointer(field.UnsafeAddr())) = int(^uint32(0))
	return nil
}

func fixtureLargeNativeCalls() uint32 { return uint32(C.rubin_li_calls()) }

func fixtureLargeFault(store *Store, mode uint32, rank uint8, key []byte, run func()) (evidence fixtureLargeEvidence, err error) {
	fixtureLargeMu.Lock()
	defer fixtureLargeMu.Unlock()
	if store == nil || len(key) == 0 || rank >= 8 || run == nil {
		return evidence, errors.New("invalid large-image fixture")
	}
	rc := int(C.rubin_li_arm(store.env, store.dbis[rank], C.uint(mode), unsafe.Pointer(&key[0]), C.size_t(len(key))))
	runtime.KeepAlive(key)
	if rc != codeSuccess {
		return evidence, fixtureResult(operationInit, rc)
	}
	defer func() {
		var native C.rubin_li_state
		C.rubin_li_disarm(&native)
		evidence = fixtureLargeEvidence{uint32(native.gets), uint32(native.commits), uint32(native.aborts), uint32(native.closes), uint32(native.drift)}
	}()
	run()
	return evidence, nil
}

// FixtureStartupCleanup binds the actual startup invocation to the existing
// readonly abort transports (9: consumed EIO, 10: retained THREAD_MISMATCH),
// optionally holding a real foreign-thread writer until that invocation exits.
// It supplies no checker result, canonical bytes or permission assignment.
func FixtureStartupCleanup(store *Store, mode uint32, busy bool, run func()) (state string, verified bool, err error) {
	if store == nil || store.env == nil || run == nil || !validStartupCleanupMode(mode) {
		return "", false, errors.New("invalid startup cleanup fixture")
	}
	if busy {
		_, release, beginErr := fixtureHeldUpdate(store)
		if beginErr != nil {
			return "", false, beginErr
		}
		defer func() { err = errors.Join(err, release()) }()
	}
	if mode == 0 {
		run()
	} else {
		_, err = fixtureLargeFault(store, mode, 0, []byte{2}, run)
	}
	return string(store.state), store.canonicalOwnerVerified, err
}

func validStartupCleanupMode(mode uint32) bool {
	switch mode {
	case 0, 9, 10:
		return true
	default:
		return false
	}
}

// FixtureStartupRelease disposes a retained test handle only after its native
// state, error, permission and next-operation assertions have been observed.
func FixtureStartupRelease(store *Store) error {
	return fixtureLargeRelease(store)
}

// FixtureCleanupReadbackDrift changes one retained cleanup artifact after commit.
// Only the three frozen physical shapes reach the existing fixed-mode owner.
func FixtureCleanupReadbackDrift(store *Store, rank uint8, key []byte, run func()) (uint32, error) {
	valid := rank == 4 && len(key) == 32 || rank == 5 && (len(key) == 33 || len(key) == 77)
	if store == nil || run == nil || !valid {
		return 0, errors.New("invalid cleanup readback fixture")
	}
	evidence, err := fixtureLargeFault(store, 3, rank, key, run)
	return evidence.drift, err
}

// FixtureWriteSnapshotDrift drifts one armed row to 0x7f before the write-transaction begin (large-image mode 14)
// while run executes, and returns the drift count.
func FixtureWriteSnapshotDrift(store *Store, rank uint8, key []byte, run func()) (uint32, error) {
	if store == nil || run == nil || rank >= 8 || len(key) == 0 {
		return 0, errors.New("invalid write snapshot drift fixture")
	}
	evidence, err := fixtureLargeFault(store, 14, rank, key, run)
	return evidence.drift, err
}

// FixtureCleanupInvalidStage0 delegates one malformed outcome to the real owner.
func FixtureCleanupInvalidStage0(store *Store, cleanup error) (CommitTruth, UpdateStage, error) {
	if store == nil || cleanup == nil || !store.operations.TryLock() {
		return CommitTruthOld, UpdateStagePrewrite, errors.New("invalid cleanup outcome fixture")
	}
	defer store.operations.Unlock()
	if store.state != storeOPEN || !validStoreShape(store) {
		return CommitTruthOld, UpdateStagePrewrite, errors.New("invalid cleanup outcome fixture")
	}
	return store.applyUpdateOutcome(updateNativeOutcome{truth: CommitTruthOld}, nil, cleanup, false)
}

// Test teardown disposes a real retained handle after its terminal projection was observed.
func fixtureLargeRelease(store *Store) error {
	var err error
	switch store.state {
	case storePOISONEDTHREAD:
		if err := fixtureResult(operationAbort, int(C.rubin_fixture_txn_abort(store.txn))); err != nil {
			return err
		}
		store.txn = nil
		_, err = store.consume(store.terminal)
	case storeCLOSEBLOCKED:
		err = store.Close()
	}
	if store.state != storeCLOSED {
		return err
	}
	return nil
}

func fixtureDeletePrefixRow(store *Store, dbi DBI, key []byte) error {
	return fixtureWrite(store, operationInit, func(txn *C.MDBX_txn) error {
		rc := int(C.rubin_fixture_del(txn, store.dbis[dbi.Rank], unsafe.Pointer(&key[0]), C.size_t(len(key))))
		runtime.KeepAlive(key)
		return fixtureResult(operationInit, rc)
	})
}

// fixtureLegacySchemaEnvironment creates a store at path, rewrites it into the retired seven-DBI shape (canonical-owner-v1
// dropped from the main DB) carrying version value 00000001, and closes it. It is test-only persisted-image injection.
func fixtureLegacySchemaEnvironment(path string, cfg ConfigV1) error {
	store, err := Create(path, cfg)
	if err != nil {
		return err
	}
	meta := store.dbis[0]
	err = fixtureWrite(store, operationOpen, func(txn *C.MDBX_txn) error {
		return fixtureResult(operationOpen, int(C.rubin_fixture_schema_v1(txn, meta)))
	})
	return joinErrors(err, store.Close())
}

func fixturePrefixNativeShape(dbi DBI, prefix, seek []byte, mode uint32) error {
	result := C.rubin_fixture_prefix_shape(C.uint(mode))
	_, err := prefixPageNativeRow(dbi, prefix, seek, int(result.rc), unsafe.Pointer(result.key_bytes), result.key_len, unsafe.Pointer(result.value_bytes), result.value_len)
	return err
}

func fixturePrefixNativeAddresses(reader *Reader, dbi DBI, key []byte, valueLength int) (unsafe.Pointer, unsafe.Pointer, error) {
	result := C.rubin_fixture_prefix_address(reader.txn, reader.dbis[dbi.Rank], unsafe.Pointer(&key[0]), C.size_t(len(key)))
	runtime.KeepAlive(key)
	if int(result.rc) != codeSuccess || result.key_bytes == nil || result.key_len != C.size_t(len(key)) || result.value_bytes == nil || result.value_len != C.size_t(valueLength) {
		return nil, nil, errors.New("fixture lower-bound address result was not exact")
	}
	return unsafe.Pointer(result.key_bytes), unsafe.Pointer(result.value_bytes), nil
}

func fixtureBreakPrefixReader(reader *Reader) error {
	return fixtureResult(operationPrefixPage, int(C.mdbx_txn_break(reader.txn)))
}

func reopenAfterFixture(path string, cfg ConfigV1, store *Store, primary error) (*Store, error) {
	if err := joinErrors(primary, store.Close()); err != nil {
		return nil, err
	}
	return Open(path, cfg)
}

func fixtureShapeRejected(store *Store, mutate, restore func()) bool {
	mutate()
	self, env, writer, txn, cfg, dbis, state, terminal := store.self, store.env, store.writer, store.txn, store.config, store.dbis, store.state, store.terminal
	err := store.Close()
	unchanged := fixtureStoreSnapshotMatches(store, self, env, writer, txn, cfg, dbis, state, terminal)
	restore()
	return unchanged && fixtureShapeError(err)
}

func fixtureStoreSnapshotMatches(store, self *Store, env *C.MDBX_env, writer *filelock.Handle, txn *C.MDBX_txn, cfg ConfigV1, dbis [8]C.MDBX_dbi, state storeState, terminal error) bool {
	return store.self == self && store.env == env && store.writer == writer && store.txn == txn && store.config == cfg && store.dbis == dbis && store.state == state && store.terminal == terminal
}

func fixtureShapeError(err error) bool {
	engine, ok := err.(*EngineError)
	return ok && engine != nil && engine.Class == EngineLocalInvariant && engine.Code == codeProblem && engine.Diagnostic == "invalid Store resource shape"
}

func fixtureCloseBusy(path string, store *Store) (error, error, error) {
	var first error
	var held *C.MDBX_txn
	_, abortErr := fixtureHeldWrite(store, func(txn *C.MDBX_txn) (int, bool) {
		held = txn
		self, env, writer, cfg, dbis := store.self, store.env, store.writer, store.config, store.dbis
		validOpen := fixtureShapeRejected(store, func() { store.txn = txn }, func() { store.txn = nil })
		poison := nativeError(operationInit, codeThreadMismatch)
		store.state, store.txn, store.config, store.dbis, store.terminal = storePOISONEDTHREAD, txn, ConfigV1{}, [8]C.MDBX_dbi{}, poison
		validPoison := store.Close() == poison
		poisonShapes := []struct{ mutate, restore func() }{
			{func() { store.env = nil }, func() { store.env = env }},
			{func() { store.writer = nil }, func() { store.writer = writer }},
			{func() { store.txn = nil }, func() { store.txn = txn }},
			{func() { store.config = cfg }, func() { store.config = ConfigV1{} }},
			{func() { store.dbis = dbis }, func() { store.dbis = [8]C.MDBX_dbi{} }},
			{func() { store.terminal = nil }, func() { store.terminal = poison }},
			{func() { store.self = nil }, func() { store.self = self }},
		}
		for _, shape := range poisonShapes {
			validPoison = fixtureShapeRejected(store, shape.mutate, shape.restore) && validPoison
		}
		store.state, store.txn, store.config, store.dbis, store.terminal = storeOPEN, nil, cfg, dbis, nil
		first = store.Close()
		again := store.Close()
		engine, ok := first.(*EngineError)
		if ok && engine != nil && engine.Code == codeBusy {
			terminal := store.terminal
			shapes := []struct{ mutate, restore func() }{
				{func() { store.env = nil }, func() { store.env = env }},
				{func() { store.writer = nil }, func() { store.writer = writer }},
				{func() { store.txn = txn }, func() { store.txn = nil }},
				{func() { store.config = ConfigV1{} }, func() { store.config = cfg }},
				{func() { store.dbis = [8]C.MDBX_dbi{} }, func() { store.dbis = dbis }},
				{func() { store.terminal = nil }, func() { store.terminal = terminal }},
				{func() { store.self = nil }, func() { store.self = self }},
			}
			validShapes := true
			for _, shape := range shapes {
				validShapes = fixtureShapeRejected(store, shape.mutate, shape.restore) && validShapes
			}
			construction := orderedErrors(operationClose, orderResultCausesPrimary, errors.New("construction"), nativeError(operationClose, codeBusy))
			store.config, store.dbis, store.terminal = ConfigV1{}, [8]C.MDBX_dbi{}, construction
			validConstruction := store.Close() == construction
			constructionShapes := []struct{ mutate, restore func() }{
				{func() { store.env = nil }, func() { store.env = env }},
				{func() { store.writer = nil }, func() { store.writer = writer }},
				{func() { store.txn = txn }, func() { store.txn = nil }},
				{func() { store.config = cfg }, func() { store.config = ConfigV1{} }},
				{func() { store.dbis = dbis }, func() { store.dbis = [8]C.MDBX_dbi{} }},
				{func() { store.terminal = nativeError(operationClose, codeBusy) }, func() { store.terminal = construction }},
				{func() { store.self = nil }, func() { store.self = self }},
			}
			for _, shape := range constructionShapes {
				validConstruction = fixtureShapeRejected(store, shape.mutate, shape.restore) && validConstruction
			}
			store.config, store.dbis, store.terminal = cfg, dbis, terminal
			handle, result, lockErr := filelock.AcquireDirectory(path)
			_ = releaseError(handle)
			if store.state != storeCLOSEBLOCKED || store.env == nil || store.writer == nil || store.terminal != first || again != first || !validOpen || !validPoison || !validShapes || !validConstruction || result != filelock.ResultContended || lockErr == nil || handle != nil {
				first = adapterError(operationClose, EngineLocalInvariant, codeProblem, "invalid Store resource shape", first)
			}
			return codeBusy, false
		}
		return codeSuccess, true
	})
	closeErr := store.Close()
	if closeErr == nil && !fixtureShapeRejected(store, func() { store.txn = held }, func() { store.txn = nil }) {
		closeErr = adapterError(operationClose, EngineLocalInvariant, codeProblem, "CLOSED txn shape was accepted", nil)
	}
	return first, abortErr, closeErr
}

func fixtureWriteOwnerMismatch(store *Store) (int, error) {
	return fixtureHeldWrite(store, func(txn *C.MDBX_txn) (int, bool) {
		rc := int(C.rubin_fixture_txn_commit(txn))
		return rc, commitTransition(rc).consumed
	})
}

func fixtureHeldWrite(store *Store, attempt func(*C.MDBX_txn) (int, bool)) (int, error) {
	ready, consumed, cleanup := make(chan *C.MDBX_txn, 1), make(chan bool, 1), make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		begun := C.rubin_fixture_txn_begin(store.env, C.MDBX_TXN_READWRITE)
		if err := nativePointerResultError(operationInit, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil); err != nil {
			ready <- nil
			cleanup <- err
			runtime.UnlockOSThread()
			return
		}
		ready <- begun.txn
		var err error
		if !<-consumed {
			err = fixtureResult(operationAbort, int(C.rubin_fixture_txn_abort(begun.txn)))
		}
		cleanup <- err
		runtime.UnlockOSThread()
	}()
	txn := <-ready
	if txn == nil {
		return codeProblem, <-cleanup
	}
	rc, wasConsumed := attempt(txn)
	consumed <- wasConsumed
	return rc, <-cleanup
}

func fixtureHeldUpdate(store *Store) (*C.MDBX_txn, func() error, error) {
	ready, release, cleanup := make(chan *C.MDBX_txn, 1), make(chan struct{}), make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		begun := C.rubin_fixture_txn_begin(store.env, C.MDBX_TXN_READWRITE)
		if err := nativePointerResultError(operationInit, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil); err != nil {
			ready <- nil
			cleanup <- err
			return
		}
		ready <- begun.txn
		<-release
		cleanup <- fixtureResult(operationAbort, int(C.rubin_fixture_txn_abort(begun.txn)))
	}()
	txn := <-ready
	if txn == nil {
		return nil, nil, <-cleanup
	}
	return txn, func() error { close(release); return <-cleanup }, nil
}

func fixtureUpdateWrongThread(store *Store) (updateNativeOutcome, func() error, error) {
	txn, release, err := fixtureHeldUpdate(store)
	if err != nil {
		return updateNativeConsumed(CommitTruthOld, false, err, nil, 1), nil, err
	}
	return updateNativeCommit(store.env, store.dbis, nil, nil, nil, txn, 1), release, nil
}

func fixtureUpdateAbortWrongThread(store *Store) (updateNativeOutcome, func() error, error) {
	txn, release, err := fixtureHeldUpdate(store)
	if err != nil {
		return updateNativeConsumed(CommitTruthOld, false, err, nil, 1), nil, err
	}
	return updateNativeAbort(txn, nativeError(operationUpdate, codeNotFound), 1), release, nil
}

func fixtureUpdateResultTrue(store *Store, plan []ownedMutation) updateNativeOutcome {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	old := C.rubin_fixture_txn_begin(store.env, C.MDBX_TXN_RDONLY)
	if err := nativePointerResultError(operationUpdate, "mdbx_txn_begin returned invalid result shape", int(old.rc), old.txn != nil); err != nil {
		return updateNativeConsumed(CommitTruthOld, false, err, nil, 1)
	}
	defer C.rubin_fixture_txn_abort(old.txn)
	begun := C.rubin_fixture_txn_begin(store.env, C.MDBX_TXN_READWRITE)
	if err := nativePointerResultError(operationUpdate, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil); err != nil {
		if begun.txn != nil {
			return updateNativeRetainedWrite(false, err, nil, begun.txn, 1)
		}
		return updateNativeConsumed(CommitTruthOld, false, err, nil, 1)
	}
	if rc := int(C.mdbx_txn_break(begun.txn)); rc != codeSuccess {
		return updateNativeAbort(begun.txn, nativeError(operationUpdate, rc), 1)
	}
	return updateNativeCommit(store.env, store.dbis, plan, nil, old.txn, begun.txn, 1)
}

func fixtureCleanNew(outcome updateNativeOutcome) bool {
	return outcome.valid() == nil && outcome.truth == CommitTruthNew && outcome.commitAttempted && outcome.primary == nil && outcome.secondary == nil && outcome.retainedWrite == nil && outcome.retainedRead == nil
}

func fixtureCommittedUpdate(store *Store, plan []ownedMutation, old *C.MDBX_txn) (updateNativeOutcome, error) {
	outcome := updateNativeExecute(store.env, store.dbis, plan, nil, old)
	if !fixtureCleanNew(outcome) {
		return outcome, updateNativeInvariant("fixed post-commit fixture did not finish one write")
	}
	return outcome, nil
}

func fixtureUpdatePostCommitENOSPC(store *Store, plan []ownedMutation) (updateNativeOutcome, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	old := C.rubin_fixture_txn_begin(store.env, C.MDBX_TXN_RDONLY)
	if err := nativePointerResultError(operationUpdate, "mdbx_txn_begin returned invalid result shape", int(old.rc), old.txn != nil); err != nil {
		return updateNativeConsumed(CommitTruthOld, false, err, nil, 1), err
	}
	committed, err := fixtureCommittedUpdate(store, plan, old.txn)
	if err != nil {
		_ = C.rubin_fixture_txn_abort(old.txn)
		return committed, err
	}
	outcome := updateNativeReadback(store.env, store.dbis, plan, nil, old.txn, nativeError(operationUpdate, codeENOSPC))
	if rc := int(C.rubin_fixture_txn_abort(old.txn)); rc != codeSuccess {
		return outcome, nativeError(operationAbort, rc)
	}
	return outcome, nil
}

func fixtureUpdatePostCommitENOSPCUnreadable(store *Store, plan []ownedMutation) (updateNativeOutcome, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	old := C.rubin_fixture_txn_begin(store.env, C.MDBX_TXN_RDONLY)
	if err := nativePointerResultError(operationUpdate, "mdbx_txn_begin returned invalid result shape", int(old.rc), old.txn != nil); err != nil {
		return updateNativeConsumed(CommitTruthOld, false, err, nil, 1), err
	}
	committed, err := fixtureCommittedUpdate(store, plan, old.txn)
	if err != nil {
		_ = C.rubin_fixture_txn_abort(old.txn)
		return committed, err
	}
	dbis := store.dbis
	dbis[plan[0].dbi.Rank] = ^C.MDBX_dbi(0)
	outcome := updateNativeReadback(store.env, dbis, plan, nil, old.txn, nativeError(operationUpdate, codeENOSPC))
	if rc := int(C.rubin_fixture_txn_abort(old.txn)); rc != codeSuccess {
		return outcome, nativeError(operationAbort, rc)
	}
	return outcome, nil
}

func fixtureUpdatePostCommitENOSPCThird(store *Store, plan []ownedMutation) (updateNativeOutcome, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	old := C.rubin_fixture_txn_begin(store.env, C.MDBX_TXN_RDONLY)
	if err := nativePointerResultError(operationUpdate, "mdbx_txn_begin returned invalid result shape", int(old.rc), old.txn != nil); err != nil {
		return updateNativeConsumed(CommitTruthOld, false, err, nil, 1), err
	}
	committed, err := fixtureCommittedUpdate(store, plan, old.txn)
	if err != nil {
		_ = C.rubin_fixture_txn_abort(old.txn)
		return committed, err
	}
	write := C.rubin_fixture_txn_begin(store.env, C.MDBX_TXN_READWRITE)
	if err := nativePointerResultError(operationUpdate, "mdbx_txn_begin returned invalid result shape", int(write.rc), write.txn != nil); err != nil {
		_ = C.rubin_fixture_txn_abort(old.txn)
		return updateNativeConsumed(CommitTruthUnknown, true, err, nil, 3), err
	}
	third, mutation := []byte{0x7f}, plan[0]
	rc := int(C.rubin_fixture_put(write.txn, store.dbis[mutation.dbi.Rank], unsafe.Pointer(&mutation.key[0]), C.size_t(len(mutation.key)), unsafe.Pointer(&third[0]), C.size_t(len(third))))
	runtime.KeepAlive(mutation)
	runtime.KeepAlive(third)
	if rc != codeSuccess {
		_ = C.rubin_fixture_txn_abort(write.txn)
		_ = C.rubin_fixture_txn_abort(old.txn)
		return updateNativeConsumed(CommitTruthUnknown, true, nativeError(operationUpdate, rc), nil, 3), nativeError(operationUpdate, rc)
	}
	if rc = int(C.rubin_fixture_txn_commit(write.txn)); rc != codeSuccess {
		_ = C.rubin_fixture_txn_abort(old.txn)
		return updateNativeConsumed(CommitTruthUnknown, true, nativeError(operationUpdate, rc), nil, 3), nativeError(operationUpdate, rc)
	}
	outcome := updateNativeReadback(store.env, store.dbis, plan, nil, old.txn, nativeError(operationUpdate, codeENOSPC))
	if rc = int(C.rubin_fixture_txn_abort(old.txn)); rc != codeSuccess {
		return outcome, nativeError(operationAbort, rc)
	}
	return outcome, nil
}

func fixtureUpdatePostCommitENOSPCMissing(store *Store, plan []ownedMutation) (updateNativeOutcome, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	old := C.rubin_fixture_txn_begin(store.env, C.MDBX_TXN_RDONLY)
	if err := nativePointerResultError(operationUpdate, "mdbx_txn_begin returned invalid result shape", int(old.rc), old.txn != nil); err != nil {
		return updateNativeConsumed(CommitTruthOld, false, err, nil, 1), err
	}
	committed, err := fixtureCommittedUpdate(store, plan, old.txn)
	if err != nil {
		_ = C.rubin_fixture_txn_abort(old.txn)
		return committed, err
	}
	write := C.rubin_fixture_txn_begin(store.env, C.MDBX_TXN_READWRITE)
	if err := nativePointerResultError(operationUpdate, "mdbx_txn_begin returned invalid result shape", int(write.rc), write.txn != nil); err != nil {
		_ = C.rubin_fixture_txn_abort(old.txn)
		return updateNativeConsumed(CommitTruthUnknown, true, err, nil, 3), err
	}
	mutation := plan[0]
	rc := int(C.rubin_fixture_del(write.txn, store.dbis[mutation.dbi.Rank], unsafe.Pointer(&mutation.key[0]), C.size_t(len(mutation.key))))
	runtime.KeepAlive(mutation)
	if rc != codeSuccess {
		_ = C.rubin_fixture_txn_abort(write.txn)
		_ = C.rubin_fixture_txn_abort(old.txn)
		return updateNativeConsumed(CommitTruthUnknown, true, nativeError(operationUpdate, rc), nil, 3), nativeError(operationUpdate, rc)
	}
	if rc = int(C.rubin_fixture_txn_commit(write.txn)); rc != codeSuccess {
		_ = C.rubin_fixture_txn_abort(old.txn)
		return updateNativeConsumed(CommitTruthUnknown, true, nativeError(operationUpdate, rc), nil, 3), nativeError(operationUpdate, rc)
	}
	outcome := updateNativeReadback(store.env, store.dbis, plan, nil, old.txn, nativeError(operationUpdate, codeENOSPC))
	if rc = int(C.rubin_fixture_txn_abort(old.txn)); rc != codeSuccess {
		return outcome, nativeError(operationAbort, rc)
	}
	return outcome, nil
}

func fixtureOpenReverseUTXO(path string) (*Store, []byte, error) {
	cfg := ConfigV1{1 << 20, 2 << 20, 256 << 20, 1 << 20, 2 << 20, 4096, 492}
	store, err := Create(path, cfg)
	if err != nil {
		return store, nil, err
	}
	var copied []byte
	meta := store.dbis[0]
	read := func(txn *C.MDBX_txn) error {
		var readErr error
		copied, readErr = getSizedValue(txn, meta, []byte{1}, 48, operationOpen)
		return readErr
	}
	copyTxnErr := fixtureWrite(store, operationOpen, read)
	mutationErr := fixtureWrite(store, operationOpen, func(txn *C.MDBX_txn) error {
		return fixtureResult(operationOpen, int(C.rubin_fixture_reverse_utxo(txn)))
	})
	opened, err := reopenAfterFixture(path, cfg, store, joinErrors(copyTxnErr, mutationErr))
	return opened, copied, err
}

func fixtureOpenStoredReadersMismatch(path string) (*Store, error) {
	cfg := ConfigV1{1 << 20, 2 << 20, 256 << 20, 1 << 20, 2 << 20, 4096, 492}
	store, err := Create(path, cfg)
	if err != nil {
		return store, err
	}
	addErr := fixtureWrite(store, operationOpen, func(txn *C.MDBX_txn) error {
		return fixtureResult(operationOpen, int(C.rubin_fixture_add_rows(txn, store.dbis[0], store.dbis[2])))
	})
	if store, err = reopenAfterFixture(path, cfg, store, addErr); err != nil {
		return store, err
	}
	mutationErr := fixtureWrite(store, operationOpen, func(txn *C.MDBX_txn) error {
		return fixtureResult(operationOpen, int(C.rubin_fixture_check_and_reconfigure(txn, store.dbis[0], store.dbis[2])))
	})
	return reopenAfterFixture(path, cfg, store, mutationErr)
}

// FixtureSeedRawRow writes one raw row of any width into the SchemaV2 DBI of rank; consensus fixture tests use it to
// persist damaged images (wrong width, wrong hash, unpaired owner row) that the ordinary Update grammar refuses.
func FixtureSeedRawRow(store *Store, rank uint8, key, value []byte) error {
	return fixtureSeedPrefixRawRow(store, schemaDBIs[rank], key, value)
}

// FixtureStartupDeleteRow creates a definitive absence through the existing raw
// writer, rather than confusing a zero-width stored value with NOTFOUND.
func FixtureStartupDeleteRow(store *Store, rank uint8, key []byte) error {
	if int(rank) >= len(schemaDBIs) {
		return errors.New("invalid startup deletion fixture")
	}
	return fixtureDeletePrefixRow(store, schemaDBIs[rank], key)
}

// FixtureRawRowEqual reports whether the committed row (rank, key) is exactly want (nil means absent), reading the
// native value in one fixture read transaction and comparing it with memcmp: no SchemaV2 width bound, no Go copy.
func FixtureRawRowEqual(store *Store, rank uint8, key, want []byte) (bool, error) {
	store.operations.Lock()
	defer store.operations.Unlock()
	var wantBytes unsafe.Pointer
	if len(want) != 0 {
		wantBytes = unsafe.Pointer(&want[0])
	}
	present, equal := C.int(0), C.int(0)
	if want != nil {
		present = 1
	}
	rc := int(C.rubin_fixture_row_equal(store.env, store.dbis[rank], unsafe.Pointer(&key[0]), C.size_t(len(key)), present, wantBytes, C.size_t(len(want)), &equal))
	runtime.KeepAlive(key)
	runtime.KeepAlive(want)
	return equal != 0, fixtureResult(operationView, rc)
}

// fixtureOptionalSideShape evaluates optionalSideResult for one literal native tuple. present supplies a non-nil
// one-byte pointer, so callers pass only tuples that the decision refuses before any copy.
func fixtureOptionalSideShape(dbi DBI, rc int, present bool, length uint64) (OptionalSideValueV1, error) {
	var anchor [1]byte
	var value unsafe.Pointer
	if present {
		value = unsafe.Pointer(&anchor[0])
	}
	return optionalSideResult(dbi, make([]byte, 32), rc, value, C.size_t(length))
}

// SelectedDamageScenario is one closed native-boundary scenario of the fixture-only mdbx_cgo.go preamble block; its
// values are that block's scenario numbers.
type SelectedDamageScenario uint32

const (
	SelectedDamageProbeOnly SelectedDamageScenario = iota + 1
	SelectedDamageBeginTxnFull
	SelectedDamageBeginEIO
	SelectedDamageGetEIO
	SelectedDamageGetAbortEIO
	SelectedDamageDeleteEIO
	SelectedDamageCommitOld
	SelectedDamageCommitNew
	SelectedDamageCommitUnreadable
	SelectedDamageCommitThird
	SelectedDamageAbortEIO
	SelectedDamagePutEIO
	SelectedDamageWriteBeginTxnFull
	SelectedDamageStartupPullEIO
)

// SelectedDamageEvidence is the bounded native evidence of one armed invocation: site counters, injected faults and
// the full-lane probe observations at post-plan write begin, commit, readback begin and around the OLD abort.
type SelectedDamageEvidence struct {
	BeginOld, BeginWrite, BeginRead uint64
	OldGets                         [8]uint64
	OldPulls                        [8]uint64
	ReadGets, Faults, Deletes       uint64
	Commits, OldAborts              uint64
	Probes, ProbeDenied, ProbeRan   uint64
}

type selectedDamageProbe struct {
	owner               *OperationReservationOwner
	probes, denied, ran uint64
}

var selectedDamageMu sync.Mutex

// rubinSelectedDamageProbe is the fixed synchronous reservation probe: one competing full-lane WithReservation whose
// callback only counts; it touches no Store, spawns nothing and never panics.
//
//export rubinSelectedDamageProbe
func rubinSelectedDamageProbe(handle C.uintptr_t) {
	probe := cgo.Handle(handle).Value().(*selectedDamageProbe)
	probe.probes++
	if probe.owner.WithReservation(MaxOperationDataBytes, func() error { probe.ran++; return nil }) == errOperationReservationCapacity { //nolint:errorlint // The owner's exact capacity refusal.
		probe.denied++
	}
}

// FixtureSelectedDamage arms one closed scenario on store's environment, runs run (which must invoke the actual
// selected-side operation or VerifyPersistedReplayStartupMDBX and keep its return), disarms even on panic and reports the native evidence. key is copied
// into C during arming. A setup failure, a fault site not reached exactly as armed or a failed native bridge step is
// the returned error, never a selected outcome. Invocations are serialized.
func FixtureSelectedDamage(store *Store, reservations *OperationReservationOwner, scenario SelectedDamageScenario, rank uint8, key []byte, run func()) (evidence SelectedDamageEvidence, err error) {
	selectedDamageMu.Lock()
	defer selectedDamageMu.Unlock()
	if !validSelectedDamageFixture(store, scenario, rank, run) {
		return evidence, errors.New("invalid selected damage fixture")
	}
	probe := &selectedDamageProbe{owner: reservations}
	handle := cgo.NewHandle(probe)
	defer handle.Delete()
	var keyBytes unsafe.Pointer
	if len(key) != 0 {
		keyBytes = unsafe.Pointer(&key[0])
	}
	armed := C.rubin_sd_arm(store.env, C.uint(scenario), &store.dbis[0], store.dbis[rank], keyBytes, C.size_t(len(key)), C.uintptr_t(handle))
	runtime.KeepAlive(key)
	if armed != 0 {
		return evidence, errors.New("selected damage fixture is already armed")
	}
	defer func() {
		var counts C.rubin_sd_counts
		C.rubin_sd_disarm(&counts)
		evidence, err = selectedDamageEvidence(scenario, counts, probe)
	}()
	run()
	return evidence, nil
}

func validSelectedDamageFixture(store *Store, scenario SelectedDamageScenario, rank uint8, run func()) bool {
	return store != nil && store.env != nil && int(rank) < len(schemaDBIs) && scenario >= SelectedDamageProbeOnly && scenario <= SelectedDamageStartupPullEIO && run != nil
}

func selectedDamageEvidence(scenario SelectedDamageScenario, counts C.rubin_sd_counts, probe *selectedDamageProbe) (SelectedDamageEvidence, error) {
	evidence := SelectedDamageEvidence{
		BeginOld: uint64(counts.begin_old), BeginWrite: uint64(counts.begin_write), BeginRead: uint64(counts.begin_read),
		ReadGets: uint64(counts.read_gets), Faults: uint64(counts.faults), Deletes: uint64(counts.dels), Commits: uint64(counts.commits),
		OldAborts: uint64(counts.old_aborts), Probes: probe.probes, ProbeDenied: probe.denied, ProbeRan: probe.ran,
	}
	for i := range evidence.OldGets {
		evidence.OldGets[i] = uint64(counts.old_gets[i])
		evidence.OldPulls[i] = uint64(counts.old_pulls[i])
	}
	want := uint64(1)
	switch scenario {
	case SelectedDamageProbeOnly:
		want = 0
	case SelectedDamageGetAbortEIO, SelectedDamageCommitUnreadable:
		want = 2
	}
	if evidence.Faults != want || counts.bridge_error != 0 {
		return evidence, errors.New("selected damage fixture site was not reached exactly as armed")
	}
	return evidence, nil
}
