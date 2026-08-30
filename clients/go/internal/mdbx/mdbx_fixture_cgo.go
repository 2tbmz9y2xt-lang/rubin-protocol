//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

/*
#cgo CFLAGS: -std=c11
#include "../../../../third_party/libmdbx/mdbx.h"
#include <string.h>
typedef struct { int rc; MDBX_txn *txn; } rubin_fixture_txn_result;
static rubin_fixture_txn_result rubin_fixture_txn_begin(MDBX_env *env, MDBX_txn_flags_t flags) { rubin_fixture_txn_result result = {0, NULL}; result.rc = mdbx_txn_begin(env, NULL, flags, &result.txn); return result; }
typedef struct { int rc; const char *path; } rubin_fixture_path_result;
static rubin_fixture_path_result rubin_fixture_txn_path(MDBX_txn *txn) { rubin_fixture_path_result result = {MDBX_INVALID, NULL}; MDBX_env *env = mdbx_txn_env(txn); if (env) result.rc = mdbx_env_get_path(env, &result.path); return result; }
static int rubin_fixture_named(MDBX_txn *txn) { MDBX_dbi dbi; return mdbx_dbi_open(txn, "fixture-v1", MDBX_DB_DEFAULTS | MDBX_CREATE, &dbi); }
static int rubin_fixture_meta(MDBX_txn *txn, MDBX_dbi meta) { const unsigned char key = 2; MDBX_val k = {(void *)&key, 1}, v = {NULL, 0}; return mdbx_put(txn, meta, &k, &v, MDBX_NOOVERWRITE); }
static int rubin_fixture_main_row(MDBX_txn *txn) { MDBX_dbi main; const char key[] = "fixture-main-row", value[] = "ordinary"; MDBX_val k = {(void *)key, sizeof(key) - 1}, v = {(void *)value, sizeof(value) - 1}; int rc = mdbx_dbi_open(txn, NULL, MDBX_DB_DEFAULTS, &main); return rc == MDBX_SUCCESS ? mdbx_put(txn, main, &k, &v, MDBX_UPSERT) : rc; }
static int rubin_fixture_schema_version(MDBX_txn *txn, MDBX_dbi meta) { const unsigned char key = 0, value[4] = {0, 0, 0, 2}; MDBX_val k = {(void *)&key, 1}, v = {(void *)value, 4}; return mdbx_put(txn, meta, &k, &v, MDBX_UPSERT); }
static int rubin_fixture_reverse_utxo(MDBX_txn *txn) { MDBX_dbi dbi; int rc = mdbx_dbi_open(txn, "utxo-v1", MDBX_DB_DEFAULTS, &dbi); if (rc == MDBX_SUCCESS) rc = mdbx_drop(txn, dbi, true); return rc == MDBX_SUCCESS ? mdbx_dbi_open(txn, "utxo-v1", MDBX_REVERSEKEY | MDBX_CREATE, &dbi) : rc; }
static int rubin_fixture_add_rows(MDBX_txn *txn, MDBX_dbi meta, MDBX_dbi canonical) { const unsigned char mk = 2, mv = 0x42, ak[16] = {1}, av[104] = {1}; MDBX_val mkey = {(void *)&mk, 1}, mval = {(void *)&mv, 1}, akey = {(void *)ak, 16}, aval = {(void *)av, 104}; int rc = mdbx_put(txn, meta, &mkey, &mval, MDBX_NOOVERWRITE); return rc == MDBX_SUCCESS ? mdbx_put(txn, canonical, &akey, &aval, MDBX_NOOVERWRITE) : rc; }
static int rubin_fixture_check_rows(MDBX_txn *txn, MDBX_dbi meta, MDBX_dbi canonical) { const unsigned char mk = 2, mv = 0x42, ak[16] = {1}, av[104] = {1}; MDBX_val mkey = {(void *)&mk, 1}, akey = {(void *)ak, 16}, got; int rc = mdbx_get(txn, meta, &mkey, &got); if (rc == MDBX_SUCCESS && (got.iov_len != 1 || memcmp(got.iov_base, &mv, 1))) rc = MDBX_INVALID; if (rc == MDBX_SUCCESS) rc = mdbx_get(txn, canonical, &akey, &got); return rc == MDBX_SUCCESS && (got.iov_len != 104 || memcmp(got.iov_base, av, 104)) ? MDBX_INVALID : rc; }
static int rubin_fixture_readers_493(MDBX_txn *txn, MDBX_dbi meta) { const unsigned char key = 1, value[48] = {0,0,0,0,0,0x10,0,0, 0,0,0,0,0,0x20,0,0, 0,0,0,0,0x10,0,0,0, 0,0,0,0,0,0x10,0,0, 0,0,0,0,0,0x20,0,0, 0,0,0x10,0, 0,0,1,0xed}; MDBX_val k = {(void *)&key, 1}, v = {(void *)value, 48}; return mdbx_put(txn, meta, &k, &v, MDBX_UPSERT); }
static int rubin_fixture_check_and_reconfigure(MDBX_txn *txn, MDBX_dbi meta, MDBX_dbi canonical) { int rc = rubin_fixture_check_rows(txn, meta, canonical); return rc == MDBX_SUCCESS ? rubin_fixture_readers_493(txn, meta) : rc; }
*/
import "C"

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

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
	store.operations.RLock()
	defer store.operations.RUnlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	begun := C.rubin_fixture_txn_begin(store.env, C.MDBX_TXN_READWRITE)
	if err := nativePointerResultError(operation, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil); err != nil {
		return err
	}
	if primary := mutate(begun.txn); primary != nil {
		abortRC := int(C.mdbx_txn_abort(begun.txn))
		return joinErrors(primary, fixtureResult(operationAbort, abortRC))
	}
	return fixtureResult(operation, int(C.mdbx_txn_commit(begun.txn)))
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

func fixtureStoreSnapshotMatches(store, self *Store, env *C.MDBX_env, writer *filelock.Handle, txn *C.MDBX_txn, cfg ConfigV1, dbis [7]C.MDBX_dbi, state storeState, terminal error) bool {
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
		store.state, store.txn, store.config, store.dbis, store.terminal = storePOISONEDTHREAD, txn, ConfigV1{}, [7]C.MDBX_dbi{}, poison
		validPoison := store.Close() == poison
		poisonShapes := []struct{ mutate, restore func() }{
			{func() { store.env = nil }, func() { store.env = env }},
			{func() { store.writer = nil }, func() { store.writer = writer }},
			{func() { store.txn = nil }, func() { store.txn = txn }},
			{func() { store.config = cfg }, func() { store.config = ConfigV1{} }},
			{func() { store.dbis = dbis }, func() { store.dbis = [7]C.MDBX_dbi{} }},
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
				{func() { store.dbis = [7]C.MDBX_dbi{} }, func() { store.dbis = dbis }},
				{func() { store.terminal = nil }, func() { store.terminal = terminal }},
				{func() { store.self = nil }, func() { store.self = self }},
			}
			validShapes := true
			for _, shape := range shapes {
				validShapes = fixtureShapeRejected(store, shape.mutate, shape.restore) && validShapes
			}
			construction := orderedErrors(operationClose, orderResultCausesPrimary, errors.New("construction"), nativeError(operationClose, codeBusy))
			store.config, store.dbis, store.terminal = ConfigV1{}, [7]C.MDBX_dbi{}, construction
			validConstruction := store.Close() == construction
			constructionShapes := []struct{ mutate, restore func() }{
				{func() { store.env = nil }, func() { store.env = env }},
				{func() { store.writer = nil }, func() { store.writer = writer }},
				{func() { store.txn = txn }, func() { store.txn = nil }},
				{func() { store.config = cfg }, func() { store.config = ConfigV1{} }},
				{func() { store.dbis = dbis }, func() { store.dbis = [7]C.MDBX_dbi{} }},
				{func() { store.terminal = nativeError(operationClose, codeBusy) }, func() { store.terminal = construction }},
				{func() { store.self = nil }, func() { store.self = self }},
			}
			for _, shape := range constructionShapes {
				validConstruction = fixtureShapeRejected(store, shape.mutate, shape.restore) && validConstruction
			}
			store.config, store.dbis, store.terminal = cfg, dbis, terminal
			handle, result, lockErr := filelock.Acquire(filepath.Join(path, "rubin-writer.lock"))
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
		rc := int(C.mdbx_txn_commit(txn))
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
			err = fixtureResult(operationAbort, int(C.mdbx_txn_abort(begun.txn)))
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
