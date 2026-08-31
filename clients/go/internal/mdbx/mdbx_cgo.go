//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

/*
#cgo CFLAGS: -std=c11
#include "../../../../third_party/libmdbx/mdbx.h"
typedef struct { int first; int second; } rubin_mdbx_debug_result;
static rubin_mdbx_debug_result rubin_mdbx_normalize_debug(void) {
	rubin_mdbx_debug_result result = {MDBX_PROBLEM, MDBX_PROBLEM};
	result.first = mdbx_setup_debug(MDBX_LOG_NOTICE, MDBX_DBG_NONE, NULL);
	result.second = mdbx_setup_debug(MDBX_LOG_NOTICE, MDBX_DBG_NONE, NULL);
	return result;
}
typedef struct { int rc; MDBX_env *env; } rubin_mdbx_env_result;
static rubin_mdbx_env_result rubin_mdbx_env_create(void) { rubin_mdbx_env_result result = {0, NULL}; result.rc = mdbx_env_create(&result.env); return result; }
typedef struct { int rc; MDBX_txn *txn; } rubin_mdbx_txn_result;
static rubin_mdbx_txn_result rubin_mdbx_txn_begin(MDBX_env *env, MDBX_txn_flags_t flags) { rubin_mdbx_txn_result result = {0, NULL}; result.rc = mdbx_txn_begin(env, NULL, flags, &result.txn); return result; }
static int rubin_mdbx_put_required(MDBX_txn *txn, MDBX_dbi dbi, const void *key_bytes, size_t key_len, const void *value_bytes, size_t value_len) { MDBX_val key = {(void *)key_bytes, key_len}, value = {(void *)value_bytes, value_len}; return mdbx_put(txn, dbi, &key, &value, MDBX_NOOVERWRITE); }
typedef struct { int rc; const void *bytes; size_t length; } rubin_mdbx_get_result;
static rubin_mdbx_get_result rubin_mdbx_get(const MDBX_txn *txn, MDBX_dbi dbi, const void *key_bytes, size_t key_len) { MDBX_val key = {(void *)key_bytes, key_len}, value = {0, 0}; rubin_mdbx_get_result result; result.rc = mdbx_get(txn, dbi, &key, &value); result.bytes = value.iov_base; result.length = value.iov_len; return result; }
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

var (
	fixtureCreateExtraDBI   func(string) bool
	fixtureBeforeInitCensus func(*C.MDBX_txn, C.MDBX_dbi) error
)

type engineOperation string

const (
	operationCreate  engineOperation = "create"
	operationOpen    engineOperation = "open"
	operationInit    engineOperation = "init"
	operationAbort   engineOperation = "abort"
	operationClose   engineOperation = "close"
	operationView    engineOperation = "view"
	operationGet     engineOperation = "get"
	operationInspect engineOperation = "inspect"
	operationUpdate  engineOperation = "update"
)

func validEngineOperation(operation engineOperation) bool {
	switch operation {
	case operationCreate, operationOpen, operationInit, operationAbort, operationClose, operationView, operationGet, operationInspect, operationUpdate:
		return true
	}
	return false
}

type EngineClass string

const (
	EngineInvalidInput   EngineClass = "InvalidInput"
	EngineIntegrity      EngineClass = "Integrity"
	EngineCapacity       EngineClass = "Capacity"
	EngineConcurrency    EngineClass = "Concurrency"
	EngineTransaction    EngineClass = "Transaction"
	EngineIO             EngineClass = "IO"
	EngineStateMismatch  EngineClass = "StateMismatch"
	EngineLocalInvariant EngineClass = "LocalInvariant"
)

type EngineError struct {
	Class          EngineClass
	Operation      string
	Code           int
	Diagnostic     string
	Cause          error
	ReopenRequired bool
}

func (e *EngineError) Error() string {
	if e == nil {
		return "<nil>"
	}
	message := fmt.Sprintf("%s: %s: code %d: %s", e.Operation, e.Class, e.Code, e.Diagnostic)
	if e.Cause != nil {
		message += ": " + e.Cause.Error()
	}
	return message
}

func (e *EngineError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

const (
	codeSuccess, codeResultTrue                                                          = int(C.MDBX_SUCCESS), int(C.MDBX_RESULT_TRUE)
	codePageNotFound, codeCorrupted, codePanic, codeVersionMismatch, codeInvalid         = int(C.MDBX_PAGE_NOTFOUND), int(C.MDBX_CORRUPTED), int(C.MDBX_PANIC), int(C.MDBX_VERSION_MISMATCH), int(C.MDBX_INVALID)
	codeMapFull, codeDBsFull, codeReadersFull, codeTxnFull, codeCursorFull, codePageFull = int(C.MDBX_MAP_FULL), int(C.MDBX_DBS_FULL), int(C.MDBX_READERS_FULL), int(C.MDBX_TXN_FULL), int(C.MDBX_CURSOR_FULL), int(C.MDBX_PAGE_FULL)
	codeUnableExtendMapsize, codeBadRSlot, codeBadTxn, codeBadValSize, codeBadDBI        = int(C.MDBX_UNABLE_EXTEND_MAPSIZE), int(C.MDBX_BAD_RSLOT), int(C.MDBX_BAD_TXN), int(C.MDBX_BAD_VALSIZE), int(C.MDBX_BAD_DBI)
	codeProblem, codeBadSignature, codeWannaRecovery, codeKeyMismatch                    = int(C.MDBX_PROBLEM), int(C.MDBX_EBADSIGN), int(C.MDBX_WANNA_RECOVERY), int(C.MDBX_EKEYMISMATCH)
	codeTooLarge, codeThreadMismatch, codeMultiValue, codeTxnOverlapping                 = int(C.MDBX_TOO_LARGE), int(C.MDBX_THREAD_MISMATCH), int(C.MDBX_EMULTIVAL), int(C.MDBX_TXN_OVERLAPPING)
	codeBacklogDepleted, codeDuplicatedLock, codeDanglingDBI, codeOusted                 = int(C.MDBX_BACKLOG_DEPLETED), int(C.MDBX_DUPLICATED_LCK), int(C.MDBX_DANGLING_DBI), int(C.MDBX_OUSTED)
	codeMVCCRetarded, codeLaggardReader, codeBusy, codeEINVAL, codeEIO                   = int(C.MDBX_MVCC_RETARDED), int(C.MDBX_LAGGARD_READER), int(C.MDBX_BUSY), int(C.MDBX_EINVAL), int(C.MDBX_EIO)
	codeEROFS, codeEREMOTE, codeEAccess, codeEPerm, codeEIntr, codeEDeadlock             = int(C.MDBX_EROFS), int(C.MDBX_EREMOTE), int(C.MDBX_EACCESS), int(C.MDBX_EPERM), int(C.MDBX_EINTR), int(C.MDBX_EDEADLK)
	codeENOMEM, codeEExist, codeENOFile, codeIncompatible                                = int(C.MDBX_ENOMEM), int(C.MDBX_EEXIST), int(C.MDBX_ENOFILE), int(C.MDBX_INCOMPATIBLE)
	codeKeyExist, codeNotFound                                                           = int(C.MDBX_KEYEXIST), int(C.MDBX_NOTFOUND)
	codeENODEV, codeESTALE, codeENOSPC, codeEDQUOT                                       = int(syscall.ENODEV), int(syscall.ESTALE), int(syscall.ENOSPC), int(syscall.EDQUOT)
)

func fixedNativeClass(code int) (EngineClass, bool) {
	switch code {
	case codeBadValSize, codeEINVAL:
		return EngineInvalidInput, true
	case codePageNotFound, codeCorrupted, codePanic, codeVersionMismatch, codeInvalid,
		codeWannaRecovery, codeDuplicatedLock, codeCursorFull:
		return EngineIntegrity, true
	case codeMapFull, codeUnableExtendMapsize, codeENOMEM, codeENOSPC, codeEDQUOT:
		return EngineCapacity, true
	case codeReadersFull, codeBusy, codeLaggardReader, codeEDeadlock:
		return EngineConcurrency, true
	case codeTxnFull, codeResultTrue:
		return EngineTransaction, true
	case codeBadRSlot, codePageFull, codeBadDBI, codeDBsFull, codeMultiValue,
		codeKeyMismatch, codeBadTxn, codeThreadMismatch, codeTxnOverlapping,
		codeOusted, codeMVCCRetarded, codeProblem, codeBacklogDepleted,
		codeDanglingDBI, codeBadSignature:
		return EngineLocalInvariant, true
	case codeENOFile, codeEIO, codeEROFS, codeENODEV, codeESTALE, codeEREMOTE,
		codeEAccess, codeEPerm, codeEIntr:
		return EngineIO, true
	default:
		return "", false
	}
}

func chooseClass(condition bool, yes, no EngineClass) EngineClass {
	if condition {
		return yes
	}
	return no
}

func classifyNative(operation engineOperation, code int) EngineClass {
	if class, ok := fixedNativeClass(code); ok {
		return class
	}
	switch code {
	case codeIncompatible:
		if operation == operationCreate {
			return EngineInvalidInput
		}
		if operation == operationOpen {
			return EngineIntegrity
		}
		return EngineLocalInvariant
	case codeTooLarge:
		return chooseClass(operation == operationCreate, EngineInvalidInput, EngineCapacity)
	case codeEExist:
		return chooseClass(operation == operationCreate, EngineInvalidInput, EngineIO)
	default:
		return chooseClass(code < 0, EngineLocalInvariant, EngineIO)
	}
}

func reopenRequired(code int) bool {
	switch code {
	case codePageNotFound, codeCorrupted, codePanic, codeVersionMismatch, codeInvalid,
		codeCursorFull, codeUnableExtendMapsize, codeBadSignature, codeWannaRecovery,
		codeDuplicatedLock, codeThreadMismatch:
		return true
	default:
		return false
	}
}

func validEngineClass(class EngineClass) bool {
	return class == EngineInvalidInput || class == EngineIntegrity || class == EngineCapacity || class == EngineConcurrency || class == EngineTransaction || class == EngineIO || class == EngineLocalInvariant
}

func engineError(operation engineOperation, class EngineClass, code int, diagnostic string, cause error) *EngineError {
	if !validEngineOperation(operation) {
		return &EngineError{EngineLocalInvariant, string(operationInit), codeProblem, "unsupported engine operation", cause, false}
	}
	if !validEngineClass(class) {
		return &EngineError{EngineLocalInvariant, string(operation), codeProblem, "unsupported engine class", cause, false}
	}
	return &EngineError{class, string(operation), code, diagnostic, cause, reopenRequired(code)}
}

func nativeDiagnostic(code int) string {
	cCode := C.int(code)
	if int(cCode) != code {
		return fmt.Sprintf("error code %d outside C int range", code)
	}
	if code >= 0 {
		return fmt.Sprintf("error %d", code)
	}
	if diagnostic := C.mdbx_liberr2str(cCode); diagnostic != nil {
		return C.GoString(diagnostic)
	}
	return fmt.Sprintf("error %d", code)
}

func nativeError(operation engineOperation, code int) *EngineError {
	if !validEngineOperation(operation) {
		return engineError(operation, EngineLocalInvariant, code, "", nil)
	}
	if code == codeSuccess {
		return nil
	}
	return engineError(operation, classifyNative(operation, code), code, nativeDiagnostic(code), nil)
}

func metadataError(operation engineOperation, code, ownershipCode int) *EngineError {
	err := nativeError(operation, code)
	if err == nil {
		return nil
	}
	if err.Code == code && code == ownershipCode && (code == codeKeyExist || code == codeNotFound) {
		return engineError(operation, EngineIntegrity, err.Code, err.Diagnostic, err.Cause)
	}
	return err
}

func adapterError(operation engineOperation, class EngineClass, code int, diagnostic string, cause error) *EngineError {
	return engineError(operation, class, code, diagnostic, cause)
}

func integrityError(operation engineOperation, diagnostic string, cause error) *EngineError {
	return adapterError(operation, EngineIntegrity, codeInvalid, diagnostic, cause)
}

func ioError(operation engineOperation, diagnostic string, cause error) *EngineError {
	code := codeEIO
	var errno syscall.Errno
	if errors.As(cause, &errno) {
		code = int(errno)
	}
	return adapterError(operation, classifyNative(operation, code), code, diagnostic, cause)
}

func writerLockError(operation engineOperation, result filelock.Result, cause error) *EngineError {
	switch result {
	case filelock.ResultContended:
		return adapterError(operation, EngineConcurrency, codeBusy, "Rubin writer lock is already held", cause)
	case filelock.ResultInvalidOrUnopenable:
		err := ioError(operation, "acquire Rubin writer lock", cause)
		return engineError(operation, EngineIO, err.Code, err.Diagnostic, err.Cause)
	default:
		return adapterError(operation, EngineLocalInvariant, codeProblem, "unsupported writer-lock result", cause)
	}
}

type storeState string

const (
	storeOPEN           storeState = "OPEN"
	storeCLOSEBLOCKED   storeState = "CLOSE_BLOCKED"
	storeCLOSED         storeState = "CLOSED"
	storePOISONEDTHREAD storeState = "POISONED_THREAD"
)

type errorOrder uint8

const (
	orderNone errorOrder = iota
	orderPrimary
	orderResult
	orderPrimaryResult
	orderResultCausesPrimary
)

type nativeTransition struct {
	consumed bool
	next     storeState
	order    errorOrder
}

func commitTransition(code int) nativeTransition {
	switch code {
	case codeSuccess:
		return nativeTransition{true, storeOPEN, orderNone}
	case codeThreadMismatch:
		return nativeTransition{false, storePOISONEDTHREAD, orderResult}
	default:
		return nativeTransition{true, storeCLOSED, orderResult}
	}
}

func abortTransition(code int, hasPrimary bool) nativeTransition {
	switch code {
	case codeThreadMismatch:
		return nativeTransition{false, storePOISONEDTHREAD, chooseOrder(hasPrimary, orderResultCausesPrimary, orderResult)}
	case codeSuccess:
		return nativeTransition{true, chooseState(hasPrimary, storeCLOSED, storeOPEN), chooseOrder(hasPrimary, orderPrimary, orderNone)}
	default:
		return nativeTransition{true, storeCLOSED, chooseOrder(hasPrimary, orderPrimaryResult, orderResult)}
	}
}

func closeTransition(code int, hasPrimary bool) nativeTransition {
	switch code {
	case codeBusy:
		return nativeTransition{false, storeCLOSEBLOCKED, chooseOrder(hasPrimary, orderResultCausesPrimary, orderResult)}
	case codeSuccess:
		return nativeTransition{true, storeCLOSED, chooseOrder(hasPrimary, orderPrimary, orderNone)}
	default:
		return nativeTransition{true, storeCLOSED, chooseOrder(hasPrimary, orderPrimaryResult, orderResult)}
	}
}

func chooseOrder(condition bool, yes, no errorOrder) errorOrder {
	if condition {
		return yes
	}
	return no
}

func chooseState(condition bool, yes, no storeState) storeState {
	if condition {
		return yes
	}
	return no
}

//nolint:errorlint // Native cleanup results must be direct EngineError pointers.
func directNativeResult(operation engineOperation, result error) (*EngineError, bool) {
	engine, ok := result.(*EngineError)
	return engine, ok && engine != nil && engine.Operation == string(operation) && validEngineClass(engine.Class) && engine.Code != codeSuccess && engine.Class == classifyNative(operation, engine.Code) && engine.ReopenRequired == reopenRequired(engine.Code)
}

func errorOrderShape(order errorOrder) (bool, bool, bool) {
	switch order {
	case orderNone:
		return false, false, true
	case orderPrimary:
		return true, false, true
	case orderResult:
		return false, true, true
	case orderPrimaryResult, orderResultCausesPrimary:
		return true, true, true
	default:
		return false, false, false
	}
}

func orderedErrors(operation engineOperation, order errorOrder, primary, result error) error {
	if !validEngineOperation(operation) {
		return adapterError(operation, EngineLocalInvariant, codeProblem, "unsupported engine operation", joinErrors(primary, result))
	}
	needsPrimary, needsResult, knownOrder := errorOrderShape(order)
	if !knownOrder {
		return composeOrderedErrors(operation, order, primary, result, nil)
	}
	hasPrimary, hasResult := primary != nil, result != nil
	if hasPrimary != needsPrimary || hasResult != needsResult {
		return adapterError(operation, EngineLocalInvariant, codeProblem, "native errors do not match ordering", joinErrors(primary, result))
	}
	engine, validResult := directNativeResult(operation, result)
	if needsResult && !validResult {
		return adapterError(operation, EngineLocalInvariant, codeProblem, "native result is not an EngineError", joinErrors(primary, result))
	}
	return composeOrderedErrors(operation, order, primary, result, engine)
}

func composeOrderedErrors(operation engineOperation, order errorOrder, primary, result error, engine *EngineError) error {
	switch order {
	case orderNone:
		return nil
	case orderPrimary:
		return joinErrors(primary)
	case orderResult:
		return result
	case orderPrimaryResult:
		return joinErrors(primary, result)
	case orderResultCausesPrimary:
		copy := *engine
		copy.Cause = joinErrors(primary, engine.Cause)
		return &copy
	default:
		return adapterError(operation, EngineLocalInvariant, codeProblem, "invalid native result ordering", joinErrors(primary, result))
	}
}

func requiredValueResult(operation engineOperation, rc int, length uint64, present bool, expected uint64) error {
	if !validEngineOperation(operation) {
		return adapterError(operation, EngineLocalInvariant, codeProblem, "unsupported engine operation", nil)
	}
	if rc != codeSuccess {
		return metadataError(operation, rc, codeNotFound)
	}
	if length != expected || !present {
		return integrityError(operation, "required metadata width mismatch", nil)
	}
	return nil
}

func joinErrors(errs ...error) error {
	nonNil := make([]error, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			nonNil = append(nonNil, err)
		}
	}
	switch len(nonNil) {
	case 0:
		return nil
	case 1:
		return nonNil[0]
	default:
		return errors.Join(nonNil...)
	}
}

type Store struct {
	operations sync.RWMutex
	self       *Store
	env        *C.MDBX_env
	writer     *filelock.Handle
	txn        *C.MDBX_txn
	config     ConfigV1
	dbis       [7]C.MDBX_dbi
	state      storeState
	terminal   error
}

type Reader struct {
	self    *Reader
	txn     *C.MDBX_txn
	dbis    [7]C.MDBX_dbi
	getMu   sync.Mutex
	active  atomic.Bool
	failure error
}

type DBIInspection struct {
	DBI           DBI
	Entries       uint64
	Depth         uint32
	BranchPages   uint64
	LeafPages     uint64
	OverflowPages uint64
	PageSize      uint32
}

type Inspection struct {
	Config            ConfigV1
	MapSize           uint64
	FileSize          uint64
	AllocatedSize     uint64
	MaxReaders        uint32
	ReaderTableLength uint32
	RecentTxnID       uint64
	LatterReaderTxnID uint64
	UnsyncBytes       uint64
	DBIs              [7]DBIInspection
}

type getResult uint8

const (
	getResultAbsent getResult = iota
	getResultEmpty
	getResultCopy
	getResultInvalidShape
	getResultInvalidBound
	getResultNative
)

type AfterKind uint8

const (
	AfterAbsent AfterKind = iota + 1
	AfterLiteral
	AfterOldValueRef
)

type Mutation struct {
	DBI           DBI
	Key           []byte
	BeforePresent bool
	AfterKind     AfterKind
	Literal       []byte
	RefDBI        DBI
	RefKey        []byte
}

type Batch struct {
	Mutations []Mutation
}

const (
	maxUpdateInputs    uint64 = 414_634
	maxUpdateOutputs   uint64 = 1_545_454
	maxUpdateAux       uint64 = 16_384
	maxUpdateMutations uint64 = 2_391_106
	maxUpdateKeyBytes  uint64 = 137_676_154
	maxUpdateLiterals  uint64 = 155_659_727
)

type ownedMutation struct {
	dbi           DBI
	key           []byte
	beforePresent bool
	after         AfterKind
	literal       []byte
	refDBI        DBI
	refKey        []byte
}

type updateBudget struct {
	mutations, keyBytes, literals uint64
	utxoDeletes, undoRefs         uint64
	utxoLiterals, aux             uint64
}

func updateInvalidBatch() error {
	return adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "invalid Update Batch", nil)
}

func updateBoundError() error {
	return adapterError(operationUpdate, EngineCapacity, codeTooLarge, "Update Batch exceeds bound", nil)
}

func updateAdd(total, add, limit uint64) (uint64, bool) {
	if total > limit || add > limit-total {
		return 0, false
	}
	return total + add, true
}

func updateClone(bytes []byte) []byte {
	if bytes == nil {
		return nil
	}
	out := make([]byte, len(bytes))
	copy(out, bytes)
	return out
}

func updateOrdered(previous, next Mutation) bool {
	if previous.DBI.Rank != next.DBI.Rank {
		return previous.DBI.Rank < next.DBI.Rank
	}
	return bytes.Compare(previous.Key, next.Key) < 0
}

func updateMutableMeta(key []byte, absent bool) bool {
	if key[0] == 0 || key[0] == 1 {
		return false
	}
	return !absent || key[0] != 2
}

func updateLiteralAllowed(m Mutation) bool {
	switch m.DBI.Rank {
	case 0:
		return updateMutableMeta(m.Key, false)
	case 1, 2, 6:
		return true
	case 3, 4:
		return !m.BeforePresent
	case 5:
		return m.Key[32] == 0 && !m.BeforePresent
	default:
		return false
	}
}

func updateAbsentAllowed(m Mutation) bool {
	if m.DBI.Rank != 0 {
		return true
	}
	return updateMutableMeta(m.Key, true)
}

func updateLiteralPayload(m Mutation) bool {
	return m.Literal != nil && m.RefDBI == (DBI{}) && m.RefKey == nil && updateLiteralAllowed(m)
}

func updateAbsentPayload(m Mutation) bool {
	return m.BeforePresent && m.Literal == nil && m.RefDBI == (DBI{}) && m.RefKey == nil && updateAbsentAllowed(m)
}

func updateRefPayload(m Mutation) bool {
	dbis := SchemaV1DBIs()
	return !m.BeforePresent && m.Literal == nil && m.DBI == dbis[5] && len(m.Key) == 77 && m.Key[32] == 1 && m.RefDBI == dbis[1] && validKey(m.RefDBI.Rank, m.RefKey) && bytes.Equal(m.Key[41:77], m.RefKey[8:44])
}

func updateValidMutation(m Mutation) bool {
	if ValidateDBI(m.DBI) != nil || !validKey(m.DBI.Rank, m.Key) {
		return false
	}
	switch m.AfterKind {
	case AfterAbsent:
		return updateAbsentPayload(m)
	case AfterLiteral:
		return updateLiteralPayload(m)
	case AfterOldValueRef:
		return updateRefPayload(m)
	default:
		return false
	}
}

func updateKeyCharge(m Mutation) uint64 {
	charge := uint64(len(m.Key))
	if m.AfterKind == AfterOldValueRef {
		charge += uint64(len(m.RefKey))
	}
	return charge
}

func (budget *updateBudget) addTotals(m Mutation) bool {
	var ok bool
	if budget.mutations, ok = updateAdd(budget.mutations, 1, maxUpdateMutations); !ok {
		return false
	}
	if budget.keyBytes, ok = updateAdd(budget.keyBytes, updateKeyCharge(m), maxUpdateKeyBytes); !ok {
		return false
	}
	if budget.literals, ok = updateAdd(budget.literals, uint64(len(m.Literal)), maxUpdateLiterals); !ok {
		return false
	}
	return true
}

func (budget *updateBudget) addMutation(m Mutation) bool {
	if !budget.addTotals(m) {
		return false
	}
	var ok bool
	switch {
	case m.DBI.Rank == 1 && m.AfterKind == AfterAbsent:
		budget.utxoDeletes, ok = updateAdd(budget.utxoDeletes, 1, maxUpdateInputs)
	case m.DBI.Rank == 5 && m.AfterKind == AfterOldValueRef:
		budget.undoRefs, ok = updateAdd(budget.undoRefs, 1, maxUpdateInputs)
	case m.DBI.Rank == 1 && m.AfterKind == AfterLiteral:
		budget.utxoLiterals, ok = updateAdd(budget.utxoLiterals, 1, maxUpdateOutputs)
	default:
		budget.aux, ok = updateAdd(budget.aux, 1, maxUpdateAux)
	}
	return ok
}

func updateScanMutation(first bool, previous, mutation Mutation, budget *updateBudget) error {
	if !updateValidMutation(mutation) {
		return updateInvalidBatch()
	}
	if !first && !updateOrdered(previous, mutation) {
		return updateInvalidBatch()
	}
	if mutation.AfterKind == AfterLiteral && ValidateRow(mutation.DBI, mutation.Key, mutation.Literal) != nil {
		return updateInvalidBatch()
	}
	if !budget.addMutation(mutation) {
		return updateBoundError()
	}
	return nil
}

func updateOwnedBatch(batch Batch) ([]ownedMutation, error) {
	if len(batch.Mutations) == 0 {
		return nil, updateInvalidBatch()
	}
	budget, previous := updateBudget{}, Mutation{}
	for i, mutation := range batch.Mutations {
		scanErr := updateScanMutation(i == 0, previous, mutation, &budget)
		if scanErr != nil {
			return nil, scanErr
		}
		previous = mutation
	}
	owned := make([]ownedMutation, len(batch.Mutations))
	for i, mutation := range batch.Mutations {
		owned[i] = ownedMutation{mutation.DBI, updateClone(mutation.Key), mutation.BeforePresent, mutation.AfterKind, updateClone(mutation.Literal), mutation.RefDBI, updateClone(mutation.RefKey)}
	}
	return owned, nil
}

func (s *Store) View(callback func(*Reader) error) (err error) {
	if s == nil {
		return adapterError(operationView, EngineInvalidInput, codeEINVAL, "nil Store", nil)
	}
	if callback == nil {
		return adapterError(operationView, EngineInvalidInput, codeEINVAL, "nil View callback", nil)
	}
	if !s.operations.TryLock() {
		return adapterError(operationView, EngineConcurrency, codeBusy, "store operation in progress", nil)
	}
	defer s.operations.Unlock()
	stateErr := s.observationStateError(operationView)
	if stateErr != nil {
		return stateErr
	}
	begun := C.rubin_mdbx_txn_begin(s.env, C.MDBX_TXN_RDONLY)
	beginErr := nativePointerResultError(operationView, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil)
	if beginErr != nil {
		return s.failedReadBegin(begun.txn, beginErr)
	}
	reader := newReader(begun.txn, s.dbis)
	reader.active.Store(true)
	defer func() {
		reader.expire()
		primary, infrastructure := readPrimary(err, reader.failure)
		err = s.abortReadLocked(begun.txn, primary, infrastructure)
	}()
	return callback(reader)
}

func (r *Reader) Get(dbi DBI, key []byte) ([]byte, bool, error) {
	if !r.usable() {
		return nil, false, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "Reader is not active", nil)
	}
	dbiErr := ValidateDBI(dbi)
	if dbiErr != nil {
		return nil, false, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "invalid SchemaV1 DBI", dbiErr)
	}
	if !validKey(dbi.Rank, key) {
		return nil, false, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "invalid SchemaV1 key", nil)
	}
	r.getMu.Lock()
	defer r.getMu.Unlock()
	if !r.usable() {
		return nil, false, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "Reader is not active", nil)
	}
	value := C.rubin_mdbx_get(r.txn, r.dbis[dbi.Rank], unsafe.Pointer(&key[0]), C.size_t(len(key)))
	runtime.KeepAlive(key)
	result, present, err := copiedGetResult(dbi, key, int(value.rc), unsafe.Pointer(value.bytes), value.length)
	if err != nil {
		r.failure = err
		r.active.Store(false)
	}
	return result, present, err
}

func (s *Store) Inspect() (Inspection, error) {
	if s == nil {
		return Inspection{}, adapterError(operationInspect, EngineInvalidInput, codeEINVAL, "nil Store", nil)
	}
	if !s.operations.TryLock() {
		return Inspection{}, adapterError(operationInspect, EngineConcurrency, codeBusy, "store operation in progress", nil)
	}
	defer s.operations.Unlock()
	stateErr := s.observationStateError(operationInspect)
	if stateErr != nil {
		return Inspection{}, stateErr
	}
	begun := C.rubin_mdbx_txn_begin(s.env, C.MDBX_TXN_RDONLY)
	beginErr := nativePointerResultError(operationInspect, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil)
	if beginErr != nil {
		return Inspection{}, s.failedReadBegin(begun.txn, beginErr)
	}
	inspection, primary := s.inspectReadLocked(begun.txn)
	cleanupErr := s.abortReadLocked(begun.txn, primary, primary != nil)
	if cleanupErr != nil {
		return Inspection{}, cleanupErr
	}
	return inspection, nil
}

func (s *Store) failedReadBegin(txn *C.MDBX_txn, primary error) error {
	if txn != nil {
		return s.poison(txn, primary).err
	}
	_, err := s.consume(primary)
	return err
}

//nolint:errorlint // Only the exact recorded EngineError is de-duplicated.
func readPrimary(application, infrastructure error) (error, bool) {
	if infrastructure == nil {
		return application, false
	}
	if recorded, ok := infrastructure.(*EngineError); ok {
		if returned, exact := application.(*EngineError); exact && returned == recorded {
			return infrastructure, true
		}
	}
	return joinErrors(application, infrastructure), true
}

func (s *Store) abortReadLocked(txn *C.MDBX_txn, primary error, infrastructure bool) error {
	return s.applyReadAbort(txn, primary, infrastructure, int(C.mdbx_txn_abort(txn)))
}

func (s *Store) applyReadAbort(txn *C.MDBX_txn, primary error, infrastructure bool, rc int) error {
	decision := abortTransition(rc, primary != nil)
	var abortErr error
	if rc != codeSuccess {
		abortErr = nativeError(operationAbort, rc)
	}
	result := orderedErrors(operationAbort, decision.order, primary, abortErr)
	if !decision.consumed {
		return s.poison(txn, result).err
	}
	if rc == codeSuccess && !infrastructure {
		return result
	}
	_, result = s.consume(result)
	return result
}

func (s *Store) observationStateError(operation engineOperation) error {
	if !validStoreState(s.state) {
		return adapterError(operation, EngineLocalInvariant, codeProblem, "invalid Store state", nil)
	}
	if !validStoreShape(s) {
		return adapterError(operation, EngineLocalInvariant, codeProblem, "invalid Store resource shape", nil)
	}
	if s.state == storeOPEN {
		return nil
	}
	if s.terminal != nil {
		return s.terminal
	}
	return adapterError(operation, EngineInvalidInput, codeEINVAL, "Store is closed", nil)
}

func newReader(txn *C.MDBX_txn, dbis [7]C.MDBX_dbi) *Reader {
	reader := &Reader{txn: txn, dbis: dbis}
	reader.self = reader
	return reader
}

func (r *Reader) usable() bool {
	return r != nil && r.self == r && r.txn != nil && validRetainedDBIs(r.dbis) && r.active.Load()
}

func (r *Reader) expire() {
	r.active.Store(false)
	r.getMu.Lock()
	//nolint:staticcheck // Lock acquisition drains every in-flight Get before abort.
	r.getMu.Unlock()
}

func copiedGetResult(dbi DBI, key []byte, rc int, bytes unsafe.Pointer, length C.size_t) ([]byte, bool, error) {
	minimum, maximum := rawValueBounds(dbi, key)
	decision := getResultDecision(rc, bytes != nil, uint64(length), minimum, maximum)
	switch decision {
	case getResultAbsent:
		return nil, false, nil
	case getResultEmpty:
		return []byte{}, true, nil
	case getResultCopy:
		return C.GoBytes(bytes, C.int(length)), true, nil
	case getResultInvalidShape:
		return nil, false, adapterError(operationGet, EngineLocalInvariant, codeProblem, "mdbx_get returned invalid result shape", nil)
	case getResultInvalidBound:
		return nil, false, integrityError(operationGet, "stored value width outside SchemaV1 bound", nil)
	default:
		return nil, false, nativeError(operationGet, rc)
	}
}

func getResultDecision(rc int, present bool, length, minimum, maximum uint64) getResult {
	if rc == codeNotFound {
		if !present && length == 0 {
			return getResultAbsent
		}
		return getResultInvalidShape
	}
	if rc != codeSuccess {
		return getResultNative
	}
	if length == 0 {
		return zeroLengthGetResult(minimum)
	}
	if !present {
		return getResultInvalidShape
	}
	if !validRawValueLength(length, minimum, maximum) {
		return getResultInvalidBound
	}
	return getResultCopy
}

func zeroLengthGetResult(minimum uint64) getResult {
	if minimum == 0 {
		return getResultEmpty
	}
	return getResultInvalidBound
}

func validRawValueLength(length, minimum, maximum uint64) bool {
	return length >= minimum && length <= maximum
}

func rawValueBounds(dbi DBI, key []byte) (uint64, uint64) {
	if dbi.Rank == 0 {
		return metaRawValueBounds(key[0])
	}
	if dbi.Rank == 5 {
		return undoRawValueBounds(key[32])
	}
	return rankedRawValueBounds(dbi.Rank)
}

func metaRawValueBounds(kind byte) (uint64, uint64) {
	switch kind {
	case 0x00:
		return 4, 4
	case 0x01:
		return 48, 48
	case 0x02:
		return 0, MaxMetadataBytes
	default:
		return 16, 16
	}
}

func undoRawValueBounds(kind byte) (uint64, uint64) {
	if kind == 0 {
		return 33, 33
	}
	return 20, 65_560
}

func rankedRawValueBounds(rank uint8) (uint64, uint64) {
	switch rank {
	case 1:
		return 20, 65_560
	case 2, 6:
		return 104, 104
	case 3:
		return 116, 116
	default:
		return 116, MaxBlockBytes
	}
}

func (s *Store) inspectReadLocked(txn *C.MDBX_txn) (Inspection, error) {
	var info C.MDBX_envinfo
	if rc := int(C.mdbx_env_info_ex(s.env, txn, &info, C.size_t(unsafe.Sizeof(info)))); rc != codeSuccess {
		return Inspection{}, nativeError(operationInspect, rc)
	}
	current := uint64(info.mi_geo.current)
	if !validEffectiveCurrent(s.config, current) {
		return Inspection{}, integrityError(operationInspect, "effective ConfigV1 Now is invalid", nil)
	}
	inspection := Inspection{Config: s.config, MapSize: uint64(info.mi_mapsize), FileSize: uint64(info.mi_dxb_fsize), AllocatedSize: uint64(info.mi_dxb_fallocated), MaxReaders: uint32(info.mi_maxreaders), ReaderTableLength: uint32(info.mi_numreaders), RecentTxnID: uint64(info.mi_recent_txnid), LatterReaderTxnID: uint64(info.mi_latter_reader_txnid), UnsyncBytes: uint64(info.mi_unsync_volume)}
	inspection.Config.Now = current
	for i, dbi := range SchemaV1DBIs() {
		var stat C.MDBX_stat
		if rc := int(C.mdbx_dbi_stat(txn, s.dbis[i], &stat, C.size_t(unsafe.Sizeof(stat)))); rc != codeSuccess {
			return Inspection{}, nativeError(operationInspect, rc)
		}
		inspection.DBIs[i] = DBIInspection{DBI: dbi, Entries: uint64(stat.ms_entries), Depth: uint32(stat.ms_depth), BranchPages: uint64(stat.ms_branch_pages), LeafPages: uint64(stat.ms_leaf_pages), OverflowPages: uint64(stat.ms_overflow_pages), PageSize: uint32(stat.ms_psize)}
	}
	return inspection, nil
}

func Create(path string, cfg ConfigV1) (*Store, error) {
	encoded, err := validateCreateStatic(path, cfg)
	if err != nil {
		return nil, err
	}
	err = normalizeMDBXModule()
	if err != nil {
		return nil, err
	}
	err = validateLimits(cfg, limitsForPage(cfg.PageSize))
	if err != nil {
		return nil, adapterError(operationCreate, EngineInvalidInput, codeTooLarge, "ConfigV1 exceeds pinned native limits", err)
	}
	store := &Store{}
	store.self = store
	err = store.configureCreateEnvironment(path, cfg)
	if err != nil {
		return store.consumeFailure(err)
	}
	err = createDirectory(path)
	if err != nil {
		return store.consumeFailure(err)
	}
	writer, err := acquireWriter(path, operationCreate, true)
	if err != nil {
		return store.consumeFailure(err)
	}
	store.writer = writer
	err = store.createEnvironment(path, cfg)
	if err != nil {
		return store.consumeFailure(err)
	}
	return finishConstruction(store, runLocked(func() transactionOutcome { return store.initializeLocked(cfg, encoded) }))
}

func Open(path string, cfg ConfigV1) (*Store, error) {
	err := validatePath(operationOpen, path)
	if err != nil {
		return nil, err
	}
	_, err = validateOpenArtifacts(path)
	if err != nil {
		return nil, err
	}
	err = validateOpenStatic(cfg)
	if err != nil {
		return nil, err
	}
	err = validateOpenNativePreconditions(path, cfg)
	if err != nil {
		return nil, err
	}
	writer, err := acquireWriter(path, operationOpen, false)
	if err != nil {
		return nil, err
	}
	store := &Store{writer: writer}
	store.self = store
	err = store.openEnvironment(path, cfg)
	if err != nil {
		return store.consumeFailure(err)
	}
	return finishConstruction(store, runLocked(func() transactionOutcome { return store.inspectOpenLocked(cfg) }))
}

func validateOpenNativePreconditions(path string, cfg ConfigV1) error {
	err := normalizeMDBXModule()
	if err != nil {
		return err
	}
	err = validatePreopenSnapshot(path)
	if err != nil {
		return err
	}
	err = validateLimits(cfg, limitsForPage(cfg.PageSize))
	if err != nil {
		return adapterError(operationOpen, EngineInvalidInput, codeTooLarge, "ConfigV1 exceeds pinned native limits", err)
	}
	return nil
}

func validateCreateStatic(path string, cfg ConfigV1) ([]byte, error) {
	err := validatePath(operationCreate, path)
	if err != nil {
		return nil, err
	}
	err = requireCreateTargetAbsent(path)
	if err != nil {
		return nil, err
	}
	encoded, err := cfg.Encode()
	if err != nil {
		return nil, adapterError(operationCreate, EngineInvalidInput, codeEINVAL, "invalid ConfigV1", err)
	}
	return encoded, nil
}

func finishConstruction(store *Store, outcome transactionOutcome) (*Store, error) {
	if outcome.poisoned {
		return store, outcome.err
	}
	if outcome.err != nil {
		return store.consumeFailure(outcome.err)
	}
	return store, nil
}

func (s *Store) Close() error {
	if s == nil {
		return adapterError(operationClose, EngineInvalidInput, codeEINVAL, "nil Store", nil)
	}
	if !s.operations.TryLock() {
		return adapterError(operationClose, EngineConcurrency, codeBusy, "store operation in progress", nil)
	}
	defer s.operations.Unlock()
	if !validStoreState(s.state) {
		return adapterError(operationClose, EngineLocalInvariant, codeProblem, "invalid Store state", nil)
	}
	if !validStoreShape(s) {
		return adapterError(operationClose, EngineLocalInvariant, codeProblem, "invalid Store resource shape", nil)
	}
	if s.state == storeCLOSED || s.state == storePOISONEDTHREAD {
		return s.terminal
	}
	_, err := s.consume(nil)
	return err
}

func validStoreState(state storeState) bool {
	return state == storeOPEN || state == storeCLOSEBLOCKED || state == storeCLOSED || state == storePOISONEDTHREAD
}

func validStoreShape(s *Store) bool {
	if s.self != s {
		return false
	}
	switch s.state {
	case storeOPEN:
		return validOpenStoreShape(s)
	case storeCLOSEBLOCKED:
		return validCloseBlockedStoreShape(s)
	case storeCLOSED:
		return validClosedStoreShape(s)
	case storePOISONEDTHREAD:
		return validPoisonedStoreShape(s)
	default:
		return false
	}
}

func validOpenStoreShape(s *Store) bool {
	return s.env != nil && s.writer != nil && s.txn == nil && s.terminal == nil && s.config.valid() && validRetainedDBIs(s.dbis)
}

func validCloseBlockedStoreShape(s *Store) bool {
	engine, terminalOK := directNativeResult(operationClose, s.terminal)
	resourcesOK := validPublishedStoreResources(s) || validConstructionStoreResources(s, engine, terminalOK)
	return s.env != nil && s.writer != nil && s.txn == nil && terminalOK && engine.Code == codeBusy && resourcesOK
}

func validPublishedStoreResources(s *Store) bool {
	return s.config.valid() && validRetainedDBIs(s.dbis)
}

func validConstructionStoreResources(s *Store, engine *EngineError, terminalOK bool) bool {
	return s.config == (ConfigV1{}) && s.dbis == ([7]C.MDBX_dbi{}) && terminalOK && engine.Cause != nil
}

func validClosedStoreShape(s *Store) bool {
	return s.env == nil && s.writer == nil && s.txn == nil && s.config == (ConfigV1{}) && s.dbis == ([7]C.MDBX_dbi{}) && validClosedTerminal(s.terminal)
}

func validPoisonedStoreShape(s *Store) bool {
	return s.env != nil && s.writer != nil && s.txn != nil && s.config == (ConfigV1{}) && s.dbis == ([7]C.MDBX_dbi{}) && validPoisonTerminal(s.terminal)
}

func validRetainedDBIs(dbis [7]C.MDBX_dbi) bool {
	seen := make(map[C.MDBX_dbi]bool, len(dbis))
	for _, dbi := range dbis {
		if dbi == 0 || seen[dbi] {
			return false
		}
		seen[dbi] = true
	}
	return true
}

func validPoisonTerminal(err error) bool {
	engine, ok := directEngineError(err)
	if !ok {
		return false
	}
	operation := engineOperation(engine.Operation)
	if engine.Code == codeThreadMismatch && (operation == operationInit || operation == operationAbort) {
		_, ok := directNativeResult(operation, err)
		return ok
	}
	if !validPointerShapePoison(engine, operation) {
		return false
	}
	_, ok = directNativeResult(operation, engine.Cause)
	return ok
}

func validPointerShapePoison(engine *EngineError, operation engineOperation) bool {
	return engine.Class == EngineLocalInvariant && engine.Code == codeProblem && engine.Diagnostic == "mdbx_txn_begin returned invalid result shape" && (operation == operationInit || operation == operationOpen || operation == operationView || operation == operationInspect)
}

func validClosedTerminal(err error) bool {
	if err == nil || validReleaseTerminal(err) || validConsumedCloseTerminal(err) || validConsumedReadTerminal(err) {
		return true
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return false
	}
	parts := joined.Unwrap()
	return len(parts) == 2 && validConsumedCloseTerminal(parts[0]) && validReleaseTerminal(parts[1])
}

func validConsumedReadTerminal(err error) bool {
	if valid, direct := validDirectConsumedReadTerminal(err); direct {
		return valid
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return false
	}
	parts := joined.Unwrap()
	if len(parts) != 2 {
		return false
	}
	if validConsumedReadTerminal(parts[1]) {
		return parts[0] != nil
	}
	if validConsumedCleanupTerminal(parts[1]) {
		return validConsumedReadTerminal(parts[0])
	}
	return false
}

func validDirectConsumedReadTerminal(err error) (bool, bool) {
	engine, direct := directEngineError(err)
	if !direct {
		return false, false
	}
	operation := engineOperation(engine.Operation)
	switch operation {
	case operationAbort:
		_, valid := directNativeResult(operationAbort, err)
		return valid && engine.Code != codeThreadMismatch, true
	case operationView, operationGet, operationInspect:
		_, valid := directNativeResult(operation, err)
		return valid, true
	default:
		return false, true
	}
}

func validConsumedCleanupTerminal(err error) bool {
	return validConsumedCloseTerminal(err) || validReleaseTerminal(err)
}

func validConsumedCloseTerminal(e error) bool {
	v, ok := directNativeResult(operationClose, e)
	return ok && v.Code != codeBusy
}

func validReleaseTerminal(err error) bool {
	engine, ok := directEngineError(err)
	return ok && engine.Operation == string(operationClose) && engine.Diagnostic == "release Rubin writer lock" && engine.Cause != nil && engine.Class == classifyNative(operationClose, engine.Code) && engine.ReopenRequired == reopenRequired(engine.Code)
}

func directEngineError(err error) (*EngineError, bool) {
	value := reflect.ValueOf(err)
	if !value.IsValid() || value.Type() != reflect.TypeFor[*EngineError]() || value.Kind() != reflect.Pointer || value.IsNil() {
		return nil, false
	}
	engine, ok := value.Interface().(*EngineError)
	return engine, ok
}

func validatePath(operation engineOperation, path string) error {
	if path == "" || strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return adapterError(operation, EngineInvalidInput, codeEINVAL, "path must be nonempty, NUL-free, absolute and clean", nil)
	}
	return nil
}

func requireCreateTargetAbsent(path string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return adapterError(operationCreate, EngineInvalidInput, codeEExist, "Create path already exists", nil)
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return ioError(operationCreate, "inspect Create path", err)
}

func createDirectory(path string) error {
	err := os.Mkdir(path, 0o700)
	if err != nil {
		return ioError(operationCreate, "create environment directory", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return ioError(operationCreate, "read back environment directory", err)
	}
	if !validDirectoryInfo(info, false) {
		return integrityError(operationCreate, "environment directory is unsafe", nil)
	}
	err = os.Chmod(path, 0o700)
	if err != nil {
		return ioError(operationCreate, "normalize environment directory mode", err)
	}
	info, err = os.Lstat(path)
	if err != nil {
		return ioError(operationCreate, "read back environment directory", err)
	}
	if !validDirectoryInfo(info, true) {
		return integrityError(operationCreate, "environment directory is unsafe", nil)
	}
	return nil
}

func validateOpenArtifacts(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, adapterError(operationOpen, EngineInvalidInput, codeENOFile, "Open path is absent", nil)
	}
	if err != nil {
		return false, ioError(operationOpen, "inspect environment directory", err)
	}
	if !validDirectoryInfo(info, true) {
		return false, integrityError(operationOpen, "environment directory is unsafe", nil)
	}
	for _, name := range [...]string{"mdbx.dat", "mdbx.lck"} {
		_, err = inspectOpenFile(path, name, false, false)
		if err != nil {
			return false, err
		}
	}
	return inspectOpenFile(path, "rubin-writer.lock", true, false)
}

func validateOpenStatic(cfg ConfigV1) error {
	_, err := cfg.Encode()
	if err != nil {
		return adapterError(operationOpen, EngineInvalidInput, codeEINVAL, "invalid ConfigV1", err)
	}
	return nil
}

func validatePreopenSnapshot(path string) error {
	pathBytes := append([]byte(path), 0)
	var info C.MDBX_envinfo
	rc := int(C.mdbx_preopen_snapinfo((*C.char)(unsafe.Pointer(&pathBytes[0])), &info, C.size_t(unsafe.Sizeof(info))))
	runtime.KeepAlive(pathBytes)
	if rc == codeSuccess {
		return nil
	}
	if rc == int(C.MDBX_ENODATA) {
		return integrityError(operationOpen, "mdbx.dat is undersized", nil)
	}
	return nativeError(operationOpen, rc)
}

func inspectOpenFile(path, name string, empty, missingAllowed bool) (bool, error) {
	info, err := os.Lstat(filepath.Join(path, name))
	if errors.Is(err, os.ErrNotExist) {
		if missingAllowed {
			return true, nil
		}
		return false, adapterError(operationOpen, EngineInvalidInput, codeENOFile, name+" is absent", nil)
	}
	if err != nil {
		return false, ioError(operationOpen, "inspect "+name, err)
	}
	if !validFileInfo(info, empty, true) {
		return false, integrityError(operationOpen, name+" is unsafe", nil)
	}
	return false, nil
}

func validDirectoryInfo(info os.FileInfo, exactMode bool) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0 && (!exactMode || exactPermissionBits(info.Mode()) == 0o700)
}

func validFileInfo(info os.FileInfo, empty, exactMode bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return info.Mode().IsRegular() && ok && uint64(stat.Nlink) == 1 && (!empty || info.Size() == 0) && (!exactMode || exactPermissionBits(info.Mode()) == 0o600)
}

func exactPermissionBits(mode os.FileMode) os.FileMode {
	return mode & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
}

var normalizeMDBXModule = sync.OnceValue(func() error {
	result := C.rubin_mdbx_normalize_debug()
	return debugNormalizationError(int(result.first), int(result.second))
})

func debugNormalizationError(first, second int) error {
	if first < 0 {
		return adapterError(operationInit, EngineLocalInvariant, codeProblem, "MDBX debug normalization failed", nil)
	}
	if second != 0x00030000 {
		return adapterError(operationInit, EngineLocalInvariant, codeProblem, "MDBX debug normalization did not stabilize", nil)
	}
	return nil
}

func acquireWriter(path string, operation engineOperation, create bool) (*filelock.Handle, error) {
	lockPath := filepath.Join(path, "rubin-writer.lock")
	handle, result, err := filelock.AcquireDirectory(path)
	if err != nil {
		return nil, writerLockError(operation, result, err)
	}
	if create {
		err = createWriterMarker(lockPath, operation)
		if err == nil {
			err = normalizeOwnedFile(lockPath, "rubin-writer.lock", true, operation, "normalize Rubin writer lock mode", "read back Rubin writer lock")
		}
	} else {
		err = readOwnedFile(lockPath, "rubin-writer.lock", true, operation, "read back Rubin writer lock")
	}
	if err != nil {
		return nil, joinErrors(err, releaseError(handle))
	}
	return handle, nil
}

func createWriterMarker(lockPath string, operation engineOperation) error {
	marker, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return writerLockError(operation, filelock.ResultInvalidOrUnopenable, err)
	}
	closeErr := marker.Close()
	if closeErr != nil {
		return writerLockError(operation, filelock.ResultInvalidOrUnopenable, closeErr)
	}
	return nil
}

func normalizeOwnedFile(path, name string, empty bool, operation engineOperation, normalizeDiagnostic, readDiagnostic string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return ioError(operation, readDiagnostic, err)
	}
	if !validFileInfo(info, empty, false) {
		return integrityError(operation, name+" is unsafe", nil)
	}
	err = os.Chmod(path, 0o600)
	if err != nil {
		return ioError(operation, normalizeDiagnostic, err)
	}
	return readOwnedFile(path, name, empty, operation, readDiagnostic)
}

func readOwnedFile(path, name string, empty bool, operation engineOperation, diagnostic string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return ioError(operation, diagnostic, err)
	}
	if !validFileInfo(info, empty, true) {
		return integrityError(operation, name+" is unsafe", nil)
	}
	return nil
}

type nativeLimits struct{ minDB, maxDB, maxKey, maxValue int64 }

func limitsForPage(pageSize uint32) nativeLimits {
	page := C.intptr_t(pageSize)
	return nativeLimits{minDB: int64(C.mdbx_limits_dbsize_min(page)), maxDB: int64(C.mdbx_limits_dbsize_max(page)), maxKey: int64(C.mdbx_limits_keysize_max(page, C.MDBX_DB_DEFAULTS)), maxValue: int64(C.mdbx_limits_valsize_max(page, C.MDBX_DB_DEFAULTS))}
}

func validateLimits(cfg ConfigV1, limits nativeLimits) error {
	if limits.minDB < 0 || limits.maxDB < limits.minDB || limits.maxKey < 77 || limits.maxValue < 68_000_125 {
		return fmt.Errorf("native limits min=%d max=%d key=%d value=%d", limits.minDB, limits.maxDB, limits.maxKey, limits.maxValue)
	}
	if cfg.Lower < uint64(limits.minDB) || cfg.Now < uint64(limits.minDB) || cfg.Upper > uint64(limits.maxDB) {
		return fmt.Errorf("geometry [%d,%d,%d] outside [%d,%d]", cfg.Lower, cfg.Now, cfg.Upper, limits.minDB, limits.maxDB)
	}
	return nil
}

func (s *Store) createEnvironment(path string, cfg ConfigV1) error {
	err := openNativeEnvironment(s.env, path, C.MDBX_NOSTICKYTHREADS, 0o600, operationCreate)
	if err != nil {
		return err
	}
	for _, name := range [...]string{"mdbx.dat", "mdbx.lck"} {
		err = normalizeOwnedFile(filepath.Join(path, name), name, false, operationCreate, "normalize "+name+" mode", "read back "+name)
		if err != nil {
			return err
		}
	}
	effective, err := readEffective(s.env, nil, operationCreate)
	if err != nil {
		return err
	}
	err = validateEffective(cfg, effective)
	if err != nil {
		return integrityError(operationCreate, "effective environment mismatch", err)
	}
	return nil
}

func (s *Store) configureCreateEnvironment(path string, cfg ConfigV1) error {
	err := s.allocateEnvironment(operationCreate)
	if err != nil {
		return err
	}
	maxDBs := C.MDBX_dbi(7)
	if fixtureCreateExtraDBI != nil && fixtureCreateExtraDBI(path) {
		maxDBs = 8
	}
	if rc := int(C.mdbx_env_set_maxdbs(s.env, maxDBs)); rc != codeSuccess {
		return nativeError(operationCreate, rc)
	}
	if rc := int(C.mdbx_env_set_maxreaders(s.env, C.uint(cfg.MaxReaders))); rc != codeSuccess {
		return nativeError(operationCreate, rc)
	}
	if rc := int(C.mdbx_env_set_geometry(s.env, C.intptr_t(cfg.Lower), C.intptr_t(cfg.Now), C.intptr_t(cfg.Upper), C.intptr_t(cfg.Growth), C.intptr_t(cfg.Shrink), C.intptr_t(cfg.PageSize))); rc != codeSuccess {
		return nativeError(operationCreate, rc)
	}
	return validateCreateGeometry(s.env, cfg)
}

func validateCreateGeometry(env *C.MDBX_env, cfg ConfigV1) error {
	var info C.MDBX_envinfo
	if rc := int(C.mdbx_env_info_ex(env, nil, &info, C.size_t(unsafe.Sizeof(info)))); rc != codeSuccess {
		return nativeError(operationCreate, rc)
	}
	for _, field := range []struct {
		name      string
		got, want uint64
	}{{"PageSize", uint64(info.mi_dxb_pagesize), uint64(cfg.PageSize)}, {"Lower", uint64(info.mi_geo.lower), cfg.Lower}, {"Now", uint64(info.mi_geo.current), cfg.Now}, {"Upper", uint64(info.mi_geo.upper), cfg.Upper}, {"Growth", uint64(info.mi_geo.grow), cfg.Growth}, {"Shrink", uint64(info.mi_geo.shrink), cfg.Shrink}} {
		if field.got != field.want {
			err := fmt.Errorf("%s: got %d, want %d", field.name, field.got, field.want)
			return adapterError(operationCreate, EngineInvalidInput, codeEINVAL, "ConfigV1 geometry is not natively representable", err)
		}
	}
	return nil
}

func (s *Store) openEnvironment(path string, cfg ConfigV1) error {
	err := s.allocateEnvironment(operationOpen)
	if err != nil {
		return err
	}
	if rc := int(C.mdbx_env_set_maxdbs(s.env, 7)); rc != codeSuccess {
		return nativeError(operationOpen, rc)
	}
	if rc := int(C.mdbx_env_set_maxreaders(s.env, C.uint(cfg.MaxReaders))); rc != codeSuccess {
		return nativeError(operationOpen, rc)
	}
	err = openNativeEnvironment(s.env, path, C.MDBX_NOSTICKYTHREADS, 0, operationOpen)
	if err != nil {
		return err
	}
	for _, name := range []string{"mdbx.dat", "mdbx.lck"} {
		err = readOwnedFile(filepath.Join(path, name), name, false, operationOpen, "read back "+name)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) allocateEnvironment(operation engineOperation) error {
	created := C.rubin_mdbx_env_create()
	err := nativePointerResultError(operation, "mdbx_env_create returned invalid result shape", int(created.rc), created.env != nil)
	if err != nil {
		return err
	}
	s.env = created.env
	return nil
}

func nativePointerResultError(operation engineOperation, diagnostic string, rc int, present bool) error {
	if !validEngineOperation(operation) {
		return adapterError(operation, EngineLocalInvariant, codeProblem, diagnostic, nil)
	}
	if rc == codeSuccess && present {
		return nil
	}
	if rc == codeSuccess {
		return adapterError(operation, EngineLocalInvariant, codeProblem, diagnostic, nil)
	}
	native := nativeError(operation, rc)
	if !present {
		return native
	}
	return adapterError(operation, EngineLocalInvariant, codeProblem, diagnostic, native)
}

func openNativeEnvironment(env *C.MDBX_env, path string, flags C.MDBX_env_flags_t, mode C.mdbx_mode_t, operation engineOperation) error {
	pathBytes := append([]byte(path), 0)
	rc := int(C.mdbx_env_open(env, (*C.char)(unsafe.Pointer(&pathBytes[0])), flags, mode))
	runtime.KeepAlive(pathBytes)
	if rc != codeSuccess {
		return nativeError(operation, rc)
	}
	return nil
}

type effectiveConfig struct {
	flags, mode, pageSize, systemPageSize uint32
	maxReaders                            uint32
	lower, current, upper, growth, shrink uint64
	maxKey, maxValue                      int64
	limits                                nativeLimits
}

func readEffective(env *C.MDBX_env, txn *C.MDBX_txn, operation engineOperation) (effectiveConfig, error) {
	var flags C.uint
	if rc := int(C.mdbx_env_get_flags(env, &flags)); rc != codeSuccess {
		return effectiveConfig{}, nativeError(operation, rc)
	}
	var info C.MDBX_envinfo
	if rc := int(C.mdbx_env_info_ex(env, txn, &info, C.size_t(unsafe.Sizeof(info)))); rc != codeSuccess {
		return effectiveConfig{}, nativeError(operation, rc)
	}
	pageSize := uint32(info.mi_dxb_pagesize)
	return effectiveConfig{flags: uint32(flags), mode: uint32(info.mi_mode), pageSize: pageSize, systemPageSize: uint32(info.mi_sys_pagesize), maxReaders: uint32(info.mi_maxreaders), lower: uint64(info.mi_geo.lower), current: uint64(info.mi_geo.current), upper: uint64(info.mi_geo.upper), growth: uint64(info.mi_geo.grow), shrink: uint64(info.mi_geo.shrink), maxKey: int64(C.mdbx_env_get_maxkeysize_ex(env, C.MDBX_DB_DEFAULTS)), maxValue: int64(C.mdbx_env_get_maxvalsize_ex(env, C.MDBX_DB_DEFAULTS)), limits: limitsForPage(pageSize)}, nil
}

func validateEffective(cfg ConfigV1, got effectiveConfig) error {
	err := validateEffectiveHeader(cfg, got)
	if err != nil {
		return err
	}
	for _, field := range []struct {
		name      string
		got, want uint64
	}{
		{"Lower", got.lower, cfg.Lower},
		{"Upper", got.upper, cfg.Upper},
		{"Growth", got.growth, cfg.Growth},
		{"Shrink", got.shrink, cfg.Shrink},
	} {
		if field.got != field.want {
			return fmt.Errorf("%s: got %d, want %d", field.name, field.got, field.want)
		}
	}
	if !validEffectiveCurrent(cfg, got.current) {
		return fmt.Errorf("%s: got %d outside aligned [%d,%d]", "Current", got.current, cfg.Lower, cfg.Upper)
	}
	if got.maxKey < 77 {
		return fmt.Errorf("MaxKey: got %d, want at least 77", got.maxKey)
	}
	if got.maxValue < 68_000_125 {
		return fmt.Errorf("MaxValue: got %d, want at least 68000125", got.maxValue)
	}
	return validateLimits(cfg, got.limits)
}

func validateEffectiveHeader(cfg ConfigV1, got effectiveConfig) error {
	if got.flags != 0x02200000 {
		return fmt.Errorf("flags: got %#x, want 0x2200000", got.flags)
	}
	if got.mode != 0 {
		return fmt.Errorf("mode: got %#x, want 0", got.mode)
	}
	if got.pageSize != cfg.PageSize {
		return fmt.Errorf("PageSize: got %d, want %d", got.pageSize, cfg.PageSize)
	}
	return validateEffectiveMaxReaders(cfg.MaxReaders, got.maxReaders, got.systemPageSize)
}

func validateEffectiveMaxReaders(requested, effective, systemPageSize uint32) error {
	if systemPageSize < 256 || systemPageSize > 16*1024*1024 || systemPageSize&(systemPageSize-1) != 0 {
		return fmt.Errorf("%s: got %d outside supported power-of-two [256,16777216]", "SystemPageSize", systemPageSize)
	}
	upper := uint64(requested) + uint64(systemPageSize)/32 - 1
	if upper > 32767 {
		upper = 32767
	}
	if effective < requested || effective > 32767 || uint64(effective) > upper {
		return fmt.Errorf("%s: got %d outside native rounding [%d,%d] for system page %d", "MaxReaders", effective, requested, upper, systemPageSize)
	}
	return nil
}

func validEffectiveCurrent(cfg ConfigV1, current uint64) bool {
	return current >= cfg.Lower && current <= cfg.Upper && current%uint64(cfg.PageSize) == 0
}

type transactionOutcome struct {
	err      error
	poisoned bool
}

func runLocked(operation func() transactionOutcome) transactionOutcome {
	result := make(chan transactionOutcome, 1)
	go func() {
		runtime.LockOSThread()
		outcome := operation()
		if !outcome.poisoned {
			runtime.UnlockOSThread()
		}
		result <- outcome
		if outcome.poisoned {
			select {}
		}
	}()
	return <-result
}

func (s *Store) initializeLocked(cfg ConfigV1, encodedConfig []byte) transactionOutcome {
	begun := C.rubin_mdbx_txn_begin(s.env, C.MDBX_TXN_READWRITE)
	err := nativePointerResultError(operationInit, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil)
	if err != nil {
		if begun.txn != nil {
			return s.poison(begun.txn, err)
		}
		return transactionOutcome{err: err}
	}
	dbis, err := initializeSchema(begun.txn, encodedConfig)
	if err != nil {
		return s.abortLocked(begun.txn, err)
	}
	rc := int(C.mdbx_txn_commit(begun.txn))
	decision := commitTransition(rc)
	var commitErr error
	if rc != codeSuccess {
		commitErr = nativeError(operationInit, rc)
	}
	result := orderedErrors(operationInit, decision.order, nil, commitErr)
	if !decision.consumed {
		return s.poison(begun.txn, result)
	}
	if result != nil {
		return transactionOutcome{err: result}
	}
	s.state, s.config, s.dbis = storeOPEN, cfg, dbis
	return transactionOutcome{}
}

func initializeSchema(txn *C.MDBX_txn, encodedConfig []byte) ([7]C.MDBX_dbi, error) {
	dbis, err := openSchemaDBIs(txn, true, operationInit)
	if err != nil {
		return dbis, err
	}
	err = putRequiredMeta(txn, dbis[0], encodedConfig)
	if err != nil {
		return dbis, err
	}
	if fixtureBeforeInitCensus != nil {
		err = fixtureBeforeInitCensus(txn, dbis[0])
		if err != nil {
			return dbis, err
		}
	}
	err = verifyMainCardinality(txn, operationInit)
	if err != nil {
		return dbis, err
	}
	return dbis, verifyCreatedMeta(txn, dbis[0], encodedConfig)
}

func (s *Store) inspectOpenLocked(cfg ConfigV1) transactionOutcome {
	begun := C.rubin_mdbx_txn_begin(s.env, C.MDBX_TXN_RDONLY)
	err := nativePointerResultError(operationOpen, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil)
	if err != nil {
		if begun.txn != nil {
			return s.poison(begun.txn, err)
		}
		return transactionOutcome{err: err}
	}
	dbis, primary := inspectSchema(s.env, begun.txn, cfg)
	outcome := s.abortLocked(begun.txn, primary)
	if outcome.err == nil && !outcome.poisoned {
		s.state, s.config, s.dbis = storeOPEN, cfg, dbis
	}
	return outcome
}

func inspectSchema(env *C.MDBX_env, txn *C.MDBX_txn, cfg ConfigV1) ([7]C.MDBX_dbi, error) {
	err := verifyMainCardinality(txn, operationOpen)
	if err != nil {
		return [7]C.MDBX_dbi{}, err
	}
	dbis, err := openSchemaDBIs(txn, false, operationOpen)
	if err != nil {
		return dbis, err
	}
	stored, err := readRequiredMeta(txn, dbis[0])
	if err != nil {
		return dbis, err
	}
	err = validateStoredConfig(stored, cfg)
	if err != nil {
		return dbis, integrityError(operationOpen, "effective environment mismatch", err)
	}
	effective, err := readEffective(env, txn, operationOpen)
	if err != nil {
		return dbis, err
	}
	if err = validateEffective(cfg, effective); err != nil {
		return dbis, integrityError(operationOpen, "effective environment mismatch", err)
	}
	return dbis, nil
}

func validateStoredConfig(stored, caller ConfigV1) error {
	for _, field := range []struct {
		name        string
		got, wanted uint64
	}{
		{"Lower", stored.Lower, caller.Lower},
		{"Now", stored.Now, caller.Now},
		{"Upper", stored.Upper, caller.Upper},
		{"Growth", stored.Growth, caller.Growth},
		{"Shrink", stored.Shrink, caller.Shrink},
		{"PageSize", uint64(stored.PageSize), uint64(caller.PageSize)},
		{"MaxReaders", uint64(stored.MaxReaders), uint64(caller.MaxReaders)},
	} {
		if field.got != field.wanted {
			return fmt.Errorf("%s: got %d, want %d", field.name, field.got, field.wanted)
		}
	}
	return nil
}

func (s *Store) abortLocked(txn *C.MDBX_txn, primary error) transactionOutcome {
	rc := int(C.mdbx_txn_abort(txn))
	decision := abortTransition(rc, primary != nil)
	var abortErr error
	if rc != codeSuccess {
		abortErr = nativeError(operationAbort, rc)
	}
	result := orderedErrors(operationAbort, decision.order, primary, abortErr)
	if !decision.consumed {
		return s.poison(txn, result)
	}
	return transactionOutcome{err: result}
}

func (s *Store) poison(txn *C.MDBX_txn, err error) transactionOutcome {
	s.state, s.txn, s.config, s.dbis, s.terminal = storePOISONEDTHREAD, txn, ConfigV1{}, [7]C.MDBX_dbi{}, err
	return transactionOutcome{err: err, poisoned: true}
}

func openSchemaDBIs(txn *C.MDBX_txn, create bool, operation engineOperation) ([7]C.MDBX_dbi, error) {
	var opened [7]C.MDBX_dbi
	flags := C.MDBX_db_flags_t(C.MDBX_DB_ACCEDE)
	if create {
		flags = C.MDBX_DB_DEFAULTS | C.MDBX_CREATE
	}
	for i, dbi := range SchemaV1DBIs() {
		name := append([]byte(dbi.Name), 0)
		rc := int(C.mdbx_dbi_open(txn, (*C.char)(unsafe.Pointer(&name[0])), flags, &opened[i]))
		runtime.KeepAlive(name)
		if rc != codeSuccess {
			if !create {
				return opened, metadataError(operation, rc, codeNotFound)
			}
			return opened, nativeError(operation, rc)
		}
		var persistent, state C.uint
		if rc = int(C.mdbx_dbi_flags_ex(txn, opened[i], &persistent, &state)); rc != codeSuccess {
			return opened, nativeError(operation, rc)
		}
		if persistent != 0 {
			return opened, integrityError(operation, "SchemaV1 DBI flags mismatch", nil)
		}
	}
	return opened, nil
}

func putRequiredMeta(txn *C.MDBX_txn, meta C.MDBX_dbi, encodedConfig []byte) error {
	for _, row := range []struct{ key, value []byte }{{[]byte{0}, []byte{0, 0, 0, 1}}, {[]byte{1}, encodedConfig}} {
		rc := int(C.rubin_mdbx_put_required(txn, meta, unsafe.Pointer(&row.key[0]), C.size_t(len(row.key)), unsafe.Pointer(&row.value[0]), C.size_t(len(row.value))))
		runtime.KeepAlive(row)
		if rc != codeSuccess {
			return metadataError(operationInit, rc, codeKeyExist)
		}
	}
	return nil
}

func verifyMainCardinality(txn *C.MDBX_txn, operation engineOperation) error {
	var main C.MDBX_dbi
	if rc := int(C.mdbx_dbi_open(txn, nil, C.MDBX_DB_DEFAULTS, &main)); rc != codeSuccess {
		return nativeError(operation, rc)
	}
	var stat C.MDBX_stat
	if rc := int(C.mdbx_dbi_stat(txn, main, &stat, C.size_t(unsafe.Sizeof(stat)))); rc != codeSuccess {
		return nativeError(operation, rc)
	}
	if uint64(stat.ms_entries) != 7 {
		return integrityError(operation, "SchemaV1 main cardinality mismatch", nil)
	}
	return nil
}

func verifyCreatedMeta(txn *C.MDBX_txn, meta C.MDBX_dbi, encodedConfig []byte) error {
	var stat C.MDBX_stat
	if rc := int(C.mdbx_dbi_stat(txn, meta, &stat, C.size_t(unsafe.Sizeof(stat)))); rc != codeSuccess {
		return nativeError(operationInit, rc)
	}
	if uint64(stat.ms_entries) != 2 {
		return integrityError(operationInit, "SchemaV1 metadata cardinality mismatch", nil)
	}
	if err := verifyExactValue(txn, meta, []byte{0}, []byte{0, 0, 0, 1}, operationInit); err != nil {
		return err
	}
	return verifyExactValue(txn, meta, []byte{1}, encodedConfig, operationInit)
}

func readRequiredMeta(txn *C.MDBX_txn, meta C.MDBX_dbi) (ConfigV1, error) {
	version, err := getSizedValue(txn, meta, []byte{0}, 4, operationOpen)
	if err != nil {
		return ConfigV1{}, err
	}
	if err = DecodeSchemaVersionValue(version); err != nil {
		return ConfigV1{}, integrityError(operationOpen, "invalid SchemaV1 version row", err)
	}
	encoded, err := getSizedValue(txn, meta, []byte{1}, 48, operationOpen)
	if err != nil {
		return ConfigV1{}, err
	}
	cfg, err := DecodeConfigV1(encoded)
	if err != nil {
		return ConfigV1{}, integrityError(operationOpen, "invalid ConfigV1 row", err)
	}
	return cfg, nil
}

func verifyExactValue(txn *C.MDBX_txn, dbi C.MDBX_dbi, key, expected []byte, operation engineOperation) error {
	value, err := getSizedValue(txn, dbi, key, len(expected), operation)
	if err != nil {
		return err
	}
	if !bytes.Equal(value, expected) {
		return integrityError(operation, "required metadata value mismatch", nil)
	}
	return nil
}

func getSizedValue(txn *C.MDBX_txn, dbi C.MDBX_dbi, key []byte, size int, operation engineOperation) ([]byte, error) {
	value := C.rubin_mdbx_get(txn, dbi, unsafe.Pointer(&key[0]), C.size_t(len(key)))
	runtime.KeepAlive(key)
	if err := requiredValueResult(operation, int(value.rc), uint64(value.length), value.bytes != nil, uint64(size)); err != nil {
		return nil, err
	}
	return C.GoBytes(unsafe.Pointer(value.bytes), C.int(size)), nil
}

func (s *Store) consumeFailure(primary error) (*Store, error) {
	retained, err := s.consume(primary)
	if retained {
		return s, err
	}
	return nil, err
}

func (s *Store) consume(primary error) (bool, error) {
	nativeOutcome := primary
	if s.env != nil {
		rc := int(C.mdbx_env_close_ex(s.env, false))
		decision := closeTransition(rc, primary != nil)
		var closeErr error
		if rc != codeSuccess {
			closeErr = nativeError(operationClose, rc)
		}
		nativeOutcome = orderedErrors(operationClose, decision.order, primary, closeErr)
		if !decision.consumed {
			if s.state != storeCLOSEBLOCKED {
				s.state, s.terminal = decision.next, nativeOutcome
			}
			return true, s.terminal
		}
		s.env = nil
	}
	releaseErr := releaseError(s.writer)
	s.writer, s.txn = nil, nil
	s.config, s.dbis = ConfigV1{}, [7]C.MDBX_dbi{}
	s.state = storeCLOSED
	s.terminal = joinErrors(nativeOutcome, releaseErr)
	return false, s.terminal
}

func releaseError(handle *filelock.Handle) error {
	return releaseResult(handle.Release())
}

func releaseResult(err error) error {
	if err == nil {
		return nil
	}
	return ioError(operationClose, "release Rubin writer lock", err)
}
