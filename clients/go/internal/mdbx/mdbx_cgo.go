//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

/*
#cgo CFLAGS: -std=c11
#include "../../../../third_party/libmdbx/mdbx.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

type engineOperation string

const (
	operationCreate engineOperation = "create"
	operationOpen   engineOperation = "open"
	operationInit   engineOperation = "init"
	operationAbort  engineOperation = "abort"
	operationClose  engineOperation = "close"
)

func validEngineOperation(operation engineOperation) bool {
	return operation == operationCreate || operation == operationOpen || operation == operationInit || operation == operationAbort || operation == operationClose
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

func orderedErrors(operation engineOperation, order errorOrder, primary, result error) error {
	if !validEngineOperation(operation) {
		return adapterError(operation, EngineLocalInvariant, codeProblem, "unsupported engine operation", joinErrors(primary, result))
	}
	engine, validResult := result.(*EngineError)
	validResult = validResult && engine != nil && engine.Operation == string(operation) && validEngineClass(engine.Class) && engine.Code != codeSuccess && engine.Class == classifyNative(operation, engine.Code) && engine.ReopenRequired == reopenRequired(engine.Code)
	if (order == orderResult || order == orderPrimaryResult || order == orderResultCausesPrimary) && !validResult {
		return adapterError(operation, EngineLocalInvariant, codeProblem, "native result is not an EngineError", joinErrors(primary, result))
	}
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
