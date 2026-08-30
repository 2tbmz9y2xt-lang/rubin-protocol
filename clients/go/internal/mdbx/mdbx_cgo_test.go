//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

func sameError(got, want error) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	gotValue, wantValue := reflect.ValueOf(got), reflect.ValueOf(want)
	return gotValue.Type() == wantValue.Type() && gotValue.Kind() == reflect.Pointer && gotValue.Pointer() == wantValue.Pointer()
}

type nilPointerError struct{}

func (*nilPointerError) Error() string { return "nil pointer" }
func (*nilPointerError) Unwrap() error { return syscall.ENOSPC }

type panicErrorWrapper struct{ cause error }

func (w panicErrorWrapper) Error() string { return w.cause.Error() }
func (panicErrorWrapper) Unwrap() error   { panic("Unwrap called") }
func (panicErrorWrapper) As(any) bool     { panic("As called") }

var pinnedNegativeDiagnostics = map[int]string{
	-1:     "error -1",
	-30799: "MDBX_KEYEXIST: Key/data pair already exists",
	-30798: "MDBX_NOTFOUND: No matching key/data pair found",
	-30797: "MDBX_PAGE_NOTFOUND: Requested page not found",
	-30796: "MDBX_CORRUPTED: Database is corrupted",
	-30795: "MDBX_PANIC: Environment had fatal error",
	-30794: "MDBX_VERSION_MISMATCH: DB version mismatch libmdbx",
	-30793: "MDBX_INVALID: File is not an MDBX file",
	-30792: "MDBX_MAP_FULL: Environment mapsize limit reached",
	-30791: "MDBX_DBS_FULL: Too many DBI-handles (maxdbs reached)",
	-30790: "MDBX_READERS_FULL: Too many readers (maxreaders reached)",
	-30788: "MDBX_TXN_FULL: Transaction has too many dirty pages, i.e transaction is too big",
	-30787: "MDBX_CURSOR_FULL: Cursor stack limit reached - this usually indicates corruption, i.e branch-pages loop",
	-30786: "MDBX_PAGE_FULL: Internal error - Page has no more space",
	-30785: "MDBX_UNABLE_EXTEND_MAPSIZE: Database engine was unable to extend mapping, e.g. since address space is unavailable or busy, or Operation system not supported such operations",
	-30784: "MDBX_INCOMPATIBLE: Environment or database is not compatible with the requested operation or the specified flags",
	-30783: "MDBX_BAD_RSLOT: Reader locktable slot was unexpectly reused or cleared by an enemy thread",
	-30782: "MDBX_BAD_TXN: Transaction is not valid for requested operation, e.g. had errored and be must aborted, has a child, or is invalid",
	-30781: "MDBX_BAD_VALSIZE: Invalid size or alignment of key or data for target database, either invalid table name",
	-30780: "MDBX_BAD_DBI: The specified DBI-handle is invalid or changed by another thread/transaction",
	-30779: "MDBX_PROBLEM: Unexpected internal error, transaction should be aborted",
	-30778: "MDBX_BUSY: Another write transaction is running, or environment is already used while opening with MDBX_EXCLUSIVE flag",
	-30421: "MDBX_EMULTIVAL: The specified key has more than one associated value",
	-30420: "MDBX_EBADSIGN: Wrong signature of a runtime object(s), e.g. memory corruption or double-free",
	-30419: "MDBX_WANNA_RECOVERY: Database should be recovered, but this could NOT be done automatically for now since it opened in read-only mode",
	-30418: "MDBX_EKEYMISMATCH: The given key value is mismatched to the current cursor position",
	-30417: "MDBX_TOO_LARGE: Database is too large for current system, e.g. could NOT be mapped into RAM",
	-30416: "MDBX_THREAD_MISMATCH: A thread has attempted to use a not owned object, e.g. a transaction that started by another thread",
	-30415: "MDBX_TXN_OVERLAPPING: Overlapping read and write transactions for the current thread",
	-30414: "error -30414",
	-30413: "MDBX_DUPLICATED_LCK: Alternative/Duplicate LCK-file is exists, please keep one and remove unused other",
	-30412: "MDBX_DANGLING_DBI: Some cursors and/or other resources should be closed before table or corresponding DBI-handle could be (re)used",
	-30411: "MDBX_OUSTED: The parked read transaction was outed for the sake of recycling old MVCC snapshots",
	-30410: "MDBX_MVCC_RETARDED: MVCC snapshot used by parked transaction was bygone",
	-30409: "An operation cannot continue because a lagging reader is interfering with the reclaiming of GC and old MVCC-snapshots",
}

func expectedNativeDiagnostic(code int) string {
	if diagnostic, ok := pinnedNegativeDiagnostics[code]; ok {
		return diagnostic
	}
	return fmt.Sprintf("error %d", code)
}

//nolint:errorlint // Exact direct EngineError output is required.
func requireEngineError(t *testing.T, err error, class EngineClass, operation engineOperation, code int) *EngineError {
	t.Helper()
	engine, ok := err.(*EngineError)
	if !ok || engine == nil || engine.Class != class || engine.Operation != string(operation) || engine.Code != code {
		t.Fatalf("error=%v, want %s/%s/%d", err, class, operation, code)
	}
	return engine
}

func requireFallback(t *testing.T, operation engineOperation, order errorOrder, primary, result error, diagnostic, causeText string, identities ...error) {
	got := requireEngineError(t, orderedErrors(operation, order, primary, result), EngineLocalInvariant, operation, codeProblem)
	if got.Diagnostic != diagnostic || (got.Cause == nil) != (causeText == "") || got.Cause != nil && got.Cause.Error() != causeText {
		t.Fatalf("fallback=%+v, want %q / %q", got, diagnostic, causeText)
	}
	for _, identity := range identities {
		if !errors.Is(got, identity) {
			t.Fatalf("fallback %v lost %v", got, identity)
		}
	}
}

//nolint:errorlint // Exact unwrap identity is part of the error contract.
func TestEngineErrorAndPinnedMapping(t *testing.T) {
	cause := errors.New("cause")
	var nilEngine *EngineError
	if nilEngine.Error() != "<nil>" || errors.Unwrap(nilEngine) != nil {
		t.Fatal("nil EngineError receiver changed")
	}
	err := &EngineError{Class: EngineIO, Operation: "open", Code: 7, Diagnostic: "diagnostic", Cause: cause}
	if got, want := err.Error(), "open: IO: code 7: diagnostic: cause"; got != want || !errors.Is(err, cause) || errors.Unwrap(err) != cause {
		t.Fatalf("EngineError=%q unwrap=%v", got, errors.Unwrap(err))
	}
	if got := (&EngineError{Class: EngineIO, Operation: "open", Code: 7, Diagnostic: "diagnostic"}).Error(); got != "open: IO: code 7: diagnostic" {
		t.Fatalf("nil-cause EngineError=%q", got)
	}
	if got, want := fmt.Sprint([...]EngineClass{EngineInvalidInput, EngineIntegrity, EngineCapacity, EngineConcurrency, EngineTransaction, EngineIO, EngineStateMismatch, EngineLocalInvariant}), "[InvalidInput Integrity Capacity Concurrency Transaction IO StateMismatch LocalInvariant]"; got != want {
		t.Fatalf("EngineClass values=%s", got)
	}
	if got, want := [...]engineOperation{operationCreate, operationOpen, operationInit, operationAbort, operationClose}, [...]engineOperation{"create", "open", "init", "abort", "close"}; got != want {
		t.Fatalf("engine operations=%v, want %v", got, want)
	}
	remoteCode := int(syscall.ENOTBLK)
	if runtime.GOOS == "linux" {
		remoteCode = 121
	}
	if got, want := [...]int{codeEINVAL, codeEAccess, codeENOMEM, codeEROFS, codeEIO, codeEPerm, codeEIntr, codeEExist, codeENOFile, codeEDeadlock, codeEREMOTE, codeENODEV, codeESTALE, codeENOSPC, codeEDQUOT}, [...]int{int(syscall.EINVAL), int(syscall.EACCES), int(syscall.ENOMEM), int(syscall.EROFS), int(syscall.EIO), int(syscall.EPERM), int(syscall.EINTR), int(syscall.EEXIST), int(syscall.ENOENT), int(syscall.EDEADLK), remoteCode, int(syscall.ENODEV), int(syscall.ESTALE), int(syscall.ENOSPC), int(syscall.EDQUOT)}; got != want {
		t.Fatalf("positive errno bindings=%v, want %v", got, want)
	}
	if got, want := [...]int{codeSuccess, codeEINVAL, codeENOMEM, codeEIO, codeResultTrue, codeKeyExist, codeNotFound, codePageNotFound, codeCorrupted, codePanic, codeVersionMismatch, codeInvalid, codeMapFull, codeDBsFull, codeReadersFull, codeTxnFull, codeCursorFull, codePageFull, codeUnableExtendMapsize, codeIncompatible, codeBadRSlot, codeBadTxn, codeBadValSize, codeBadDBI, codeProblem, codeBusy, codeMultiValue, codeBadSignature, codeWannaRecovery, codeKeyMismatch, codeTooLarge, codeThreadMismatch, codeTxnOverlapping, codeBacklogDepleted, codeDuplicatedLock, codeDanglingDBI, codeOusted, codeMVCCRetarded, codeLaggardReader}, [...]int{0, int(syscall.EINVAL), int(syscall.ENOMEM), int(syscall.EIO), -1, -30799, -30798, -30797, -30796, -30795, -30794, -30793, -30792, -30791, -30790, -30788, -30787, -30786, -30785, -30784, -30783, -30782, -30781, -30780, -30779, -30778, -30421, -30420, -30419, -30418, -30417, -30416, -30415, -30414, -30413, -30412, -30411, -30410, -30409}; got != want {
		t.Fatalf("negative MDBX bindings=%v, want %v", got, want)
	}
	for _, tc := range []struct {
		code int
		want string
	}{{codeCorrupted, "MDBX_CORRUPTED: Database is corrupted"}, {int(syscall.EIO), "error 5"}, {-12345, "error -12345"}, {-1 << 31, "error -2147483648"}, {1<<31 - 1, "error 2147483647"}, {1 << 31, "error code 2147483648 outside C int range"}, {-(1 << 31) - 1, "error code -2147483649 outside C int range"}, {1 << 32, "error code 4294967296 outside C int range"}, {-(1 << 32), "error code -4294967296 outside C int range"}} {
		if got := nativeDiagnostic(tc.code); got != tc.want {
			t.Errorf("nativeDiagnostic(%d)=%q, want %q", tc.code, got, tc.want)
		}
	}
	cases := []struct {
		name      string
		operation engineOperation
		code      int
		class     EngineClass
		reopen    bool
	}{
		{"BAD_VALSIZE", operationInit, codeBadValSize, EngineInvalidInput, false},
		{"EINVAL", operationInit, codeEINVAL, EngineInvalidInput, false},
		{"PAGE_NOTFOUND", operationInit, codePageNotFound, EngineIntegrity, true},
		{"CORRUPTED", operationInit, codeCorrupted, EngineIntegrity, true},
		{"PANIC", operationInit, codePanic, EngineIntegrity, true},
		{"VERSION_MISMATCH", operationInit, codeVersionMismatch, EngineIntegrity, true},
		{"INVALID", operationInit, codeInvalid, EngineIntegrity, true},
		{"WANNA_RECOVERY", operationInit, codeWannaRecovery, EngineIntegrity, true},
		{"DUPLICATED_LCK", operationInit, codeDuplicatedLock, EngineIntegrity, true},
		{"CURSOR_FULL", operationInit, codeCursorFull, EngineIntegrity, true},
		{"MAP_FULL", operationInit, codeMapFull, EngineCapacity, false},
		{"UNABLE_EXTEND_MAPSIZE", operationInit, codeUnableExtendMapsize, EngineCapacity, true},
		{"ENOMEM", operationInit, codeENOMEM, EngineCapacity, false},
		{"ENOSPC", operationInit, codeENOSPC, EngineCapacity, false},
		{"EDQUOT", operationInit, codeEDQUOT, EngineCapacity, false},
		{"READERS_FULL", operationInit, codeReadersFull, EngineConcurrency, false},
		{"BUSY", operationInit, codeBusy, EngineConcurrency, false},
		{"LAGGARD_READER", operationInit, codeLaggardReader, EngineConcurrency, false},
		{"EDEADLK", operationInit, codeEDeadlock, EngineConcurrency, false},
		{"TXN_FULL", operationInit, codeTxnFull, EngineTransaction, false},
		{"RESULT_TRUE", operationInit, codeResultTrue, EngineTransaction, false},
		{"BAD_RSLOT", operationInit, codeBadRSlot, EngineLocalInvariant, false},
		{"PAGE_FULL", operationInit, codePageFull, EngineLocalInvariant, false},
		{"BAD_DBI", operationInit, codeBadDBI, EngineLocalInvariant, false},
		{"DBS_FULL", operationInit, codeDBsFull, EngineLocalInvariant, false},
		{"EMULTIVAL", operationInit, codeMultiValue, EngineLocalInvariant, false},
		{"EKEYMISMATCH", operationInit, codeKeyMismatch, EngineLocalInvariant, false},
		{"BAD_TXN", operationInit, codeBadTxn, EngineLocalInvariant, false},
		{"THREAD_MISMATCH", operationInit, codeThreadMismatch, EngineLocalInvariant, true},
		{"TXN_OVERLAPPING", operationInit, codeTxnOverlapping, EngineLocalInvariant, false},
		{"OUSTED", operationInit, codeOusted, EngineLocalInvariant, false},
		{"MVCC_RETARDED", operationInit, codeMVCCRetarded, EngineLocalInvariant, false},
		{"PROBLEM", operationInit, codeProblem, EngineLocalInvariant, false},
		{"BACKLOG_DEPLETED", operationInit, codeBacklogDepleted, EngineLocalInvariant, false},
		{"DANGLING_DBI", operationInit, codeDanglingDBI, EngineLocalInvariant, false},
		{"EBADSIGN", operationInit, codeBadSignature, EngineLocalInvariant, true},
		{"KEYEXIST native", operationInit, codeKeyExist, EngineLocalInvariant, false},
		{"NOTFOUND native", operationOpen, codeNotFound, EngineLocalInvariant, false},
		{"unknown negative", operationInit, -12345, EngineLocalInvariant, false},
		{"negative EROFS collision", operationInit, -int(syscall.EROFS), EngineLocalInvariant, false},
		{"ENOFILE", operationInit, codeENOFile, EngineIO, false},
		{"EIO", operationInit, codeEIO, EngineIO, false},
		{"EROFS", operationInit, codeEROFS, EngineIO, false},
		{"ENODEV", operationInit, codeENODEV, EngineIO, false},
		{"ESTALE", operationInit, codeESTALE, EngineIO, false},
		{"EREMOTE", operationInit, codeEREMOTE, EngineIO, false},
		{"EACCESS", operationInit, codeEAccess, EngineIO, false},
		{"EPERM", operationInit, codeEPerm, EngineIO, false},
		{"EINTR", operationInit, codeEIntr, EngineIO, false},
		{"unknown positive", operationInit, 12345, EngineIO, false},
		{"create INCOMPATIBLE", operationCreate, codeIncompatible, EngineInvalidInput, false},
		{"open INCOMPATIBLE", operationOpen, codeIncompatible, EngineIntegrity, false},
		{"init INCOMPATIBLE", operationInit, codeIncompatible, EngineLocalInvariant, false},
		{"abort INCOMPATIBLE", operationAbort, codeIncompatible, EngineLocalInvariant, false},
		{"close INCOMPATIBLE", operationClose, codeIncompatible, EngineLocalInvariant, false},
		{"create TOO_LARGE", operationCreate, codeTooLarge, EngineInvalidInput, false},
		{"open TOO_LARGE", operationOpen, codeTooLarge, EngineCapacity, false},
		{"create EEXIST", operationCreate, codeEExist, EngineInvalidInput, false},
		{"open EEXIST", operationOpen, codeEExist, EngineIO, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nativeError(tc.operation, tc.code)
			if got.Class != tc.class || got.Operation != string(tc.operation) || got.Code != tc.code || got.ReopenRequired != tc.reopen || got.Diagnostic != expectedNativeDiagnostic(tc.code) || got.Cause != nil {
				t.Fatalf("error=%+v, want %s/%s/%d reopen=%v", got, tc.class, tc.operation, tc.code, tc.reopen)
			}
		})
	}
}

func TestEngineDomainClosure(t *testing.T) {
	cause := errors.New("cause")
	invalid := engineOperation("invalid")
	if nativeError(operationInit, codeSuccess) != nil || metadataError(operationInit, codeSuccess, codeNotFound) != nil {
		t.Fatal("native or metadata success returned an error")
	}
	for _, tc := range []struct {
		err        error
		keepsCause bool
	}{
		{nativeError(invalid, codeCorrupted), false},
		{nativeError(invalid, codeSuccess), false},
		{metadataError(invalid, codeNotFound, codeNotFound), false},
		{metadataError(invalid, codeSuccess, codeNotFound), false},
		{adapterError(invalid, EngineIO, codeEIO, "ignored", cause), true},
		{integrityError(invalid, "ignored", cause), true},
		{ioError(invalid, "ignored", cause), true},
		{writerLockError(invalid, filelock.ResultInvalidOrUnopenable, cause), true},
		{requiredValueResult(invalid, codeNotFound, 4, true, 4), false},
		{requiredValueResult(invalid, codeSuccess, 4, true, 4), false},
		{orderedErrors(invalid, orderResultCausesPrimary, cause, errors.New("result")), true},
	} {
		got := requireEngineError(t, tc.err, EngineLocalInvariant, operationInit, codeProblem)
		if got.Diagnostic != "unsupported engine operation" || errors.Is(got, cause) != tc.keepsCause {
			t.Errorf("invalid-operation error=%+v cause=%v", got, errors.Unwrap(got))
		}
	}
	invalidPrimary, invalidResult := errors.New("invalid primary"), errors.New("invalid result")
	for _, order := range []errorOrder{orderNone, orderPrimary} {
		got := requireEngineError(t, orderedErrors(invalid, order, invalidPrimary, invalidResult), EngineLocalInvariant, operationInit, codeProblem)
		if got.Diagnostic != "unsupported engine operation" || got.Cause == nil || got.Cause.Error() != "invalid primary\ninvalid result" || !errors.Is(got, invalidPrimary) || !errors.Is(got, invalidResult) {
			t.Errorf("invalid-operation order %d=%+v", order, got)
		}
	}
	if got := adapterError("", EngineStateMismatch, codeInvalid, "ignored", cause); got.Operation != "init" || got.Diagnostic != "unsupported engine operation" || !errors.Is(got, cause) {
		t.Fatalf("empty operation precedence=%+v", got)
	}
	for _, class := range []EngineClass{EngineStateMismatch, "Persistence"} {
		got := requireEngineError(t, adapterError(operationAbort, class, codeInvalid, "ignored", cause), EngineLocalInvariant, operationAbort, codeProblem)
		if got.Diagnostic != "unsupported engine class" || !errors.Is(got, cause) {
			t.Errorf("class %q closure=%+v", class, got)
		}
	}
}

func TestMetadataAndRequiredValueResults(t *testing.T) {
	for _, tc := range []struct {
		name      string
		operation engineOperation
		code      int
		ownership int
		class     EngineClass
		reopen    bool
	}{
		{"owned KEYEXIST", operationInit, codeKeyExist, codeKeyExist, EngineIntegrity, false},
		{"owned NOTFOUND", operationOpen, codeNotFound, codeNotFound, EngineIntegrity, false},
		{"unowned KEYEXIST", operationInit, codeKeyExist, codeNotFound, EngineLocalInvariant, false},
		{"unowned NOTFOUND", operationOpen, codeNotFound, codeKeyExist, EngineLocalInvariant, false},
		{"MAP_FULL same", operationInit, codeMapFull, codeMapFull, EngineCapacity, false},
		{"TXN_FULL same", operationInit, codeTxnFull, codeTxnFull, EngineTransaction, false},
		{"EIO same", operationOpen, codeEIO, codeEIO, EngineIO, false},
		{"unknown same", operationInit, -12345, -12345, EngineLocalInvariant, false},
		{"reopen native same", operationOpen, codePageNotFound, codePageNotFound, EngineIntegrity, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := metadataError(tc.operation, tc.code, tc.ownership)
			if got.Class != tc.class || got.Operation != string(tc.operation) || got.Code != tc.code || got.Diagnostic != expectedNativeDiagnostic(tc.code) || got.ReopenRequired != tc.reopen || got.Cause != nil {
				t.Fatalf("error=%+v, want %s/%s/%d", got, tc.class, tc.operation, tc.code)
			}
		})
	}
	for _, tc := range []struct {
		name, diagnostic string
		rc, code         int
		length, expected uint64
		present, success bool
		class            EngineClass
	}{
		{"success", "", codeSuccess, 0, 4, 4, true, true, ""},
		{"non-4 success", "", codeSuccess, 0, 16, 16, true, true, ""},
		{"not found", "MDBX_NOTFOUND: No matching key/data pair found", codeNotFound, codeNotFound, 0, 4, false, false, EngineIntegrity},
		{"map full", "MDBX_MAP_FULL: Environment mapsize limit reached", codeMapFull, codeMapFull, 0, 4, false, false, EngineCapacity},
		{"wrong width", "required metadata width mismatch", codeSuccess, codeInvalid, 3, 4, true, false, EngineIntegrity},
		{"too wide", "required metadata width mismatch", codeSuccess, codeInvalid, 5, 4, true, false, EngineIntegrity},
		{"nil value", "required metadata width mismatch", codeSuccess, codeInvalid, 4, 4, false, false, EngineIntegrity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := requiredValueResult(operationOpen, tc.rc, tc.length, tc.present, tc.expected)
			if tc.success {
				if err != nil {
					t.Fatalf("error=%v, want nil", err)
				}
				return
			}
			got := requireEngineError(t, err, tc.class, operationOpen, tc.code)
			if got.Diagnostic != tc.diagnostic || got.Cause != nil || errors.Unwrap(got) != nil {
				t.Fatalf("error=%+v, want diagnostic %q with nil cause", got, tc.diagnostic)
			}
		})
	}
}

//nolint:errorlint // Exact cause and passthrough identity are under test.
func TestIOAndWriterLockResults(t *testing.T) {
	var nilCause *nilPointerError
	if got := adapterError(operationInit, EngineIO, codeEIO, "typed nil", nilCause); got.Cause != nilCause || errors.Unwrap(got) != nilCause || got.Error() != fmt.Sprintf("init: IO: code %d: typed nil: nil pointer", int(syscall.EIO)) {
		t.Fatalf("typed-nil adapter cause=%+v", got)
	}
	if got := ioError(operationOpen, "typed nil", nilCause); got.Class != EngineCapacity || got.Code != int(syscall.ENOSPC) || got.Cause != nilCause || !errors.Is(got, syscall.ENOSPC) {
		t.Fatalf("typed-nil IO cause=%+v", got)
	}
	if joinErrors(nilCause) != nilCause || orderedErrors(operationAbort, orderPrimary, nilCause, nil) != nilCause {
		t.Fatal("typed-nil identity was not preserved")
	}
	var nilEngine *EngineError
	wrappedNil := fmt.Errorf("wrapped nil: %w", nilEngine)
	if got := ioError(operationOpen, "wrapped", wrappedNil); got.Class != EngineIO || got.Code != codeEIO || got.Cause != wrappedNil || got.Error() != fmt.Sprintf("open: IO: code %d: wrapped: wrapped nil: <nil>", int(syscall.EIO)) || !errors.Is(got, nilEngine) {
		t.Fatalf("wrapped typed-nil IO cause=%+v", got)
	}
	for _, tc := range []struct {
		name      string
		operation engineOperation
		cause     error
		class     EngineClass
		code      int
	}{
		{"create EEXIST", operationCreate, fmt.Errorf("wrapped: %w", syscall.EEXIST), EngineInvalidInput, int(syscall.EEXIST)},
		{"open EEXIST", operationOpen, fmt.Errorf("wrapped: %w", syscall.EEXIST), EngineIO, int(syscall.EEXIST)},
		{"ENOSPC", operationOpen, fmt.Errorf("wrapped: %w", syscall.ENOSPC), EngineCapacity, int(syscall.ENOSPC)},
		{"EDQUOT", operationCreate, fmt.Errorf("wrapped: %w", syscall.EDQUOT), EngineCapacity, int(syscall.EDQUOT)},
		{"EDEADLK", operationOpen, fmt.Errorf("wrapped: %w", syscall.EDEADLK), EngineConcurrency, int(syscall.EDEADLK)},
		{"fallback", operationOpen, errors.New("plain"), EngineIO, codeEIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ioError(tc.operation, "diagnostic", tc.cause)
			if got.Class != tc.class || got.Code != tc.code || got.Diagnostic != "diagnostic" || errors.Unwrap(got) != tc.cause {
				t.Fatalf("error=%+v, want %s/%d with exact cause", got, tc.class, tc.code)
			}
		})
	}
	for _, tc := range []struct {
		name       string
		operation  engineOperation
		diagnostic string
		result     filelock.Result
		cause      error
		class      EngineClass
		code       int
	}{
		{"contended", operationOpen, "Rubin writer lock is already held", filelock.ResultContended, errors.New("contended"), EngineConcurrency, codeBusy},
		{"invalid ENOSPC", operationOpen, "acquire Rubin writer lock", filelock.ResultInvalidOrUnopenable, fmt.Errorf("wrapped: %w", syscall.ENOSPC), EngineIO, int(syscall.ENOSPC)},
		{"invalid create EEXIST", operationCreate, "acquire Rubin writer lock", filelock.ResultInvalidOrUnopenable, fmt.Errorf("wrapped: %w", syscall.EEXIST), EngineIO, int(syscall.EEXIST)},
		{"unsupported", operationCreate, "unsupported writer-lock result", filelock.ResultUnsupportedHost, errors.New("unsupported"), EngineLocalInvariant, codeProblem},
		{"unknown", operationClose, "unsupported writer-lock result", filelock.Result("unknown"), errors.New("unknown"), EngineLocalInvariant, codeProblem},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := writerLockError(tc.operation, tc.result, tc.cause)
			if got.Class != tc.class || got.Operation != string(tc.operation) || got.Code != tc.code || got.Diagnostic != tc.diagnostic || errors.Unwrap(got) != tc.cause {
				t.Fatalf("error=%+v, want %s/%s/%d/%q with exact cause", got, tc.class, tc.operation, tc.code, tc.diagnostic)
			}
		})
	}
	if !integrityError(operationInit, "invalid", nil).ReopenRequired || !adapterError(operationAbort, EngineLocalInvariant, codeThreadMismatch, "thread", nil).ReopenRequired {
		t.Fatal("adapter reopen bits changed")
	}
}

//nolint:errorlint // Exact result identity and ordering are under test.
func TestPureOwnershipTransitionsAndErrorOrder(t *testing.T) {
	if got, want := [...]storeState{storeOPEN, storeCLOSEBLOCKED, storeCLOSED, storePOISONEDTHREAD}, [...]storeState{"OPEN", "CLOSE_BLOCKED", "CLOSED", "POISONED_THREAD"}; got != want {
		t.Fatalf("store-state tokens=%v, want %v", got, want)
	}
	for _, tc := range []struct {
		name      string
		got, want nativeTransition
	}{
		{"commit success", commitTransition(codeSuccess), nativeTransition{true, storeOPEN, orderNone}},
		{"commit RESULT_TRUE", commitTransition(codeResultTrue), nativeTransition{true, storeCLOSED, orderResult}},
		{"commit mismatch", commitTransition(codeThreadMismatch), nativeTransition{false, storePOISONEDTHREAD, orderResult}},
		{"commit busy", commitTransition(codeBusy), nativeTransition{true, storeCLOSED, orderResult}},
		{"commit error", commitTransition(codeEIO), nativeTransition{true, storeCLOSED, orderResult}},
		{"abort success", abortTransition(codeSuccess, false), nativeTransition{true, storeOPEN, orderNone}},
		{"abort primary", abortTransition(codeSuccess, true), nativeTransition{true, storeCLOSED, orderPrimary}},
		{"abort RESULT_TRUE", abortTransition(codeResultTrue, true), nativeTransition{true, storeCLOSED, orderPrimaryResult}},
		{"abort mismatch", abortTransition(codeThreadMismatch, true), nativeTransition{false, storePOISONEDTHREAD, orderResultCausesPrimary}},
		{"abort mismatch alone", abortTransition(codeThreadMismatch, false), nativeTransition{false, storePOISONEDTHREAD, orderResult}},
		{"abort busy", abortTransition(codeBusy, false), nativeTransition{true, storeCLOSED, orderResult}},
		{"abort error", abortTransition(codeEIO, true), nativeTransition{true, storeCLOSED, orderPrimaryResult}},
		{"close success", closeTransition(codeSuccess, false), nativeTransition{true, storeCLOSED, orderNone}},
		{"close primary", closeTransition(codeSuccess, true), nativeTransition{true, storeCLOSED, orderPrimary}},
		{"close RESULT_TRUE", closeTransition(codeResultTrue, false), nativeTransition{true, storeCLOSED, orderResult}},
		{"close mismatch", closeTransition(codeThreadMismatch, true), nativeTransition{true, storeCLOSED, orderPrimaryResult}},
		{"close busy", closeTransition(codeBusy, false), nativeTransition{false, storeCLOSEBLOCKED, orderResult}},
		{"close busy primary", closeTransition(codeBusy, true), nativeTransition{false, storeCLOSEBLOCKED, orderResultCausesPrimary}},
		{"close error", closeTransition(codeEIO, true), nativeTransition{true, storeCLOSED, orderPrimaryResult}},
	} {
		if tc.got != tc.want {
			t.Errorf("%s transition=%+v, want %+v", tc.name, tc.got, tc.want)
		}
	}
	primary, result, release := errors.New("primary"), errors.New("result"), errors.New("release")
	var typedNil *EngineError
	valueErr := error(syscall.EIO)
	if joinErrors(valueErr) != valueErr {
		t.Fatal("non-nilable value error was omitted")
	}
	if joinErrors(nil) != nil || joinErrors(nil, primary, nil) != primary || joinErrors(typedNil, nil) != typedNil {
		t.Fatal("nil omission or lone-error identity changed")
	}
	if joined := joinErrors(typedNil, primary); joined.Error() != "<nil>\nprimary" || !errors.Is(joined, typedNil) || !errors.Is(joined, primary) {
		t.Fatalf("typed-nil join order=%v", joined)
	}
	input := []error{primary, nil, typedNil, result, release}
	before := [5]error(input)
	if joined := joinErrors(input...); [5]error(input) != before || joined.Error() != "primary\n<nil>\nresult\nrelease" || !errors.Is(joined, primary) || !errors.Is(joined, typedNil) || !errors.Is(joined, result) || !errors.Is(joined, release) {
		t.Fatalf("joined order/causes=%v", joined)
	}
	resultEngine := adapterError(operationAbort, EngineLocalInvariant, codeThreadMismatch, "result", nil)
	if orderedErrors(operationAbort, orderNone, nil, nil) != nil || orderedErrors(operationAbort, orderPrimary, primary, nil) != primary || orderedErrors(operationAbort, orderPrimary, typedNil, nil) != typedNil || orderedErrors(operationAbort, orderResult, nil, resultEngine) != resultEngine {
		t.Fatal("single-result ordering changed")
	}
	requireFallback(t, operationAbort, orderNone, primary, nil, "native errors do not match ordering", "primary", primary)
	requireFallback(t, operationAbort, orderNone, nil, result, "native errors do not match ordering", "result", result)
	requireFallback(t, operationAbort, orderPrimary, nil, nil, "native errors do not match ordering", "")
	requireFallback(t, operationAbort, orderPrimary, primary, result, "native errors do not match ordering", "primary\nresult", primary, result)
	requireFallback(t, operationAbort, orderResult, primary, resultEngine, "native errors do not match ordering", "primary\n"+resultEngine.Error(), primary, resultEngine)
	requireFallback(t, operationAbort, orderPrimaryResult, nil, resultEngine, "native errors do not match ordering", resultEngine.Error(), resultEngine)
	requireFallback(t, operationAbort, orderResultCausesPrimary, nil, resultEngine, "native errors do not match ordering", resultEngine.Error(), resultEngine)
	if ordered := orderedErrors(operationAbort, orderPrimaryResult, primary, resultEngine); ordered.Error() != "primary\n"+resultEngine.Error() || !errors.Is(ordered, primary) || !errors.Is(ordered, resultEngine) {
		t.Fatalf("primary/result order=%v", ordered)
	}
	if got := requireEngineError(t, orderedErrors(operationAbort, orderResultCausesPrimary, primary, resultEngine), EngineLocalInvariant, operationAbort, codeThreadMismatch); errors.Unwrap(got) != primary || got.Error() != "abort: LocalInvariant: code -30416: result: primary" || resultEngine.Cause != nil {
		t.Fatalf("retained result ordering=%v original=%+v", got, resultEngine)
	}
	busy := adapterError(operationClose, EngineConcurrency, codeBusy, "busy", nil)
	if got := requireEngineError(t, orderedErrors(operationClose, orderResultCausesPrimary, primary, busy), EngineConcurrency, operationClose, codeBusy); got.ReopenRequired || errors.Unwrap(got) != primary || got.Error() != "close: Concurrency: code -30778: busy: primary" || busy.Cause != nil {
		t.Fatalf("reopen-false retained result=%v original=%+v", got, busy)
	}
	forgedBusy := &EngineError{Class: EngineConcurrency, Operation: "close", Code: codeBusy, Diagnostic: "busy", ReopenRequired: true}
	requireFallback(t, operationClose, orderResultCausesPrimary, primary, forgedBusy, "native result is not an EngineError", "primary\n"+forgedBusy.Error(), primary, forgedBusy)
	forgedBusyClass := &EngineError{Class: EngineIO, Operation: "close", Code: codeBusy, Diagnostic: "forged"}
	requireFallback(t, operationClose, orderResultCausesPrimary, primary, forgedBusyClass, "native result is not an EngineError", "primary\n"+forgedBusyClass.Error(), primary, forgedBusyClass)
	forgedSuccess := &EngineError{Class: EngineIO, Operation: "close", Code: codeSuccess, Diagnostic: "forged"}
	requireFallback(t, operationClose, orderResultCausesPrimary, primary, forgedSuccess, "native result is not an EngineError", "primary\n"+forgedSuccess.Error(), primary, forgedSuccess)
	prior := errors.New("prior")
	caused := adapterError(operationAbort, EngineLocalInvariant, codeThreadMismatch, "result", prior)
	if got := requireEngineError(t, orderedErrors(operationAbort, orderResultCausesPrimary, primary, caused), EngineLocalInvariant, operationAbort, codeThreadMismatch); got.Cause.Error() != "primary\nprior" || !errors.Is(got, primary) || !errors.Is(got, prior) || caused.Cause != prior || got.Error() != "abort: LocalInvariant: code -30416: result: primary\nprior" {
		t.Fatalf("prior-cause retention=%v original=%+v", got, caused)
	}
	wrapped := fmt.Errorf("wrapped result: %w", resultEngine)
	wrappedNil := fmt.Errorf("wrapped nil: %w", typedNil)
	requireFallback(t, operationAbort, orderResult, nil, result, "native result is not an EngineError", "result", result)
	requireFallback(t, operationAbort, orderResult, nil, nil, "native errors do not match ordering", "")
	if got := requireEngineError(t, orderedErrors(operationAbort, orderResult, nil, typedNil), EngineLocalInvariant, operationAbort, codeProblem); got.Cause != typedNil || errors.Unwrap(got) != typedNil || got.Error() != "abort: LocalInvariant: code -30779: native result is not an EngineError: <nil>" {
		t.Fatalf("typed-nil result identity=%+v", got)
	}
	requireFallback(t, operationAbort, orderPrimaryResult, primary, result, "native result is not an EngineError", "primary\nresult", primary, result)
	requireFallback(t, operationAbort, orderPrimaryResult, primary, nil, "native errors do not match ordering", "primary", primary)
	requireFallback(t, operationAbort, orderPrimaryResult, primary, typedNil, "native result is not an EngineError", "primary\n<nil>", primary, typedNil)
	requireFallback(t, operationAbort, orderResultCausesPrimary, primary, result, "native result is not an EngineError", "primary\nresult", primary, result)
	requireFallback(t, operationAbort, orderResultCausesPrimary, primary, wrapped, "native result is not an EngineError", "primary\n"+wrapped.Error(), primary, wrapped, resultEngine)
	requireFallback(t, operationClose, orderResultCausesPrimary, primary, nil, "native errors do not match ordering", "primary", primary)
	requireFallback(t, operationAbort, orderResultCausesPrimary, primary, typedNil, "native result is not an EngineError", "primary\n<nil>", primary, typedNil)
	requireFallback(t, operationClose, orderResultCausesPrimary, primary, wrappedNil, "native result is not an EngineError", "primary\n"+wrappedNil.Error(), primary, wrappedNil, typedNil)
	requireFallback(t, operationClose, orderResultCausesPrimary, primary, resultEngine, "native result is not an EngineError", "primary\n"+resultEngine.Error(), primary, resultEngine)
	forgedClass := &EngineError{Class: EngineStateMismatch, Operation: "abort", Code: codeInvalid, Diagnostic: "forged", ReopenRequired: true}
	requireFallback(t, operationAbort, orderResultCausesPrimary, primary, forgedClass, "native result is not an EngineError", "primary\n"+forgedClass.Error(), primary, forgedClass)
	forgedReopen := &EngineError{Class: EngineLocalInvariant, Operation: "abort", Code: codeThreadMismatch, Diagnostic: "forged"}
	requireFallback(t, operationAbort, orderResultCausesPrimary, primary, forgedReopen, "native result is not an EngineError", "primary\n"+forgedReopen.Error(), primary, forgedReopen)
	requireFallback(t, operationAbort, errorOrder(255), primary, result, "invalid native result ordering", "primary\nresult", primary, result)
	requireFallback(t, operationClose, errorOrder(255), primary, result, "invalid native result ordering", "primary\nresult", primary, result)
}

func environmentConfig() ConfigV1 {
	return ConfigV1{Lower: 1 << 20, Now: 2 << 20, Upper: 256 << 20, Growth: 1 << 20, Shrink: 2 << 20, PageSize: 4096, MaxReaders: 492}
}

func createAndClose(path string, cfg ConfigV1) error {
	store, err := Create(path, cfg)
	if err != nil {
		return err
	}
	return store.Close()
}

func requireEnvironmentError(t *testing.T, err error, class EngineClass, operation engineOperation, code int, diagnostic string) *EngineError {
	engine := requireEngineError(t, err, class, operation, code)
	if engine.Diagnostic != diagnostic {
		t.Fatalf("diagnostic=%q, want %q", engine.Diagnostic, diagnostic)
	}
	return engine
}

func requireNoStore(t *testing.T, store *Store, err error, class EngineClass, operation engineOperation, code int, diagnostic string) *EngineError {
	if store != nil {
		t.Fatal("rejected environment operation returned Store")
	}
	return requireEnvironmentError(t, err, class, operation, code, diagnostic)
}

func mustEnvironment(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func closedEnvironment(t *testing.T) string {
	path := filepath.Join(t.TempDir(), "db")
	mustEnvironment(t, createAndClose(path, environmentConfig()))
	return path
}

func requireEnvironmentStore(t *testing.T, store *Store, cfg ConfigV1) {
	if store == nil || store.self != store || store.state != storeOPEN || store.env == nil || store.writer == nil || store.txn != nil || store.terminal != nil || store.config != cfg || !validRetainedDBIs(store.dbis) {
		t.Fatalf("Store is not one exact OPEN owner: %+v", store)
	}
}

func requireShapeRejection(t *testing.T, store *Store, mutate, restore func()) {
	t.Helper()
	mutate()
	self, env, writer, txn, cfg, dbis, state, terminal := store.self, store.env, store.writer, store.txn, store.config, store.dbis, store.state, store.terminal
	requireEnvironmentError(t, store.Close(), EngineLocalInvariant, operationClose, -30779, "invalid Store resource shape")
	if store.self != self || store.env != env || store.writer != writer || store.txn != txn || store.config != cfg || store.dbis != dbis || store.state != state || !sameError(store.terminal, terminal) {
		t.Fatal("shape rejection mutated Store")
	}
	restore()
}

func TestEnvironmentPrevalidationAndNormalization(t *testing.T) {
	if os.Getenv("RUBIN_MDBX_DEBUG_CHILD") == "1" {
		base, cfg := os.Getenv("RUBIN_MDBX_DEBUG_PATH"), environmentConfig()
		type created struct {
			store *Store
			err   error
		}
		start, release := make(chan struct{}), make(chan struct{})
		ready, results := make(chan created, 4), make(chan error, 4)
		for i := 0; i < 4; i++ {
			go func(path string) {
				<-start
				store, err := Create(path, cfg)
				ready <- created{store, err}
				<-release
				if err == nil {
					err = store.Close()
				}
				results <- err
			}(fmt.Sprintf("%s-%d", base, i))
		}
		close(start)
		for i := 0; i < 4; i++ {
			result := <-ready
			mustEnvironment(t, result.err)
			requireEnvironmentStore(t, result.store, cfg)
		}
		close(release)
		for i := 0; i < 4; i++ {
			mustEnvironment(t, <-results)
		}
		mustEnvironment(t, createAndClose(base+"-repeat", cfg))
		store, err := Open(base+"-0", cfg)
		mustEnvironment(t, err)
		mustEnvironment(t, store.Close())
		return
	}
	parent := t.TempDir()
	for _, path := range []string{"", "relative", parent + string(os.PathSeparator) + "x" + string(os.PathSeparator) + "..", filepath.Join(parent, "nul") + "\x00"} {
		created, createErr := Create(path, ConfigV1{})
		opened, openErr := Open(path, ConfigV1{})
		if created != nil || opened != nil {
			t.Fatal("invalid path returned Store")
		}
		requireEnvironmentError(t, createErr, EngineInvalidInput, operationCreate, int(syscall.EINVAL), "path must be nonempty, NUL-free, absolute and clean")
		requireEnvironmentError(t, openErr, EngineInvalidInput, operationOpen, int(syscall.EINVAL), "path must be nonempty, NUL-free, absolute and clean")
	}
	existing := filepath.Join(parent, "existing")
	mustEnvironment(t, os.Mkdir(existing, 0o700))
	store, err := Create(existing, ConfigV1{})
	requireNoStore(t, store, err, EngineInvalidInput, operationCreate, int(syscall.EEXIST), "Create path already exists")
	absent := filepath.Join(parent, "absent")
	store, err = Open(absent, ConfigV1{})
	requireNoStore(t, store, err, EngineInvalidInput, operationOpen, int(syscall.ENOENT), "Open path is absent")
	invalidOpen := closedEnvironment(t)
	store, err = Open(invalidOpen, ConfigV1{})
	if invalid := requireNoStore(t, store, err, EngineInvalidInput, operationOpen, int(syscall.EINVAL), "invalid ConfigV1"); !sameError(invalid.Cause, errSchema) {
		t.Fatalf("invalid Open ConfigV1 cause=%v", invalid.Cause)
	}
	supplied := environmentConfig()
	supplied.MaxReaders++
	store, err = Open(invalidOpen, supplied)
	if mismatch := requireNoStore(t, store, err, EngineIntegrity, operationOpen, codeInvalid, "effective environment mismatch"); mismatch.Cause == nil || mismatch.Cause.Error() != "MaxReaders: got 492, want 493" {
		t.Fatalf("stored/caller mismatch Cause=%v", mismatch.Cause)
	}
	invalidTarget := filepath.Join(parent, "invalid-config")
	store, err = Create(invalidTarget, ConfigV1{})
	if invalid := requireNoStore(t, store, err, EngineInvalidInput, operationCreate, int(syscall.EINVAL), "invalid ConfigV1"); !sameError(invalid.Cause, errSchema) {
		t.Fatalf("invalid ConfigV1 cause=%v", invalid.Cause)
	}
	if _, statErr := os.Lstat(invalidTarget); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("invalid ConfigV1 mutated filesystem: %v", statErr)
	}
	limitTarget, oversized := filepath.Join(parent, "native-limit"), environmentConfig()
	oversized.Upper = 0x7fff_ffff_ffff_f000
	store, err = Create(limitTarget, oversized)
	limit := requireNoStore(t, store, err, EngineInvalidInput, operationCreate, codeTooLarge, "ConfigV1 exceeds pinned native limits")
	if limit.Cause == nil || limit.Cause.Error() != "geometry [1048576,2097152,9223372036854771712] outside [12288,8796093022208]" {
		t.Fatalf("pinned-limit Cause=%q", limit.Cause)
	}
	if _, statErr := os.Lstat(limitTarget); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("pinned-limit Create mutated filesystem: %v", statErr)
	}
	store, err = Open(invalidOpen, oversized)
	openLimit := requireNoStore(t, store, err, EngineInvalidInput, operationOpen, codeTooLarge, "ConfigV1 exceeds pinned native limits")
	if openLimit.Cause == nil || openLimit.Cause.Error() != limit.Cause.Error() {
		t.Fatalf("Open pinned-limit Cause=%v", openLimit.Cause)
	}
	missingParent := filepath.Join(parent, "missing", "db")
	store, err = Create(missingParent, environmentConfig())
	requireNoStore(t, store, err, EngineIO, operationCreate, int(syscall.ENOENT), "create environment directory")
	if _, statErr := os.Lstat(filepath.Dir(missingParent)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Create made parent hierarchy: %v", statErr)
	}

	debugVars := []string{"MDBX_DBG_ASSERT", "MDBX_DBG_AUDIT", "MDBX_DBG_JITTER", "MDBX_DBG_DUMP", "MDBX_DBG_LEGACY_MULTIOPEN", "MDBX_DBG_LEGACY_OVERLAP", "MDBX_DBG_DONT_UPGRADE"}
	debugSet := make(map[string]bool, len(debugVars))
	rows := make([][]string, 0, 15)
	for _, name := range debugVars {
		debugSet[name] = true
		rows = append(rows, []string{name + "="}, []string{name + "=1"})
	}
	all := make([]string, len(debugVars))
	for i, name := range debugVars {
		all[i] = name + "=1"
	}
	rows = append(rows, all)
	for i, row := range rows {
		t.Run(fmt.Sprintf("fresh-process-%02d", i), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "db")
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestEnvironmentPrevalidationAndNormalization$", "-test.count=1")
			for _, entry := range os.Environ() {
				key := strings.SplitN(entry, "=", 2)[0]
				if key != "RUBIN_MDBX_DEBUG_CHILD" && key != "RUBIN_MDBX_DEBUG_PATH" && !debugSet[key] {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "RUBIN_MDBX_DEBUG_CHILD=1", "RUBIN_MDBX_DEBUG_PATH="+path)
			cmd.Env = append(cmd.Env, row...)
			if output, runErr := cmd.CombinedOutput(); runErr != nil {
				t.Fatalf("child failed: %v\n%s", runErr, output)
			}
		})
	}
}

func TestEnvironmentCreateOpenCloseAndShapes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	cfg := environmentConfig()
	store, err := func() (*Store, error) {
		oldMask := syscall.Umask(0o100)
		defer syscall.Umask(oldMask)
		return Create(path, cfg)
	}()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	requireEnvironmentStore(t, store, cfg)
	requireArtifact(t, path, 0o700, false)
	for _, name := range []string{"rubin-writer.lock", "mdbx.dat", "mdbx.lck"} {
		requireArtifact(t, filepath.Join(path, name), 0o600, name == "rubin-writer.lock")
	}
	mustEnvironment(t, createAndClose(filepath.Join(t.TempDir(), "db"), cfg))
	second, secondErr := Open(path, cfg)
	requireNoStore(t, second, secondErr, EngineConcurrency, operationOpen, -30778, "Rubin writer lock is already held")
	env, writer, dbis := store.env, store.writer, store.dbis
	forged := &Store{self: store, env: env, writer: writer, config: cfg, dbis: dbis, state: storeOPEN}
	requireEnvironmentError(t, forged.Close(), EngineLocalInvariant, operationClose, -30779, "invalid Store resource shape")
	if store.self != store || store.env != env || store.writer != writer || store.state != storeOPEN {
		t.Fatal("forged value copy changed original owner")
	}
	busyTerminal := nativeError(operationClose, codeBusy)
	published := &Store{env: env, writer: writer, config: cfg, dbis: dbis, state: storeCLOSEBLOCKED, terminal: busyTerminal}
	published.self = published
	construction := &Store{env: env, writer: writer, state: storeCLOSEBLOCKED, terminal: orderedErrors(operationClose, orderResultCausesPrimary, errors.New("construction"), busyTerminal)}
	construction.self = construction
	unknown := &Store{state: "UNKNOWN"}
	unknown.self = unknown
	if !validStoreShape(published) || !validStoreShape(construction) || validStoreShape(unknown) {
		t.Fatal("published, construction or unknown Store shape changed")
	}
	store.operations.RLock()
	busy := store.Close()
	store.operations.RUnlock()
	requireEnvironmentError(t, busy, EngineConcurrency, operationClose, -30778, "store operation in progress")
	if store.env != env || store.writer != writer || store.dbis != dbis || store.state != storeOPEN || store.terminal != nil {
		t.Fatal("adapter contention mutated Store")
	}
	zeroDBI, duplicateDBI := dbis, dbis
	zeroDBI[0], duplicateDBI[1] = 0, duplicateDBI[0]
	if validRetainedDBIs(zeroDBI) || validRetainedDBIs(duplicateDBI) {
		t.Fatal("zero or duplicate retained DBI accepted")
	}
	for _, state := range []storeState{"", "UNKNOWN"} {
		store.state = state
		requireEnvironmentError(t, store.Close(), EngineLocalInvariant, operationClose, -30779, "invalid Store state")
	}
	store.state = storeOPEN
	for _, shape := range []struct{ mutate, restore func() }{
		{func() { store.env = nil }, func() { store.env = env }},
		{func() { store.writer = nil }, func() { store.writer = writer }},
		{func() { store.config = ConfigV1{} }, func() { store.config = cfg }},
		{func() { store.dbis = zeroDBI }, func() { store.dbis = dbis }},
		{func() { store.terminal = errors.New("forged") }, func() { store.terminal = nil }},
		{func() { store.self = nil }, func() { store.self = store }},
	} {
		requireShapeRejection(t, store, shape.mutate, shape.restore)
	}
	encoded, encodeErr := cfg.Encode()
	mustEnvironment(t, encodeErr)
	duplicate := runLocked(func() transactionOutcome { return store.initializeLocked(cfg, encoded) })
	requireEnvironmentError(t, duplicate.err, EngineIntegrity, operationInit, codeKeyExist, expectedNativeDiagnostic(codeKeyExist))
	if duplicate.poisoned {
		t.Fatal("duplicate initialization poisoned owner thread")
	}
	mustEnvironment(t, os.Remove(filepath.Join(path, "rubin-writer.lock")))
	second, secondErr = Open(path, cfg)
	requireNoStore(t, second, secondErr, EngineInvalidInput, operationOpen, int(syscall.ENOENT), "rubin-writer.lock is absent")
	requireEnvironmentStore(t, store, cfg)
	if _, statErr := os.Lstat(filepath.Join(path, "rubin-writer.lock")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("missing sidecar Open created a replacement: %v", statErr)
	}
	mustEnvironment(t, store.Close())
	if store.self != store || store.state != storeCLOSED || store.env != nil || store.writer != nil || store.txn != nil || store.config != (ConfigV1{}) || store.terminal != nil {
		t.Fatalf("Close did not clear ownership: %+v", store)
	}
	for _, dbi := range store.dbis {
		if dbi != 0 {
			t.Fatal("Close retained a DBI")
		}
	}
	closeNative := nativeError(operationClose, codeEIO)
	closeRelease := releaseResult(errors.New("release"))
	for _, terminal := range []error{nil, closeNative, closeRelease, joinErrors(closeNative, closeRelease)} {
		store.terminal = terminal
		if !sameError(store.Close(), terminal) {
			t.Fatal("CLOSED terminal identity changed")
		}
	}
	store.terminal = nil
	closedDBIs := store.dbis
	for _, shape := range []struct{ mutate, restore func() }{
		{func() { store.env = env }, func() { store.env = nil }},
		{func() { store.writer = writer }, func() { store.writer = nil }},
		{func() { store.config = cfg }, func() { store.config = ConfigV1{} }},
		{func() { store.dbis = dbis }, func() { store.dbis = closedDBIs }},
		{func() { store.terminal = errors.New("forged") }, func() { store.terminal = nil }},
		{func() { store.self = nil }, func() { store.self = store }},
	} {
		requireShapeRejection(t, store, shape.mutate, shape.restore)
	}
	var nilStore *Store
	requireEnvironmentError(t, nilStore.Close(), EngineInvalidInput, operationClose, int(syscall.EINVAL), "nil Store")
	handle, result, lockErr := filelock.Acquire(filepath.Join(path, "rubin-writer.lock"))
	if lockErr != nil || result != "" || handle == nil {
		t.Fatalf("writer lock not released: %q %v", result, lockErr)
	}
	mustEnvironment(t, handle.Release())
	mustEnvironment(t, os.Remove(filepath.Join(path, "rubin-writer.lock")))
	mustEnvironment(t, os.WriteFile(filepath.Join(path, "ignored.extra"), []byte{1}, 0o600))
	reopened, err := Open(path, cfg)
	requireNoStore(t, reopened, err, EngineInvalidInput, operationOpen, int(syscall.ENOENT), "rubin-writer.lock is absent")
	if _, statErr := os.Lstat(filepath.Join(path, "rubin-writer.lock")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("missing sidecar Open created a replacement: %v", statErr)
	}
	mustEnvironment(t, os.WriteFile(filepath.Join(path, "rubin-writer.lock"), nil, 0o600))
	reopened, err = Open(path, cfg)
	if err != nil {
		t.Fatalf("Open with recreated sidecar and extra entry: %v", err)
	}
	requireEnvironmentStore(t, reopened, cfg)
	mustEnvironment(t, reopened.Close())
	if extra, readErr := os.ReadFile(filepath.Join(path, "ignored.extra")); readErr != nil || string(extra) != "\x01" {
		t.Fatalf("Open/Close changed ignored sibling: %x/%v", extra, readErr)
	}
	fixedCfg, fixedPath := cfg, filepath.Join(t.TempDir(), "db")
	fixedCfg.MaxReaders = 1004
	mustEnvironment(t, createAndClose(fixedPath, fixedCfg))
	mustEnvironment(t, os.Truncate(filepath.Join(fixedPath, "mdbx.lck"), 0))
	fixed, err := Open(fixedPath, fixedCfg)
	mustEnvironment(t, err)
	requireEnvironmentStore(t, fixed, fixedCfg)
	mustEnvironment(t, fixed.Close())
	smallPageCfg, smallPagePath := cfg, filepath.Join(t.TempDir(), "db")
	smallPageCfg.PageSize = 256
	mustEnvironment(t, createAndClose(smallPagePath, smallPageCfg))
	smallPage, err := Open(smallPagePath, smallPageCfg)
	mustEnvironment(t, err)
	requireEnvironmentStore(t, smallPage, smallPageCfg)
	mustEnvironment(t, smallPage.Close())
}

func requireArtifact(t *testing.T, path string, mode os.FileMode, empty bool) {
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		if exactPermissionBits(info.Mode()) != mode {
			t.Fatalf("%s mode=%v", path, info.Mode())
		}
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || exactPermissionBits(info.Mode()) != mode || uint64(stat.Nlink) != 1 || empty && info.Size() != 0 {
		t.Fatalf("%s mode=%v links=%v size=%d", path, info.Mode(), ok && uint64(stat.Nlink) == 1, info.Size())
	}
}

func TestEnvironmentRejectsArtifactDrift(t *testing.T) {
	mutations := []struct {
		name string
		run  func(string) error
	}{
		{"mode", func(path string) error { return os.Chmod(path, 0o644) }},
		{"hardlink", func(path string) error { return os.Link(path, path+".alias") }},
		{"fifo", func(path string) error { return errors.Join(os.Remove(path), syscall.Mkfifo(path, 0o600)) }},
		{"symlink", func(path string) error {
			return errors.Join(os.Rename(path, path+".target"), os.Symlink(path+".target", path))
		}},
	}
	for _, artifact := range []string{"mdbx.dat", "mdbx.lck", "rubin-writer.lock"} {
		for _, mutation := range mutations {
			t.Run(artifact+"/"+mutation.name, func(t *testing.T) {
				path := closedEnvironment(t)
				mustEnvironment(t, mutation.run(filepath.Join(path, artifact)))
				requireOpenEnvironmentError(t, path, EngineIntegrity, -30793, artifact+" is unsafe")
			})
		}
	}
	for _, tc := range []struct {
		name, diagnostic string
		class            EngineClass
		code             int
		prepare          func(*testing.T) string
	}{
		{"writer-nonempty", "rubin-writer.lock is unsafe", EngineIntegrity, -30793, func(t *testing.T) string {
			path := closedEnvironment(t)
			mustEnvironment(t, os.WriteFile(filepath.Join(path, "rubin-writer.lock"), []byte{1}, 0o600))
			return path
		}},
		{"missing-mdbx.dat", "mdbx.dat is absent", EngineInvalidInput, int(syscall.ENOENT), func(t *testing.T) string {
			path := closedEnvironment(t)
			mustEnvironment(t, os.Remove(filepath.Join(path, "mdbx.dat")))
			return path
		}},
		{"missing-mdbx.lck", "mdbx.lck is absent", EngineInvalidInput, int(syscall.ENOENT), func(t *testing.T) string {
			path := closedEnvironment(t)
			mustEnvironment(t, os.Remove(filepath.Join(path, "mdbx.lck")))
			return path
		}},
		{"directory-mode", "environment directory is unsafe", EngineIntegrity, -30793, func(t *testing.T) string {
			path := closedEnvironment(t)
			mustEnvironment(t, os.Chmod(path, 0o755))
			return path
		}},
		{"directory-symlink", "environment directory is unsafe", EngineIntegrity, -30793, func(t *testing.T) string {
			real := closedEnvironment(t)
			path := filepath.Join(filepath.Dir(real), "linked")
			mustEnvironment(t, os.Symlink(real, path))
			return path
		}},
		{"directory-nondirectory", "environment directory is unsafe", EngineIntegrity, -30793, func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "db")
			mustEnvironment(t, os.WriteFile(path, nil, 0o700))
			return path
		}},
	} {
		t.Run(tc.name, func(t *testing.T) { requireOpenEnvironmentError(t, tc.prepare(t), tc.class, tc.code, tc.diagnostic) })
	}
	undersizedCfg, undersized := environmentConfig(), closedEnvironment(t)
	undersizedCfg.PageSize = 256
	dataPath := filepath.Join(undersized, "mdbx.dat")
	lockPath := filepath.Join(undersized, "rubin-writer.lock")
	lockBefore, statErr := os.Lstat(lockPath)
	mustEnvironment(t, statErr)
	mustEnvironment(t, os.Truncate(dataPath, 1000))
	before, readErr := os.ReadFile(dataPath)
	mustEnvironment(t, readErr)
	store, openErr := Open(undersized, undersizedCfg)
	requireNoStore(t, store, openErr, EngineIntegrity, operationOpen, codeInvalid, "mdbx.dat is undersized")
	after, readErr := os.ReadFile(dataPath)
	mustEnvironment(t, readErr)
	lockAfter, statErr := os.Lstat(lockPath)
	mustEnvironment(t, statErr)
	if len(after) != 1000 || string(after) != string(before) {
		t.Fatal("undersized Open changed mdbx.dat")
	}
	if !os.SameFile(lockBefore, lockAfter) {
		t.Fatal("undersized Open replaced writer lock")
	}
	handle, result, lockErr := filelock.AcquireExisting(lockPath)
	if handle == nil || result != "" || lockErr != nil {
		t.Fatalf("undersized Open retained writer lock: %v/%q/%v", handle, result, lockErr)
	}
	mustEnvironment(t, handle.Release())
}

func requireOpenEnvironmentError(t *testing.T, path string, class EngineClass, code int, diagnostic string) *EngineError {
	store, err := Open(path, environmentConfig())
	return requireNoStore(t, store, err, class, operationOpen, code, diagnostic)
}

func consumeNativeTestStore(t *testing.T, store *Store) {
	t.Helper()
	if retained, err := store.consume(nil); retained || err != nil {
		t.Fatalf("direct native cleanup retained=%v err=%v", retained, err)
	}
}

func TestEnvironmentNativeNegativePaths(t *testing.T) {
	primary := nativeError(operationOpen, codeCorrupted)
	failed := &Store{}
	if store, err := finishConstruction(failed, transactionOutcome{err: primary}); store != nil || !sameError(err, primary) || failed.state != storeCLOSED {
		t.Fatalf("failed construction=%v/%v/%s", store, err, failed.state)
	}
	poisoned, poisonErr := &Store{}, nativeError(operationInit, codeThreadMismatch)
	if store, err := finishConstruction(poisoned, transactionOutcome{err: poisonErr, poisoned: true}); store != poisoned || !sameError(err, poisonErr) {
		t.Fatalf("poisoned construction identity=%v/%v", store, err)
	}
	_, artifactErr := validateOpenArtifacts("\x00")
	artifact := requireEnvironmentError(t, artifactErr, EngineInvalidInput, operationOpen, int(syscall.EINVAL), "inspect environment directory")
	_, fileErr := inspectOpenFile("\x00", "mdbx.dat", false, false)
	file := requireEnvironmentError(t, fileErr, EngineInvalidInput, operationOpen, int(syscall.EINVAL), "inspect mdbx.dat")
	if !errors.Is(artifact, syscall.EINVAL) || !errors.Is(file, syscall.EINVAL) {
		t.Fatal("filesystem diagnostic lost immediate errno Cause")
	}
	unsafe := t.TempDir()
	requireEnvironmentError(t, normalizeOwnedFile(unsafe, "mdbx.dat", false, operationCreate, "normalize", "read"), EngineIntegrity, operationCreate, codeInvalid, "mdbx.dat is unsafe")
	requireEnvironmentError(t, readOwnedFile(unsafe, "mdbx.dat", false, operationOpen, "read"), EngineIntegrity, operationOpen, codeInvalid, "mdbx.dat is unsafe")
	absentLockDir := t.TempDir()
	absentHandle, absentLockErr := acquireWriter(absentLockDir, operationOpen, false)
	if absentHandle != nil {
		t.Fatal("absent writer returned Handle")
	}
	requireEnvironmentError(t, absentLockErr, EngineIO, operationOpen, int(syscall.ENOENT), "acquire Rubin writer lock")
	if !errors.Is(absentLockErr, syscall.ENOENT) {
		t.Fatalf("absent writer lost ENOENT: %v", absentLockErr)
	}
	if _, statErr := os.Lstat(filepath.Join(absentLockDir, "rubin-writer.lock")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("absent writer created sidecar: %v", statErr)
	}
	lockDir := t.TempDir()
	mustEnvironment(t, os.WriteFile(filepath.Join(lockDir, "rubin-writer.lock"), nil, 0o644))
	mustEnvironment(t, os.Chmod(filepath.Join(lockDir, "rubin-writer.lock"), 0o644))
	handle, lockErr := acquireWriter(lockDir, operationOpen, false)
	if handle != nil {
		t.Fatal("unsafe writer mode returned Handle")
	}
	requireEnvironmentError(t, lockErr, EngineIntegrity, operationOpen, codeInvalid, "rubin-writer.lock is unsafe")
	mustEnvironment(t, os.Chmod(filepath.Join(lockDir, "rubin-writer.lock"), 0o600))
	handle, _, lockErr = filelock.Acquire(filepath.Join(lockDir, "rubin-writer.lock"))
	if handle == nil || lockErr != nil {
		t.Fatalf("unsafe writer cleanup retained lock: %v/%v", handle, lockErr)
	}
	mustEnvironment(t, handle.Release())
	empty := &Store{}
	_, effectiveErr := readEffective(empty.env, nil, operationOpen)
	if effectiveErr == nil {
		t.Fatal("nil environment accepted by readEffective")
	}
	requireEnvironmentError(t, effectiveErr, EngineInvalidInput, operationOpen, int(syscall.EINVAL), expectedNativeDiagnostic(int(syscall.EINVAL)))
	encoded, encodeErr := environmentConfig().Encode()
	mustEnvironment(t, encodeErr)
	initOutcome := empty.initializeLocked(environmentConfig(), encoded)
	requireEnvironmentError(t, initOutcome.err, EngineInvalidInput, operationInit, int(syscall.EINVAL), expectedNativeDiagnostic(int(syscall.EINVAL)))
	openOutcome := empty.inspectOpenLocked(environmentConfig())
	requireEnvironmentError(t, openOutcome.err, EngineInvalidInput, operationOpen, int(syscall.EINVAL), expectedNativeDiagnostic(int(syscall.EINVAL)))
	if initOutcome.poisoned || openOutcome.poisoned {
		t.Fatal("nil environment produced a poison owner")
	}
	_, initSchemaErr := initializeSchema(empty.txn, encoded)
	requireEnvironmentError(t, initSchemaErr, EngineInvalidInput, operationInit, int(syscall.EINVAL), expectedNativeDiagnostic(int(syscall.EINVAL)))
	for _, create := range []bool{false, true} {
		_, schemaErr := openSchemaDBIs(empty.txn, create, map[bool]engineOperation{false: operationOpen, true: operationInit}[create])
		requireEnvironmentError(t, schemaErr, EngineInvalidInput, map[bool]engineOperation{false: operationOpen, true: operationInit}[create], int(syscall.EINVAL), expectedNativeDiagnostic(int(syscall.EINVAL)))
	}
	requireEnvironmentError(t, putRequiredMeta(empty.txn, empty.dbis[0], encoded), EngineLocalInvariant, operationInit, codeBadDBI, expectedNativeDiagnostic(codeBadDBI))
	requireEnvironmentError(t, verifyMainCardinality(empty.txn, operationOpen), EngineInvalidInput, operationOpen, int(syscall.EINVAL), expectedNativeDiagnostic(int(syscall.EINVAL)))
	requireEnvironmentError(t, verifyCreatedMeta(empty.txn, empty.dbis[0], encoded), EngineInvalidInput, operationInit, int(syscall.EINVAL), expectedNativeDiagnostic(int(syscall.EINVAL)))
	_, metaErr := readRequiredMeta(empty.txn, empty.dbis[0])
	requireEnvironmentError(t, metaErr, EngineInvalidInput, operationOpen, int(syscall.EINVAL), expectedNativeDiagnostic(int(syscall.EINVAL)))
	requireEnvironmentError(t, verifyExactValue(empty.txn, empty.dbis[0], []byte{1}, encoded, operationOpen), EngineInvalidInput, operationOpen, int(syscall.EINVAL), expectedNativeDiagnostic(int(syscall.EINVAL)))
	_, valueErr := getSizedValue(empty.txn, empty.dbis[0], []byte{1}, len(encoded), operationOpen)
	requireEnvironmentError(t, valueErr, EngineInvalidInput, operationOpen, int(syscall.EINVAL), expectedNativeDiagnostic(int(syscall.EINVAL)))
	abortOutcome := empty.abortLocked(empty.txn, nil)
	requireEnvironmentError(t, abortOutcome.err, EngineInvalidInput, operationAbort, int(syscall.EINVAL), expectedNativeDiagnostic(int(syscall.EINVAL)))
	if abortOutcome.poisoned {
		t.Fatal("nil transaction abort produced a poison owner")
	}
	native := &Store{}
	mustEnvironment(t, native.allocateEnvironment(operationOpen))
	requireEnvironmentError(t, openNativeEnvironment(native.env, filepath.Join(t.TempDir(), "missing", "db"), 0, 0, operationOpen), EngineIO, operationOpen, int(syscall.ENOENT), expectedNativeDiagnostic(int(syscall.ENOENT)))
	consumeNativeTestStore(t, native)
	invalidReaders, cfg := &Store{}, environmentConfig()
	cfg.MaxReaders = 0
	requireEnvironmentError(t, invalidReaders.createEnvironment(t.TempDir(), cfg), EngineInvalidInput, operationCreate, int(syscall.EINVAL), expectedNativeDiagnostic(int(syscall.EINVAL)))
	consumeNativeTestStore(t, invalidReaders)
	invalidGeometry := &Store{}
	cfg = environmentConfig()
	cfg.PageSize = 3
	requireEnvironmentError(t, invalidGeometry.configureCreateEnvironment(t.TempDir(), cfg), EngineInvalidInput, operationCreate, int(syscall.EINVAL), expectedNativeDiagnostic(int(syscall.EINVAL)))
	consumeNativeTestStore(t, invalidGeometry)
	invalidOpenReaders := &Store{}
	cfg, cfg.MaxReaders = environmentConfig(), 0
	requireEnvironmentError(t, invalidOpenReaders.openEnvironment(t.TempDir(), cfg), EngineInvalidInput, operationOpen, int(syscall.EINVAL), expectedNativeDiagnostic(int(syscall.EINVAL)))
	consumeNativeTestStore(t, invalidOpenReaders)
	normalizedCfg, normalizedPath := environmentConfig(), filepath.Join(t.TempDir(), "normalized")
	normalizedCfg.Growth, normalizedCfg.Shrink = 4096, 8192
	normalized, normalizedErr := Create(normalizedPath, normalizedCfg)
	normalization := requireNoStore(t, normalized, normalizedErr, EngineIntegrity, operationCreate, codeInvalid, "effective environment mismatch")
	if normalization.Cause == nil || normalization.Cause.Error() != "Growth: got 16384, want 4096" {
		t.Fatalf("native normalization Cause=%v", normalization.Cause)
	}
	original, geometryPath := environmentConfig(), closedEnvironment(t)
	geometryWriter, geometryErr := acquireWriter(geometryPath, operationOpen, false)
	mustEnvironment(t, geometryErr)
	changed := original
	changed.Upper *= 2
	geometry := &Store{writer: geometryWriter}
	geometry.self = geometry
	mustEnvironment(t, geometry.configureCreateEnvironment(geometryPath, changed))
	geometryOutcome := runLocked(func() transactionOutcome { return geometry.inspectOpenLocked(original) })
	geometryMismatch := requireEnvironmentError(t, geometryOutcome.err, EngineIntegrity, operationOpen, codeInvalid, "effective environment mismatch")
	if geometryMismatch.Cause == nil || geometryMismatch.Cause.Error() != "Upper: got 536870912, want 268435456" {
		t.Fatalf("effective geometry Cause=%v", geometryMismatch.Cause)
	}
	consumeNativeTestStore(t, geometry)
	for _, tc := range []struct {
		encoded    []byte
		diagnostic string
		cause      error
	}{{[]byte{1}, "required metadata width mismatch", nil}, {make([]byte, 48), "invalid ConfigV1 row", errSchema}} {
		path := filepath.Join(t.TempDir(), "malformed")
		mustEnvironment(t, createDirectory(path))
		writer, err := acquireWriter(path, operationCreate, true)
		mustEnvironment(t, err)
		malformed := &Store{writer: writer}
		malformed.self = malformed
		mustEnvironment(t, malformed.createEnvironment(path, original))
		outcome := runLocked(func() transactionOutcome { return malformed.initializeLocked(original, tc.encoded) })
		if outcome.err != nil || outcome.poisoned || malformed.state != storeOPEN {
			t.Fatalf("malformed preparation=%v/%v/%s", outcome.err, outcome.poisoned, malformed.state)
		}
		mustEnvironment(t, malformed.Close())
		opened := requireOpenEnvironmentError(t, path, EngineIntegrity, codeInvalid, tc.diagnostic)
		if !sameError(opened.Cause, tc.cause) {
			t.Fatalf("malformed %s Cause=%v", tc.diagnostic, opened.Cause)
		}
	}
	nativeLink := closedEnvironment(t)
	mustEnvironment(t, os.Link(filepath.Join(nativeLink, "mdbx.dat"), filepath.Join(nativeLink, "mdbx.dat.alias")))
	linked := &Store{}
	requireEnvironmentError(t, linked.createEnvironment(nativeLink, environmentConfig()), EngineIntegrity, operationCreate, codeInvalid, "mdbx.dat is unsafe")
	consumeNativeTestStore(t, linked)
	maskedTarget := filepath.Join(t.TempDir(), "owner-rwx-masked")
	masked, maskedErr := func() (*Store, error) {
		old := syscall.Umask(0o777)
		defer syscall.Umask(old)
		return Create(maskedTarget, environmentConfig())
	}()
	if maskedErr != nil {
		requireNoStore(t, masked, maskedErr, EngineIO, operationCreate, int(syscall.EACCES), expectedNativeDiagnostic(int(syscall.EACCES)))
		if _, statErr := os.Lstat(filepath.Join(maskedTarget, "rubin-writer.lock")); statErr != nil {
			t.Fatalf("failed Create removed owned residue: %v", statErr)
		}
	} else {
		requireEnvironmentStore(t, masked, environmentConfig())
		for _, name := range []string{"rubin-writer.lock", "mdbx.dat", "mdbx.lck"} {
			requireArtifact(t, filepath.Join(maskedTarget, name), 0o600, name == "rubin-writer.lock")
		}
		mustEnvironment(t, masked.Close())
	}
	missingSidecar := closedEnvironment(t)
	mustEnvironment(t, os.Remove(filepath.Join(missingSidecar, "rubin-writer.lock")))
	directOpen := &Store{}
	requireEnvironmentError(t, directOpen.openEnvironment(missingSidecar, environmentConfig()), EngineIO, operationOpen, int(syscall.ENOENT), "read back Rubin writer lock")
	consumeNativeTestStore(t, directOpen)
	staticCorrupt := t.TempDir()
	mustEnvironment(t, os.Chmod(staticCorrupt, 0o700))
	mustEnvironment(t, os.WriteFile(filepath.Join(staticCorrupt, "mdbx.dat"), []byte(strings.Repeat("x", 262144)), 0o600))
	mustEnvironment(t, os.WriteFile(filepath.Join(staticCorrupt, "mdbx.lck"), []byte(strings.Repeat("x", 262144)), 0o600))
	mustEnvironment(t, os.WriteFile(filepath.Join(staticCorrupt, "rubin-writer.lock"), nil, 0o600))
	requireOpenEnvironmentError(t, staticCorrupt, EngineIntegrity, codeInvalid, expectedNativeDiagnostic(codeInvalid))
	corrupt := closedEnvironment(t)
	mustEnvironment(t, os.WriteFile(filepath.Join(corrupt, "mdbx.dat"), []byte("not mdbx"), 0o600))
	requireOpenEnvironmentError(t, corrupt, EngineIntegrity, codeInvalid, "mdbx.dat is undersized")
	handle, result, lockErr := filelock.Acquire(filepath.Join(corrupt, "rubin-writer.lock"))
	if handle == nil || result != "" || lockErr != nil {
		t.Fatalf("corrupt Open retained writer: %v/%q/%v", handle, result, lockErr)
	}
	mustEnvironment(t, handle.Release())
}

func TestEnvironmentPureMatrices(t *testing.T) {
	direct := nativeError(operationInit, codeThreadMismatch)
	var typedNil *EngineError
	if engine, ok := directEngineError(direct); !ok || engine == nil {
		t.Fatal("direct EngineError rejected")
	}
	if engine, ok := directEngineError(panicErrorWrapper{cause: direct}); ok || engine != nil {
		t.Fatal("wrapped EngineError accepted")
	}
	if engine, ok := directEngineError(typedNil); ok || engine != nil {
		t.Fatal("typed-nil EngineError accepted")
	}
	for _, tc := range []struct {
		first, second int
		diagnostic    string
	}{
		{-1, 0, "MDBX debug normalization failed"},
		{-1, 0x00030000, "MDBX debug normalization failed"},
		{0, 0, "MDBX debug normalization did not stabilize"},
		{0x00030000, 0x00030001, "MDBX debug normalization did not stabilize"},
	} {
		requireEnvironmentError(t, debugNormalizationError(tc.first, tc.second), EngineLocalInvariant, operationInit, -30779, tc.diagnostic)
	}
	if debugNormalizationError(0, 0x00030000) != nil || debugNormalizationError(0x7fffffff, 0x00030000) != nil {
		t.Fatal("valid packed debug result rejected")
	}
	for _, diagnostic := range []string{"mdbx_env_create returned invalid result shape", "mdbx_txn_begin returned invalid result shape"} {
		mustEnvironment(t, nativePointerResultError(operationOpen, diagnostic, 0, true))
		requireEnvironmentError(t, nativePointerResultError(operationOpen, diagnostic, 0, false), EngineLocalInvariant, operationOpen, -30779, diagnostic)
		native := requireEnvironmentError(t, nativePointerResultError(operationOpen, diagnostic, -30778, false), EngineConcurrency, operationOpen, -30778, expectedNativeDiagnostic(-30778))
		contradiction := requireEnvironmentError(t, nativePointerResultError(operationOpen, diagnostic, -30778, true), EngineLocalInvariant, operationOpen, -30779, diagnostic)
		if errors.Unwrap(contradiction) == nil || !errors.Is(contradiction, native) && contradiction.Cause.Error() != native.Error() {
			t.Fatal("failure+nonnil lost native cause")
		}
	}
	shapeDiagnostic := "mdbx_txn_begin returned invalid result shape"
	for i, tc := range []struct {
		err   error
		valid bool
	}{
		{nativeError(operationInit, -30416), true},
		{nativeError(operationAbort, -30416), true},
		{adapterError(operationInit, EngineLocalInvariant, -30779, shapeDiagnostic, nativeError(operationInit, -30778)), true},
		{adapterError(operationOpen, EngineLocalInvariant, -30779, shapeDiagnostic, nativeError(operationOpen, -30778)), true},
		{nativeError(operationOpen, -30416), false},
		{adapterError(operationInit, EngineLocalInvariant, -30778, shapeDiagnostic, nativeError(operationInit, -30778)), false},
		{adapterError(operationInit, EngineLocalInvariant, -30779, "forged", nativeError(operationInit, -30778)), false},
		{adapterError(operationInit, EngineLocalInvariant, -30779, shapeDiagnostic, nil), false},
		{adapterError(operationInit, EngineLocalInvariant, -30779, shapeDiagnostic, nativeError(operationOpen, -30778)), false},
		{nil, false},
	} {
		if validPoisonTerminal(tc.err) != tc.valid {
			t.Fatalf("poison terminal row %d validity changed", i)
		}
	}
	requireEnvironmentError(t, nativePointerResultError("unknown", "ignored", 0, true), EngineLocalInvariant, operationInit, -30779, "unsupported engine operation")
	releaseCause := fmt.Errorf("wrapped: %w", syscall.ENOSPC)
	release := requireEnvironmentError(t, releaseResult(releaseCause), EngineCapacity, operationClose, int(syscall.ENOSPC), "release Rubin writer lock")
	if releaseResult(nil) != nil || !sameError(errors.Unwrap(release), releaseCause) {
		t.Fatal("release result or cause identity changed")
	}
	requireEnvironmentError(t, requireCreateTargetAbsent("\x00"), EngineInvalidInput, operationCreate, int(syscall.EINVAL), "inspect Create path")
	requireEnvironmentError(t, normalizeOwnedFile("\x00", "mdbx.dat", false, operationCreate, "normalize", "read"), EngineInvalidInput, operationCreate, int(syscall.EINVAL), "read")
	requireEnvironmentError(t, readOwnedFile("\x00", "mdbx.dat", false, operationOpen, "read"), EngineInvalidInput, operationOpen, int(syscall.EINVAL), "read")
	cfg := environmentConfig()
	valid := effectiveConfig{flags: 0x02200000, mode: 0, pageSize: 4096, systemPageSize: 4096, maxReaders: 492, lower: 1 << 20, current: 2 << 20, upper: 256 << 20, growth: 1 << 20, shrink: 2 << 20, maxKey: 77, maxValue: 68_000_125, limits: nativeLimits{minDB: 1, maxDB: 1 << 40, maxKey: 77, maxValue: 68_000_125}}
	if err := validateEffective(cfg, valid); err != nil {
		t.Fatalf("valid effective tuple: %v", err)
	}
	if err := validateStoredConfig(cfg, cfg); err != nil {
		t.Fatalf("identical stored ConfigV1: %v", err)
	}
	for _, tc := range []struct {
		requested, systemPageSize, effective uint32
		want                                 string
	}{
		{492, 4096, 491, "MaxReaders: got 491 outside native rounding [492,619] for system page 4096"},
		{492, 4096, 492, ""},
		{492, 4096, 619, ""},
		{492, 4096, 620, "MaxReaders: got 620 outside native rounding [492,619] for system page 4096"},
		{32767, 4096, 32767, ""},
		{32767, 4096, 32768, "MaxReaders: got 32768 outside native rounding [32767,32767] for system page 4096"},
		{492, 256, 492, ""},
		{492, 16 * 1024 * 1024, 492, ""},
		{492, 0, 492, "SystemPageSize: got 0 outside supported power-of-two [256,16777216]"},
		{492, 16, 492, "SystemPageSize: got 16 outside supported power-of-two [256,16777216]"},
		{492, 768, 492, "SystemPageSize: got 768 outside supported power-of-two [256,16777216]"},
		{492, 16*1024*1024 + 1, 492, "SystemPageSize: got 16777217 outside supported power-of-two [256,16777216]"},
	} {
		err := validateEffectiveMaxReaders(tc.requested, tc.effective, tc.systemPageSize)
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || err.Error() != tc.want) {
			t.Fatalf("reader envelope (%d,%d,%d)=%v, want %q", tc.requested, tc.systemPageSize, tc.effective, err, tc.want)
		}
	}
	for _, tc := range []struct {
		want string
		set  func(*ConfigV1)
	}{
		{"Lower: got 1052672, want 1048576", func(v *ConfigV1) { v.Lower += 4096 }},
		{"Now: got 2101248, want 2097152", func(v *ConfigV1) { v.Now += 4096 }},
		{"Upper: got 268439552, want 268435456", func(v *ConfigV1) { v.Upper += 4096 }},
		{"Growth: got 1052672, want 1048576", func(v *ConfigV1) { v.Growth += 4096 }},
		{"Shrink: got 2101248, want 2097152", func(v *ConfigV1) { v.Shrink += 4096 }},
		{"PageSize: got 8192, want 4096", func(v *ConfigV1) { v.PageSize = 8192 }},
		{"MaxReaders: got 493, want 492", func(v *ConfigV1) { v.MaxReaders++ }},
	} {
		stored := cfg
		tc.set(&stored)
		if err := validateStoredConfig(stored, cfg); err == nil || err.Error() != tc.want {
			t.Fatalf("stored mismatch=%v, want %q", err, tc.want)
		}
	}
	lower, upper := valid, valid
	lower.current, upper.current = cfg.Lower, cfg.Upper
	if validateEffective(cfg, lower) != nil || validateEffective(cfg, upper) != nil {
		t.Fatal("inclusive Current boundary rejected")
	}
	mutations := []func(*effectiveConfig){
		func(v *effectiveConfig) { v.flags = 0x00200000 }, func(v *effectiveConfig) { v.flags = 0x02200001 }, func(v *effectiveConfig) { v.mode = 1 },
		func(v *effectiveConfig) { v.pageSize = 8192 }, func(v *effectiveConfig) { v.systemPageSize = 768 }, func(v *effectiveConfig) { v.maxReaders = 620 }, func(v *effectiveConfig) { v.lower++ },
		func(v *effectiveConfig) { v.upper-- }, func(v *effectiveConfig) { v.growth++ }, func(v *effectiveConfig) { v.shrink++ },
		func(v *effectiveConfig) { v.current = cfg.Lower - uint64(cfg.PageSize) }, func(v *effectiveConfig) { v.current = cfg.Upper + uint64(cfg.PageSize) }, func(v *effectiveConfig) { v.current = cfg.Lower + 1 },
		func(v *effectiveConfig) { v.maxKey = 76 }, func(v *effectiveConfig) { v.maxValue = 68_000_124 },
		func(v *effectiveConfig) { v.limits.maxDB = 1 },
	}
	for i, mutate := range mutations {
		got := valid
		mutate(&got)
		if validateEffective(cfg, got) == nil {
			t.Fatalf("effective mutation %d accepted", i)
		}
	}
	limits := nativeLimits{minDB: int64(cfg.Lower), maxDB: int64(cfg.Upper), maxKey: 77, maxValue: 68_000_125}
	if validateLimits(cfg, limits) != nil {
		t.Fatal("exact native limits rejected")
	}
	for _, bad := range []nativeLimits{{minDB: -1, maxDB: 1, maxKey: 77, maxValue: 68_000_125}, {minDB: 1, maxDB: 0, maxKey: 77, maxValue: 68_000_125}, {minDB: 1, maxDB: 1 << 40, maxKey: 76, maxValue: 68_000_125}, {minDB: 1, maxDB: 1 << 40, maxKey: 77, maxValue: 68_000_124}} {
		if validateLimits(cfg, bad) == nil {
			t.Fatalf("invalid native limits accepted: %+v", bad)
		}
	}
}

func TestNoPackageLocalEnvironmentEntrypointCaller(t *testing.T) {
	require := func(ok bool, format string, args ...any) {
		t.Helper()
		if !ok {
			t.Fatalf(format, args...)
		}
	}
	context := build.Default
	context.CgoEnabled = true
	pkg, err := context.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	names := append(append([]string{}, pkg.GoFiles...), pkg.CgoFiles...)
	sort.Strings(names)
	fset := token.NewFileSet()
	files, sources := make(map[string]*ast.File, len(names)), make(map[string][]byte, len(names))
	var ordinarySource strings.Builder
	for _, name := range names {
		source, readErr := os.ReadFile(name)
		require(readErr == nil, "%v", readErr)
		file, parseErr := parser.ParseFile(fset, name, source, 0)
		require(parseErr == nil, "%v", parseErr)
		files[name], sources[name] = file, source
		ordinarySource.Write(source)
	}
	file, source := files["mdbx_cgo.go"], sources["mdbx_cgo.go"]
	require(file != nil, "ordinary build omitted mdbx_cgo.go")
	allowed := map[token.Pos]bool{}
	decls := map[string][]*ast.FuncDecl{}
	functions := map[string]*ast.FuncDecl{}
	for _, parsed := range files {
		for _, declaration := range parsed.Decls {
			if fn, ok := declaration.(*ast.FuncDecl); ok {
				if parsed == file {
					functions[fn.Name.Name] = fn
				}
				if fn.Recv == nil && (fn.Name.Name == "Create" || fn.Name.Name == "Open") {
					allowed[fn.Name.Pos()] = true
					decls[fn.Name.Name] = append(decls[fn.Name.Name], fn)
				}
			}
		}
	}
	require(len(decls["Create"]) == 1 && len(decls["Open"]) == 1, "entrypoint declarations Create/Open=%d/%d, want 1/1", len(decls["Create"]), len(decls["Open"]))
	for _, parsed := range files {
		ast.Inspect(parsed, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok && (ident.Name == "Create" || ident.Name == "Open") && !allowed[ident.Pos()] {
				t.Errorf("package-local %s identifier at %s", ident.Name, fset.Position(ident.Pos()))
			}
			return true
		})
	}
	body := func(name string) string {
		fn := functions[name]
		return string(source[fset.Position(fn.Body.Lbrace).Offset:fset.Position(fn.Body.Rbrace).Offset])
	}
	nodeText := func(node ast.Node) string {
		return string(source[fset.Position(node.Pos()).Offset:fset.Position(node.End()).Offset])
	}
	compact := func(node ast.Node) string { return strings.Join(strings.Fields(nodeText(node)), " ") }
	callName := func(call *ast.CallExpr) string {
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			return fn.Name
		case *ast.SelectorExpr:
			if base, ok := fn.X.(*ast.Ident); ok {
				return base.Name + "." + fn.Sel.Name
			}
		}
		return compact(call.Fun)
	}
	var normalizeSpecs []*ast.ValueSpec
	for _, declaration := range file.Decls {
		declaration, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, raw := range declaration.Specs {
			spec, ok := raw.(*ast.ValueSpec)
			if ok && len(spec.Names) == 1 && spec.Names[0].Name == "normalizeMDBXModule" {
				normalizeSpecs = append(normalizeSpecs, spec)
			}
		}
	}
	require(len(normalizeSpecs) == 1 && functions["normalizeMDBXModule"] == nil && compact(normalizeSpecs[0]) == "normalizeMDBXModule = sync.OnceValue(func() error { result := C.rubin_mdbx_normalize_debug() return debugNormalizationError(int(result.first), int(result.second)) })", "normalizeMDBXModule OnceValue ownership drifted")
	for name, expected := range map[string]string{"Create": "validateCreateStatic", "Open": "validatePath,validateOpenArtifacts,validateOpenStatic"} {
		fn, normalizeAt := functions[name], token.NoPos
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && callName(call) == "normalizeMDBXModule" {
				normalizeAt = call.Pos()
			}
			return true
		})
		var got []string
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && call.Pos() < normalizeAt {
				got = append(got, callName(call))
			}
			return true
		})
		if normalizeAt == token.NoPos || strings.Join(got, ",") != expected {
			t.Errorf("%s pre-normalization calls=%v, want %s", name, got, expected)
		}
	}
	preopenCalls := 0
	ast.Inspect(functions["Open"].Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && callName(call) == "validatePreopenSnapshot" {
			preopenCalls++
		}
		return true
	})
	require(preopenCalls == 1, "Open preopen snapshot calls=%d, want 1", preopenCalls)
	for name, sequence := range map[string][]string{
		"Create":                  {"validateCreateStatic", "normalizeMDBXModule", "limitsForPage", "createDirectory", "acquireWriter", "createEnvironment", "runLocked"},
		"Open":                    {"validatePath", "validateOpenArtifacts", "validateOpenStatic", "normalizeMDBXModule", "validatePreopenSnapshot", "limitsForPage", "acquireWriter", "openEnvironment", "runLocked"},
		"validateOpenStatic":      {"cfg.Encode", "adapterError"},
		"validatePreopenSnapshot": {"append([]byte(path), 0)", "var info C.MDBX_envinfo", "C.mdbx_preopen_snapinfo", "unsafe.Sizeof(info)", "runtime.KeepAlive(pathBytes)", "C.MDBX_ENODATA", "integrityError", "nativeError"},
		"validateCreateStatic":    {"validatePath", "requireCreateTargetAbsent", "cfg.Encode", "adapterError"},
		"openEnvironment":         {"C.mdbx_env_set_maxdbs(s.env, 7)", "C.mdbx_env_set_maxreaders(s.env, C.uint(cfg.MaxReaders))", "openNativeEnvironment(s.env, path, C.MDBX_NOSTICKYTHREADS, 0, operationOpen)", "readOwnedFile(filepath.Join(path, artifact.name)"},
		"inspectSchema":           {"verifyMainCardinality", "openSchemaDBIs", "readRequiredMeta", "validateStoredConfig", "readEffective", "validateEffective"},
		"openNativeEnvironment":   {"append([]byte(path), 0)", "C.mdbx_env_open", "runtime.KeepAlive(pathBytes)"},
		"openSchemaDBIs":          {"C.MDBX_DB_ACCEDE", "C.MDBX_DB_DEFAULTS | C.MDBX_CREATE", "append([]byte(dbi.Name), 0)", "C.mdbx_dbi_open", "runtime.KeepAlive(name)", "C.mdbx_dbi_flags_ex", "persistent != 0"},
		"getSizedValue":           {"C.rubin_mdbx_get", "runtime.KeepAlive(key)", "requiredValueResult", "C.GoBytes"},
		"consume":                 {"nativeOutcome := primary", "nativeOutcome = orderedErrors(operationClose, decision.order, primary, closeErr)", "releaseErr := releaseError(s.writer)", "s.terminal = joinErrors(nativeOutcome, releaseErr)", "return false, s.terminal"},
	} {
		position := -1
		for _, call := range sequence {
			next := strings.Index(body(name), call)
			if next <= position {
				t.Errorf("%s call order failed at %s", name, call)
			}
			position = next
		}
	}
	production := string(source)
	preambleStart, preambleEnd := strings.Index(production, "/*"), strings.Index(production, "*/")
	require(preambleStart >= 0 && preambleEnd > preambleStart, "cgo preamble framing drifted")
	preambleDigest := fmt.Sprintf("%x", sha256.Sum256([]byte(production[preambleStart:preambleEnd+2])))
	require(preambleDigest == "19017dc3568a36890760d45263aaa13e90584909802f75d738dd4e3634eaa367", "cgo preamble digest=%s", preambleDigest)
	require(strings.Count(ordinarySource.String(), "mdbx_setup_debug") == 2 && strings.Count(ordinarySource.String(), "sync.OnceValue(") == 1 && strings.Count(ordinarySource.String(), "C.rubin_mdbx_normalize_debug()") == 1 && strings.Count(ordinarySource.String(), "normalizeMDBXModule()") == 2, "single-owner debug normalization drifted")
	require(strings.Count(ordinarySource.String(), "C.mdbx_preopen_snapinfo(") == 1 && strings.Count(body("validatePreopenSnapshot"), "cfg.PageSize") == 0, "preopen snapshot ownership drifted")
	for _, name := range []string{"Create", "Open"} {
		require(strings.Count(body(name), "&Store{") == 1 && strings.Count(body(name), "store := &Store{writer: writer}\n\tstore.self = store") == 1, "%s constructor Store publication drifted", name)
	}
	nativeFiles := "for _, name := range [...]string{\"mdbx.dat\", \"mdbx.lck\"} {\n\t\terr = normalizeOwnedFile(filepath.Join(path, name), name, false, operationCreate, \"normalize \"+name+\" mode\", \"read back \"+name)\n\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n\t}"
	require(strings.Count(body("createEnvironment"), nativeFiles) == 1, "native-created file normalization/readback loop drifted")
	normalizeBody := `{ info, err := os.Lstat(path) if err != nil { return ioError(operation, readDiagnostic, err) } if !validFileInfo(info, empty, false) { return integrityError(operation, name+" is unsafe", nil) } err = os.Chmod(path, 0o600) if err != nil { return ioError(operation, normalizeDiagnostic, err) } return readOwnedFile(path, name, empty, operation, readDiagnostic) }`
	require(compact(functions["normalizeOwnedFile"].Body) == normalizeBody, "owned-file normalization helper drifted")
	for _, literal := range []string{"C.MDBX_NOSTICKYTHREADS, 0o600, operationCreate", "C.MDBX_NOSTICKYTHREADS, 0, operationOpen", "C.MDBX_DB_ACCEDE", "C.MDBX_DB_DEFAULTS | C.MDBX_CREATE"} {
		if strings.Count(production, literal) != 1 {
			t.Errorf("native literal/call-site %q drifted", literal)
		}
	}
	var maxDBsAssignments, maxDBsCalls, fixtureBranches []string
	ast.Inspect(functions["configureCreateEnvironment"].Body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == 1 && compact(n.Lhs[0]) == "maxDBs" {
				maxDBsAssignments = append(maxDBsAssignments, compact(n))
			}
		case *ast.IncDecStmt:
			if compact(n.X) == "maxDBs" {
				maxDBsAssignments = append(maxDBsAssignments, compact(n))
			}
		case *ast.CallExpr:
			if callName(n) == "C.mdbx_env_set_maxdbs" {
				maxDBsCalls = append(maxDBsCalls, compact(n))
			}
		case *ast.IfStmt:
			if strings.Contains(compact(n.Cond), "fixtureCreateExtraDBI") {
				fixtureBranches = append(fixtureBranches, compact(n))
			}
		}
		return true
	})
	require(strings.Join(maxDBsAssignments, "|") == "maxDBs := C.MDBX_dbi(7)|maxDBs = 8" && strings.Join(maxDBsCalls, "|") == "C.mdbx_env_set_maxdbs(s.env, maxDBs)" && strings.Join(fixtureBranches, "|") == "if fixtureCreateExtraDBI != nil && fixtureCreateExtraDBI(path) { maxDBs = 8 }", "Create maxdbs ownership drifted: %v / %v / %v", maxDBsAssignments, fixtureBranches, maxDBsCalls)
	var nativeLimitCalls, limitWrapperCalls, ordinaryMaxDBCalls, effectCalls []string
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := callName(call)
			if strings.HasPrefix(name, "C.mdbx_limits_") {
				nativeLimitCalls = append(nativeLimitCalls, fn.Name.Name+":"+name)
			}
			if name == "limitsForPage" {
				limitWrapperCalls = append(limitWrapperCalls, fn.Name.Name+":"+compact(call))
			}
			if name == "C.mdbx_env_set_maxdbs" {
				ordinaryMaxDBCalls = append(ordinaryMaxDBCalls, fn.Name.Name+":"+compact(call))
			}
			if name == "os.Mkdir" || name == "os.Chmod" || name == "filelock.Acquire" || name == "filelock.AcquireExisting" {
				effectCalls = append(effectCalls, fn.Name.Name+":"+compact(call))
			}
			return true
		})
	}
	if strings.Join(nativeLimitCalls, "|") != "limitsForPage:C.mdbx_limits_dbsize_min|limitsForPage:C.mdbx_limits_dbsize_max|limitsForPage:C.mdbx_limits_keysize_max|limitsForPage:C.mdbx_limits_valsize_max" ||
		strings.Join(limitWrapperCalls, "|") != "Create:limitsForPage(cfg.PageSize)|Open:limitsForPage(cfg.PageSize)|readEffective:limitsForPage(pageSize)" {
		t.Fatalf("native-limit ownership drifted: %v / %v", nativeLimitCalls, limitWrapperCalls)
	}
	require(strings.Join(ordinaryMaxDBCalls, "|") == "configureCreateEnvironment:C.mdbx_env_set_maxdbs(s.env, maxDBs)|openEnvironment:C.mdbx_env_set_maxdbs(s.env, 7)", "ordinary maxdbs ownership drifted: %v", ordinaryMaxDBCalls)
	require(strings.Join(effectCalls, "|") == "createDirectory:os.Mkdir(path, 0o700)|createDirectory:os.Chmod(path, 0o700)|acquireWriter:filelock.Acquire(lockPath)|acquireWriter:filelock.AcquireExisting(lockPath)|normalizeOwnedFile:os.Chmod(path, 0o600)", "pre-normalization filesystem-effect ownership drifted: %v", effectCalls)
	var packageNativeLimits, packageMaxDBs, packageEffects []string
	for _, filename := range names {
		for _, declaration := range files[filename].Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := callName(call)
				owner := filename + ":" + fn.Name.Name + ":" + name
				if strings.HasPrefix(name, "C.mdbx_limits_") || name == "limitsForPage" {
					packageNativeLimits = append(packageNativeLimits, owner)
				}
				if name == "C.mdbx_env_set_maxdbs" {
					packageMaxDBs = append(packageMaxDBs, owner)
				}
				if name == "os.Mkdir" || name == "os.Chmod" || name == "filelock.Acquire" || name == "filelock.AcquireExisting" {
					packageEffects = append(packageEffects, owner)
				}
				return true
			})
		}
	}
	if strings.Join(packageNativeLimits, "|") != "mdbx_cgo.go:Create:limitsForPage|mdbx_cgo.go:Open:limitsForPage|mdbx_cgo.go:limitsForPage:C.mdbx_limits_dbsize_min|mdbx_cgo.go:limitsForPage:C.mdbx_limits_dbsize_max|mdbx_cgo.go:limitsForPage:C.mdbx_limits_keysize_max|mdbx_cgo.go:limitsForPage:C.mdbx_limits_valsize_max|mdbx_cgo.go:readEffective:limitsForPage" ||
		strings.Join(packageMaxDBs, "|") != "mdbx_cgo.go:configureCreateEnvironment:C.mdbx_env_set_maxdbs|mdbx_cgo.go:openEnvironment:C.mdbx_env_set_maxdbs" ||
		strings.Join(packageEffects, "|") != "mdbx_cgo.go:createDirectory:os.Mkdir|mdbx_cgo.go:createDirectory:os.Chmod|mdbx_cgo.go:acquireWriter:filelock.Acquire|mdbx_cgo.go:acquireWriter:filelock.AcquireExisting|mdbx_cgo.go:normalizeOwnedFile:os.Chmod" {
		t.Fatalf("package-wide native/effect ownership drifted: %v / %v / %v", packageNativeLimits, packageMaxDBs, packageEffects)
	}
	var effectiveFields, effectiveSetup []string
	ast.Inspect(functions["readEffective"].Body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				if text := compact(lhs); text == "flags" || text == "info" || text == "pageSize" || strings.HasPrefix(text, "info.") {
					effectiveSetup = append(effectiveSetup, compact(n))
					break
				}
			}
		case *ast.IncDecStmt:
			if text := compact(n.X); text == "flags" || text == "pageSize" || strings.HasPrefix(text, "info.") {
				effectiveSetup = append(effectiveSetup, compact(n))
			}
		case *ast.CallExpr:
			if name := callName(n); name == "C.mdbx_env_get_flags" || name == "C.mdbx_env_info_ex" {
				effectiveSetup = append(effectiveSetup, compact(n))
			}
		case *ast.CompositeLit:
			if compact(n.Type) == "effectiveConfig" {
				for _, elt := range n.Elts {
					effectiveFields = append(effectiveFields, compact(elt))
				}
			}
		}
		return true
	})
	effectiveWant := "flags: uint32(flags)|mode: uint32(info.mi_mode)|pageSize: pageSize|systemPageSize: uint32(info.mi_sys_pagesize)|maxReaders: uint32(info.mi_maxreaders)|lower: uint64(info.mi_geo.lower)|current: uint64(info.mi_geo.current)|upper: uint64(info.mi_geo.upper)|growth: uint64(info.mi_geo.grow)|shrink: uint64(info.mi_geo.shrink)|maxKey: int64(C.mdbx_env_get_maxkeysize_ex(env, C.MDBX_DB_DEFAULTS))|maxValue: int64(C.mdbx_env_get_maxvalsize_ex(env, C.MDBX_DB_DEFAULTS))|limits: limitsForPage(pageSize)"
	require(strings.Join(effectiveFields, "|") == effectiveWant && strings.Join(effectiveSetup, "|") == "C.mdbx_env_get_flags(env, &flags)|C.mdbx_env_info_ex(env, txn, &info, C.size_t(unsafe.Sizeof(info)))|pageSize := uint32(info.mi_dxb_pagesize)", "effective provenance drifted: %v / %v", effectiveSetup, effectiveFields)
	var effectiveCalls []string
	ast.Inspect(functions["readEffective"].Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			effectiveCalls = append(effectiveCalls, callName(call))
		}
		return true
	})
	require(strings.Join(effectiveCalls, "|") == "int|C.mdbx_env_get_flags|nativeError|int|C.mdbx_env_info_ex|C.size_t|unsafe.Sizeof|nativeError|uint32|uint32|uint32|uint32|uint32|uint64|uint64|uint64|uint64|uint64|int64|C.mdbx_env_get_maxkeysize_ex|int64|C.mdbx_env_get_maxvalsize_ex|limitsForPage", "effective native-call ownership drifted: %v", effectiveCalls)
	storedOrder := `{"Lower", stored.Lower, caller.Lower},
		{"Now", stored.Now, caller.Now},
		{"Upper", stored.Upper, caller.Upper},
		{"Growth", stored.Growth, caller.Growth},
		{"Shrink", stored.Shrink, caller.Shrink},
		{"PageSize", uint64(stored.PageSize), uint64(caller.PageSize)},
		{"MaxReaders", uint64(stored.MaxReaders), uint64(caller.MaxReaders)}`
	require(strings.Count(body("validateStoredConfig"), storedOrder) == 1, "stored/caller ConfigV1 comparison order drifted")
	consumeTail := "releaseErr := releaseError(s.writer)\n\ts.writer, s.txn = nil, nil\n\ts.config, s.dbis = ConfigV1{}, [7]C.MDBX_dbi{}\n\ts.state = storeCLOSED\n\ts.terminal = joinErrors(nativeOutcome, releaseErr)\n\treturn false, s.terminal"
	require(strings.Count(body("consume"), "nativeOutcome = orderedErrors(operationClose, decision.order, primary, closeErr)") == 1 && strings.Count(body("consume"), consumeTail) == 1, "consume terminal ordering drifted")
	errorCalls := map[string]int{}
	ast.Inspect(file, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && call.Pos() >= functions["Create"].Pos() {
			name := callName(call)
			if name == "adapterError" || name == "integrityError" || name == "ioError" || name == "writerLockError" {
				errorCalls[compact(call)]++
			}
		}
		return true
	})
	wantErrorCalls := map[string]int{
		`adapterError(operationCreate, EngineInvalidInput, codeEINVAL, "invalid ConfigV1", err)`: 1, `adapterError(operationCreate, EngineInvalidInput, codeTooLarge, "ConfigV1 exceeds pinned native limits", err)`: 1,
		`adapterError(operationOpen, EngineInvalidInput, codeEINVAL, "invalid ConfigV1", err)`: 1, `adapterError(operationOpen, EngineInvalidInput, codeTooLarge, "ConfigV1 exceeds pinned native limits", err)`: 1,
		`adapterError(operationClose, EngineInvalidInput, codeEINVAL, "nil Store", nil)`: 1, `adapterError(operationClose, EngineConcurrency, codeBusy, "store operation in progress", nil)`: 1,
		`adapterError(operationClose, EngineLocalInvariant, codeProblem, "invalid Store state", nil)`: 1, `adapterError(operationClose, EngineLocalInvariant, codeProblem, "invalid Store resource shape", nil)`: 1,
		`adapterError(operation, EngineInvalidInput, codeEINVAL, "path must be nonempty, NUL-free, absolute and clean", nil)`: 1, `adapterError(operationCreate, EngineInvalidInput, codeEExist, "Create path already exists", nil)`: 1,
		`ioError(operationCreate, "inspect Create path", err)`: 1, `ioError(operationCreate, "create environment directory", err)`: 1, `ioError(operationCreate, "read back environment directory", err)`: 2,
		`integrityError(operationCreate, "environment directory is unsafe", nil)`: 2, `ioError(operationCreate, "normalize environment directory mode", err)`: 1,
		`adapterError(operationOpen, EngineInvalidInput, codeENOFile, "Open path is absent", nil)`: 1, `ioError(operationOpen, "inspect environment directory", err)`: 1, `integrityError(operationOpen, "environment directory is unsafe", nil)`: 1,
		`adapterError(operationOpen, EngineInvalidInput, codeENOFile, name+" is absent", nil)`: 1, `ioError(operationOpen, "inspect "+name, err)`: 1, `integrityError(operationOpen, name+" is unsafe", nil)`: 1,
		`integrityError(operationOpen, "mdbx.dat is undersized", nil)`:                                           1,
		`adapterError(operationInit, EngineLocalInvariant, codeProblem, "MDBX debug normalization failed", nil)`: 1, `adapterError(operationInit, EngineLocalInvariant, codeProblem, "MDBX debug normalization did not stabilize", nil)`: 1,
		`writerLockError(operation, result, err)`: 1, `ioError(operation, readDiagnostic, err)`: 1, `integrityError(operation, name+" is unsafe", nil)`: 2,
		`ioError(operation, normalizeDiagnostic, err)`: 1, `ioError(operation, diagnostic, err)`: 1, `integrityError(operationCreate, "effective environment mismatch", err)`: 1,
		`adapterError(operation, EngineLocalInvariant, codeProblem, diagnostic, nil)`: 2, `adapterError(operation, EngineLocalInvariant, codeProblem, diagnostic, native)`: 1,
		`integrityError(operationOpen, "effective environment mismatch", err)`: 2, `integrityError(operation, "SchemaV1 DBI flags mismatch", nil)`: 1, `integrityError(operation, "SchemaV1 main cardinality mismatch", nil)`: 1,
		`integrityError(operationInit, "SchemaV1 metadata cardinality mismatch", nil)`: 1, `integrityError(operationOpen, "invalid SchemaV1 version row", err)`: 1, `integrityError(operationOpen, "invalid ConfigV1 row", err)`: 1,
		`integrityError(operation, "required metadata value mismatch", nil)`: 1, `ioError(operationClose, "release Rubin writer lock", err)`: 1,
	}
	if len(errorCalls) != len(wantErrorCalls) {
		t.Fatalf("adapter/io call-site count=%d, want %d: %v", len(errorCalls), len(wantErrorCalls), errorCalls)
	}
	for call, count := range wantErrorCalls {
		if errorCalls[call] != count {
			t.Errorf("adapter/io call-site %q count=%d, want %d", call, errorCalls[call], count)
		}
	}
	for name, marker := range map[string]string{"initializeLocked": "C.mdbx_txn_commit", "inspectOpenLocked": "s.abortLocked"} {
		var writes []string
		var writeAt []token.Pos
		markerAt := token.NoPos
		ast.Inspect(functions[name].Body, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.CallExpr:
				if callName(n) == marker {
					markerAt = n.Pos()
				}
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if text := compact(lhs); text == "*s" || text == "s.state" || text == "s.config" || text == "s.dbis" || strings.HasPrefix(text, "s.config.") {
						writes, writeAt = append(writes, compact(n)), append(writeAt, n.Pos())
						break
					}
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND && (compact(n.X) == "s.state" || compact(n.X) == "s.config" || compact(n.X) == "s.dbis") {
					writes, writeAt = append(writes, compact(n)), append(writeAt, n.Pos())
				}
			case *ast.IncDecStmt:
				if text := compact(n.X); text == "s.state" || text == "s.config" || text == "s.dbis" {
					writes, writeAt = append(writes, compact(n)), append(writeAt, n.Pos())
				}
			}
			return true
		})
		want := map[string]string{"initializeLocked": "s.state, s.config, s.dbis = storeOPEN, cfg, dbis", "inspectOpenLocked": "s.state, s.config, s.dbis = storeOPEN, cfg, dbis"}[name]
		if len(writes) != 1 || markerAt == token.NoPos || writes[0] != want || writeAt[0] <= markerAt {
			t.Errorf("%s publication writes=%v marker=%d", name, writes, markerAt)
		}
	}
	if functions["initializeSchema"].Recv != nil || functions["inspectSchema"].Recv != nil {
		t.Fatal("transaction schema helpers gained Store ownership")
	}
	for _, name := range []string{"initializeSchema", "inspectSchema"} {
		ast.Inspect(functions[name].Type.Params, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok && ident.Name == "Store" {
				t.Errorf("%s gained a Store parameter", name)
			}
			return true
		})
	}
	for name, want := range map[string]string{
		"initializeLocked":  "C.rubin_mdbx_txn_begin|nativePointerResultError|int|s.poison|initializeSchema|s.abortLocked|int|C.mdbx_txn_commit|commitTransition|nativeError|orderedErrors|s.poison",
		"inspectOpenLocked": "C.rubin_mdbx_txn_begin|nativePointerResultError|int|s.poison|inspectSchema|s.abortLocked",
	} {
		var calls []string
		ast.Inspect(functions[name].Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				calls = append(calls, callName(call))
			}
			return true
		})
		if strings.Join(calls, "|") != want {
			t.Errorf("%s helper ownership drifted: %v", name, calls)
		}
	}
	var storeWrites, packageStoreWriteOwners []string
	for _, filename := range names {
		for _, declaration := range files[filename].Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				assignment, ok := node.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range assignment.Lhs {
					_, wholeObject := lhs.(*ast.StarExpr)
					selector, ok := lhs.(*ast.SelectorExpr)
					if wholeObject || ok && (selector.Sel.Name == "state" || selector.Sel.Name == "config" || selector.Sel.Name == "dbis") {
						packageStoreWriteOwners = append(packageStoreWriteOwners, filename+":"+fn.Name.Name)
						if filename == "mdbx_cgo.go" {
							storeWrites = append(storeWrites, fn.Name.Name+":"+compact(assignment))
						}
						break
					}
				}
				return true
			})
		}
	}
	wantStoreWrites := "initializeLocked:s.state, s.config, s.dbis = storeOPEN, cfg, dbis|inspectOpenLocked:s.state, s.config, s.dbis = storeOPEN, cfg, dbis|poison:s.state, s.txn, s.terminal = storePOISONEDTHREAD, txn, err|consume:s.state, s.terminal = decision.next, nativeOutcome|consume:s.config, s.dbis = ConfigV1{}, [7]C.MDBX_dbi{}|consume:s.state = storeCLOSED"
	wantStoreOwners := "mdbx_cgo.go:initializeLocked|mdbx_cgo.go:inspectOpenLocked|mdbx_cgo.go:poison|mdbx_cgo.go:consume|mdbx_cgo.go:consume|mdbx_cgo.go:consume"
	if strings.Join(storeWrites, "|") != wantStoreWrites || strings.Join(packageStoreWriteOwners, "|") != wantStoreOwners {
		t.Fatalf("Store publication/clear ownership drifted: %v / %v", storeWrites, packageStoreWriteOwners)
	}
	if !strings.HasPrefix(production, "//go:build cgo && (darwin || linux) && (amd64 || arm64)\n") || strings.Contains(production, "os.OpenFile(") || strings.Contains(production, "os.WriteFile(") || strings.Contains(production, "os.Create(") {
		t.Fatal("production build expression or native-file ownership drifted")
	}
}
