//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

type nilPointerError struct{}

func (*nilPointerError) Error() string { return "nil pointer" }
func (*nilPointerError) Unwrap() error { return syscall.ENOSPC }

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
	if orderedErrors(operationAbort, orderNone, primary, result) != nil || orderedErrors(operationAbort, orderPrimary, primary, result) != primary || orderedErrors(operationAbort, orderPrimary, typedNil, result) != typedNil || orderedErrors(operationAbort, orderResult, nil, resultEngine) != resultEngine {
		t.Fatal("single-result ordering changed")
	}
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
	requireFallback(t, operationAbort, orderResult, nil, nil, "native result is not an EngineError", "")
	if got := requireEngineError(t, orderedErrors(operationAbort, orderResult, nil, typedNil), EngineLocalInvariant, operationAbort, codeProblem); got.Cause != typedNil || errors.Unwrap(got) != typedNil || got.Error() != "abort: LocalInvariant: code -30779: native result is not an EngineError: <nil>" {
		t.Fatalf("typed-nil result identity=%+v", got)
	}
	requireFallback(t, operationAbort, orderPrimaryResult, primary, result, "native result is not an EngineError", "primary\nresult", primary, result)
	requireFallback(t, operationAbort, orderPrimaryResult, primary, nil, "native result is not an EngineError", "primary", primary)
	requireFallback(t, operationAbort, orderPrimaryResult, primary, typedNil, "native result is not an EngineError", "primary\n<nil>", primary, typedNil)
	requireFallback(t, operationAbort, orderResultCausesPrimary, primary, result, "native result is not an EngineError", "primary\nresult", primary, result)
	requireFallback(t, operationAbort, orderResultCausesPrimary, primary, wrapped, "native result is not an EngineError", "primary\n"+wrapped.Error(), primary, wrapped, resultEngine)
	requireFallback(t, operationClose, orderResultCausesPrimary, primary, nil, "native result is not an EngineError", "primary", primary)
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
