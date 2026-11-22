package policycontrol

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

func sourceAuthorityFailIf(t *testing.T, failed bool, format string, args ...any) {
	t.Helper()
	if failed {
		t.Fatalf(format, args...)
	}
}

func sourceBorrow(t *testing.T, s *Store) *SourceAuthorityBorrowV1 {
	t.Helper()
	b, err := s.BorrowSourceAuthorityV1()
	must(t, err)
	t.Cleanup(b.ReleaseV1)
	return b
}

func sourceBorrowRefusal(t *testing.T, s *Store, want error, unresolved bool) {
	t.Helper()
	b, err := s.BorrowSourceAuthorityV1()
	matches := sameDependentValue(err, want)
	if unresolved {
		matches = errors.Is(err, want) && errors.Is(err, ErrUnresolved)
	}
	if b != nil || !matches || errors.Is(err, ErrUnresolved) != unresolved {
		t.Fatalf("source borrow: %v/%v, want %v, unresolved=%t", b, err, want, unresolved)
	}
}

func TestSourceAuthorityBorrowAdmission(t *testing.T) {
	for _, s := range []*Store{nil, {}} {
		sourceBorrowRefusal(t, s, ErrClosed, false)
	}
	s := mustCreate(t, storeDir(t), testIdentity(1))
	copied := reflect.New(reflect.TypeFor[Store]())
	copied.Elem().Set(reflect.ValueOf(s).Elem())
	sourceBorrowRefusal(t, copied.Interface().(*Store), ErrClosed, false)
	tx := mustBegin(t, s)
	sourceBorrowRefusal(t, s, ErrBusy, false)
	wantErr(t, nil)(tx.Abort())
	s.sourceBorrows = math.MaxUint64
	sourceBorrowRefusal(t, s, ErrBusy, false)
	s.sourceBorrows = 0
	s.fault = failAt(stageAck)
	r, err := controlTx(t, s, "source").Commit()
	wantResult(t, r, UNKNOWN, 0)
	wantErr(t, ErrUnresolved)(r, err)
	sourceBorrowRefusal(t, s, ErrBusy, true)
	s.sourceBorrows = math.MaxUint64
	sourceBorrowRefusal(t, s, ErrBusy, true)
	s.sourceBorrows = 0
	s.fault = nil
	wantErr(t, nil)(s.Recover())
	sourceBorrow(t, s).ReleaseV1()
	must(t, s.Close())
	sourceBorrowRefusal(t, s, ErrClosed, false)
}

func TestSourceAuthorityCloseOnly(t *testing.T) {
	s := mustCreate(t, storeDir(t), testIdentity(1))
	before := fileBytes(t, s.dir)
	checkSourceOwnerClaims(t, s)
	checkSourceBorrowClose(t, s, before)
}

func TestSourceAuthorityStagingPin(t *testing.T) {
	for _, mode := range []string{"failure", "panic", "success"} {
		t.Run(mode, func(t *testing.T) { testSourceAuthorityStagingPin(t, mode) })
	}
}

func testSourceAuthorityStagingPin(t *testing.T, mode string) {
	t.Helper()
	s := mustCreate(t, storeDir(t), testIdentity(1))
	path := filepath.Join(s.dir, "stage")
	must(t, os.WriteFile(path, []byte("staged source"), 0o600))
	b, second := sourceBorrow(t, s), sourceBorrow(t, s)
	pins := [2]*os.File{}
	for i := range pins {
		pin, err := os.Open(path)
		must(t, err)
		pins[i] = pin
		t.Cleanup(func() { _ = pin.Close() })
	}
	cause := errors.New("source construction stopped")
	use := func(stage *SourceStagePinV1) error {
		stage.File, stage.Quota = pins[0], pins[1]
		err := second.WithSourceOwnerClaimV1(func(*SourceStagePinV1) error {
			t.Fatal("second construction ran")
			return nil
		})
		sourceAuthorityFailIf(t, !sameDependentValue(err, ErrBusy), "second construction returned %v", err)
		sourceAuthorityFailIf(t, !sameDependentValue(s.Close(), ErrBusy), "close during source construction")
		assertSourcePinStatus(t, pins, nil)
		switch mode {
		case "panic":
			panic(cause)
		case "failure":
			return cause
		}
		return nil
	}
	testSourceAuthorityPinResult(t, b, use, mode, cause)
	if mode == "success" {
		assertSourcePinStatus(t, pins, nil)
		sourceAuthorityFailIf(t, !sameDependentValue(s.Close(), ErrBusy), "borrowed store closed")
		assertSourcePinStatus(t, pins, nil)
	} else {
		assertSourcePinStatus(t, pins, os.ErrClosed)
		must(t, second.WithSourceOwnerClaimV1(func(*SourceStagePinV1) error { return nil }))
	}
	b.ReleaseV1()
	second.ReleaseV1()
	must(t, s.Close())
	assertSourcePinStatus(t, pins, os.ErrClosed)
	sourceBorrowRefusal(t, s, ErrClosed, false)
	must(t, s.Close())
}

func testSourceAuthorityPinResult(t *testing.T, b *SourceAuthorityBorrowV1, use func(*SourceStagePinV1) error, mode string, cause error) {
	t.Helper()
	if mode == "panic" {
		defer func() {
			sourceAuthorityFailIf(t, !sameDependentValue(recover(), cause), "source constructor did not preserve its panic")
		}()
	}
	err := b.WithSourceOwnerClaimV1(use)
	want := map[string]error{"failure": cause}[mode]
	sourceAuthorityFailIf(t, !sameDependentValue(err, want), "source constructor returned %v, want %v", err, want)
}

func assertSourcePinStatus(t *testing.T, pins [2]*os.File, want error) {
	t.Helper()
	for _, pin := range pins {
		_, err := pin.Stat()
		sourceAuthorityFailIf(t, !errors.Is(err, want), "source descriptor status: %v, want %v", err, want)
	}
}

func checkSourceOwnerClaims(t *testing.T, s *Store) {
	t.Helper()
	one, two := sourceBorrow(t, s), sourceBorrow(t, s)
	claim := func(b *SourceAuthorityBorrowV1, use func(*SourceStagePinV1) error, want error) {
		t.Helper()
		err := b.WithSourceOwnerClaimV1(use)
		sourceAuthorityFailIf(t, !sameDependentValue(err, want), "source owner claim: %v, want %v", err, want)
	}
	unreached := func(*SourceStagePinV1) error {
		t.Fatal("refused source owner claim entered callback")
		return nil
	}
	claim(one, nil, ErrClosed)
	s.sourceBorrows = math.MaxUint64
	claim(one, unreached, ErrBusy)
	s.sourceBorrows = 2
	releaseDuringClaim := func() {
		one.ReleaseV1()
		two.ReleaseV1()
		err := s.Close()
		sourceAuthorityFailIf(t, !sameDependentValue(err, ErrBusy), "close during owner claim: %v", err)
	}
	cause := errors.New("source construction refusal")
	wrapped := fmt.Errorf("construct source: %w", cause)
	var typedNil *dependentCause
	for _, want := range []error{cause, wrapped, typedNil} {
		claim(one, func(*SourceStagePinV1) error { releaseDuringClaim(); return want }, want)
		one, two = sourceBorrow(t, s), sourceBorrow(t, s)
	}
	func() {
		defer func() {
			caught := recover()
			sourceAuthorityFailIf(t, !sameDependentValue(caught, cause), "owner claim panic: %v", caught)
		}()
		claim(one, func(*SourceStagePinV1) error { releaseDuringClaim(); panic(cause) }, nil)
	}()
	one, two = sourceBorrow(t, s), sourceBorrow(t, s)
	calls := 0
	claim(one, func(*SourceStagePinV1) error {
		calls++
		copied := *two
		claim(&copied, unreached, ErrBusy)
		claim(two, unreached, ErrBusy)
		releaseDuringClaim()
		return nil
	}, nil)
	two = sourceBorrow(t, s)
	claim(two, unreached, ErrBusy)
	sourceAuthorityFailIf(t, calls != 1, "source construction calls: %d", calls)
	two.ReleaseV1()
}

func checkSourceBorrowClose(t *testing.T, s *Store, before []byte) {
	t.Helper()
	one, two := sourceBorrow(t, s), sourceBorrow(t, s)
	copied := *one
	ask, finish := dependentChild(t, s)
	got := ask()
	sourceAuthorityFailIf(t, got != "busy\n", "borrowed writer exclusion: %q", got)
	dir, id, physical, err := one.BindingV1()
	must(t, err)
	held, err := s.lock.DirectoryIdentityV1(s.dir)
	must(t, err)
	sourceAuthorityFailIf(t, dir != s.dir || id != testIdentity(1) || physical != held || physical == (filelock.IdentityV1{}),
		"binding: %q %+v %v", dir, id, physical)
	s.RequestLatch()
	want := LatchStatus{Requested: true}
	wantLatch(t, s, want)
	tx := mustBegin(t, s)
	wantLatch(t, s, want)
	err = s.Close()
	sourceAuthorityFailIf(t, any(err) != any(ErrBusy) || s.tx != tx || tx.done || s.closed || s.lock == nil,
		"borrowed close changed transaction: %v", err)
	wantLatch(t, s, want)
	wantErr(t, nil)(tx.Abort())
	wantLatch(t, s, want)
	wantErr(t, nil)(s.Recover())
	wantLatch(t, s, want)
	one.ReleaseV1()
	one.ReleaseV1()
	dir, id, physical, err = copied.BindingV1()
	sourceAuthorityFailIf(t, dir != "" || id != (Identity{}) || physical != (filelock.IdentityV1{}) || !sameDependentValue(err, ErrClosed),
		"copied expired binding: %q %+v %v", dir, id, err)
	copied.ReleaseV1()
	err = s.Close()
	sourceAuthorityFailIf(t, any(err) != any(ErrBusy) || s.sourceBorrows != 1, "double release affected sibling: %v", err)
	got = ask()
	sourceAuthorityFailIf(t, got != "busy\n", "sibling writer exclusion: %q", got)
	sourceAuthorityFailIf(t, !bytes.Equal(before, fileBytes(t, s.dir)), "borrow changed control bytes")
	two.ReleaseV1()
	must(t, s.Close())
	wantLatch(t, s, LatchStatus{})
	got = ask()
	sourceAuthorityFailIf(t, got != "open\n", "released writer exclusion: %q", got)
	checkExpiredSourceBorrows(t, one, two)
	finish()
	must(t, mustOpen(t, s.dir, testIdentity(1)).Close())
}

func checkExpiredSourceBorrows(t *testing.T, one, two *SourceAuthorityBorrowV1) {
	t.Helper()
	for _, b := range []*SourceAuthorityBorrowV1{nil, {}, one, two} {
		err := b.WithSourceOwnerClaimV1(func(*SourceStagePinV1) error {
			t.Fatal("refused source owner claim entered callback")
			return nil
		})
		sourceAuthorityFailIf(t, !sameDependentValue(err, ErrClosed), "expired claim: %v", err)
		dir, id, physical, err := b.BindingV1()
		sourceAuthorityFailIf(t, dir != "" || id != (Identity{}) || physical != (filelock.IdentityV1{}) || !sameDependentValue(err, ErrClosed),
			"expired binding: %q %+v %v", dir, id, err)
		b.ReleaseV1()
	}
}

func TestSourceAuthorityCopiedStoreClose(t *testing.T) {
	id := testIdentity(1)
	s := mustCreate(t, storeDir(t), id)
	copiedValue := reflect.New(reflect.TypeFor[Store]())
	copiedValue.Elem().Set(reflect.ValueOf(s).Elem())
	copied := copiedValue.Interface().(*Store)
	before, lock := fileBytes(t, s.dir), s.lock
	ask, finish := dependentChild(t, s)
	b := sourceBorrow(t, s)
	err := copied.Close()
	sourceAuthorityFailIf(t, !sameDependentValue(err, ErrClosed) || copied.closed || copied.lock != lock, "copied store close: %v", err)
	err = s.Close()
	sourceAuthorityFailIf(t, !sameDependentValue(err, ErrBusy) || s.closed || s.lock != lock, "borrowed close: %v", err)
	sourceAuthorityFailIf(t, ask() != "busy\n", "copied store close released writer exclusion")
	sourceAuthorityFailIf(t, !reflect.DeepEqual(mustView(t, s), View{Identity: id}) || !bytes.Equal(before, fileBytes(t, s.dir)),
		"refused close changed control state")
	b.ReleaseV1()
	must(t, s.Close())
	sourceAuthorityFailIf(t, ask() != "open\n", "closed store retained writer exclusion")
	finish()
	reopened := mustOpen(t, s.dir, id)
	sourceAuthorityFailIf(t, !reflect.DeepEqual(mustView(t, reopened), View{Identity: id}) || !bytes.Equal(before, fileBytes(t, s.dir)),
		"reopened store has different control state")
	must(t, reopened.Close())
}

func TestSourceAuthorityCloseBorrowRace(t *testing.T) {
	for range 30 {
		s := mustCreate(t, storeDir(t), testIdentity(1))
		start := make(chan struct{})
		var wg sync.WaitGroup
		var b *SourceAuthorityBorrowV1
		var borrowErr, closeErr error
		wg.Add(2)
		go func() { defer wg.Done(); <-start; b, borrowErr = s.BorrowSourceAuthorityV1() }()
		go func() { defer wg.Done(); <-start; closeErr = s.Close() }()
		close(start)
		wg.Wait()
		if closeErr == nil {
			sourceAuthorityFailIf(t, b != nil || any(borrowErr) != any(ErrClosed), "close winner: %v %v", b, borrowErr)
		} else if any(closeErr) != any(ErrBusy) || borrowErr != nil || b == nil || s.closed {
			t.Fatalf("borrow winner: %v %v", closeErr, borrowErr)
		}
		b.ReleaseV1()
		must(t, s.Close())
	}
}

func TestSourceAuthorityDirectoryReplacement(t *testing.T) {
	id := testIdentity(1)
	s := mustCreate(t, storeDir(t), id)
	b := sourceBorrow(t, s)
	before := fileBytes(t, s.dir)
	old := filepath.Join(t.TempDir(), "old")
	must(t, os.Rename(s.dir, old))
	checkSourceBindingRefused(t, b)
	must(t, os.Symlink(old, s.dir))
	checkSourceBindingRefused(t, b)
	must(t, os.Remove(s.dir))
	must(t, os.Mkdir(s.dir, 0o700))
	checkSourceBindingRefused(t, b)
	reopened, err := Open(old, id)
	sourceAuthorityFailIf(t, reopened != nil || !errors.Is(err, ErrBusy), "open renamed directory during borrow: %v/%v", reopened, err)
	b.ReleaseV1()
	reopened, err = Open(old, id)
	sourceAuthorityFailIf(t, reopened != nil || !errors.Is(err, ErrBusy), "open renamed directory after release: %v/%v", reopened, err)
	must(t, s.Close())
	must(t, mustOpen(t, old, id).Close())
	sourceAuthorityFailIf(t, !bytes.Equal(before, fileBytes(t, old)), "renamed directory has different control bytes")
}

func checkSourceBindingRefused(t *testing.T, b *SourceAuthorityBorrowV1) {
	t.Helper()
	dir, id, physical, err := b.BindingV1()
	sourceAuthorityFailIf(t, dir != "" || id != (Identity{}) || physical != (filelock.IdentityV1{}) || !sameDependentValue(err, ErrRefused),
		"refused binding: %q %+v %v %v", dir, id, physical, err)
}

func TestSourceAuthorityDirectoryAliases(t *testing.T) {
	parent := t.TempDir()
	left, right := filepath.Join(parent, "left"), filepath.Join(parent, "right")
	clean, held := filepath.Join(left, "policy"), filepath.Join(right, "policy")
	for _, dir := range []string{left, right, filepath.Join(right, "leaf"), clean, held} {
		must(t, os.Mkdir(dir, 0o700))
	}
	must(t, os.Symlink(filepath.Join(right, "leaf"), filepath.Join(left, "link")))
	must(t, os.Symlink(right, filepath.Join(left, "alias")))
	id := testIdentity(1)
	raw := left + "/link/../policy"
	checkMismatch := func() {
		t.Helper()
		a, err := os.Stat(clean)
		must(t, err)
		b, err := os.Stat(raw)
		must(t, err)
		sourceAuthorityFailIf(t, os.SameFile(a, b), "clean and opened policy directories have the same inode")
	}
	checkMismatch()
	s, err := Create(raw, id, NewInstallationProof{Identity: id})
	sourceAuthorityFailIf(t, s != nil || !errors.Is(err, ErrRefused), "aliased create: %v/%v", s, err)
	sourceAuthorityFailIf(t, len(dirNames(t, clean)) != 0 || len(dirNames(t, held)) != 0, "aliased create changed a policy directory")
	must(t, mustCreate(t, clean, id).Close())
	must(t, mustCreate(t, held, id).Close())
	checkMismatch()
	x, y := fileBytes(t, clean), fileBytes(t, held)
	s, err = Open(raw, id)
	sourceAuthorityFailIf(t, s != nil || !errors.Is(err, ErrRefused) || !bytes.Equal(x, fileBytes(t, clean)) || !bytes.Equal(y, fileBytes(t, held)),
		"aliased open changed or qualified policy: %v/%v", s, err)
	must(t, mustOpen(t, held, id).Close())
	must(t, os.Chmod(right, 0o100))
	t.Cleanup(func() { _ = os.Chmod(right, 0o700) })
	_, err = os.ReadDir(right)
	privilegedRead := err == nil && os.Geteuid() == 0
	sourceAuthorityFailIf(t, !privilegedRead && !errors.Is(err, os.ErrPermission), "search-only parent read: %v", err)
	dir := filepath.Join(left, "alias", "leaf")
	must(t, mustCreate(t, dir, id).Close())
	must(t, mustOpen(t, dir, id).Close())
}

func TestSourceAuthorityUnknownAfterBorrow(t *testing.T) {
	t.Run("lost-acknowledgement", checkSourceBorrowLostAck)
	t.Run("retained-handle", checkSourceBorrowRetainedHandle)
}

func checkSourceBorrowLostAck(t *testing.T) {
	s := mustCreate(t, storeDir(t), testIdentity(1))
	b := sourceBorrow(t, s)
	s.fault = failAt(stageAck)
	r, err := controlTx(t, s, "retained").Commit()
	wantResult(t, r, UNKNOWN, 0)
	wantErr(t, ErrUnresolved)(r, err)
	pending, handle := s.pending, s.pending.handle
	err = s.Close()
	sourceAuthorityFailIf(t, any(err) != any(ErrBusy) || s.pending != pending || s.pending.handle != handle || s.closed,
		"borrowed close changed pending owner: %v", err)
	dir, id, _, err := b.BindingV1()
	sourceAuthorityFailIf(t, err != nil || dir != s.dir || id != testIdentity(1), "source lifetime after transaction: %q/%v/%v", dir, id, err)
	s.fault = nil
	r, err = s.Recover()
	wantResult(t, r, NEW, 1)
	must(t, err)
	b.ReleaseV1()
	must(t, s.Close())
}

func checkSourceBorrowRetainedHandle(t *testing.T) {
	s := mustCreate(t, storeDir(t), testIdentity(1))
	b := sourceBorrow(t, s)
	before := fileBytes(t, s.dir)
	s.fault = failWith(errInjectedCrash, stageFileSync)
	r, err := controlTx(t, s, "retained").Commit()
	sourceAuthorityFailIf(t, r != (Result{Truth: UNKNOWN}), "commit result = %+v, want UNKNOWN with zero sequence", r)
	wantErr(t, ErrUnresolved)(r, err)
	wantErr(t, errInjectedCrash)(r, err)
	if s.pending == nil || s.pending.handle == nil {
		t.Fatal("unresolved store has no pending scratch file")
	}
	pending, handle := s.pending, s.pending.handle
	_, err = handle.Stat()
	must(t, err)
	s.RequestLatch()
	want := LatchStatus{Requested: true}
	wantLatch(t, s, want)
	err = s.Close()
	sourceAuthorityFailIf(t, !sameDependentValue(err, ErrBusy) || s.pending != pending || pending.handle != handle || s.closed,
		"borrowed close changed pending scratch owner: %v", err)
	_, err = handle.Stat()
	must(t, err)
	wantLatch(t, s, want)
	sourceAuthorityFailIf(t, !bytes.Equal(before, fileBytes(t, s.dir)), "borrowed close changed predecessor bytes")
	b.ReleaseV1()
	must(t, s.Close())
	_, err = handle.Stat()
	sourceAuthorityFailIf(t, pending.handle != nil || !errors.Is(err, os.ErrClosed), "closed store retained pending scratch file: %v", err)
	wantLatch(t, s, LatchStatus{})
}

func TestSourceAuthorityCrossingAdmission(t *testing.T) {
	s := mustCreate(t, storeDir(t), testIdentity(1))
	tx := controlTx(t, s, "source crossing")
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release); awaitDependent(t, done) })
	t.Cleanup(finish)
	s.fault = func(stage stage) error {
		if stage == stageFileSync {
			close(entered)
			<-release
		}
		return nil
	}
	var result Result
	var commitErr error
	go func() { defer close(done); result, commitErr = tx.Commit() }()
	awaitDependent(t, entered)
	sourceBorrowRefusal(t, s, ErrBusy, false)
	finish()
	wantResult(t, result, NEW, 1)
	must(t, commitErr)
	s.fault = nil
	sourceBorrow(t, s).ReleaseV1()
	must(t, s.Close())
}
