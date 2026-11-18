package policycontrol

import (
	"bytes"
	"errors"
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
	s.fault = nil
	wantErr(t, nil)(s.Recover())
	sourceBorrow(t, s).ReleaseV1()
	must(t, s.Close())
	sourceBorrowRefusal(t, s, ErrClosed, false)
}

func TestSourceAuthorityCloseOnly(t *testing.T) {
	s := mustCreate(t, storeDir(t), testIdentity(1))
	before := fileBytes(t, s.dir)
	one, two := sourceBorrow(t, s), sourceBorrow(t, s)
	claim := func(b *SourceAuthorityBorrowV1, use func() error, want error) {
		t.Helper()
		err := b.WithSourceOwnerClaimV1(use)
		sourceAuthorityFailIf(t, !sameDependentValue(err, want), "source owner claim: %v, want %v", err, want)
	}
	unreached := func() error {
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
	claim(one, func() error { releaseDuringClaim(); return cause }, cause)
	one, two = sourceBorrow(t, s), sourceBorrow(t, s)
	func() {
		defer func() {
			caught := recover()
			sourceAuthorityFailIf(t, !sameDependentValue(caught, cause), "owner claim panic: %v", caught)
		}()
		claim(one, func() error { releaseDuringClaim(); panic(cause) }, nil)
	}()
	one, two = sourceBorrow(t, s), sourceBorrow(t, s)
	calls := 0
	claim(one, func() error {
		calls++
		claim(two, unreached, ErrBusy)
		releaseDuringClaim()
		return nil
	}, nil)
	one, two = sourceBorrow(t, s), sourceBorrow(t, s)
	claim(two, unreached, ErrBusy)
	sourceAuthorityFailIf(t, calls != 1, "source construction calls: %d", calls)
	copied := *one
	ask, finish := dependentChild(t, s)
	got := ask()
	sourceAuthorityFailIf(t, got != "busy\n", "borrowed writer exclusion: %q", got)
	dir, id, physical, err := one.BindingV1()
	must(t, err)
	sourceAuthorityFailIf(t, dir != s.dir || id != testIdentity(1) || physical == (filelock.IdentityV1{}), "binding: %q %+v", dir, id)
	tx := mustBegin(t, s)
	err = s.Close()
	sourceAuthorityFailIf(t, any(err) != any(ErrBusy) || s.tx != tx || tx.done || s.closed || s.lock == nil,
		"borrowed close changed transaction: %v", err)
	wantErr(t, nil)(tx.Abort())
	wantErr(t, nil)(s.Recover())
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
	got = ask()
	sourceAuthorityFailIf(t, got != "open\n", "released writer exclusion: %q", got)
	for _, b := range []*SourceAuthorityBorrowV1{nil, {}, one, two} {
		claim(b, unreached, ErrClosed)
		dir, id, physical, err := b.BindingV1()
		sourceAuthorityFailIf(t, dir != "" || id != (Identity{}) || physical != (filelock.IdentityV1{}) || !sameDependentValue(err, ErrClosed),
			"expired binding: %q %+v %v", dir, id, err)
		b.ReleaseV1()
	}
	finish()
	must(t, mustOpen(t, s.dir, testIdentity(1)).Close())
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
	s := mustCreate(t, storeDir(t), testIdentity(1))
	b := sourceBorrow(t, s)
	old := filepath.Join(t.TempDir(), "old")
	must(t, os.Rename(s.dir, old))
	must(t, os.Mkdir(s.dir, 0o700))
	_, _, _, err := b.BindingV1()
	sourceAuthorityFailIf(t, !sameDependentValue(err, ErrRefused), "replaced directory binding: %v", err)
	b.ReleaseV1()
	must(t, s.Close())
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
	sourceAuthorityFailIf(t, !errors.Is(err, os.ErrPermission), "search-only parent read: %v", err)
	dir := filepath.Join(left, "alias", "leaf")
	must(t, mustCreate(t, dir, id).Close())
	must(t, mustOpen(t, dir, id).Close())
}

func TestSourceAuthorityUnknownAfterBorrow(t *testing.T) {
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
	go func() { defer close(done); mustCommit(t, tx, NEW, 1) }()
	awaitDependent(t, entered)
	sourceBorrowRefusal(t, s, ErrBusy, false)
	finish()
	s.fault = nil
	sourceBorrow(t, s).ReleaseV1()
	must(t, s.Close())
}
