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

func sourceBorrow(t *testing.T, s *Store) *SourceAuthorityBorrowV1 {
	t.Helper()
	b, err := s.BorrowSourceAuthorityV1()
	must(t, err)
	return b
}

func TestSourceAuthorityBorrowAdmission(t *testing.T) {
	for _, s := range []*Store{nil, {}} {
		if b, err := s.BorrowSourceAuthorityV1(); b != nil || any(err) != any(ErrClosed) {
			t.Fatalf("unopened store borrow: %v %v", b, err)
		}
	}
	s := mustCreate(t, storeDir(t), testIdentity(1))
	copied := reflect.New(reflect.TypeFor[Store]())
	copied.Elem().Set(reflect.ValueOf(s).Elem())
	if b, err := copied.Interface().(*Store).BorrowSourceAuthorityV1(); b != nil || !sameDependentValue(err, ErrClosed) {
		t.Fatalf("copied store borrow: %v/%v", b, err)
	}
	tx := mustBegin(t, s)
	if b, err := s.BorrowSourceAuthorityV1(); b != nil || any(err) != any(ErrBusy) || errors.Is(err, ErrUnresolved) {
		t.Fatalf("held transaction borrow: %v %v", b, err)
	}
	wantErr(t, nil)(tx.Abort())
	s.sourceBorrows = math.MaxUint64
	if b, err := s.BorrowSourceAuthorityV1(); b != nil || any(err) != any(ErrBusy) {
		t.Fatalf("counter exhaustion: %v %v", b, err)
	}
	s.sourceBorrows = 0
	s.fault = failAt(stageAck)
	r, err := controlTx(t, s, "source").Commit()
	wantResult(t, r, UNKNOWN, 0)
	wantErr(t, ErrUnresolved)(r, err)
	if b, err := s.BorrowSourceAuthorityV1(); b != nil || !errors.Is(err, ErrBusy) || !errors.Is(err, ErrUnresolved) {
		t.Fatalf("unresolved borrow: %v %v", b, err)
	}
	s.fault = nil
	wantErr(t, nil)(s.Recover())
	sourceBorrow(t, s).ReleaseV1()
	must(t, s.Close())
	if b, err := s.BorrowSourceAuthorityV1(); b != nil || any(err) != any(ErrClosed) {
		t.Fatalf("closed borrow: %v %v", b, err)
	}
}

func TestSourceAuthorityCloseOnly(t *testing.T) {
	s := mustCreate(t, storeDir(t), testIdentity(1))
	before := fileBytes(t, s.dir)
	one, two := sourceBorrow(t, s), sourceBorrow(t, s)
	copied := *one
	ask, finish := dependentChild(t, s)
	if got := ask(); got != "busy\n" {
		t.Fatalf("borrowed writer exclusion: %q", got)
	}
	dir, id, physical, err := one.BindingV1()
	must(t, err)
	if dir != s.dir || id != testIdentity(1) || physical == (filelock.IdentityV1{}) {
		t.Fatalf("binding: %q %+v", dir, id)
	}
	tx := mustBegin(t, s)
	if err := s.Close(); any(err) != any(ErrBusy) || s.tx != tx || tx.done || s.closed || s.lock == nil {
		t.Fatalf("borrowed close changed transaction: %v", err)
	}
	wantErr(t, nil)(tx.Abort())
	wantErr(t, nil)(s.Recover())
	one.ReleaseV1()
	one.ReleaseV1()
	if dir, id, physical, err := copied.BindingV1(); dir != "" || id != (Identity{}) || physical != (filelock.IdentityV1{}) || !sameDependentValue(err, ErrClosed) {
		t.Fatalf("copied expired binding: %q %+v %v", dir, id, err)
	}
	copied.ReleaseV1()
	if err := s.Close(); any(err) != any(ErrBusy) || s.sourceBorrows != 1 {
		t.Fatalf("double release affected sibling: %v", err)
	}
	if got := ask(); got != "busy\n" {
		t.Fatalf("sibling writer exclusion: %q", got)
	}
	if !bytes.Equal(before, fileBytes(t, s.dir)) {
		t.Fatal("borrow changed control bytes")
	}
	two.ReleaseV1()
	must(t, s.Close())
	if got := ask(); got != "open\n" {
		t.Fatalf("released writer exclusion: %q", got)
	}
	for _, b := range []*SourceAuthorityBorrowV1{nil, {}, one, two} {
		dir, id, physical, err := b.BindingV1()
		if dir != "" || id != (Identity{}) || physical != (filelock.IdentityV1{}) || !sameDependentValue(err, ErrClosed) {
			t.Fatalf("expired binding: %q %+v %v", dir, id, err)
		}
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
			if b != nil || any(borrowErr) != any(ErrClosed) {
				t.Fatalf("close winner: %v %v", b, borrowErr)
			}
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
	if _, _, _, err := b.BindingV1(); !sameDependentValue(err, ErrRefused) {
		t.Fatalf("replaced directory binding: %v", err)
	}
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
		if os.SameFile(a, b) {
			t.Fatal("clean and opened policy directories have the same inode")
		}
	}
	checkMismatch()
	s, err := Create(raw, id, NewInstallationProof{Identity: id})
	if s != nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("aliased create: %v/%v", s, err)
	}
	must(t, mustCreate(t, clean, id).Close())
	must(t, mustCreate(t, held, id).Close())
	checkMismatch()
	x, y := fileBytes(t, clean), fileBytes(t, held)
	s, err = Open(raw, id)
	if s != nil || !errors.Is(err, ErrRefused) || !bytes.Equal(x, fileBytes(t, clean)) || !bytes.Equal(y, fileBytes(t, held)) {
		t.Fatalf("aliased open changed or qualified policy: %v/%v", s, err)
	}
	must(t, mustOpen(t, held, id).Close())
	must(t, os.Chmod(right, 0o100))
	t.Cleanup(func() { _ = os.Chmod(right, 0o700) })
	if _, err := os.ReadDir(right); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("search-only parent read: %v", err)
	}
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
	if err := s.Close(); any(err) != any(ErrBusy) || s.pending != pending || s.pending.handle != handle || s.closed {
		t.Fatalf("borrowed close changed pending owner: %v", err)
	}
	if dir, id, _, err := b.BindingV1(); err != nil || dir != s.dir || id != testIdentity(1) {
		t.Fatalf("source lifetime after transaction: %q/%v/%v", dir, id, err)
	}
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
	if b, err := s.BorrowSourceAuthorityV1(); b != nil || any(err) != any(ErrBusy) || errors.Is(err, ErrUnresolved) {
		t.Fatalf("crossing borrow: %v/%v", b, err)
	}
	finish()
	s.fault = nil
	sourceBorrow(t, s).ReleaseV1()
	must(t, s.Close())
}
