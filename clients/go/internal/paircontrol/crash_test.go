package paircontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

type faultAt struct {
	event string
	nth int
	err error
	after bool
}

type observedFS struct {
	dir string
	faults []faultAt
	counts map[string]int
	events []string
	files map[*os.File]int
	releases int
	partial bool
	zero bool
	block string
	entered, resume chan struct{}
}

func (o *observedFS) event(name string) error {
	o.events = append(o.events, name)
	o.counts[name]++
	if o.block == name {
		o.block = ""
		close(o.entered)
		<-o.resume
	}
	for _, f := range o.faults {
		if f.event == name && o.counts[name] == f.nth {
			return f.err
		}
	}
	return nil
}

func (o *observedFS) leaf(path string) string {
	if path == o.dir {
		return "dir"
	}
	return filepath.Base(path)
}

func (o *observedFS) count(name string) int { return o.counts[name] }

func (o *observedFS) resetCounts() {
	o.counts = map[string]int{}
	o.events = nil
}

func (o *observedFS) add(f faultAt) { o.faults = append(o.faults, f) }

func installFaults(t *testing.T, s *Store, faults ...faultAt) *observedFS {
	t.Helper()
	o := &observedFS{dir: s.dir, faults: faults, counts: map[string]int{}, files: map[*os.File]int{}}
	s.ops = fileOpsV1{
		open: func(path string, flags int, mode fs.FileMode) (*os.File, error) {
			if err := o.event("open:" + o.leaf(path)); err != nil {
				return nil, err
			}
			f, err := os.OpenFile(path, flags, mode)
			if f != nil {
				o.files[f] = 0
			}
			return f, err
		},
		write: func(f *os.File, b []byte) (int, error) {
			if err := o.event("write:" + o.leaf(f.Name())); err != nil {
				return 0, err
			}
			if o.zero {
				return 0, nil
			}
			if o.partial && len(b) > 1 {
				b = b[:1]
			}
			return f.Write(b)
		},
		sync: func(f *os.File) error {
			if err := o.event("sync:" + o.leaf(f.Name())); err != nil {
				return err
			}
			return f.Sync()
		},
		close: func(f *os.File) error {
			injected := o.event("close:" + o.leaf(f.Name()))
			o.files[f]++
			// Real Close is unconditional and occurs exactly once, even on a reported fault.
			return errors.Join(f.Close(), injected)
		},
		remove: func(path string) error {
			if err := o.event("remove:" + o.leaf(path)); err != nil {
				return err
			}
			return os.Remove(path)
		},
		rename: func(from, to string) error {
			if err := o.event("rename"); err != nil {
				return err
			}
			return os.Rename(from, to)
		},
		link: func(from, to string) error {
			if err := o.event("link"); err != nil {
				return err
			}
			return os.Link(from, to)
		},
		release: func(h *filelock.Handle) error {
			o.releases++
			injected := o.event("release")
			return errors.Join(h.Release(), injected)
		},
		ack: func() error { return o.event("ack") },
	}
	return o
}

func wantConsumed(t *testing.T, o *observedFS) {
	t.Helper()
	for f, n := range o.files {
		if n != 1 {
			t.Fatalf("file %s Close count %d", f.Name(), n)
		}
		if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("reported consumed file remains open")
		}
	}
}

func causeLeaves(err error) []error {
	if err == nil {
		return nil
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		var leaves []error
		for _, child := range many.Unwrap() {
			leaves = append(leaves, causeLeaves(child)...)
		}
		return leaves
	}
	return []error{err}
}

func wantCauses(t *testing.T, e *ErrorV1, want ...error) {
	t.Helper()
	if got := causeLeaves(e.Cause); !slices.Equal(got, want) {
		t.Fatalf("ordered original causes: got %#v want %#v", got, want)
	}
	for _, cause := range want {
		if !errors.Is(e, cause) {
			t.Fatal("original error interface identity lost")
		}
	}
}

type faultRow struct {
	name, event string
	nth int
	truth TruthV1
	code string
	latch, pending bool
}

func faultRows() []faultRow {
	return []faultRow{
		{"arming_create", "open:outer-control.pending", 1, 1, "precommit", false, false},
		{"arming_sync", "sync:outer-control.pending", 1, 1, "precommit", false, false},
		{"arming_close", "close:outer-control.pending", 1, 1, "precommit", true, true},
		{"arming_dirsync", "sync:dir", 1, 1, "precommit", false, false},
		{"arming_dirclose", "close:dir", 1, 1, "precommit", true, true},
		{"arming_dirsync_close", "sync:dir", 1, 1, "precommit", true, true},
		{"scratch_create", "open:outer-control.scratch", 1, 1, "precommit", false, false},
		{"scratch_write", "write:outer-control.scratch", 1, 1, "precommit", false, false},
		{"scratch_sync", "sync:outer-control.scratch", 1, 1, "precommit", false, false},
		{"scratch_close", "close:outer-control.scratch", 1, 1, "precommit", true, true},
		{"publication", "publish", 1, 1, "precommit", false, false},
		{"publication_dirsync", "sync:dir", 2, 3, "unresolved", true, true},
		{"publication_dirclose", "close:dir", 2, 2, "postcommit_new", true, true},
		{"pending_unlink", "remove:outer-control.pending", 1, 2, "postcommit_new", true, true},
		{"cleanup_dirsync", "sync:dir", 3, 2, "postcommit_new", true, false},
		{"cleanup_dirclose", "close:dir", 3, 2, "postcommit_new", true, false},
		{"acknowledgement", "ack", 1, 3, "unresolved", true, false},
	}
}

func checkBlockedNext(t *testing.T, s *Store, o *observedFS, original *ErrorV1, want ResultV1, old, next RecordV1) {
	t.Helper()
	n := len(o.events)
	observed, err := s.ObserveV1()
	e := wantLocal(t, ResultV1{}, err, "observe", "unresolved", ResultV1{})
	if e.Cause != original {
		t.Fatal("Observe replaced original ErrorV1 wrapper")
	}
	if want.Truth == 3 {
		if !reflect.DeepEqual(observed, RecordV1{}) {
			t.Fatal("UNKNOWN exposed a qualified Record")
		}
	} else {
		expected := old
		if want.Truth == 2 {
			expected = next
		}
		if !reflect.DeepEqual(observed, expected) {
			t.Fatal("known blocked observation lost exact image")
		}
	}
	if want.Truth != 3 || o.count("ack") == 0 {
		r, err := s.RecoverV1()
		e = wantLocal(t, r, err, "recover", "unresolved", want)
		if e.Cause != original {
			t.Fatal("Recover replaced original wrapper")
		}
		if len(o.events) != n {
			t.Fatal("known/poisoned Recover performed I/O")
		}
	}
	r, err := s.PersistIntentV1(context.Background(), 17, replacement(), nil)
	e = wantLocal(t, r, err, "persist_intent", "unresolved", want)
	if e.Cause != original || len(o.events) != n {
		t.Fatal("blocked mutator performed effects/lost wrapper")
	}
}

// checkAtomicFileFailure shares the physical assertions of only Create and PersistIntent.
func checkAtomicFileFailure(t *testing.T, row faultRow, creating, failRelease bool) {
	t.Helper()
	old, next := selected(), selected()
	i := replacement()
	next.Sequence, next.Intent = 18, &i
	var s *Store
	var dir string
	if creating {
		dir = directory(t)
		s = &Store{dir: dir}
		next = RecordV1{Identity: identity(), Selector: 1}
	} else {
		s, dir = existing(t, old)
	}
	event := row.event
	if event == "publish" {
		event = "rename"
		if creating {
			event = "link"
		}
	}
	primary, release := errors.New(row.name), errors.New("release")
	faults := []faultAt{{event, row.nth, primary, false}}
	causes := []error{primary}
	if row.name == "arming_dirsync_close" {
		closeCause, nth := errors.New("following-close"), 1
		if creating {
			nth++
		}
		faults = append(faults, faultAt{"close:dir", nth, closeCause, false})
		causes = append(causes, closeCause)
	}
	if failRelease {
		faults = append(faults, faultAt{"release", 1, release, false})
	}
	o := installFaults(t, s, faults...)
	var failure *ErrorV1
	var want ResultV1
	if creating {
		failed, err := startV1(dir, identity(), &NewInstallationProofV1{identity()}, s.ops)
		failure = wantNilStore(t, failed, err, "create", row.code)
	} else {
		result, err := s.PersistIntentV1(context.Background(), 17, i, nil)
		want = ResultV1{row.truth, map[TruthV1]uint64{1: 17, 2: 18, 3: 0}[row.truth], row.latch}
		failure = wantLocal(t, result, err, "persist_intent", row.code, want)
	}
	if failRelease {
		causes = append(causes, release)
	}
	wantCauses(t, failure, causes...)
	wantConsumed(t, o)
	if !creating && row.truth == 1 && !bytes.Equal(diskBytes(t, dir), fixtureBytes(old)) {
		t.Fatal("OLD preimage changed")
	}
	if creating && row.truth == 1 {
		if _, err := os.Lstat(filepath.Join(dir, "outer-control")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("precommit creation published control")
		}
	}
	if row.truth == 2 && !bytes.Equal(diskBytes(t, dir), fixtureBytes(next)) {
		t.Fatal("known NEW demoted or lost")
	}
	_, pendingErr := os.Lstat(filepath.Join(dir, "outer-control.pending"))
	if (pendingErr == nil) != row.pending {
		t.Fatal("pending disposition differs")
	}
	if !creating {
		if row.latch {
			checkBlockedNext(t, s, o, failure, want, old, next)
		} else {
			wantRecord(t, s, old)
			result, err := s.RecoverV1()
			require(t, err)
			if result != (ResultV1{}) {
				t.Fatal("clean OLD retained an attempt")
			}
			o.faults = nil
			result, err = s.PersistIntentV1(context.Background(), 17, i, nil)
			require(t, err)
			if result != (ResultV1{2, 18, false}) {
				t.Fatal("clean OLD disallowed legal next write")
			}
		}
		require(t, s.CloseV1())
	}
	if o.releases != 1 {
		t.Fatal("operation did not consume acquired flock exactly once")
	}
	fresh, err := OpenV1(dir, identity())
	if row.pending {
		wantNilStore(t, fresh, err, "open", "unresolved")
	} else if creating && row.truth == 1 {
		wantNilStore(t, fresh, err, "open", "missing")
	} else {
		require(t, err)
		require(t, fresh.CloseV1())
	}
	fresh, err = CreateV1(dir, identity(), NewInstallationProofV1{identity()})
	if creating && row.truth == 1 && !row.pending {
		require(t, err)
		require(t, fresh.CloseV1())
	} else {
		wantNilStore(t, fresh, err, "create", "refused")
	}
}

func TestActualFileFailureMatrix(t *testing.T) {
	for _, row := range faultRows() {
		t.Run(row.name, func(t *testing.T) {
			checkAtomicFileFailure(t, row, false, false)
		})
	}
}

func TestCleanupCauseProducts(t *testing.T) {
	for _, secondaryEvent := range []string{"close:outer-control.scratch", "remove:outer-control.scratch", "remove:outer-control.pending", "sync:dir", "close:dir"} {
		t.Run(secondaryEvent, func(t *testing.T) {
			s, dir := existing(t, selected())
			primary, secondary := errors.New("main-sync"), errors.New("cleanup")
			nth := 1
			if strings.HasSuffix(secondaryEvent, ":dir") {
				nth = 2
			}
			o := installFaults(t, s,
				faultAt{"sync:outer-control.scratch", 1, primary, false},
				faultAt{secondaryEvent, nth, secondary, false})
			r, err := s.PersistIntentV1(context.Background(), 17, replacement(), nil)
			e := wantLocal(t, r, err, "persist_intent", "precommit", ResultV1{1, 17, true})
			wantCauses(t, e, primary, secondary)
			wantConsumed(t, o)
			checkBlockedNext(t, s, o, e, r, selected(), selected())
			if !bytes.Equal(diskBytes(t, dir), fixtureBytes(selected())) {
				t.Fatal("cleanup error changed preimage")
			}
		})
	}
}

func TestConstructorCleanupCauseProducts(t *testing.T) {
	for _, event := range []string{"close:outer-control.scratch", "remove:outer-control.scratch", "remove:outer-control.pending", "sync:dir", "close:dir"} {
		t.Run(event, func(t *testing.T) {
			dir := directory(t)
			holder := &Store{dir: dir}
			main, cleanup, release := errors.New("scratch-sync"), errors.New("cleanup"), errors.New("release")
			nth := 1
			if event == "sync:dir" {
				nth = 2
			}
			if event == "close:dir" {
				nth = 3
			}
			o := installFaults(t, holder, faultAt{"sync:outer-control.scratch", 1, main, false}, faultAt{event, nth, cleanup, false}, faultAt{"release", 1, release, false})
			s, err := startV1(dir, identity(), &NewInstallationProofV1{identity()}, holder.ops)
			e := wantNilStore(t, s, err, "create", "precommit")
			wantCauses(t, e, main, cleanup, release)
			wantConsumed(t, o)
			if o.releases != 1 {
				t.Fatal("failed constructor did not consume flock exactly once")
			}
			if _, err := os.Stat(filepath.Join(dir, "outer-control")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("failed creation published control")
			}
			fresh, err := OpenV1(dir, identity())
			if event == "sync:dir" || event == "close:dir" {
				wantNilStore(t, fresh, err, "open", "missing")
			} else {
				wantNilStore(t, fresh, err, "open", "unresolved")
			}
		})
	}
}

func TestOpenFailureResourceMatrix(t *testing.T) {
	for _, event := range []string{"open:outer-control", "sync:outer-control", "open:dir", "sync:dir", "close:dir", "close:outer-control"} {
		for _, failRelease := range []bool{false, true} {
			t.Run(event+fmt.Sprint(failRelease), func(t *testing.T) {
				dir, v := directory(t), selected()
				writeFixture(t, dir, fixtureBytes(v))
				holder := &Store{dir: dir}
				main, release := errors.New("qualification"), errors.New("release")
				faults := []faultAt{{event, 1, main, false}}
				if failRelease {
					faults = append(faults, faultAt{"release", 1, release, false})
				}
				o := installFaults(t, holder, faults...)
				s, err := startV1(dir, identity(), nil, holder.ops)
				e := wantNilStore(t, s, err, "open", "unreadable")
				if failRelease {
					wantCauses(t, e, main, release)
				} else {
					wantCauses(t, e, main)
				}
				wantConsumed(t, o)
				if o.releases != 1 || !bytes.Equal(diskBytes(t, dir), fixtureBytes(v)) {
					t.Fatal("failed Open changed owner/bytes")
				}
				fresh, err := OpenV1(dir, identity())
				require(t, err)
				wantRecord(t, fresh, v)
				require(t, fresh.CloseV1())
				fresh, err = CreateV1(dir, identity(), NewInstallationProofV1{identity()})
				wantNilStore(t, fresh, err, "create", "refused")
			})
		}
	}
}

func TestFullWriteAndRequiredOperationOrder(t *testing.T) {
	for _, zero := range []bool{false, true} {
		s, dir := existing(t, selected())
		o := installFaults(t, s)
		o.partial, o.zero = true, zero
		r, err := s.PersistIntentV1(context.Background(), 17, replacement(), nil)
		if zero {
			e := wantLocal(t, r, err, "persist_intent", "precommit", ResultV1{1, 17, false})
			wantCauses(t, e, io.ErrShortWrite)
			continue
		}
		require(t, err)
		v, i := selected(), replacement()
		v.Sequence, v.Intent = 18, &i
		if !bytes.Equal(diskBytes(t, dir), fixtureBytes(v)) {
			t.Fatal("partial writes were not retried completely")
		}
		wantOrder := []string{"sync:outer-control.pending", "close:outer-control.pending", "sync:dir", "sync:outer-control.scratch", "close:outer-control.scratch", "rename", "sync:dir", "remove:outer-control.pending", "sync:dir", "ack"}
		at := 0
		for _, event := range o.events {
			if event == "remove:outer-control" {
				t.Fatal("control unlinked before atomic replace")
			}
			if at < len(wantOrder) && event == wantOrder[at] {
				at++
			}
		}
		if at != len(wantOrder) {
			t.Fatalf("missing actual effect/order: %v", o.events)
		}
		wantConsumed(t, o)
	}
}

func TestCreateFaultMatrix(t *testing.T) {
	rows := faultRows()
	rows = append(rows,
		faultRow{"readback_open", "open:outer-control", 1, 2, "postcommit_new", true, true},
		faultRow{"readback_sync", "sync:outer-control", 1, 2, "postcommit_new", true, true},
		faultRow{"readback_dirsync", "sync:dir", 3, 2, "postcommit_new", true, true},
		faultRow{"readback_dirclose", "close:dir", 3, 2, "postcommit_new", true, true},
		faultRow{"readback_close", "close:outer-control", 1, 2, "postcommit_new", true, true},
		faultRow{"scratch_unlink", "remove:outer-control.scratch", 1, 2, "postcommit_new", true, true})
	for _, row := range rows {
		switch row.name {
		case "arming_dirclose":
			row.nth = 2
		case "publication_dirclose":
			row.nth = 3
		case "readback_dirclose":
			row.nth = 4
		case "cleanup_dirclose":
			row.nth = 5
		case "cleanup_dirsync":
			row.nth = 4
		}
		for _, failRelease := range []bool{false, true} {
			t.Run(row.name+map[bool]string{false: "", true: "_release"}[failRelease], func(t *testing.T) {
				checkAtomicFileFailure(t, row, true, failRelease)
			})
		}
	}
}

func TestCreationConflictAndReadbackMismatch(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		dir, holder := directory(t), &Store{}
		holder.dir = dir
		o := installFaults(t, holder)
		ops := holder.ops
		if mismatch {
			originalOpen := ops.open
			ops.open = func(path string, flags int, mode fs.FileMode) (*os.File, error) {
				if path == filepath.Join(dir, "outer-control") {
					writeFixture(t, dir, []byte{1})
				}
				return originalOpen(path, flags, mode)
			}
		} else {
			originalLink := ops.link
			ops.link = func(from, to string) error {
				require(t, os.WriteFile(to, []byte("unexpected-owner"), 0o600))
				return originalLink(from, to)
			}
		}
		s, err := startV1(dir, identity(), &NewInstallationProofV1{identity()}, ops)
		code := "integrity"
		if mismatch {
			code = "postcommit_new"
		}
		e := wantNilStore(t, s, err, "create", code)
		if mismatch {
			if e.Cause.Error() != "paircontrol: created image did not read back exactly" {
				t.Fatal("exact mismatch diagnostic lost")
			}
		} else {
			if !errors.Is(e, fs.ErrExist) || string(diskBytes(t, dir)) != "unexpected-owner" {
				t.Fatal("unexpected owner overwritten or wrong cause")
			}
		}
		if _, err := os.Stat(filepath.Join(dir, "outer-control.pending")); err != nil {
			t.Fatal("unexpected/mismatching control lost fail-closed sentinel")
		}
		wantConsumed(t, o)
		s, err = OpenV1(dir, identity())
		wantNilStore(t, s, err, "open", "unresolved")
	}
}

func TestActualProcessLockAndExit(t *testing.T) {
	if dir := os.Getenv("RUB1661_CHILD_DIR"); dir != "" {
		stage := os.Getenv("RUB1661_CHILD_STAGE")
		if stage == "contended" {
			s, err := OpenV1(dir, identity())
			wantNilStore(t, s, err, "open", "busy")
			return
		}
		s, err := OpenV1(dir, identity())
		require(t, err)
		o := installFaults(t, s)
		original := s.ops.sync
		s.ops.sync = func(f *os.File) error {
			err := original(f)
			event := "sync:" + o.leaf(f.Name())
			if err == nil && (stage == event || stage == "publication" && event == "sync:dir" && o.count(event) == 2 || stage == "cleanup" && event == "sync:dir" && o.count(event) == 3) {
				os.Exit(71)
			}
			return err
		}
		originalRename := s.ops.rename
		s.ops.rename = func(from, to string) error {
			err := originalRename(from, to)
			if err == nil && stage == "rename" {
				os.Exit(71)
			}
			return err
		}
		_, _ = s.PersistIntentV1(context.Background(), 17, replacement(), nil)
		t.Fatal("requested actual process exit point was not reached")
	}
	for _, stage := range []string{"contended", "sync:outer-control.pending", "sync:outer-control.scratch", "rename", "publication", "cleanup"} {
		t.Run(stage, func(t *testing.T) {
			s, dir := existing(t, selected())
			if stage != "contended" {
				require(t, s.CloseV1())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestActualProcessLockAndExit$")
			cmd.Env = append(os.Environ(), "RUB1661_CHILD_DIR="+dir, "RUB1661_CHILD_STAGE="+stage)
			out, err := cmd.CombinedOutput()
			if stage == "contended" {
				require(t, err)
				require(t, s.CloseV1())
				return
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 71 {
				t.Fatalf("child exit: %v %s", err, out)
			}
			fresh, err := OpenV1(dir, identity())
			if stage == "cleanup" {
				require(t, err)
				v, i := selected(), replacement()
				v.Sequence, v.Intent = 18, &i
				wantRecord(t, fresh, v)
				require(t, fresh.CloseV1())
			} else {
				wantNilStore(t, fresh, err, "open", "unresolved")
			}
			fresh, err = CreateV1(dir, identity(), NewInstallationProofV1{identity()})
			wantNilStore(t, fresh, err, "create", "refused")
		})
	}
}

func TestPublicationEIORetainsUnresolvedDisposition(t *testing.T) {
	for _, creating := range []bool{false, true} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("create=%t/after=%t", creating, after), func(t *testing.T) {
				dir := directory(t)
				s := &Store{dir: dir}
				if !creating {
					s, dir = existing(t, selected())
				}
				o := installFaults(t, s)
				cause := fmt.Errorf("publication: %w", syscall.EIO)
				remove := s.ops.remove
				var cleanupError error
				s.ops.remove = func(path string) error {
					err := remove(path)
					if err != nil {
						cleanupError = err
					}
					return err
				}
				publish := s.ops.rename
				if creating {
					publish = s.ops.link
				}
				wrapped := func(from, to string) error {
					if after {
						require(t, publish(from, to))
					}
					return cause
				}
				if creating {
					s.ops.link = wrapped
				} else {
					s.ops.rename = wrapped
				}
				if creating {
					failed, err := startV1(dir, identity(), &NewInstallationProofV1{identity()}, s.ops)
					e := wantNilStore(t, failed, err, "create", "unresolved")
					wantCauses(t, e, cause)
					if cleanupError != nil {
						t.Fatal("Link EIO row observed an unexpected cleanup failure")
					}
				} else {
					r, err := s.PersistIntentV1(context.Background(), 17, replacement(), nil)
					e := wantLocal(t, r, err, "persist_intent", "unresolved", ResultV1{3, 0, true})
					if after {
						var pathError *os.PathError
						if !errors.As(cleanupError, &pathError) || !errors.Is(cleanupError, fs.ErrNotExist) || pathError.Op != "remove" || pathError.Path != filepath.Join(dir, "outer-control.scratch") {
							t.Fatal("Rename removed scratch but its exact cleanup ENOENT was not retained")
						}
						wantCauses(t, e, cause, cleanupError)
					} else {
						wantCauses(t, e, cause)
						if cleanupError != nil {
							t.Fatal("before-effect EIO row observed an unexpected cleanup failure")
						}
					}
					checkBlockedNext(t, s, o, e, r, selected(), selected())
					require(t, s.CloseV1())
				}
				wantConsumed(t, o)
				if _, err := os.Stat(filepath.Join(dir, "outer-control.pending")); err != nil {
					t.Fatal("EIO lost prearmed pending")
				}
				if after {
					want := RecordV1{Identity: identity(), Selector: 1}
					if !creating {
						want, want.Sequence = selected(), 18
						i := replacement()
						want.Intent = &i
					}
					if !bytes.Equal(diskBytes(t, dir), fixtureBytes(want)) {
						t.Fatal("real published bytes not observed")
					}
				}
				fresh, err := OpenV1(dir, identity())
				wantNilStore(t, fresh, err, "open", "unresolved")
				fresh, err = CreateV1(dir, identity(), NewInstallationProofV1{identity()})
				wantNilStore(t, fresh, err, "create", "refused")
			})
		}
	}
}

func TestCloseConsumesReportedReleaseFailureOnce(t *testing.T) {
	s, dir := existing(t, selected())
	before := diskBytes(t, dir)
	cause := errors.New("reported release failure")
	o := installFaults(t, s, faultAt{"release", 1, cause, false})
	err := s.CloseV1()
	e := wantLocal(t, ResultV1{}, err, "close", "unresolved", ResultV1{})
	wantCauses(t, e, cause)
	require(t, s.CloseV1())
	if o.releases != 1 || !bytes.Equal(before, diskBytes(t, dir)) {
		t.Fatal("Close retried consumed flock or changed control")
	}
	v, err := s.ObserveV1()
	wantLocal(t, ResultV1{}, err, "observe", "closed", ResultV1{})
	if !reflect.DeepEqual(v, RecordV1{}) {
		t.Fatal("closed owner returned a record")
	}
	r, err := s.RecoverV1()
	wantLocal(t, r, err, "recover", "closed", ResultV1{})
	r, err = s.PersistIntentV1(context.Background(), 17, replacement(), nil)
	wantLocal(t, r, err, "persist_intent", "closed", ResultV1{})
	// The adapter reports failure only after actual Release; fresh ownership is
	// proved by this actual acquisition, never inferred from consumed Go state.
	fresh, err := OpenV1(dir, identity())
	require(t, err)
	wantRecord(t, fresh, selected())
	require(t, fresh.CloseV1())
}

