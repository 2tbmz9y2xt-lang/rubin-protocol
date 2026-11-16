package policycontrol

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

// dependentCause keeps a distinct application error and its original cause.
type dependentCause struct{ cause error }

func (e *dependentCause) Error() string { return "dependent application error" }
func (e *dependentCause) Unwrap() error { return e.cause }

// sameDependentValue preserves exact interface identity; errors.Is would accept replacement wrappers.
func sameDependentValue(got, want any) bool {
	return reflect.ValueOf(got).Equal(reflect.ValueOf(want))
}

// awaitDependent bounds test synchronization, not the application's callback.
func awaitDependent(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("dependent operation did not finish; callback mutex or slot was retained")
	}
}

// dependentBoth checks the same operation directly and from a joined goroutine.
func dependentBoth(t *testing.T, check func()) {
	t.Helper()
	check()
	done := make(chan struct{})
	go func() { defer close(done); check() }()
	awaitDependent(t, done)
}

// refuseDependent checks both callback shapes without fabricating Store state.
func refuseDependent(t *testing.T, s *Store, want error, unresolved bool) {
	t.Helper()
	before := fileBytes(t, s.dir)
	calls := 0
	for _, use := range []func(View) error{nil, func(View) error { calls++; return nil }} {
		err := s.WithDependentViewV1(use)
		if unresolved {
			if !errors.Is(err, ErrBusy) || !errors.Is(err, ErrUnresolved) {
				t.Fatalf("UNKNOWN admission: %v", err)
			}
		} else if !sameDependentValue(err, want) || errors.Is(err, ErrUnresolved) {
			t.Fatalf("admission error %v, want exact %v", err, want)
		}
	}
	if calls != 0 || !bytes.Equal(fileBytes(t, s.dir), before) {
		t.Fatalf("refused admission invoked %d callbacks or changed P", calls)
	}
}

// A1/X1: nilness follows real owner/closed admission; idle use has no durable effect.
func TestDependentViewAdmission(t *testing.T) {
	id, dir := testIdentity(1), storeDir(t)
	s := mustCreate(t, dir, id)
	before := fileBytes(t, dir)
	if err := s.WithDependentViewV1(nil); !sameDependentValue(err, ErrRefused) {
		t.Fatalf("idle nil: %v", err)
	}
	tx := mustBegin(t, s)
	refuseDependent(t, s, ErrBusy, false)
	r, err := tx.Abort()
	wantResult(t, r, OLD, 0)
	must(t, err)
	calls := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		must(t, s.WithDependentViewV1(func(v View) error {
			calls++
			if !reflect.DeepEqual(v, View{Identity: id}) {
				t.Errorf("initial dependent view: %+v", v)
			}
			refuseDependent(t, s, ErrBusy, false)
			return nil
		}))
	}()
	awaitDependent(t, done)
	if calls != 1 || !bytes.Equal(fileBytes(t, dir), before) {
		t.Fatal("idle callback count or read-only P law")
	}
	must(t, s.Close())
	refuseDependent(t, s, ErrClosed, false)
	s = mustOpen(t, dir, id)
	must(t, s.WithDependentViewV1(func(v View) error {
		if !reflect.DeepEqual(v, View{Identity: id}) {
			t.Fatal("Open changed initial P")
		}
		return nil
	}))
}

// dependentOtherStore checks actual directory-lock contention for both constructors.
func dependentOtherStore(t *testing.T, s *Store) {
	t.Helper()
	id := testIdentity(1)
	for _, open := range []func() (*Store, error){
		func() (*Store, error) { return Open(s.dir, id) },
		func() (*Store, error) { return Create(s.dir, id, NewInstallationProof{Identity: id}) },
	} {
		if other, err := open(); other != nil || !errors.Is(err, ErrBusy) {
			t.Fatalf("live-slot constructor contention: %v %v", other, err)
		}
	}
}

// dependentOperations owns exact live-slot tuples and reentrant reads.
func dependentOperations(t *testing.T, s *Store, want View) {
	t.Helper()
	if tx, err := s.Begin(); tx != nil || !sameDependentValue(err, ErrBusy) {
		t.Fatalf("live-slot Begin: %v %v", tx, err)
	}
	if r, err := s.PersistLatch(stableProof(&Guard{})); r != (Result{}) || !sameDependentValue(err, ErrBusy) {
		t.Fatalf("live-slot PersistLatch: %+v %v", r, err)
	}
	if r, err := s.Recover(); r != (Result{}) || !sameDependentValue(err, ErrBusy) {
		t.Fatalf("live-slot Recover without pending: %+v %v", r, err)
	}
	prior := s.Latch()
	if err := s.Close(); !sameDependentValue(err, ErrBusy) || s.Latch() != prior {
		t.Fatalf("live-slot Close: %v, latch %+v -> %+v", err, prior, s.Latch())
	}
	refuseDependent(t, s, ErrBusy, false)
	dependentOtherStore(t, s)
	if g := s.Gate(); g != (Gate{}) {
		t.Fatalf("live-slot gate: %+v", g)
	}
	if got := mustView(t, s); !reflect.DeepEqual(got, want) {
		t.Fatalf("live-slot View: %+v, want %+v", got, want)
	}
	if rows, err := s.Membership(); err != nil || len(rows) != 0 {
		t.Fatalf("live-slot Membership: %+v %v", rows, err)
	}
	s.RequestLatch()
	s.RequestLatch()
	wantLatch(t, s, LatchStatus{Requested: true})
}

// dependentExit preserves application outcomes including non-returning Go exits.
type dependentExit struct {
	returned bool
	err      error
	panicked any
}

// runDependentOutcome exercises final use in callback defers before slot cleanup.
func runDependentOutcome(t *testing.T, s *Store, outcome func() error) dependentExit {
	t.Helper()
	want := View{Identity: testIdentity(1)}
	done := make(chan struct{})
	var got dependentExit
	finalUses, ioCalls := 0, 0
	s.fault = func(stage) error { ioCalls++; return errors.New("unexpected dependent I/O") }
	go func() {
		defer close(done)
		defer func() { got.panicked = recover() }()
		got.err = s.WithDependentViewV1(func(v View) error {
			defer func() { dependentOperations(t, s, want); finalUses++ }()
			dependentBoth(t, func() { dependentOperations(t, s, want) })
			if !reflect.DeepEqual(v, want) {
				t.Errorf("effect used wrong P: %+v", v)
			}
			return outcome()
		})
		got.returned = true
	}()
	awaitDependent(t, done)
	s.fault = nil
	if finalUses != 1 || ioCalls != 0 {
		t.Fatalf("callback final uses %d, forbidden P I/O %d", finalUses, ioCalls)
	}
	return got
}

// dependentNextOwner proves cleanup, OLD abort and unchanged reopened durable P.
func dependentNextOwner(t *testing.T, s *Store, before []byte) {
	t.Helper()
	wantLatch(t, s, LatchStatus{Requested: true})
	if !bytes.Equal(fileBytes(t, s.dir), before) || !reflect.DeepEqual(mustView(t, s), View{Identity: testIdentity(1)}) {
		t.Fatal("dependent exit changed P sequence, receipt or bytes")
	}
	tx := mustBegin(t, s)
	r, err := tx.Abort()
	wantResult(t, r, OLD, 0)
	must(t, err)
	must(t, s.Close())
	reopened := mustOpen(t, s.dir, testIdentity(1))
	if !bytes.Equal(fileBytes(t, s.dir), before) || !reflect.DeepEqual(mustView(t, reopened), View{Identity: testIdentity(1)}) {
		t.Fatal("dependent exit did not reopen identical P")
	}
}

// A4/H3: every application outcome retains its identity and retires after defers.
func TestDependentViewOutcomes(t *testing.T) {
	sentinel := errors.New("application sentinel")
	wrapped := fmt.Errorf("wrapped application: %w", sentinel)
	caused := &dependentCause{cause: sentinel}
	var typedNil *dependentCause
	for _, tc := range []struct {
		name string
		err  error
	}{{"nil", nil}, {"direct", sentinel}, {"wrapped", wrapped}, {"own cause", caused}, {"typed nil", typedNil}} {
		t.Run(tc.name, func(t *testing.T) {
			s := mustCreate(t, storeDir(t), testIdentity(1))
			s.RequestLatch()
			before := fileBytes(t, s.dir)
			got := runDependentOutcome(t, s, func() error { return tc.err })
			if !got.returned || !sameDependentValue(got.err, tc.err) || got.panicked != nil {
				t.Fatalf("application outcome changed: %+v", got)
			}
			dependentNextOwner(t, s, before)
		})
	}
	for _, tc := range []struct {
		name       string
		panicValue any
	}{{"panic", sentinel}, {"panic nil", nil}, {"Goexit", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			s := mustCreate(t, storeDir(t), testIdentity(1))
			s.RequestLatch()
			before := fileBytes(t, s.dir)
			got := runDependentOutcome(t, s, func() error {
				switch tc.name {
				case "panic", "panic nil":
					panic(tc.panicValue)
				default:
					runtime.Goexit()
				}
				return nil
			})
			checkDependentUnwind(t, tc.name, got, sentinel)
			dependentNextOwner(t, s, before)
		})
	}
}

// checkDependentUnwind distinguishes original panic identity, nil panic and Goexit.
func checkDependentUnwind(t *testing.T, name string, got dependentExit, sentinel error) {
	t.Helper()
	if got.returned || got.err != nil {
		t.Fatalf("%s fabricated return: %+v", name, got)
	}
	switch name {
	case "panic":
		if !sameDependentValue(got.panicked, sentinel) {
			t.Fatalf("panic identity changed: %v", got.panicked)
		}
	case "panic nil":
		if _, ok := got.panicked.(*runtime.PanicNilError); !ok {
			t.Fatalf("panic(nil) suppressed or changed: %T", got.panicked)
		}
	default:
		if got.panicked != nil {
			t.Fatalf("Goexit changed into panic: %v", got.panicked)
		}
	}
}

// dependentPopulated commits OBSERVED and INTENT with a retained original epoch.
func dependentPopulated(t *testing.T) *Store {
	t.Helper()
	s := mustCreate(t, storeDir(t), testIdentity(1))
	mustControl(t, s, observe(diag(5, 321, "diagnosis")))
	must(t, s.WithDependentViewV1(func(v View) error {
		want := &Incident{Diagnosis: diag(5, 321, "diagnosis"), State: StateObserved}
		if v.Sequence != 1 || v.ControlSequence != 1 || v.HasAttempt || v.InitialSyncCompleted || !reflect.DeepEqual(v.Incident, want) {
			t.Fatalf("OBSERVED dependent shape: %+v", v)
		}
		return nil
	}))
	tx := mustBegin(t, s)
	tx.RetainOwner(Owner{Kind: OwnerH1, Epoch: 1, Intent: []byte("original-owner")})
	tx.Operation(ClassReconciliationBatch, 9)
	tx.Batch(7, 19)
	must(t, tx.ConsumeIntent(admission("destination")))
	put(t, tx, KindAudit, "member-key", "member-payload")
	mustCommit(t, tx, NEW, 2)
	return s
}

// wantDependentPopulated pins independently specified nondefault committed fields.
func wantDependentPopulated(t *testing.T, v View) {
	t.Helper()
	if v.Identity != testIdentity(1) || v.Sequence != 2 || v.ControlSequence != 2 || v.InitialSyncCompleted || !v.HasAttempt {
		t.Fatalf("populated identity/scalars: %+v", v)
	}
	r := v.Receipt
	owner := Owner{Kind: OwnerH1, Epoch: 1, Intent: []byte("original-owner")}
	if r == nil || r.Predecessor != 1 || r.Successor != 2 || r.Class != ClassReconciliationBatch || r.Ordinal != 9 ||
		!reflect.DeepEqual(r.Owner, owner) || !reflect.DeepEqual(r.Cursors, &Cursors{Before: 7, After: 19}) {
		t.Fatalf("populated receipt: %+v", r)
	}
	want := &Incident{
		Diagnosis: Diagnosis{Height: 321, Hash: fill32(5), Error: []byte("diagnosis"), Source: []byte("own-current-replay"), Trigger: []byte("L/T")},
		State:     StateIntent, Attempted: true, Admission: &Admission{Old: []byte("OLD"), Destination: []byte("destination"), Source: SourceGenesisReplay, Profile: ProfileV1, Ownership: []byte("h1-owner")},
	}
	if !reflect.DeepEqual(v.Incident, want) {
		t.Fatalf("populated incident: %+v", v.Incident)
	}
}

// mutateDependentCopy changes every scalar and nested mutable View component.
func mutateDependentCopy(v *View) {
	v.Identity.InstallationID[0] ^= 255
	v.Identity.ChainID[0] ^= 255
	v.Identity.GenesisHash[0] ^= 255
	v.Identity.Profile, v.Sequence, v.ControlSequence = 99, 99, 99
	v.InitialSyncCompleted, v.HasAttempt = true, false
	v.Receipt.Predecessor, v.Receipt.Successor = 99, 99
	v.Receipt.Operation[0] ^= 255
	v.Receipt.Owner.Kind, v.Receipt.Owner.Epoch, v.Receipt.Owner.Intent[0] = 99, 99, 'X'
	v.Receipt.Class, v.Receipt.Ordinal = 99, 99
	v.Receipt.Cursors.Before, v.Receipt.Cursors.After = 99, 99
	v.Incident.Diagnosis.Height, v.Incident.Diagnosis.Hash[0] = 99, 99
	v.Incident.Diagnosis.Error[0], v.Incident.Diagnosis.Source[0], v.Incident.Diagnosis.Trigger[0] = 'X', 'X', 'X'
	v.Incident.State, v.Incident.Attempted = 99, false
	a := v.Incident.Admission
	a.Old[0], a.Destination[0], a.Ownership[0], a.Source, a.Profile = 'X', 'X', 'X', 99, 99
}

// wantDependentMembership checks independent literals then changes the returned copy.
func wantDependentMembership(t *testing.T, s *Store) {
	t.Helper()
	rows, err := s.Membership()
	must(t, err)
	want := []Row{{Kind: KindAudit, Key: []byte("member-key"), Sequence: 2, Payload: []byte("member-payload")}}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("dependent membership: %+v", rows)
	}
	rows[0].Key[0], rows[0].Payload[0], rows[0].Kind, rows[0].Sequence = 'X', 'X', 99, 99
}

// A2/A5: every nested mutable field is detached in callback, ordinary and retained copies.
func TestDependentViewCopyAndSuccessor(t *testing.T) {
	s := dependentPopulated(t)
	before := fileBytes(t, s.dir)
	var retained View
	must(t, s.WithDependentViewV1(func(v View) error {
		wantDependentPopulated(t, v)
		ordinary := mustView(t, s)
		mutateDependentCopy(&v)
		wantDependentPopulated(t, ordinary)
		mutateDependentCopy(&ordinary)
		wantDependentPopulated(t, mustView(t, s))
		wantDependentMembership(t, s)
		wantDependentMembership(t, s)
		retained = mustView(t, s)
		return nil
	}))
	mutateDependentCopy(&retained)
	wantDependentPopulated(t, mustView(t, s))
	wantDependentMembership(t, s)
	if !bytes.Equal(fileBytes(t, s.dir), before) {
		t.Fatal("copy mutation changed durable P")
	}
	mustCommit(t, controlTx(t, s, "successor"), NEW, 3)
	must(t, s.WithDependentViewV1(func(v View) error {
		if v.Sequence != 3 || v.Receipt.Predecessor != 2 || v.Receipt.Successor != 3 || v.Receipt.Owner.Epoch != 3 || v.ControlSequence != 2 {
			t.Fatalf("successor callback used saved predecessor: %+v", v)
		}
		return nil
	}))
}

func testIdentity(b byte) Identity {
	return Identity{InstallationID: fill32(b), ChainID: fill32(b + 1), GenesisHash: fill32(b + 2), Profile: ProfileV1}
}

func storeDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "policy")
	must(t, os.Mkdir(dir, 0o700))
	must(t, os.Chmod(dir, 0o700))
	return dir
}

func mustCreate(t *testing.T, dir string, id Identity) *Store {
	t.Helper()
	s, err := Create(dir, id, NewInstallationProof{Identity: id})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustOpen(t *testing.T, dir string, id Identity) *Store {
	t.Helper()
	s, err := Open(dir, id)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	must(t, err)
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func fileBytes(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, controlFile))
	must(t, err)
	return b
}

func mustView(t *testing.T, s *Store) View {
	t.Helper()
	v, err := s.View()
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	return v
}

// A1: positive creation yields exactly the initial state and reads back.
func TestCreateNewInstallation(t *testing.T) {
	dir, id := storeDir(t), testIdentity(1)
	s := mustCreate(t, dir, id)
	want := View{Identity: id}
	if v := mustView(t, s); !reflect.DeepEqual(v, want) {
		t.Fatalf("view %+v, want %+v", v, want)
	}
	if names := dirNames(t, dir); !reflect.DeepEqual(names, []string{controlFile}) {
		t.Fatalf("directory holds %v", names)
	}
	if info, err := os.Stat(filepath.Join(dir, controlFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("P mode %v err %v", info, err)
	}
	img, _ := initialImage()
	if got := fileBytes(t, dir); !bytes.Equal(got[8+96:], img[8+96:]) {
		t.Fatal("initial image differs from the independent initial shape")
	}
	must(t, s.Close())
	if v := mustView(t, mustOpen(t, dir, id)); !reflect.DeepEqual(v, want) {
		t.Fatalf("reopened view %+v", v)
	}
}

// A1, X14: Create refuses without positive proof or directory and creates nothing.
func TestCreateRefusesWithoutProofOrDirectory(t *testing.T) {
	id := testIdentity(1)
	other := testIdentity(9)
	for name, proof := range map[string]NewInstallationProof{"zero proof": {}, "other identity": {Identity: other}} {
		dir := storeDir(t)
		if s, err := Create(dir, id, proof); s != nil || !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: Create err=%v", name, err)
		}
		if names := dirNames(t, dir); len(names) != 0 {
			t.Fatalf("%s: created %v", name, names)
		}
	}
	wantErr(t, ErrRefused)(Create(storeDir(t), Identity{}, NewInstallationProof{}))
	absent := filepath.Join(t.TempDir(), "absent")
	if s, err := Create(absent, id, NewInstallationProof{Identity: id}); s != nil || !errors.Is(err, ErrUnreadable) {
		t.Fatalf("absent directory: %v", err)
	}
	if _, err := os.Lstat(absent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Create made the directory: %v", err)
	}
}

// X1: missing P without positive proof is never fresh; nothing is created.
func TestOpenMissingControl(t *testing.T) {
	id := testIdentity(1)
	absent := filepath.Join(t.TempDir(), "absent")
	if s, err := Open(absent, id); s != nil || !errors.Is(err, ErrMissingControl) {
		t.Fatalf("absent directory: %v", err)
	}
	if _, err := os.Lstat(absent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Open made the directory: %v", err)
	}
	dir := storeDir(t)
	if s, err := Open(dir, id); s != nil || !errors.Is(err, ErrMissingControl) {
		t.Fatalf("empty directory: %v", err)
	}
	if names := dirNames(t, dir); len(names) != 0 {
		t.Fatalf("Open created %v", names)
	}
	if s, err := Create(dir, id, NewInstallationProof{Identity: id}); err != nil {
		t.Fatalf("lock was not released after missing control: %v", err)
	} else {
		_ = s.Close()
	}
}

// X2, H4: malformed, unreadable or mismatched P is an integrity error and is never reset, recreated or adopted; Create over an existing store refuses.
func TestOpenRejectsMalformedOrMismatchedControl(t *testing.T) {
	id := testIdentity(1)
	dir := storeDir(t)
	must(t, mustCreate(t, dir, id).Close())
	good := fileBytes(t, dir)
	if s, err := Create(dir, id, NewInstallationProof{Identity: id}); s != nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("Create over existing store: %v", err)
	}
	foreignDir := storeDir(t)
	for _, other := range []Identity{testIdentity(7), func() Identity { o := id; o.ChainID = fill32(0x77); return o }()} {
		must(t, mustCreate(t, foreignDir, other).Close())
		foreign := fileBytes(t, foreignDir)
		_ = os.Remove(filepath.Join(foreignDir, controlFile))
		must(t, os.WriteFile(filepath.Join(dir, controlFile), foreign, 0o600))
		if s, err := Open(dir, id); s != nil || !errors.Is(err, ErrIdentityMismatch) || !errors.Is(err, ErrIntegrity) {
			t.Fatalf("foreign identity adopted: %v", err)
		}
		if !bytes.Equal(fileBytes(t, dir), foreign) {
			t.Fatal("mismatched P was rewritten")
		}
	}
	profile := bytes.Clone(good)
	profile[8+96] = 2
	for name, img := range map[string][]byte{"truncated": good[:len(good)-1], "trailing": append(bytes.Clone(good), 0), "profile": profile, "empty": {}} {
		must(t, os.WriteFile(filepath.Join(dir, controlFile), img, 0o600))
		if s, err := Open(dir, id); s != nil || !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s: Open err=%v", name, err)
		}
		if !bytes.Equal(fileBytes(t, dir), img) || !reflect.DeepEqual(dirNames(t, dir), []string{controlFile}) {
			t.Fatalf("%s: malformed P was reset or recreated", name)
		}
	}
	wantErr(t, ErrRefused)(Open(dir, Identity{}))
}

// X14, X4: the lock result decides before any read; nothing is created and no invalid result is treated as unlocked or fresh.
func TestLockAndPathResults(t *testing.T) {
	id := testIdentity(1)
	base := t.TempDir()
	regular := filepath.Join(base, "regular")
	must(t, os.WriteFile(regular, nil, 0o700))
	wide := filepath.Join(base, "wide")
	must(t, os.Mkdir(wide, 0o700))
	must(t, os.Chmod(wide, 0o755))
	target := storeDir(t)
	link := filepath.Join(base, "link")
	must(t, os.Symlink(target, link))
	for name, path := range map[string]string{"regular": regular, "mode 0755": wide, "symlink": link} {
		if s, err := Open(path, id); s != nil || !errors.Is(err, ErrUnreadable) {
			t.Fatalf("Open %s: %v", name, err)
		}
		if s, err := Create(path, id, NewInstallationProof{Identity: id}); s != nil || !errors.Is(err, ErrUnreadable) {
			t.Fatalf("Create %s: %v", name, err)
		}
	}
	if names := dirNames(t, wide); len(names) != 0 {
		t.Fatalf("created %v under a refused directory", names)
	}
	if names := dirNames(t, target); len(names) != 0 {
		t.Fatalf("created %v through a symlink", names)
	}
	for name, res := range map[string]filelock.Result{"unsupported host": filelock.ResultUnsupportedHost, "invalid": filelock.ResultInvalidOrUnopenable, "empty": ""} {
		h := hooks{acquire: func(string) (*filelock.Handle, filelock.Result, error) {
			if res == "" {
				return nil, "", nil
			}
			return nil, res, errors.New("injected")
		}}
		dir := storeDir(t)
		if s, err := start(dir, id, &NewInstallationProof{Identity: id}, h); s != nil || !errors.Is(err, ErrUnreadable) {
			t.Fatalf("create %s: %v", name, err)
		}
		if s, err := start(dir, id, nil, h); s != nil || !errors.Is(err, ErrUnreadable) {
			t.Fatalf("open %s: %v", name, err)
		}
		if names := dirNames(t, dir); len(names) != 0 {
			t.Fatalf("%s: created %v", name, names)
		}
	}
	dir := storeDir(t)
	mustCreate(t, dir, id)
	if s, err := Open(dir, id); s != nil || !errors.Is(err, ErrBusy) {
		t.Fatalf("second Open in process: %v", err)
	}
	fifoDir := storeDir(t)
	must(t, syscall.Mkfifo(filepath.Join(fifoDir, controlFile), 0o600))
	// A FIFO P refuses within a bounded deadline (a liveness bound only), first without a writer and then with a live writer that writes nothing.
	for _, live := range []bool{false, true} {
		if live {
			writer, err := os.OpenFile(filepath.Join(fifoDir, controlFile), os.O_RDWR, 0)
			must(t, err)
			t.Cleanup(func() { _ = writer.Close() })
		}
		done := make(chan error, 1)
		go func() { _, err := Open(fifoDir, id); done <- err }()
		select {
		case err := <-done:
			if !errors.Is(err, ErrUnreadable) {
				t.Fatalf("FIFO P (live writer %t): %v", live, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Open waited on a FIFO P (live writer %t)", live)
		}
	}
	pdir := storeDir(t)
	must(t, os.Symlink(filepath.Join(dir, controlFile), filepath.Join(pdir, controlFile)))
	if s, err := Open(pdir, id); s != nil || !errors.Is(err, ErrUnreadable) {
		t.Fatalf("symlinked P: %v", err)
	}
}

// A1: Create reads the new image back; a readback that differs refuses.
func TestCreateReadbackRefusesTamperedImage(t *testing.T) {
	dir, id := storeDir(t), testIdentity(1)
	h := productionHooks
	h.fault = func(st stage) error {
		if st == stageRead {
			return os.WriteFile(filepath.Join(dir, controlFile), append(fileBytes(t, dir), 0), 0o600)
		}
		return nil
	}
	if s, err := start(dir, id, &NewInstallationProof{Identity: id}, h); s != nil || !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered readback: %v", err)
	}
}
