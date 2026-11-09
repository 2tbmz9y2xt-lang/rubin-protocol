package policycontrol

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

const (
	controlFile    = "policy-control"
	scratchFile    = "policy-control.scratch"
	unresolvedFile = "policy-control.unresolved" // durable post-rename durability failure; Open then refuses forever
)

// NewInstallationProof names the identity it attests; a zero value or another identity refuses.
type NewInstallationProof struct{ Identity Identity }

// View is a protected copy of the last qualified committed P.
type View struct {
	Identity                         Identity
	Sequence                         uint64
	Receipt                          *Receipt // nil only for the initial empty receipt at sequence 0
	InitialSyncCompleted, HasAttempt bool
	ControlSequence                  uint64 // committing P sequence of the control record
	Incident                         *Incident
}

type stage uint8

const (
	stageCreate stage = iota + 1
	stageWrite
	stageFileSync
	stageRename
	stageDirSync
	stageClose
	stageAck
	stageRead
)

var errInjectedCrash = errors.New("policycontrol: injected crash")

type hooks struct {
	acquire func(string) (*filelock.Handle, filelock.Result, error)
	fault   func(stage) error // nil in production
	ops     fsOps
}

type fsOps struct {
	remove, syncDir func(string) error
	open            func(string) (*os.File, error)
	write           func(*os.File, []byte) error
	sync, close     func(*os.File) error
	rename          func(string, string) error
}

var realFS = fsOps{
	remove: os.Remove, syncDir: syncDir, sync: (*os.File).Sync, close: (*os.File).Close, rename: os.Rename,
	open: func(path string) (*os.File, error) {
		return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600) // nosemgrep: Semgrep_go_filesystem_rule-fileread -- caller-owned store directory plus a fixed package-constant leaf, opened with O_NOFOLLOW.
	},
	write: func(f *os.File, b []byte) error { _, err := f.Write(b); return err },
}

var productionHooks = hooks{acquire: filelock.AcquireDirectory, ops: realFS}

// Store is an open P holding the directory's exclusive inode lock until Close; safe for concurrent use.
type Store struct {
	dir                          string
	lock                         *filelock.Handle
	fault                        func(stage) error
	ops                          fsOps
	mu                           sync.Mutex
	st                           *state   // last qualified committed state
	image                        []byte   // its exact bytes
	tx                           *Tx      // the held transaction
	crossing                     bool     // commit or recovery I/O in progress
	pending                      *attempt // unresolved UNKNOWN attempt
	closed                       bool
	latchRequested, latchRenewed bool // the one coalesced RAM latch request; one recorded since the latest latch decision
}

// Create creates positively new P (sequence 0, empty receipt, both booleans false, no incident, empty
// journal) in the existing mode-0700 directory dir, which must hold nothing but a stale scratch file,
// holding the directory's exclusive lock until Close, then reads it back. It never creates the directory;
// a zero or mismatched proof refuses, a contended lock is ErrBusy, any other lock failure ErrUnreadable.
func Create(dir string, id Identity, proof NewInstallationProof) (*Store, error) {
	return start(dir, id, &proof, productionHooks)
}

// Open qualifies existing P in dir against expected, holding the directory's exclusive lock until Close.
// It creates nothing: an absent directory or P is ErrMissingControl, a contended lock ErrBusy, unobtainable
// bytes ErrUnreadable, malformed or mismatched P ErrIntegrity. P is never reset, recreated or defaulted to fresh.
func Open(dir string, expected Identity) (*Store, error) {
	return start(dir, expected, nil, productionHooks)
}

func refuseLock(lock *filelock.Handle, res filelock.Result, err error, creating bool) error {
	if lock != nil {
		_ = lock.Release()
	}
	switch {
	case res == filelock.ResultContended:
		return fmt.Errorf("%w: store directory is held: %w", ErrBusy, err)
	case res == filelock.ResultInvalidOrUnopenable && errors.Is(err, fs.ErrNotExist) && !creating:
		return fmt.Errorf("%w: store directory absent", ErrMissingControl)
	}
	return fmt.Errorf("%w: store directory lock result %q: %w", ErrUnreadable, res, err)
}

// start decides from the lock result before any read: only a held handle proceeds.
func start(dir string, id Identity, proof *NewInstallationProof, h hooks) (*Store, error) {
	if !id.valid() || (proof != nil && proof.Identity != id) {
		return nil, refused("invalid identity or new-installation proof")
	}
	lock, res, err := h.acquire(dir)
	if lock == nil || res != "" || err != nil {
		return nil, refuseLock(lock, res, err, proof != nil)
	}
	s := &Store{dir: dir, lock: lock, fault: h.fault, ops: h.ops}
	if err = s.load(id, proof != nil); err != nil {
		return nil, errors.Join(err, lock.Release())
	}
	return s, nil
}

func (s *Store) load(id Identity, creating bool) (err error) {
	if creating {
		return s.create(id)
	}
	if _, e := os.Lstat(filepath.Join(s.dir, unresolvedFile)); !errors.Is(e, fs.ErrNotExist) {
		return fmt.Errorf("%w: a post-rename durability failure was recorded; operator resolution required", ErrUnresolved)
	}
	if s.image, err = s.readImage(); err != nil {
		return err
	}
	if s.st, err = decode(s.image); err == nil && s.st.id != id {
		err = fmt.Errorf("%w: %w", ErrIntegrity, ErrIdentityMismatch)
	}
	return err
}

func (s *Store) create(id Identity) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return unreadable(err)
	}
	for _, e := range entries {
		if e.Name() != scratchFile {
			return refused("store directory is not empty; existing control is never recreated")
		}
	}
	st := &state{id: id}
	c := s.cross(st)
	if c.err != nil {
		if c.handle != nil {
			_ = c.handle.Close()
		}
		return fmt.Errorf("create policy control (namespace committed=%t): %w", c.committed, c.err)
	}
	if got, err := s.readImage(); err != nil || !bytes.Equal(got, c.image) {
		return errors.Join(fmt.Errorf("%w: created image did not read back exactly", ErrIntegrity), err)
	}
	s.st, s.image = st, c.image
	return nil
}

// markUnresolved records that readable P bytes must never qualify again.
func markUnresolved(dir string) error {
	f, err := os.OpenFile(filepath.Join(dir, unresolvedFile), os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600) // nosemgrep: Semgrep_go_filesystem_rule-fileread -- caller-owned store directory plus a fixed package-constant leaf, opened with O_NOFOLLOW.
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close(), syncDir(dir))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

func unreadable(err error) error { return fmt.Errorf("%w: %w", ErrUnreadable, err) }

func (s *Store) inject(st stage) error {
	if s.fault == nil {
		return nil
	}
	return s.fault(st)
}

// readImage establishes durability of the current P bytes, then reads them.
func (s *Store) readImage() ([]byte, error) {
	if err := s.inject(stageRead); err != nil {
		return nil, unreadable(err)
	}
	f, err := os.OpenFile(filepath.Join(s.dir, controlFile), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0) // nosemgrep: Semgrep_go_filesystem_rule-fileread -- caller-owned store directory plus a fixed package-constant leaf, opened with O_NOFOLLOW.
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrMissingControl
	} else if err != nil {
		return nil, unreadable(err)
	}
	defer func() { _ = f.Close() }()
	b, err := s.readDurable(f)
	if err != nil {
		return nil, unreadable(err)
	}
	return b, nil
}

// readDurable probes for growth only on a fully read regular file: a FIFO could block.
func (s *Store) readDurable(f *os.File) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxImageBytes {
		return nil, errors.New("policy control is not a regular file within its size ceiling")
	}
	if err = errors.Join(s.ops.sync(f), s.ops.syncDir(s.dir)); err != nil {
		return nil, errors.Join(err, markUnresolved(s.dir))
	}
	b := make([]byte, info.Size())
	if _, err = io.ReadFull(f, b); err != nil {
		return nil, err
	}
	if n, rerr := f.Read(make([]byte, 1)); n != 0 || rerr != io.EOF {
		return nil, errors.New("policy control changed size while read")
	}
	return b, nil
}

type crossingResult struct {
	committed, poisoned, crashed, ackLost bool
	image                                 []byte   // the encoded successor
	handle                                *os.File // scratch handle retained by a crash
	err                                   error
}

// cross atomically replaces P with st's image. A failure before the rename leaves
// OLD; one after it is poisoned UNKNOWN; a crash retains the open handle.
func (s *Store) cross(st *state) (c crossingResult) {
	if c.image = encode(st); c.image == nil {
		c.err = refused("state does not encode within its ceilings")
		return c
	}
	scratch := filepath.Join(s.dir, scratchFile)
	var f *os.File
	step := func(st stage, op func() error) {
		if c.err == nil {
			c.err = s.inject(st)
		}
		if c.err == nil {
			c.err = op()
		}
	}
	step(stageCreate, func() (err error) {
		if err = s.ops.remove(scratch); err == nil || errors.Is(err, fs.ErrNotExist) {
			f, err = s.ops.open(scratch)
		}
		return err
	})
	step(stageWrite, func() error { return s.ops.write(f, c.image) })
	step(stageFileSync, func() error { return s.ops.sync(f) })
	step(stageRename, func() error { return s.ops.rename(scratch, filepath.Join(s.dir, controlFile)) })
	c.committed = c.err == nil
	step(stageDirSync, func() error { return s.ops.syncDir(s.dir) })
	step(stageClose, func() error { h := f; f = nil; return s.ops.close(h) })
	if c.crashed = errors.Is(c.err, errInjectedCrash); c.crashed {
		c.handle = f
		return c
	}
	s.settleCrossing(&c, scratch, f)
	return c
}

func (s *Store) settleCrossing(c *crossingResult, scratch string, f *os.File) {
	if f != nil {
		_ = s.ops.close(f)
	}
	if c.err != nil && !c.committed {
		_ = s.ops.remove(scratch)
		_ = s.ops.syncDir(s.dir)
	}
	if c.poisoned = c.err != nil && c.committed; c.poisoned {
		c.err = errors.Join(c.err, markUnresolved(s.dir))
	}
	if err := s.inject(stageAck); err != nil {
		c.ackLost, c.err = true, errors.Join(c.err, err)
	}
}

// View returns a protected copy of the last qualified committed P; it refuses
// with ErrBusy during a crossing or while an attempt is UNKNOWN.
func (s *Store) View() (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readableLocked(); err != nil {
		return View{}, err
	}
	st := s.st
	v := View{Identity: st.id, Sequence: st.seq, InitialSyncCompleted: st.ctl.initialSync, HasAttempt: st.ctl.hasAttempt, ControlSequence: st.ctl.sequence, Incident: st.ctl.incident.clone()}
	if r := st.receipt; r != nil {
		rc := *r
		rc.Owner.Intent = clone(r.Owner.Intent)
		if r.Cursors != nil {
			rc.Cursors = &Cursors{r.Cursors.Before, r.Cursors.After}
		}
		v.Receipt = &rc
	}
	return v, nil
}

func (s *Store) readableLocked() error {
	switch {
	case s.closed:
		return ErrClosed
	case s.crossing || s.pending != nil:
		return fmt.Errorf("%w: %w", ErrBusy, ErrUnresolved)
	}
	return nil
}

// Close ends a held transaction as OLD, disposes a retained crossing handle
// and releases the directory lock. It refuses with ErrBusy during a crossing.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.crossing {
		return ErrBusy
	}
	if s.tx != nil {
		s.tx.done, s.tx = true, nil
	}
	if p := s.pending; p != nil && p.handle != nil {
		_ = p.handle.Close()
		p.handle = nil
	}
	s.closed, s.latchRequested = true, false
	return s.lock.Release()
}
