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
	controlFile = "policy-control"
	scratchFile = "policy-control.scratch"
	// unresolvedFile durably records an observed post-rename durability
	// failure; Open then refuses forever (no API removes it).
	unresolvedFile = "policy-control.unresolved"
)

// NewInstallationProof is the caller-built positive new-installation/network
// proof naming the identity it attests; a zero value or another identity refuses.
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

// errInjectedCrash, returned by a fault hook, stops a crossing at that stage
// with no cleanup, as a process loss would.
var errInjectedCrash = errors.New("policycontrol: injected crash")

type hooks struct {
	acquire func(string) (*filelock.Handle, filelock.Result, error)
	fault   func(stage) error // nil in production
}

var productionHooks = hooks{acquire: filelock.AcquireDirectory}

// Store is an open P holding the store directory's exclusive inode lock from
// Create or Open until Close. All methods are safe for concurrent use.
type Store struct {
	dir            string
	lock           *filelock.Handle
	fault          func(stage) error
	mu             sync.Mutex
	st             *state   // last qualified committed state
	image          []byte   // its exact bytes
	tx             *Tx      // the held transaction
	crossing       bool     // commit or recovery I/O in progress
	pending        *attempt // unresolved UNKNOWN attempt
	closed         bool
	latchRequested bool // the one coalesced RAM latch request
}

// Create creates positively new P (sequence 0, empty receipt, both booleans
// false, no incident, empty journal) in the existing mode-0700 directory dir,
// which must hold nothing but a stale scratch file, then reads it back. It
// never creates the directory; a zero or mismatched proof refuses.
func Create(dir string, id Identity, proof NewInstallationProof) (*Store, error) {
	return start(dir, id, &proof, productionHooks)
}

// Open qualifies existing P in dir against expected. It creates nothing: an
// absent directory or P is ErrMissingControl; malformed or mismatched P is
// ErrIntegrity and is never reset, recreated or defaulted to fresh.
func Open(dir string, expected Identity) (*Store, error) {
	return start(dir, expected, nil, productionHooks)
}

// start decides from the lock result before any read: only a held handle
// proceeds, contention is ErrBusy and every other result is unreadable.
func start(dir string, id Identity, proof *NewInstallationProof, h hooks) (*Store, error) {
	if !id.valid() || (proof != nil && proof.Identity != id) {
		return nil, refused("invalid identity or new-installation proof")
	}
	lock, res, err := h.acquire(dir)
	switch {
	case lock != nil && res == "" && err == nil:
	case res == filelock.ResultContended:
		return nil, fmt.Errorf("%w: store directory is held: %v", ErrBusy, err)
	case res == filelock.ResultInvalidOrUnopenable && errors.Is(err, fs.ErrNotExist) && proof == nil:
		return nil, fmt.Errorf("%w: store directory absent", ErrMissingControl)
	default:
		if lock != nil {
			_ = lock.Release()
		}
		return nil, fmt.Errorf("%w: store directory lock result %q: %v", ErrUnreadable, res, err)
	}
	s := &Store{dir: dir, lock: lock, fault: h.fault}
	if proof != nil {
		err = s.create(id)
	} else if _, e := os.Lstat(filepath.Join(dir, unresolvedFile)); !errors.Is(e, fs.ErrNotExist) {
		err = fmt.Errorf("%w: a post-rename durability failure was recorded; operator resolution required", ErrUnresolved)
	} else if s.image, err = s.readImage(); err == nil {
		if s.st, err = decode(s.image); err == nil && s.st.id != id {
			err = fmt.Errorf("%w: %w", ErrIntegrity, ErrIdentityMismatch)
		}
	}
	if err != nil {
		return nil, errors.Join(err, lock.Release())
	}
	return s, nil
}

func (s *Store) create(id Identity) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	for _, e := range entries {
		if e.Name() != scratchFile {
			return refused("store directory is not empty; existing control is never recreated")
		}
	}
	st := &state{id: id}
	image := encode(st)
	if c := s.cross(image); c.err != nil {
		if c.handle != nil {
			_ = c.handle.Close()
		}
		return fmt.Errorf("create policy control (namespace committed=%t): %w", c.committed, c.err)
	}
	if got, err := s.readImage(); err != nil || !bytes.Equal(got, image) {
		return errors.Join(fmt.Errorf("%w: created image did not read back exactly", ErrIntegrity), err)
	}
	s.st, s.image = st, image
	return nil
}

// markUnresolved records that readable P bytes must never qualify again: a
// repeated synchronization after a reported failure proves nothing.
func markUnresolved(dir string) error {
	f, err := os.OpenFile(filepath.Join(dir, unresolvedFile), os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
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

// readImage establishes durability of the current P bytes (file and
// directory synchronization), then reads them with the size checked first.
func (s *Store) readImage() ([]byte, error) {
	if s.fault != nil {
		if err := s.fault(stageRead); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
		}
	}
	f, err := os.OpenFile(filepath.Join(s.dir, controlFile), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrMissingControl
	} else if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err == nil && (!info.Mode().IsRegular() || info.Size() > maxImageBytes) {
		err = errors.New("policy control is not a regular file within its size ceiling")
	}
	var b []byte
	if err == nil {
		if err = errors.Join(f.Sync(), syncDir(s.dir)); err != nil {
			err = errors.Join(err, markUnresolved(s.dir))
		} else {
			b = make([]byte, info.Size())
			_, err = io.ReadFull(f, b)
		}
	}
	if n, rerr := f.Read(make([]byte, 1)); err == nil && (n != 0 || rerr != io.EOF) {
		err = errors.New("policy control changed size while read")
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	return b, nil
}

type crossingResult struct {
	committed, poisoned, crashed, ackLost bool
	handle                                *os.File // scratch handle retained by a crash
	err                                   error
}

// cross atomically replaces P with image: fixed 0600 scratch, write, file
// sync, rename, directory sync, handle close, acknowledgement. A failure
// before the rename removes the scratch (OLD); one after it leaves durability
// unestablished (poisoned, UNKNOWN); a crash retains the open handle.
func (s *Store) cross(image []byte) (c crossingResult) {
	scratch := filepath.Join(s.dir, scratchFile)
	var f *os.File
	step := func(st stage, op func() error) {
		if c.err == nil && s.fault != nil {
			c.err = s.fault(st)
		}
		if c.err == nil {
			c.err = op()
		}
	}
	step(stageCreate, func() (err error) {
		if err = os.Remove(scratch); err == nil || errors.Is(err, fs.ErrNotExist) {
			f, err = os.OpenFile(scratch, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
		}
		return err
	})
	step(stageWrite, func() error { _, err := f.Write(image); return err })
	step(stageFileSync, func() error { return f.Sync() })
	step(stageRename, func() error { return os.Rename(scratch, filepath.Join(s.dir, controlFile)) })
	c.committed = c.err == nil
	step(stageDirSync, func() error { return syncDir(s.dir) })
	step(stageClose, func() error { h := f; f = nil; return h.Close() })
	if c.crashed = errors.Is(c.err, errInjectedCrash); c.crashed {
		c.handle = f
		return c
	}
	if f != nil {
		_ = f.Close()
	}
	if c.err != nil && !c.committed {
		_ = os.Remove(scratch)
		_ = syncDir(s.dir)
	}
	if c.poisoned = c.err != nil && c.committed; c.poisoned {
		c.err = errors.Join(c.err, markUnresolved(s.dir))
	}
	if s.fault != nil {
		if err := s.fault(stageAck); err != nil {
			c.ackLost, c.err = true, errors.Join(c.err, err)
		}
	}
	return c
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
	v := View{Identity: st.id, Sequence: st.seq, InitialSyncCompleted: st.ctl.initialSync, HasAttempt: st.ctl.hasAttempt,
		ControlSequence: st.ctl.sequence, Incident: st.ctl.incident.clone()}
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
	if s.closed {
		return ErrClosed
	}
	if s.crossing || s.pending != nil {
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
	s.closed = true
	return s.lock.Release()
}
