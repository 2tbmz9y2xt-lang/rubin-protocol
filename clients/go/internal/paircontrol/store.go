package paircontrol

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

const (
	controlV1 = "outer-control"
	scratchV1 = "outer-control.scratch"
	pendingV1 = "outer-control.pending"
)

// TruthV1 describes this aggregate's transition, independently of P/native truth.
type TruthV1 uint8

const (
	OLDV1 TruthV1 = iota + 1
	NEWV1
	UNKNOWNV1
)

// ResultV1 establishes Sequence only for OLD/NEW; zero means no attempt.
type ResultV1 struct {
	Truth    TruthV1
	Sequence uint64
	Latched  bool
}

// ErrorV1 preserves the called operation, closed local code and original causes.
type ErrorV1 struct {
	Operation, Code string
	Cause           error
}

// Error reports local disposition without dereferencing a possibly typed-nil cause.
func (e *ErrorV1) Error() string { return "paircontrol: " + e.Operation + "/" + e.Code }

// Unwrap preserves every observed cause and wrapper unchanged.
func (e *ErrorV1) Unwrap() error { return e.Cause }

// localV1 constructs only package-owned output classifications.
func localV1(op, code string, cause error) *ErrorV1 {
	return &ErrorV1{Operation: op, Code: code, Cause: cause}
}

// NewInstallationProofV1 is the caller's independent positive installation attestation.
type NewInstallationProofV1 struct{ Identity IdentityV1 }

// fileOpsV1 forwards the bounded physical boundary; production uses only real OS calls.
type fileOpsV1 struct {
	open         func(string, int, fs.FileMode) (*os.File, error)
	write        func(*os.File, []byte) (int, error)
	sync, close  func(*os.File) error
	remove       func(string) error
	rename, link func(string, string) error
	release      func(*filelock.Handle) error
	ack          func() error
}

// realOpsV1 has no mutable package-global hook or exposed test capability.
func realOpsV1() fileOpsV1 {
	return fileOpsV1{open: os.OpenFile, write: (*os.File).Write,
		sync: (*os.File).Sync, close: (*os.File).Close, remove: os.Remove,
		rename: os.Rename, link: os.Link, release: (*filelock.Handle).Release,
		ack: func() error { return nil }}
}

// Store owns one inode flock and immutable bounded data, never a source/native lease.
type Store struct {
	dir     string
	lock    *filelock.Handle
	ops     fileOpsV1
	mu      sync.Mutex
	record  RecordV1
	image   []byte
	blocked *blockedV1
	closed  bool
}

// blockedV1 retains terminal local truth; only ackRead permits one readback.
type blockedV1 struct {
	result    ResultV1
	err       *ErrorV1
	old, next []byte
	ackRead   bool
}

// CreateV1 writes a positively new installation only in an actually empty directory.
func CreateV1(dir string, id IdentityV1, proof NewInstallationProofV1) (*Store, error) {
	return startV1(dir, id, &proof, realOpsV1())
}

// OpenV1 strictly qualifies existing control and never creates or repairs a leaf.
func OpenV1(dir string, id IdentityV1) (*Store, error) {
	return startV1(dir, id, nil, realOpsV1())
}

// startV1 consumes every acquired object on failure, including release errors.
func startV1(dir string, id IdentityV1, proof *NewInstallationProofV1, ops fileOpsV1) (*Store, error) {
	op := "open"
	if proof != nil {
		op = "create"
	}
	if !identityValidV1(id) {
		return nil, localV1(op, "identity", errShapeV1)
	}
	if proof != nil && proof.Identity != id {
		return nil, localV1(op, "refused", errors.New("paircontrol: positive installation proof required"))
	}
	s := &Store{dir: dir, ops: ops}
	if err := s.acquireV1(op); err != nil {
		return nil, err
	}
	var failure *ErrorV1
	if proof == nil {
		failure = s.openV1(id)
	} else {
		failure = s.createV1(id)
	}
	if failure != nil {
		failure.Cause = errors.Join(failure.Cause, s.ops.release(s.lock))
		s.lock = nil
		return nil, failure
	}
	return s, nil
}

// acquireV1 accepts only a real held directory inode owner.
func (s *Store) acquireV1(op string) *ErrorV1 {
	h, result, err := filelock.AcquireDirectory(s.dir)
	if h != nil && result == "" && err == nil {
		s.lock = h
		return nil
	}
	code := "unreadable"
	if result == filelock.ResultContended {
		code = "busy"
	}
	if op == "open" && errors.Is(err, fs.ErrNotExist) {
		code = "missing"
	}
	if h != nil {
		err = errors.Join(err, s.ops.release(h))
	}
	return localV1(op, code, err)
}

// openV1 checks the fail-closed sentinel before any aggregate view.
func (s *Store) openV1(id IdentityV1) *ErrorV1 {
	if _, err := os.Lstat(filepath.Join(s.dir, pendingV1)); !errors.Is(err, fs.ErrNotExist) {
		return localV1("open", "unresolved", err)
	}
	b, failure := s.readV1("open")
	if failure != nil {
		return failure
	}
	v, err := decodeV1(b)
	if err != nil {
		return localV1("open", "integrity", err)
	}
	if v.Identity != id {
		return localV1("open", "identity", errShapeV1)
	}
	s.record, s.image = v, b
	return nil
}

// createV1 permits no scratch exception and qualifies its initial readback inside crossing.
func (s *Store) createV1(id IdentityV1) *ErrorV1 {
	if failure := s.emptyV1(); failure != nil {
		return failure
	}
	v := RecordV1{Identity: id, Selector: 1}
	b, err := encodeV1(v)
	if err != nil {
		return localV1("create", "refused", err)
	}
	_, failure := s.crossV1("create", v, b, true)
	return failure
}

// emptyV1 bounds directory enumeration and preserves its actual Close result.
func (s *Store) emptyV1() *ErrorV1 {
	f, err := s.ops.open(s.dir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
	if err != nil {
		return localV1("create", "unreadable", err)
	}
	entries, err := f.ReadDir(1)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	code := "unreadable"
	if len(entries) != 0 {
		code, err = "refused", errors.New("paircontrol: installation directory is not empty")
	}
	err = errors.Join(err, s.ops.close(f))
	if err != nil {
		return localV1("create", code, err)
	}
	return nil
}

// directorySyncV1 keeps successful durability distinct from its following Close.
func (s *Store) directorySyncV1() (bool, error) {
	f, err := s.ops.open(s.dir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
	if err != nil {
		return false, err
	}
	syncErr := s.ops.sync(f)
	return syncErr == nil, errors.Join(syncErr, s.ops.close(f))
}

// readV1 consumes one no-follow regular bounded file, including a growth probe.
func (s *Store) readV1(op string) ([]byte, *ErrorV1) {
	f, err := s.ops.open(filepath.Join(s.dir, controlV1), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		code := "unreadable"
		if errors.Is(err, fs.ErrNotExist) {
			code = "missing"
		}
		return nil, localV1(op, code, err)
	}
	b, code, err := s.readFileV1(f)
	err = errors.Join(err, s.ops.close(f))
	if err != nil {
		return nil, localV1(op, code, err)
	}
	return b, nil
}

// readFileV1 checks type/size before allocation and qualifies both file and directory.
func (s *Store) readFileV1(f *os.File) ([]byte, string, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, "unreadable", err
	}
	if !info.Mode().IsRegular() {
		return nil, "unreadable", errShapeV1
	}
	if info.Size() < 1 || info.Size() > maxImageV1 {
		return nil, "integrity", errShapeV1
	}
	if err = s.ops.sync(f); err != nil {
		return nil, "unreadable", err
	}
	if _, err = s.directorySyncV1(); err != nil {
		return nil, "unreadable", err
	}
	return readBoundedV1(f, info.Size())
}

// readBoundedV1 reads one previously checked extent and rejects any trailing growth.
func readBoundedV1(f *os.File, size int64) ([]byte, string, error) {
	b := make([]byte, size)
	var err error
	if _, err = io.ReadFull(f, b); err != nil {
		return nil, "unreadable", err
	}
	var probe [1]byte
	if n, e := f.Read(probe[:]); n != 0 || e != io.EOF {
		return nil, "integrity", errors.Join(errShapeV1, e)
	}
	return b, "unreadable", nil
}

// crossingV1 owns the single-pass file/namespace cleanup through publication.
type crossingV1 struct {
	s                            *Store
	f                            *os.File
	pending, scratch             bool
	consumed, published, durable bool
	stopCleanup                  bool
	err                          error
}

// openLeafV1 creates only an exclusive fixed private leaf.
func (c *crossingV1) openLeafV1(leaf string) {
	if c.err != nil {
		return
	}
	c.f, c.err = c.s.ops.open(filepath.Join(c.s.dir, leaf), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0o600)
	if errors.Is(c.err, fs.ErrExist) {
		c.consumed = false
	}
	if c.err == nil {
		if leaf == pendingV1 {
			c.pending = true
		} else {
			c.scratch = true
		}
	}
}

// consumeV1 passes each owned object to its actual Close exactly once.
func (c *crossingV1) consumeV1() {
	if c.f == nil {
		return
	}
	f := c.f
	c.f = nil
	err := c.s.ops.close(f)
	if err != nil {
		c.consumed = false
	}
	c.err = errors.Join(c.err, err)
}

// armV1 durably prearms pending before any scratch/control effect.
func (c *crossingV1) armV1() {
	c.openLeafV1(pendingV1)
	if c.err == nil {
		c.err = c.s.ops.sync(c.f)
	}
	c.consumeV1()
	if c.err == nil {
		var synced bool
		synced, c.err = c.s.directorySyncV1()
		if synced && c.err != nil {
			c.consumed = false
		}
	}
}

// writeV1 completely writes and closes scratch before publication can run.
func (c *crossingV1) writeV1(b []byte) {
	c.openLeafV1(scratchV1)
	if c.err == nil {
		c.err = writeFullV1(c.s.ops, c.f, b)
	}
	if c.err == nil {
		c.err = c.s.ops.sync(c.f)
	}
	c.consumeV1()
}

// writeFullV1 treats zero/invalid progress as a definite prepublication failure.
func writeFullV1(ops fileOpsV1, f *os.File, b []byte) error {
	for len(b) != 0 {
		n, err := ops.write(f, b)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// publishV1 never deletes control; creation uses no-replace link.
func (c *crossingV1) publishV1(creating bool) {
	if c.err != nil {
		return
	}
	from, to := filepath.Join(c.s.dir, scratchV1), filepath.Join(c.s.dir, controlV1)
	if creating {
		c.err = c.s.ops.link(from, to)
	} else {
		c.err = c.s.ops.rename(from, to)
	}
	if c.err != nil {
		c.publicationFailureV1(creating)
		return
	}
	c.published = true
	if !creating {
		c.scratch = false
	}
	c.durable, c.err = c.s.directorySyncV1()
	if c.err != nil {
		c.stopCleanup = true
	}
}

// publicationFailureV1 never treats a reached EIO as proof of an untouched namespace.
func (c *crossingV1) publicationFailureV1(creating bool) {
	if errors.Is(c.err, syscall.EIO) {
		c.published, c.stopCleanup = true, true
		return
	}
	if creating && errors.Is(c.err, fs.ErrExist) {
		c.stopCleanup = true
	}
}

// readbackV1 qualifies initial creation before removing either owned link/sentinel.
func (c *crossingV1) readbackV1(b []byte) {
	if c.err != nil {
		return
	}
	got, failure := c.s.readV1("create")
	if failure != nil {
		c.err = failure.Cause
	} else if !bytes.Equal(got, b) {
		c.err = errors.New("paircontrol: created image did not read back exactly")
	}
	if c.err != nil {
		c.stopCleanup = true
	}
}

// cleanupV1 does one ordered pass and never removes an unowned pending sentinel.
func (c *crossingV1) cleanupV1() {
	c.consumeV1()
	changed := false
	if c.scratch {
		c.removeV1(scratchV1)
		changed = true
	}
	if c.pending && c.consumed && !c.stopCleanup {
		c.removeV1(pendingV1)
		changed = true
	}
	if changed {
		_, err := c.s.directorySyncV1()
		c.err = errors.Join(c.err, err)
		if err != nil {
			c.consumed = false
		}
	}
}

// removeV1 retains each observed cleanup failure and physical-disposition gate.
func (c *crossingV1) removeV1(leaf string) {
	err := c.s.ops.remove(filepath.Join(c.s.dir, leaf))
	c.err = errors.Join(c.err, err)
	if err != nil {
		c.consumed = false
	}
}

// crossV1 preserves known NEW across cleanup errors and admits ack recovery only last.
func (s *Store) crossV1(op string, next RecordV1, b []byte, creating bool) (ResultV1, *ErrorV1) {
	c := crossingV1{s: s, consumed: true}
	defer c.consumeV1()
	c.armV1()
	c.writeV1(b)
	c.publishV1(creating)
	if creating && c.durable {
		c.readbackV1(b)
	}
	c.cleanupV1()
	if c.err != nil {
		return s.failedCrossV1(op, next, b, &c)
	}
	if err := s.ops.ack(); err != nil {
		r := ResultV1{Truth: UNKNOWNV1, Latched: true}
		e := localV1(op, "unresolved", err)
		s.blocked = &blockedV1{result: r, err: e, old: s.image, next: b, ackRead: !creating}
		return r, e
	}
	s.record, s.image = next, b
	return ResultV1{Truth: NEWV1, Sequence: next.Sequence}, nil
}

// failedCrossV1 separates raw durability, unknown crossing and definite precommit truth.
func (s *Store) failedCrossV1(op string, next RecordV1, b []byte, c *crossingV1) (ResultV1, *ErrorV1) {
	oldImage := s.image
	r, code := ResultV1{Truth: OLDV1, Sequence: s.record.Sequence}, "precommit"
	if c.durable {
		r.Truth, r.Sequence, code = NEWV1, next.Sequence, "postcommit_new"
		s.record, s.image = next, b
	} else if c.published {
		r.Truth, r.Sequence, code = UNKNOWNV1, 0, "unresolved"
	}
	if !c.consumed || c.stopCleanup {
		r.Latched = true
	}
	if c.stopCleanup && !c.published {
		code = "integrity"
	}
	e := localV1(op, code, c.err)
	if r.Latched {
		s.blocked = &blockedV1{result: r, err: e, old: oldImage, next: b}
	}
	return r, e
}

// CloseV1 consumes the flock once, retaining actual release failure separately.
func (s *Store) CloseV1() error {
	if !s.mu.TryLock() {
		return localV1("close", "busy", nil)
	}
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	h := s.lock
	s.lock = nil
	if err := s.ops.release(h); err != nil {
		return localV1("close", "unresolved", err)
	}
	return nil
}
