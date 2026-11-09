package policycontrol

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"sync"
)

type Truth uint8

const (
	OLD Truth = iota + 1
	NEW
	UNKNOWN
)

// Result carries only P truth and the sequence that truth establishes; it
// grants no native, pair, selector, outer or publication permission.
type Result struct {
	Truth    Truth
	sequence uint64
}

// Sequence returns the sequence established by OLD or NEW; UNKNOWN establishes
// none. A zero Result (Truth 0) means the call attempted no transaction.
func (r Result) Sequence() (uint64, bool) {
	return r.sequence, r.Truth == OLD || r.Truth == NEW
}

// Guard is a caller-owned revision; a commit requiring it holds it through the crossing.
type Guard struct {
	mu      sync.Mutex
	version uint64
}

type Qualified struct {
	guard   *Guard
	version uint64
}

// Advance records a change of the guarded input; it waits for a crossing protecting this guard.
func (g *Guard) Advance() {
	g.mu.Lock()
	g.version++
	g.mu.Unlock()
}

// Qualify returns the current revision for Tx.Require.
func (g *Guard) Qualify() Qualified {
	g.mu.Lock()
	defer g.mu.Unlock()
	return Qualified{guard: g, version: g.version}
}

type ownerMode uint8

const (
	ownerNone ownerMode = iota + 1
	ownerAdmit
	ownerRetain
)

// Tx is the one exclusive P transaction; its changes stay staged until Commit.
type Tx struct {
	s           *Store
	base        *state
	ctl         control
	puts        map[string]Row
	dels        map[string]struct{}
	mode        ownerMode
	owner       Owner
	class       OpClass
	ordinal     uint64
	cursors     *Cursors
	guards      []Qualified
	latch, done bool // latch persistence transaction; ended
}

type attempt struct {
	old, new        []byte
	next            *state
	handle          *os.File
	poisoned, latch bool
}

// Begin is try-or-refuse: it never waits and returns ErrBusy while another
// transaction is held, a crossing runs or an attempted transaction is UNKNOWN.
func (s *Store) Begin() (*Tx, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return nil, ErrClosed
	case s.heldLocked():
		return nil, ErrBusy
	}
	s.tx = &Tx{s: s, base: s.st, ctl: s.st.ctl.clone(), puts: map[string]Row{}, dels: map[string]struct{}{}}
	return s.tx, nil
}

// Ownerless records ownerless control: epoch n+1 and empty intent.
func (tx *Tx) Ownerless() { tx.mode, tx.owner = ownerNone, Owner{} }

// AdmitOwner records a new semantic admission of kind and intent at epoch n+1.
func (tx *Tx) AdmitOwner(kind OwnerKind, intent []byte) {
	tx.mode, tx.owner = ownerAdmit, Owner{Kind: kind, Intent: clone(intent)}
}

// RetainOwner records a live, continuing, handed-off or ending owner with its
// original epoch (at most n) and exact intent; it is never re-epoched.
func (tx *Tx) RetainOwner(o Owner) {
	tx.mode, tx.owner = ownerRetain, Owner{Kind: o.Kind, Epoch: o.Epoch, Intent: clone(o.Intent)}
}

// Operation records the semantic operation class and owner-defined ordinal.
func (tx *Tx) Operation(class OpClass, ordinal uint64) { tx.class, tx.ordinal = class, ordinal }

// Batch records a participating reconciliation batch's cursors.
func (tx *Tx) Batch(before, after uint64) { tx.cursors = &Cursors{Before: before, After: after} }

// Require adds a qualified guard that Commit checks and protects through the crossing.
func (tx *Tx) Require(q Qualified) { tx.guards = append(tx.guards, q) }

func (tx *Tx) receiptOwner(n1 uint64) (Owner, error) {
	o := tx.owner
	switch {
	case tx.mode == ownerNone:
		return Owner{Kind: OwnerlessControl, Epoch: n1}, nil
	case tx.mode == ownerAdmit && o.Kind != OwnerlessControl:
		o.Epoch = n1
		return o, nil
	case tx.mode == ownerRetain && o.Epoch <= tx.base.seq:
		return o, nil
	}
	return Owner{}, refused("owner undeclared, ownerless admission or re-epoched retained owner")
}

func (tx *Tx) successorRows(n1 uint64) map[string]Row {
	if len(tx.puts)+len(tx.dels) == 0 {
		return tx.base.rows
	}
	rows := make(map[string]Row, len(tx.base.rows)+len(tx.puts))
	maps.Copy(rows, tx.base.rows)
	for id := range tx.dels {
		delete(rows, id)
	}
	for id, r := range tx.puts {
		r.Sequence = n1
		rows[id] = r
	}
	return rows
}

func (tx *Tx) successor() (*state, error) {
	b := tx.base
	if b.seq == math.MaxUint64 {
		return nil, refused("sequence exhausted")
	}
	n1 := b.seq + 1
	o, err := tx.receiptOwner(n1)
	if err != nil {
		return nil, err
	}
	next := &state{id: b.id, seq: n1, ctl: tx.ctl.clone(), rows: tx.successorRows(n1), receipt: &Receipt{Predecessor: b.seq, Successor: n1, Operation: operationID(b.id, n1), Owner: o, Class: tx.class, Ordinal: tx.ordinal, Cursors: tx.cursors}}
	if !tx.ctl.equal(b.ctl) {
		next.ctl.sequence = n1
	}
	if err := validateState(next); err != nil {
		return nil, refused(err.Error())
	}
	return next, nil
}

// lockGuards locks and checks every guard without waiting; held guards stay locked.
func lockGuards(qs []Qualified) (held []*Guard, err error) {
	seen := map[*Guard]uint64{}
	for _, q := range qs {
		v, ok := seen[q.guard]
		switch {
		case q.guard == nil:
			return held, refused("zero guard")
		case !ok && !q.guard.mu.TryLock():
			return held, fmt.Errorf("%w: guard is changing", ErrStaleLocalPlan)
		case !ok:
			held, v, seen[q.guard] = append(held, q.guard), q.guard.version, q.guard.version
		}
		if v != q.version {
			return held, ErrStaleLocalPlan
		}
	}
	return held, nil
}

// Commit ends the transaction with exactly one of OLD, NEW or UNKNOWN. An
// empty change set writes nothing and is OLD. A refusal before the rename
// (guard, sequence, domain, bound, scratch I/O) is OLD with nothing changed.
// A successful durable crossing is NEW with no compulsory second read. A
// failure after the rename or a lost acknowledgement is UNKNOWN: the store
// then refuses Begin, views and dependent effects until Recover resolves it.
func (tx *Tx) Commit() (Result, error) {
	old, proceed, err := tx.enterCommit()
	if !proceed {
		return old, err
	}
	next, c, err := tx.crossGuarded()
	return tx.finishCommit(old, next, c, err)
}

func (tx *Tx) enterCommit() (old Result, proceed bool, err error) {
	s := tx.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if tx.done || s.tx != tx {
		return Result{}, false, ErrFinished
	}
	old = Result{Truth: OLD, sequence: tx.base.seq}
	if len(tx.puts) == 0 && len(tx.dels) == 0 && tx.ctl.equal(tx.base.ctl) {
		if tx.done, s.tx = true, nil; tx.latch {
			s.afterLatchLocked(true, nil)
		}
		return old, false, nil
	}
	tx.done, s.crossing, s.latchRenewed = true, true, false // Abort and a second Commit now see a finished Tx
	return old, true, nil
}

func (tx *Tx) crossGuarded() (next *state, c crossingResult, err error) {
	held, err := lockGuards(tx.guards)
	if err == nil {
		next, err = tx.successor()
	}
	if err == nil {
		c = tx.s.cross(next)
	}
	for _, g := range held {
		g.mu.Unlock()
	}
	return next, c, err
}

func (tx *Tx) finishCommit(old Result, next *state, c crossingResult, failure error) (res Result, err error) {
	s := tx.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if tx.done, s.tx, s.crossing = true, nil, false; tx.latch {
		defer func() { s.afterLatchLocked(true, err) }()
	}
	switch {
	case failure != nil:
		return old, failure
	case c.crashed || c.ackLost || c.poisoned:
		s.pending = &attempt{old: s.image, new: c.image, next: next, handle: c.handle, poisoned: c.crashed || c.poisoned, latch: tx.latch}
		return Result{Truth: UNKNOWN}, fmt.Errorf("%w: %w", ErrUnresolved, c.err)
	case c.err != nil:
		return old, c.err
	}
	s.st, s.image = next, c.image
	return Result{Truth: NEW, sequence: next.seq}, nil
}

// Abort ends the transaction before commit: OLD with nothing changed.
func (tx *Tx) Abort() (Result, error) {
	s := tx.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if tx.done || s.tx != tx {
		return Result{}, ErrFinished
	}
	tx.done, s.tx = true, nil
	return Result{Truth: OLD, sequence: tx.base.seq}, nil
}

// Recover classifies a retained UNKNOWN attempt. A retained crossing handle
// or an observed post-rename durability failure stays UNKNOWN with no
// synchronization or read. Otherwise, under the held writer with no
// transaction, it establishes durability and reads P once: the exact
// predecessor image is OLD, the exact successor image (sequence, receipt,
// rows, cursors) is NEW, anything else UNKNOWN (or the integrity error).
func (s *Store) Recover() (Result, error) {
	p, res, err := s.enterRecover()
	if p == nil {
		return res, err
	}
	return s.finishRecover(p)
}

func (s *Store) enterRecover() (*attempt, Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pending
	switch {
	case s.closed:
		return nil, Result{}, ErrClosed
	case s.crossing || s.tx != nil:
		return nil, Result{}, ErrBusy
	case p == nil:
		return nil, Result{}, nil
	case p.handle != nil || p.poisoned:
		return nil, Result{Truth: UNKNOWN}, fmt.Errorf("%w: crossing handle retained or durability failed", ErrUnresolved)
	}
	s.crossing = true
	return p, Result{}, nil
}

func (s *Store) classifyReadback(p *attempt) (Truth, error) {
	got, err := s.readImage()
	switch {
	case err != nil:
		return UNKNOWN, err
	case bytes.Equal(got, p.old):
		return OLD, nil
	case bytes.Equal(got, p.new):
		return NEW, nil
	}
	if _, err = decode(got); err == nil {
		err = fmt.Errorf("%w: readback is neither the predecessor nor the successor", ErrUnresolved)
	}
	return UNKNOWN, err
}

func (s *Store) finishRecover(p *attempt) (Result, error) {
	truth, err := s.classifyReadback(p)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crossing = false
	if truth == UNKNOWN {
		p.poisoned = p.poisoned || errors.Is(err, ErrUnreadable)
		return Result{Truth: UNKNOWN}, err
	}
	if truth == NEW {
		s.st, s.image = p.next, p.new
	}
	if s.pending = nil; p.latch {
		s.afterLatchLocked(false, nil)
	}
	return Result{Truth: truth, sequence: s.st.seq}, nil
}

// Gate reports the P-dependent uses permitted now: none while a transaction is
// held, crossing or UNKNOWN; AutomaticH1 also needs the durable latch.
type Gate struct{ DependentEffects, AutomaticH1, LatchUse bool }

func (s *Store) heldLocked() bool { return s.tx != nil || s.crossing || s.pending != nil }

// Gate never waits and holds no lock over independent native work.
func (s *Store) Gate() Gate {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := !s.closed && !s.heldLocked()
	return Gate{DependentEffects: ok, AutomaticH1: ok && s.st.ctl.initialSync, LatchUse: ok}
}
