package policycontrol

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
)

// Truth is the P truth of one attempted transaction.
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

// Guard is a caller-owned revision of a consulted input. A commit requiring
// it holds it from its check through the durable crossing.
type Guard struct {
	mu      sync.Mutex
	version uint64
}

// Qualified is a guard revision observed at qualification.
type Qualified struct {
	guard   *Guard
	version uint64
}

// Advance records a change of the guarded input; it waits for a crossing
// that protects this guard.
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
	ownerUnset ownerMode = iota
	ownerNone
	ownerAdmit
	ownerRetain
)

// Tx is the one exclusive P transaction; its changes stay staged until Commit.
type Tx struct {
	s       *Store
	base    *state
	ctl     control
	puts    map[string]Row
	dels    map[string]struct{}
	mode    ownerMode
	owner   Owner
	class   OpClass
	ordinal uint64
	cursors *Cursors
	guards  []Qualified
	done    bool
}

type attempt struct {
	old, new []byte
	next     *state
	handle   *os.File
	poisoned bool
}

// Begin is try-or-refuse: it never waits and returns ErrBusy while another
// transaction is held, a crossing runs or an attempted transaction is UNKNOWN.
func (s *Store) Begin() (*Tx, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if s.tx != nil || s.crossing || s.pending != nil {
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

// successor builds and fully validates state n+1; every failure is before effects.
func (tx *Tx) successor() (*state, error) {
	b := tx.base
	if b.seq == math.MaxUint64 {
		return nil, refused("sequence exhausted")
	}
	n1, o := b.seq+1, tx.owner
	switch {
	case tx.mode == ownerNone:
		o = Owner{Kind: OwnerlessControl, Epoch: n1}
	case tx.mode == ownerAdmit && o.Kind != OwnerlessControl:
		o.Epoch = n1
	case tx.mode == ownerRetain && o.Epoch <= b.seq:
	default:
		return nil, refused("owner undeclared, ownerless admission or re-epoched retained owner")
	}
	next := &state{id: b.id, seq: n1, ctl: tx.ctl.clone(), rows: b.rows, receipt: &Receipt{Predecessor: b.seq, Successor: n1,
		Operation: operationID(b.id, n1), Owner: o, Class: tx.class, Ordinal: tx.ordinal}}
	if tx.cursors != nil {
		next.receipt.Cursors = &Cursors{tx.cursors.Before, tx.cursors.After}
	}
	if !tx.ctl.equal(b.ctl) {
		next.ctl.sequence = n1
	}
	if len(tx.puts)+len(tx.dels) != 0 {
		next.rows = make(map[string]Row, len(b.rows)+len(tx.puts))
		for id, r := range b.rows {
			next.rows[id] = r
		}
		for id := range tx.dels {
			delete(next.rows, id)
		}
		for id, r := range tx.puts {
			r.Sequence = n1
			next.rows[id] = r
		}
	}
	if err := validateState(next); err != nil {
		return nil, refused(err.Error())
	}
	return next, nil
}

// lockGuards takes every required guard without waiting and checks its
// revision; the held guards stay locked through the crossing.
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
func (tx *Tx) Commit() (res Result, err error) {
	s := tx.s
	s.mu.Lock()
	if tx.done || s.tx != tx {
		s.mu.Unlock()
		return Result{}, ErrFinished
	}
	old := Result{Truth: OLD, sequence: tx.base.seq}
	if len(tx.puts) == 0 && len(tx.dels) == 0 && tx.ctl.equal(tx.base.ctl) {
		tx.done, s.tx = true, nil
		s.mu.Unlock()
		return old, nil
	}
	tx.done, s.crossing = true, true // Abort and a second Commit now see a finished Tx
	s.mu.Unlock()
	held, err := lockGuards(tx.guards)
	var next *state
	var image []byte
	var c crossingResult
	if err == nil {
		next, err = tx.successor()
	}
	if err == nil {
		image = encode(next)
		c = s.cross(image)
	}
	for _, g := range held {
		g.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx.done, s.tx, s.crossing = true, nil, false
	switch {
	case err != nil:
		return old, err
	case c.crashed || c.ackLost || c.poisoned:
		s.pending = &attempt{old: s.image, new: image, next: next, handle: c.handle, poisoned: c.crashed || c.poisoned}
		return Result{Truth: UNKNOWN}, fmt.Errorf("%w: %w", ErrUnresolved, c.err)
	case c.err != nil:
		return old, c.err
	}
	s.st, s.image = next, image
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
	s.mu.Lock()
	p := s.pending
	switch {
	case s.closed:
		s.mu.Unlock()
		return Result{}, ErrClosed
	case s.crossing || s.tx != nil:
		s.mu.Unlock()
		return Result{}, ErrBusy
	case p == nil:
		s.mu.Unlock()
		return Result{}, nil
	case p.handle != nil || p.poisoned:
		s.mu.Unlock()
		return Result{Truth: UNKNOWN}, fmt.Errorf("%w: crossing handle retained or durability failed", ErrUnresolved)
	}
	s.crossing = true
	s.mu.Unlock()
	got, err := s.readImage()
	truth := UNKNOWN
	switch {
	case err != nil:
	case bytes.Equal(got, p.old):
		truth = OLD
	case bytes.Equal(got, p.new):
		truth = NEW
	default:
		if _, err = decode(got); err == nil {
			err = fmt.Errorf("%w: readback is neither the predecessor nor the successor", ErrUnresolved)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crossing = false
	switch truth {
	case UNKNOWN:
		p.poisoned = p.poisoned || errors.Is(err, ErrUnreadable)
		return Result{Truth: UNKNOWN}, err
	case NEW:
		s.st, s.image = p.next, p.new
	}
	s.pending = nil
	return Result{Truth: truth, sequence: s.st.seq}, nil
}

// Gate reports which P-dependent uses the store permits now: none while a
// transaction is held, crossing or UNKNOWN; AutomaticH1 also needs the
// durable latch. The store holds no lock over independent native work.
type Gate struct{ DependentEffects, AutomaticH1, LatchUse bool }

// Gate never waits.
func (s *Store) Gate() Gate {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := !s.closed && s.tx == nil && !s.crossing && s.pending == nil
	return Gate{DependentEffects: ok, AutomaticH1: ok && s.st.ctl.initialSync, LatchUse: ok}
}
