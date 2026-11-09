package policycontrol

import (
	"bytes"
	"errors"
)

// ObserveIncident stages the first OBSERVED (attempted=false) record when no incident exists and
// no change is staged, preserving initial_sync_completed and has_attempt. A request equal in hash,
// height and error to the staged, else the committed, incident is a no-op returning it. The same
// hash with another height or error is ErrContradiction; another hash is refused (see
// ReplaceObserved). A transaction carries at most one incident change; a refusal stages nothing.
func (tx *Tx) ObserveIncident(d Diagnosis) (Incident, error) {
	if err := validDiagnosis(d); err != nil {
		return Incident{}, err
	}
	switch cur := tx.ctl.incident; {
	case cur == nil && !tx.incidentStaged():
		tx.ctl.incident = (&Incident{Diagnosis: d, State: StateObserved}).clone()
	case cur == nil || cur.Diagnosis.Hash != d.Hash:
		return Incident{}, refused("another incident is current")
	case cur.Diagnosis.Height != d.Height || !bytes.Equal(cur.Diagnosis.Error, d.Error):
		return Incident{}, ErrContradiction
	}
	return *tx.ctl.incident.clone(), nil
}

// ReplaceObserved stages the one atomic replacement of OBSERVED, attempted=false
// by a new OBSERVED of a different hash; staleness qualification is the caller's.
// INTENT, AUTO_BLOCKED and attempted=true are never replaced.
func (tx *Tx) ReplaceObserved(d Diagnosis) error {
	if err := validDiagnosis(d); err != nil {
		return err
	}
	if cur := tx.ctl.incident; tx.incidentStaged() || cur == nil || cur.State != StateObserved || cur.Attempted || cur.Diagnosis.Hash == d.Hash {
		return refused("replacement needs OBSERVED, attempted=false and a different hash")
	}
	tx.ctl.incident = (&Incident{Diagnosis: d, State: StateObserved}).clone()
	return nil
}

func (tx *Tx) incidentStaged() bool {
	return !bytes.Equal(incidentBytes(tx.ctl.incident), incidentBytes(tx.base.ctl.incident))
}

func (in *Incident) admits(destination []byte) bool {
	return in != nil && (in.State == StateObserved && !in.Attempted ||
		in.State == StateAutoBlocked && !bytes.Equal(in.Admission.Destination, destination))
}

// ConsumeIntent stages INTENT with the exact admission, attempted=true and
// has_attempt=true, from OBSERVED with attempted=false or, as a new manual
// intent with a distinct destination, from AUTO_BLOCKED. A live INTENT is
// never replaced. Only the committed NEW result proves the consumed intent.
func (tx *Tx) ConsumeIntent(a Admission) error {
	if err := validAdmission(&a); err != nil {
		return err
	}
	cur := tx.ctl.incident
	if tx.incidentStaged() || !cur.admits(a.Destination) {
		return refused("intent needs OBSERVED with attempted=false, or AUTO_BLOCKED and a distinct destination")
	}
	next := cur.clone()
	next.State, next.Attempted, next.Admission = StateIntent, true, &a
	tx.ctl.incident, tx.ctl.hasAttempt = next.clone(), true
	return nil
}

// AutoBlock stages INTENT to AUTO_BLOCKED, preserving every diagnosis and
// admission field and has_attempt.
func (tx *Tx) AutoBlock() error {
	if tx.incidentStaged() || tx.ctl.incident == nil || tx.ctl.incident.State != StateIntent {
		return refused("AUTO_BLOCKED needs INTENT")
	}
	tx.ctl.incident.State = StateAutoBlocked
	return nil
}

// RemoveOnSuccess stages the qualified SUCCESS removal of an INTENT
// incident, preserving has_attempt and initial_sync_completed.
func (tx *Tx) RemoveOnSuccess() error {
	if tx.incidentStaged() || tx.ctl.incident == nil || tx.ctl.incident.State != StateIntent {
		return refused("SUCCESS removal needs INTENT")
	}
	tx.ctl.incident = nil
	return nil
}

// LatchProof is a fresh STABLE predicate qualification bound to the guard
// whose change before commit voids it.
type LatchProof struct {
	PredicateTrue bool
	Basis         Qualified
}

// LatchStatus is the durable latch, the RAM request and the pending-persistence owner.
type LatchStatus struct{ Durable, Requested, PendingPersistence bool }

// Latch reports the latch status; it never waits.
func (s *Store) Latch() LatchStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return LatchStatus{s.st.ctl.initialSync, s.latchRequested, s.pending != nil && s.pending.latch}
}

// RequestLatch records a named observation with the predicate true as at most one coalesced RAM
// request. It starts no persistence, also while an attempt is UNKNOWN, and is a no-op once the
// latch is durably true or the store is closed. Made while a latch attempt crosses, it is a new
// request that the attempt's own OLD or UNKNOWN leaves in place. Close discards it.
func (s *Store) RequestLatch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latchRequested, s.latchRenewed = !s.closed && !s.st.ctl.initialSync, s.crossing
}

// PersistLatch services the request. A durably true latch consumes it with
// no write; a false predicate writes nothing and retains it; otherwise it
// commits false to true as one ownerless control transaction: NEW latches
// durably and clears every request, OLD clears the serviced request (STALE_LOCAL_PLAN retains it
// for fresh qualification), UNKNOWN clears the serviced request and leaves the pending-persistence
// owner to Recover. Nothing starts while a transaction is held, crossing or UNKNOWN. No exported
// operation clears a true latch.
func (s *Store) PersistLatch(p LatchProof) (Result, error) {
	res, proceed, err := s.latchDecision(p)
	if !proceed {
		return res, err
	}
	tx, err := s.Begin()
	if err != nil {
		return Result{}, err
	}
	tx.latch, tx.ctl.initialSync = true, true
	tx.Ownerless()
	tx.Operation(ClassControl, 0)
	tx.Require(p.Basis)
	return tx.Commit()
}

func (s *Store) latchDecision(p LatchProof) (Result, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := Result{Truth: OLD, sequence: s.st.seq}
	switch {
	case s.closed:
		return Result{}, false, ErrClosed
	case s.heldLocked():
		return Result{}, false, ErrBusy
	case s.st.ctl.initialSync:
		s.latchRequested = false
		return old, false, nil
	case !s.latchRequested:
		return old, false, ErrNoRequest
	case !p.PredicateTrue:
		return old, false, nil
	case p.Basis.guard == nil:
		return old, false, refused("latch proof without basis")
	}
	return old, true, nil
}

// afterLatchLocked applies the request law after Commit or Recover readback.
func (s *Store) afterLatchLocked(direct bool, err error) {
	if s.st.ctl.initialSync || (direct && !s.latchRenewed && !errors.Is(err, ErrStaleLocalPlan)) {
		s.latchRequested = false
	}
}
