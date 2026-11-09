package policycontrol

import (
	"bytes"
	"errors"
)

// ObserveIncident stages the first OBSERVED (attempted=false) record when no
// incident exists, preserving initial_sync_completed and has_attempt. The
// same hash at the same height and error is the SAME incident: a no-op that
// returns it unchanged, attempted bit included. The same hash with another
// height or error is ErrContradiction; another hash while an incident exists
// is refused (see ReplaceObserved). A refusal stages nothing.
func (tx *Tx) ObserveIncident(d Diagnosis) (Incident, error) {
	if err := validDiagnosis(d); err != nil {
		return Incident{}, err
	}
	switch cur := tx.ctl.incident; {
	case cur == nil:
		tx.ctl.incident = (&Incident{Diagnosis: d, State: StateObserved}).clone()
	case cur.Diagnosis.Hash != d.Hash:
		return Incident{}, refused("another incident is current")
	case cur.Diagnosis.Height != d.Height || !bytes.Equal(cur.Diagnosis.Error, d.Error):
		return Incident{}, ErrContradiction
	}
	return *tx.ctl.incident.clone(), nil
}

// ReplaceObserved stages the one atomic replacement of OBSERVED with
// attempted=false by a new OBSERVED (attempted=false) of a different hash;
// staleness qualification is the caller's. INTENT, AUTO_BLOCKED and
// attempted=true are never replaced.
func (tx *Tx) ReplaceObserved(d Diagnosis) error {
	if err := validDiagnosis(d); err != nil {
		return err
	}
	if cur := tx.ctl.incident; cur == nil || cur.State != StateObserved || cur.Attempted || cur.Diagnosis.Hash == d.Hash {
		return refused("replacement needs OBSERVED, attempted=false and a different hash")
	}
	tx.ctl.incident = (&Incident{Diagnosis: d, State: StateObserved}).clone()
	return nil
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
	if cur == nil || !(cur.State == StateObserved && !cur.Attempted ||
		cur.State == StateAutoBlocked && !bytes.Equal(cur.Admission.Destination, a.Destination)) {
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
	if tx.ctl.incident == nil || tx.ctl.incident.State != StateIntent {
		return refused("AUTO_BLOCKED needs INTENT")
	}
	tx.ctl.incident.State = StateAutoBlocked
	return nil
}

// RemoveOnSuccess stages the qualified SUCCESS removal of an INTENT
// incident, preserving has_attempt and initial_sync_completed.
func (tx *Tx) RemoveOnSuccess() error {
	if tx.ctl.incident == nil || tx.ctl.incident.State != StateIntent {
		return refused("SUCCESS removal needs INTENT")
	}
	tx.ctl.incident = nil
	return nil
}

// LatchProof is a caller's fresh STABLE qualification of the unchanged
// predicate on the selected source and pair, bound to the guard whose
// change before commit voids it.
type LatchProof struct {
	PredicateTrue bool
	Basis         Qualified
}

// LatchStatus is the durable latch of the last qualified committed P, the
// one coalesced RAM request and the pending-persistence owner.
type LatchStatus struct{ Durable, Requested, PendingPersistence bool }

// Latch reports the latch status; it never waits.
func (s *Store) Latch() LatchStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return LatchStatus{s.st.ctl.initialSync, s.latchRequested, s.pending != nil && s.pending.latch}
}

// RequestLatch records a named observation with the predicate true as at
// most one coalesced RAM request. It starts no persistence, also while an
// attempt is UNKNOWN, and is a no-op once the latch is durably true. Close
// discards it.
func (s *Store) RequestLatch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latchRequested = !s.st.ctl.initialSync
}

// PersistLatch services the request. A durably true latch consumes it with
// no write; a false predicate writes nothing and retains it; otherwise it
// commits false to true as one ownerless control transaction: NEW latches
// durably and clears the request, OLD clears it (STALE_LOCAL_PLAN retains it
// for fresh qualification), UNKNOWN clears it and leaves the
// pending-persistence owner to Recover. Nothing starts while a transaction is
// held, crossing or UNKNOWN. No exported operation clears a true latch.
func (s *Store) PersistLatch(p LatchProof) (Result, error) {
	s.mu.Lock()
	old, busy := Result{Truth: OLD, sequence: s.st.seq}, s.tx != nil || s.crossing || s.pending != nil
	var err error
	switch {
	case s.closed:
		old, err = Result{}, ErrClosed
	case busy:
		old, err = Result{}, ErrBusy
	case s.st.ctl.initialSync:
		s.latchRequested = false
	case !s.latchRequested:
		err = ErrNoRequest
	case p.PredicateTrue && p.Basis.guard == nil:
		err = refused("latch proof without basis")
	case p.PredicateTrue:
		s.mu.Unlock()
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
	s.mu.Unlock()
	return old, err
}

// afterLatchLocked applies the request law to a latch persistence attempt
// resolved directly by Commit or by Recover readback.
func (s *Store) afterLatchLocked(direct bool, err error) {
	if s.st.ctl.initialSync || (direct && !errors.Is(err, ErrStaleLocalPlan)) {
		s.latchRequested = false
	}
}
