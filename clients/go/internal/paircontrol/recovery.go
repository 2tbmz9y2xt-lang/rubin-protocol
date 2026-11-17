package paircontrol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

// availableV1 projects the original blocked disposition before any new P or I/O owner.
func (s *Store) availableV1(op string) (ResultV1, *ErrorV1) {
	if s.closed {
		return ResultV1{}, localV1(op, "closed", nil)
	}
	if s.blocked != nil {
		return s.blocked.result, localV1(op, "unresolved", s.blocked.err)
	}
	return ResultV1{}, nil
}

// ObserveV1 returns a detached data snapshot, retaining known blocked truth without I/O.
func (s *Store) ObserveV1() (RecordV1, error) {
	if !s.mu.TryLock() {
		return RecordV1{}, localV1("observe", "busy", nil)
	}
	defer s.mu.Unlock()
	r, failure := s.availableV1("observe")
	if s.closed || r.Truth == UNKNOWNV1 {
		return RecordV1{}, failure
	}
	v, err := decodeV1(s.image)
	if err != nil {
		return RecordV1{}, localV1("observe", "integrity", err)
	}
	if failure != nil {
		return v, failure
	}
	return v, nil
}

// RecoverV1 permits exactly one qualified read only after fully durable lost acknowledgement.
func (s *Store) RecoverV1() (ResultV1, error) {
	if !s.mu.TryLock() {
		return ResultV1{}, localV1("recover", "busy", nil)
	}
	defer s.mu.Unlock()
	if s.closed {
		return ResultV1{}, localV1("recover", "closed", nil)
	}
	p := s.blocked
	if p == nil {
		return ResultV1{}, nil
	}
	if !p.ackRead {
		return p.result, localV1("recover", "unresolved", p.err)
	}
	p.ackRead = false
	b, failure := s.readV1("recover")
	if failure != nil {
		p.err = localV1("recover", failure.Code, errors.Join(p.err, failure.Cause))
		return p.result, p.err
	}
	return s.classifyRecoverV1(p, b)
}

// classifyRecoverV1 evaluates both complete predicates and retains a terminal latch.
func (s *Store) classifyRecoverV1(p *blockedV1, b []byte) (ResultV1, error) {
	v, err := decodeV1(b)
	if err != nil {
		p.err = localV1("recover", "integrity", errors.Join(p.err, err))
		return p.result, p.err
	}
	oldEqual := bytes.Equal(b, p.old)
	newEqual := bytes.Equal(b, p.next)
	code := "unresolved"
	if oldEqual {
		p.result, code = ResultV1{OLDV1, v.Sequence, true}, "postcommit_old"
	} else if newEqual {
		p.result, code = ResultV1{NEWV1, v.Sequence, true}, "postcommit_new"
	}
	if oldEqual || newEqual {
		s.record, s.image = v, b
	}
	return p.result, localV1("recover", code, p.err)
}

// qualifyH1V1 binds only actual protected P data, never the arbitrary latest receipt owner.
func qualifyH1V1(id IdentityV1, i *IntentV1, v policycontrol.View, initial, ending bool) string {
	if !h1IdentityV1(id, i, v) {
		return "refused"
	}
	h := i.H1Binding
	if initial && v.Sequence != h.ObservedPSequence {
		return "refused"
	}
	if v.Sequence < h.ObservedPSequence {
		return "integrity"
	}
	if ending {
		return terminalH1V1(h, v)
	}
	if !liveH1V1(h, v) {
		return "refused"
	}
	return ""
}

// h1IdentityV1 checks the immutable cross-store identity and required original bridge.
func h1IdentityV1(id IdentityV1, i *IntentV1, v policycontrol.View) bool {
	return v.Identity == id.Identity && i != nil && i.H1Binding != nil
}

// liveH1V1 preserves every original field even when unrelated P transactions advance.
func liveH1V1(h *H1BindingV1, v policycontrol.View) bool {
	in := v.Incident
	if !v.HasAttempt || in == nil {
		return false
	}
	return in.State == policycontrol.StateIntent && in.Attempted && sameAdmissionV1(h, in)
}

// sameAdmissionV1 compares all original diagnosis and admission bytes and presence fields.
func sameAdmissionV1(h *H1BindingV1, in *policycontrol.Incident) bool {
	return reflect.DeepEqual(h.Diagnosis, in.Diagnosis) && reflect.DeepEqual(&h.Admission, in.Admission)
}

// terminalH1V1 recognizes only legal terminal history of the original protected admission.
func terminalH1V1(h *H1BindingV1, v policycontrol.View) string {
	if !v.HasAttempt {
		return "integrity"
	}
	in := v.Incident
	if in == nil || in.State == policycontrol.StateObserved {
		if v.Sequence <= h.ObservedPSequence {
			return "integrity"
		}
		return ""
	}
	if sameAdmissionV1(h, in) {
		if in.State == policycontrol.StateAutoBlocked && v.Sequence <= h.ObservedPSequence {
			return "integrity"
		}
		return sameOwnerTerminalV1(in)
	}
	return laterOwnerV1(h, in, v.Sequence)
}

// sameOwnerTerminalV1 distinguishes exact live INTENT from its exact terminal AUTO_BLOCKED.
func sameOwnerTerminalV1(in *policycontrol.Incident) string {
	if !in.Attempted {
		return "integrity"
	}
	switch in.State {
	case policycontrol.StateAutoBlocked:
		return ""
	case policycontrol.StateIntent:
		return "refused"
	default:
		return "integrity"
	}
}

// laterOwnerV1 requires canonical later ownership and distinct D in a legal current payload.
func laterOwnerV1(h *H1BindingV1, in *policycontrol.Incident, sequence uint64) string {
	if in.Admission == nil || !in.Attempted {
		return "integrity"
	}
	if in.State != policycontrol.StateIntent && in.State != policycontrol.StateAutoBlocked {
		return "integrity"
	}
	a := in.Admission
	if len(a.Ownership) != 40 {
		return "integrity"
	}
	epoch := binary.BigEndian.Uint64(a.Ownership[:8])
	var owner [32]byte
	copy(owner[:], a.Ownership[8:])
	current := H1BindingV1{OwnerEpoch: epoch, OwnerIntent: owner, ObservedPSequence: sequence, Diagnosis: in.Diagnosis, Admission: *a}
	return qualifyLaterOwnerV1(h, &current)
}

// qualifyLaterOwnerV1 binds the later canonical tuple and distinct exact destination.
func qualifyLaterOwnerV1(h, current *H1BindingV1) string {
	if current.OwnerEpoch <= h.OwnerEpoch || current.OwnerIntent == h.OwnerIntent {
		return "integrity"
	}
	if bytes.Equal(current.Admission.Destination, h.Admission.Destination) {
		return "integrity"
	}
	c := wireV1{validating: true}
	c.h1(current)
	if c.err != nil {
		return "integrity"
	}
	return canonicalAdmissionV1(&current.Admission)
}

// canonicalAdmissionV1 requires the released exact leaf grammar on both current P locations.
func canonicalAdmissionV1(a *policycontrol.Admission) string {
	if _, err := DecodeDatabaseLocationV1(a.Old); err != nil {
		return "integrity"
	}
	d, err := DecodeDatabaseLocationV1(a.Destination)
	if err != nil || d.Form != 2 {
		return "integrity"
	}
	return ""
}
