package paircontrol

import (
	"bytes"
	"context"
	"errors"
	"math"
	"reflect"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

// changeV1 is one closed internal request, never a caller-supplied transition callback.
type changeV1 struct {
	op       string
	expected uint64
	intent   IntentV1
	id       [32]byte
	old      PairBindingV1
	ref      ReferenceV1
	p        *policycontrol.Store
}

// PersistIntentV1 records one exact qualified replacement source, without creating D.
func (s *Store) PersistIntentV1(ctx context.Context, expected uint64, intent IntentV1, p *policycontrol.Store) (ResultV1, error) {
	return s.changeV1(ctx, changeV1{op: "persist_intent", expected: expected, intent: intent, p: p})
}

// RetireV1 records the caller's qualified no-OLD-service disposition, never native closure.
func (s *Store) RetireV1(ctx context.Context, expected uint64, id [32]byte, ref ReferenceV1, p *policycontrol.Store) (ResultV1, error) {
	return s.changeV1(ctx, changeV1{op: "retire", expected: expected, id: id, ref: ref, p: p})
}

// RecordDamageV1 preserves existing source ownership while recording positive no-service data.
func (s *Store) RecordDamageV1(ctx context.Context, expected uint64, old PairBindingV1, ref ReferenceV1) (ResultV1, error) {
	return s.changeV1(ctx, changeV1{op: "damage", expected: expected, old: old, ref: ref})
}

// EndH1V1 removes only historical intent bookkeeping after qualified terminal P.
func (s *Store) EndH1V1(ctx context.Context, expected uint64, id [32]byte, p *policycontrol.Store) (ResultV1, error) {
	return s.changeV1(ctx, changeV1{op: "end_h1", expected: expected, id: id, p: p})
}

// staticV1 reuses released field owners before cancellation or operation acquisition.
func (q *changeV1) staticV1() error {
	switch q.op {
	case "persist_intent":
		return q.intentDomainV1()
	case "retire":
		return q.retireDomainV1()
	case "damage":
		c := wireV1{validating: true}
		c.pair(&q.old)
		c.reference(&q.ref)
		return c.err
	case "end_h1":
		if q.id == [32]byte{} || q.p == nil {
			return errShapeV1
		}
	}
	return nil
}

// intentDomainV1 rejects H1/operator extra or missing P payload before acquisition.
func (q *changeV1) intentDomainV1() error {
	c := wireV1{validating: true}
	c.intent(&q.intent)
	if (q.intent.Origin == 3) != (q.p != nil) {
		return errShapeV1
	}
	return c.err
}

// retireDomainV1 checks the independently caller-owned ID/result fields.
func (q *changeV1) retireDomainV1() error {
	c := wireV1{validating: true}
	c.reference(&q.ref)
	if q.id == [32]byte{} {
		return errShapeV1
	}
	return c.err
}

// changeV1 enforces static/context/try-lock/state/CAS/transition/P/effect order.
func (s *Store) changeV1(ctx context.Context, q changeV1) (ResultV1, error) {
	old, admitted, err := s.admitChangeV1(ctx, &q)
	if !admitted {
		return old, err
	}
	defer s.mu.Unlock()
	next, code := s.prepareV1(&q)
	if code != "" {
		return old, localV1(q.op, code, errShapeV1)
	}
	b, err := encodeV1(next)
	if err != nil {
		return old, localV1(q.op, "refused", err)
	}
	if !bytes.Equal(b, s.image) && next.Sequence == math.MaxUint64 {
		return s.exhaustedV1(q.op)
	}
	next, err = decodeV1(b)
	if err != nil {
		return old, localV1(q.op, "integrity", err)
	}
	return s.protectedChangeV1(&q, next, b)
}

// admitChangeV1 transfers the try-lock only after ordered entry qualification succeeds.
func (s *Store) admitChangeV1(ctx context.Context, q *changeV1) (ResultV1, bool, error) {
	if err := q.staticV1(); err != nil {
		return ResultV1{}, false, localV1(q.op, "refused", err)
	}
	if ctx == nil {
		return ResultV1{}, false, localV1(q.op, "refused", errShapeV1)
	}
	if err := ctx.Err(); err != nil {
		return ResultV1{}, false, localV1(q.op, "precommit", err)
	}
	if !s.mu.TryLock() {
		return ResultV1{}, false, localV1(q.op, "busy", nil)
	}
	if result, err := s.availableV1(q.op); err != nil {
		s.mu.Unlock()
		return result, false, err
	}
	old := ResultV1{Truth: OLDV1, Sequence: s.record.Sequence}
	if q.expected != s.record.Sequence {
		s.mu.Unlock()
		return old, false, localV1(q.op, "stale", nil)
	}
	return old, true, nil
}

// exhaustedV1 latches the local invariant before P admission or filesystem effects.
func (s *Store) exhaustedV1(op string) (ResultV1, error) {
	r := ResultV1{Truth: OLDV1, Sequence: s.record.Sequence, Latched: true}
	e := localV1(op, "refused", errors.New("paircontrol: sequence exhausted"))
	s.blocked = &blockedV1{result: r, err: e}
	return r, e
}

// prepareV1 starts from a detached complete preimage and delegates the closed operation.
func (s *Store) prepareV1(q *changeV1) (RecordV1, string) {
	v, err := decodeV1(s.image)
	if err != nil {
		return RecordV1{}, "integrity"
	}
	switch q.op {
	case "persist_intent":
		return prepareIntentV1(v, q.intent)
	case "retire":
		return prepareRetireV1(v, q)
	case "damage":
		return prepareDamageV1(v, q)
	case "end_h1":
		return prepareEndV1(v, q.id)
	}
	return v, "refused"
}

// prepareEndV1 preserves every selector byte while matching the exact historical owner.
func prepareEndV1(v RecordV1, id [32]byte) (RecordV1, string) {
	if v.Intent == nil || v.Intent.Origin != 3 || v.Intent.ID != id {
		return v, "stale"
	}
	v.Intent = nil
	return v, ""
}

// originalV1 returns identity data for selected or unavailable original OLD.
func originalV1(v RecordV1) *PairBindingV1 {
	if v.Selector == 2 {
		return v.Selected
	}
	if v.Selector == 3 {
		return &v.Retired.Old
	}
	return nil
}

// prepareIntentV1 refuses a changed live intent without altering its original payload.
func prepareIntentV1(v RecordV1, i IntentV1) (RecordV1, string) {
	old := originalV1(v)
	if old == nil {
		return v, "refused"
	}
	if *old != *i.Old {
		return v, "stale"
	}
	if v.Intent != nil {
		if !reflect.DeepEqual(v.Intent, &i) {
			return v, "refused"
		}
		return v, ""
	}
	v.Intent = &i
	return v, ""
}

// prepareRetireV1 preserves the exact intent and admits only ECONOMY/H1 retirement.
func prepareRetireV1(v RecordV1, q *changeV1) (RecordV1, string) {
	i := v.Intent
	if code := retireOriginV1(i, q); code != "" {
		return v, code
	}
	reason := uint8(1)
	if i.Origin == 3 {
		reason = 2
	}
	r := RetirementV1{Old: *i.Old, Reason: reason, Result: q.ref}
	if v.Selector == 3 {
		if !reflect.DeepEqual(v.Retired, &r) {
			return v, "refused"
		}
		return v, ""
	}
	v.Selector, v.Selected, v.Retired = 3, nil, &r
	return v, ""
}

// retireOriginV1 separates exact owner matching from the finite retirement projection.
func retireOriginV1(i *IntentV1, q *changeV1) string {
	if i == nil || i.ID != q.id {
		return "stale"
	}
	if i.Origin == 2 {
		return "refused"
	}
	if (i.Origin == 3) != (q.p != nil) {
		return "refused"
	}
	return ""
}

// prepareDamageV1 copies the positive result without interpreting its opaque source.
func prepareDamageV1(v RecordV1, q *changeV1) (RecordV1, string) {
	old := originalV1(v)
	if old == nil || *old != q.old {
		return v, "stale"
	}
	r := RetirementV1{Old: q.old, Reason: 3, Result: q.ref}
	if v.Selector == 3 {
		if !reflect.DeepEqual(v.Retired, &r) {
			return v, "refused"
		}
		return v, ""
	}
	v.Selector, v.Selected, v.Retired = 3, nil, &r
	return v, ""
}

// protectedChangeV1 records callback entry independently of its error's sentinel identity.
func (s *Store) protectedChangeV1(q *changeV1, next RecordV1, b []byte) (ResultV1, error) {
	if q.p == nil {
		return s.applyV1(q.op, next, b)
	}
	entered := false
	var result ResultV1
	var outcome error
	err := q.p.WithDependentViewV1(func(view policycontrol.View) error {
		entered = true
		result, outcome = s.h1ChangeV1(q, next, view)
		return outcome
	})
	if entered {
		return result, outcome
	}
	return ResultV1{Truth: OLDV1, Sequence: s.record.Sequence}, localV1(q.op, "refused", err)
}

// h1ChangeV1 keeps P qualified through encoding, readback and every cleanup barrier.
func (s *Store) h1ChangeV1(q *changeV1, next RecordV1, view policycontrol.View) (ResultV1, error) {
	i := next.Intent
	if q.op == "end_h1" {
		i = s.record.Intent
	}
	initial := q.op == "persist_intent" && s.record.Intent == nil
	code := qualifyH1V1(s.record.Identity, i, view, initial, q.op == "end_h1")
	if code != "" {
		return ResultV1{Truth: OLDV1, Sequence: s.record.Sequence}, localV1(q.op, code, errShapeV1)
	}
	b, err := encodeV1(next)
	if err != nil {
		return ResultV1{Truth: OLDV1, Sequence: s.record.Sequence}, localV1(q.op, "refused", err)
	}
	return s.applyV1(q.op, next, b)
}

// applyV1 checks the final complete image before incrementing or acquiring private leaves.
func (s *Store) applyV1(op string, next RecordV1, b []byte) (ResultV1, error) {
	if bytes.Equal(s.image, b) {
		return ResultV1{Truth: OLDV1, Sequence: s.record.Sequence}, nil
	}
	next.Sequence++
	b, err := encodeV1(next)
	if err != nil {
		return ResultV1{Truth: OLDV1, Sequence: s.record.Sequence}, localV1(op, "refused", err)
	}
	owned, err := decodeV1(b)
	if err != nil {
		return ResultV1{Truth: OLDV1, Sequence: s.record.Sequence}, localV1(op, "refused", err)
	}
	r, failure := s.crossV1(op, owned, b, false)
	if failure != nil {
		return r, failure
	}
	return r, nil
}
