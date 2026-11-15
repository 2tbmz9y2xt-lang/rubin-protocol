//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"context"
	"sync"
	"time"
)

// ServingReadEndV1 reports actual read consumption, separately from eligibility.
type ServingReadEndV1 uint8

const (
	// ServingNoReadV1 means no native read transaction was acquired.
	ServingNoReadV1 ServingReadEndV1 = iota
	// ServingConsumedHealthyV1 means the read was consumed and Store remained OPEN.
	ServingConsumedHealthyV1
	// ServingConsumedTerminalV1 includes a consumed read with a retained environment.
	ServingConsumedTerminalV1
	// ServingRetainedV1 means actual read ownership remains with the native Store.
	ServingRetainedV1
)

// ServingViewOutcomeV1 is an observation, never source qualification or a lease.
// The zero value reports no acquired read and grants no close permission.
type ServingViewOutcomeV1 struct {
	readEnd          ServingReadEndV1
	eligibilityEnded bool
	opened           time.Time
}

// ReadEndV1 returns the actual native read disposition observed before unlock.
func (o ServingViewOutcomeV1) ReadEndV1() ServingReadEndV1 { return o.readEnd }

// EligibilityEndedV1 reports expiry or internal closure, excluding request cancellation.
func (o ServingViewOutcomeV1) EligibilityEndedV1() bool { return o.eligibilityEnded }

// ServingViewOwnerV1 serializes one finite synchronous serving borrow and source
// exclusion spans. Install one node-global owner across selected Store replacement;
// neither construction nor a successful call qualifies a serving source.
// Do not copy an owner. Its zero value refuses admission.
type ServingViewOwnerV1 struct {
	mu       sync.Mutex
	self     *ServingViewOwnerV1
	lifetime time.Duration
	current  *ServingEpochV1
	priority *servingMutationV1
	span     *servingMutationV1
}

// ServingEpochV1 is valid only inside its synchronous WithViewV1 callback.
// Call CheckV1 before every protected read/proof/copy and after completing an
// owned output copy. Qualification consumes the original lifetime. No Reader,
// epoch, cursor or borrowed buffer may escape or be used by another goroutine.
type ServingEpochV1 struct {
	self     *ServingEpochV1
	owner    *ServingViewOwnerV1
	store    *Store
	request  context.Context
	opened   time.Time
	closing  bool
	finished bool
}

// servingMutationV1 identifies one attempt; its nonzero size preserves identity.
type servingMutationV1 struct {
	owner *ServingViewOwnerV1
}

// NewServingViewOwnerV1 requires an explicit positive finite lifetime.
func NewServingViewOwnerV1(lifetime time.Duration) (*ServingViewOwnerV1, error) {
	if lifetime <= 0 {
		return nil, servingInputV1(operationView)
	}
	o := &ServingViewOwnerV1{lifetime: lifetime}
	o.self = o
	return o, nil
}

// servingInputV1 preserves the finite local input tuple.
func servingInputV1(operation engineOperation) error {
	return adapterError(operation, EngineInvalidInput, codeEINVAL, "invalid serving view input", nil)
}

// servingBusyV1 preserves native contention's class, code and diagnostic.
func servingBusyV1(operation engineOperation) error {
	return adapterError(operation, EngineConcurrency, codeBusy, "store operation in progress", nil)
}

// inputV1 checks static input without touching admission, native state or context.
func (o *ServingViewOwnerV1) inputV1(ctx context.Context, s *Store, callback bool, operation engineOperation) error {
	switch {
	case o == nil:
	case o.self != o || o.lifetime <= 0:
	case s == nil:
	case ctx == nil:
	case !callback:
	default:
		return nil
	}
	return servingInputV1(operation)
}

// bindV1 installs the sole owner of s without reading native fields.
func (o *ServingViewOwnerV1) bindV1(s *Store, operation engineOperation) error {
	bound := s.servingOwner.Load()
	if bound == o {
		return nil
	}
	if bound == nil && s.servingOwner.CompareAndSwap(nil, o) {
		return nil
	}
	if s.servingOwner.Load() != o {
		return servingInputV1(operation)
	}
	return nil
}

// servingLaneV1 accepts only the existing open LaneOperation, without a charge.
func servingLaneV1(a *OperationAccount) bool {
	if a == nil || a.shared == nil || a.shared.origin == nil {
		return false
	}
	return a.openV1() && a.shared.ceiling == LaneMaxBytes
}

// WithViewV1 borrows one native snapshot until callback cleanup completes. The
// caller supplies its open LaneOperation; this method creates no account or
// reservation and imposes no earlier capacity precheck. use must qualify this
// same snapshot through the actual semantic producers before any serving use.
// Owned output needs an independent network owner and a final CheckV1.
func (o *ServingViewOwnerV1) WithViewV1(ctx context.Context, s *Store, account *OperationAccount, use func(*Reader, *ServingEpochV1) error) (out ServingViewOutcomeV1, err error) {
	if err := o.inputV1(ctx, s, use != nil, operationView); err != nil {
		return out, err
	}
	if !servingLaneV1(account) {
		return out, errOperationReservationInput
	}
	if err := o.bindV1(s, operationView); err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	epoch, admission := o.admitViewV1(ctx, s)
	if admission != nil {
		return out, admission
	}
	defer o.finishViewV1(epoch, &out)
	err, _ = s.viewWithStartupCompletion(func(r *Reader) (StartupCanonicalCompletionV1, error) {
		if opening := epoch.openV1(out.opened); opening != nil {
			return StartupCanonicalNotCompleteV1, opening
		}
		return StartupCanonicalNotCompleteV1, use(r, epoch)
	}, false, &out)
	return out, err
}

// admitViewV1 occupies OPENING before attempting the existing native View lock.
func (o *ServingViewOwnerV1) admitViewV1(ctx context.Context, s *Store) (*ServingEpochV1, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.current != nil || o.priority != nil || o.span != nil {
		return nil, servingBusyV1(operationView)
	}
	e := &ServingEpochV1{owner: o, store: s, request: ctx}
	e.self = e
	o.current = e
	return e, nil
}

// servingOpeningV1 stamps the actual native begin boundary. Native begin and
// Reader construction/qualification consume this lifetime, never extend it.
func servingOpeningV1(out *ServingViewOutcomeV1) {
	if out != nil {
		out.opened = time.Now()
	}
}

// openV1 publishes the original native opening time, without restarting it.
func (e *ServingEpochV1) openV1(opened time.Time) error {
	o := e.owner
	o.mu.Lock()
	e.opened = opened
	o.mu.Unlock()
	return e.CheckV1()
}

// CheckV1 checks this live epoch without I/O; equality at the deadline remains
// eligible. Expiry stops the next unit but keeps the native borrow occupied.
func (e *ServingEpochV1) CheckV1() error {
	if e == nil || e.self != e {
		return servingInputV1(operationView)
	}
	o := e.owner
	o.mu.Lock()
	finished := e.finished
	eligible := o.current == e && e.store.servingOwner.Load() == o && !e.endedV1(time.Since(e.opened))
	o.mu.Unlock()
	if finished {
		return servingInputV1(operationView)
	}
	if err := e.request.Err(); err != nil {
		return err
	}
	if !eligible {
		return servingBusyV1(operationView)
	}
	return nil
}

// endedV1 compares elapsed monotonic time with the original lifetime, under mu.
func (e *ServingEpochV1) endedV1(elapsed time.Duration) bool {
	return e.closing || !e.opened.IsZero() && elapsed > e.owner.lifetime
}

// finishViewV1 runs after the shared View's actual abort and operation unlock,
// including panic/Goexit. Retained native ownership never frees the occupied slot.
func (o *ServingViewOwnerV1) finishViewV1(e *ServingEpochV1, out *ServingViewOutcomeV1) {
	o.mu.Lock()
	defer o.mu.Unlock()
	out.eligibilityEnded = e.endedV1(time.Since(e.opened))
	e.finished = true
	if o.current == e && out.readEnd != ServingRetainedV1 {
		o.current = nil
	}
}

// requestServingCloseV1 is optional and never changes native admission/errors.
// The attempt's mark survives a failed TryLock until an actual retry completes.
func (s *Store) requestServingCloseV1() *servingMutationV1 {
	o := s.servingOwner.Load()
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.markV1()
}

// contendedServingCloseV1 covers first binding after a nil initial observation.
// An already-marked attempt must not replace a newer pending identity.
func (s *Store) contendedServingCloseV1(initial *servingMutationV1) {
	if initial == nil {
		s.requestServingCloseV1()
	}
}

// markV1 installs the latest bounded identity and ends eligibility only.
func (o *ServingViewOwnerV1) markV1() *servingMutationV1 {
	m := &servingMutationV1{owner: o}
	o.priority = m
	if o.current != nil {
		o.current.closing = true
	}
	return m
}

// completeV1 ends only this attempt's priority, after native unlock/cleanup.
func (m *servingMutationV1) completeV1() {
	if m == nil {
		return
	}
	o := m.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.priority == m {
		o.priority = nil
	}
}

// WithQuiescenceV1 holds serving exclusion through the synchronous source
// effect and cleanup in use. The caller owns semantic admission and projects a
// refusal to its existing storage_concurrency/OLD result. This is required only
// at an actual semantic trigger; optional native closures must not call it.
// No coordinator/native lock is held across use, and no effect may escape it.
func (o *ServingViewOwnerV1) WithQuiescenceV1(ctx context.Context, s *Store, use func() error) error {
	if err := o.inputV1(ctx, s, use != nil, operationUpdate); err != nil {
		return err
	}
	if err := o.bindV1(s, operationUpdate); err != nil {
		return err
	}
	m, err := o.admitSpanV1()
	if err != nil {
		return err
	}
	completed := false
	defer func() { o.finishSpanV1(m, completed) }()
	if err, completed = s.servingPreflightV1(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return use()
}

// admitSpanV1 requests closure before testing actual ownership, without waiting.
func (o *ServingViewOwnerV1) admitSpanV1() (*servingMutationV1, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	m := o.markV1()
	if o.current != nil || o.span != nil {
		return nil, servingBusyV1(operationUpdate)
	}
	o.span = m
	return m, nil
}

// servingPreflightV1 observes Store health only under its existing operation lock.
func (s *Store) servingPreflightV1() (error, bool) {
	if !s.operations.TryLock() {
		return servingBusyV1(operationUpdate), false
	}
	defer s.operations.Unlock()
	err, _ := s.observationStateError(operationUpdate)
	return err, true
}

// finishSpanV1 preserves a newer contender and never derives truth from use.
func (o *ServingViewOwnerV1) finishSpanV1(m *servingMutationV1, completed bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.span == m {
		o.span = nil
	}
	if completed && o.priority == m {
		o.priority = nil
	}
}
