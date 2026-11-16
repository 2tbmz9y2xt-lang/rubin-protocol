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
	live     uint64
	span     *servingMutationV1
	changed  chan struct{}
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

// servingMutationV1 owns one live invocation; its nonzero size preserves identity.
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
	if o.current != nil || o.live != 0 || o.span != nil {
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
	o.notifyV1()
}

// requestServingCloseV1 is optional and never changes native admission/errors.
// Its scope ends at this invocation's return, including a failed TryLock.
func (s *Store) requestServingCloseV1() *servingMutationV1 {
	o := s.servingOwner.Load()
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.markV1()
}

// contendedServingCloseV1 refreshes eligibility if binding happened after entry.
func (s *Store) contendedServingCloseV1() {
	o := s.servingOwner.Load()
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.current != nil {
		o.current.closing = true
	}
}

// markV1 registers one material live scope and ends eligibility only, under mu.
func (o *ServingViewOwnerV1) markV1() *servingMutationV1 {
	m := &servingMutationV1{owner: o}
	o.live++
	if o.current != nil {
		o.current.closing = true
	}
	return m
}

// completeV1 retires only this invocation, without masking an unlock notification.
func (m *servingMutationV1) completeV1() {
	if m == nil {
		return
	}
	o := m.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	o.live--
}

// WithQuiescenceV1 holds serving exclusion through the synchronous source
// effect and cleanup in use. The caller owns semantic admission and projects a
// refusal to its existing storage_concurrency/OLD result. This is required only
// at an actual semantic trigger; optional native closures must not call it.
// Waits and use hold no coordinator/native lock; effects and cleanup cannot escape.
// Invoke outside a View/native callback or span whose completion it must await.
// use must not await another caller blocked by this span. Native retries elected
// by use remain inside this invocation and its original work/account/deadline.
func (o *ServingViewOwnerV1) WithQuiescenceV1(ctx context.Context, s *Store, use func() error) error {
	if err := o.inputV1(ctx, s, use != nil, operationUpdate); err != nil {
		return err
	}
	if err := o.bindV1(s, operationUpdate); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m := s.requestServingCloseV1()
	defer m.completeV1()
	if err := o.waitSpanV1(ctx, m); err != nil {
		return err
	}
	defer o.finishSpanV1(m)
	if err := o.waitNativeV1(ctx, s); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return use()
}

// admitSpanV1 captures the ownership generation; false refuses a finished retained view.
func (o *ServingViewOwnerV1) admitSpanV1(m *servingMutationV1) (<-chan struct{}, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.current != nil && o.current.finished {
		return nil, false
	}
	if o.current != nil || o.span != nil {
		return o.generationV1(), true
	}
	o.span = m
	return nil, true
}

// waitSpanV1 preserves this scope until actual view/span completion or cancellation.
func (o *ServingViewOwnerV1) waitSpanV1(ctx context.Context, m *servingMutationV1) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		changed, permitted := o.admitSpanV1(m)
		if !permitted {
			return servingBusyV1(operationUpdate)
		}
		if changed == nil {
			return nil
		}
		done := ctx.Done()
		select {
		case <-changed:
		case <-done:
		}
	}
}

// waitNativeV1 reserves the span across lock contention and never replays use.
func (o *ServingViewOwnerV1) waitNativeV1(ctx context.Context, s *Store) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		o.mu.Lock()
		changed := o.generationV1()
		o.mu.Unlock()
		if err, acquired := s.servingPreflightV1(); acquired {
			return err
		}
		done := ctx.Done()
		select {
		case <-changed:
		case <-done:
		}
	}
}

// servingPreflightV1 observes Store health only under its existing operation lock.
func (s *Store) servingPreflightV1() (error, bool) {
	if !s.operations.TryLock() {
		return nil, false
	}
	defer s.notifyServingCompletionV1()
	defer s.operations.Unlock()
	err, _ := s.observationStateError(operationUpdate)
	return err, true
}

// finishSpanV1 releases only the matching span after actual synchronous cleanup.
func (o *ServingViewOwnerV1) finishSpanV1(m *servingMutationV1) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.span == m {
		o.span = nil
		o.notifyV1()
	}
}

// generationV1 lazily captures one shared completion channel, under mu.
func (o *ServingViewOwnerV1) generationV1() <-chan struct{} {
	if o.changed == nil {
		o.changed = make(chan struct{})
	}
	return o.changed
}

// notifyV1 publishes a completed ownership transition to captured waiters, under mu.
func (o *ServingViewOwnerV1) notifyV1() {
	if o.changed != nil {
		close(o.changed)
		o.changed = nil
	}
}

// notifyServingCompletionV1 observes binding at completion, after native Unlock.
func (s *Store) notifyServingCompletionV1() {
	if o := s.servingOwner.Load(); o != nil {
		o.mu.Lock()
		o.notifyV1()
		o.mu.Unlock()
	}
}
