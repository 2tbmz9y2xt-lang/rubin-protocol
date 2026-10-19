package mdbx

import (
	"errors"
	"sync"
)

// LaneMaxBytes (LANE_MAX) is the reservation ceiling of every storage operation other than
// a complete-block tree-integrated one; TreeLaneMaxBytes (TREE_LANE_MAX) is the ceiling of
// one complete-block tree-integrated operation; MinReservationLimit (R_MIN = R_DEFAULT) is
// the smallest aggregate limit under which an owner admits any charge.
const (
	LaneMaxBytes        uint64 = 154_611_183
	TreeLaneMaxBytes    uint64 = 402_653_184
	MinReservationLimit uint64 = 805_306_368
)

// MaxOperationDataBytes is the legacy SchemaV2 grant, page and consulted-image budget that
// existing callers charge per operation. It is not the owner's ceiling, which is
// LaneMaxBytes for a LaneOperation. It equals the cgo-only MaxPrefixPageBytes of
// mdbx_cgo.go and is declared here because this file also builds without cgo.
const MaxOperationDataBytes uint64 = 154_611_151

// The legacy budget never exceeds LANE_MAX.
const _ = LaneMaxBytes - MaxOperationDataBytes

// OperationKind fixes an operation's reservation ceiling before its first charge.
type OperationKind uint8

const (
	// LaneOperation is bounded by LaneMaxBytes.
	LaneOperation OperationKind = iota + 1
	// TreeOperation is one complete-block tree-integrated operation, bounded by TreeLaneMaxBytes.
	TreeOperation
)

var (
	errOperationReservationInput    = errors.New("invalid storage operation reservation input")
	errOperationReservationCapacity = errors.New("storage operation reservation capacity unavailable")
)

// IsOperationReservationCapacity reports only the owner's direct capacity refusal.
func IsOperationReservationCapacity(err error) bool {
	return any(err) == any(errOperationReservationCapacity)
}

// ceiling returns the reservation ceiling of k and whether k is a defined kind.
func (k OperationKind) ceiling() (uint64, bool) {
	switch k {
	case LaneOperation:
		return LaneMaxBytes, true
	case TreeOperation:
		return TreeLaneMaxBytes, true
	}
	return 0, false
}

// operationReservationState is the one aggregate every copy of an owner shares.
type operationReservationState struct {
	mu    sync.Mutex
	limit uint64
	live  uint64
}

// operationAccountState is the per-operation sum every copy of an account shares; held and
// closed are guarded by the owner state's mutex.
type operationAccountState struct {
	origin  *operationReservationState
	ceiling uint64
	held    uint64
	closed  bool
}

// operationReservationGrant is the released-once record every copy of a token shares;
// account is nil for a legacy owner charge.
type operationReservationGrant struct {
	bytes    uint64
	released bool
	account  *operationAccountState
}

// operationReservationToken identifies one admission by its issuing owner state and grant.
type operationReservationToken struct {
	origin *operationReservationState
	grant  *operationReservationGrant
}

// OperationReservationOwner admits storage operation bytes against one process-local
// aggregate limit. Every copy of an owner shares the same limit and live counter, nothing
// is persisted, and the zero value refuses every call. An owner below MinReservationLimit
// refuses every charge with the capacity refusal; it never latches or clamps. An owner and
// every copy of it is safe for concurrent use.
//
// A tree-integrated operation opens exactly one WithOperation(TreeOperation) before its
// first charge and charges every primitive only through that account; an owner
// WithReservation or WithOperation call made while it is open is a separate operation
// outside that account's sum.
type OperationReservationOwner struct {
	shared *operationReservationState
}

// OperationAccount is one open operation's reservation account. Every charge on it, nested
// or from any goroutine, adds to one held sum bounded by its kind's ceiling. The zero value
// and an account whose WithOperation callback has left refuse every charge with the input
// refusal. Use it only through the pointer WithOperation passes.
type OperationAccount struct {
	shared *operationAccountState
}

// NewOperationReservationOwner returns an owner with zero live bytes and limit for every
// limit; the error is always nil.
func NewOperationReservationOwner(limit uint64) (*OperationReservationOwner, error) {
	return &OperationReservationOwner{shared: &operationReservationState{limit: limit}}, nil
}

// admits is the capacity precheck of bytes on an operation holding held of ceiling.
func (s *operationReservationState) admits(ceiling, held, bytes uint64) bool {
	return s.limit >= MinReservationLimit && bytes <= ceiling-held && s.live <= s.limit && bytes <= s.limit-s.live
}

// reserve charges bytes to the live counter and to account (nil: a one-charge
// LaneOperation) and returns its token. A closed account refuses with the input refusal;
// a failed capacity precheck refuses with the capacity refusal; neither changes anything.
func (s *operationReservationState) reserve(account *operationAccountState, bytes uint64) (operationReservationToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ceiling, held := LaneMaxBytes, uint64(0)
	if account != nil {
		if account.closed {
			return operationReservationToken{}, errOperationReservationInput
		}
		ceiling, held = account.ceiling, account.held
	}
	if !s.admits(ceiling, held, bytes) {
		return operationReservationToken{}, errOperationReservationCapacity
	}
	s.live += bytes
	if account != nil {
		account.held += bytes
	}
	return operationReservationToken{origin: s, grant: &operationReservationGrant{bytes: bytes, account: account}}, nil
}

// release subtracts the bytes of an unreleased token issued by this state from the live
// counter and its account and reports whether it did; a nil, foreign, released or
// oversized token changes nothing. The report is the exactly-once signal for same-package
// callers.
func (s *operationReservationState) release(token operationReservationToken) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := token.grant
	if g == nil || token.origin != s {
		return false
	}
	if g.released || g.bytes > s.live {
		return false
	}
	g.released = true
	s.live -= g.bytes
	if g.account != nil {
		g.account.held -= g.bytes
	}
	return true
}

// close marks account closed; held charges stay until their own frames release them.
func (s *operationReservationState) close(account *operationAccountState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	account.closed = true
}

// withReservation charges bytes to account, runs callback once and releases the charge
// exactly once when the callback's return, panic or Goexit leaves this frame.
func (s *operationReservationState) withReservation(account *operationAccountState, bytes uint64, callback func() error) error {
	token, err := s.reserve(account, bytes)
	if err != nil {
		return err
	}
	defer s.release(token)
	return callback()
}

// WithOperation runs callback once, synchronously in the calling goroutine, with a fresh
// open account of kind holding zero bytes, closes that account when the callback returns,
// panics or calls Goexit, and returns the callback's error unchanged (nil on success). It
// performs no capacity check and charges nothing; it neither waits for nor releases charges
// still held on the account. A nil or zero-value owner, a nil callback or a kind other than
// LaneOperation and TreeOperation returns errOperationReservationInput without running
// callback.
func (o *OperationReservationOwner) WithOperation(kind OperationKind, callback func(*OperationAccount) error) error {
	if o == nil || o.shared == nil || callback == nil {
		return errOperationReservationInput
	}
	ceiling, ok := kind.ceiling()
	if !ok {
		return errOperationReservationInput
	}
	s := o.shared
	account := &operationAccountState{origin: s, ceiling: ceiling}
	defer s.close(account)
	return callback(&OperationAccount{shared: account})
}

// WithReservation charges bytes to the account and the owner's aggregate, runs callback
// once, synchronously in the calling goroutine, and releases the charge before the
// callback's return, panic or Goexit leaves this frame; it returns the callback's error
// unchanged (nil on success). A nil, zero-value or closed account or a nil callback returns
// errOperationReservationInput, and a refused charge (owner limit below
// MinReservationLimit, bytes above the ceiling minus held, or above the aggregate
// remainder) returns errOperationReservationCapacity; neither runs callback or changes any
// counter. Charges may be released in any order.
func (a *OperationAccount) WithReservation(bytes uint64, callback func() error) error {
	if a == nil || a.shared == nil || callback == nil {
		return errOperationReservationInput
	}
	return a.shared.origin.withReservation(a.shared, bytes, callback)
}

// WithReservation runs callback once, synchronously in the calling goroutine, while bytes
// are charged as one LaneOperation of its own; it releases them before the callback's
// return, panic or Goexit leaves this frame and then returns the callback's error unchanged
// (nil on success). A nil or zero-value owner or a nil callback returns
// errOperationReservationInput and a refused charge returns errOperationReservationCapacity;
// neither runs callback. The reservation cannot be transferred: work the callback hands to
// a goroutine, queue or task that outlives the call runs uncharged. A nested call inside
// callback is a competing operation whose bytes are charged in addition.
func (o *OperationReservationOwner) WithReservation(bytes uint64, callback func() error) error {
	if o == nil || o.shared == nil || callback == nil {
		return errOperationReservationInput
	}
	return o.shared.withReservation(nil, bytes, callback)
}
