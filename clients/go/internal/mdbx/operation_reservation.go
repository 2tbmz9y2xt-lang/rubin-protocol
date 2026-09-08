package mdbx

import (
	"errors"
	"sync"
)

// MaxOperationDataBytes bounds the bytes one storage operation may reserve.
const MaxOperationDataBytes uint64 = 154_611_151

var (
	errOperationReservationLimit    = errors.New("invalid storage operation reservation limit")
	errOperationReservationInput    = errors.New("invalid storage operation reservation input")
	errOperationReservationCapacity = errors.New("storage operation reservation capacity unavailable")
)

// operationReservationState is the one aggregate every copy of an owner shares.
type operationReservationState struct {
	mu    sync.Mutex
	limit uint64
	live  uint64
}

// operationReservationGrant is the released-once record every copy of a token shares.
type operationReservationGrant struct {
	bytes    uint64
	released bool
}

// operationReservationToken identifies one admission by its issuing owner state and grant.
type operationReservationToken struct {
	origin *operationReservationState
	grant  *operationReservationGrant
}

// OperationReservationOwner admits storage operation bytes against one process-local
// limit. Every copy of an owner shares the same limit and live counter, nothing is
// persisted, and the zero value refuses every reservation.
type OperationReservationOwner struct {
	state *operationReservationState
}

// NewOperationReservationOwner returns an owner with zero live bytes whose limit is at
// least MaxOperationDataBytes, or errOperationReservationLimit for a smaller limit.
func NewOperationReservationOwner(limit uint64) (*OperationReservationOwner, error) {
	if limit < MaxOperationDataBytes {
		return nil, errOperationReservationLimit
	}
	return &OperationReservationOwner{state: &operationReservationState{limit: limit}}, nil
}

// reserve charges bytes to the live counter and returns its token; it refuses without
// change when bytes exceeds MaxOperationDataBytes, the live counter exceeds the limit,
// or bytes exceeds the remaining capacity.
func (o *OperationReservationOwner) reserve(bytes uint64) (operationReservationToken, error) {
	s := o.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if bytes > MaxOperationDataBytes || s.live > s.limit || bytes > s.limit-s.live {
		return operationReservationToken{}, errOperationReservationCapacity
	}
	s.live += bytes
	return operationReservationToken{origin: s, grant: &operationReservationGrant{bytes: bytes}}, nil
}

// release subtracts the bytes of an unreleased token issued by this owner and reports
// whether it did; a nil, foreign, released or oversized token changes nothing.
func (o *OperationReservationOwner) release(token operationReservationToken) bool {
	s := o.state
	s.mu.Lock()
	defer s.mu.Unlock()
	g := token.grant
	if g == nil || token.origin != s || g.released || g.bytes > s.live {
		return false
	}
	g.released = true
	s.live -= g.bytes
	return true
}

// WithReservation runs callback once in the calling goroutine while bytes are charged
// and releases them before the callback's return, panic or Goexit leaves this frame. A
// nil owner, nil owner state or nil callback returns errOperationReservationInput and a
// refused charge returns errOperationReservationCapacity; neither runs callback.
func (o *OperationReservationOwner) WithReservation(bytes uint64, callback func() error) error {
	if o == nil || o.state == nil || callback == nil {
		return errOperationReservationInput
	}
	token, err := o.reserve(bytes)
	if err != nil {
		return err
	}
	defer o.release(token)
	return callback()
}
