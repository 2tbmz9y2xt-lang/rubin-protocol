package p2p

import (
	"errors"
	"math"
	"sync"
)

const (
	defaultInboundBlockBudgetBytes = 1 << 30
	minInboundBlockBudgetBytes     = 1 << 30
	maxInboundBlockBudgetBytes     = 8 << 30
	inboundBudgetCapacityResource  = "inbound_budget_capacity"
	inboundBudgetOverflowResource  = "inbound_budget_overflow"
)

var (
	errInboundBlockBudgetRange = errors.New("inbound block budget must be zero or between 1073741824 and 8589934592 bytes")
	errInboundBlockCommand     = errors.New("unsupported inbound block budget command")
	errInboundBlockLease       = errors.New("invalid inbound block lease")
	errNilInboundBlockBudget   = errors.New("nil inbound block budget")
)

// inboundBlockBudget owns the inbound byte accounting shared by everything that
// reserves against it. mu covers used, gen and the charge/active state of its leases.
type inboundBlockBudget struct {
	mu    sync.Mutex
	limit uint64
	used  uint64
	gen   chan struct{}
}

// inboundBlockLease is one holder's handle on one reservation; owner is written once.
type inboundBlockLease struct {
	owner  *inboundBlockBudget
	charge uint64
	active bool
}

// inboundBlockBudgetError reports why the budget refused. It is a value type, so it can
// never reach a caller as a typed-nil error.
type inboundBlockBudgetError struct {
	resource string
	notify   <-chan struct{}
	hash     [32]byte
	hashOK   bool
}

func (e inboundBlockBudgetError) Error() string {
	return "LOCAL_RESOURCE_UNAVAILABLE(" + e.resource + ")"
}

// Resource names the refused resource identity.
func (e inboundBlockBudgetError) Resource() string { return e.resource }

// Notification returns the generation channel that closes when capacity grows, nil for
// an arithmetic refusal.
func (e inboundBlockBudgetError) Notification() <-chan struct{} { return e.notify }

// BlockHash returns the identity of the retained header bytes when the refusal carries
// one: which bytes arrived, not their validity (RUBIN_L1_P2P_AUX.md Section 2.0). A refusal
// without that evidence carries no block identity, so a consumer decides retry eligibility
// from a proven hash rather than from this field.
func (e inboundBlockBudgetError) BlockHash() ([32]byte, bool) { return e.hash, e.hashOK }

// newInboundBlockBudget returns a budget whose limit is exactly the accepted
// configuration, zero selecting the 1 GiB default; an out-of-range value yields no budget
// and an ordinary error (RUBIN_COMPACT_BLOCKS.md Units).
func newInboundBlockBudget(configured uint64) (*inboundBlockBudget, error) {
	limit := configured
	if limit == 0 {
		limit = defaultInboundBlockBudgetBytes
	}
	if limit < minInboundBlockBudgetBytes || limit > maxInboundBlockBudgetBytes {
		return nil, errInboundBlockBudgetRange
	}
	return &inboundBlockBudget{limit: limit, gen: make(chan struct{})}, nil
}

// inboundBlockCharge returns the checked byte charge payloadBytes costs for the two
// commands this budget accounts for. It is arithmetic only: no message cap is applied,
// so an over-cap size still yields its product.
func inboundBlockCharge(command string, payloadBytes uint64) (uint64, error) {
	var factor uint64
	switch command {
	case messageBlock:
		factor = 6
	case messageCmpctBlock:
		factor = 3
	default:
		return 0, errInboundBlockCommand
	}
	if payloadBytes > math.MaxUint64/factor {
		return 0, inboundBlockBudgetError{resource: inboundBudgetOverflowResource}
	}
	return factor * payloadBytes, nil
}

// TryReserveOrSubscribe hands back a live lease when the charge fits, and otherwise
// leaves used bytes and every existing lease untouched: an arithmetic refusal carries no
// notification, a capacity refusal carries the generation current at the refusal.
func (b *inboundBlockBudget) TryReserveOrSubscribe(charge uint64) (*inboundBlockLease, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if charge > math.MaxUint64-b.used {
		return nil, inboundBlockBudgetError{resource: inboundBudgetOverflowResource}
	}
	if b.used+charge > b.limit {
		return nil, inboundBlockBudgetError{resource: inboundBudgetCapacityResource, notify: b.gen}
	}
	b.used += charge
	return &inboundBlockLease{owner: b, charge: charge, active: true}, nil
}

// ReplaceOrSubscribe re-prices one active lease of this budget in one step. A refusal keeps
// the old charge and used bytes; a success creates no second lease and publishes freed
// capacity only when the charge strictly decreases. A refused holder that waits on that
// notification without releasing first, or bounding the wait, can starve.
func (b *inboundBlockBudget) ReplaceOrSubscribe(lease *inboundBlockLease, newCharge uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if lease == nil || lease.owner != b || !lease.active {
		return errInboundBlockLease
	}
	others := b.used - lease.charge
	if newCharge > math.MaxUint64-others {
		return inboundBlockBudgetError{resource: inboundBudgetOverflowResource}
	}
	if others+newCharge > b.limit {
		return inboundBlockBudgetError{resource: inboundBudgetCapacityResource, notify: b.gen}
	}
	previous := lease.charge
	b.used = others + newCharge
	lease.charge = newCharge
	if newCharge < previous {
		close(b.gen)
		b.gen = make(chan struct{})
	}
	return nil
}

// Release subtracts an active lease's charge exactly once and publishes any capacity that
// frees. A nil receiver, a lease that reached no budget, and every later call change
// nothing.
func (l *inboundBlockLease) Release() {
	if l == nil || l.owner == nil {
		return
	}
	b := l.owner
	b.mu.Lock()
	defer b.mu.Unlock()
	if !l.active {
		return
	}
	l.active = false
	b.used -= l.charge
	if l.charge > 0 {
		close(b.gen)
		b.gen = make(chan struct{})
	}
}
