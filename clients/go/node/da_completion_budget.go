package node

import "sync"

// RUBIN_COMPACT_BLOCKS.md Section 18.5 completion work budget limits (bytes).
const (
	daCompletionWorkPerSource = 100_000_000
	daCompletionWorkGlobal    = 1_600_000_000
)

// daCompletionBudget is the volatile owner-lifetime completion work budget of
// RUBIN_COMPACT_BLOCKS.md Section 18.5. Retained-state images never copy it.
// Its mutex is never held across parse, cryptography, a DA or owner lock,
// a callback, I/O or a wait. Every ordinary return and every completion-hook
// panic acquires it with no DA or owner lock held; no lock-order statement is
// made for a non-hook panic inside the DA/owner interval.
type daCompletionBudget struct {
	mu      sync.Mutex
	present bool
	tip     daCompletionTip
	global  daCompletionUse
	sources map[string]daCompletionUse
}

// daCompletionTip is the stored best-tip identity; generation and HasTip
// never participate.
type daCompletionTip struct {
	hash   [32]byte
	height uint64
}

type daCompletionUse struct {
	used     uint64
	reserved uint64
}

// daCompletionCharge is a checked u64 sum; overflow is recorded, not wrapped,
// so the step-2a preflight rejects it before any budget change.
type daCompletionCharge struct {
	bytes    uint64
	overflow bool
}

// daCompletionReservation is one successful step-2a reservation. It must be
// settled exactly once.
type daCompletionReservation struct {
	quota  string
	charge uint64
}

type daCompletionVerdict uint8

const (
	daCompletionReserved daCompletionVerdict = iota + 1
	daCompletionDeclined
	daCompletionOverflow
	daCompletionReservedAtRenewal
)

func (c *daCompletionCharge) add(n uint64) {
	if c.overflow || ^uint64(0)-c.bytes < n {
		c.overflow = true
		return
	}
	c.bytes += n
}

// daCompletionChargeOf sums Section 18.1 incomplete_member_charge over the
// target snapshot (every retained chunk, in range or not, and a present
// commit) plus the candidate, from lengths only.
func daCompletionChargeOf(snapshot *daCompleteSnapshot) daCompletionCharge {
	var charge daCompletionCharge
	if snapshot.prior.commit.member != nil {
		charge.add(uint64(len(snapshot.prior.commit.txBytes)))
	}
	for _, chunk := range snapshot.prior.chunks {
		charge.add(uint64(len(chunk.txBytes)))
		charge.add(uint64(len(chunk.payload)))
	}
	candidate := snapshot.candidate.member
	charge.add(uint64(len(candidate.txBytes)))
	if candidate.locator.kind == daRelayLocatorChunk {
		charge.add(uint64(len(candidate.payload)))
	}
	return charge
}

// reserve is the atomic step-2a operation for one PEER attempt under the held
// ChainState guard. Only context.StableTip Hash and Height form the observed
// identity. Every error leaves the budget unchanged except that a decline
// keeps a renewal made by the same operation.
func (b *daCompletionBudget) reserve(context PendingOutpointAdmissionContext, provenance DAProvenance, charge daCompletionCharge) (daCompletionReservation, error) {
	observed := daCompletionTip{hash: context.StableTip.Hash, height: context.StableTip.Height}
	b.mu.Lock()
	verdict := b.reserveLocked(observed, provenance.quotaIdentity, charge)
	b.mu.Unlock()
	return daCompletionResult(verdict, provenance.quotaIdentity, charge.bytes)
}

func (b *daCompletionBudget) reserveLocked(observed daCompletionTip, quota string, charge daCompletionCharge) daCompletionVerdict {
	renew := !b.present || b.tip != observed
	source, fits, verdict := b.preflightLocked(renew, quota, charge)
	if verdict != 0 {
		return verdict
	}
	if renew {
		b.renewLocked(observed)
	}
	if !fits {
		return daCompletionDeclined
	}
	source.reserved += charge.bytes
	b.global.reserved += charge.bytes
	b.storeLocked(quota, source)
	return daCompletionReserved
}

// preflightLocked prepares the whole result on virtually renewed counters
// before any budget change; a nonzero verdict is a zero-effect INTERNAL.
func (b *daCompletionBudget) preflightLocked(renew bool, quota string, charge daCompletionCharge) (daCompletionUse, bool, daCompletionVerdict) {
	if renew && b.global.reserved != 0 {
		return daCompletionUse{}, false, daCompletionReservedAtRenewal
	}
	if charge.overflow {
		return daCompletionUse{}, false, daCompletionOverflow
	}
	global, source := b.global, b.sources[quota]
	if renew {
		global.used, source = 0, daCompletionUse{}
	}
	fits, ok := daCompletionFits(global, source, charge.bytes)
	if !ok {
		return daCompletionUse{}, false, daCompletionOverflow
	}
	return source, fits, 0
}

// daCompletionFits returns whether both limits admit charge, and false ok on
// checked overflow in either test.
func daCompletionFits(global, source daCompletionUse, charge uint64) (fits bool, ok bool) {
	globalSum, globalOK := daCompletionSum(global, charge)
	sourceSum, sourceOK := daCompletionSum(source, charge)
	if !globalOK || !sourceOK {
		return false, false
	}
	return globalSum <= daCompletionWorkGlobal && sourceSum <= daCompletionWorkPerSource, true
}

func daCompletionSum(use daCompletionUse, charge uint64) (uint64, bool) {
	var sum daCompletionCharge
	sum.add(use.used)
	sum.add(use.reserved)
	sum.add(charge)
	return sum.bytes, !sum.overflow
}

func (b *daCompletionBudget) renewLocked(observed daCompletionTip) {
	b.present, b.tip = true, observed
	b.global.used = 0
	b.sources = nil
}

func (b *daCompletionBudget) storeLocked(quota string, use daCompletionUse) {
	if use == (daCompletionUse{}) {
		delete(b.sources, quota)
		return
	}
	if b.sources == nil {
		b.sources = map[string]daCompletionUse{}
	}
	b.sources[quota] = use
}

func daCompletionResult(verdict daCompletionVerdict, quota string, charge uint64) (daCompletionReservation, error) {
	switch verdict {
	case daCompletionReserved:
		return daCompletionReservation{quota: quota, charge: charge}, nil
	case daCompletionDeclined:
		return daCompletionReservation{}, selectRelayDisposition(txAdmitUnavailable("DA completion work budget unavailable"), RelayAdmissionUnavailable)
	case daCompletionOverflow:
		return daCompletionReservation{}, daCompletionInternal(errDARelayArithmeticOverflow)
	default:
		return daCompletionReservation{}, daCompletionInternal(errDARelayImageIncompatible)
	}
}

// daCompletionInternal is the INTERNAL refusal carrying cause for errors.Is.
func daCompletionInternal(cause error) error {
	rejected := txAdmitRejected(cause.Error())
	rejected.cause = cause
	return selectRelayDisposition(rejected, RelayAdmissionInternal)
}

// settle resolves one reservation: accepted (step-11 State C publication only)
// returns the charge; every other terminal outcome converts it to used.
func (b *daCompletionBudget) settle(reservation daCompletionReservation, accepted bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	source := b.sources[reservation.quota]
	source.reserved -= reservation.charge
	b.global.reserved -= reservation.charge
	if !accepted {
		source.used += reservation.charge
		b.global.used += reservation.charge
	}
	b.storeLocked(reservation.quota, source)
}
