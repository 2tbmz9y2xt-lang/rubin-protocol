package node

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// RelayAdmissionDisposition is the closed classification of ONE remote-mempool
// admission outcome, published for relay-side download and representation
// state. The enum is exactly the eleven values below, and every production exit
// of Mempool.AddRemoteTxForRelay selects one of them AT the branch that decided
// the outcome, before any compatibility mapping onto TxAdmitErrorKind.
//
// A consumer MUST NOT infer a disposition from TxAdmitError.Kind, from Error(),
// from message text, from the HTTP status mapping, or from a fallback default:
// those are lossy compatibility views. TxAdmitConflict alone carries both the
// DUPLICATE and the CONFLICT branch, and TxAdmitUnavailable carries the floor,
// capacity, sequence, dependency-free unavailability and internal branches.
//
// The zero value is deliberately NOT a member of the enum, so a value that no
// branch selected can never be mistaken for a classification.
type RelayAdmissionDisposition uint8

const (
	// RelayAdmissionRetained means the exact candidate representation is
	// resident in the mempool after the call.
	RelayAdmissionRetained RelayAdmissionDisposition = iota + 1
	// RelayAdmissionStableTerminalReject is an explicit canonical, structural,
	// consensus, or constructor-frozen context-bound static-policy rejection.
	// It is the ONLY disposition that may carry cache-authorizing context
	// evidence, and only when that exact context was proven for this call.
	RelayAdmissionStableTerminalReject
	// RelayAdmissionDuplicate means a resident txid or wtxid duplicate.
	RelayAdmissionDuplicate
	// RelayAdmissionConflict means an exact existing pending-outpoint owner
	// conflict.
	RelayAdmissionConflict
	// RelayAdmissionMissingDependency means a referenced input is absent or not
	// spendable yet. It is retryable and is never stable-terminal: the same
	// bytes can admit at a later height.
	RelayAdmissionMissingDependency
	// RelayAdmissionRollingFloor is the retryable rolling-relay-fee-floor
	// outcome.
	RelayAdmissionRollingFloor
	// RelayAdmissionCapacity is the retryable capacity outcome.
	RelayAdmissionCapacity
	// RelayAdmissionAdmissionSequence is the retryable admission-sequence
	// outcome.
	RelayAdmissionAdmissionSequence
	// RelayAdmissionUnavailable covers an absent chain, owner or admission
	// context, an active canonical transition, a stale expected context, and
	// retryable runtime unavailability.
	RelayAdmissionUnavailable
	// RelayAdmissionInternal covers an impossible invariant, a retained
	// identity mismatch, accounting corruption, and an adapter contract
	// violation.
	RelayAdmissionInternal
	// RelayAdmissionCancelled is a closed enum value ONLY. This surface
	// implements no cancellation framework and no production branch selects it.
	RelayAdmissionCancelled
)

var relayAdmissionDispositionNames = [...]string{
	RelayAdmissionRetained:             "RETAINED",
	RelayAdmissionStableTerminalReject: "STABLE_TERMINAL_REJECT",
	RelayAdmissionDuplicate:            "DUPLICATE",
	RelayAdmissionConflict:             "CONFLICT",
	RelayAdmissionMissingDependency:    "MISSING_DEPENDENCY",
	RelayAdmissionRollingFloor:         "ROLLING_FLOOR",
	RelayAdmissionCapacity:             "CAPACITY",
	RelayAdmissionAdmissionSequence:    "ADMISSION_SEQUENCE",
	RelayAdmissionUnavailable:          "UNAVAILABLE",
	RelayAdmissionInternal:             "INTERNAL",
	RelayAdmissionCancelled:            "CANCELLED",
}

// String renders the closed enum name. A value outside the enum — including the
// zero value that means "no branch selected" — renders as UNSELECTED and is
// never a classification.
func (d RelayAdmissionDisposition) String() string {
	if int(d) < len(relayAdmissionDispositionNames) && relayAdmissionDispositionNames[d] != "" {
		return relayAdmissionDispositionNames[d]
	}
	return "UNSELECTED"
}

// RelayAdmissionResult is the immutable result of one relay admission. It is
// returned by value and holds no reference the caller can mutate back into the
// mempool.
//
// TxID and WTxID are the identities the producer PARSED from the candidate
// bytes; they are the zero hash when the candidate never parsed canonically.
//
// AdmissionContext is meaningful ONLY when HasAdmissionContext is true, and is
// the zero context otherwise. HasAdmissionContext is set only for
// RelayAdmissionStableTerminalReject, and only when the caller-supplied
// expected context was proven equal to the exact complete stable admission
// context this call validated against. Nothing else authorizes a relay
// representation cache.
//
// Err is the unchanged public admission error the equivalent AddRemoteTx call
// returns: same type, same TxAdmitErrorKind, same message. It is nil exactly on
// the success exit, whose disposition is RelayAdmissionRetained — or, if the
// published record somehow failed to be the exact candidate, the
// retained-identity-mismatch RelayAdmissionInternal that a nil error can also
// carry.
type RelayAdmissionResult struct {
	Disposition         RelayAdmissionDisposition
	TxID                [32]byte
	WTxID               [32]byte
	AdmissionContext    PendingOutpointAdmissionContext
	HasAdmissionContext bool
	Err                 error
}

// AddRemoteTxForRelay admits a transaction received from a peer through EXACTLY
// the AddRemoteTx implementation, and additionally publishes the
// producer-selected relay disposition, the parsed candidate identity, and — for
// a proven stable terminal rejection only — the exact stable admission context
// a relay representation cache needs.
//
// expected is the caller's own observed pending-outpoint admission context. A
// nil expected context admits exactly as AddRemoteTx does, never sets
// HasAdmissionContext, and never authorizes caching. A NON-nil expected context
// is validated at the existing owner seam (PendingOutpointOwner.Reserve), after
// the baseline parse, consensus, policy, cheap-floor and duplicate precedence: a
// stale, superseded or mismatched context is UNAVAILABLE there, before the
// owner scans for a conflict and before it consumes a sequence.
//
// It classifies without mutating: every classification input is either the
// producing branch's own decision or a pure read. Public errors, messages,
// admission counters, validation order and mutation order are untouched.
//
// Nil-safe like every other exported Mempool accessor: a nil receiver returns
// RelayAdmissionUnavailable carrying the legacy "nil mempool" TxAdmitUnavailable
// error, publishes no identity and no context, and moves no counter.
func (m *Mempool) AddRemoteTxForRelay(txBytes []byte, expected *PendingOutpointAdmissionContext) RelayAdmissionResult {
	probe := &relayAdmissionProbe{expected: expected}
	err := m.addTxWithSource(txBytes, mempoolTxSourceRemote, probe)
	return probe.result(err)
}

// relayAdmissionProbe is the per-call producer sink for the relay evidence a
// plain error cannot carry: the candidate identity the producer parsed, the
// exact stable admission context this call ran against, and the selection made
// on the success exit. Exactly one admission call owns one probe.
//
// A nil probe is the legacy AddTx / AddRemoteTx / AddReorgTx path: every method
// here is nil-safe, so that path allocates nothing and does nothing extra.
//
// The disposition of a FAILED admission deliberately does not travel here. It is
// selected at its originating branch and carried by the admission error itself
// (selectRelayDisposition), so no helper signature, error, message, counter or
// ordering had to change to make a branch classifiable.
type relayAdmissionProbe struct {
	expected      *PendingOutpointAdmissionContext
	observed      PendingOutpointAdmissionContext
	contextProven bool
	// success is the disposition of the nil-error exit only.
	success RelayAdmissionDisposition
	txid    [32]byte
	wtxid   [32]byte
}

// noteIdentity records the identity the producer parsed from the candidate
// bytes. It is called once, immediately after the canonical parse succeeds, so
// every outcome decided from that point on reports the real candidate identity
// and an unparseable candidate reports none.
func (p *relayAdmissionProbe) noteIdentity(txid, wtxid [32]byte) {
	if p == nil {
		return
	}
	p.txid = txid
	p.wtxid = wtxid
}

// checkExpectedContext validates a caller-supplied expected admission context
// against the owner AT the seam, without creating an owner and without any
// other mutation. It exists for the candidate shape that claims no outpoint and
// therefore never reaches Reserve, so no candidate shape can bypass the check.
//
// tip is the ChainState tip the caller's admission read guard is pinning. The
// availability and tip-agreement checks are the SAME two the input-bearing
// sibling runs before Reserve (reserveEntryInputsLocked), with the same messages
// and the same order, and the equality check below stands in for the generation
// refusal Reserve would perform — so this seam enforces exactly what the sibling
// enforces, never less.
//
// It is a no-op for the legacy path (nil probe) and for a nil expected context,
// so an input-less candidate keeps its exact baseline behavior there.
func (p *relayAdmissionProbe) checkExpectedContext(owner *PendingOutpointOwner, tip PendingOutpointTip) error {
	if p == nil || p.expected == nil {
		return nil
	}
	observed, ok := owner.AdmissionContext()
	if !ok {
		return selectRelayDisposition(txAdmitUnavailable("pending-outpoint owner admission context unavailable"), RelayAdmissionUnavailable)
	}
	if observed.StableTip != tip {
		return selectRelayDisposition(txAdmitUnavailable("pending-outpoint owner tip does not match the guarded chainstate tip"), RelayAdmissionUnavailable)
	}
	if observed != *p.expected {
		return selectRelayDisposition(txAdmitUnavailable("pending-outpoint expected admission context mismatch"), RelayAdmissionUnavailable)
	}
	return nil
}

// result assembles the immutable published result from the producer's own
// selections. It reads no error message and no error kind.
func (p *relayAdmissionProbe) result(err error) RelayAdmissionResult {
	if p == nil {
		// The legacy path allocates no probe. It publishes no identity and no
		// context, and a nil error there is an unselected outcome, which
		// relayDispositionOf reports as INTERNAL, fail closed.
		return RelayAdmissionResult{Disposition: relayDispositionOf(err), Err: err}
	}
	out := RelayAdmissionResult{TxID: p.txid, WTxID: p.wtxid, Err: err}
	switch {
	case err != nil:
		out.Disposition = relayDispositionOf(err)
	case p.success != 0:
		out.Disposition = p.success
	default:
		// Unreachable: the success exit always selects. Fail closed rather than
		// publish an unselected value as a classification.
		out.Disposition = RelayAdmissionInternal
	}
	// Only an explicit stable terminal rejection carries cache-authorizing
	// context, and only when that exact context was proven for this call.
	if out.Disposition == RelayAdmissionStableTerminalReject && p.contextProven {
		out.AdmissionContext = p.observed
		out.HasAdmissionContext = true
	}
	return out
}

// bindRelayAdmissionContext proves ONCE per relay call that the owner's exact
// complete admission context is available, agrees with the guarded chainstate
// tip, and equals the caller-supplied expected context.
//
// It is a pure read: it returns no error, decides no admission outcome, and
// mutates nothing — in particular it never creates an owner. A context it
// cannot prove simply leaves contextProven false, so no branch's error, message
// or ordering can depend on it.
//
// The caller holds ChainState.admissionMu for read. Every owner generation and
// stable-tip move happens inside a canonical transition that holds the SAME
// guard for write (beginCanonicalTransition through finish/abort), and the
// chainstate tip only moves under that guard too. The context proven here is
// therefore the exact one every later decision of this call runs against,
// including the decisions that return before the owner seam.
func (m *Mempool) bindRelayAdmissionContext(probe *relayAdmissionProbe) {
	if probe == nil || probe.expected == nil {
		return
	}
	m.mu.RLock()
	owner := m.pendingOutpoints
	m.mu.RUnlock()
	observed, ok := owner.AdmissionContext()
	if !ok || observed.StableTip != pendingOutpointTipOf(m.chainState) || observed != *probe.expected {
		return
	}
	probe.observed = observed
	probe.contextProven = true
}

// noteRetainedLocked selects the success-exit disposition. RETAINED is the
// contract's exact statement — the exact candidate representation is resident
// after the call — so the residency is READ from the live index rather than
// assumed from a nil error. A mismatch is the retained-identity-mismatch
// invariant and is INTERNAL. The read mutates nothing; the caller holds m.mu.
func (m *Mempool) noteRetainedLocked(entry *mempoolEntry, probe *relayAdmissionProbe) {
	if probe == nil {
		return
	}
	probe.noteIdentity(entry.txid, entry.wtxid)
	if resident, ok := m.txs[entry.txid]; ok && resident == entry {
		probe.success = RelayAdmissionRetained
		return
	}
	probe.success = RelayAdmissionInternal
}

// selectRelayDisposition records, ON the admission error the branch just built,
// the relay disposition that SAME branch selected for it. It changes no error
// type, kind, message, HTTP mapping or counter behavior: the field is
// unexported and no public mapping reads it.
//
// The FIRST selection wins, so an outer caller that classifies a whole failure
// class cannot overwrite the more precise disposition an inner branch already
// selected. err is returned unchanged — including nil and non-TxAdmitError
// values — so a branch wraps its existing return expression in place.
func selectRelayDisposition(err error, disposition RelayAdmissionDisposition) error {
	var admitErr *TxAdmitError
	if errors.As(err, &admitErr) && admitErr.disposition == 0 {
		admitErr.disposition = disposition
	}
	return err
}

// relayDispositionOf reads the disposition the PRODUCING branch stored on err.
// It never inspects Kind, Error(), message text or an HTTP mapping. An
// admission error no branch classified is an impossible invariant and is
// reported INTERNAL, fail closed — never as a stable terminal rejection.
func relayDispositionOf(err error) RelayAdmissionDisposition {
	var admitErr *TxAdmitError
	if errors.As(err, &admitErr) && admitErr.disposition != 0 {
		return admitErr.disposition
	}
	return RelayAdmissionInternal
}

// relayDispositionForOwnerError selects the disposition of a pending-outpoint
// owner failure from the OWNER's own typed kind, not from the compatibility
// TxAdmitErrorKind that txAdmitFromPendingOutpointError folds the owner's
// Unavailable and Internal kinds together into.
func relayDispositionForOwnerError(err error) RelayAdmissionDisposition {
	var ownerErr *PendingOutpointError
	if !errors.As(err, &ownerErr) {
		return RelayAdmissionInternal
	}
	switch ownerErr.Kind {
	case PendingOutpointConflict:
		return RelayAdmissionConflict
	case PendingOutpointUnavailable:
		return RelayAdmissionUnavailable
	default:
		return RelayAdmissionInternal
	}
}

// relayDispositionForInputError separates the RETRYABLE input-dependency class
// from the branch's own non-dependency selection, discriminating on the typed
// consensus error CODE rather than on its rendered text. An input that is
// absent, still immature, or not yet unlocked becomes spendable at a later
// height, so it must never be published as a stable terminal rejection.
//
// nonDependency is the disposition the calling branch selects for everything
// else it can produce: stable terminal invalidity for the consensus validation
// seam, an impossible invariant for the policy input-snapshot seam.
func relayDispositionForInputError(err error, nonDependency RelayAdmissionDisposition) RelayAdmissionDisposition {
	var txErr *consensus.TxError
	if errors.As(err, &txErr) {
		switch txErr.Code {
		case consensus.TX_ERR_MISSING_UTXO, consensus.TX_ERR_COINBASE_IMMATURE, consensus.TX_ERR_TIMELOCK_NOT_MET:
			return RelayAdmissionMissingDependency
		}
	}
	return nonDependency
}
