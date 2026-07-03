package simplicity

import "encoding/hex"

// EvalHost supplies context-ABI values through one shared execution meter.
//
// Postconditions implementations MUST uphold:
//   - Charge MUST either add exactly cost to Cost and return nil, or return an error and leave
//     Cost unchanged. Saturating a partially-spent budget up to MaxExecCost is the caller's job
//     (see chargeCost/chargeSteps), never Charge's own responsibility.
//   - IntrinsicCost MUST not materialize the intrinsic's value (it computes a cost only) and MUST
//     have no side effects that depend on whether the caller goes on to charge/read.
//   - ReadIntrinsic MUST not charge the meter.
//   - E7 totality: for an Either-typed (intrinsic.Either) intrinsic, an out-of-range/invalid read
//     (e.g. an index outside the referenced group) MUST be reported via
//     IntrinsicResult{Failure: true}, never a non-nil error. Only IntrinsicResult.Failure is a
//     total, in-protocol sum-type outcome (see validFor); a non-nil error from ReadIntrinsic is
//     always treated as a resource/host fault, not a valid "no value at this index" result.
type EvalHost interface {
	Charge(uint64) error
	Cost() uint64
	IntrinsicCost(ContextIntrinsic) (uint64, error)
	ReadIntrinsic(ContextIntrinsic) (IntrinsicResult, error)
}

type ContextIntrinsic struct {
	ID, Index                    uint16
	Name, Signature, SelectorHex string
	CMR                          [32]byte
	OutputBitWidth               uint64
	Kind                         ContextValueKind
	Either, Indexed              bool
}

type ContextValueKind uint8

const (
	ContextValueInvalid ContextValueKind = iota
	ContextValueBytes32
	ContextValueBytes
	ContextValueU8
	ContextValueU16
	ContextValueU32
	ContextValueU64
	ContextValueU128
)

type ContextValue struct {
	Kind    ContextValueKind
	Bytes32 [32]byte
	Bytes   []byte
	Uint    uint64
	Uint128 Uint128
}

type IntrinsicResult struct {
	Value   ContextValue
	Failure bool
}

func contextIntrinsicProgramEntries(rows []ContextIntrinsic, witnesses map[witnessKey]struct{}) map[string]programEntry {
	out := make(map[string]programEntry, len(rows))
	for _, row := range rows {
		inputWidth := uint64(0)
		if row.Indexed {
			inputWidth = 16
		}
		out[string(mustHexBytes(row.SelectorHex))] = programEntry{program: Program{
			CMR:            row.CMR,
			witnesses:      witnesses,
			intrinsics:     []ContextIntrinsic{row},
			frameBitWidths: []uint64{inputWidth, row.OutputBitWidth},
		}}
	}
	return out
}

func mergeProgramEntries(base, extra map[string]programEntry) map[string]programEntry {
	out := make(map[string]programEntry, len(base)+len(extra))
	for key, entry := range base {
		out[key] = entry
	}
	for key, entry := range extra {
		out[key] = entry
	}
	return out
}

func mustHexBytes(s string) []byte {
	raw, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid embedded hex: " + err.Error())
	}
	return raw
}

func evaluateJetWithLocalMeter(result EvalResult) (EvalResult, error) {
	var meter meter
	err := meter.charge(result.Cost)
	result.Cost = meter.cost
	if err != nil {
		return result, err
	}
	if !result.Accepted {
		return result, &Error{Code: ErrRejected}
	}
	return result, nil
}

func (p Program) evaluateIntrinsics(opts EvalOptions) (EvalResult, error) {
	if opts.Host == nil {
		return EvalResult{}, &Error{Code: ErrDecode}
	}
	if p.evalSteps > 0 {
		if err := chargeSteps(opts.Host, p.evalSteps); err != nil {
			return EvalResult{Accepted: true, Cost: opts.Host.Cost()}, err
		}
	}
	for _, intrinsic := range p.intrinsics {
		rejected, err := evaluateOneIntrinsic(opts, intrinsic)
		if rejected {
			return EvalResult{Cost: opts.Host.Cost()}, err
		}
		if err != nil {
			return EvalResult{Accepted: true, Cost: opts.Host.Cost()}, err
		}
	}
	return EvalResult{Accepted: true, Cost: opts.Host.Cost()}, nil
}

// evaluateOneIntrinsic reads and validates a single context intrinsic, charging its cost first.
// rejected=true means the value failed validation (a logical ErrRejected — the caller keeps
// Accepted=false); rejected=false with a non-nil err means a resource/host error (the caller sets
// Accepted=true, mirroring chargeSteps/chargeCost's own convention elsewhere in this file).
//
// Deliberately no "Host.Cost() >= MaxExecCost" pre-check here: that would reject a zero-cost
// intrinsic exactly at the cap, which is wrong (chargeCost accepts a zero-size charge at the cap —
// see ChargeCost's own boundary). chargeCost below is the sole authority for the accept/reject
// boundary; it already guarantees the expensive ReadIntrinsic call is skipped whenever the actual
// charge would exceed the remaining budget, so no separate pre-check is needed to keep
// ReadIntrinsic from running once the meter is truly exhausted.
func evaluateOneIntrinsic(opts EvalOptions, intrinsic ContextIntrinsic) (rejected bool, err error) {
	if intrinsic.Indexed {
		intrinsic.Index = opts.ContextIndex
	}
	cost, err := opts.Host.IntrinsicCost(intrinsic)
	if err != nil {
		return false, err
	}
	if err := chargeCost(opts.Host, cost); err != nil {
		return false, err
	}
	result, err := opts.Host.ReadIntrinsic(intrinsic)
	if err != nil {
		return false, err
	}
	if !intrinsicAccepted(opts, intrinsic, result) {
		return true, &Error{Code: ErrRejected}
	}
	return false, nil
}

// intrinsicAccepted combines the type/bounds check with the caller-supplied value predicate.
func intrinsicAccepted(opts EvalOptions, intrinsic ContextIntrinsic, result IntrinsicResult) bool {
	if !result.validFor(intrinsic) {
		return false
	}
	return opts.ContextEvaluator == nil || opts.ContextEvaluator(intrinsic, result)
}

func chargeSteps(host EvalHost, steps uint64) error {
	if StepCost == 0 || steps == 0 {
		return nil
	}
	if steps > MaxExecCost/StepCost {
		return chargeCost(host, MaxExecCost+1)
	}
	return chargeCost(host, steps*StepCost)
}

// chargeCost routes through ChargeCost (the SAME cap-boundary function the legacy no-Host meter
// path uses) so a zero-cost charge exactly at MaxExecCost behaves identically on both paths — this
// issue's own one_invariant claims "a SINGLE shared meter"; two different accept/reject boundaries
// for the same state would contradict that.
func chargeCost(host EvalHost, cost uint64) error {
	current := host.Cost()
	if _, err := ChargeCost(current, cost); err != nil {
		if current < MaxExecCost {
			if chargeErr := host.Charge(MaxExecCost - current); chargeErr != nil {
				return chargeErr
			}
		}
		return err
	}
	return host.Charge(cost)
}

// maxContextStateBytes mirrors consensus.MAX_SIMPLICITY_STATE_BYTES (clients/go/consensus/constants.go);
// package simplicity cannot import package consensus (see EvalHost doc), so this is a hand-kept
// duplicate, not a derived value. Keep it in sync by hand if the consensus constant changes: staying
// too NARROW only over-rejects (fail-closed, safe); staying too WIDE would under-reject, so never
// widen this without also widening the consensus constant in the same change.
const maxContextStateBytes = 512

// MaxContextStateBytes exposes maxContextStateBytes read-only so package consensus (which CAN
// import package simplicity, unlike the reverse) can assert by test that the two hand-kept
// duplicates never drift — see TestSimplicityMaxContextStateBytesMatchesConsensusConstant.
func MaxContextStateBytes() uint64 { return maxContextStateBytes }

func (r IntrinsicResult) validFor(intrinsic ContextIntrinsic) bool {
	if r.Failure {
		return intrinsic.Either
	}
	if intrinsic.Kind == ContextValueInvalid || r.Value.Kind != intrinsic.Kind {
		return false
	}
	switch r.Value.Kind {
	case ContextValueBytes:
		return len(r.Value.Bytes) <= maxContextStateBytes
	case ContextValueU8:
		return r.Value.Uint <= 0xff
	case ContextValueU16:
		return r.Value.Uint <= 0xffff
	case ContextValueU32:
		return r.Value.Uint <= 0xffffffff
	default:
		return true
	}
}
