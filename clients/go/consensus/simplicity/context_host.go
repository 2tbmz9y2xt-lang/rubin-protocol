package simplicity

import "encoding/hex"

// EvalHost supplies context-ABI values through one shared execution meter. Charge MUST either add exactly cost or return an error without changing Cost; IntrinsicCost MUST not materialize values, and ReadIntrinsic MUST not charge.
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
		if opts.Host.Cost() >= MaxExecCost {
			return EvalResult{Accepted: true, Cost: opts.Host.Cost()}, &Error{Code: ErrBudgetExceeded}
		}
		if intrinsic.Indexed {
			intrinsic.Index = opts.ContextIndex
		}
		cost, err := opts.Host.IntrinsicCost(intrinsic)
		if err != nil {
			return EvalResult{Accepted: true, Cost: opts.Host.Cost()}, err
		}
		if err := chargeCost(opts.Host, cost); err != nil {
			return EvalResult{Accepted: true, Cost: opts.Host.Cost()}, err
		}
		result, err := opts.Host.ReadIntrinsic(intrinsic)
		if err != nil {
			return EvalResult{Accepted: true, Cost: opts.Host.Cost()}, err
		}
		if !result.validFor(intrinsic) {
			return EvalResult{Cost: opts.Host.Cost()}, &Error{Code: ErrRejected}
		}
		if opts.ContextEvaluator != nil && !opts.ContextEvaluator(intrinsic, result) {
			return EvalResult{Cost: opts.Host.Cost()}, &Error{Code: ErrRejected}
		}
	}
	return EvalResult{Accepted: true, Cost: opts.Host.Cost()}, nil
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

func chargeCost(host EvalHost, cost uint64) error {
	current := host.Cost()
	if current >= MaxExecCost || cost > MaxExecCost-current {
		if current < MaxExecCost {
			if err := host.Charge(MaxExecCost - current); err != nil {
				return err
			}
		}
		return &Error{Code: ErrBudgetExceeded}
	}
	return host.Charge(cost)
}

// maxContextStateBytes mirrors consensus.MAX_SIMPLICITY_STATE_BYTES (clients/go/consensus/constants.go);
// package simplicity cannot import package consensus (see EvalHost doc), so this is a hand-kept
// duplicate, not a derived value. Keep it in sync by hand if the consensus constant changes: staying
// too NARROW only over-rejects (fail-closed, safe); staying too WIDE would under-reject, so never
// widen this without also widening the consensus constant in the same change.
const maxContextStateBytes = 512

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
