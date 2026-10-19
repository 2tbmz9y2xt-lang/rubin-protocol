package mdbx

import (
	"errors"
	"math"
	"math/bits"
)

var (
	errOrdinaryEnvelopeInput    = errors.New("invalid ordinary envelope input")
	errOrdinaryEnvelopeCapacity = errors.New("ordinary envelope capacity unavailable")
)

// OrdinaryEnvelopeInputV1 holds copied scalar quantities for an ordinary paired
// retained envelope. Zero metrics are quantities, not source-completeness proofs.
type OrdinaryEnvelopeInputV1 struct {
	KPair       uint64
	SCurrentOld uint64
	SLagOld     uint64
	UndoOld     uint64
	R           uint64
	LRet        uint64
	HOld        uint32
	F           uint32
	D           uint32
	C           uint32
}

// IsOrdinaryEnvelopeCapacity recognizes only the direct capacity singleton.
func IsOrdinaryEnvelopeCapacity(err error) bool {
	return any(err) == any(errOrdinaryEnvelopeCapacity)
}

// EvaluateOrdinaryEnvelopeV1 evaluates the conservative CURRENT/LAG bound of
// RUBIN_COMPACT_BLOCKS.md 10.1. Invalid scalar domains precede capacity refusal.
// Success proves only this arithmetic fit, without qualifying sources, reserving
// resources, changing state or proving native/physical capacity.
func EvaluateOrdinaryEnvelopeV1(input OrdinaryEnvelopeInputV1) error {
	if !validOrdinaryEnvelope(input) {
		return errOrdinaryEnvelopeInput
	}
	hOld, hNew := uint64(input.HOld), uint64(input.F)+uint64(input.C)
	jOld, jNew := ordinaryEnvelopeLag(hOld), ordinaryEnvelopeLag(hNew)
	if jNew < jOld || jNew-jOld > 1440 {
		return errOrdinaryEnvelopeInput
	}
	a, c := jNew-jOld, uint64(input.C)
	arithmetic := ordinaryEnvelopeArithmetic{}
	sc := arithmetic.sum(input.SCurrentOld, input.UndoOld, arithmetic.product(c, 86545430))
	qc := arithmetic.sum(input.SCurrentOld, input.UndoOld, arithmetic.product(c-1, 86545430))
	sl := arithmetic.sum(input.SLagOld, arithmetic.product(a, 86545430))
	var ql uint64
	if a != 0 {
		ql = arithmetic.sum(input.SLagOld, arithmetic.product(a-1, 86545430))
	}
	u := arithmetic.sum(input.KPair, sc, arithmetic.tree(sc), arithmetic.product(112, max(hOld+1, hNew+1)),
		sl, arithmetic.tree(sl), arithmetic.product(112, max(jOld, jNew)), qc, ql, input.R)
	if arithmetic.overflow != 0 || u > input.LRet {
		return errOrdinaryEnvelopeCapacity
	}
	return nil
}

func validOrdinaryEnvelope(input OrdinaryEnvelopeInputV1) bool {
	hOld, hNew := uint64(input.HOld), uint64(input.F)+uint64(input.C)
	suffixes := all(input.D <= 1440, input.C >= 1, input.C <= 1440, anyTrue(input.D >= 1, input.C >= 2))
	heights := all(input.D <= input.HOld, uint64(input.F)+uint64(input.D) == hOld,
		hNew <= math.MaxUint32, laggedPromise(hNew, 1440) >= laggedPromise(hOld, 1440))
	metrics := all(anyTrue(input.D != 0, input.UndoOld == 0), anyTrue(input.HOld >= 15120, input.SLagOld == 0))
	return all(suffixes, heights, metrics, input.R >= 805306368, input.R <= input.LRet)
}

func ordinaryEnvelopeLag(height uint64) uint64 {
	if height < 15120 {
		return 0
	}
	return 720*((height-15120)/720) + 1
}

// Each nonnegative intermediate retains its overflow independently of later sums.
type ordinaryEnvelopeArithmetic struct {
	overflow uint64
}

func (a *ordinaryEnvelopeArithmetic) sum(values ...uint64) uint64 {
	var total, carry uint64
	for _, value := range values {
		total, carry = bits.Add64(total, value, 0)
		a.overflow |= carry
	}
	return total
}

func (a *ordinaryEnvelopeArithmetic) product(left, right uint64) uint64 {
	high, low := bits.Mul64(left, right)
	a.overflow |= high
	return low
}

func (a *ordinaryEnvelopeArithmetic) tree(state uint64) uint64 {
	n := state / 56
	if n == 0 {
		return 32
	}
	return a.sum(a.product(68, n), a.product(102, n-1), 32)
}
