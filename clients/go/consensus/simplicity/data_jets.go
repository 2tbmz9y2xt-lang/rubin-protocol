package simplicity

import (
	"bytes"
	"cmp"
	"math/bits"
)

const dataJetFlatCost, bytesJetChunkLen uint64 = 1, 32

type Ordering int8

const (
	OrderingLT Ordering = -1
	OrderingEQ Ordering = 0
	OrderingGT Ordering = 1
)

type Uint128 struct{ Hi, Lo uint64 }

type U64JetResult struct {
	Value    uint64
	Accepted bool
	Cost     uint64
}

type U128JetResult struct {
	Value    Uint128
	Accepted bool
	Cost     uint64
}

type OrderingJetResult struct {
	Ordering Ordering
	Cost     uint64
}

type BoolJetResult struct {
	Value bool
	Cost  uint64
}

type BytesJetResult struct {
	Bytes    []byte
	Accepted bool
	Cost     uint64
}

func EvaluateU64CheckedAddJet(a, b uint64) U64JetResult {
	value, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return U64JetResult{Cost: dataJetFlatCost}
	}
	return U64JetResult{Value: value, Accepted: true, Cost: dataJetFlatCost}
}

func EvaluateU64CheckedSubJet(a, b uint64) U64JetResult {
	value, borrow := bits.Sub64(a, b, 0)
	if borrow != 0 {
		return U64JetResult{Cost: dataJetFlatCost}
	}
	return U64JetResult{Value: value, Accepted: true, Cost: dataJetFlatCost}
}

func EvaluateU64CheckedMulJet(a, b uint64) U64JetResult {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return U64JetResult{Cost: dataJetFlatCost}
	}
	return U64JetResult{Value: lo, Accepted: true, Cost: dataJetFlatCost}
}

func EvaluateU64CmpJet(a, b uint64) OrderingJetResult {
	return OrderingJetResult{Ordering: Ordering(cmp.Compare(a, b)), Cost: dataJetFlatCost}
}

func EvaluateU128CheckedAddJet(a, b Uint128) U128JetResult {
	lo, carry := bits.Add64(a.Lo, b.Lo, 0)
	hi, overflow := bits.Add64(a.Hi, b.Hi, carry)
	if overflow != 0 {
		return U128JetResult{Cost: dataJetFlatCost}
	}
	return U128JetResult{Value: Uint128{Hi: hi, Lo: lo}, Accepted: true, Cost: dataJetFlatCost}
}

func EvaluateU128CheckedSubJet(a, b Uint128) U128JetResult {
	lo, borrow := bits.Sub64(a.Lo, b.Lo, 0)
	hi, underflow := bits.Sub64(a.Hi, b.Hi, borrow)
	if underflow != 0 {
		return U128JetResult{Cost: dataJetFlatCost}
	}
	return U128JetResult{Value: Uint128{Hi: hi, Lo: lo}, Accepted: true, Cost: dataJetFlatCost}
}

func EvaluateU128CmpJet(a, b Uint128) OrderingJetResult {
	ordering := Ordering(cmp.Compare(a.Hi, b.Hi))
	if ordering == OrderingEQ {
		ordering = Ordering(cmp.Compare(a.Lo, b.Lo))
	}
	return OrderingJetResult{Ordering: ordering, Cost: dataJetFlatCost}
}

func EvaluateBytesEqJet(a, b []byte) BoolJetResult {
	return BoolJetResult{
		Value: bytes.Equal(a, b),
		Cost:  bytesJetCost(max(uint64(len(a)), uint64(len(b)))),
	}
}

func EvaluateBytesCmpJet(a, b []byte) OrderingJetResult {
	return OrderingJetResult{
		Ordering: Ordering(bytes.Compare(a, b)),
		Cost:     bytesJetCost(max(uint64(len(a)), uint64(len(b)))),
	}
}

func EvaluateBytesSliceJet(src []byte, start, length uint64) BytesJetResult {
	cost := bytesJetCost(length)
	end, carry := bits.Add64(start, length, 0)
	if carry != 0 || end > uint64(len(src)) {
		return BytesJetResult{Cost: cost}
	}

	out := append([]byte(nil), src[int(start):int(end)]...)
	return BytesJetResult{Bytes: out, Accepted: true, Cost: cost}
}

func bytesJetCost(length uint64) uint64 {
	chunks := length / bytesJetChunkLen
	if length%bytesJetChunkLen != 0 {
		chunks++
	}
	return dataJetFlatCost + chunks
}
