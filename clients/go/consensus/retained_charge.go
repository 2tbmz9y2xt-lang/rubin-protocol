package consensus

import (
	"errors"
	"math"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// LimitsV1 is an immutable, caller-local retained-capacity configuration.
type LimitsV1 struct{ r, lRet uint64 }

// NewLimitsV1 preserves both supplied limits, including zero and maximal values.
func NewLimitsV1(r, lRet uint64) LimitsV1 { return LimitsV1{r: r, lRet: lRet} }

// DefaultLimitsV1 returns the initial retained-capacity configuration.
func DefaultLimitsV1() LimitsV1 { return NewLimitsV1(805306368, 18446744073709551615) }

// R returns the configured operation reservation limit.
func (v LimitsV1) R() uint64 { return v.r }

// LRet returns the configured logical retained limit.
func (v LimitsV1) LRet() uint64 { return v.lRet }

const (
	RetainedHeaderChargeV1 uint64 = 148
	RetainedIndexChargeV1  uint64 = 112
	RetainedRootChargeV1   uint64 = 32
)

var errRetainedArithmetic = errors.New("retained capacity arithmetic exceeds bound")

// RetainedStateEntryChargeV1 validates the sole native suffix and charges its outpoint.
func RetainedStateEntryChargeV1(nativeValue []byte) (uint64, error) {
	if _, err := mdbx.DecodeUTXOValue(nativeValue); err != nil {
		return 0, err
	}
	return 36 + uint64(len(nativeValue)), nil
}

// RetainedTreeChargeV1 charges a complete tree, including its empty root binding.
func RetainedTreeChargeV1(entries uint64) (uint64, error) {
	if entries == 0 {
		return RetainedRootChargeV1, nil
	}
	if entries-1 > (math.MaxUint64-100)/170 {
		return 0, errRetainedArithmetic
	}
	return 100 + 170*(entries-1), nil
}

// RetainedNodeChargeV1 charges an established raw node kind without decoding its value.
func RetainedNodeChargeV1(kind mdbx.TreeNodeKindV1) (uint64, error) {
	switch kind {
	case mdbx.TreeNodeLeafV1:
		return 68, nil
	case mdbx.TreeNodeBranchV1:
		return 102, nil
	default:
		return 0, errRetainedArithmetic
	}
}
