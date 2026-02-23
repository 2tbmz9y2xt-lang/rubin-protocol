package consensus

import (
	"bytes"
	"math/big"
)

// RetargetV1 computes the next target using the consensus formula in CANONICAL §15.
//
// All arithmetic is done with arbitrary precision; the result MUST fit in 32 bytes.
func RetargetV1(targetOld [32]byte, timestampFirst uint64, timestampLast uint64) ([32]byte, error) {
	var tActual uint64
	if timestampLast <= timestampFirst {
		tActual = 1
	} else {
		tActual = timestampLast - timestampFirst
	}
	return retargetV1WithActual(targetOld, tActual)
}

// RetargetV1Clamped computes retarget using clamped per-block timestamps (CANONICAL §15).
// The caller MUST provide exactly WINDOW_SIZE timestamps for the retarget window.
func RetargetV1Clamped(targetOld [32]byte, windowTimestamps []uint64) ([32]byte, error) {
	if len(windowTimestamps) != int(WINDOW_SIZE) {
		var zero [32]byte
		return zero, txerr(TX_ERR_PARSE, "retarget: invalid window timestamp count")
	}
	first := windowTimestamps[0]
	prev := first
	maxStep := uint64(MAX_TIMESTAMP_STEP_PER_BLOCK)

	for i := 1; i < len(windowTimestamps); i++ {
		lo, err := addU64(prev, 1)
		if err != nil {
			var zero [32]byte
			return zero, txerr(TX_ERR_PARSE, "retarget: timestamp clamp overflow")
		}
		hi, err := addU64(prev, maxStep)
		if err != nil {
			var zero [32]byte
			return zero, txerr(TX_ERR_PARSE, "retarget: timestamp clamp overflow")
		}
		v := windowTimestamps[i]
		if v < lo {
			v = lo
		} else if v > hi {
			v = hi
		}
		prev = v
	}

	tActual := prev - first
	if tActual == 0 {
		tActual = 1
	}
	return retargetV1WithActual(targetOld, tActual)
}

func retargetV1WithActual(targetOld [32]byte, tActual uint64) ([32]byte, error) {
	powLimit := new(big.Int).SetBytes(POW_LIMIT[:])
	tOld := new(big.Int).SetBytes(targetOld[:]) // big-endian
	if tOld.Sign() == 0 {
		var zero [32]byte
		return zero, txerr(TX_ERR_PARSE, "retarget: target_old is zero")
	}
	if tOld.Cmp(powLimit) > 0 {
		var zero [32]byte
		return zero, txerr(TX_ERR_PARSE, "retarget: target_old above pow_limit")
	}

	tExpected := uint64(TARGET_BLOCK_INTERVAL) * uint64(WINDOW_SIZE)
	if tExpected == 0 {
		var zero [32]byte
		return zero, txerr(TX_ERR_PARSE, "retarget: t_expected is zero")
	}

	// floor(target_old * T_actual / T_expected)
	num := new(big.Int).Mul(tOld, new(big.Int).SetUint64(tActual))
	den := new(big.Int).SetUint64(tExpected)
	tNew := new(big.Int).Div(num, den)

	// clamp lower = max(1, floor(target_old / 4))
	lower := new(big.Int).Rsh(new(big.Int).Set(tOld), 2) // /4
	if lower.Cmp(big.NewInt(1)) < 0 {
		lower.SetInt64(1)
	}
	// upper = target_old * 4
	upper := new(big.Int).Lsh(new(big.Int).Set(tOld), 2)
	if upper.Cmp(powLimit) > 0 {
		upper = powLimit
	}

	if tNew.Cmp(lower) < 0 {
		tNew = lower
	}
	if tNew.Cmp(upper) > 0 {
		tNew = upper
	}

	return bigIntToBytes32(tNew)
}

// PowCheck verifies integer(block_hash, be) < integer(target, be).
func PowCheck(headerBytes []byte, target [32]byte) error {
	targetInt := new(big.Int).SetBytes(target[:])
	powLimit := new(big.Int).SetBytes(POW_LIMIT[:])
	if targetInt.Sign() == 0 || targetInt.Cmp(powLimit) > 0 {
		return txerr(BLOCK_ERR_TARGET_INVALID, "target out of range")
	}

	h, err := BlockHash(headerBytes)
	if err != nil {
		return err
	}
	if bytes.Compare(h[:], target[:]) >= 0 {
		return txerr(BLOCK_ERR_POW_INVALID, "pow invalid")
	}
	return nil
}

func bigIntToBytes32(x *big.Int) ([32]byte, error) {
	var out [32]byte
	if x.Sign() < 0 {
		return out, txerr(TX_ERR_PARSE, "u256: negative")
	}
	b := x.Bytes() // big-endian without leading zeros
	if len(b) > 32 {
		return out, txerr(TX_ERR_PARSE, "u256: overflow")
	}
	copy(out[32-len(b):], b)
	return out, nil
}
