package consensus

import (
	"math/big"
)

// WorkFromTarget computes CANONICAL §23 per-block work:
//   work = floor(2^256 / target)
//
// This is a non-validation helper but MUST be deterministic and MUST NOT use floats.
func WorkFromTarget(target [32]byte) (*big.Int, error) {
	t := new(big.Int).SetBytes(target[:]) // big-endian
	if t.Sign() <= 0 {
		return nil, txerr(TX_ERR_PARSE, "fork_work: target is zero")
	}
	powLimit := new(big.Int).SetBytes(POW_LIMIT[:])
	if t.Cmp(powLimit) > 0 {
		return nil, txerr(TX_ERR_PARSE, "fork_work: target above pow_limit")
	}

	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	return new(big.Int).Div(two256, t), nil
}

// ChainWorkFromTargets sums WorkFromTarget for a list of targets (CANONICAL §23).
func ChainWorkFromTargets(targets [][32]byte) (*big.Int, error) {
	total := new(big.Int)
	for _, t := range targets {
		w, err := WorkFromTarget(t)
		if err != nil {
			return nil, err
		}
		total.Add(total, w)
	}
	return total, nil
}

