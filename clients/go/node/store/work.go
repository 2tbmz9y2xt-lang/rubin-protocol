package store

import (
	"fmt"
	"math/big"
)

var twoTo256 = new(big.Int).Lsh(big.NewInt(1), 256)

// WorkFromTarget returns floor(2^256 / target) for PoW chainwork.
// target is interpreted as an unsigned big-endian integer.
func WorkFromTarget(target32 [32]byte) (*big.Int, error) {
	t := new(big.Int).SetBytes(target32[:])
	if t.Sign() <= 0 {
		return nil, fmt.Errorf("work: target must be > 0")
	}
	return new(big.Int).Quo(twoTo256, t), nil
}

