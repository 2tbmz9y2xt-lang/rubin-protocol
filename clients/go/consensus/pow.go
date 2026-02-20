package consensus

import (
	"fmt"
	"math/big"
	"sort"

	"rubin.dev/node/crypto"
)

// blockHeaderHash computes the SHA3-256 hash of the given block header.
// The header is serialized and hashed via the provided CryptoProvider.
func blockHeaderHash(p crypto.CryptoProvider, header *BlockHeader) [32]byte {
	out := BlockHeaderBytes(*header)
	return p.SHA3_256(out)
}

// blockRewardForHeight computes the block subsidy for a given block height.
// It distributes SUBSIDY_TOTAL_MINED evenly across SUBSIDY_DURATION_BLOCKS and
// awards an extra unit to the first rem = SUBSIDY_TOTAL_MINED % SUBSIDY_DURATION_BLOCKS
// heights to account for any remainder. For heights greater than or equal to
// SUBSIDY_DURATION_BLOCKS the subsidy is 0.
func blockRewardForHeight(height uint64) uint64 {
	if height >= SUBSIDY_DURATION_BLOCKS {
		return 0
	}
	base := uint64(SUBSIDY_TOTAL_MINED / SUBSIDY_DURATION_BLOCKS)
	rem := uint64(SUBSIDY_TOTAL_MINED % SUBSIDY_DURATION_BLOCKS)
	if height < rem {
		return base + 1
	}
	return base
}

// medianPastTimestamp computes the median timestamp from up to the last 11 block headers preceding the given height.
// It uses at most 11 most-recent headers (fewer if height or header count is smaller) and returns an error
// with message BLOCK_ERR_TIMESTAMP_OLD if height is zero or the headers slice is empty.
func medianPastTimestamp(headers []BlockHeader, height uint64) (uint64, error) {
	if height == 0 {
		return 0, fmt.Errorf(BLOCK_ERR_TIMESTAMP_OLD)
	}
	if len(headers) == 0 {
		return 0, fmt.Errorf(BLOCK_ERR_TIMESTAMP_OLD)
	}

	k := uint64(11)
	if height < k {
		k = height
	}
	limit := int(k)
	if len(headers) < limit {
		limit = len(headers)
	}
	timestamps := make([]uint64, limit)
	for i := 0; i < limit; i++ {
		timestamps[i] = headers[len(headers)-1-i].Timestamp
	}
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i] < timestamps[j]
	})
	return timestamps[(len(timestamps)-1)/2], nil
}

// blockExpectedTarget computes the expected 32-byte difficulty target for the block at the given height using the recent header window.
//
// If height is 0 the input target is returned unchanged. If height is not a WINDOW_SIZE boundary the current target from the last header is returned. An error is returned when headers is empty or contains fewer than WINDOW_SIZE elements required to compute a windowed adjustment. The returned target is clamped to within [old/4, old*4] of the previous target and scaled according to the actual time span between the first and last headers in the window.
func blockExpectedTarget(headers []BlockHeader, height uint64, targetIn [32]byte) ([32]byte, error) {
	if height == 0 {
		return targetIn, nil
	}
	if len(headers) == 0 {
		return [32]byte{}, fmt.Errorf(BLOCK_ERR_TARGET_INVALID)
	}

	targetOld := new(big.Int).SetBytes(headers[len(headers)-1].Target[:])
	if int(height%WINDOW_SIZE) != 0 {
		var target [32]byte
		targetOld.FillBytes(target[:])
		return target, nil
	}

	if len(headers) < WINDOW_SIZE {
		return [32]byte{}, fmt.Errorf(BLOCK_ERR_TARGET_INVALID)
	}

	first := headers[len(headers)-WINDOW_SIZE].Timestamp
	last := headers[len(headers)-1].Timestamp
	tActual := new(big.Int)
	if last >= first {
		tActual.SetUint64(last - first)
	} else {
		tActual.SetInt64(1)
	}

	targetNew := new(big.Int).Mul(targetOld, tActual)
	targetNew.Quo(targetNew, targetBlockIntervalBig)

	minTarget := new(big.Int).Quo(targetOld, big.NewInt(4))
	if minTarget.Sign() == 0 {
		minTarget = big.NewInt(1)
	}
	maxTarget := new(big.Int).Mul(targetOld, big.NewInt(4))

	if targetNew.Cmp(minTarget) < 0 {
		targetNew = minTarget
	}
	if targetNew.Cmp(maxTarget) > 0 {
		targetNew = maxTarget
	}

	var expected [32]byte
	targetNew.FillBytes(expected[:])
	return expected, nil
}
