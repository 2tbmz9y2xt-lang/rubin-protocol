package consensus

import (
	"fmt"
	"math/big"
	"sort"

	"rubin.dev/node/crypto"
)

func blockHeaderHash(p crypto.CryptoProvider, header *BlockHeader) ([32]byte, error) {
	out := BlockHeaderBytes(*header)
	return p.SHA3_256(out)
}

// BlockHeaderHash returns the canonical RUBIN block header hash (SHA3-256 over the 116-byte header encoding).
//
// This is exported for node tooling to stay consistent with consensus linkage/PoW validation.
func BlockHeaderHash(p crypto.CryptoProvider, header BlockHeader) ([32]byte, error) {
	return blockHeaderHash(p, &header)
}

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
	// Cap maxTarget at the protocol maximum to prevent big.Int exceeding 256 bits,
	// which would cause FillBytes([32]byte) to panic. Mirrors Rust u256_shl2_saturating.
	if maxTarget.Cmp(maxTargetBig) > 0 {
		maxTarget = maxTargetBig
	}

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

// MedianPastTimestamp computes the median time past (MTP) used for header-chain timestamp validation.
// This is exported for node/P2P tooling and must remain consistent with ApplyBlock's header checks.
func MedianPastTimestamp(headers []BlockHeader, height uint64) (uint64, error) {
	return medianPastTimestamp(headers, height)
}

// BlockExpectedTarget computes the expected difficulty target for a given height, given ancestor headers.
// This is exported for node/P2P tooling and must remain consistent with ApplyBlock's header checks.
func BlockExpectedTarget(headers []BlockHeader, height uint64, targetIn [32]byte) ([32]byte, error) {
	return blockExpectedTarget(headers, height, targetIn)
}
