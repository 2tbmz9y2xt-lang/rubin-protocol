package consensus

import "sort"

func validateHeaderCommitments(pb *ParsedBlock, expectedPrevHash *[32]byte, expectedTarget *[32]byte) error {
	if err := PowCheck(pb.HeaderBytes, pb.Header.Target); err != nil {
		return err
	}

	if expectedTarget != nil && pb.Header.Target != *expectedTarget {
		return txerr(BLOCK_ERR_TARGET_INVALID, "target mismatch")
	}

	if expectedPrevHash != nil && pb.Header.PrevBlockHash != *expectedPrevHash {
		return txerr(BLOCK_ERR_LINKAGE_INVALID, "prev_block_hash mismatch")
	}

	root, err := MerkleRootTxids(pb.Txids)
	if err != nil {
		return txerr(BLOCK_ERR_MERKLE_INVALID, "failed to compute merkle root")
	}
	if root != pb.Header.MerkleRoot {
		return txerr(BLOCK_ERR_MERKLE_INVALID, "merkle_root mismatch")
	}
	return nil
}

func validateTimestampRules(headerTimestamp uint64, blockHeight uint64, prevTimestamps []uint64) error {
	median, ok, err := medianTimePast(blockHeight, prevTimestamps)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if headerTimestamp <= median {
		return txerr(BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median")
	}
	upperBound := median + MAX_FUTURE_DRIFT
	if upperBound < median {
		upperBound = ^uint64(0)
	}
	if headerTimestamp > upperBound {
		return txerr(BLOCK_ERR_TIMESTAMP_FUTURE, "timestamp exceeds future drift")
	}
	return nil
}

func medianTimePast(blockHeight uint64, prevTimestamps []uint64) (uint64, bool, error) {
	if blockHeight == 0 || len(prevTimestamps) == 0 {
		return 0, false, nil
	}
	k := uint64(11)
	if blockHeight < k {
		k = blockHeight
	}
	if len(prevTimestamps) < int(k) {
		return 0, false, txerr(BLOCK_ERR_PARSE, "insufficient prev_timestamps context")
	}
	window := append([]uint64(nil), prevTimestamps[:int(k)]...)
	sort.Slice(window, func(i, j int) bool { return window[i] < window[j] })
	return window[(len(window)-1)/2], true, nil
}
