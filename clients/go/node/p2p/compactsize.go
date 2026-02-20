package p2p

import (
	"fmt"

	"rubin.dev/node/consensus"
)

func readCompactSize(b []byte) (uint64, int, error) {
	n, used, err := consensus.DecodeCompactSize(b)
	if err != nil {
		return 0, 0, fmt.Errorf("p2p: compactsize: %w", err)
	}
	return uint64(n), used, nil
}

func encodeCompactSize(n uint64) []byte {
	return consensus.CompactSize(n).Encode()
}
