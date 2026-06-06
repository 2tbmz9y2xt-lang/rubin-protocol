package p2p

import (
	"bytes"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func extractAcceptedBlockDAIDs(blockBytes []byte) ([][32]byte, error) {
	parsed, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}

	seen := make(map[[32]byte]struct{})
	for _, tx := range parsed.Txs {
		if tx == nil || tx.TxKind != 0x01 || tx.DaCommitCore == nil {
			continue
		}
		seen[tx.DaCommitCore.DaID] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, nil
	}

	ids := make([][32]byte, 0, len(seen))
	for daID := range seen {
		ids = append(ids, daID)
	}
	sort.Slice(ids, func(i, j int) bool {
		return bytes.Compare(ids[i][:], ids[j][:]) < 0
	})
	return ids, nil
}
