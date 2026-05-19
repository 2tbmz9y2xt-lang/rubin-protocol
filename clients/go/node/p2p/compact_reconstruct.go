package p2p

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"

type compactReconstructionResult struct {
	Transactions   [][]byte
	MissingIndexes []uint64
}

func reconstructCompactBlock(p cmpctBlockPayload, localTxs [][]byte) (compactReconstructionResult, error) {
	if _, err := encodeCmpctBlockPayload(p); err != nil {
		return compactReconstructionResult{}, err
	}
	totalEntries := len(p.ShortIDs) + len(p.Prefilled)
	shortIDIndexes := compactShortIDIndexes(totalEntries, p.Prefilled)
	txs := make([][]byte, totalEntries)
	blockedShortIDs := compactDuplicateShortIDs(p.ShortIDs)
	for _, entry := range p.Prefilled {
		txs[int(entry.Index)] = append([]byte(nil), entry.Tx...) // #nosec G115 -- encodeCmpctBlockPayload bounds-checks prefilled indexes.
		_, _, wtxid, _, _ := consensus.ParseTx(entry.Tx)         // validated by encodeCmpctBlockPayload above.
		blockedShortIDs[compactShortID(consensus.CompactShortID(wtxid, p.Nonce1, p.Nonce2))] = true
	}
	if len(p.ShortIDs) == 0 {
		return compactReconstructionResult{Transactions: txs}, nil
	}
	index, err := compactLocalTxIndex(localTxs, p.Nonce1, p.Nonce2, blockedShortIDs)
	if err != nil {
		return compactReconstructionResult{}, err
	}

	missing := compactFillShortIDTransactions(txs, shortIDIndexes, p.ShortIDs, index)
	if len(missing) > 0 {
		return compactReconstructionResult{MissingIndexes: missing}, nil
	}
	return compactReconstructionResult{Transactions: txs}, nil
}

func compactFillShortIDTransactions(txs [][]byte, absoluteIndexes []uint64, shortIDs []compactShortID, index map[compactShortID][]byte) []uint64 {
	missing := make([]uint64, 0)
	for i, shortID := range shortIDs {
		absoluteIndex := absoluteIndexes[i]
		tx := index[shortID]
		if tx == nil {
			missing = append(missing, absoluteIndex)
			continue
		}
		txs[int(absoluteIndex)] = append([]byte(nil), tx...) // #nosec G115 -- compactShortIDIndexes returns bounded indexes.
	}
	return missing
}

func compactShortIDIndexes(totalEntries int, prefilled []prefilledTxn) []uint64 {
	prefilledIndexes := make([]bool, totalEntries)
	for _, entry := range prefilled {
		prefilledIndexes[int(entry.Index)] = true // #nosec G115 -- encodeCmpctBlockPayload bounds-checks prefilled indexes.
	}
	out := make([]uint64, 0, totalEntries-len(prefilled))
	for index, isPrefilled := range prefilledIndexes {
		if !isPrefilled {
			out = append(out, uint64(index))
		}
	}
	return out
}

func compactLocalTxIndex(localTxs [][]byte, nonce1, nonce2 uint64, blocked map[compactShortID]bool) (map[compactShortID][]byte, error) {
	out := make(map[compactShortID][]byte, len(localTxs)+len(blocked))
	for shortID := range blocked {
		out[shortID] = nil
	}
	for _, tx := range localTxs {
		wtxid, err := compactLocalTxWTxID(tx)
		if err != nil {
			return nil, err
		}
		shortID := compactShortID(consensus.CompactShortID(wtxid, nonce1, nonce2))
		if _, ok := out[shortID]; ok {
			out[shortID] = nil
			continue
		}
		out[shortID] = append([]byte(nil), tx...)
	}
	return out, nil
}

func compactLocalTxWTxID(tx []byte) ([32]byte, error) {
	var zero [32]byte
	if _, _, _, err := decodeCompactRelayTxEnvelope(tx, uint64(len(tx)), 0, "compact local transaction is non-canonical"); err != nil {
		return zero, err
	}
	_, _, wtxid, _, _ := consensus.ParseTx(tx) // validated by decodeCompactRelayTxEnvelope above.
	return wtxid, nil
}

func compactDuplicateShortIDs(shortIDs []compactShortID) map[compactShortID]bool {
	seen := make(map[compactShortID]struct{}, len(shortIDs))
	duplicates := make(map[compactShortID]bool)
	for _, shortID := range shortIDs {
		if _, ok := seen[shortID]; ok {
			duplicates[shortID] = true
			continue
		}
		seen[shortID] = struct{}{}
	}
	return duplicates
}
