package node

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"

func (m *Miner) mempoolCandidateTransactions(maxSelected int) [][]byte {
	entries := m.sync.mempool.snapshotEntries()
	sortMempoolEntries(entries)
	return pickMinerCandidateEntries(entries, maxSelected, int(consensus.MAX_BLOCK_WEIGHT))
}

func pickFlatCandidateRaw(txs [][]byte, maxCount int) [][]byte {
	if maxCount <= 0 {
		return nil
	}
	selected := make([][]byte, 0, min(len(txs), maxCount))
	for _, raw := range txs {
		if isMiningDATxRaw(raw) {
			continue
		}
		selected = append(selected, raw)
		if len(selected) >= maxCount {
			break
		}
	}
	return selected
}

func pickMinerCandidateEntries(entries []*mempoolEntry, maxCount int, maxBytes int) [][]byte {
	if maxCount <= 0 || maxBytes <= 0 {
		return nil
	}
	selected := make([][]byte, 0, min(len(entries), maxCount))
	usedBytes := 0
	for _, entry := range entries {
		if entry == nil || isMiningDATxRaw(entry.raw) {
			continue
		}
		if len(selected) >= maxCount {
			break
		}
		if entry.size > maxBytes-usedBytes {
			continue
		}
		selected = append(selected, append([]byte(nil), entry.raw...))
		usedBytes += entry.size
	}
	return selected
}

func isMiningDATxRaw(raw []byte) bool {
	tx, _, _, consumed, err := consensus.ParseTx(raw)
	if err != nil || consumed != len(raw) {
		return false
	}
	return isMiningDATx(tx)
}

func isMiningDATx(tx *consensus.Tx) bool {
	return tx != nil && (tx.TxKind == 0x01 || tx.TxKind == 0x02)
}
