package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const compactDuplicateReportedIndex = ^uint64(0)

type compactReconstructionResult struct {
	Transactions   [][]byte
	MissingIndexes []uint64
}

func reconstructCompactBlock(p cmpctBlockPayload, localTxs [][]byte) (compactReconstructionResult, error) {
	totalEntries, err := compactReconstructionEntryCount(len(p.ShortIDs), p.Prefilled)
	if err != nil {
		return compactReconstructionResult{}, err
	}
	prefilledShortIDs, prefilledTxBytes, err := compactPrefilledShortIDs(p.Prefilled, totalEntries, p.Nonce1, p.Nonce2)
	if err != nil {
		return compactReconstructionResult{}, err
	}
	if len(p.ShortIDs) == 0 {
		txs := make([][]byte, totalEntries)
		compactFillPrefilledTransactions(txs, p.Prefilled)
		return compactReconstructionResult{Transactions: txs}, nil
	}
	index, err := compactLocalTxIndex(localTxs, p.Nonce1, p.Nonce2)
	if err != nil {
		return compactReconstructionResult{}, err
	}

	missing := compactMissingShortIDIndexes(totalEntries, p.Prefilled, p.ShortIDs, index, prefilledShortIDs)
	if len(missing) > 0 {
		return compactReconstructionResult{MissingIndexes: missing}, nil
	}
	txs := make([][]byte, totalEntries)
	compactFillPrefilledTransactions(txs, p.Prefilled)
	if err := compactFillShortIDTransactions(txs, totalEntries, p.Prefilled, p.ShortIDs, index, prefilledTxBytes); err != nil {
		return compactReconstructionResult{}, err
	}
	return compactReconstructionResult{Transactions: txs}, nil
}

func compactReconstructionEntryCount(shortIDCount int, prefilled []prefilledTxn) (int, error) {
	totalEntries, err := validateCmpctBlockEntryCount(uint64(shortIDCount), uint64(len(prefilled)))
	if err != nil {
		return 0, err
	}
	if _, err := cmpctBlockPayloadByteLen(uint64(shortIDCount), prefilled); err != nil {
		return 0, err
	}
	return int(totalEntries), nil // #nosec G115 -- validateCmpctBlockEntryCount caps at maxCmpctBlockEntries.
}

func compactPrefilledShortIDs(prefilled []prefilledTxn, totalEntries int, nonce1, nonce2 uint64) (map[compactShortID]bool, uint64, error) {
	out := make(map[compactShortID]bool, len(prefilled))
	var prev uint64
	var totalTxBytes uint64
	for i, entry := range prefilled {
		if entry.Index >= uint64(totalEntries) || (i > 0 && entry.Index <= prev) {
			return nil, 0, errors.New("compact relay index out of range")
		}
		nextTotal, err := validateBlockTxnTransactionSize(uint64(len(entry.Tx)), totalTxBytes)
		if err != nil {
			return nil, 0, err
		}
		_, _, wtxid, consumed, err := consensus.ParseTx(entry.Tx)
		if err != nil || consumed != len(entry.Tx) {
			return nil, 0, errors.New("cmpctblock prefilled transaction is non-canonical")
		}
		out[compactShortID(consensus.CompactShortID(wtxid, nonce1, nonce2))] = true
		totalTxBytes = nextTotal
		prev = entry.Index
	}
	return out, totalTxBytes, nil
}

func compactFillPrefilledTransactions(txs [][]byte, prefilled []prefilledTxn) {
	for _, entry := range prefilled {
		txs[int(entry.Index)] = append([]byte(nil), entry.Tx...) // #nosec G115 -- compactPrefilledShortIDs bounds-checks prefilled indexes.
	}
}

func compactFillShortIDTransactions(txs [][]byte, totalEntries int, prefilled []prefilledTxn, shortIDs []compactShortID, index map[compactShortID][]byte, totalTxBytes uint64) error {
	shortPos, prefilledPos := 0, 0
	for absoluteIndex := 0; absoluteIndex < totalEntries && shortPos < len(shortIDs); absoluteIndex++ {
		if compactIndexIsPrefilled(uint64(absoluteIndex), prefilled, &prefilledPos) {
			continue
		}
		tx := index[shortIDs[shortPos]]
		nextTotal, err := validateBlockTxnTransactionSize(uint64(len(tx)), totalTxBytes)
		if err != nil {
			return err
		}
		txs[absoluteIndex] = append([]byte(nil), tx...)
		totalTxBytes = nextTotal
		shortPos++
	}
	return nil
}

func compactMissingShortIDIndexes(totalEntries int, prefilled []prefilledTxn, shortIDs []compactShortID, index map[compactShortID][]byte, blocked map[compactShortID]bool) []uint64 {
	missing := make([]uint64, 0)
	firstHit := make(map[compactShortID]uint64)
	shortPos, prefilledPos := 0, 0
	for absoluteIndex := 0; absoluteIndex < totalEntries && shortPos < len(shortIDs); absoluteIndex++ {
		if compactIndexIsPrefilled(uint64(absoluteIndex), prefilled, &prefilledPos) {
			continue
		}
		shortID := shortIDs[shortPos]
		missing = compactAppendMissingIndex(missing, firstHit, shortID, uint64(absoluteIndex), index[shortID], blocked[shortID])
		if len(missing) >= maxCompactRelayEntries {
			return missing[:maxCompactRelayEntries]
		}
		shortPos++
	}
	return missing
}

func compactIndexIsPrefilled(index uint64, prefilled []prefilledTxn, pos *int) bool {
	if *pos < len(prefilled) && prefilled[*pos].Index == index {
		*pos = *pos + 1
		return true
	}
	return false
}

func compactAppendMissingIndex(missing []uint64, firstHit map[compactShortID]uint64, shortID compactShortID, absoluteIndex uint64, tx []byte, blocked bool) []uint64 {
	if tx == nil || blocked {
		return append(missing, absoluteIndex)
	}
	if firstIndex, ok := firstHit[shortID]; ok {
		if firstIndex != compactDuplicateReportedIndex {
			missing = append(missing, firstIndex)
			firstHit[shortID] = compactDuplicateReportedIndex
		}
		return append(missing, absoluteIndex)
	}
	firstHit[shortID] = absoluteIndex
	return missing
}

func compactLocalTxIndex(localTxs [][]byte, nonce1, nonce2 uint64) (map[compactShortID][]byte, error) {
	out := make(map[compactShortID][]byte, len(localTxs))
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
		out[shortID] = tx
	}
	return out, nil
}

func compactLocalTxWTxID(tx []byte) ([32]byte, error) {
	var zero [32]byte
	if _, err := validateBlockTxnTransactionSize(uint64(len(tx)), 0); err != nil {
		return zero, err
	}
	_, _, wtxid, consumed, err := consensus.ParseTx(tx)
	if err != nil || consumed != len(tx) {
		return zero, errors.New("compact local transaction is non-canonical")
	}
	return wtxid, nil
}
