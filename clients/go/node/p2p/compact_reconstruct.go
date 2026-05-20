package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const compactDuplicateReportedIndex = ^uint64(0)

var errCompactRelayMissingRequestTooLarge = errors.New("too many compact relay missing transactions")

type compactReconstructionResult struct {
	Transactions        [][]byte
	PartialTransactions [][]byte
	MissingIndexes      []uint64
	MissingShortIDs     []compactShortID
}

func reconstructCompactBlock(p cmpctBlockPayload, localTxs [][]byte) (compactReconstructionResult, error) {
	totalEntries, err := compactReconstructionEntryCount(len(p.ShortIDs), p.Prefilled)
	if err != nil {
		return compactReconstructionResult{}, err
	}
	prefilledShortIDs, _, err := compactPrefilledShortIDs(p.Prefilled, totalEntries, p.Nonce1, p.Nonce2)
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

	txs := make([][]byte, totalEntries)
	compactFillPrefilledTransactions(txs, p.Prefilled)
	missing, missingShortIDs, overflow, err := compactFillOrCollectMissing(
		txs,
		totalEntries,
		p.Prefilled,
		p.ShortIDs,
		index,
		prefilledShortIDs,
	)
	if overflow {
		return compactReconstructionResult{}, errCompactRelayMissingRequestTooLarge
	}
	if err != nil {
		return compactReconstructionResult{}, err
	}
	if len(missing) > 0 {
		return compactReconstructionResult{
			PartialTransactions: txs,
			MissingIndexes:      missing,
			MissingShortIDs:     missingShortIDs,
		}, nil
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
	staged := cloneCompactTransactions(txs)
	missing, _, overflow, err := compactFillOrCollectMissing(staged, totalEntries, prefilled, shortIDs, index, nil)
	if overflow {
		return errCompactRelayMissingRequestTooLarge
	}
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return errors.New("compact block transaction missing")
	}
	if err := compactValidatePresentTransactionsFrom(staged, true, totalTxBytes); err != nil {
		return err
	}
	copy(txs, staged)
	return nil
}

func compactFillOrCollectMissing(txs [][]byte, totalEntries int, prefilled []prefilledTxn, shortIDs []compactShortID, index map[compactShortID][]byte, blocked map[compactShortID]bool) ([]uint64, []compactShortID, bool, error) {
	missing := make([]uint64, 0)
	missingShortIDs := make([]compactShortID, 0)
	firstHit := make(map[compactShortID]uint64)
	shortPos, prefilledPos := 0, 0
	for absoluteIndex := 0; absoluteIndex < totalEntries && shortPos < len(shortIDs); absoluteIndex++ {
		if compactIndexIsPrefilled(uint64(absoluteIndex), prefilled, &prefilledPos) {
			continue
		}
		shortID := shortIDs[shortPos]
		tx := index[shortID]
		if tx == nil || blocked[shortID] {
			missing, missingShortIDs = compactAppendMissing(missing, missingShortIDs, uint64(absoluteIndex), shortID)
			if len(missing) > maxCompactRelayEntries {
				return missing, missingShortIDs, true, nil
			}
			shortPos++
			continue
		}
		if firstIndex, ok := firstHit[shortID]; ok {
			if firstIndex != compactDuplicateReportedIndex {
				missing, missingShortIDs = compactAppendMissing(missing, missingShortIDs, firstIndex, shortID)
				txs[int(firstIndex)] = nil // #nosec G115 -- firstIndex was produced by this bounded loop.
				firstHit[shortID] = compactDuplicateReportedIndex
			}
			missing, missingShortIDs = compactAppendMissing(missing, missingShortIDs, uint64(absoluteIndex), shortID)
			if len(missing) > maxCompactRelayEntries {
				return missing, missingShortIDs, true, nil
			}
			shortPos++
			continue
		}
		firstHit[shortID] = uint64(absoluteIndex)
		txs[absoluteIndex] = append([]byte(nil), tx...)
		shortPos++
	}
	if err := compactValidatePresentTransactions(txs, false); err != nil {
		return nil, nil, false, err
	}
	return missing, missingShortIDs, false, nil
}

func compactAppendMissing(missing []uint64, missingShortIDs []compactShortID, absoluteIndex uint64, shortID compactShortID) ([]uint64, []compactShortID) {
	return append(missing, absoluteIndex), append(missingShortIDs, shortID)
}

func compactIndexIsPrefilled(index uint64, prefilled []prefilledTxn, pos *int) bool {
	if *pos < len(prefilled) && prefilled[*pos].Index == index {
		*pos = *pos + 1
		return true
	}
	return false
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

func newCompactOutstandingRequest(block cmpctBlockPayload, blockHash [32]byte, result compactReconstructionResult) (compactOutstandingRequest, error) {
	if len(result.MissingIndexes) == 0 || len(result.MissingIndexes) != len(result.MissingShortIDs) {
		return compactOutstandingRequest{}, errors.New("compact reconstruction missing request mismatch")
	}
	return compactOutstandingRequest{
		BlockHash:          blockHash,
		Header:             block.Header,
		MissingIndexes:     append([]uint64(nil), result.MissingIndexes...),
		MissingShortIDs:    append([]compactShortID(nil), result.MissingShortIDs...),
		Transactions:       cloneCompactTransactions(result.PartialTransactions),
		Nonce1:             block.Nonce1,
		Nonce2:             block.Nonce2,
		BlockTxnPayloadCap: compactRelayPayloadCap(messageBlockTxn),
	}, nil
}

func compactFillResponseTransactions(req compactOutstandingRequest, responseTxs [][]byte, responseWTxIDs [][32]byte) ([][]byte, error) {
	if len(req.MissingIndexes) != len(req.MissingShortIDs) || len(responseTxs) != len(req.MissingIndexes) || len(responseWTxIDs) != len(responseTxs) {
		return nil, errors.New("blocktxn transaction count mismatch")
	}
	txs := cloneCompactTransactions(req.Transactions)
	for i, tx := range responseTxs {
		shortID := compactShortID(consensus.CompactShortID(responseWTxIDs[i], req.Nonce1, req.Nonce2))
		if shortID != req.MissingShortIDs[i] {
			return nil, errors.New("blocktxn transaction short id mismatch")
		}
		idx := req.MissingIndexes[i]
		if idx >= uint64(len(txs)) {
			return nil, errors.New("compact relay index out of range")
		}
		txs[int(idx)] = append([]byte(nil), tx...) // #nosec G115 -- idx is bounded by len(txs) above.
	}
	if err := compactValidatePresentTransactions(txs, true); err != nil {
		return nil, err
	}
	return txs, nil
}

func compactValidatePresentTransactions(txs [][]byte, requireComplete bool) error {
	return compactValidatePresentTransactionsFrom(txs, requireComplete, 0)
}

func compactValidatePresentTransactionsFrom(txs [][]byte, requireComplete bool, totalTxBytes uint64) error {
	for _, tx := range txs {
		if tx == nil {
			if requireComplete {
				return errors.New("compact block transaction missing")
			}
			continue
		}
		nextTotal, err := validateBlockTxnTransactionSize(uint64(len(tx)), totalTxBytes)
		if err != nil {
			return err
		}
		totalTxBytes = nextTotal
	}
	return nil
}

func cloneCompactTransactions(txs [][]byte) [][]byte {
	if txs == nil {
		return nil
	}
	out := make([][]byte, len(txs))
	for i, tx := range txs {
		if tx != nil {
			out[i] = append([]byte(nil), tx...)
		}
	}
	return out
}
