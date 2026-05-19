package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type compactReconstructionResult struct {
	Transactions   [][]byte
	MissingIndexes []uint64
}

type compactLocalTxCandidate struct {
	tx        []byte
	ambiguous bool
}

func reconstructCompactBlock(p cmpctBlockPayload, localTxs [][]byte) (compactReconstructionResult, error) {
	totalEntries, err := validateCmpctBlockEntryCount(uint64(len(p.ShortIDs)), uint64(len(p.Prefilled)))
	if err != nil {
		return compactReconstructionResult{}, err
	}
	shortIDIndexes, err := compactShortIDIndexes(totalEntries, p.Prefilled)
	if err != nil {
		return compactReconstructionResult{}, err
	}

	txs := make([][]byte, int(totalEntries)) // #nosec G115 -- validateCmpctBlockEntryCount caps totalEntries at MAX_BLOCK_BYTES.
	for _, entry := range p.Prefilled {
		if err := validateCompactCanonicalTx(entry.Tx, "cmpctblock prefilled transaction is non-canonical"); err != nil {
			return compactReconstructionResult{}, err
		}
		txs[int(entry.Index)] = append([]byte(nil), entry.Tx...) // #nosec G115 -- compactShortIDIndexes bounds-checks prefilled indexes.
	}
	index, err := compactLocalTxIndex(localTxs, p.Nonce1, p.Nonce2)
	if err != nil {
		return compactReconstructionResult{}, err
	}

	duplicateShortIDs := compactDuplicateShortIDs(p.ShortIDs)
	missing := make([]uint64, 0)
	for i, shortID := range p.ShortIDs {
		absoluteIndex := shortIDIndexes[i]
		candidate, ok := index[shortID]
		if duplicateShortIDs[shortID] || !ok || candidate.ambiguous {
			missing = append(missing, absoluteIndex)
			continue
		}
		txs[int(absoluteIndex)] = append([]byte(nil), candidate.tx...) // #nosec G115 -- compactShortIDIndexes returns bounded indexes.
	}
	if len(missing) > 0 {
		return compactReconstructionResult{MissingIndexes: missing}, nil
	}
	if err := validateCompactRelayTransactions(txs, "compact reconstruction transaction is non-canonical"); err != nil {
		return compactReconstructionResult{}, err
	}
	return compactReconstructionResult{Transactions: txs}, nil
}

func compactShortIDIndexes(totalEntries uint64, prefilled []prefilledTxn) ([]uint64, error) {
	prefilledIndexes := make(map[uint64]struct{}, len(prefilled))
	var prevPlusOne uint64
	for i, entry := range prefilled {
		if entry.Index >= totalEntries || (i > 0 && entry.Index < prevPlusOne) {
			return nil, errors.New("compact relay index out of range")
		}
		prefilledIndexes[entry.Index] = struct{}{}
		prevPlusOne = entry.Index + 1
	}
	out := make([]uint64, 0, int(totalEntries)-len(prefilled)) // #nosec G115 -- totalEntries is capped before call.
	for index := uint64(0); index < totalEntries; index++ {
		if _, ok := prefilledIndexes[index]; !ok {
			out = append(out, index)
		}
	}
	return out, nil
}

func compactLocalTxIndex(localTxs [][]byte, nonce1, nonce2 uint64) (map[compactShortID]compactLocalTxCandidate, error) {
	out := make(map[compactShortID]compactLocalTxCandidate, len(localTxs))
	for _, tx := range localTxs {
		_, _, wtxid, consumed, err := consensus.ParseTx(tx)
		if err != nil || consumed != len(tx) {
			return nil, errors.New("compact local transaction is non-canonical")
		}
		shortID := compactShortID(consensus.CompactShortID(wtxid, nonce1, nonce2))
		if candidate, ok := out[shortID]; ok {
			candidate.tx = nil
			candidate.ambiguous = true
			out[shortID] = candidate
			continue
		}
		out[shortID] = compactLocalTxCandidate{tx: append([]byte(nil), tx...)}
	}
	return out, nil
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

func validateCompactCanonicalTx(tx []byte, nonCanonicalErr string) error {
	_, _, _, consumed, err := consensus.ParseTx(tx)
	if err != nil || consumed != len(tx) {
		return errors.New(nonCanonicalErr)
	}
	return nil
}
