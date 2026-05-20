package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const compactDuplicateReportedIndex = ^uint64(0)

var errCompactRelayMissingRequestTooLarge = errors.New("too many compact relay missing transactions")

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

	missing, overflow := compactMissingShortIDIndexes(totalEntries, p.Prefilled, p.ShortIDs, index, prefilledShortIDs)
	if overflow {
		return compactReconstructionResult{}, errCompactRelayMissingRequestTooLarge
	}
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

func compactMissingShortIDIndexes(totalEntries int, prefilled []prefilledTxn, shortIDs []compactShortID, index map[compactShortID][]byte, blocked map[compactShortID]bool) ([]uint64, bool) {
	missing := make([]uint64, 0)
	firstHit := make(map[compactShortID]uint64)
	shortPos, prefilledPos := 0, 0
	for absoluteIndex := 0; absoluteIndex < totalEntries && shortPos < len(shortIDs); absoluteIndex++ {
		if compactIndexIsPrefilled(uint64(absoluteIndex), prefilled, &prefilledPos) {
			continue
		}
		shortID := shortIDs[shortPos]
		missing = compactAppendMissingIndex(missing, firstHit, shortID, uint64(absoluteIndex), index[shortID], blocked[shortID])
		if len(missing) > maxCompactRelayEntries {
			return missing[:maxCompactRelayEntries], true
		}
		shortPos++
	}
	return missing, false
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

func (p *peer) handleCmpctBlock(payload []byte) error {
	block, err := decodeCmpctBlockPayload(payload)
	if err != nil {
		return err
	}
	blockHash, err := consensus.BlockHash(block.Header[:])
	if err != nil {
		return err
	}
	have, err := p.service.hasBlock(blockHash)
	if err != nil || have {
		return err
	}
	result, err := reconstructCompactBlock(block, nil)
	if err != nil {
		if errors.Is(err, errCompactRelayMissingRequestTooLarge) {
			return p.requestCompactFullBlock(blockHash)
		}
		return err
	}
	if result.Transactions != nil {
		return p.processCompactTransactions(block.Header, result.Transactions)
	}
	return p.requestMissingCompactTransactions(block, blockHash, result.MissingIndexes)
}

func (p *peer) requestMissingCompactTransactions(block cmpctBlockPayload, blockHash [32]byte, missing []uint64) error {
	if _, ok := p.compactOutstandingRequest(); ok {
		return p.requestCompactFullBlock(blockHash)
	}
	req, err := newCompactOutstandingRequest(block, blockHash, missing)
	if err != nil {
		return err
	}
	body, err := encodeGetBlockTxnPayload(getBlockTxnPayload{BlockHash: blockHash, Indexes: missing})
	if err != nil {
		return err
	}
	p.setCompactOutstandingRequest(req)
	if err := p.send(messageGetBlockTxn, body); err != nil {
		p.clearCompactOutstandingRequest()
		return err
	}
	return nil
}

func (p *peer) handleBlockTxn(payload []byte) error {
	var responseHash [32]byte
	if len(payload) < 32 {
		p.clearCompactOutstandingRequest()
		return errors.New("blocktxn payload missing block hash")
	}
	copy(responseHash[:], payload[:32])
	req, ok := p.compactOutstandingRequest()
	if !ok {
		return errors.New("unsolicited blocktxn response")
	}
	if responseHash != req.BlockHash {
		return errors.New("unexpected blocktxn response")
	}
	p.clearCompactOutstandingRequest()
	response, err := decodeBlockTxnRuntimePayload(payload)
	if err != nil {
		return err
	}
	if err := validateBlockTxnResponseMatchesRequest(req, response); err != nil {
		return p.requestCompactFullBlock(req.BlockHash)
	}
	result, err := reconstructCompactBlock(req.Block, response.Transactions)
	if err != nil {
		return p.requestCompactFullBlock(req.BlockHash)
	}
	if result.Transactions == nil {
		return p.requestCompactFullBlock(req.BlockHash)
	}
	return p.processCompactTransactions(req.Block.Header, result.Transactions)
}

func (p *peer) requestCompactFullBlock(blockHash [32]byte) error {
	body, err := encodeInventoryVectors([]InventoryVector{{Type: MSG_BLOCK, Hash: blockHash}})
	if err != nil {
		return err
	}
	return p.send(messageGetData, body)
}

func newCompactOutstandingRequest(block cmpctBlockPayload, blockHash [32]byte, missing []uint64) (compactOutstandingRequest, error) {
	missingShortIDs, err := compactShortIDsAtIndexes(block, missing)
	if err != nil {
		return compactOutstandingRequest{}, err
	}
	return compactOutstandingRequest{
		BlockHash:          blockHash,
		Block:              block,
		MissingShortIDs:    missingShortIDs,
		BlockTxnPayloadCap: uint32(32 + maxCompactSizeBytes + consensus.MAX_BLOCK_BYTES + uint64(len(missing))*maxCompactSizeBytes),
	}, nil
}

func compactShortIDsAtIndexes(block cmpctBlockPayload, indexes []uint64) ([]compactShortID, error) {
	if err := validateCompactRequestedIndexShape(indexes); err != nil {
		return nil, err
	}
	if len(indexes) == 0 {
		return nil, errors.New("compact reconstruction missing request mismatch")
	}
	out := make([]compactShortID, 0, len(indexes))
	want := make(map[uint64]struct{}, len(indexes))
	for _, idx := range indexes {
		want[idx] = struct{}{}
	}
	shortPos, prefilledPos := 0, 0
	total := len(block.ShortIDs) + len(block.Prefilled)
	for absoluteIndex := 0; absoluteIndex < total && len(out) < len(indexes); absoluteIndex++ {
		if compactIndexIsPrefilled(uint64(absoluteIndex), block.Prefilled, &prefilledPos) {
			if _, ok := want[uint64(absoluteIndex)]; ok {
				return nil, errors.New("compact relay index points to prefilled transaction")
			}
			continue
		}
		if _, ok := want[uint64(absoluteIndex)]; ok {
			out = append(out, block.ShortIDs[shortPos])
		}
		shortPos++
	}
	if len(out) != len(indexes) {
		return nil, errors.New("compact relay index out of range")
	}
	return out, nil
}

func validateBlockTxnResponseMatchesRequest(req compactOutstandingRequest, response blockTxnRuntimePayload) error {
	if len(response.Transactions) != len(req.MissingShortIDs) || len(response.WTxIDs) != len(response.Transactions) {
		return errors.New("blocktxn transaction count mismatch")
	}
	for i, wtxid := range response.WTxIDs {
		shortID := compactShortID(consensus.CompactShortID(wtxid, req.Block.Nonce1, req.Block.Nonce2))
		if shortID != req.MissingShortIDs[i] {
			return errors.New("blocktxn transaction short id mismatch")
		}
	}
	return nil
}

func (p *peer) processCompactTransactions(header [consensus.BLOCK_HEADER_BYTES]byte, txs [][]byte) error {
	if len(txs) == 0 {
		return errors.New("compact block has no transactions")
	}
	blockBytes := append([]byte(nil), header[:]...)
	blockBytes = consensus.AppendCompactSize(blockBytes, uint64(len(txs)))
	for _, tx := range txs {
		if tx == nil {
			return errors.New("compact block transaction missing")
		}
		blockBytes = append(blockBytes, tx...)
	}
	if len(blockBytes) > consensus.MAX_BLOCK_BYTES {
		return errors.New("compact block exceeds block size")
	}
	summary, err := p.processRelayedBlock(blockBytes)
	if err != nil || summary == nil {
		return err
	}
	return p.service.requestBlocksIfBehind(p)
}

func validateCompactRequestedIndexShape(indexes []uint64) error {
	if len(indexes) > maxCompactRelayEntries {
		return errors.New("too many compact relay indexes")
	}
	seen := make(map[uint64]struct{}, len(indexes))
	for _, idx := range indexes {
		if idx > maxCompactRelayIndexValue {
			return errors.New("compact relay index exceeds runtime cap")
		}
		if _, ok := seen[idx]; ok {
			return errors.New("duplicate compact relay index")
		}
		seen[idx] = struct{}{}
	}
	return nil
}

func (p *peer) setCompactOutstandingRequest(req compactOutstandingRequest) {
	p.compactMu.Lock()
	p.compact.outstanding = &req
	p.compactMu.Unlock()
}

func (p *peer) clearCompactOutstandingRequest() {
	p.compactMu.Lock()
	p.compact.outstanding = nil
	p.compactMu.Unlock()
}

func (p *peer) compactOutstandingRequest() (compactOutstandingRequest, bool) {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	if p.compact.outstanding == nil {
		return compactOutstandingRequest{}, false
	}
	return *p.compact.outstanding, true
}
