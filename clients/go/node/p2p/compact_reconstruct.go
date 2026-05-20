package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

const compactDuplicateReportedIndex = ^uint64(0)

var errCompactRelayMissingRequestTooLarge = errors.New("too many compact relay missing indexes")

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
	if totalEntries > maxCompactRelayEntries {
		return compactReconstructionResult{}, errCompactRelayMissingRequestTooLarge
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
	missingIndexes, missingShortIDs, err := compactResolveShortIDTransactions(txs, totalEntries, p.Prefilled, p.ShortIDs, index, prefilledShortIDs)
	if err != nil {
		return compactReconstructionResult{}, err
	}
	if len(missingIndexes) > 0 {
		return compactReconstructionResult{
			PartialTransactions: cloneCompactTransactions(txs),
			MissingIndexes:      missingIndexes,
			MissingShortIDs:     missingShortIDs,
		}, nil
	}
	if err := compactValidateTransactionTotal(txs); err != nil {
		return compactReconstructionResult{}, err
	}
	return compactReconstructionResult{Transactions: cloneCompactTransactions(txs)}, nil
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

func compactResolveShortIDTransactions(
	txs [][]byte,
	totalEntries int,
	prefilled []prefilledTxn,
	shortIDs []compactShortID,
	index map[compactShortID][]byte,
	blocked map[compactShortID]bool,
) ([]uint64, []compactShortID, error) {
	missing := make([]uint64, 0)
	missingShortIDs := make([]compactShortID, 0)
	firstHit := make(map[compactShortID]uint64)
	shortPos, prefilledPos := 0, 0
	for absoluteIndex := 0; absoluteIndex < totalEntries && shortPos < len(shortIDs); absoluteIndex++ {
		if compactIndexIsPrefilled(uint64(absoluteIndex), prefilled, &prefilledPos) {
			continue
		}
		shortID := shortIDs[shortPos]
		var err error
		missing, missingShortIDs, err = compactAppendResolvedShortID(
			txs,
			missing,
			missingShortIDs,
			firstHit,
			shortID,
			uint64(absoluteIndex),
			index[shortID],
			blocked[shortID],
		)
		if err != nil {
			return nil, nil, err
		}
		shortPos++
	}
	return missing, missingShortIDs, nil
}

func compactIndexIsPrefilled(index uint64, prefilled []prefilledTxn, pos *int) bool {
	if *pos < len(prefilled) && prefilled[*pos].Index == index {
		*pos = *pos + 1
		return true
	}
	return false
}

func compactAppendResolvedShortID(
	txs [][]byte,
	missing []uint64,
	missingShortIDs []compactShortID,
	firstHit map[compactShortID]uint64,
	shortID compactShortID,
	absoluteIndex uint64,
	tx []byte,
	blocked bool,
) ([]uint64, []compactShortID, error) {
	if tx == nil || blocked {
		return compactAppendMissingIndex(missing, missingShortIDs, absoluteIndex, shortID)
	}
	if firstIndex, ok := firstHit[shortID]; ok {
		if firstIndex != compactDuplicateReportedIndex {
			txs[int(firstIndex)] = nil // #nosec G115 -- firstIndex was captured from bounded loop index.
			var err error
			missing, missingShortIDs, err = compactAppendMissingIndex(missing, missingShortIDs, firstIndex, shortID)
			if err != nil {
				return nil, nil, err
			}
			firstHit[shortID] = compactDuplicateReportedIndex
		}
		return compactAppendMissingIndex(missing, missingShortIDs, absoluteIndex, shortID)
	}
	firstHit[shortID] = absoluteIndex
	txs[int(absoluteIndex)] = tx // #nosec G115 -- absoluteIndex is bounded by totalEntries loop.
	return missing, missingShortIDs, nil
}

func compactAppendMissingIndex(missing []uint64, missingShortIDs []compactShortID, absoluteIndex uint64, shortID compactShortID) ([]uint64, []compactShortID, error) {
	if len(missing) >= maxCompactRelayEntries {
		return nil, nil, errCompactRelayMissingRequestTooLarge
	}
	return append(missing, absoluteIndex), append(missingShortIDs, shortID), nil
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

func compactValidateTransactionTotal(txs [][]byte) error {
	var totalTxBytes uint64
	for _, tx := range txs {
		if tx == nil {
			return errors.New("compact block transaction missing")
		}
		nextTotal, err := validateBlockTxnTransactionSize(uint64(len(tx)), totalTxBytes)
		if err != nil {
			return err
		}
		totalTxBytes = nextTotal
	}
	return nil
}

type compactOutstandingRequest struct {
	BlockHash       [32]byte
	Header          [consensus.BLOCK_HEADER_BYTES]byte
	MissingIndexes  []uint64
	MissingShortIDs []compactShortID
	Transactions    [][]byte
	Nonce1          uint64
	Nonce2          uint64
}

func (p *peer) handleCmpctBlock(payload []byte) error {
	header, blockHash, err := compactBlockHeaderAndHash(payload)
	if err != nil {
		return err
	}
	if err := p.validateCompactBlockHeader(header); err != nil {
		return err
	}
	block, err := decodeCmpctBlockPayload(payload)
	if err != nil {
		return err
	}
	have, err := p.service.hasBlock(blockHash)
	if err != nil || have {
		return err
	}
	result, err := reconstructCompactBlock(block, compactRelayLocalTransactions(p.service.cfg.TxPool))
	if errors.Is(err, errCompactRelayMissingRequestTooLarge) {
		return p.requestCompactFullBlockFallback(blockHash)
	}
	if err != nil {
		return err
	}
	if result.Transactions != nil {
		return p.processCompactTransactions(blockHash, block.Header, result.Transactions)
	}
	req, err := newCompactOutstandingRequest(block, blockHash, result)
	if err != nil {
		return err
	}
	if p.hasCompactOutstandingRequest() {
		return p.requestCompactFullBlockFallback(blockHash)
	}
	body, err := encodeGetBlockTxnPayload(getBlockTxnPayload{BlockHash: blockHash, Indexes: req.MissingIndexes})
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

func (p *peer) handleGetBlockTxn(payload []byte) error {
	req, err := decodeGetBlockTxnPayload(payload)
	if err != nil {
		return err
	}
	if err := validateCompactRequestedIndexShape(req.Indexes); err != nil {
		return err
	}
	blockBytes, ok, err := p.blockBytes(req.BlockHash)
	if err != nil || !ok {
		return err
	}
	responseTxs, err := compactRequestedTransactionsFromBlock(blockBytes, req.Indexes)
	if err != nil {
		return err
	}
	body, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: req.BlockHash, Transactions: responseTxs})
	if err != nil {
		return err
	}
	return p.send(messageBlockTxn, body)
}

func (p *peer) handleBlockTxn(payload []byte) error {
	req, ok := p.compactOutstandingRequestSnapshot()
	if !ok {
		return errors.New("unexpected blocktxn response")
	}
	responseHash, err := compactBlockTxnPayloadHash(payload)
	if err != nil {
		return p.requestCompactFullBlockFallbackForOutstanding(err)
	}
	if responseHash != req.BlockHash {
		return p.requestCompactFullBlockFallbackForOutstanding(errors.New("unexpected blocktxn response"))
	}
	response, err := decodeBlockTxnRuntimePayload(payload)
	if err != nil {
		return p.requestCompactFullBlockFallbackForOutstanding(err)
	}
	req, ok = p.popCompactOutstandingRequest()
	if !ok {
		return errors.New("unexpected blocktxn response")
	}
	txs, err := compactFillResponseTransactions(req, response.Transactions, response.WTxIDs)
	if err != nil {
		return p.requestCompactFullBlockFallback(req.BlockHash)
	}
	if err := p.processCompactTransactions(req.BlockHash, req.Header, txs); err != nil {
		return err
	}
	return nil
}

func newCompactOutstandingRequest(block cmpctBlockPayload, blockHash [32]byte, result compactReconstructionResult) (compactOutstandingRequest, error) {
	if len(result.MissingIndexes) == 0 || len(result.MissingIndexes) != len(result.MissingShortIDs) {
		return compactOutstandingRequest{}, errors.New("compact reconstruction missing request mismatch")
	}
	return compactOutstandingRequest{
		BlockHash:       blockHash,
		Header:          block.Header,
		MissingIndexes:  append([]uint64(nil), result.MissingIndexes...),
		MissingShortIDs: append([]compactShortID(nil), result.MissingShortIDs...),
		Transactions:    cloneCompactTransactions(result.PartialTransactions),
		Nonce1:          block.Nonce1,
		Nonce2:          block.Nonce2,
	}, nil
}

func compactBlockHeaderAndHash(payload []byte) ([consensus.BLOCK_HEADER_BYTES]byte, [32]byte, error) {
	var header [consensus.BLOCK_HEADER_BYTES]byte
	var blockHash [32]byte
	if len(payload) > consensus.MAX_RELAY_MSG_BYTES {
		return header, blockHash, errors.New("cmpctblock payload too large")
	}
	if len(payload) < consensus.BLOCK_HEADER_BYTES {
		return header, blockHash, errors.New("cmpctblock payload missing header or nonce")
	}
	copy(header[:], payload[:consensus.BLOCK_HEADER_BYTES])
	hash, err := consensus.BlockHash(header[:])
	if err != nil {
		return header, blockHash, err
	}
	return header, hash, nil
}

func (p *peer) validateCompactBlockHeader(header [consensus.BLOCK_HEADER_BYTES]byte) error {
	parsed, err := consensus.ParseBlockHeaderBytes(header[:])
	if err != nil {
		p.bumpBan(10, err.Error())
		return err
	}
	if err := consensus.PowCheck(header[:], parsed.Target); err != nil {
		p.bumpBan(100, err.Error())
		return err
	}
	return nil
}

func compactBlockTxnPayloadHash(payload []byte) ([32]byte, error) {
	var blockHash [32]byte
	if len(payload) < 32 {
		return blockHash, errors.New("blocktxn payload missing block hash")
	}
	copy(blockHash[:], payload[:32])
	return blockHash, nil
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
	return txs, nil
}

func (p *peer) processCompactTransactions(blockHash [32]byte, header [consensus.BLOCK_HEADER_BYTES]byte, txs [][]byte) error {
	blockBytes, err := compactBlockBytes(header, txs)
	if err != nil {
		return p.requestCompactFullBlockFallback(blockHash)
	}
	accepted, err := p.processCompactRelayedBlock(blockHash, blockBytes)
	if err != nil {
		return p.requestCompactFullBlockFallback(blockHash)
	}
	if !accepted {
		return nil
	}
	return p.service.requestBlocksIfBehind(p)
}

func (p *peer) processCompactRelayedBlock(expectedHash [32]byte, blockBytes []byte) (bool, error) {
	pb, blockHash, err := parseRelayedBlock(blockBytes)
	if err != nil {
		return false, err
	}
	if pb == nil {
		return false, errors.New("nil parsed block")
	}
	if blockHash != expectedHash {
		return false, errors.New("compact block hash mismatch")
	}
	have, err := p.service.hasBlock(blockHash)
	if err != nil || have {
		return false, err
	}

	p.service.chainMu.Lock()
	summary, err := p.service.cfg.SyncEngine.ApplyBlockWithReorg(blockBytes, nil)
	p.service.chainMu.Unlock()
	if err != nil {
		if errors.Is(err, node.ErrParentNotFound) {
			_, retainErr := p.retainRelayedOrphanIfValid(pb, blockHash, blockBytes)
			return false, retainErr
		}
		return false, err
	}
	p.acceptedRelayedBlock(blockHash, summary)
	return true, nil
}

func (p *peer) requestCompactFullBlockFallbackForOutstanding(cause error) error {
	req, ok := p.popCompactOutstandingRequest()
	if !ok {
		return cause
	}
	return p.requestCompactFullBlockFallback(req.BlockHash)
}

func (p *peer) requestCompactFullBlockFallback(blockHash [32]byte) error {
	body, err := encodeInventoryVectors([]InventoryVector{{Type: MSG_BLOCK, Hash: blockHash}})
	if err != nil {
		return err
	}
	return p.send(messageGetData, body)
}

func compactBlockBytes(header [consensus.BLOCK_HEADER_BYTES]byte, txs [][]byte) ([]byte, error) {
	if len(txs) == 0 {
		return nil, errors.New("compact block has no transactions")
	}
	out := append([]byte(nil), header[:]...)
	out = consensus.AppendCompactSize(out, uint64(len(txs)))
	var totalTxBytes uint64
	for _, tx := range txs {
		if tx == nil {
			return nil, errors.New("compact block transaction missing")
		}
		nextTotal, err := validateBlockTxnTransactionSize(uint64(len(tx)), totalTxBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, tx...)
		totalTxBytes = nextTotal
		if len(out) > consensus.MAX_BLOCK_BYTES {
			return nil, errors.New("compact block exceeds block size")
		}
	}
	return out, nil
}

func compactBlockTransactions(blockBytes []byte) ([consensus.BLOCK_HEADER_BYTES]byte, [][]byte, error) {
	var header [consensus.BLOCK_HEADER_BYTES]byte
	if len(blockBytes) < consensus.BLOCK_HEADER_BYTES+1 {
		return header, nil, errors.New("block too short")
	}
	copy(header[:], blockBytes[:consensus.BLOCK_HEADER_BYTES])
	offset := consensus.BLOCK_HEADER_BYTES
	txCount, consumed, err := consensus.DecodeCompactSize(blockBytes[offset:])
	if err != nil {
		return header, nil, err
	}
	if txCount == 0 || txCount > maxCmpctBlockEntries {
		return header, nil, errors.New("invalid compact relay entry count")
	}
	offset += consumed
	txs := make([][]byte, 0, int(txCount)) // #nosec G115 -- txCount is capped at maxCmpctBlockEntries above.
	for i := uint64(0); i < txCount; i++ {
		_, _, _, txConsumed, err := consensus.ParseTx(blockBytes[offset:])
		if err != nil {
			return header, nil, err
		}
		txs = append(txs, append([]byte(nil), blockBytes[offset:offset+txConsumed]...))
		offset += txConsumed
	}
	if offset != len(blockBytes) {
		return header, nil, errors.New("trailing bytes after tx list")
	}
	return header, txs, nil
}

func compactRequestedTransactionsFromBlock(blockBytes []byte, indexes []uint64) ([][]byte, error) {
	if err := validateCompactRequestedIndexShape(indexes); err != nil {
		return nil, err
	}
	if len(indexes) == 0 {
		return [][]byte{}, nil
	}
	txCount, offset, err := compactBlockTransactionCount(blockBytes)
	if err != nil {
		return nil, err
	}
	requested := make(map[uint64]int, len(indexes))
	var maxRequested uint64
	for pos, idx := range indexes {
		if idx >= txCount {
			return nil, errors.New("compact relay index out of range")
		}
		requested[idx] = pos
		if idx > maxRequested {
			maxRequested = idx
		}
	}
	out := make([][]byte, 0, len(indexes))
	for range indexes {
		out = append(out, nil)
	}
	var totalTxBytes uint64
	for idx := uint64(0); idx <= maxRequested; idx++ {
		_, _, _, consumed, err := consensus.ParseTx(blockBytes[offset:])
		if err != nil {
			return nil, err
		}
		if pos, ok := requested[idx]; ok {
			nextTotal, err := validateBlockTxnTransactionSize(uint64(consumed), totalTxBytes)
			if err != nil {
				return nil, err
			}
			out[pos] = append([]byte(nil), blockBytes[offset:offset+consumed]...)
			totalTxBytes = nextTotal
		}
		offset += consumed
	}
	return out, nil
}

func compactBlockTransactionCount(blockBytes []byte) (uint64, int, error) {
	if len(blockBytes) < consensus.BLOCK_HEADER_BYTES+1 {
		return 0, 0, errors.New("block too short")
	}
	offset := consensus.BLOCK_HEADER_BYTES
	txCount, consumed, err := consensus.DecodeCompactSize(blockBytes[offset:])
	if err != nil {
		return 0, 0, err
	}
	if txCount == 0 || txCount > maxCmpctBlockEntries {
		return 0, 0, errors.New("invalid compact relay entry count")
	}
	return txCount, offset + consumed, nil
}

func validateCompactRequestedIndexShape(indexes []uint64) error {
	seen := make(map[uint64]struct{}, len(indexes))
	for _, idx := range indexes {
		if _, ok := seen[idx]; ok {
			return errors.New("duplicate compact relay index")
		}
		seen[idx] = struct{}{}
	}
	return nil
}

func compactRelayLocalTransactions(pool TxPool) [][]byte {
	switch pool := pool.(type) {
	case *MemoryTxPool:
		if pool == nil {
			return nil
		}
		pool.mu.RLock()
		defer pool.mu.RUnlock()
		out := make([][]byte, 0, len(pool.txs))
		for _, entry := range pool.txs {
			out = append(out, entry.raw)
		}
		return out
	case *CanonicalMempoolTxPool:
		if pool == nil || pool.mempool == nil {
			return nil
		}
		ids := pool.mempool.AllTxIDs()
		out := make([][]byte, 0, len(ids))
		for _, txid := range ids {
			if tx, ok := pool.mempool.TxByID(txid); ok {
				out = append(out, tx)
			}
		}
		return out
	default:
		return nil
	}
}

func compactTransactionShortID(tx []byte, nonce1, nonce2 uint64) (compactShortID, error) {
	wtxid, err := compactLocalTxWTxID(tx)
	if err != nil {
		return compactShortID{}, err
	}
	return compactShortID(consensus.CompactShortID(wtxid, nonce1, nonce2)), nil
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

func (p *peer) setCompactOutstandingRequest(req compactOutstandingRequest) {
	p.compactMu.Lock()
	clone := cloneCompactOutstandingRequest(req)
	p.compact.outstanding = &clone
	p.compactMu.Unlock()
}

func (p *peer) hasCompactOutstandingRequest() bool {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	return p.compact.outstanding != nil
}

func (p *peer) fallbackCompactOutstandingRequest() error {
	req, ok := p.popCompactOutstandingRequest()
	if !ok {
		return nil
	}
	return p.requestCompactFullBlockFallback(req.BlockHash)
}

func (p *peer) clearCompactOutstandingRequest() {
	p.compactMu.Lock()
	p.compact.outstanding = nil
	p.compactMu.Unlock()
}

func (p *peer) popCompactOutstandingRequest() (compactOutstandingRequest, bool) {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	if p.compact.outstanding == nil {
		return compactOutstandingRequest{}, false
	}
	req := cloneCompactOutstandingRequest(*p.compact.outstanding)
	p.compact.outstanding = nil
	return req, true
}

func (p *peer) compactOutstandingRequestSnapshot() (compactOutstandingRequest, bool) {
	p.compactMu.Lock()
	defer p.compactMu.Unlock()
	if p.compact.outstanding == nil {
		return compactOutstandingRequest{}, false
	}
	return cloneCompactOutstandingRequest(*p.compact.outstanding), true
}

func cloneCompactOutstandingRequest(req compactOutstandingRequest) compactOutstandingRequest {
	req.MissingIndexes = append([]uint64(nil), req.MissingIndexes...)
	req.MissingShortIDs = append([]compactShortID(nil), req.MissingShortIDs...)
	req.Transactions = cloneCompactTransactions(req.Transactions)
	return req
}
