package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
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

	if _, _, overflow, err := compactFillOrCollectMissing(nil, totalEntries, p.Prefilled, p.ShortIDs, index, prefilledShortIDs); overflow {
		return compactReconstructionResult{}, errCompactRelayMissingRequestTooLarge
	} else if err != nil {
		return compactReconstructionResult{}, err
	}
	txs := make([][]byte, totalEntries)
	compactStagePrefilledTransactions(txs, p.Prefilled)
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

func compactStagePrefilledTransactions(txs [][]byte, prefilled []prefilledTxn) {
	for _, entry := range prefilled {
		txs[int(entry.Index)] = entry.Tx // #nosec G115 -- compactPrefilledShortIDs bounds-checks prefilled indexes.
	}
}

func compactFillShortIDTransactions(txs [][]byte, totalEntries int, prefilled []prefilledTxn, shortIDs []compactShortID, index map[compactShortID][]byte) error {
	staged := append([][]byte(nil), txs...)
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
	if err := compactValidatePresentTransactions(staged, true); err != nil {
		return err
	}
	copy(txs, staged)
	return nil
}

type compactFillContext struct {
	txs             [][]byte
	missing         []uint64
	missingShortIDs []compactShortID
	firstHit        map[compactShortID]uint64
}

func compactFillOrCollectMissing(txs [][]byte, totalEntries int, prefilled []prefilledTxn, shortIDs []compactShortID, index map[compactShortID][]byte, blocked map[compactShortID]bool) ([]uint64, []compactShortID, bool, error) {
	ctx := newCompactFillContext(txs)
	shortPos, prefilledPos := 0, 0
	for absoluteIndex := 0; absoluteIndex < totalEntries && shortPos < len(shortIDs); absoluteIndex++ {
		if compactIndexIsPrefilled(uint64(absoluteIndex), prefilled, &prefilledPos) {
			continue
		}
		shortID := shortIDs[shortPos]
		overflow, err := ctx.fill(uint64(absoluteIndex), shortID, index[shortID], blocked[shortID])
		if overflow || err != nil {
			return ctx.missing, ctx.missingShortIDs, overflow, err
		}
		shortPos++
	}
	if txs != nil {
		if err := compactValidatePresentTransactions(txs, false); err != nil {
			return nil, nil, false, err
		}
		cloneCompactTransactionsInPlace(txs)
	}
	return ctx.missing, ctx.missingShortIDs, false, nil
}

func newCompactFillContext(txs [][]byte) *compactFillContext {
	return &compactFillContext{
		txs:             txs,
		missing:         make([]uint64, 0),
		missingShortIDs: make([]compactShortID, 0),
		firstHit:        make(map[compactShortID]uint64),
	}
}

func (c *compactFillContext) fill(absoluteIndex uint64, shortID compactShortID, tx []byte, blocked bool) (bool, error) {
	if compactShortIDUnavailable(tx, blocked) {
		return c.appendMissing(absoluteIndex, shortID), nil
	}
	if firstIndex, ok := c.firstHit[shortID]; ok {
		return c.handleDuplicate(firstIndex, absoluteIndex, shortID), nil
	}
	c.firstHit[shortID] = absoluteIndex
	if c.txs != nil {
		c.txs[int(absoluteIndex)] = tx // #nosec G115 -- absoluteIndex is bounded by totalEntries.
	}
	return false, nil
}

func compactShortIDUnavailable(tx []byte, blocked bool) bool {
	return tx == nil || blocked
}

func (c *compactFillContext) handleDuplicate(firstIndex uint64, absoluteIndex uint64, shortID compactShortID) bool {
	if firstIndex != compactDuplicateReportedIndex {
		if c.txs != nil {
			c.txs[int(firstIndex)] = nil // #nosec G115 -- firstIndex was produced by the bounded fill loop.
		}
		c.firstHit[shortID] = compactDuplicateReportedIndex
		if c.appendMissing(firstIndex, shortID) {
			return true
		}
	}
	return c.appendMissing(absoluteIndex, shortID)
}

func (c *compactFillContext) appendMissing(absoluteIndex uint64, shortID compactShortID) bool {
	c.missing, c.missingShortIDs = compactAppendMissing(c.missing, c.missingShortIDs, absoluteIndex, shortID)
	return len(c.missing) > maxCompactRelayEntries
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

func (p *peer) handleCmpctBlock(payload []byte) error {
	block, err := decodeCmpctBlockPayload(payload)
	if err != nil {
		return err
	}
	blockHash, err := consensus.BlockHash(block.Header[:])
	if err != nil {
		return err
	}
	if err := p.validateCompactBlockHeader(block.Header); err != nil {
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
	return p.requestMissingCompactTransactions(block, blockHash, result)
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
	if expected := p.service.cfg.SyncConfig.ExpectedTarget; expected != nil && parsed.Target != *expected {
		err := &consensus.TxError{Code: consensus.BLOCK_ERR_TARGET_INVALID, Msg: "target mismatch"}
		p.bumpBan(100, err.Error())
		return err
	}
	return nil
}

func (p *peer) requestMissingCompactTransactions(block cmpctBlockPayload, blockHash [32]byte, result compactReconstructionResult) error {
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		return p.requestCompactFullBlockFallback(blockHash)
	}
	req, err := newCompactOutstandingRequest(block, blockHash, result)
	if err != nil {
		return err
	}
	body, err := encodeGetBlockTxnPayload(getBlockTxnPayload{BlockHash: blockHash, Indexes: req.MissingIndexes})
	if err != nil {
		return err
	}
	p.setCompactOutstandingRequest(req)
	if err := p.send(messageGetBlockTxn, body); err != nil {
		p.popCompactOutstandingRequest()
		return err
	}
	return nil
}

func (p *peer) handleBlockTxn(payload []byte) error {
	responseHash, err := compactBlockTxnPayloadHash(payload)
	if err != nil {
		return err
	}
	req, ok := p.compactOutstandingRequestSnapshot()
	if !ok {
		return errors.New("unexpected blocktxn response")
	}
	if responseHash != req.BlockHash {
		return errors.New("blocktxn block hash mismatch")
	}
	response, err := decodeBlockTxnRuntimePayload(payload)
	if err != nil {
		p.popCompactOutstandingRequest()
		return p.requestCompactFullBlockFallback(req.BlockHash)
	}
	req, ok = p.popCompactOutstandingRequest()
	if !ok {
		return errors.New("unexpected blocktxn response")
	}
	txs, err := compactFillResponseTransactions(req, response)
	if err != nil {
		return p.requestCompactFullBlockFallback(req.BlockHash)
	}
	return p.processCompactTransactions(req.BlockHash, req.Header, txs)
}

func compactBlockTxnPayloadHash(payload []byte) ([32]byte, error) {
	var blockHash [32]byte
	if len(payload) < 32 {
		return blockHash, errors.New("blocktxn payload missing block hash")
	}
	copy(blockHash[:], payload[:32])
	return blockHash, nil
}

func (p *peer) processCompactTransactions(blockHash [32]byte, header [consensus.BLOCK_HEADER_BYTES]byte, txs [][]byte) error {
	blockBytes, err := compactBlockBytes(header, txs)
	if err != nil {
		return p.requestCompactFullBlockFallback(blockHash)
	}
	accepted, fallback, err := p.processCompactRelayedBlock(blockHash, blockBytes)
	if fallback {
		return p.requestCompactFullBlockFallback(blockHash)
	}
	if err != nil || !accepted {
		return err
	}
	return p.service.requestBlocksIfBehind(p)
}

func (p *peer) processCompactRelayedBlock(expectedHash [32]byte, blockBytes []byte) (bool, bool, error) {
	pb, blockHash, err := parseRelayedBlock(blockBytes)
	if err != nil || pb == nil || blockHash != expectedHash {
		return false, true, err
	}
	have, err := p.service.hasBlock(blockHash)
	if err != nil || have {
		return false, false, err
	}
	p.service.chainMu.Lock()
	summary, err := p.service.cfg.SyncEngine.ApplyBlockWithReorg(blockBytes, nil)
	p.service.chainMu.Unlock()
	if err != nil {
		if compactApplyErrorNeedsFullBlock(err) {
			return false, true, err
		}
		p.recordRelayedBlockApplyError(err)
		return false, false, err
	}
	p.acceptedRelayedBlock(blockHash, summary)
	return true, false, nil
}

func compactApplyErrorNeedsFullBlock(err error) bool {
	return errors.Is(err, node.ErrParentNotFound) || isConsensusApplyBlockError(err)
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

func compactRelayLocalTransactions(pool TxPool) [][]byte {
	switch pool := pool.(type) {
	case *MemoryTxPool:
		return compactRelayMemoryPoolTransactions(pool)
	case *CanonicalMempoolTxPool:
		return compactRelayCanonicalPoolTransactions(pool)
	default:
		return nil
	}
}

func compactRelayMemoryPoolTransactions(pool *MemoryTxPool) [][]byte {
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
}

func compactRelayCanonicalPoolTransactions(pool *CanonicalMempoolTxPool) [][]byte {
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
}

func newCompactOutstandingRequest(block cmpctBlockPayload, blockHash [32]byte, result compactReconstructionResult) (compactOutstandingRequest, error) {
	if len(result.MissingIndexes) == 0 || len(result.MissingIndexes) != len(result.MissingShortIDs) {
		return compactOutstandingRequest{}, errors.New("compact reconstruction missing request mismatch")
	}
	if err := compactValidateOutstandingShape(result.PartialTransactions, result.MissingIndexes); err != nil {
		return compactOutstandingRequest{}, err
	}
	payloadCap, err := compactBlockTxnResponsePayloadCap(result.PartialTransactions, len(result.MissingIndexes))
	if err != nil {
		return compactOutstandingRequest{}, err
	}
	// Take ownership of reconstruction slices; peer state clones at the mutex boundary.
	return compactOutstandingRequest{
		BlockHash:          blockHash,
		Header:             block.Header,
		MissingIndexes:     result.MissingIndexes,
		MissingShortIDs:    result.MissingShortIDs,
		Transactions:       result.PartialTransactions,
		Nonce1:             block.Nonce1,
		Nonce2:             block.Nonce2,
		BlockTxnPayloadCap: payloadCap,
	}, nil
}

func compactValidateOutstandingShape(partial [][]byte, missing []uint64) error {
	for _, idx := range missing {
		if idx >= uint64(len(partial)) {
			return errors.New("compact relay index out of range")
		}
		if partial[int(idx)] != nil { // #nosec G115 -- idx is bounded by len(partial) above.
			return errors.New("compact reconstruction missing request mismatch")
		}
	}
	return nil
}

func compactBlockTxnResponsePayloadCap(partial [][]byte, missingCount int) (uint32, error) {
	if missingCount <= 0 || missingCount > maxCompactRelayEntries {
		return 0, errors.New("compact reconstruction missing request mismatch")
	}
	presentBytes, err := compactPresentTransactionBytes(partial)
	if err != nil {
		return 0, err
	}
	remainingBytes := uint64(consensus.MAX_BLOCK_BYTES) - presentBytes
	capBytes := uint64(32+len(consensus.EncodeCompactSize(uint64(missingCount)))) + remainingBytes + uint64(missingCount)*maxCompactSizeBytes
	if capBytes > uint64(compactRelayPayloadCap(messageBlockTxn)) {
		return 0, errors.New("blocktxn payload cap overflow")
	}
	return uint32(capBytes), nil
}

func compactFillResponseTransactions(req compactOutstandingRequest, response blockTxnRuntimePayload) ([][]byte, error) {
	if response.BlockHash != req.BlockHash {
		return nil, errors.New("blocktxn block hash mismatch")
	}
	responseTxs, responseWTxIDs := response.Transactions, response.WTxIDs
	if len(req.MissingIndexes) != len(req.MissingShortIDs) || len(responseTxs) != len(req.MissingIndexes) || len(responseWTxIDs) != len(responseTxs) {
		return nil, errors.New("blocktxn transaction count mismatch")
	}
	txs := append([][]byte(nil), req.Transactions...)
	for i, tx := range responseTxs {
		idx := req.MissingIndexes[i]
		if idx >= uint64(len(txs)) {
			return nil, errors.New("compact relay index out of range")
		}
		txs[int(idx)] = tx // #nosec G115 -- idx is bounded by len(txs) above.
	}
	if err := compactValidatePresentTransactions(txs, true); err != nil {
		return nil, err
	}
	for i, tx := range responseTxs {
		wtxid, err := compactBlockTxnResponseWTxID(tx)
		if err != nil {
			return nil, err
		}
		if wtxid != responseWTxIDs[i] {
			return nil, errors.New("blocktxn transaction wtxid mismatch")
		}
		shortID := compactShortID(consensus.CompactShortID(wtxid, req.Nonce1, req.Nonce2))
		if shortID != req.MissingShortIDs[i] {
			return nil, errors.New("blocktxn transaction short id mismatch")
		}
	}
	cloneCompactTransactionsInPlace(txs)
	return txs, nil
}

func compactBlockTxnResponseWTxID(tx []byte) ([32]byte, error) {
	var zero [32]byte
	if _, err := validateBlockTxnTransactionSize(uint64(len(tx)), 0); err != nil {
		return zero, err
	}
	_, _, wtxid, consumed, err := consensus.ParseTx(tx)
	if err != nil || consumed != len(tx) {
		return zero, errors.New("blocktxn transaction is non-canonical")
	}
	return wtxid, nil
}

func compactValidatePresentTransactions(txs [][]byte, requireComplete bool) error {
	return compactValidatePresentTransactionsFrom(txs, requireComplete, 0)
}

func compactValidatePresentTransactionsFrom(txs [][]byte, requireComplete bool, totalTxBytes uint64) error {
	_, err := compactPresentTransactionBytesFrom(txs, requireComplete, totalTxBytes)
	return err
}

func compactPresentTransactionBytes(txs [][]byte) (uint64, error) {
	return compactPresentTransactionBytesFrom(txs, false, 0)
}

func compactPresentTransactionBytesFrom(txs [][]byte, requireComplete bool, totalTxBytes uint64) (uint64, error) {
	for _, tx := range txs {
		if tx == nil {
			if requireComplete {
				return 0, errors.New("compact block transaction missing")
			}
			continue
		}
		nextTotal, err := validateBlockTxnTransactionSize(uint64(len(tx)), totalTxBytes)
		if err != nil {
			return 0, err
		}
		totalTxBytes = nextTotal
	}
	return totalTxBytes, nil
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

func cloneCompactTransactionsInPlace(txs [][]byte) {
	for i, tx := range txs {
		if tx != nil {
			txs[i] = append([]byte(nil), tx...)
		}
	}
}
