package p2p

import (
	"bytes"
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

const (
	compactDuplicateReportedIndex = ^uint64(0)
	// Local candidate snapshots are best-effort: missing candidates fall back
	// to compact relay recovery, so keep the per-reconstruction copy budget
	// well below the full block cap.
	compactLocalTxCandidateLimit      = defaultMaxTxPoolSize
	compactLocalTxCandidateBytesLimit = 1 << 20
	// compactReconstructionCharge is the inbound budget charge a cmpctblock frame lease carries
	// from its replacement on: twelve times the 72000000-byte block cap.
	compactReconstructionCharge = 864000000
)

var (
	errCompactRelayMissingRequestTooLarge = errors.New("too many compact relay missing transactions")
	errBlockTxnTransactionShortIDMismatch = errors.New("blocktxn transaction short id mismatch")
	errGetBlockTxnIndexOutOfRange         = errors.New("getblocktxn index out of range")
)

type compactReconstructionResult struct {
	Transactions        [][]byte
	PartialTransactions [][]byte
	MissingIndexes      []uint64
	MissingShortIDs     []compactShortID
}

var (
	errCompactCandidateInput    = errors.New("invalid compact candidate input")
	errCompactCandidateFault    = errors.New("compact candidate local fault")
	errCompactCandidateResource = errors.New("compact candidate resource bound")
)

type compactCandidateOutcome struct {
	Result                 compactReconstructionResult
	D4Complete             bool
	DistinctCollisionCount uint64
}

type compactCandidateObservation struct {
	Identity node.CompactCandidateIdentity
	ShortID  compactShortID
	Sources  uint8
}

type compactCandidateCatalog struct {
	Observed []compactCandidateObservation
	Index    map[compactShortID]int
}

// reconstructCompactCandidates is dormant: qualified ingress and publication
// belong to a future consumer. It observes owners but changes no live relay state.
func reconstructCompactCandidates(block cmpctBlockPayload, profile uint64, byteBudget uint64, standard TxPool, da *node.DARelayState) (compactCandidateOutcome, error) {
	total, txs, prefilledIDs, err := compactCandidateInput(block, profile, byteBudget)
	if err != nil {
		return compactCandidateOutcome{}, err
	}
	if len(block.ShortIDs) == 0 {
		return compactCandidateOutcome{Result: compactReconstructionResult{Transactions: txs}}, nil
	}
	mp, catalog, err := compactCandidateOwners(standard, da, block.Nonce1, block.Nonce2)
	if err != nil {
		return compactCandidateOutcome{}, err
	}
	eligible, collisions := compactCandidateEligibility(block, prefilledIDs, catalog)
	outcome := compactCandidateOutcome{D4Complete: true, DistinctCollisionCount: collisions}
	current, err := compactCandidateBaseline(total, block.Prefilled, byteBudget)
	if err != nil {
		return outcome, err
	}
	missingLimit := len(block.ShortIDs)
	if profile == 1 {
		missingLimit = 4096
	}
	result, err := compactCandidateFill(block.ShortIDs, txs, eligible, catalog, mp, da, current, byteBudget, missingLimit)
	if err != nil {
		return outcome, err
	}
	if len(result.MissingIndexes) > missingLimit {
		return outcome, errCompactRelayMissingRequestTooLarge
	}
	outcome.Result = result
	return outcome, nil
}

func compactCandidateInput(block cmpctBlockPayload, profile, byteBudget uint64) (uint64, [][]byte, [][32]byte, error) {
	if profile != 1 && profile != 2 {
		return 0, nil, nil, errCompactCandidateInput
	}
	if byteBudget < 72_000_000 {
		return 0, nil, nil, errCompactCandidateInput
	}
	total, err := compactCandidateEntryCount(profile, uint64(len(block.ShortIDs)), uint64(len(block.Prefilled)))
	if err != nil {
		return 0, nil, nil, err
	}
	txs, ids, err := compactCandidatePrefills(block.Prefilled, profile, total)
	return total, txs, ids, err
}

func compactCandidateEntryCount(profile, shortIDCount, prefilledCount uint64) (uint64, error) {
	var limit uint64
	switch profile {
	case 1:
		limit = 72_000_000
	case 2:
		limit = 280_991
	default:
		return 0, errCompactCandidateInput
	}
	if shortIDCount > ^uint64(0)-prefilledCount {
		return 0, errCompactCandidateInput
	}
	total := shortIDCount + prefilledCount
	if total == 0 || total > limit {
		return 0, errCompactCandidateInput
	}
	return total, nil
}

func compactCandidatePrefills(prefilled []prefilledTxn, profile, total uint64) ([][]byte, [][32]byte, error) {
	seen := make(map[uint64]bool, len(prefilled))
	ids := make([][32]byte, len(prefilled))
	var previous uint64
	for i, entry := range prefilled {
		if entry.Index >= total || seen[entry.Index] {
			return nil, nil, errCompactCandidateInput
		}
		if profile == 2 && i != 0 && entry.Index <= previous {
			return nil, nil, errCompactCandidateInput
		}
		wtxid, err := compactCandidatePrefillIdentity(entry.Tx)
		if err != nil {
			return nil, nil, err
		}
		seen[entry.Index], ids[i], previous = true, wtxid, entry.Index
	}
	txs := make([][]byte, total)
	compactFillPrefilledTransactions(txs, prefilled)
	return txs, ids, nil
}

func compactCandidatePrefillIdentity(raw []byte) ([32]byte, error) {
	_, _, wtxid, consumed, err := consensus.ParseTx(raw)
	if err != nil || consumed != len(raw) {
		return [32]byte{}, errCompactCandidateInput
	}
	return wtxid, nil
}

func compactCandidateOwners(standard TxPool, da *node.DARelayState, nonce1, nonce2 uint64) (*node.Mempool, compactCandidateCatalog, error) {
	pool, ok := standard.(*CanonicalMempoolTxPool)
	if !ok || pool == nil || pool.mempool == nil {
		return nil, compactCandidateCatalog{}, errCompactCandidateFault
	}
	daIDs, ok := da.CompactDAIdentities(pool.mempool)
	if !ok {
		return nil, compactCandidateCatalog{}, errCompactCandidateFault
	}
	standardIDs, ok := pool.mempool.CompactStandardIdentities()
	if !ok {
		return nil, compactCandidateCatalog{}, errCompactCandidateFault
	}
	observed := make([]compactCandidateObservation, 0, len(daIDs)+len(standardIDs))
	for _, source := range []struct {
		mask       uint8
		identities []node.CompactCandidateIdentity
	}{{1, daIDs}, {2, standardIDs}} {
		for _, identity := range source.identities {
			observed = append(observed, compactCandidateObservation{Identity: identity, ShortID: compactShortID(consensus.CompactShortID(identity.WTxID, nonce1, nonce2)), Sources: source.mask})
		}
	}
	catalog, err := compactCandidateScan(observed)
	return pool.mempool, catalog, err
}

// compactCandidateScan consumes already computed identity/SID observations.
// Its full scan retains every observer and rejects conflicting TXID metadata.
func compactCandidateScan(observed []compactCandidateObservation) (compactCandidateCatalog, error) {
	catalog := compactCandidateCatalog{Observed: make([]compactCandidateObservation, 0, len(observed)), Index: make(map[compactShortID]int, len(observed))}
	pairs := make(map[[32]byte]int, len(observed))
	for _, observation := range observed {
		if at, found := pairs[observation.Identity.WTxID]; found {
			prior := &catalog.Observed[at]
			if prior.Identity != observation.Identity || prior.ShortID != observation.ShortID {
				return compactCandidateCatalog{}, errCompactCandidateFault
			}
			prior.Sources |= observation.Sources
			continue
		}
		at := len(catalog.Observed)
		pairs[observation.Identity.WTxID] = at
		catalog.Observed = append(catalog.Observed, observation)
		if _, found := catalog.Index[observation.ShortID]; found {
			catalog.Index[observation.ShortID] = -1
			continue
		}
		catalog.Index[observation.ShortID] = at
	}
	return catalog, nil
}

func compactCandidateEligibility(block cmpctBlockPayload, prefilledIDs [][32]byte, catalog compactCandidateCatalog) (map[compactShortID]int, uint64) {
	counts := make(map[compactShortID]uint64, len(block.ShortIDs))
	for _, sid := range block.ShortIDs {
		counts[sid]++
	}
	blocked := make(map[compactShortID]bool, len(prefilledIDs))
	for _, wtxid := range prefilledIDs {
		blocked[compactShortID(consensus.CompactShortID(wtxid, block.Nonce1, block.Nonce2))] = true
	}
	eligible := make(map[compactShortID]int, len(counts))
	var collisions uint64
	for sid, count := range counts {
		at, found := catalog.Index[sid]
		if compactCandidateCollision(count, blocked[sid], at, found) {
			collisions++
			eligible[sid] = -1
			continue
		}
		if !found {
			at = -1
		}
		eligible[sid] = at
	}
	return eligible, collisions
}

func compactCandidateCollision(count uint64, prefilled bool, at int, found bool) bool {
	return count > 1 || prefilled || (found && at < 0)
}

func compactCandidateAdd(current, extra, budget uint64) (uint64, error) {
	if extra > ^uint64(0)-current {
		return 0, errCompactCandidateResource
	}
	next := current + extra
	if next > budget {
		return 0, errCompactCandidateResource
	}
	return next, nil
}

func compactCandidateBaseline(total uint64, prefilled []prefilledTxn, budget uint64) (uint64, error) {
	current, err := compactCandidateAdd(116, uint64(len(consensus.EncodeCompactSize(total))), budget)
	if err != nil {
		return 0, err
	}
	for _, entry := range prefilled {
		current, err = compactCandidateAdd(current, uint64(len(entry.Tx)), budget)
		if err != nil {
			return 0, err
		}
	}
	return current, nil
}

func compactCandidateCompose(selected []byte, read node.CompactCandidateRead, maxBytes uint64) ([]byte, error) {
	switch read.Disposition {
	case node.CompactCandidateAbsent:
		if read.Raw != nil {
			return nil, errCompactCandidateFault
		}
		return selected, nil
	case node.CompactCandidatePresent:
		return compactCandidatePresent(selected, read.Raw, maxBytes)
	case node.CompactCandidateOverBudget:
		return nil, errCompactCandidateResource
	default:
		return nil, errCompactCandidateFault
	}
}

func compactCandidatePresent(selected, raw []byte, maxBytes uint64) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errCompactCandidateFault
	}
	if uint64(len(raw)) > maxBytes {
		return nil, errCompactCandidateResource
	}
	if selected != nil && !bytes.Equal(selected, raw) {
		return nil, errCompactCandidateFault
	}
	if selected != nil {
		return selected, nil
	}
	return raw, nil
}

func compactCandidateHydrate(observed compactCandidateObservation, mp *node.Mempool, da *node.DARelayState, remaining uint64) ([]byte, error) {
	var selected []byte
	for source := uint8(1); source <= 2; source <<= 1 {
		if observed.Sources&source == 0 {
			continue
		}
		var read node.CompactCandidateRead
		switch source {
		case 1:
			read = da.ReadCompactDA(observed.Identity, remaining)
		case 2:
			read = mp.ReadCompactStandard(observed.Identity, remaining)
		}
		var err error
		selected, err = compactCandidateCompose(selected, read, remaining)
		if err != nil {
			return nil, err
		}
	}
	return selected, nil
}

func compactCandidateFill(shortIDs []compactShortID, txs [][]byte, eligible map[compactShortID]int, catalog compactCandidateCatalog, mp *node.Mempool, da *node.DARelayState, current, budget uint64, missingLimit int) (compactReconstructionResult, error) {
	result := compactReconstructionResult{}
	shortPosition := 0
	for absolute, prefilled := range txs {
		if prefilled != nil {
			continue
		}
		sid := shortIDs[shortPosition]
		shortPosition++
		if at := eligible[sid]; at >= 0 {
			raw, err := compactCandidateHydrate(catalog.Observed[at], mp, da, budget-current)
			if err != nil {
				return compactReconstructionResult{}, err
			}
			current, err = compactCandidateAdd(current, uint64(len(raw)), budget)
			if err != nil {
				return compactReconstructionResult{}, err
			}
			txs[absolute] = raw
		}
		if txs[absolute] == nil {
			// Retain one overflow marker; later source/resource errors precede count refusal.
			retained := min(len(result.MissingIndexes), missingLimit)
			result.MissingIndexes = append(result.MissingIndexes[:retained], uint64(absolute))
			result.MissingShortIDs = append(result.MissingShortIDs[:retained], sid)
		}
	}
	if len(result.MissingIndexes) == 0 {
		result.Transactions = txs
		return result, nil
	}
	result.PartialTransactions = txs
	return result, nil
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
			continue
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
	if err := p.validateCmpctBlockReceiveHeader(payload); err != nil {
		return err
	}
	block, err := decodeCmpctBlockPayload(payload)
	if err != nil {
		p.bumpBan(10, err.Error())
		return err
	}
	blockHash, _ := consensus.BlockHash(block.Header[:]) // fixed-size header slice cannot hit the length error path
	if reconstruct, err := p.beginCompactReconstruction(blockHash); !reconstruct {
		return err
	}
	localTxs := compactRelayLocalTransactionsForBlock(block, p.service.cfg.TxPool)
	result, err := reconstructCompactBlock(block, localTxs)
	if errors.Is(err, errCompactRelayMissingRequestTooLarge) {
		return p.requestCompactFullBlockFallback(blockHash)
	}
	if err != nil {
		if len(block.ShortIDs) > 0 {
			return p.requestCompactFullBlockFallback(blockHash)
		}
		return err
	}
	if result.Transactions != nil {
		return p.processCompactTransactions(blockHash, block.Header, result.Transactions, len(block.ShortIDs) > 0)
	}
	return p.requestMissingCompactTransactions(block, blockHash, result)
}

// beginCompactReconstruction returns true, with a nil error, only when blockHash is not stored
// and the frame lease on p.inboundLease was replaced in place by compactReconstructionCharge.
// Otherwise it returns false: a stored block or a presence error clears the outstanding request
// for blockHash and returns the presence error, nil for a stored block; a capacity refusal of the
// replacement returns the result of requestCompactFullBlockFallback; any other refusal is
// returned unchanged.
func (p *peer) beginCompactReconstruction(blockHash [32]byte) (bool, error) {
	have, err := p.service.hasBlock(blockHash)
	if err != nil || have {
		p.clearCompactOutstandingRequestForBlock(blockHash)
		return false, err
	}
	err = p.service.inboundBudget.ReplaceOrSubscribe(p.inboundLease, compactReconstructionCharge)
	var refusal inboundBlockBudgetError
	if errors.As(err, &refusal) && refusal.Resource() == inboundBudgetCapacityResource {
		return false, p.requestCompactFullBlockFallback(blockHash)
	}
	return err == nil, err
}

func (p *peer) validateCmpctBlockReceiveHeader(payload []byte) error {
	header, ok := cmpctBlockHeaderValidationCandidate(payload)
	if !ok {
		return nil
	}
	return p.validateCompactBlockHeader(header)
}

func (p *peer) validateCompactBlockHeader(header [consensus.BLOCK_HEADER_BYTES]byte) error {
	parsed, _ := consensus.ParseBlockHeaderBytes(header[:]) // fixed-size header slice cannot hit the length error path
	if err := consensus.PowCheck(header[:], parsed.Target); err != nil {
		p.bumpBan(100, err.Error())
		return err
	}
	// The stock Phase-0 devnet predicate gates ONLY this optional static
	// equality. When it holds, a header whose target follows the derived
	// schedule must not be rejected here against one configured constant; the
	// reconstructed block goes on to SyncEngine.ApplyBlockWithReorg, which
	// derives the target from the selected parent and candidate height. Parse,
	// PoW range, PoW work and the peer disposition are untouched — nothing new
	// is accepted, the authority simply moves to the apply path. When the
	// predicate is false this comparison and its peer outcome are byte-identical
	// to pre-RUB-655.
	//
	// Ask the ENGINE, never this service's own SyncConfig copy.
	// validateServiceConfig does not require the two to agree, so reading the
	// copy would let this layer reject a header the engine it defers to would
	// have accepted. Nil-safe on the method.
	stockDevnet := p.service.cfg.SyncEngine.StockDevnetTargetSchedule()
	if expected := p.service.cfg.SyncConfig.ExpectedTarget; expected != nil && !stockDevnet && parsed.Target != *expected {
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
	return p.sendCompactOutstandingRequest(req)
}

func (p *peer) handleBlockTxn(payload []byte) error {
	req, ok, err := p.blockTxnOutstandingRequest(payload)
	if !ok {
		return err
	}
	if uint64(len(payload)) > uint64(req.BlockTxnPayloadCap) {
		p.clearCompactOutstandingRequestForBlock(req.BlockHash)
		p.bumpBan(10, "blocktxn payload exceeds outstanding cap")
		return errors.New("blocktxn payload exceeds outstanding cap")
	}
	response, err := decodeBlockTxnRuntimePayload(payload)
	if err != nil {
		p.clearCompactOutstandingRequestForBlock(req.BlockHash)
		p.bumpBan(10, err.Error())
		return err
	}
	p.inboundLease = p.takeCompactOutstandingLeaseForBlock(req.BlockHash)
	p.clearCompactOutstandingRequestForBlock(req.BlockHash)
	txs, err := compactFillResponseTransactions(req, response)
	if err != nil {
		if compactBlockTxnFillErrorAllowsFallback(err) {
			return p.requestCompactFullBlockFallback(req.BlockHash)
		}
		p.bumpBan(10, err.Error())
		return err
	}
	return p.processCompactTransactions(req.BlockHash, req.Header, txs, true)
}

// blockTxnOutstandingRequest returns, with true, the snapshot of the outstanding request whose
// block hash a blocktxn payload carries. For a payload that answers none it returns false and
// the error to report: the rejectBlockTxn error for a payload shorter than a block hash,
// blockTxnStaleBodyError for another hash with a body, and nil after a LastError diagnostic
// otherwise.
func (p *peer) blockTxnOutstandingRequest(payload []byte) (compactOutstandingRequest, bool, error) {
	if len(payload) < 32 {
		return compactOutstandingRequest{}, false, p.rejectBlockTxn("blocktxn payload missing block hash")
	}
	var responseHash [32]byte
	copy(responseHash[:], payload[:32])
	blockHash, ok := p.compactOutstandingBlockHash()
	if !ok {
		p.setLastError("ignored unexpected blocktxn response")
		return compactOutstandingRequest{}, false, nil
	}
	if responseHash != blockHash {
		if len(payload) > blockTxnHashPayloadBytes {
			return compactOutstandingRequest{}, false, blockTxnStaleBodyError{}
		}
		p.setLastError("ignored stale blocktxn response")
		return compactOutstandingRequest{}, false, nil
	}
	req, ok := p.compactOutstandingRequestSnapshot()
	if !ok {
		p.setLastError("ignored unexpected blocktxn response")
	}
	return req, ok, nil
}

func (p *peer) handleGetBlockTxn(payload []byte) error {
	req, err := decodeGetBlockTxnPayload(payload)
	if err != nil {
		return p.rejectGetBlockTxn(err.Error())
	}
	if err := compactValidateUniqueGetBlockTxnIndexes(req.Indexes); err != nil {
		return p.rejectGetBlockTxn(err.Error())
	}
	p.compactSendBarrier()
	if !p.consumeCompactBlockAnnouncement(req.BlockHash) {
		p.setLastError("ignored unannounced getblocktxn request")
		return nil
	}
	block, ok, err := p.blockBytes(req.BlockHash)
	if err != nil || !ok {
		return err
	}
	txs, err := compactBlockTransactionsByIndex(block, req.Indexes)
	if err != nil {
		if errors.Is(err, errGetBlockTxnIndexOutOfRange) {
			return p.rejectGetBlockTxn(err.Error())
		}
		return err
	}
	response, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: req.BlockHash, Transactions: txs})
	if err != nil {
		return err
	}
	return p.send(messageBlockTxn, response)
}

func compactValidateUniqueGetBlockTxnIndexes(indexes []uint64) error {
	if len(indexes) < 2 {
		return nil
	}
	seen := make(map[uint64]struct{}, len(indexes))
	for _, idx := range indexes {
		if _, ok := seen[idx]; ok {
			return errors.New("duplicate getblocktxn index")
		}
		seen[idx] = struct{}{}
	}
	return nil
}

func compactBlockTransactionsByIndex(block []byte, indexes []uint64) ([][]byte, error) {
	txCount, offset, err := compactBlockTransactionCount(block)
	if err != nil {
		return nil, err
	}
	for _, idx := range indexes {
		if idx >= txCount {
			return nil, errGetBlockTxnIndexOutOfRange
		}
	}
	if len(indexes) == 0 {
		return [][]byte{}, nil
	}

	positions := make(map[uint64]int, len(indexes))
	var maxIndex uint64
	for pos, idx := range indexes {
		positions[idx] = pos
		if idx > maxIndex {
			maxIndex = idx
		}
	}
	txs := make([][]byte, len(indexes))
	for txIndex := uint64(0); txIndex <= maxIndex; txIndex++ {
		_, _, _, consumed, err := consensus.ParseTx(block[offset:])
		if err != nil || consumed <= 0 || offset+consumed > len(block) {
			return nil, errors.New("stored block transaction is non-canonical")
		}
		if pos, ok := positions[txIndex]; ok {
			txs[pos] = append([]byte(nil), block[offset:offset+consumed]...)
		}
		offset += consumed
	}
	if maxIndex == txCount-1 && offset != len(block) {
		return nil, errors.New("stored block has trailing bytes after transactions")
	}
	return txs, nil
}

func compactBlockTransactionCount(block []byte) (uint64, int, error) {
	if len(block) < consensus.BLOCK_HEADER_BYTES {
		return 0, 0, errors.New("stored block missing header")
	}
	txCount, countLen, err := consensus.DecodeCompactSize(block[consensus.BLOCK_HEADER_BYTES:])
	if err != nil {
		return 0, 0, err
	}
	return txCount, consensus.BLOCK_HEADER_BYTES + countLen, nil
}

func (p *peer) rejectBlockTxn(msg string) error {
	p.bumpBan(10, msg)
	return errors.New(msg)
}

func (p *peer) rejectGetBlockTxn(msg string) error {
	p.bumpBan(10, msg)
	return errors.New(msg)
}

func (p *peer) processCompactTransactions(blockHash [32]byte, header [consensus.BLOCK_HEADER_BYTES]byte, txs [][]byte, fallbackOnApply bool) error {
	blockBytes, err := compactBlockBytes(header, txs)
	if err != nil {
		if fallbackOnApply {
			return p.requestCompactFullBlockFallback(blockHash)
		}
		p.bumpBan(10, err.Error())
		return err
	}
	fallback, accepted, err := p.processCompactRelayedBlockWithFallback(blockHash, blockBytes, fallbackOnApply)
	if fallback {
		return p.requestCompactFullBlockFallback(blockHash)
	}
	if err != nil {
		return err
	}
	if accepted {
		return p.service.requestBlocksIfBehind(p)
	}
	return nil
}

func (p *peer) processCompactRelayedBlockWithFallback(expectedHash [32]byte, blockBytes []byte, fallbackOnApply bool) (bool, bool, error) {
	pb, blockHash, err := parseRelayedBlock(blockBytes)
	if err != nil {
		return fallbackOnApply, false, err
	}
	if pb == nil {
		return false, false, errors.New("nil parsed compact block")
	}
	if blockHash != expectedHash {
		if fallbackOnApply {
			return true, false, nil
		}
		return false, false, errors.New("compact block hash mismatch")
	}
	have, err := p.service.hasBlock(blockHash)
	if err != nil {
		p.clearCompactOutstandingRequestForBlock(blockHash)
		return false, false, err
	}
	if have {
		p.clearCompactOutstandingRequestForBlock(blockHash)
		return false, false, nil
	}
	return p.applyCompactRelayedBlock(pb, blockHash, blockBytes, fallbackOnApply)
}

func (p *peer) applyCompactRelayedBlock(pb *consensus.ParsedBlock, blockHash [32]byte, blockBytes []byte, fallbackOnApply bool) (bool, bool, error) {
	summary, err := p.service.applyBlockWithReorg(blockBytes)
	if summary != nil && err != nil {
		_, resultErr := p.acceptRelayedBlockResult(blockHash, summary, err)
		return false, true, resultErr
	}
	if err != nil {
		return p.compactApplyErrorFallback(pb, blockHash, blockBytes, err, fallbackOnApply)
	}
	if summary == nil {
		return false, false, errors.New("compact block apply returned nil summary")
	}
	have, err := p.service.hasBlock(blockHash)
	if err != nil {
		return false, false, err
	}
	if !have {
		return false, false, errors.New("compact block apply succeeded without accepting block")
	}
	_, _ = p.acceptRelayedBlockResult(blockHash, summary, nil)
	return false, true, nil
}

func (p *peer) compactApplyErrorFallback(pb *consensus.ParsedBlock, blockHash [32]byte, blockBytes []byte, err error, fallbackOnApply bool) (bool, bool, error) {
	p.clearCompactOutstandingRequestForBlock(blockHash)
	if errors.Is(err, node.ErrParentNotFound) {
		if fallbackOnApply {
			p.setLastError(err.Error())
			return true, false, nil
		}
		if _, retainErr := p.retainRelayedOrphanIfValid(pb, blockHash, blockBytes); retainErr != nil {
			return false, false, retainErr
		}
		return false, false, nil
	}
	if fallbackOnApply && isConsensusApplyBlockError(err) {
		p.setLastError(err.Error())
		return true, false, nil
	}
	p.recordRelayedBlockApplyError(err)
	return false, false, err
}

func (p *peer) requestCompactFullBlockFallback(blockHash [32]byte) error {
	p.clearCompactOutstandingRequestForBlock(blockHash)
	p.releaseInboundLease()
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
		if len(out) > consensus.MAX_BLOCK_BYTES-len(tx) {
			return nil, errors.New("compact block exceeds block size")
		}
		out = append(out, tx...)
		totalTxBytes = nextTotal
	}
	return out, nil
}

func compactRelayLocalTransactions(pool TxPool, limit int) [][]byte {
	return compactRelayLocalTransactionsWithBudget(pool, limit, compactLocalTxCandidateBytesLimit)
}

func compactRelayLocalTransactionsForBlock(block cmpctBlockPayload, pool TxPool) [][]byte {
	if len(block.ShortIDs) == 0 {
		return nil
	}
	return compactRelayLocalTransactions(pool, compactLocalTxCandidateLimit)
}

func compactRelayLocalTransactionsWithBudget(pool TxPool, limit int, byteLimit int) [][]byte {
	switch pool := pool.(type) {
	case *MemoryTxPool:
		return compactMemoryPoolTransactions(pool, limit, byteLimit)
	case *CanonicalMempoolTxPool:
		return compactCanonicalPoolTransactions(pool, limit, byteLimit)
	default:
		return nil
	}
}

func compactMemoryPoolTransactions(pool *MemoryTxPool, limit int, byteLimit int) [][]byte {
	if pool == nil || limit <= 0 || byteLimit <= 0 {
		return nil
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	capHint := len(pool.txs)
	if limit < capHint {
		capHint = limit
	}
	collector := newCompactLocalTxCandidateCollector(capHint, limit, byteLimit)
	for _, entry := range pool.txs {
		if !collector.consider(entry.raw) {
			break
		}
	}
	return collector.out
}

type compactLocalTxCandidateCollector struct {
	out        [][]byte
	limit      int
	byteLimit  int
	scanned    int
	totalBytes int
}

func newCompactLocalTxCandidateCollector(capHint int, limit int, byteLimit int) *compactLocalTxCandidateCollector {
	return &compactLocalTxCandidateCollector{out: make([][]byte, 0, capHint), limit: limit, byteLimit: byteLimit}
}

func (c *compactLocalTxCandidateCollector) consider(raw []byte) bool {
	if c.scanned >= c.limit || len(c.out) >= c.limit || c.totalBytes >= c.byteLimit {
		return false
	}
	c.scanned++
	if c.byteLimit-c.totalBytes >= len(raw) {
		c.out = append(c.out, append([]byte(nil), raw...))
		c.totalBytes += len(raw)
	}
	return c.scanned < c.limit && len(c.out) < c.limit && c.totalBytes < c.byteLimit
}

func compactCanonicalPoolTransactions(pool *CanonicalMempoolTxPool, limit int, byteLimit int) [][]byte {
	if pool == nil || pool.mempool == nil || limit <= 0 || byteLimit <= 0 {
		return nil
	}
	ids := pool.mempool.TxIDsLimit(limit)
	return compactTxIDSnapshotTransactions(ids, pool.mempool.TxByID, limit, byteLimit)
}

func compactTxIDSnapshotTransactions(ids [][32]byte, getTx func([32]byte) ([]byte, bool), limit int, byteLimit int) [][]byte {
	collector := newCompactLocalTxCandidateCollector(len(ids), limit, byteLimit)
	for _, txid := range ids {
		tx, ok := getTx(txid)
		if !ok {
			continue
		}
		if !collector.consider(tx) {
			break
		}
	}
	return collector.out
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
			return nil, errBlockTxnTransactionShortIDMismatch
		}
	}
	cloneCompactTransactionsInPlace(txs)
	return txs, nil
}

func compactBlockTxnFillErrorAllowsFallback(err error) bool {
	return errors.Is(err, errBlockTxnTransactionShortIDMismatch)
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
