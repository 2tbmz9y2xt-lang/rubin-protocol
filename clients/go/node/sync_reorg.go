package node

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type reorgBranchBlock struct {
	hash       [32]byte
	blockBytes []byte
	parsed     *consensus.ParsedBlock
	header     consensus.BlockHeader
}

// verifiedStoredBlock retains one verified block-store read and parse.
type verifiedStoredBlock struct {
	lookupHash [32]byte
	blockBytes []byte
	parsed     *consensus.ParsedBlock
}

func (s *SyncEngine) ApplyBlockWithReorg(blockBytes []byte, prevTimestamps []uint64) (*ChainStateConnectSummary, error) {
	if s == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.mutationAllowed(); err != nil {
		return nil, err
	}
	pb, blockHash, err := parseReorgBlock(blockBytes)
	if err != nil {
		return nil, err
	}

	if summary, handled, err := s.applyDirectBlockIfPossible(pb, blockBytes, prevTimestamps); handled {
		return summary, err
	}
	branch, commonAncestorHeight, switchToBranch, candidateHeight, err := s.evaluateSideBranch(blockHash, blockBytes, pb)
	if err != nil {
		return nil, err
	}
	if !switchToBranch {
		return s.storeSideBlockAndSummary(branch, commonAncestorHeight, candidateHeight)
	}
	return s.applyPreferredBranch(branch, commonAncestorHeight)
}

func parseReorgBlock(blockBytes []byte) (*consensus.ParsedBlock, [32]byte, error) {
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, [32]byte{}, err
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return pb, blockHash, nil
}

func (s *SyncEngine) evaluateSideBranch(
	blockHash [32]byte,
	blockBytes []byte,
	pb *consensus.ParsedBlock,
) ([]reorgBranchBlock, uint64, bool, uint64, error) {
	if s.blockStore == nil {
		return nil, 0, false, 0, &consensus.TxError{Code: consensus.BLOCK_ERR_LINKAGE_INVALID, Msg: "missing blockstore for side-chain block"}
	}
	branch, commonAncestorHash, commonAncestorHeight, err := s.collectBranchToCanonical(blockHash, blockBytes, pb)
	if err != nil {
		return nil, 0, false, 0, err
	}
	switchToBranch, candidateHeight, err := s.shouldSwitchToBranch(branch, commonAncestorHash, commonAncestorHeight)
	if err != nil {
		return nil, 0, false, 0, err
	}
	return branch, commonAncestorHeight, switchToBranch, candidateHeight, nil
}

func (s *SyncEngine) storeSideBlockAndSummary(branch []reorgBranchBlock, commonAncestorHeight uint64, candidateHeight uint64) (*ChainStateConnectSummary, error) {
	if err := s.mutationAllowed(); err != nil {
		return nil, err
	}
	if len(branch) == 0 {
		return nil, errors.New("empty side branch")
	}
	candidate := branch[len(branch)-1]
	// Target context BEFORE the MTP window, so a target-context failure
	// short-circuits without reading MTP state. Selected parent = the
	// candidate's PrevBlockHash, already resolved against stored ancestry by
	// collectBranchToCanonical; height = the caller-owned candidateHeight.
	targetCtx, err := s.targetContextForCandidate(candidate.header.PrevBlockHash, candidateHeight)
	if err != nil {
		return nil, err
	}
	prevTimestamps, err := sideBranchPrevTimestamps(s.blockStore, branch, commonAncestorHeight)
	if err != nil {
		return nil, err
	}
	// Full validation still precedes StoreBlock, so an invalid side-branch
	// target contributes nothing to stored state or to fork choice.
	if _, err := consensus.ValidateBlockBasicWithContextAtHeightAndRotation(candidate.blockBytes, &candidate.header.PrevBlockHash, targetCtx.expected, candidateHeight, prevTimestamps, s.cfg.ChainID, s.cfg.RotationProvider); err != nil {
		return nil, err
	}
	if err := s.blockStore.StoreBlock(candidate.hash, candidate.parsed.HeaderBytes, candidate.blockBytes); err != nil {
		if isAtomicWritePostCommit(err) {
			return nil, s.handlePersistenceError(err, false, false)
		}
		return nil, err
	}
	return s.syntheticSideChainSummary(candidateHeight, candidate.hash), nil
}

func sideBranchPrevTimestamps(store *BlockStore, branch []reorgBranchBlock, commonAncestorHeight uint64) ([]uint64, error) {
	if len(branch) == 0 {
		return nil, errors.New("empty side branch")
	}
	if store == nil {
		return nil, errors.New("missing blockstore for side branch timestamp context")
	}
	prevTimestamps, err := prevTimestampsFromStore(store, commonAncestorHeight+1)
	if err != nil {
		return nil, err
	}
	for _, item := range branch[:len(branch)-1] {
		prevTimestamps = advancePrevTimestamps(prevTimestamps, item.header.Timestamp)
	}
	return prevTimestamps, nil
}

func (s *SyncEngine) applyDirectBlockIfPossible(
	pb *consensus.ParsedBlock,
	blockBytes []byte,
	prevTimestamps []uint64,
) (*ChainStateConnectSummary, bool, error) {
	var zero [32]byte
	view := s.chainState.view()
	switch {
	case !view.hasTip:
		if pb.Header.PrevBlockHash != zero {
			return nil, true, ErrParentNotFound
		}
		summary, err := s.applyCanonicalParsedBlock(pb, blockBytes, prevTimestamps, nil)
		return summary, true, err
	case pb.Header.PrevBlockHash == view.tipHash:
		summary, err := s.applyDirectTipBlock(pb, blockBytes, view)
		return summary, true, err
	default:
		return nil, false, nil
	}
}

// applyDirectTipBlock applies a candidate whose parent is the canonical tip.
// Acquisition order is target-then-MTP: the target context must precede the
// RUB-647 canonical MTP window so a target-context failure short-circuits
// before any MTP state is read. The height-0 genesis branch never reaches here.
func (s *SyncEngine) applyDirectTipBlock(pb *consensus.ParsedBlock, blockBytes []byte, view chainStateView) (*ChainStateConnectSummary, error) {
	nextHeight, _, err := nextBlockContextFromFields(view.hasTip, view.height, view.tipHash)
	if err != nil {
		return nil, err
	}
	if s.blockStore == nil {
		return nil, errors.New("missing blockstore for direct-tip timestamp context")
	}
	targetCtx, err := s.targetContextForCandidate(view.tipHash, nextHeight)
	if err != nil {
		return nil, err
	}
	canonicalPrevTimestamps, err := prevTimestampsFromStore(s.blockStore, nextHeight)
	if err != nil {
		return nil, err
	}
	return s.applyCanonicalParsedBlock(pb, blockBytes, canonicalPrevTimestamps, targetCtx)
}

func (s *SyncEngine) shouldSwitchToBranch(
	branch []reorgBranchBlock,
	commonAncestorHash [32]byte,
	commonAncestorHeight uint64,
) (bool, uint64, error) {
	if len(branch) == 0 {
		return false, commonAncestorHeight, errors.New("empty side branch")
	}
	_, currentTipHash, err := s.currentCanonicalTip()
	if err != nil {
		return false, 0, err
	}

	currentWork, err := s.blockStore.ChainWork(currentTipHash)
	if err != nil {
		return false, 0, err
	}
	ancestorWork, err := s.blockStore.ChainWork(commonAncestorHash)
	if err != nil {
		return false, 0, err
	}
	branchTargets := make([][32]byte, 0, len(branch))
	for _, item := range branch {
		branchTargets = append(branchTargets, item.header.Target)
	}
	branchWork, err := consensus.ChainWorkFromTargets(branchTargets)
	if err != nil {
		return false, 0, err
	}
	candidateWork := new(big.Int).Add(new(big.Int).Set(ancestorWork), branchWork)
	candidateHeight := commonAncestorHeight + uint64(len(branch))
	switch candidateWork.Cmp(currentWork) {
	case 1:
		return true, candidateHeight, nil
	case -1:
		return false, candidateHeight, nil
	default:
		candidateTipHash := branch[len(branch)-1].hash
		return bytes.Compare(candidateTipHash[:], currentTipHash[:]) < 0, candidateHeight, nil
	}
}

// preparedBranchBlock is one fully validated preferred-branch row: its prepared
// post-state, that connect's summary, and the canonical context it was validated
// against. Retaining all three is what keeps the in-guard commit free of any
// repeated parse, ConnectBlock, signature verification or fallible preparation.
type preparedBranchBlock struct {
	item     reorgBranchBlock
	prepared *ChainState
	summary  *ChainStateConnectSummary
	ctx      canonicalBlockApplyContext
}

// applyPreferredBranch applies the candidate branch selected by fork choice —
// greater ChainWork, or equal ChainWork with a lexicographically lower tip hash
// — inside EXACTLY ONE canonical transition: one generation for the whole
// winning branch, one standard pre-clean for the final prepared branch, every
// per-block inner cleanup suppressed, and the existing deterministic requeue
// running only after the final stable owner tip is committed. Every row is fully
// validated BEFORE the transition opens, so nothing under the guard re-runs
// consensus or re-verifies a signature.
func (s *SyncEngine) applyPreferredBranch(
	branch []reorgBranchBlock,
	commonAncestorHeight uint64,
) (*ChainStateConnectSummary, error) {
	canonicalIndex, err := s.canonicalIndexPreflight()
	if err != nil {
		return nil, err
	}
	rows, preparedDisconnectedBlocks, reorgDepth, err := s.preparePreferredBranch(branch, commonAncestorHeight)
	if err != nil {
		return nil, err
	}
	tr, err := s.beginCanonicalTransition(canonicalIndex)
	if err != nil {
		return nil, err
	}
	tr.suppressInnerCleanup = true
	summary, canonicalBlocks, err := s.applyPreferredBranchUnderGuard(tr, rows, commonAncestorHeight, preparedDisconnectedBlocks)
	if endErr := tr.end(err); endErr != nil {
		return nil, endErr
	}
	s.requeueVerifiedDisconnectedTransactions(preparedDisconnectedBlocks)
	s.noteBlockApplyAcceptedN(uint64(len(rows)))
	s.noteReorg(reorgDepth)
	if summary != nil {
		summary.CanonicalAppliedBlocks = canonicalBlocks
	}
	return summary, nil
}

// applyPreferredBranchUnderGuard is commit-only: pre-clean, disconnect to the
// common ancestor, then publish and persist each already-prepared row.
func (s *SyncEngine) applyPreferredBranchUnderGuard(
	tr *canonicalTransition,
	rows []preparedBranchBlock,
	commonAncestorHeight uint64,
	preparedDisconnectedBlocks []verifiedStoredBlock,
) (*ChainStateConnectSummary, []CanonicalAppliedBlock, error) {
	if err := s.precleanPreferredBranch(tr, rows); err != nil {
		return nil, nil, s.rollbackApplyBlock(err, tr.rollback)
	}
	if err := s.disconnectCanonicalToAncestor(commonAncestorHeight, preparedDisconnectedBlocks, tr.rollback); err != nil {
		return nil, nil, s.rollbackApplyBlock(err, tr.rollback)
	}
	var summary *ChainStateConnectSummary
	canonicalBlocks := make([]CanonicalAppliedBlock, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		if err := s.commitPreparedBlockUnderGuard(tr, row.prepared, row.summary, row.ctx, row.item.parsed, row.item.blockBytes); err != nil {
			return nil, nil, err
		}
		tr.appliedHeight, tr.appliedTimestamp, tr.applied = row.summary.BlockHeight, row.item.header.Timestamp, true
		summary = row.summary
		canonicalBlocks = append(canonicalBlocks, row.summary.CanonicalAppliedBlocks...)
	}
	return summary, canonicalBlocks, nil
}

// precleanPreferredBranch removes, in one standard-domain commit, every entry
// the final prepared branch includes or conflicts with, before any live
// ChainState or BlockStore canonical tip change.
func (s *SyncEngine) precleanPreferredBranch(tr *canonicalTransition, rows []preparedBranchBlock) error {
	if tr.mempool == nil {
		return nil
	}
	blocks := make([]*consensus.ParsedBlock, 0, len(rows))
	for i := range rows {
		blocks = append(blocks, rows[i].item.parsed)
	}
	return tr.mempool.applyConnectedBlocksParsed(blocks)
}

// preparePreferredBranch validates the whole winning branch against private
// clones and retains every prepared post-state, summary and canonical context.
// It touches no live state, and nothing it does repeats once the guard is held.
func (s *SyncEngine) preparePreferredBranch(
	branch []reorgBranchBlock,
	commonAncestorHeight uint64,
) ([]preparedBranchBlock, []verifiedStoredBlock, uint64, error) {
	previewState := cloneChainState(s.chainState)
	if previewState == nil {
		return nil, nil, 0, errors.New("nil preview chainstate")
	}
	preparedDisconnectedBlocks, reorgDepth, err := s.previewDisconnectCanonicalToAncestor(previewState, commonAncestorHeight)
	if err != nil {
		return nil, nil, 0, err
	}
	// Build a sliding MTP window: start from pre-fork timestamps, advance
	// after each block.  The blockstore index is NOT updated during preview,
	// so per-block advancement uses a sliding window instead of
	// re-deriving from the store each iteration (B.9 fix).
	slidingTs, err := prevTimestampsFromStore(s.blockStore, commonAncestorHeight+1)
	if err != nil {
		return nil, nil, 0, err
	}
	rows := make([]preparedBranchBlock, 0, len(branch))
	// Row i's prev state is row i-1's prepared post-state, matching exactly
	// what the guard publishes one row at a time.
	prev := previewState
	for i, item := range branch {
		row, rowErr := s.prepareBranchRow(prev, item, commonAncestorHeight+1+uint64(i), slidingTs)
		if rowErr != nil {
			return nil, nil, 0, rowErr
		}
		rows = append(rows, row)
		prev = row.prepared
		slidingTs = advancePrevTimestamps(slidingTs, item.header.Timestamp)
	}
	return rows, preparedDisconnectedBlocks, reorgDepth, nil
}

// prepareBranchRow fully validates one branch row against a private clone of its
// predecessor's prepared post-state and retains everything the commit needs.
//
// Per-row target derivation: a branch can cross a retarget boundary. Unlike the
// MTP window it needs no sliding workaround — it reads headers by hash, never
// the canonical index, and every ancestor it needs is already stored. Target
// context resolves first, so its failure short-circuits before the connect.
func (s *SyncEngine) prepareBranchRow(
	prevState *ChainState,
	item reorgBranchBlock,
	height uint64,
	prevTimestamps []uint64,
) (preparedBranchBlock, error) {
	targetCtx, err := s.targetContextForCandidate(item.header.PrevBlockHash, height)
	if err != nil {
		return preparedBranchBlock{}, err
	}
	ctx := canonicalBlockApplyContext{
		blockHeight:    height,
		blockHash:      item.hash,
		expectedTarget: targetCtx.expected,
		prevState:      prevState,
	}
	prepared := cloneChainState(prevState)
	if prepared == nil {
		return preparedBranchBlock{}, errors.New("nil prepared branch chainstate")
	}
	summary, err := prepared.ConnectBlockWithSuiteContext(
		item.blockBytes,
		ctx.expectedTarget,
		prevTimestamps,
		s.cfg.ChainID,
		s.cfg.RotationProvider,
		s.cfg.SuiteRegistry,
	)
	s.runPVShadowIfActive(item.blockBytes, prevTimestamps, ctx, err, summary)
	if err != nil {
		// No apply-outcome metric: a branch row rejected during preparation was
		// never a canonical apply attempt, matching the pre-transition behavior
		// where the preview rejected before any per-row apply was counted.
		return preparedBranchBlock{}, err
	}
	daIDs, err := CompleteDASetIDsFromParsedBlock(item.parsed)
	if err != nil {
		return preparedBranchBlock{}, err
	}
	summary.CanonicalAppliedBlocks = []CanonicalAppliedBlock{{Hash: item.hash, CompleteDAIDs: daIDs}}
	return preparedBranchBlock{item: item, prepared: prepared, summary: summary, ctx: ctx}, nil
}

// advancePrevTimestamps prepends newTs to prev and keeps at most 11 entries,
// sliding the MTP window forward by one block.
func advancePrevTimestamps(prev []uint64, newTs uint64) []uint64 {
	const maxWindow = 11
	out := make([]uint64, 0, maxWindow)
	out = append(out, newTs)
	for _, ts := range prev {
		if len(out) >= maxWindow {
			break
		}
		out = append(out, ts)
	}
	return out
}

// errBranchStoreCorrupt marks failed stored identity/commitments or a branch cycle.
//
// It is deliberately a plain error and NOT a *consensus.TxError, and it is
// deliberately distinct from ErrParentNotFound. node/p2p classifies an apply
// failure by errors.As(*consensus.TxError) (handlers_block.go
// isConsensusApplyBlockError), so a peer that relayed a perfectly well-formed
// block is never ban-scored for OUR corrupt store; the failure is recorded as a
// local error instead. Unexported: no caller outside this package should branch
// on the specific cause, only on "not a consensus fault".
var errBranchStoreCorrupt = errors.New("local block-store corruption")

// collectBranchToCanonical walks a candidate's ancestry back to the first block
// the canonical index knows, returning the branch in canonical (oldest-first)
// order together with the common ancestor.
//
// Two independent guards bound the walk, and their relationship is NOT
// redundancy — do not remove either one on that theory:
//
//   - Per-ancestor verification (loadVerifiedBranchAncestor) is the live guard.
//     It is what actually stops a corrupt or hostile store file whose
//     prev_block_hash points at itself, or at another file that points back:
//     such a file cannot also hash to the name it was fetched under, so it is
//     rejected on the first read. Without it this loop runs forever, appending
//     the same block bytes on every pass, since nothing else in the walk bounds
//     it.
//   - The walked set below is defense-in-depth that the verification guard makes
//     UNREACHABLE today. Reaching it needs an ancestry that returns to an
//     already-walked hash while every loaded block still hashes to its own
//     lookup key — i.e. a SHA3-256 cycle. It exists so the walk stays bounded if
//     the verification guard is ever weakened, reordered, or removed.
//
// Because it is unreachable, the walked-set branch cannot be pinned by a test
// against the shipped code, and a line-coverage tool WILL report it uncovered.
// That is expected, not a gap: the relationship is demonstrated by mutation —
// removing the verification guard alone leaves the walked set catching both the
// self-referencing and the two-file cycle shapes, and removing both hangs the
// walk (measured, RUB-880).
//
// With either guard in place the walk is bounded by the number of distinct
// blocks actually on disk, so no explicit depth limit is needed: an honest
// branch still terminates at the canonical index or at ErrParentNotFound.
func (s *SyncEngine) collectBranchToCanonical(
	blockHash [32]byte,
	blockBytes []byte,
	pb *consensus.ParsedBlock,
) ([]reorgBranchBlock, [32]byte, uint64, error) {
	branch := []reorgBranchBlock{{
		hash:       blockHash,
		blockBytes: append([]byte(nil), blockBytes...),
		parsed:     pb,
		header:     pb.Header,
	}}
	// Unreachable while loadVerifiedBranchAncestor stands; see the guard
	// relationship on this function. The candidate is seeded so that ancestry
	// looping back to the candidate itself would be caught on the same rule as
	// any other repeat.
	walked := map[[32]byte]struct{}{blockHash: {}}
	parentHash := pb.Header.PrevBlockHash
	for {
		height, found, err := s.blockStore.FindCanonicalHeight(parentHash)
		if err != nil {
			return nil, [32]byte{}, 0, err
		}
		if found {
			reverseBranchBlocks(branch)
			return branch, parentHash, height, nil
		}
		if _, repeated := walked[parentHash]; repeated {
			return nil, [32]byte{}, 0, fmt.Errorf("%w: ancestor %x already walked", errBranchStoreCorrupt, parentHash)
		}
		walked[parentHash] = struct{}{}
		parentParsed, parentBlockBytes, err := s.loadVerifiedBranchAncestor(parentHash)
		if err != nil {
			return nil, [32]byte{}, 0, err
		}
		branch = append(branch, reorgBranchBlock{
			hash:       parentHash,
			blockBytes: parentBlockBytes,
			parsed:     parentParsed,
			header:     parentParsed.Header,
		})
		parentHash = parentParsed.Header.PrevBlockHash
	}
}

// loadVerifiedStoredBlock verifies identity and commitments as local corruption.
func (s *SyncEngine) loadVerifiedStoredBlock(lookupHash [32]byte) (verifiedStoredBlock, error) {
	blockBytes, err := s.blockStore.GetBlockByHash(lookupHash)
	if err != nil {
		return verifiedStoredBlock{}, storedBlockReadCorruption(lookupHash, err)
	}
	parsed, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return verifiedStoredBlock{}, storedBlockCorruption(lookupHash, "does not parse", err)
	}
	observedHash, err := consensus.BlockHash(parsed.HeaderBytes)
	if err != nil {
		return verifiedStoredBlock{}, storedBlockCorruption(lookupHash, "does not hash", err)
	}
	if observedHash != lookupHash {
		return verifiedStoredBlock{}, fmt.Errorf(
			"%w: stored block for %x hashes to %x",
			errBranchStoreCorrupt, lookupHash, observedHash,
		)
	}
	if err := consensus.ValidateStoredBlockCommitments(parsed); err != nil {
		return verifiedStoredBlock{}, storedBlockCorruption(lookupHash, "has invalid commitments", err)
	}
	return verifiedStoredBlock{lookupHash: lookupHash, blockBytes: blockBytes, parsed: parsed}, nil
}

func storedBlockCorruption(lookupHash [32]byte, reason string, err error) error {
	return fmt.Errorf("%w: stored block for %x %s: %v", errBranchStoreCorrupt, lookupHash, reason, err) //nolint:errorlint // %v is required: wrapped consensus.TxError would satisfy p2p's consensus-error predicate for local corruption.
}

func storedBlockReadCorruption(lookupHash [32]byte, err error) error {
	return fmt.Errorf("%w: cannot read stored block for %x: %w", errBranchStoreCorrupt, lookupHash, err)
}

// loadVerifiedBranchAncestor preserves missing-side-ancestor orphan handling.
func (s *SyncEngine) loadVerifiedBranchAncestor(parentHash [32]byte) (*consensus.ParsedBlock, []byte, error) {
	stored, err := s.loadVerifiedStoredBlock(parentHash)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, ErrParentNotFound
		}
		return nil, nil, err
	}
	return stored.parsed, stored.blockBytes, nil
}

func (s *SyncEngine) syntheticSideChainSummary(height uint64, blockHash [32]byte) *ChainStateConnectSummary {
	utxoCount := uint64(0)
	alreadyGenerated := uint64(0)
	if s != nil && s.chainState != nil {
		view := s.chainState.view()
		utxoCount = uint64(view.utxoCount) //nolint:gosec // G115: view.utxoCount is non-negative by chainstate invariant
		alreadyGenerated = view.alreadyGenerated
	}
	return &ChainStateConnectSummary{
		BlockHeight:        height,
		BlockHash:          blockHash,
		AlreadyGenerated:   alreadyGenerated,
		AlreadyGeneratedN1: alreadyGenerated,
		UtxoCount:          utxoCount,
	}
}

func (s *SyncEngine) requeueVerifiedDisconnectedTransactions(disconnectedBlocks []verifiedStoredBlock) {
	parsedBlocks := make([]*consensus.ParsedBlock, 0, len(disconnectedBlocks))
	for _, block := range disconnectedBlocks {
		parsedBlocks = append(parsedBlocks, block.parsed)
	}
	s.requeueParsedDisconnectedTransactions(parsedBlocks)
}

// requeueDisconnectedTransactions is for raw-byte callers; reorgs retain parses.
func (s *SyncEngine) requeueDisconnectedTransactions(disconnectedBlocks [][]byte) {
	parsedBlocks := make([]*consensus.ParsedBlock, 0, len(disconnectedBlocks))
	for _, blockBytes := range disconnectedBlocks {
		parsed, err := consensus.ParseBlockBytes(blockBytes)
		if err != nil {
			continue
		}
		parsedBlocks = append(parsedBlocks, parsed)
	}
	s.requeueParsedDisconnectedTransactions(parsedBlocks)
}

// requeueParsedDisconnectedTransactions MUST NOT be called under the canonical
// transition guard: it routes to Mempool.AddReorgTx, which takes
// ChainState.admissionMu.RLock, and sync.RWMutex is not reentrant. Its only
// caller runs it after the transition released that guard.
func (s *SyncEngine) requeueParsedDisconnectedTransactions(disconnectedBlocks []*consensus.ParsedBlock) {
	if s == nil || s.mempool == nil || len(disconnectedBlocks) == 0 {
		return
	}
	// Disconnect helpers append blocks tip-down, matching h_max -> h_min requeue order.
	for _, parsed := range disconnectedBlocks {
		txs, err := nonCoinbaseParsedBlockTransactions(parsed)
		if err != nil {
			continue
		}
		for _, txBytes := range txs {
			if err := s.mempool.AddReorgTx(txBytes); err != nil {
				_, _ = fmt.Fprintf(s.stderr, "mempool: requeue-tx: %v\n", err)
			}
		}
	}
}

func nonCoinbaseBlockTransactions(blockBytes []byte) ([][]byte, error) {
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	return nonCoinbaseParsedBlockTransactions(pb)
}

func nonCoinbaseParsedBlockTransactions(pb *consensus.ParsedBlock) ([][]byte, error) {
	if pb == nil {
		return nil, errors.New("nil parsed block")
	}
	if len(pb.Txs) <= 1 {
		return nil, nil
	}
	txs := make([][]byte, 0, len(pb.Txs)-1)
	for txIndex := 1; txIndex < len(pb.Txs); txIndex++ {
		txBytes, err := consensus.MarshalTx(pb.Txs[txIndex])
		if err != nil {
			return nil, err
		}
		txs = append(txs, txBytes)
	}
	return txs, nil
}

func reverseBranchBlocks(branch []reorgBranchBlock) {
	for left, right := 0, len(branch)-1; left < right; left, right = left+1, right-1 {
		branch[left], branch[right] = branch[right], branch[left]
	}
}
