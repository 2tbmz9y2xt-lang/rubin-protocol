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

// applyPreferredBranch applies the candidate branch selected by fork choice:
// greater ChainWork, or equal ChainWork with a lexicographically lower tip hash.
func (s *SyncEngine) applyPreferredBranch(
	branch []reorgBranchBlock,
	commonAncestorHeight uint64,
) (*ChainStateConnectSummary, error) {
	rollbackState, err := s.captureRollbackState()
	if err != nil {
		return nil, err
	}
	disconnectedBlocks, reorgDepth, err := s.preparePreferredBranch(branch, commonAncestorHeight, rollbackState)
	if err != nil {
		return nil, err
	}
	if _, _, err := s.disconnectCanonicalToAncestor(commonAncestorHeight); err != nil {
		return nil, s.rollbackApplyBlock(err, rollbackState)
	}

	var summary *ChainStateConnectSummary
	var pendingAccepted uint64
	var canonicalBlocks []CanonicalAppliedBlock
	for i, item := range branch {
		var outcome blockApplyMetricOutcome
		summary, outcome, err = s.applyBranchBlock(item, commonAncestorHeight+1+uint64(i))
		if err != nil {
			return nil, s.rollbackBranchBlockApply(err, rollbackState, outcome)
		}
		if outcome == blockApplyMetricAccepted {
			pendingAccepted++
		}
		if summary != nil && len(summary.CanonicalAppliedBlocks) > 0 {
			canonicalBlocks = append(canonicalBlocks, summary.CanonicalAppliedBlocks[0])
		}
	}
	s.requeueDisconnectedTransactions(disconnectedBlocks)
	s.noteBlockApplyAcceptedN(pendingAccepted)
	s.noteReorg(reorgDepth)
	if summary != nil {
		summary.CanonicalAppliedBlocks = canonicalBlocks
	}
	return summary, nil
}

// applyBranchBlock commits one row of the preferred branch at its caller-owned
// height. Both context windows are re-derived per iteration: the canonical
// index moved when the previous row committed, and a branch can cross a
// retarget boundary (the target half of the B.9 / issue #1166 argument). Target
// context first, so a target-context failure short-circuits before the MTP
// window is read.
func (s *SyncEngine) applyBranchBlock(item reorgBranchBlock, nextHeight uint64) (*ChainStateConnectSummary, blockApplyMetricOutcome, error) {
	targetCtx, err := s.targetContextForCandidate(item.header.PrevBlockHash, nextHeight)
	if err != nil {
		return nil, blockApplyMetricNone, err
	}
	freshTs, err := prevTimestampsFromStore(s.blockStore, nextHeight)
	if err != nil {
		return nil, blockApplyMetricNone, err
	}
	return s.applyCanonicalParsedBlockTracked(item.parsed, item.blockBytes, freshTs, targetCtx)
}

func (s *SyncEngine) rollbackBranchBlockApply(
	err error,
	rollbackState syncRollbackState,
	outcome blockApplyMetricOutcome,
) error {
	rollbackErr := s.rollbackApplyBlock(err, rollbackState)
	if outcome == blockApplyMetricRejected {
		s.noteBlockApplyRejected()
	}
	return rollbackErr
}

func (s *SyncEngine) preparePreferredBranch(
	branch []reorgBranchBlock,
	commonAncestorHeight uint64,
	rollbackState syncRollbackState,
) ([][]byte, uint64, error) {
	previewState := cloneChainState(rollbackState.chainState)
	if previewState == nil {
		return nil, 0, errors.New("nil preview chainstate")
	}
	var err error
	disconnectedBlocks, reorgDepth, err := s.previewDisconnectCanonicalToAncestor(previewState, commonAncestorHeight)
	if err != nil {
		return nil, 0, err
	}
	// Build a sliding MTP window: start from pre-fork timestamps, advance
	// after each block.  The blockstore index is NOT updated during preview,
	// so per-block advancement uses a sliding window instead of
	// re-deriving from the store each iteration (B.9 fix).
	slidingTs, err := prevTimestampsFromStore(s.blockStore, commonAncestorHeight+1)
	if err != nil {
		return nil, 0, err
	}
	for i, item := range branch {
		// Per-row derivation: a branch can cross a retarget boundary. Unlike
		// the MTP window this needs no sliding workaround — it reads headers
		// by hash and never consults the canonical index, and every ancestor
		// it needs is already stored (collectBranchToCanonical fetched
		// branch[0..len-2] from the store; the common ancestor is canonical).
		targetCtx, targetErr := s.targetContextForCandidate(item.header.PrevBlockHash, commonAncestorHeight+1+uint64(i))
		if targetErr != nil {
			return nil, 0, targetErr
		}
		if _, err := previewState.ConnectBlockWithSuiteContext(
			item.blockBytes,
			targetCtx.expected,
			slidingTs,
			s.cfg.ChainID,
			s.cfg.RotationProvider,
			s.cfg.SuiteRegistry,
		); err != nil {
			return nil, 0, err
		}
		slidingTs = advancePrevTimestamps(slidingTs, item.header.Timestamp)
	}
	return disconnectedBlocks, reorgDepth, nil
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

// errBranchStoreCorrupt marks a local block-store defect observed while walking
// a side branch: a stored block whose bytes do not hash to the hash they were
// looked up by, or an ancestry that revisits a hash already walked.
//
// It is deliberately a plain error and NOT a *consensus.TxError, and it is
// deliberately distinct from ErrParentNotFound. node/p2p classifies an apply
// failure by errors.As(*consensus.TxError) (handlers_block.go
// isConsensusApplyBlockError), so a peer that relayed a perfectly well-formed
// block is never ban-scored for OUR corrupt store; the failure is recorded as a
// local error instead. Unexported: no caller outside this package should branch
// on the specific cause, only on "not a consensus fault".
var errBranchStoreCorrupt = errors.New("block store corruption during side-branch collection")

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

// loadVerifiedBranchAncestor reads one stored ancestor and proves it is the
// block that was asked for. A plain file read cannot: BlockStore.GetBlockByHash
// returns whatever bytes sit at the path named by the hash. Mirrors the
// defense-in-depth re-hash verifyReplayBlockHash performs on the startup replay
// path. A genuinely absent ancestor keeps the pre-existing ErrParentNotFound
// outcome, which the caller turns into normal orphan handling.
//
// EVERY way the stored bytes can fail to be the requested block — unparseable,
// unhashable, or hashing to something else — is one local-corruption class and
// is reported as errBranchStoreCorrupt. Bytes that cannot even yield a header
// certainly do not hash to their lookup key, so parse failure is not a separate
// verdict. The cause is rendered with %v and deliberately NOT wrapped with %w:
// consensus.ParseBlockBytes returns a *consensus.TxError, and errors.As unwraps
// through %w, so a %w-chained cause would still satisfy node/p2p's
// isConsensusApplyBlockError and bump a relaying peer's ban score by 100 for OUR
// corrupt datadir. Measured both renderings against that exact predicate: %w =>
// matched, %v => did not, with identical message text.
func (s *SyncEngine) loadVerifiedBranchAncestor(parentHash [32]byte) (*consensus.ParsedBlock, []byte, error) {
	parentBlockBytes, err := s.blockStore.GetBlockByHash(parentHash)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, ErrParentNotFound
		}
		return nil, nil, err
	}
	parentParsed, err := consensus.ParseBlockBytes(parentBlockBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: stored block for %x does not parse: %v", errBranchStoreCorrupt, parentHash, err) //nolint:errorlint // %v is required, not %w: errors.As unwraps %w, so a wrapped *consensus.TxError cause would satisfy p2p isConsensusApplyBlockError and bump the relaying peer's ban score 100 for OUR corrupt store (measured)
	}
	observedHash, err := consensus.BlockHash(parentParsed.HeaderBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: stored block for %x does not hash: %v", errBranchStoreCorrupt, parentHash, err) //nolint:errorlint // %v is required, not %w: errors.As unwraps %w, so a wrapped *consensus.TxError cause would satisfy p2p isConsensusApplyBlockError and bump the relaying peer's ban score 100 for OUR corrupt store (measured)
	}
	if observedHash != parentHash {
		return nil, nil, fmt.Errorf(
			"%w: stored block for %x hashes to %x",
			errBranchStoreCorrupt, parentHash, observedHash,
		)
	}
	return parentParsed, parentBlockBytes, nil
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

func (s *SyncEngine) requeueDisconnectedTransactions(disconnectedBlocks [][]byte) {
	if s == nil || s.mempool == nil || len(disconnectedBlocks) == 0 {
		return
	}
	// Disconnect helpers append blocks tip-down, matching h_max -> h_min requeue order.
	for blockIndex := 0; blockIndex < len(disconnectedBlocks); blockIndex++ {
		txs, err := nonCoinbaseBlockTransactions(disconnectedBlocks[blockIndex])
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
