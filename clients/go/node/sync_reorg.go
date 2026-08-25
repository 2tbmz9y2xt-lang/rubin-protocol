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

// ApplyBlockWithReorg is the relay entry point: it connects a tip extension, or
// stores a losing side-branch block, or switches to a winning branch — whichever
// fork choice selects — and any canonical switch runs inside exactly one
// canonical transition.
//
// It has the same return contract as ApplyBlock:
//   - (summary, nil) — ordinary ACCEPTED/NEW, or the synthetic summary for a
//     stored side-branch block that did not win fork choice.
//   - (summary, err) — EXACTLY and ONLY TERMINAL_PERSISTENCE(new): C1/M1/O1 and
//     the accepted delta are published for the whole branch, the engine latches,
//     admission stays closed until restart, and zero requeue owners run.
//   - (nil, err) — every other outcome, including a consensus rejection, a
//     side-block LOCAL_STORE_ERROR(noncanonical) that never latches, and every
//     OLD/open canonical refusal. A canonical refusal PUBLISHES nothing — no
//     index write, no C/M/O, no counter, no latch, live image untouched — but
//     one reached after the precommit steps leaves the whole branch's staged
//     artifacts behind and the checkpoint rewritten to the COMMON ANCESTOR
//     image, which lags the preserved live tip. Both harmless: staged rows stay
//     noncanonical, and startup replays the unchanged canonical index forward
//     from that common row.
//
// Nil-safe on the receiver, like the other exported SyncEngine methods.
func (s *SyncEngine) ApplyBlockWithReorg(blockBytes []byte, prevTimestamps []uint64) (*ChainStateConnectSummary, error) {
	if s == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	diag := &diagnosticBatch{}
	defer s.flushDiagnostics(diag)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := s.mutationAllowed(); err != nil {
		return nil, err
	}
	pb, blockHash, err := parseReorgBlock(blockBytes)
	if err != nil {
		return nil, err
	}

	if summary, handled, err := s.applyDirectBlockIfPossible(pb, blockBytes, prevTimestamps, diag); handled {
		return summary, err
	}
	branch, commonAncestorHeight, switchToBranch, candidateHeight, err := s.evaluateSideBranch(blockHash, blockBytes, pb)
	if err != nil {
		return nil, err
	}
	if !switchToBranch {
		return s.storeSideBlockAndSummary(branch, commonAncestorHeight, candidateHeight)
	}
	return s.applyPreferredBranch(branch, commonAncestorHeight, diag)
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
		// A side-block store failure is LOCAL_STORE_ERROR(noncanonical): it leaves
		// the canonical index, chainstate, mempool and owner untouched, so it is
		// NOT_APPLICABLE and never latches the engine.
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
	diag *diagnosticBatch,
) (*ChainStateConnectSummary, bool, error) {
	var zero [32]byte
	view := s.chainState.view()
	switch {
	case !view.hasTip:
		if pb.Header.PrevBlockHash != zero {
			return nil, true, ErrParentNotFound
		}
		summary, _, err := s.applyCanonicalParsedBlock(pb, blockBytes, prevTimestamps, nil, diag)
		return summary, true, err
	case pb.Header.PrevBlockHash == view.tipHash:
		summary, err := s.applyDirectTipBlock(pb, blockBytes, view, diag)
		return summary, true, err
	default:
		return nil, false, nil
	}
}

// applyDirectTipBlock applies a candidate whose parent is the canonical tip.
// Acquisition order is target-then-MTP: the target context must precede the
// RUB-647 canonical MTP window so a target-context failure short-circuits
// before any MTP state is read. The height-0 genesis branch never reaches here.
func (s *SyncEngine) applyDirectTipBlock(pb *consensus.ParsedBlock, blockBytes []byte, view chainStateView, diag *diagnosticBatch) (*ChainStateConnectSummary, error) {
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
	summary, _, err := s.applyCanonicalParsedBlock(pb, blockBytes, canonicalPrevTimestamps, targetCtx, diag)
	return summary, err
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

// preparedBranchBlock is one fully validated preferred-branch row on its way into
// the plan. It retains NO ChainState: only the parsed block and bytes the
// existing path already carried, that connect's summary, and the precomputed
// BlockUndo staging writes. The whole branch is validated against ONE rolling
// private clone, the mechanism Bitcoin Core's DisconnectTip/ConnectTip and btcd's
// reorganizeChain use for one coins view with per-block undo. The slice of these
// records dies with planPreferredBranch, but the payloads move into plan.staged
// and outlive it until the recovery proof writes and releases them; only charged
// descriptors survive past that point.
type preparedBranchBlock struct {
	item    reorgBranchBlock
	summary *ChainStateConnectSummary
	undo    *BlockUndo
	// includedDA is this row's contribution to I, in its own block's
	// transaction order. planPreferredBranch concatenates the rows in ascending
	// canonical order, which is the combined ordered list the contract asks for.
	includedDA []canonicalDASetIdentity
}

// applyPreferredBranch applies the candidate branch selected by fork choice —
// greater ChainWork, or equal ChainWork with a lexicographically lower tip hash
// — inside EXACTLY ONE canonical transition: one plan, one prepared-index
// commit, one final C/M/O publication with no intermediate public tip, and
// deterministic requeue only after an ordinary NEW reopened admission.
func (s *SyncEngine) applyPreferredBranch(
	branch []reorgBranchBlock,
	commonAncestorHeight uint64,
	diag *diagnosticBatch,
) (*ChainStateConnectSummary, error) {
	canonicalIndex, err := s.canonicalIndexPreflight()
	if err != nil {
		return nil, err
	}
	plan, summary, reorgDepth, finalTimestamp, err := s.planPreferredBranch(canonicalIndex, branch, commonAncestorHeight)
	if err != nil {
		return nil, err
	}
	truth, err := s.commitCanonicalTransition(plan, diag)
	if truth != canonicalTruthNew {
		return nil, err
	}
	summary.CanonicalAppliedBlocks = plan.applied
	s.recordAppliedBlock(summary.BlockHeight, finalTimestamp)
	s.noteBlockApplyAcceptedN(uint64(len(plan.connect)))
	s.noteReorg(reorgDepth)
	if err == nil {
		// Ordinary ACCEPTED/NEW only: TERMINAL_PERSISTENCE(new) publishes the same
		// image but invokes zero requeue owners. This runs after the transition
		// reopened admission and still under the entry point's mutationMu, so its
		// diagnostics join the same batch.
		s.requeueCanonicalDisconnectedRows(plan.disconnect, diag)
	}
	return summary, err
}

// planPreferredBranch derives the complete winning-reorg plan: the immutable
// common-checkpoint image, ONE rolling image that becomes final C1, the ordered
// disconnect and connect descriptors, A1, and the new-suffix artifacts staging
// will consume. It returns the final row's summary, the reorg depth and the new
// tip timestamp.
//
// Per-row payloads do NOT die with this call: each row's header bytes, block
// bytes and precomputed undo move into plan.staged and stay reachable until
// proveCanonicalRecoverySet writes them and releases the slice, at the very
// start of the transition. plan.staged is the ONLY guaranteed reachability —
// the caller's branch slice may be collected after its last use — and past
// staging the transition carries only the charged descriptors.
func (s *SyncEngine) planPreferredBranch(
	canonicalIndex []string,
	branch []reorgBranchBlock,
	commonAncestorHeight uint64,
) (*canonicalTransitionPlan, *ChainStateConnectSummary, uint64, uint64, error) {
	priorTip := chainTipScalarsOf(s.chainState)
	checkpoint, rolling, rows, reorgDepth, finalMTP, err := s.preparePreferredBranch(canonicalIndex, branch, commonAncestorHeight)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	disconnect, err := canonicalSequenceDescriptors(canonicalIndex, commonAncestorHeight+1, uint64(len(canonicalIndex)))
	if err != nil {
		return nil, nil, 0, 0, err
	}
	plan := &canonicalTransitionPlan{
		oldSequence: canonicalIndex,
		disconnect:  disconnect,
		connect:     make([]canonicalRowDescriptor, 0, len(rows)),
		applied:     make([]CanonicalAppliedBlock, 0, len(rows)),
		staged:      make([]canonicalStagedRow, 0, len(rows)),
		checkpoint:  checkpoint,
		final:       rolling,
		priorTip:    priorTip,
		finalMTP:    finalMTP,
	}
	suffix := make([][32]byte, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		descriptor := canonicalRowDescriptor{height: row.summary.BlockHeight, hash: row.item.hash}
		plan.connect = append(plan.connect, descriptor)
		plan.applied = append(plan.applied, row.summary.CanonicalAppliedBlocks...)
		plan.includedDA = append(plan.includedDA, row.includedDA...)
		plan.staged = append(plan.staged, canonicalStagedRow{
			descriptor:  descriptor,
			headerBytes: row.item.parsed.HeaderBytes,
			blockBytes:  row.item.blockBytes,
			undo:        row.undo,
		})
		suffix = append(suffix, row.item.hash)
	}
	plan.newSequence = canonicalSequenceWithSuffix(canonicalIndex, commonAncestorHeight+1, suffix)
	final := rows[len(rows)-1]
	return plan, final.summary, reorgDepth, final.item.header.Timestamp, nil
}

// preparePreferredBranch validates the whole winning branch against ONE rolling
// private clone and retains only the compact per-row staging record.
//
// It returns exactly TWO O(UTXO) images and never a third: the immutable
// common-checkpoint clone taken once the preview has disconnected back to the
// common ancestor, and the rolling clone that goes on to become final C1. The
// per-row records still grow linearly in branch depth — block bytes, parse and
// precomputed undo — and they enter the transition inside plan.staged; staging
// consumes and releases them in the recovery-proof step, so nothing
// depth-proportional survives PAST it.
//
// It touches no live state and nothing it does repeats once the fence is held. A
// failed row aborts the whole preparation and discards both clones with it,
// which is why connecting into the rolling clone IN PLACE is safe even though a
// rejected connect may leave it partially advanced.
func (s *SyncEngine) preparePreferredBranch(
	canonicalIndex []string,
	branch []reorgBranchBlock,
	commonAncestorHeight uint64,
) (*ChainState, *ChainState, []preparedBranchBlock, uint64, uint64, error) {
	rolling := cloneChainState(s.chainState)
	if rolling == nil {
		return nil, nil, nil, 0, 0, errors.New("nil preview chainstate")
	}
	reorgDepth, err := s.previewDisconnectCanonicalToAncestor(rolling, canonicalIndex, commonAncestorHeight)
	if err != nil {
		return nil, nil, nil, 0, 0, err
	}
	checkpoint := cloneChainState(rolling)
	if checkpoint == nil {
		return nil, nil, nil, 0, 0, errors.New("nil common-checkpoint chainstate")
	}
	// Build a sliding MTP window: start from pre-fork timestamps, advance
	// after each block.  The blockstore index is NOT updated during preview,
	// so per-block advancement uses a sliding window instead of
	// re-deriving from the store each iteration (B.9 fix).
	slidingTs, err := prevTimestampsFromStore(s.blockStore, commonAncestorHeight+1)
	if err != nil {
		return nil, nil, nil, 0, 0, err
	}
	rows := make([]preparedBranchBlock, 0, len(branch))
	for i, item := range branch {
		// The rolling state carries row i-1's post-state into row i, so the last
		// row leaves it holding exactly the image the transition publishes.
		row, rowErr := s.prepareBranchRow(rolling, item, commonAncestorHeight+1+uint64(i), slidingTs)
		if rowErr != nil {
			return nil, nil, nil, 0, 0, rowErr
		}
		rows = append(rows, row)
		slidingTs = advancePrevTimestamps(slidingTs, item.header.Timestamp)
	}
	return checkpoint, rolling, rows, reorgDepth, mtpMedian(commonAncestorHeight+uint64(len(rows))+1, slidingTs), nil
}

// prepareBranchRow fully validates one branch row by connecting it into the
// caller's single rolling private state, then retains only what the commit needs.
//
// Per-row target derivation: a branch can cross a retarget boundary. Unlike the
// MTP window it needs no sliding workaround — it reads headers by hash, never
// the canonical index, and every ancestor it needs is already stored. Target
// context resolves first, so its failure short-circuits before the connect.
//
// The connect below is the only block-row verdict; commit does not revalidate rows.
// Its failure records canonical rejection and aborts the entire preparation, so a branch
// contributes at most ONE rejected outcome however many rows it has, and the
// rows that already prepared contribute nothing: the branch never opened a
// transition, so it never published and they are neither accepted nor rejected.
//
// The accounting is scoped to that error and nothing else. The target-context
// resolution before it and the undo/delta/DA-set derivation after it are local
// failures, not consensus verdicts on the candidate, and neither may add an
// outcome — the same rule that keeps side-chain storage, orphan / missing
// parent, local I/O, recovery-proof, commit-refusal and retained-state planning
// failures at zero.
func (s *SyncEngine) prepareBranchRow(
	rolling *ChainState,
	item reorgBranchBlock,
	height uint64,
	prevTimestamps []uint64,
) (preparedBranchBlock, error) {
	targetCtx, err := s.targetContextForCandidate(item.header.PrevBlockHash, height)
	if err != nil {
		return preparedBranchBlock{}, err
	}
	priorAlreadyGenerated := chainTipScalarsOf(rolling).alreadyGenerated
	// The undo needs the pre-block image of every spent outpoint, and the
	// sequential connect below overwrites the rolling map in place, so the
	// touched entries — and ONLY those — are read out first.
	preImages := capturePreImages(rolling, item.parsed)
	summary, err := rolling.ConnectBlockWithSuiteContext(
		item.blockBytes,
		targetCtx.expected,
		prevTimestamps,
		s.cfg.ChainID,
		s.cfg.RotationProvider,
		s.cfg.SuiteRegistry,
	)
	// PV shadow is DIRECT-CONNECT ONLY, in every pv mode: resource_bounds gives
	// this path exactly two O(UTXO) images (common checkpoint + the rolling image
	// that becomes C1), and a per-row shadow pre-state would be a third, the
	// shadow's own clone a fourth. Reorg rows are PV-skipped.
	s.pvTelemetry.RecordBlockSkipped()
	if err != nil {
		// The ONE canonical block-apply rejection for this whole branch; see the
		// accounting rule on this function.
		s.noteBlockApplyRejected()
		return preparedBranchBlock{}, err
	}
	return prepareCommitRow(item, summary, priorAlreadyGenerated, preImages)
}

// prepareCommitRow turns one already-connected row into its compact staging
// record — precomputed undo and this row's A1 entry — reading only the captured
// pre-entries.
func prepareCommitRow(item reorgBranchBlock, summary *ChainStateConnectSummary, priorAlreadyGenerated consensus.Uint128, preImages map[consensus.Outpoint]consensus.UtxoEntry) (preparedBranchBlock, error) {
	undo, err := buildPreparedBlockUndo(preImages, item.parsed, summary.BlockHeight, priorAlreadyGenerated)
	if err != nil {
		return preparedBranchBlock{}, err
	}
	daIDs, err := CompleteDASetIDsFromParsedBlock(item.parsed)
	if err != nil {
		return preparedBranchBlock{}, err
	}
	includedDA, err := canonicalDASetIdentitiesFromParsedBlock(item.parsed)
	if err != nil {
		return preparedBranchBlock{}, err
	}
	summary.CanonicalAppliedBlocks = []CanonicalAppliedBlock{{Hash: item.hash, CompleteDAIDs: daIDs}}
	return preparedBranchBlock{item: item, summary: summary, undo: undo, includedDA: includedDA}, nil
}

// capturePreImages reads the pre-block UTXO entry of every outpoint the block's
// non-coinbase transactions spend, and nothing else — that is what lets undo and
// delta be derived without copying the whole UTXO map per row. An input absent
// here was created earlier in the SAME block, which the undo builder resolves
// from its own block-local map.
func capturePreImages(state *ChainState, pb *consensus.ParsedBlock) map[consensus.Outpoint]consensus.UtxoEntry {
	preImages := make(map[consensus.Outpoint]consensus.UtxoEntry)
	state.mu.RLock()
	defer state.mu.RUnlock()
	for i := 1; i < len(pb.Txs); i++ {
		tx := pb.Txs[i]
		if tx == nil {
			continue
		}
		for _, in := range tx.Inputs {
			op := outpointFromInput(in)
			if entry, ok := state.Utxos[op]; ok {
				preImages[op] = copyUtxoEntry(entry)
			}
		}
	}
	return preImages
}

// buildPreparedBlockUndo builds exactly the BlockUndo buildBlockUndo builds, from
// the captured touched entries instead of a full UTXO-set copy. buildTxUndos adds
// each transaction's created outputs to its work map as it goes, so an input
// spending a same-block output resolves identically under either work map.
func buildPreparedBlockUndo(preImages map[consensus.Outpoint]consensus.UtxoEntry, pb *consensus.ParsedBlock, blockHeight uint64, previousAlreadyGenerated consensus.Uint128) (*BlockUndo, error) {
	if pb == nil {
		return nil, errors.New("nil parsed block")
	}
	if len(pb.Txs) != len(pb.Txids) {
		return nil, errors.New("parsed block txid length mismatch")
	}
	work := make(map[consensus.Outpoint]consensus.UtxoEntry, len(preImages))
	for op, entry := range preImages {
		work[op] = copyUtxoEntry(entry)
	}
	txUndos, err := buildTxUndos(work, pb, blockHeight)
	if err != nil {
		return nil, err
	}
	return &BlockUndo{
		BlockHeight:              blockHeight,
		PreviousAlreadyGenerated: previousAlreadyGenerated,
		Txs:                      txUndos,
	}, nil
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
	alreadyGenerated := consensus.Uint128{}
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

// requeueDisconnectedTransactions is for raw-byte callers; the reorg path
// re-reads its disconnected rows from the store instead. It has no production
// call site, so it takes no batch and emits directly, which is legal exactly
// because its callers hold none of the engine's locks.
func (s *SyncEngine) requeueDisconnectedTransactions(disconnectedBlocks [][]byte) {
	parsedBlocks := make([]*consensus.ParsedBlock, 0, len(disconnectedBlocks))
	for _, blockBytes := range disconnectedBlocks {
		parsed, err := consensus.ParseBlockBytes(blockBytes)
		if err != nil {
			continue
		}
		parsedBlocks = append(parsedBlocks, parsed)
	}
	s.requeueParsedDisconnectedTransactions(parsedBlocks, nil)
}

// requeueParsedDisconnectedTransactions MUST NOT be called under the canonical
// transition guard: it routes to Mempool.AddReorgTx, which takes
// ChainState.admissionMu.RLock, and sync.RWMutex is not reentrant. Its only
// caller runs it after the transition released that guard.
//
// diag is the owning mutation's batch when a public entry point drives this
// (the reorg path), or nil for a caller outside a mutation, which holds none of
// the engine's locks and may therefore write directly.
// Section 11.1 selects ONE owner per disconnected non-coinbase row from the
// row's own tx_kind, and this is that selection for the current line:
//
//	tx_kind 0x00                 -> exactly one standard-owner attempt
//	tx_kind 0x01/0x02 (DA)       -> zero owners, dropped
//	every other/unsupported kind -> zero owners, dropped
//
// The DA row is a BOUNDED INTERMEDIATE SAFETY GUARD, not Section 11.1's DA
// re-admission: routing a DA_COMMIT_TX or DA_CHUNK_TX into the standard owner
// would admit it under the wrong domain's rules, so until RUB-680 owns the
// detached DA owner the row invokes no owner at all. This is deliberately a
// smaller behavior than the subsection describes, and it MUST NOT be read as
// completing it.
//
// Each dropped row records at most one local diagnostic, which is all the
// subsection permits, and the drop touches no DA owner and no peer quota.
func (s *SyncEngine) requeueParsedDisconnectedTransactions(disconnectedBlocks []*consensus.ParsedBlock, diag *diagnosticBatch) {
	if s == nil || s.mempool == nil || len(disconnectedBlocks) == 0 {
		return
	}
	// Disconnect helpers append blocks tip-down, matching h_max -> h_min requeue order.
	for _, parsed := range disconnectedBlocks {
		rows, err := nonCoinbaseParsedBlockTransactions(parsed)
		if err != nil {
			continue
		}
		for _, row := range rows {
			if row.kind != 0x00 {
				s.diagnose(diag, "mempool: requeue-tx: tx_kind %#02x invokes no owner in this line\n", row.kind)
				continue
			}
			if err := s.mempool.AddReorgTx(row.txBytes); err != nil {
				s.diagnose(diag, "mempool: requeue-tx: %v\n", err)
			}
		}
	}
}

// canonicalRequeueRow is one disconnected non-coinbase row: the tx_kind the
// block's ALREADY VALIDATED parse reported, and that row's canonical bytes. The
// kind travels with the bytes precisely so the requeue selection never re-parses
// and never falls back to a second classifier.
type canonicalRequeueRow struct {
	txBytes []byte
	kind    uint8
}

func nonCoinbaseBlockTransactions(blockBytes []byte) ([]canonicalRequeueRow, error) {
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	return nonCoinbaseParsedBlockTransactions(pb)
}

// nonCoinbaseParsedBlockTransactions returns the block's rows from index 1 in
// canonical body order — the coinbase row at index 0 is skipped and invokes zero
// owners whatever it parsed as.
func nonCoinbaseParsedBlockTransactions(pb *consensus.ParsedBlock) ([]canonicalRequeueRow, error) {
	if pb == nil {
		return nil, errors.New("nil parsed block")
	}
	if len(pb.Txs) <= 1 {
		return nil, nil
	}
	rows := make([]canonicalRequeueRow, 0, len(pb.Txs)-1)
	for txIndex := 1; txIndex < len(pb.Txs); txIndex++ {
		tx := pb.Txs[txIndex]
		if tx == nil {
			return nil, fmt.Errorf("parsed block row %d is nil", txIndex)
		}
		txBytes, err := consensus.MarshalTx(tx)
		if err != nil {
			return nil, err
		}
		rows = append(rows, canonicalRequeueRow{txBytes: txBytes, kind: tx.TxKind})
	}
	return rows, nil
}

func reverseBranchBlocks(branch []reorgBranchBlock) {
	for left, right := 0, len(branch)-1; left < right; left, right = left+1, right-1 {
		branch[left], branch[right] = branch[right], branch[left]
	}
}
