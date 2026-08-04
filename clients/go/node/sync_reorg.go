package node

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

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

// preparedBranchBlock is one fully validated preferred-branch row. It retains NO
// ChainState: only the parsed block and bytes the existing path already carried,
// that connect's summary, the exact prior-tip scalars the commit rechecks, the
// precomputed BlockUndo, and the compact block-local UTXO delta — bounded by the
// branch's own inputs and outputs, never by branch depth times the UTXO set. The
// whole branch is validated against ONE rolling private clone, the mechanism
// Bitcoin Core's DisconnectTip/ConnectTip and btcd's reorganizeChain use when
// they roll a single coins view with per-block undo. Everything the in-guard
// commit needs is here, so it repeats no parse, no ConnectBlock, no signature
// verification and no fallible preparation.
type preparedBranchBlock struct {
	item     reorgBranchBlock
	summary  *ChainStateConnectSummary
	priorTip canonicalTipScalars
	undo     *BlockUndo
	delta    chainStateDelta
}

// chainStateDelta is the compact block-local change one prepared row publishes:
// the pre-existing outpoints the block spends, the outpoints it leaves created,
// and the post-block scalars. One created AND spent inside the same block
// appears in neither list — the live chainstate never observes it.
type chainStateDelta struct {
	spent   []consensus.Outpoint
	created []createdUtxo
	post    canonicalTipScalars
}

type createdUtxo struct {
	outpoint consensus.Outpoint
	entry    consensus.UtxoEntry
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
// common ancestor, then publish and persist each already-prepared row. Nothing
// suppresses the per-block inner cleanup — this path never calls it.
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
		if err := s.commitPreparedRowUnderGuard(tr, row); err != nil {
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

// preparePreferredBranch validates the whole winning branch against ONE rolling
// private clone and retains only the compact per-row commit record.
//
// The retention claim is exactly this and no more: the number of retained full
// ChainState / UTXO-set images is O(1) in branch depth — ONE rolling clone,
// whatever the depth. Total retained memory is NOT O(1). Each prepared row still
// keeps its own block bytes, parse, precomputed undo and block-local delta, so
// those grow linearly in branch depth; each is bounded by the consensus block
// limits the row already passed, which is why the path needs no separate depth
// cap rather than why it uses constant memory.
//
// It touches no live state and nothing it does repeats once the guard is held. A
// failed row aborts the whole preparation and discards the rolling clone with
// it, which is why connecting into that clone IN PLACE is safe even though a
// rejected connect may leave it partially advanced.
func (s *SyncEngine) preparePreferredBranch(
	branch []reorgBranchBlock,
	commonAncestorHeight uint64,
) ([]preparedBranchBlock, []verifiedStoredBlock, uint64, error) {
	rolling := cloneChainState(s.chainState)
	if rolling == nil {
		return nil, nil, 0, errors.New("nil preview chainstate")
	}
	preparedDisconnectedBlocks, reorgDepth, err := s.previewDisconnectCanonicalToAncestor(rolling, commonAncestorHeight)
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
	for i, item := range branch {
		// The rolling state carries row i-1's post-state into row i, matching
		// exactly what the guard publishes one row at a time.
		row, rowErr := s.prepareBranchRow(rolling, item, commonAncestorHeight+1+uint64(i), slidingTs)
		if rowErr != nil {
			return nil, nil, 0, rowErr
		}
		rows = append(rows, row)
		slidingTs = advancePrevTimestamps(slidingTs, item.header.Timestamp)
	}
	return rows, preparedDisconnectedBlocks, reorgDepth, nil
}

// prepareBranchRow fully validates one branch row by connecting it into the
// caller's single rolling private state, then retains only what the commit needs.
//
// Per-row target derivation: a branch can cross a retarget boundary. Unlike the
// MTP window it needs no sliding workaround — it reads headers by hash, never
// the canonical index, and every ancestor it needs is already stored. Target
// context resolves first, so its failure short-circuits before the connect.
//
// The connect below is the branch path's ONLY consensus verdict — the commit
// half revalidates nothing — so its failure is where the canonical block-apply
// rejection is recorded. A failed row aborts the entire preparation, so a branch
// contributes at most ONE rejected outcome however many rows it has, and the
// rows that already prepared contribute nothing: the branch never opened a
// transition, so it never published and they are neither accepted nor rejected.
//
// The accounting is scoped to that error and nothing else. The target-context
// resolution before it and the undo/delta/DA-set derivation after it are local
// failures, not consensus verdicts on the candidate, and neither may add an
// outcome — the same rule that keeps side-chain storage, orphan / missing
// parent, local I/O, persistence, rollback and cleanup failures at zero.
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
	priorTip := chainTipScalarsOf(rolling)
	// The undo needs the pre-block image of every spent outpoint, and the
	// sequential connect below overwrites the rolling map in place, so the
	// touched entries — and ONLY those — are read out first.
	preImages := capturePreImages(rolling, item.parsed)
	ctx := canonicalBlockApplyContext{
		blockHeight:    height,
		blockHash:      item.hash,
		expectedTarget: targetCtx.expected,
		prevState:      s.pvShadowPreState(rolling),
	}
	summary, err := rolling.ConnectBlockWithSuiteContext(
		item.blockBytes,
		ctx.expectedTarget,
		prevTimestamps,
		s.cfg.ChainID,
		s.cfg.RotationProvider,
		s.cfg.SuiteRegistry,
	)
	if ctx.prevState != nil {
		s.runPVShadow(item.blockBytes, prevTimestamps, ctx, err, summary)
	} else {
		s.pvTelemetry.RecordBlockSkipped()
	}
	if err != nil {
		// The ONE canonical block-apply rejection for this whole branch; see the
		// accounting rule on this function.
		s.noteBlockApplyRejected()
		return preparedBranchBlock{}, err
	}
	return prepareCommitRow(item, summary, priorTip, preImages, rolling)
}

// prepareCommitRow turns one already-connected row into its compact commit
// record — precomputed undo, block-local delta, DA-set summary — reading only
// the captured pre-entries and the rolling post-state.
func prepareCommitRow(item reorgBranchBlock, summary *ChainStateConnectSummary, priorTip canonicalTipScalars, preImages map[consensus.Outpoint]consensus.UtxoEntry, post *ChainState) (preparedBranchBlock, error) {
	undo, err := buildPreparedBlockUndo(preImages, item.parsed, summary.BlockHeight, priorTip.alreadyGenerated)
	if err != nil {
		return preparedBranchBlock{}, err
	}
	delta, err := deriveChainStateDelta(preImages, post, undo, item.parsed)
	if err != nil {
		return preparedBranchBlock{}, err
	}
	daIDs, err := CompleteDASetIDsFromParsedBlock(item.parsed)
	if err != nil {
		return preparedBranchBlock{}, err
	}
	summary.CanonicalAppliedBlocks = []CanonicalAppliedBlock{{Hash: item.hash, CompleteDAIDs: daIDs}}
	return preparedBranchBlock{item: item, summary: summary, priorTip: priorTip, undo: undo, delta: delta}, nil
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
func buildPreparedBlockUndo(preImages map[consensus.Outpoint]consensus.UtxoEntry, pb *consensus.ParsedBlock, blockHeight, previousAlreadyGenerated uint64) (*BlockUndo, error) {
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

// deriveChainStateDelta reports the net change the live chainstate must observe
// for one already-validated row: every spend whose outpoint existed BEFORE the
// block, and every output the connected post-state still holds. Both halves come
// from the block's own ordered inputs and outputs plus the touched entries —
// never a scan or a copy of the UTXO map.
func deriveChainStateDelta(preImages map[consensus.Outpoint]consensus.UtxoEntry, post *ChainState, undo *BlockUndo, pb *consensus.ParsedBlock) (chainStateDelta, error) {
	if undo == nil || pb == nil || post == nil || len(pb.Txs) != len(pb.Txids) {
		return chainStateDelta{}, errors.New("nil or malformed prepared row delta source")
	}
	created, err := deriveCreatedUtxos(post, pb)
	if err != nil {
		return chainStateDelta{}, err
	}
	return chainStateDelta{
		spent:   derivePreExistingSpends(preImages, undo),
		created: created,
		post:    chainTipScalarsOf(post),
	}, nil
}

// derivePreExistingSpends lists, in undo order, the outpoints this block spends
// that ALSO existed before it; one created and spent inside it is absent.
func derivePreExistingSpends(preImages map[consensus.Outpoint]consensus.UtxoEntry, undo *BlockUndo) []consensus.Outpoint {
	var spent []consensus.Outpoint
	for _, txUndo := range undo.Txs {
		for _, item := range txUndo.Spent {
			if _, existed := preImages[item.Outpoint]; existed {
				spent = append(spent, item.Outpoint)
			}
		}
	}
	return spent
}

// deriveCreatedUtxos lists every output the connected post-state still holds,
// with its exact entry read back from that state, so no output-encoding rule is
// restated here: one the connect did not index, or one a later transaction in
// the same block already spent, is simply absent.
func deriveCreatedUtxos(post *ChainState, pb *consensus.ParsedBlock) ([]createdUtxo, error) {
	var created []createdUtxo
	post.mu.RLock()
	defer post.mu.RUnlock()
	for i, tx := range pb.Txs {
		if tx == nil {
			return nil, fmt.Errorf("nil tx at index %d", i)
		}
		for outputIndex := range tx.Outputs {
			op := consensus.Outpoint{Txid: pb.Txids[i], Vout: uint32(outputIndex)}
			if entry, ok := post.Utxos[op]; ok {
				created = append(created, createdUtxo{outpoint: op, entry: copyUtxoEntry(entry)})
			}
		}
	}
	return created, nil
}

// commitPreparedRowUnderGuard publishes and persists ONE already-validated
// preferred-branch row: live tip recheck, the compact delta onto the single live
// ChainState, then that row's precomputed undo through the existing persistence
// path. ChainState and BlockStore therefore correspond at every successfully
// persisted row, rather than the store running ahead of a chainstate published
// once at the end. Nothing here parses, connects, verifies or revalidates.
func (s *SyncEngine) commitPreparedRowUnderGuard(tr *canonicalTransition, row *preparedBranchBlock) error {
	if err := s.recheckLiveTipIdentity(tr, row.priorTip); err != nil {
		return s.rollbackApplyBlock(err, tr.rollback)
	}
	if err := applyPreparedRowDelta(tr.chainState, row.delta); err != nil {
		return s.rollbackApplyBlock(err, tr.rollback)
	}
	commitStart := time.Now()
	if err := s.persistPreparedRow(row); err != nil {
		return s.classifyPersistenceFailure(err, tr.rollback)
	}
	s.pvTelemetry.RecordCommitLatency(time.Since(commitStart))
	return nil
}

// applyPreparedRowDelta publishes one compact row onto the live ChainState under
// ChainState.mu only: the transition already owns the non-reentrant admissionMu,
// so the ChainState wrappers that reacquire it must not be called here. Every
// precondition is checked BEFORE the first write, so a live map that is not what
// the row was prepared against fails into the exact rollback, not half-applied.
func applyPreparedRowDelta(dst *ChainState, delta chainStateDelta) error {
	if dst == nil {
		return errors.New("nil chainstate delta destination")
	}
	dst.mu.Lock()
	defer dst.mu.Unlock()
	if dst.Utxos == nil {
		dst.Utxos = make(map[consensus.Outpoint]consensus.UtxoEntry)
	}
	if err := checkPreparedRowDeltaLocked(dst, delta); err != nil {
		return err
	}
	for _, op := range delta.spent {
		delete(dst.Utxos, op)
	}
	for _, created := range delta.created {
		dst.Utxos[created.outpoint] = created.entry
	}
	dst.HasTip, dst.Height = delta.post.hasTip, delta.post.height
	dst.TipHash, dst.AlreadyGenerated = delta.post.tipHash, delta.post.alreadyGenerated
	return nil
}

// checkPreparedRowDeltaLocked proves the live map is exactly the pre-image the
// row was prepared against, for every outpoint it touches. Spent and created are
// disjoint by construction, so no ordering is implied. The caller holds dst.mu.
func checkPreparedRowDeltaLocked(dst *ChainState, delta chainStateDelta) error {
	for _, op := range delta.spent {
		if _, live := dst.Utxos[op]; !live {
			return fmt.Errorf("prepared row spends %x:%d which the live chainstate does not hold", op.Txid, op.Vout)
		}
	}
	for _, created := range delta.created {
		if _, live := dst.Utxos[created.outpoint]; live {
			return fmt.Errorf("prepared row creates %x:%d which the live chainstate already holds", created.outpoint.Txid, created.outpoint.Vout)
		}
	}
	return nil
}

// persistPreparedRow commits one prepared row through the existing
// BlockStore.CommitCanonicalBlock and ChainState.Save semantics, changing no
// persistence format and no error class: the ONLY difference from
// persistAppliedBlock is the precomputed undo.
func (s *SyncEngine) persistPreparedRow(row *preparedBranchBlock) error {
	if row.undo == nil {
		return errors.New("nil prepared block undo")
	}
	if s.blockStore != nil {
		if err := s.blockStore.CommitCanonicalBlock(row.summary.BlockHeight, row.item.hash, row.item.parsed.HeaderBytes, row.item.blockBytes, row.undo); err != nil {
			return err
		}
	}
	if s.cfg.ChainStatePath != "" && (s.blockStore == nil || shouldPersistChainStateSnapshot(s.chainState, row.summary)) {
		return s.chainState.Save(s.cfg.ChainStatePath)
	}
	return nil
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
				_, _ = fmt.Fprintf(s.diagnosticWriter(), "mempool: requeue-tx: %v\n", err)
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
