package node

import (
	"errors"
	"fmt"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	chainStateSnapshotIntervalBlocks  = uint64(32)
	chainStateSnapshotSmallUtxoCutoff = 4096
)

func shouldPersistChainStateSnapshot(state *ChainState, summary *ChainStateConnectSummary) bool {
	if state == nil || summary == nil {
		return true
	}
	view := state.view()
	if !view.hasTip || summary.BlockHeight == 0 {
		return true
	}
	if view.utxoCount <= chainStateSnapshotSmallUtxoCutoff {
		return true
	}
	return summary.BlockHeight%chainStateSnapshotIntervalBlocks == 0
}

func cloneChainState(src *ChainState) *ChainState {
	if src == nil {
		return nil
	}
	src.mu.RLock()
	defer src.mu.RUnlock()
	return &ChainState{
		Utxos:            copyUtxoSet(src.Utxos),
		Height:           src.Height,
		AlreadyGenerated: src.AlreadyGenerated,
		TipHash:          src.TipHash,
		HasTip:           src.HasTip,
		Rotation:         src.Rotation,
		Registry:         src.Registry,
	}
}

// errCanonicalIndexZeroCompletePrefix: the canonical index claims blocks but not
// even height 0 has a complete header/block/undo set. Discarding the rows would
// silently destroy the operator's whole chain, so this is fatal. Raised AFTER the
// scan's structural/IO/corruption errors (they keep precedence) and BEFORE
// any chainstate reset/replay/save and any service start.
// Cross-client literal — Rust mirror CANONICAL_INDEX_ZERO_COMPLETE_PREFIX_ERR.
var errCanonicalIndexZeroCompletePrefix = errors.New("persisted canonical index has zero complete prefix")

// errCanonicalIndexIncompleteSuffix: the canonical index declares committed
// entries whose header/block/undo set is incomplete. Committed canonical rows
// are never truncated or repaired to hide that, so startup fails closed and the
// operator decides. Go-primary; the Rust mirror is RUB-897.
var errCanonicalIndexIncompleteSuffix = errors.New("persisted canonical index has an incomplete committed suffix")

// requireCompleteCanonicalPrefix proves every entry the canonical index already
// declares committed has a complete header/block/undo set. It WRITES NOTHING:
// its domain is store.CanonicalIndexSnapshot(), so every state it can reach is
// index-declared-committed and dropping the suffix would discard committed
// chain to hide corruption. Precedence is unchanged from the scan it replaces:
// structural/IO/corruption errors first, then the zero-complete-prefix literal,
// then the incomplete-suffix refusal.
func requireCompleteCanonicalPrefix(store *BlockStore) error {
	canonical, err := store.CanonicalIndexSnapshot()
	if err != nil {
		return err
	}
	validCount, err := countCompleteCanonicalPrefix(store, canonical)
	if err != nil {
		return err
	}
	if validCount == uint64(len(canonical)) {
		return nil
	}
	if validCount == 0 {
		return errCanonicalIndexZeroCompletePrefix
	}
	return fmt.Errorf("%w: index declares %d entries but only %d have a complete header/block/undo set",
		errCanonicalIndexIncompleteSuffix, len(canonical), validCount)
}

func countCompleteCanonicalPrefix(store *BlockStore, canonical []string) (uint64, error) {
	validCount := uint64(0)
	for i, hashHex := range canonical {
		complete, err := store.canonicalArtifactsComplete(hashHex)
		if err != nil {
			return 0, err
		}
		if !complete {
			break
		}
		validCount = uint64(i + 1)
	}
	return validCount, nil
}

func (bs *BlockStore) canonicalArtifactsComplete(hashHex string) (bool, error) {
	blockHash, err := parseHex32("canonical hash", hashHex)
	if err != nil {
		return false, err
	}
	if complete, err := canonicalArtifactExists(bs.headerExists, blockHash); err != nil || !complete {
		return complete, err
	}
	if complete, err := canonicalArtifactExists(bs.blockExists, blockHash); err != nil || !complete {
		return complete, err
	}
	if complete, err := canonicalArtifactExists(bs.undoExists, blockHash); err != nil || !complete {
		return complete, err
	}
	return true, nil
}

func canonicalArtifactExists(check func([32]byte) error, blockHash [32]byte) (bool, error) {
	if err := check(blockHash); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (bs *BlockStore) headerExists(blockHash [32]byte) error {
	_, err := bs.GetHeaderByHash(blockHash)
	return err
}

func (bs *BlockStore) blockExists(blockHash [32]byte) error {
	_, err := bs.GetBlockByHash(blockHash)
	return err
}

func (bs *BlockStore) undoExists(blockHash [32]byte) error {
	_, err := bs.GetUndo(blockHash)
	return err
}

// ReconcileChainStateWithBlockStore replays any canonical blocks that are present
// in the blockstore but missing from the persisted chainstate snapshot. When the
// loaded snapshot disagrees with the canonical chain at its claimed height, the
// canonical blockstore view wins and replay restarts from an empty state.
//
// It fails closed on canonical corruption before anything else: an incomplete
// committed canonical prefix returns an error rather than being truncated or
// repaired, so this function performs no durable write of its own on any path.
func ReconcileChainStateWithBlockStore(state *ChainState, store *BlockStore, cfg SyncConfig) (bool, error) {
	if state == nil {
		return false, errors.New("nil chainstate")
	}
	if store == nil {
		return false, errors.New("nil blockstore")
	}
	if err := requireCompleteCanonicalPrefix(store); err != nil {
		return false, err
	}
	tipHeight, _, ok, err := store.Tip()
	if err != nil {
		return false, err
	}
	if !ok {
		return reconcileEmptyBlockStore(state), nil
	}

	replayFrom, changed, replayNeeded, err := reconcileReplayStart(state, store, tipHeight)
	if err != nil || !replayNeeded {
		return changed, err
	}
	return replayCanonicalBlocks(state, store, cfg, replayFrom, tipHeight, changed)
}

func reconcileEmptyBlockStore(state *ChainState) bool {
	view := state.view()
	dirty := view.hasTip || view.utxoCount != 0 || !view.alreadyGenerated.IsZero() || view.height != 0 || view.tipHash != ([32]byte{})
	if dirty {
		state.replaceFrom(NewChainState())
		return true
	}
	return false
}

func reconcileReplayStart(state *ChainState, store *BlockStore, tipHeight uint64) (uint64, bool, bool, error) {
	view := state.view()
	if !view.hasTip || view.height > tipHeight {
		state.replaceFrom(NewChainState())
		return 0, true, true, nil
	}
	canonicalHash, hasHeight, err := store.CanonicalHash(view.height)
	if err != nil {
		return 0, false, false, err
	}
	if !hasHeight || canonicalHash != view.tipHash {
		state.replaceFrom(NewChainState())
		return 0, true, true, nil
	}
	if view.height == tipHeight {
		return 0, false, false, nil
	}
	return view.height + 1, false, true, nil
}

func replayCanonicalBlocks(state *ChainState, store *BlockStore, cfg SyncConfig, replayFrom uint64, tipHeight uint64, changed bool) (bool, error) {
	for height := replayFrom; height <= tipHeight; height++ {
		blockHash, ok, err := store.CanonicalHash(height)
		if err != nil {
			return false, err
		}
		if !ok {
			// Suffix `at height N (tip_height=N')` is part of the
			// cross-client error literal — Rust mirror in
			// `clients/rust/crates/rubin-node/src/chainstate_recovery.rs`
			// emits the bit-identical wording. Operators searching
			// logs for canonical-index corruption get the exact
			// height instead of having to reconstruct the loop state.
			return false, fmt.Errorf("missing canonical block hash during chainstate replay at height %d (tip_height=%d)", height, tipHeight)
		}
		expectedTarget, err := replayExpectedTarget(store, cfg, height, tipHeight)
		if err != nil {
			return false, err
		}
		blockBytes, prevTimestamps, err := replayBlockInputs(store, blockHash, height)
		if err != nil {
			return false, err
		}
		if _, err := state.ConnectBlockWithSuiteContext(
			blockBytes,
			expectedTarget,
			prevTimestamps,
			cfg.ChainID,
			cfg.RotationProvider,
			cfg.SuiteRegistry,
		); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

// replayExpectedTarget resolves the expected target per replayed block: the
// selected parent is the canonical index entry at height-1. Only the
// free-function form of the primitive is callable here — this runs before the
// sync engine exists.
//
// Failure contract (RUB-655 done_when): the error returns unchanged through
// replayCanonicalBlocks and ReconcileChainStateWithBlockStore to
// cmd/rubin-node/main.go, which exits 2 BEFORE chainState.Save, before
// newSyncEngineFn, and before the mempool, peer manager and every service
// start. This helper writes nothing, and neither does any other step of the
// reconcile: the incomplete-suffix truncation that used to run first is gone,
// so a failed recovery leaves the datadir byte-identical. The in-memory reset
// reconcileReplayStart may have done is not durable — chainState.Save is never
// reached.
func replayExpectedTarget(store *BlockStore, cfg SyncConfig, height uint64, tipHeight uint64) (*[32]byte, error) {
	if height == 0 {
		return cfg.ExpectedTarget, nil
	}
	if !StockDevnetTargetSchedule(cfg.Network, cfg.ChainID) {
		return cfg.ExpectedTarget, nil
	}
	parentHash, ok, err := store.CanonicalHash(height - 1)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("missing canonical parent hash for target context during chainstate replay at height %d (tip_height=%d)", height, tipHeight)
	}
	target, err := deriveExpectedTargetFn(store, parentHash, height)
	if err != nil {
		return nil, err
	}
	return &target, nil
}

func replayBlockInputs(store *BlockStore, blockHash [32]byte, height uint64) ([]byte, []uint64, error) {
	blockBytes, err := store.GetBlockByHash(blockHash)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyReplayBlockHash(blockBytes, blockHash, height); err != nil {
		return nil, nil, err
	}
	prevTimestamps, err := prevTimestampsFromStore(store, height)
	if err != nil {
		return nil, nil, err
	}
	return blockBytes, prevTimestamps, nil
}

// storedBlockHeaderHash re-derives the content-addressed identity of stored
// block bytes: parse, then hash the contained header. step names the stage that
// failed so each caller keeps its own message. It is shared by replay's re-hash
// defense and InspectBlockPresence's block leaf, so the two can never disagree
// on what makes stored block bytes valid.
func storedBlockHeaderHash(blockBytes []byte) (blockHash [32]byte, step string, err error) {
	parsed, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return blockHash, "parse block bytes", err
	}
	blockHash, err = consensus.BlockHash(parsed.HeaderBytes)
	return blockHash, "hash header", err
}

func verifyReplayBlockHash(blockBytes []byte, blockHash [32]byte, height uint64) error {
	// Defense-in-depth: re-hash the loaded block's header before ConnectBlock.
	observedHash, step, err := storedBlockHeaderHash(blockBytes)
	if err != nil {
		return fmt.Errorf("%s during chainstate replay at height %d: %w", step, height, err)
	}
	if observedHash != blockHash {
		return fmt.Errorf(
			"canonical artifact corruption during chainstate replay at height %d: expected %x, on-disk header hashes to %x",
			height, blockHash, observedHash,
		)
	}
	return nil
}
