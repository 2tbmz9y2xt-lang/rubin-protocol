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

func truncateIncompleteCanonicalSuffix(store *BlockStore) (bool, error) {
	if store == nil {
		return false, errors.New("nil blockstore")
	}
	return scanAndTruncateCanonicalSuffix(store)
}

func scanAndTruncateCanonicalSuffix(store *BlockStore) (bool, error) {
	canonical, err := store.CanonicalIndexSnapshot()
	if err != nil {
		return false, err
	}
	validCount, err := countCompleteCanonicalPrefix(store, canonical)
	if err != nil {
		return false, err
	}
	if validCount == uint64(len(canonical)) {
		return false, nil
	}
	if err := store.TruncateCanonical(validCount); err != nil {
		return false, err
	}
	return true, nil
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
func ReconcileChainStateWithBlockStore(state *ChainState, store *BlockStore, cfg SyncConfig) (bool, error) {
	if state == nil {
		return false, errors.New("nil chainstate")
	}
	if store == nil {
		return false, errors.New("nil blockstore")
	}
	truncated, err := truncateIncompleteCanonicalSuffix(store)
	if err != nil {
		return false, err
	}
	tipHeight, _, ok, err := store.Tip()
	if err != nil {
		return false, err
	}
	if !ok {
		return reconcileEmptyBlockStore(state, truncated), nil
	}

	replayFrom, changed, replayNeeded, err := reconcileReplayStart(state, store, tipHeight, truncated)
	if err != nil || !replayNeeded {
		return changed, err
	}
	return replayCanonicalBlocks(state, store, cfg, replayFrom, tipHeight, changed)
}

func reconcileEmptyBlockStore(state *ChainState, truncated bool) bool {
	view := state.view()
	dirty := view.hasTip || view.utxoCount != 0 || view.alreadyGenerated != 0 || view.height != 0 || view.tipHash != ([32]byte{})
	if truncated || dirty {
		state.replaceFrom(NewChainState())
		return true
	}
	return false
}

func reconcileReplayStart(state *ChainState, store *BlockStore, tipHeight uint64, changed bool) (uint64, bool, bool, error) {
	view := state.view()
	if !view.hasTip || view.height > tipHeight {
		state.replaceFrom(NewChainState())
		return 0, true, true, nil
	}
	canonicalHash, hasHeight, err := store.CanonicalHash(view.height)
	if err != nil {
		return 0, changed, false, err
	}
	if !hasHeight || canonicalHash != view.tipHash {
		state.replaceFrom(NewChainState())
		return 0, true, true, nil
	}
	if view.height == tipHeight {
		return 0, changed, false, nil
	}
	return view.height + 1, changed, true, nil
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
		blockBytes, prevTimestamps, err := replayBlockInputs(store, blockHash, height)
		if err != nil {
			return false, err
		}
		if _, err := state.ConnectBlockWithSuiteContext(
			blockBytes,
			cfg.ExpectedTarget,
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

func verifyReplayBlockHash(blockBytes []byte, blockHash [32]byte, height uint64) error {
	// Defense-in-depth: re-hash the loaded block's header before ConnectBlock.
	parsed, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return fmt.Errorf("parse block bytes during chainstate replay at height %d: %w", height, err)
	}
	observedHash, err := consensus.BlockHash(parsed.HeaderBytes)
	if err != nil {
		return fmt.Errorf("hash header during chainstate replay at height %d: %w", height, err)
	}
	if observedHash != blockHash {
		return fmt.Errorf(
			"canonical artifact corruption during chainstate replay at height %d: expected %x, on-disk header hashes to %x",
			height, blockHash, observedHash,
		)
	}
	return nil
}
