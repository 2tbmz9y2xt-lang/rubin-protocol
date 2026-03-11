package node

import (
	"errors"
	"os"
)

const (
	chainStateSnapshotIntervalBlocks  = uint64(32)
	chainStateSnapshotSmallUtxoCutoff = 4096
)

func shouldPersistChainStateSnapshot(state *ChainState, summary *ChainStateConnectSummary) bool {
	if state == nil || summary == nil {
		return true
	}
	if !state.HasTip || summary.BlockHeight == 0 {
		return true
	}
	if len(state.Utxos) <= chainStateSnapshotSmallUtxoCutoff {
		return true
	}
	return summary.BlockHeight%chainStateSnapshotIntervalBlocks == 0
}

func cloneChainState(src *ChainState) *ChainState {
	if src == nil {
		return nil
	}
	return &ChainState{
		Utxos:            copyUtxoSet(src.Utxos),
		Height:           src.Height,
		AlreadyGenerated: src.AlreadyGenerated,
		TipHash:          src.TipHash,
		HasTip:           src.HasTip,
	}
}

func truncateIncompleteCanonicalSuffix(store *BlockStore) (bool, error) {
	if store == nil {
		return false, errors.New("nil blockstore")
	}
	canonical, err := store.CanonicalIndexSnapshot()
	if err != nil {
		return false, err
	}
	validCount := uint64(0)
	for i, hashHex := range canonical {
		blockHash, err := parseHex32("canonical hash", hashHex)
		if err != nil {
			return false, err
		}
		if _, err := store.GetHeaderByHash(blockHash); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return false, err
			}
			break
		}
		if _, err := store.GetBlockByHash(blockHash); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return false, err
			}
			break
		}
		if _, err := store.GetUndo(blockHash); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return false, err
			}
			break
		}
		validCount = uint64(i + 1)
	}
	if validCount == uint64(len(canonical)) {
		return false, nil
	}
	if err := store.TruncateCanonical(validCount); err != nil {
		return false, err
	}
	return true, nil
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
		if truncated || state.HasTip || len(state.Utxos) != 0 || state.AlreadyGenerated != 0 || state.Height != 0 || state.TipHash != ([32]byte{}) {
			*state = *NewChainState()
			return true, nil
		}
		return false, nil
	}

	replayFrom := uint64(0)
	changed := truncated
	if state.HasTip {
		if state.Height <= tipHeight {
			canonicalHash, hasHeight, err := store.CanonicalHash(state.Height)
			if err != nil {
				return false, err
			}
			if hasHeight && canonicalHash == state.TipHash {
				if state.Height == tipHeight {
					return false, nil
				}
				replayFrom = state.Height + 1
			} else {
				*state = *NewChainState()
				changed = true
			}
		} else {
			*state = *NewChainState()
			changed = true
		}
	} else {
		*state = *NewChainState()
		changed = true
	}

	for height := replayFrom; height <= tipHeight; height++ {
		blockHash, ok, err := store.CanonicalHash(height)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, errors.New("missing canonical block hash during chainstate replay")
		}
		blockBytes, err := store.GetBlockByHash(blockHash)
		if err != nil {
			return false, err
		}
		prevTimestamps, err := prevTimestampsFromStore(store, height)
		if err != nil {
			return false, err
		}
		if _, err := state.ConnectBlockWithCoreExtProfiles(
			blockBytes,
			cfg.ExpectedTarget,
			prevTimestamps,
			cfg.ChainID,
			cfg.CoreExtProfiles,
		); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}
