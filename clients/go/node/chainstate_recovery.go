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
		view := state.view()
		if truncated || view.hasTip || view.utxoCount != 0 || view.alreadyGenerated != 0 || view.height != 0 || view.tipHash != ([32]byte{}) {
			state.replaceFrom(NewChainState())
			return true, nil
		}
		return false, nil
	}

	replayFrom := uint64(0)
	changed := truncated
	view := state.view()
	if view.hasTip {
		if view.height <= tipHeight {
			canonicalHash, hasHeight, err := store.CanonicalHash(view.height)
			if err != nil {
				return false, err
			}
			if hasHeight && canonicalHash == view.tipHash {
				if view.height == tipHeight {
					return changed, nil
				}
				replayFrom = view.height + 1
			} else {
				state.replaceFrom(NewChainState())
				changed = true
			}
		} else {
			state.replaceFrom(NewChainState())
			changed = true
		}
	} else {
		state.replaceFrom(NewChainState())
		changed = true
	}

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
		blockBytes, err := store.GetBlockByHash(blockHash)
		if err != nil {
			return false, err
		}
		// Defense-in-depth: re-hash the loaded block's header and
		// confirm it matches the canonical-index entry BEFORE
		// delegating to ConnectBlockWithCoreExtProfilesAndSuiteContext.
		// A parseable-but-swapped <hash>.bin (bit-rot, manual disk
		// repair gone wrong, adversarial replacement that happens to
		// link to the current tip's prev_hash) would otherwise be
		// accepted by ConnectBlock, leaving ChainState with a tip
		// that no longer corresponds to its canonical-index entry.
		// The prev_hash chain-integrity check inside ConnectBlock
		// catches some of this class but NOT the same-prev-hash
		// adversarial case. One hash per replay block is recovery-
		// path-only cost (N rows, not steady state). Cross-client
		// symmetric: Rust `clients/rust/crates/rubin-node/src/chainstate_recovery.rs`
		// reconcile_chain_state_with_block_store performs the
		// bit-identical check with the same error literal.
		parsed, err := consensus.ParseBlockBytes(blockBytes)
		if err != nil {
			return false, fmt.Errorf("parse block bytes during chainstate replay at height %d: %w", height, err)
		}
		observedHash, err := consensus.BlockHash(parsed.HeaderBytes)
		if err != nil {
			return false, fmt.Errorf("hash header during chainstate replay at height %d: %w", height, err)
		}
		if observedHash != blockHash {
			return false, fmt.Errorf(
				"canonical artifact corruption during chainstate replay at height %d: expected %x, on-disk header hashes to %x",
				height, blockHash, observedHash,
			)
		}
		prevTimestamps, err := prevTimestampsFromStore(store, height)
		if err != nil {
			return false, err
		}
		if _, err := state.ConnectBlockWithCoreExtProfilesAndSuiteContext(
			blockBytes,
			cfg.ExpectedTarget,
			prevTimestamps,
			cfg.ChainID,
			cfg.CoreExtProfiles,
			cfg.RotationProvider,
			cfg.SuiteRegistry,
		); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}
