package node

import (
	"errors"
)

// validateNewMinerInputs validates the inputs to NewMiner
func validateNewMinerInputs(chainState *ChainState, blockStore *BlockStore, sync *SyncEngine) error {
	if chainState == nil {
		return errors.New("nil chainstate")
	}
	if blockStore == nil {
		return errors.New("nil blockstore")
	}
	if sync == nil {
		return errors.New("nil sync engine")
	}
	return nil
}

// validateMinerAliasRequirements validates that miner components are correctly aliased to sync engine
func validateMinerAliasRequirements(chainState *ChainState, blockStore *BlockStore, sync *SyncEngine) error {
	// Miner.MineOne calls SyncEngine.BootstrapCanonicalGenesisIfEmpty which
	// mutates sync.chainState and persists the canonical genesis through
	// sync.blockStore, then m.buildBlock reads timestamp context from
	// m.blockStore and the chainstate snapshot from m.chainState. Both
	// pointers MUST alias the SyncEngine's instances; otherwise the
	// bootstrap mutation lands in one pair while the miner reads from
	// another, and the first devnet mine on an empty chain deterministically
	// fails with "missing canonical hash at height 0 for timestamp context"
	// (because blockstore is split) or with "genesis_hash mismatch" (because
	// chainstate is split and the synthetic block hits the height-0 guard).
	// Reject both split shapes at NewMiner time so misuse cannot reach
	// runtime.
	if chainState != sync.chainState {
		return errors.New("miner chainstate must alias sync engine chainstate")
	}
	if blockStore != sync.blockStore {
		return errors.New("miner blockstore must alias sync engine blockstore")
	}
	return nil
}

// normalizeMinerConfig normalizes the miner configuration
func normalizeMinerConfig(cfg *MinerConfig) error {
	if cfg.TimestampSource == nil {
		cfg.TimestampSource = func() uint64 { return unixNowU64() }
	}
	if cfg.MaxTxPerBlock <= 0 {
		cfg.MaxTxPerBlock = 1024
	}
	mineAddress, err := normalizeMineAddress(cfg.MineAddress)
	if err != nil {
		return err
	}
	cfg.MineAddress = mineAddress
	return nil
}
