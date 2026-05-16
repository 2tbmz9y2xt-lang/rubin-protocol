package node

import (
	"context"
	"errors"
)

// validateMineOneInput validates the miner state for MineOne
func (m *Miner) validateMineOneInput() error {
	if m == nil || m.chainState == nil || m.blockStore == nil || m.sync == nil {
		return errors.New("miner is not initialized")
	}
	return nil
}

// bootstrapGenesisIfNeeded bootstraps the canonical genesis if needed
func (m *Miner) bootstrapGenesisIfNeeded() error {
	// Ensure the chain is bootstrapped at the canonical published genesis
	// before the miner builds any post-genesis block. The height-0 genesis-
	// identity guard in sync.go rejects miner-synthesized height-0 blocks
	// under a devnet ChainID (their hashes differ from the published
	// genesis), so empty-chain mining must start from the published bytes.
	// BootstrapCanonicalGenesisIfEmpty is idempotent: a no-op once the
	// chain has a tip and a no-op for ChainIDs without a published canonical
	// genesis (e.g. the all-zero ChainID used by some unit tests).
	return m.sync.BootstrapCanonicalGenesisIfEmpty()
}

// executeMineOne executes the core mining logic
func (m *Miner) executeMineOne(ctx context.Context, txs [][]byte) (*MinedBlock, error) {
	blockBytes, prevTimestamps, timestamp, nonce, txCount, err := m.buildBlock(ctx, txs)
	if err != nil {
		return nil, err
	}
	summary, err := m.sync.ApplyBlock(blockBytes, prevTimestamps)
	if err != nil {
		return nil, err
	}
	return &MinedBlock{
		Height:    summary.BlockHeight,
		Hash:      summary.BlockHash,
		Timestamp: timestamp,
		Nonce:     nonce,
		TxCount:   txCount,
	}, nil
}
