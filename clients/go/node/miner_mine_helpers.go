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

// executeMineOne observes ctx at the pre-apply checkpoint (after buildBlock,
// before ApplyBlock): cancellation there returns ctx.Err() with no write; a
// clean check hands the result to ApplyBlock, never re-checked.
func (m *Miner) executeMineOne(ctx context.Context, txs [][]byte) (*MinedBlock, error) {
	blockBytes, prevTimestamps, timestamp, nonce, txCount, err := m.buildBlock(ctx, txs)
	if err != nil {
		return nil, err
	}
	// Pre-apply cancellation checkpoint (RUBIN_NODE_RPC_DEVNET.md 3.4): the
	// last defined observation before canonical-apply entry. buildBlock above
	// persists no canonical state, so returning here leaves the chain
	// unchanged; a clean check hands the result to ApplyBlock, which is never
	// re-checked or rolled back afterwards. Same form as the MineOne entry
	// check so both checkpoints report the caller's own cancellation
	// error (ctx.Err()).
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
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
