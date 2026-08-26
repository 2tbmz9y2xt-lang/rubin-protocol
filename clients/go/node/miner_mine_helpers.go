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

// executeMineOne observes ctx at the pre-apply checkpoint (after buildBlock,
// before the canonical apply): cancellation there returns ctx.Err() with no
// write; a clean check hands the result to the apply, never re-checked.
//
// The canonical genesis bootstrap ran earlier, in MineOneWithOutcome: it is
// idempotent — a no-op once the chain has a tip and a no-op for ChainIDs with no
// published canonical genesis (the all-zero ChainID some unit tests use) — and it
// must precede any post-genesis candidate, because the height-0 genesis-identity
// guard rejects a miner-synthesized height-0 block under a devnet ChainID.
func (m *Miner) executeMineOne(ctx context.Context, txs [][]byte) (MineOneOutcome, error) {
	blockBytes, prevTimestamps, timestamp, nonce, txCount, err := m.buildBlock(ctx, txs)
	if err != nil {
		return unprocessableMineOneOutcome(), err
	}
	// Pre-apply cancellation checkpoint (RUBIN_NODE_RPC_DEVNET.md 3.4): the
	// last defined observation before canonical-apply entry. buildBlock above
	// persists no canonical state, so returning here leaves the chain
	// unchanged; a clean check hands the result to the apply, which is never
	// re-checked or rolled back afterwards.
	if err := mineOneContextErr(ctx); err != nil {
		return unprocessableMineOneOutcome(), err
	}
	summary, projection, err := m.sync.applyBlockWithProjection(blockBytes, prevTimestamps)
	state, disposition := canonicalMineOneOutcome(projection, err)
	outcome := MineOneOutcome{CommitState: state, Disposition: disposition}
	// The summary is nonnil for exactly the two published truths — ordinary NEW
	// and terminal NEW — so the identity travels with the terminal error rather
	// than being dropped by it.
	if summary != nil {
		outcome.Block = &MinedBlock{
			Height:    summary.BlockHeight,
			Hash:      summary.BlockHash,
			Timestamp: timestamp,
			Nonce:     nonce,
			TxCount:   txCount,
		}
	}
	return outcome, err
}
