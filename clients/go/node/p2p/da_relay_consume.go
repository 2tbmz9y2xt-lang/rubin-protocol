package p2p

import (
	"errors"
	"fmt"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// consumeCanonicalAppliedDASets consumes the complete DA sets carried by every
// block the SyncEngine reported as canonical-applied through
// ChainStateConnectSummary.CanonicalAppliedBlocks: a direct apply reports the
// single connected block, a reorg reports every newly-canonical branch block in
// canonical order, and a stored-but-not-switched side branch reports none (nil
// slice) so nothing is consumed. DA consume is therefore driven strictly by
// canonical application, never by mere block storage. It no-ops when DA relay is
// disabled (nil relay), mirroring advanceDAOrphanTTL. It is best-effort across
// blocks — each block is attempted and the first error is returned — so one
// block's accounting failure cannot silently skip DA cleanup for the remaining
// canonical blocks of a reorg.
//
// It consumes the IDs the apply path already extracted; the summary carries no
// block bytes and nothing here re-parses a block.
func (s *Service) consumeCanonicalAppliedDASets(blocks []node.CanonicalAppliedBlock) error {
	if s == nil || s.daRelay == nil {
		return nil
	}
	var firstErr error
	for i := range blocks {
		if err := s.consumeCompleteDASetIDs(blocks[i].CompleteDAIDs); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("consume canonical-applied DA sets for block %x: %w", blocks[i].Hash, err)
		}
	}
	return firstErr
}

// ConsumeAcceptedBlockDASets consumes the complete DA sets carried by a block
// supplied as raw bytes. It is the entry point for callers that hold bytes and
// no canonical-apply summary — today the RPC accepted-block hook wired in
// cmd/rubin-node. It parses, then delegates to the same
// node.CompleteDASetIDsFromParsedBlock core the canonical-apply path uses, so
// the two entry points cannot select different DA sets for the same block.
//
// It takes one Service call lease before parsing or DA mutation: once Close
// has published the non-OPEN state the call returns exactly "service already
// closed" with no parse, no DA-state mutation and no send, and a call that
// won the lease first keeps running while Close waits for it.
func (s *Service) ConsumeAcceptedBlockDASets(blockBytes []byte) error {
	if s == nil {
		return errors.New("nil service")
	}
	if !s.acquireWork() {
		return errServiceClosed
	}
	defer s.releaseWork()
	if s.daRelay == nil {
		return errors.New("nil DA relay")
	}
	parsed, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return err
	}
	daIDs, err := node.CompleteDASetIDsFromParsedBlock(parsed)
	if err != nil {
		return err
	}
	return s.consumeCompleteDASetIDs(daIDs)
}

// consumeCompleteDASetIDs releases relay accounting for each ID in order. An
// item-local failure leaves that ID unchanged, while later IDs are still
// attempted; the earliest failure is returned after all attempts. Callers
// guarantee a non-nil relay.
func (s *Service) consumeCompleteDASetIDs(daIDs [][32]byte) error {
	var firstErr error
	for _, daID := range daIDs {
		if _, err := s.daRelay.ConsumeCompleteSet(daID); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("consume DA set %x: %w", daID, err)
		}
	}
	return firstErr
}
