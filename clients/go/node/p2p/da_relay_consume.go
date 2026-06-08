package p2p

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

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
func (s *Service) consumeCanonicalAppliedDASets(blocks []node.CanonicalAppliedBlock) error {
	if s == nil || s.daRelay == nil {
		return nil
	}
	var firstErr error
	for i := range blocks {
		if err := s.ConsumeAcceptedBlockDASets(blocks[i].BlockBytes); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("consume canonical-applied DA sets for block %x: %w", blocks[i].Hash, err)
		}
	}
	return firstErr
}

func (s *Service) ConsumeAcceptedBlockDASets(blockBytes []byte) error {
	if s == nil {
		return errors.New("nil service")
	}
	if s.daRelay == nil {
		return errors.New("nil DA relay")
	}
	daIDs, err := extractAcceptedBlockDAIDs(blockBytes)
	if err != nil {
		return err
	}
	for _, daID := range daIDs {
		if _, err := s.daRelay.consumeCompleteSet(daID); err != nil {
			return err
		}
	}
	return nil
}

func extractAcceptedBlockDAIDs(blockBytes []byte) ([][32]byte, error) {
	parsed, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}

	sets := make(map[[32]byte]acceptedBlockDASet)
	for _, tx := range parsed.Txs {
		recordAcceptedBlockDATx(sets, tx)
	}
	ids := make([][32]byte, 0, len(sets))
	for daID, set := range sets {
		if !set.complete() {
			continue
		}
		ids = append(ids, daID)
	}
	sort.Slice(ids, func(i, j int) bool {
		return bytes.Compare(ids[i][:], ids[j][:]) < 0
	})
	return ids, nil
}

func recordAcceptedBlockDATx(sets map[[32]byte]acceptedBlockDASet, tx *consensus.Tx) {
	switch tx.TxKind {
	case 0x01:
		daID := tx.DaCommitCore.DaID
		set := sets[daID]
		set.commitCount++
		set.chunkCount = tx.DaCommitCore.ChunkCount
		sets[daID] = set
	case 0x02:
		daID := tx.DaChunkCore.DaID
		set := sets[daID]
		if set.chunks == nil {
			set.chunks = make(map[uint16]struct{})
		}
		set.chunks[tx.DaChunkCore.ChunkIndex] = struct{}{}
		sets[daID] = set
	}
}

type acceptedBlockDASet struct {
	commitCount int
	chunkCount  uint16
	chunks      map[uint16]struct{}
}

func (s acceptedBlockDASet) complete() bool {
	if s.commitCount != 1 || s.chunkCount == 0 || uint64(s.chunkCount) > consensus.MAX_DA_CHUNK_COUNT {
		return false
	}
	if len(s.chunks) != int(s.chunkCount) {
		return false
	}
	for i := uint16(0); i < s.chunkCount; i++ {
		if _, ok := s.chunks[i]; !ok {
			return false
		}
	}
	return true
}
