package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func (p *peer) handleGetBlocks(payload []byte) error {
	req, err := decodeGetBlocksPayload(payload)
	if err != nil {
		return err
	}
	items, err := p.blockInventoryAfterLocators(req)
	if err != nil || len(items) == 0 {
		return err
	}
	body, err := encodeInventoryVectors(items)
	if err != nil {
		return err
	}
	return p.send(messageInv, body)
}

func (p *peer) blockInventoryAfterLocators(req GetBlocksPayload) ([]InventoryVector, error) {
	p.service.chainMu.Lock()
	hashes, err := p.service.cfg.BlockStore.HashesAfterLocators(
		req.LocatorHashes,
		req.StopHash,
		p.service.cfg.GetBlocksBatchSize,
	)
	p.service.chainMu.Unlock()
	if err != nil {
		return nil, err
	}
	items := make([]InventoryVector, 0, len(hashes))
	for _, hash := range hashes {
		items = append(items, InventoryVector{Type: MSG_BLOCK, Hash: hash})
	}
	return items, nil
}

func (p *peer) handleBlock(blockBytes []byte) error {
	summary, err := p.processRelayedBlock(blockBytes)
	if err != nil {
		return err
	}
	if summary == nil {
		return nil
	}
	return p.service.requestBlocksIfBehind(p)
}

func (p *peer) processRelayedBlock(blockBytes []byte) (*node.ChainStateConnectSummary, error) {
	pb, blockHash, err := parseRelayedBlock(blockBytes)
	if err != nil {
		p.bumpBan(10, err.Error())
		return nil, err
	}
	if pb == nil {
		return nil, errors.New("nil parsed block")
	}
	have, err := p.service.hasBlock(blockHash)
	if err != nil || have {
		return nil, err
	}

	p.service.chainMu.Lock()
	summary, err := p.service.cfg.SyncEngine.ApplyBlockWithReorg(blockBytes, nil)
	p.service.chainMu.Unlock()
	if err != nil {
		if errors.Is(err, node.ErrParentNotFound) {
			if err := consensus.PowCheck(pb.HeaderBytes, pb.Header.Target); err != nil {
				p.bumpBan(100, err.Error())
				return nil, err
			}
			p.service.retainOrResolveOrphan(p, blockHash, pb.Header.PrevBlockHash, blockBytes)
			return nil, nil
		}
		p.bumpBan(100, err.Error())
		return nil, err
	}
	p.acceptedRelayedBlock(blockHash, summary)
	return summary, nil
}

func parseRelayedBlock(blockBytes []byte) (*consensus.ParsedBlock, [32]byte, error) {
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, [32]byte{}, err
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return pb, blockHash, nil
}

func (p *peer) acceptedRelayedBlock(blockHash [32]byte, summary *node.ChainStateConnectSummary) {
	p.service.cfg.SyncEngine.RecordBestKnownHeight(summary.BlockHeight)
	p.service.blockSeen.Add(blockHash)
	_ = p.service.broadcastInventory(p, []InventoryVector{{Type: MSG_BLOCK, Hash: blockHash}})
	p.service.resolveOrphans(p, blockHash)
}

func (s *Service) retainOrResolveOrphan(skip *peer, blockHash, parentHash [32]byte, blockBytes []byte) {
	if !s.orphans.Add(blockHash, parentHash, blockBytes) {
		return
	}
	s.blockSeen.Add(blockHash)
	parentPresent, err := s.hasBlock(parentHash)
	if err != nil || !parentPresent {
		return
	}
	s.resolveOrphans(skip, parentHash)
}

func (s *Service) resolveOrphans(skip *peer, blockHash [32]byte) {
	children := s.orphans.TakeChildren(blockHash)
	for _, child := range children {
		pb, childHash, err := parseRelayedBlock(child.blockBytes)
		if err != nil {
			continue
		}
		s.chainMu.Lock()
		summary, applyErr := s.cfg.SyncEngine.ApplyBlockWithReorg(child.blockBytes, nil)
		s.chainMu.Unlock()
		if applyErr != nil {
			if errors.Is(applyErr, node.ErrParentNotFound) {
				s.retainOrResolveOrphan(skip, childHash, pb.Header.PrevBlockHash, child.blockBytes)
			}
			continue
		}
		s.cfg.SyncEngine.RecordBestKnownHeight(summary.BlockHeight)
		s.blockSeen.Add(childHash)
		_ = s.broadcastInventory(skip, []InventoryVector{{Type: MSG_BLOCK, Hash: childHash}})
		s.resolveOrphans(skip, childHash)
	}
}
