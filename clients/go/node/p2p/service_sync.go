package p2p

import (
	"errors"
	"os"
)

func (s *Service) requestBlocksIfBehind(p *peer) error {
	localHeight, hasTip, err := s.tipHeight()
	if err != nil {
		return err
	}
	remoteBest := p.snapshotState().RemoteVersion.BestHeight
	if hasTip && localHeight >= remoteBest {
		return nil
	}
	payload, err := s.getBlocksRequestPayload()
	if err != nil {
		return err
	}
	return p.send(messageGetBlk, payload)
}

func (s *Service) getBlocksRequestPayload() ([]byte, error) {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	locators, err := s.cfg.BlockStore.LocatorHashes(s.cfg.LocatorLimit)
	if err != nil {
		return nil, err
	}
	return encodeGetBlocksPayload(GetBlocksPayload{
		LocatorHashes: locators,
	})
}

func (s *Service) tipHeight() (uint64, bool, error) {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	height, _, ok, err := s.cfg.BlockStore.Tip()
	return height, ok, err
}

func (s *Service) hasBlock(blockHash [32]byte) (bool, error) {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	_, err := s.cfg.BlockStore.GetHeaderByHash(blockHash)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (s *Service) broadcastInventory(skip *peer, items []InventoryVector) error {
	payload, err := encodeInventoryVectors(items)
	if err != nil {
		return err
	}
	s.peersMu.RLock()
	peers := make([]*peer, 0, len(s.peers))
	for _, current := range s.peers {
		if skip != nil && current.addr() == skip.addr() {
			continue
		}
		peers = append(peers, current)
	}
	s.peersMu.RUnlock()
	for _, current := range peers {
		if err := current.send(messageInv, payload); err != nil {
			current.setLastError(err.Error())
			_ = current.conn.Close()
		}
	}
	return nil
}
