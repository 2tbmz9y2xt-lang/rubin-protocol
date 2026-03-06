package p2p

import (
	"bytes"
	"crypto/sha3"
	"sort"
)

func (s *Service) broadcastInventory(skip *peer, items []InventoryVector) error {
	peers := s.inventoryPeers(skip)
	if len(peers) == 0 || len(items) == 0 {
		return nil
	}
	blockItems, txItems := splitInventoryVectors(items)
	if len(blockItems) > 0 {
		if err := s.broadcastInventoryToPeers(peers, blockItems); err != nil {
			return err
		}
	}
	if len(txItems) == 0 {
		return nil
	}
	txPeers := selectTxRelayPeers(inventoryRelayKey(txItems), s.txRelaySalt(skip), peers, s.cfg.TxRelayFanout)
	return s.broadcastInventoryToPeers(txPeers, txItems)
}

func (s *Service) inventoryPeers(skip *peer) []*peer {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	peers := make([]*peer, 0, len(s.peers))
	for _, current := range s.peers {
		if skip != nil && current.addr() == skip.addr() {
			continue
		}
		peers = append(peers, current)
	}
	return peers
}

func splitInventoryVectors(items []InventoryVector) (blockItems []InventoryVector, txItems []InventoryVector) {
	for _, item := range items {
		switch item.Type {
		case MSG_BLOCK:
			blockItems = append(blockItems, item)
		case MSG_TX:
			txItems = append(txItems, item)
		}
	}
	return blockItems, txItems
}

func (s *Service) broadcastInventoryToPeers(peers []*peer, items []InventoryVector) error {
	if len(peers) == 0 || len(items) == 0 {
		return nil
	}
	payload, err := encodeInventoryVectors(items)
	if err != nil {
		return err
	}
	for _, current := range peers {
		if err := current.send(messageInv, payload); err != nil {
			current.setLastError(err.Error())
			_ = current.conn.Close()
		}
	}
	return nil
}

func selectTxRelayPeers(relayKey [32]byte, relaySalt string, peers []*peer, limit int) []*peer {
	if len(peers) == 0 {
		return nil
	}
	if limit <= 0 || limit >= len(peers) {
		return append([]*peer(nil), peers...)
	}
	scored := make([]scoredPeer, 0, len(peers))
	for _, current := range peers {
		addr := current.addr()
		scored = append(scored, scoredPeer{
			score: txRelayScore(relayKey, relaySalt, addr),
			addr:  addr,
			peer:  current,
		})
	}
	sort.Slice(scored, func(i, j int) bool {
		if cmp := bytes.Compare(scored[i].score[:], scored[j].score[:]); cmp != 0 {
			return cmp < 0
		}
		return scored[i].addr < scored[j].addr
	})
	selected := make([]*peer, 0, limit)
	for _, current := range scored[:limit] {
		selected = append(selected, current.peer)
	}
	return selected
}

func (s *Service) txRelaySalt(skip *peer) string {
	if skip != nil && skip.addr() != "" {
		return skip.addr()
	}
	if s == nil {
		return ""
	}
	return s.Addr()
}

func inventoryRelayKey(items []InventoryVector) [32]byte {
	if len(items) == 1 {
		return items[0].Hash
	}
	h := sha3.New256()
	for _, item := range items {
		_, _ = h.Write(item.Hash[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func txRelayScore(relayKey [32]byte, relaySalt string, addr string) [32]byte {
	h := sha3.New256()
	_, _ = h.Write(relayKey[:])
	_, _ = h.Write([]byte(relaySalt))
	_, _ = h.Write([]byte(addr))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type scoredPeer struct {
	score [32]byte
	addr  string
	peer  *peer
}
