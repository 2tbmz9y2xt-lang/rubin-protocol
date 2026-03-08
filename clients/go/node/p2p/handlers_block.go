package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
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
	pb, blockHash, err := parseRelayedBlock(blockBytes)
	if err != nil {
		p.bumpBan(10, err.Error())
		return err
	}
	if pb == nil {
		return errors.New("nil parsed block")
	}
	have, err := p.service.hasBlock(blockHash)
	if err != nil || have {
		return err
	}

	p.service.chainMu.Lock()
	summary, err := p.service.cfg.SyncEngine.ApplyBlockWithReorg(blockBytes, nil)
	p.service.chainMu.Unlock()
	if err != nil {
		p.bumpBan(100, err.Error())
		return err
	}
	p.acceptedRelayedBlock(blockHash, summary.BlockHeight)
	return p.service.requestBlocksIfBehind(p)
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

func (p *peer) acceptedRelayedBlock(blockHash [32]byte, height uint64) {
	p.service.cfg.SyncEngine.RecordBestKnownHeight(height)
	if p.service.blockSeen.Add(blockHash) {
		_ = p.service.broadcastInventory(p, []InventoryVector{{Type: MSG_BLOCK, Hash: blockHash}})
	}
}
