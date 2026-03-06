package p2p

func (p *peer) handleInv(payload []byte) error {
	items, err := decodeInventoryVectors(payload)
	if err != nil {
		return err
	}
	requests, err := p.missingInventory(items)
	if err != nil || len(requests) == 0 {
		return err
	}
	body, err := encodeInventoryVectors(requests)
	if err != nil {
		return err
	}
	return p.send(messageGetData, body)
}

func (p *peer) missingInventory(items []InventoryVector) ([]InventoryVector, error) {
	requests := make([]InventoryVector, 0, len(items))
	for _, item := range items {
		missing, err := p.needsInventory(item)
		if err != nil {
			return nil, err
		}
		if missing {
			requests = append(requests, item)
		}
	}
	return requests, nil
}

func (p *peer) needsInventory(item InventoryVector) (bool, error) {
	switch item.Type {
	case MSG_BLOCK:
		if p.service.blockSeen.Has(item.Hash) {
			return false, nil
		}
		have, err := p.service.hasBlock(item.Hash)
		if err != nil || have {
			return false, err
		}
		return true, nil
	case MSG_TX:
		return !p.service.txSeen.Has(item.Hash) && !p.service.cfg.TxPool.Has(item.Hash), nil
	default:
		return false, nil
	}
}

func (p *peer) handleGetData(payload []byte) error {
	items, err := decodeInventoryVectors(payload)
	if err != nil {
		return err
	}
	for _, item := range items {
		if err := p.respondToInventory(item); err != nil {
			return err
		}
	}
	return nil
}

func (p *peer) respondToInventory(item InventoryVector) error {
	switch item.Type {
	case MSG_BLOCK:
		blockBytes, ok, err := p.blockBytes(item.Hash)
		if err != nil || !ok {
			return err
		}
		return p.send(messageBlock, blockBytes)
	case MSG_TX:
		txBytes, ok := p.service.cfg.TxPool.Get(item.Hash)
		if !ok {
			return nil
		}
		return p.send(messageTx, txBytes)
	default:
		return nil
	}
}

func (p *peer) blockBytes(blockHash [32]byte) ([]byte, bool, error) {
	p.service.chainMu.Lock()
	defer p.service.chainMu.Unlock()
	blockBytes, err := p.service.cfg.BlockStore.GetBlockByHash(blockHash)
	if err != nil {
		return nil, false, nil
	}
	return blockBytes, true, nil
}
