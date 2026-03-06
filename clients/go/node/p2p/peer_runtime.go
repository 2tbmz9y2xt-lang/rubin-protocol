package p2p

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func (p *peer) run(ctx context.Context) error {
	for {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
		}
		if deadline := p.service.cfg.PeerRuntimeConfig.ReadDeadline; deadline > 0 {
			if err := p.conn.SetReadDeadline(time.Now().Add(deadline)); err != nil {
				return err
			}
		}
		frame, err := readFrame(p.conn, p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
		if err != nil {
			if shouldIgnoreReadError(err) {
				continue
			}
			return normalizeReadError(err)
		}
		if err := p.handleMessage(frame); err != nil {
			return err
		}
	}
}

func shouldIgnoreReadError(err error) bool {
	var netErr net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

func normalizeReadError(err error) error {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
		return nil
	default:
		return err
	}
}

func (p *peer) handleMessage(frame message) error {
	switch frame.Kind {
	case messageInv:
		return p.handleInv(frame.Payload)
	case messageGetData:
		return p.handleGetData(frame.Payload)
	case messageBlock:
		return p.handleBlock(frame.Payload)
	case messageTx:
		return p.handleTx(frame.Payload)
	case messageGetBlk:
		return p.handleGetBlocks(frame.Payload)
	case messageVersion:
		return errors.New("invalid version message after handshake")
	default:
		return fmt.Errorf("unknown message type: %d", frame.Kind)
	}
}

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
		p.bumpBan(100, err.Error())
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
	summary, err := p.service.cfg.SyncEngine.ApplyBlock(blockBytes, nil)
	p.service.chainMu.Unlock()
	if err != nil {
		p.bumpBan(100, err.Error())
		return err
	}
	p.service.cfg.SyncEngine.RecordBestKnownHeight(summary.BlockHeight)
	if p.service.blockSeen.Add(blockHash) {
		_ = p.service.broadcastInventory(p, []InventoryVector{{Type: MSG_BLOCK, Hash: blockHash}})
	}
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

func (p *peer) handleTx(txBytes []byte) error {
	txid, err := canonicalTxID(txBytes)
	if err != nil {
		if p.bumpBan(10, err.Error()) {
			return err
		}
		return nil
	}
	if !p.service.cfg.TxPool.Put(txid, txBytes) {
		return nil
	}
	if p.service.txSeen.Add(txid) {
		_ = p.service.broadcastInventory(p, []InventoryVector{{Type: MSG_TX, Hash: txid}})
	}
	return nil
}

func canonicalTxID(txBytes []byte) ([32]byte, error) {
	_, txid, _, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		return [32]byte{}, err
	}
	if consumed != len(txBytes) {
		return [32]byte{}, errors.New("non-canonical tx bytes")
	}
	return txid, nil
}

func (p *peer) send(kind byte, payload []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if deadline := p.service.cfg.PeerRuntimeConfig.WriteDeadline; deadline > 0 {
		if err := p.conn.SetWriteDeadline(time.Now().Add(deadline)); err != nil {
			return err
		}
	}
	return writeFrame(p.conn, message{Kind: kind, Payload: payload}, p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
}

func (p *peer) addr() string {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.state.Addr
}

func (p *peer) snapshotState() node.PeerState {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.state
}

func (p *peer) setLastError(reason string) {
	p.stateMu.Lock()
	p.state.LastError = reason
	state := p.state
	p.stateMu.Unlock()
	_ = p.service.cfg.PeerManager.UpsertPeer(&state)
}

func (p *peer) bumpBan(delta int, reason string) bool {
	p.stateMu.Lock()
	p.state.BanScore += delta
	p.state.LastError = reason
	state := p.state
	p.stateMu.Unlock()
	_ = p.service.cfg.PeerManager.UpsertPeer(&state)
	return state.BanScore >= p.service.cfg.PeerRuntimeConfig.BanThreshold
}
