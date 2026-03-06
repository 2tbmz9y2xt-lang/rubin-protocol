package p2p

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

const (
	defaultGetBlocksBatchLimit uint64 = 128
	defaultLocatorLimit               = 32
)

type ServiceConfig struct {
	BindAddr           string
	BootstrapPeers     []string
	UserAgent          string
	GenesisHash        [32]byte
	LocatorLimit       int
	GetBlocksBatchSize uint64
	PeerRuntimeConfig  node.PeerRuntimeConfig
	PeerManager        *node.PeerManager
	SyncConfig         node.SyncConfig
	SyncEngine         *node.SyncEngine
	BlockStore         *node.BlockStore
	TxPool             TxPool
	Now                func() time.Time
}

type Service struct {
	cfg      ServiceConfig
	ctx      context.Context
	cancel   context.CancelFunc
	listener net.Listener

	peersMu sync.RWMutex
	peers   map[string]*peer

	chainMu   sync.Mutex
	blockSeen *hashSet
	txSeen    *hashSet
}

type peer struct {
	conn    net.Conn
	service *Service

	stateMu sync.Mutex
	state   node.PeerState

	writeMu sync.Mutex
}

func NewService(cfg ServiceConfig) (*Service, error) {
	if strings.TrimSpace(cfg.BindAddr) == "" {
		return nil, errors.New("bind address is required")
	}
	if cfg.PeerManager == nil {
		return nil, errors.New("nil peer manager")
	}
	if cfg.SyncEngine == nil {
		return nil, errors.New("nil sync engine")
	}
	if cfg.BlockStore == nil {
		return nil, errors.New("nil blockstore")
	}
	if cfg.TxPool == nil {
		cfg.TxPool = NewMemoryTxPool()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if strings.TrimSpace(cfg.UserAgent) == "" {
		cfg.UserAgent = "rubin-go/p2p"
	}
	var zero [32]byte
	if cfg.GenesisHash == zero {
		cfg.GenesisHash = node.DevnetGenesisBlockHash()
	}
	if cfg.LocatorLimit <= 0 {
		cfg.LocatorLimit = defaultLocatorLimit
	}
	if cfg.GetBlocksBatchSize == 0 {
		if cfg.SyncConfig.HeaderBatchLimit > 0 {
			cfg.GetBlocksBatchSize = cfg.SyncConfig.HeaderBatchLimit
		} else {
			cfg.GetBlocksBatchSize = defaultGetBlocksBatchLimit
		}
	}
	cfg.PeerRuntimeConfig = mergePeerRuntimeConfig(cfg.PeerRuntimeConfig)
	if cfg.PeerRuntimeConfig.Network == "" {
		cfg.PeerRuntimeConfig.Network = cfg.SyncConfig.Network
	}
	return &Service{
		cfg:       cfg,
		peers:     make(map[string]*peer),
		blockSeen: newHashSet(),
		txSeen:    newHashSet(),
	}, nil
}

func (s *Service) Start(ctx context.Context) error {
	if s == nil {
		return errors.New("nil service")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if s.listener != nil {
		return errors.New("service already started")
	}
	listener, err := net.Listen("tcp", s.cfg.BindAddr)
	if err != nil {
		return err
	}
	s.listener = listener
	s.ctx, s.cancel = context.WithCancel(ctx)

	go s.acceptLoop()
	for _, peerAddr := range s.cfg.BootstrapPeers {
		peerAddr = strings.TrimSpace(peerAddr)
		if peerAddr == "" {
			continue
		}
		go s.dialPeer(peerAddr)
	}
	return nil
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.peersMu.RLock()
	peers := make([]*peer, 0, len(s.peers))
	for _, current := range s.peers {
		peers = append(peers, current)
	}
	s.peersMu.RUnlock()
	for _, current := range peers {
		_ = current.conn.Close()
	}
	return nil
}

func (s *Service) Addr() string {
	if s == nil {
		return ""
	}
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.cfg.BindAddr
}

func (s *Service) AnnounceBlock(blockBytes []byte) error {
	if s == nil {
		return errors.New("nil service")
	}
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return err
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		return err
	}
	if !s.blockSeen.Add(blockHash) {
		return nil
	}
	return s.broadcastInventory(nil, []InventoryVector{{Type: MSG_BLOCK, Hash: blockHash}})
}

func (s *Service) AnnounceTx(txBytes []byte) error {
	if s == nil {
		return errors.New("nil service")
	}
	_, txid, _, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		return err
	}
	if consumed != len(txBytes) {
		return errors.New("non-canonical tx bytes")
	}
	s.cfg.TxPool.Put(txid, txBytes)
	if !s.txSeen.Add(txid) {
		return nil
	}
	return s.broadcastInventory(nil, []InventoryVector{{Type: MSG_TX, Hash: txid}})
}

func (s *Service) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.ctx != nil && s.ctx.Err() != nil {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Service) dialPeer(addr string) {
	dialer := &net.Dialer{Timeout: s.cfg.PeerRuntimeConfig.HandshakeTimeout}
	conn, err := dialer.DialContext(s.ctx, "tcp", addr)
	if err != nil {
		return
	}
	s.handleConn(conn)
}

func (s *Service) handleConn(conn net.Conn) {
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	localVersion, err := s.localVersion()
	if err != nil {
		return
	}
	state, err := performHandshake(
		s.ctx,
		conn,
		s.cfg.PeerRuntimeConfig,
		localVersion,
		s.cfg.SyncConfig.ChainID,
		s.cfg.GenesisHash,
	)
	if err != nil {
		return
	}

	current := &peer{
		conn:    conn,
		service: s,
		state:   state,
	}
	if err := s.registerPeer(current); err != nil {
		return
	}
	defer s.unregisterPeer(current.addr())

	s.cfg.SyncEngine.RecordBestKnownHeight(state.RemoteVersion.BestHeight)
	if err := s.requestBlocksIfBehind(current); err != nil {
		current.setLastError(err.Error())
		return
	}
	if err := current.run(s.ctx); err != nil && s.ctx.Err() == nil {
		current.setLastError(err.Error())
		return
	}
}

func (s *Service) registerPeer(p *peer) error {
	if err := s.cfg.PeerManager.AddPeer(&p.state); err != nil {
		return err
	}
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	s.peers[p.addr()] = p
	return nil
}

func (s *Service) unregisterPeer(addr string) {
	s.peersMu.Lock()
	delete(s.peers, addr)
	s.peersMu.Unlock()
	s.cfg.PeerManager.RemovePeer(addr)
}

func (s *Service) localVersion() (node.VersionPayloadV1, error) {
	bestHeight, _, ok, err := s.cfg.BlockStore.Tip()
	if err != nil {
		return node.VersionPayloadV1{}, err
	}
	if !ok {
		bestHeight = 0
	}
	return node.VersionPayloadV1{
		Magic:           ProtocolMagic,
		ProtocolVersion: ProtocolVersion,
		ChainID:         s.cfg.SyncConfig.ChainID,
		GenesisHash:     s.cfg.GenesisHash,
		UserAgent:       s.cfg.UserAgent,
		BestHeight:      bestHeight,
	}, nil
}

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
			var netErr net.Error
			switch {
			case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
				return nil
			case errors.Is(err, os.ErrDeadlineExceeded):
				continue
			case errors.As(err, &netErr) && netErr.Timeout():
				continue
			default:
				return err
			}
		}
		switch frame.Kind {
		case messageInv:
			if err := p.handleInv(frame.Payload); err != nil {
				return err
			}
		case messageGetData:
			if err := p.handleGetData(frame.Payload); err != nil {
				return err
			}
		case messageBlock:
			if err := p.handleBlock(frame.Payload); err != nil {
				return err
			}
		case messageTx:
			if err := p.handleTx(frame.Payload); err != nil {
				return err
			}
		case messageGetBlk:
			if err := p.handleGetBlocks(frame.Payload); err != nil {
				return err
			}
		case messageVersion:
			return errors.New("invalid version message after handshake")
		default:
			return fmt.Errorf("unknown message type: %d", frame.Kind)
		}
	}
}

func (p *peer) handleInv(payload []byte) error {
	items, err := decodeInventoryVectors(payload)
	if err != nil {
		return err
	}
	requests := make([]InventoryVector, 0, len(items))
	for _, item := range items {
		switch item.Type {
		case MSG_BLOCK:
			if p.service.blockSeen.Has(item.Hash) {
				continue
			}
			have, err := p.service.hasBlock(item.Hash)
			if err != nil {
				return err
			}
			if have {
				continue
			}
			requests = append(requests, item)
		case MSG_TX:
			if p.service.txSeen.Has(item.Hash) || p.service.cfg.TxPool.Has(item.Hash) {
				continue
			}
			requests = append(requests, item)
		}
	}
	if len(requests) == 0 {
		return nil
	}
	body, err := encodeInventoryVectors(requests)
	if err != nil {
		return err
	}
	return p.send(messageGetData, body)
}

func (p *peer) handleGetData(payload []byte) error {
	items, err := decodeInventoryVectors(payload)
	if err != nil {
		return err
	}
	for _, item := range items {
		switch item.Type {
		case MSG_BLOCK:
			p.service.chainMu.Lock()
			blockBytes, err := p.service.cfg.BlockStore.GetBlockByHash(item.Hash)
			p.service.chainMu.Unlock()
			if err == nil {
				if sendErr := p.send(messageBlock, blockBytes); sendErr != nil {
					return sendErr
				}
			}
		case MSG_TX:
			txBytes, ok := p.service.cfg.TxPool.Get(item.Hash)
			if ok {
				if sendErr := p.send(messageTx, txBytes); sendErr != nil {
					return sendErr
				}
			}
		}
	}
	return nil
}

func (p *peer) handleGetBlocks(payload []byte) error {
	req, err := decodeGetBlocksPayload(payload)
	if err != nil {
		return err
	}
	p.service.chainMu.Lock()
	hashes, err := p.service.cfg.BlockStore.HashesAfterLocators(
		req.LocatorHashes,
		req.StopHash,
		p.service.cfg.GetBlocksBatchSize,
	)
	p.service.chainMu.Unlock()
	if err != nil || len(hashes) == 0 {
		return err
	}
	items := make([]InventoryVector, 0, len(hashes))
	for _, hash := range hashes {
		items = append(items, InventoryVector{Type: MSG_BLOCK, Hash: hash})
	}
	body, err := encodeInventoryVectors(items)
	if err != nil {
		return err
	}
	return p.send(messageInv, body)
}

func (p *peer) handleBlock(blockBytes []byte) error {
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		p.bumpBan(100, err.Error())
		return err
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		p.bumpBan(100, err.Error())
		return err
	}
	have, err := p.service.hasBlock(blockHash)
	if err != nil {
		return err
	}
	if have {
		return nil
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

func (p *peer) handleTx(txBytes []byte) error {
	_, txid, _, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		if p.bumpBan(10, err.Error()) {
			return err
		}
		return nil
	}
	if consumed != len(txBytes) {
		if p.bumpBan(10, "non-canonical tx bytes") {
			return errors.New("non-canonical tx bytes")
		}
		return nil
	}
	isNew := p.service.cfg.TxPool.Put(txid, txBytes)
	if !isNew {
		return nil
	}
	if p.service.txSeen.Add(txid) {
		_ = p.service.broadcastInventory(p, []InventoryVector{{Type: MSG_TX, Hash: txid}})
	}
	return nil
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

func performHandshake(
	ctx context.Context,
	conn net.Conn,
	cfg node.PeerRuntimeConfig,
	local node.VersionPayloadV1,
	expectedChainID [32]byte,
	expectedGenesisHash [32]byte,
) (node.PeerState, error) {
	cfg = mergePeerRuntimeConfig(cfg)

	state := node.PeerState{
		Addr: conn.RemoteAddr().String(),
	}
	deadline := time.Now().Add(cfg.HandshakeTimeout)
	if ctx != nil {
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return state, err
	}
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	done := make(chan struct{})
	defer close(done)
	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				_ = conn.SetDeadline(time.Now())
			case <-done:
			}
		}()
	}

	payload, err := encodeVersionPayload(local)
	if err != nil {
		return state, err
	}
	if err := writeFrame(conn, message{Kind: messageVersion, Payload: payload}, cfg.MaxMessageSize); err != nil {
		return state, err
	}
	frame, err := readFrame(conn, cfg.MaxMessageSize)
	if err != nil {
		return state, err
	}
	if frame.Kind != messageVersion {
		state.LastError = "invalid version message"
		return state, errors.New("invalid version message")
	}
	remote, err := decodeVersionPayload(frame.Payload)
	if err != nil {
		state.LastError = err.Error()
		return state, err
	}
	state.RemoteVersion = remote
	switch {
	case remote.Magic != ProtocolMagic:
		state.BanScore = cfg.BanThreshold
		state.LastError = "magic mismatch"
		return state, errors.New("magic mismatch")
	case remote.ProtocolVersion != ProtocolVersion:
		state.LastError = "invalid protocol_version"
		return state, errors.New("invalid protocol_version")
	case remote.ChainID != expectedChainID:
		state.BanScore = cfg.BanThreshold
		state.LastError = "chain_id mismatch"
		return state, errors.New("chain_id mismatch")
	case remote.GenesisHash != expectedGenesisHash:
		state.BanScore = cfg.BanThreshold
		state.LastError = "genesis_hash mismatch"
		return state, errors.New("genesis_hash mismatch")
	}
	state.HandshakeComplete = true
	return state, nil
}

func normalizeDuration(current, fallback time.Duration) time.Duration {
	if current > 0 {
		return current
	}
	return fallback
}

func mergePeerRuntimeConfig(cfg node.PeerRuntimeConfig) node.PeerRuntimeConfig {
	defaults := node.DefaultPeerRuntimeConfig(cfg.Network, cfg.MaxPeers)
	if cfg.Network == "" {
		cfg.Network = defaults.Network
	}
	if cfg.MaxPeers <= 0 {
		cfg.MaxPeers = defaults.MaxPeers
	}
	cfg.ReadDeadline = normalizeDuration(cfg.ReadDeadline, defaults.ReadDeadline)
	cfg.WriteDeadline = normalizeDuration(cfg.WriteDeadline, defaults.WriteDeadline)
	cfg.HandshakeTimeout = normalizeDuration(cfg.HandshakeTimeout, defaults.HandshakeTimeout)
	if cfg.BanThreshold <= 0 {
		cfg.BanThreshold = defaults.BanThreshold
	}
	if cfg.MaxMessageSize == 0 {
		cfg.MaxMessageSize = defaults.MaxMessageSize
	}
	return cfg
}
