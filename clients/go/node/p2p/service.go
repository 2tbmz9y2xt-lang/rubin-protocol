package p2p

import (
	"context"
	"errors"
	"net"
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
