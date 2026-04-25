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
	defaultTxRelayFanout              = 8
)

type ServiceConfig struct {
	BindAddr           string
	BootstrapPeers     []string
	UserAgent          string
	GenesisHash        [32]byte
	LocatorLimit       int
	GetBlocksBatchSize uint64
	TxRelayFanout      int
	PeerRuntimeConfig  node.PeerRuntimeConfig
	PeerManager        *node.PeerManager
	SyncConfig         node.SyncConfig
	SyncEngine         *node.SyncEngine
	BlockStore         *node.BlockStore
	TxPool             TxPool
	TxMetadataFunc     func([]byte) (node.RelayTxMetadata, error)
	Now                func() time.Time
}

type Service struct {
	cfg      ServiceConfig
	ctx      context.Context
	cancel   context.CancelFunc
	listener net.Listener

	peersMu sync.RWMutex
	peers   map[string]*peer
	// closed is set to true by Close. A Service instance is single-use: once
	// Close has returned, Start refuses to restart the same Service and the
	// accept/reconnect loops must not be revived. Guarded by peersMu.
	closed bool
	// boundAddr caches listener.Addr().String() captured when Start
	// successfully publishes the listener. Addr() returns it so that
	// wildcard/ephemeral binds (e.g. ":0") still surface the concrete
	// resolved port after Close, without needing to call Addr() on a
	// closed net.Listener. Guarded by peersMu.
	boundAddr string
	loopWG    sync.WaitGroup
	// startWG counts in-progress Start invocations. Start increments on
	// entry and decrements via defer on exit. Close waits on this before
	// snapshotting s.listener so that a Close that races with a Start call
	// which has already returned from net.Listen but not yet published the
	// listener into s.listener cannot return while the freshly created
	// listener is still bound. Start observes s.closed in its write-lock
	// re-check and closes the local listener on its own, but Close must
	// wait for that cleanup before declaring the port free.
	startWG sync.WaitGroup

	dialMu       sync.Mutex
	inFlightDial map[string]struct{}

	reconnectMu    sync.Mutex
	reconnectState map[string]*reconnectEntry
	outboundAddrs  []string
	addrMgr        *addrManager
	handshakeSlots chan struct{}

	chainMu   sync.Mutex
	blockSeen *boundedHashSet
	txSeen    *boundedHashSet
	orphans   *orphanPool
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
	if cfg.TxMetadataFunc == nil {
		return nil, errors.New("nil tx metadata func")
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
	if cfg.TxRelayFanout <= 0 {
		cfg.TxRelayFanout = defaultTxRelayFanout
	}
	outboundAddrs := normalizeDialTargets(cfg.BootstrapPeers)
	addrMgr := newAddrManager(cfg.Now)
	seedAddrManagerFromBootstrap(addrMgr, outboundAddrs)
	return &Service{
		cfg:            cfg,
		peers:          make(map[string]*peer),
		inFlightDial:   make(map[string]struct{}),
		reconnectState: make(map[string]*reconnectEntry),
		outboundAddrs:  outboundAddrs,
		addrMgr:        addrMgr,
		handshakeSlots: make(chan struct{}, cfg.PeerRuntimeConfig.MaxPeers),
		blockSeen:      newBoundedHashSet(defaultBlockSeenCapacity),
		txSeen:         newBoundedHashSet(defaultTxSeenCapacity),
		orphans:        newOrphanPool(500),
	}, nil
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
	admitted := s.cfg.TxPool.Has(txid)
	if !admitted {
		meta, err := s.relayTxMetadata(txBytes)
		if err != nil {
			return err
		}
		admitted = s.cfg.TxPool.Put(txid, txBytes, meta.Fee, meta.Size)
	}
	if !admitted && !s.cfg.TxPool.Has(txid) {
		return errors.New("tx not admitted to relay pool")
	}
	if !s.txSeen.Add(txid) {
		return nil
	}
	return s.broadcastInventory(nil, []InventoryVector{{Type: MSG_TX, Hash: txid}})
}

func normalizePeerAddrs(addrs []string) []string {
	return normalizeUniqueAddrs(addrs, normalizeNetAddr)
}

func normalizeDialTargets(addrs []string) []string {
	return normalizeUniqueAddrs(addrs, normalizeDialTarget)
}

func normalizeUniqueAddrs(addrs []string, normalize func(string) string) []string {
	seen := make(map[string]struct{}, len(addrs))
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addr = normalize(addr)
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func seedAddrManagerFromBootstrap(manager *addrManager, addrs []string) {
	if manager == nil || len(addrs) == 0 {
		return
	}
	manager.AddAddrs(normalizePeerAddrs(addrs))
}
