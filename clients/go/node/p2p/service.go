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
	maxDiscoveredDialFanout           = 8
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
	loopWG  sync.WaitGroup

	reconnectMu    sync.Mutex
	reconnectState map[string]*reconnectEntry
	outboundAddrs  []string
	addrMgr        *addrManager
	dialingMu      sync.Mutex
	dialing        map[string]struct{}

	chainMu   sync.Mutex
	blockSeen *boundedHashSet
	txSeen    *boundedHashSet
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
	if cfg.TxRelayFanout <= 0 {
		cfg.TxRelayFanout = defaultTxRelayFanout
	}
	outboundAddrs := normalizeDialTargets(cfg.BootstrapPeers)
	return &Service{
		cfg:            cfg,
		peers:          make(map[string]*peer),
		reconnectState: make(map[string]*reconnectEntry),
		outboundAddrs:  outboundAddrs,
		addrMgr:        newAddrManager(cfg.Now),
		dialing:        make(map[string]struct{}),
		blockSeen:      newBoundedHashSet(defaultBlockSeenCapacity),
		txSeen:         newBoundedHashSet(defaultTxSeenCapacity),
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
	meta, err := s.relayTxMetadata(txBytes)
	if err != nil {
		return err
	}
	s.cfg.TxPool.Put(txid, txBytes, meta.Fee, meta.Size)
	if !s.txSeen.Add(txid) {
		return nil
	}
	return s.broadcastInventory(nil, []InventoryVector{{Type: MSG_TX, Hash: txid}})
}

func normalizePeerAddrs(addrs []string) []string {
	seen := make(map[string]struct{}, len(addrs))
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addr = normalizeNetAddr(addr)
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

func normalizeDialTargets(addrs []string) []string {
	seen := make(map[string]struct{}, len(addrs))
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addr = normalizeDialTarget(addr)
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
