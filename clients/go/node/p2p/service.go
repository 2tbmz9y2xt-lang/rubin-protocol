package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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
	// EnableCompactReceive opens Go compact object receive after negotiated sendcmpct.
	// It defaults false until the controller/parity boundary explicitly enables it.
	EnableCompactReceive bool
	PeerRuntimeConfig    node.PeerRuntimeConfig
	PeerManager          *node.PeerManager
	SyncConfig           node.SyncConfig
	SyncEngine           *node.SyncEngine
	BlockStore           *node.BlockStore
	TxPool               TxPool
	TxMetadataFunc       func([]byte) (node.RelayTxMetadata, error)
	Now                  func() time.Time
}

type Service struct {
	cfg      ServiceConfig
	ctx      context.Context
	cancel   context.CancelFunc
	listener net.Listener

	peersMu          sync.RWMutex
	peers            map[string]*peer
	peerQuotaLocksMu sync.Mutex
	peerQuotaLocks   map[string]*peerQuotaLock
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
	daRelay   *daRelayState

	// peerLifecycleExits counts peer lifecycle exits at the single
	// canonical removal boundary inside unregisterPeer. The counter is
	// incremented exactly once per unregisterPeer call that actually
	// deletes one or more entries from the s.peers map (i.e. when the
	// dedupe flag remove==true). Repeated unregisterPeer calls on the
	// same already-removed peer leave remove==false and do not bump
	// the counter. The metric is intentionally unlabeled: the
	// underlying exit cause (remote EOF, protocol error, local
	// Service.Close ctx cancel, request/send error) is not available
	// at the unregisterPeer site without plumbing it through, and
	// labeled buckets cannot be proven non-overlapping under the
	// current cleanup graph (issue #1307).
	peerLifecycleExits atomic.Uint64
}

type peerQuotaLock struct {
	mu   sync.Mutex
	refs int
}

type peer struct {
	conn    net.Conn
	service *Service

	stateMu sync.Mutex
	state   node.PeerState

	writeMu sync.Mutex

	compactMu sync.Mutex
	compact   peerCompactRelayState
}

func NewService(cfg ServiceConfig) (*Service, error) {
	if err := validateServiceConfig(cfg); err != nil {
		return nil, err
	}
	cfg = normalizeServiceConfig(cfg)
	outboundAddrs := normalizeDialTargets(cfg.BootstrapPeers)
	addrMgr := newAddrManager(cfg.Now)
	seedAddrManagerFromBootstrap(addrMgr, outboundAddrs)
	daRelay, err := newDARelayState(defaultDARelayCaps())
	if err != nil {
		return nil, err
	}
	return &Service{
		cfg:            cfg,
		peers:          make(map[string]*peer),
		peerQuotaLocks: make(map[string]*peerQuotaLock),
		inFlightDial:   make(map[string]struct{}),
		reconnectState: make(map[string]*reconnectEntry),
		outboundAddrs:  outboundAddrs,
		addrMgr:        addrMgr,
		handshakeSlots: make(chan struct{}, cfg.PeerRuntimeConfig.MaxPeers),
		blockSeen:      newBoundedHashSet(defaultBlockSeenCapacity),
		txSeen:         newBoundedHashSet(defaultTxSeenCapacity),
		orphans:        newOrphanPool(500),
		daRelay:        daRelay,
	}, nil
}

func validateServiceConfig(cfg ServiceConfig) error {
	for _, check := range []struct {
		invalid bool
		err     string
	}{
		{strings.TrimSpace(cfg.BindAddr) == "", "bind address is required"},
		{cfg.PeerManager == nil, "nil peer manager"},
		{cfg.SyncEngine == nil, "nil sync engine"},
		{cfg.BlockStore == nil, "nil blockstore"},
		{cfg.TxMetadataFunc == nil, "nil tx metadata func"},
	} {
		if check.invalid {
			return errors.New(check.err)
		}
	}
	return nil
}

func normalizeServiceConfig(cfg ServiceConfig) ServiceConfig {
	if cfg.TxPool == nil {
		cfg.TxPool = NewMemoryTxPool()
	}
	cfg = normalizeServiceIdentityConfig(cfg)
	cfg.GetBlocksBatchSize = normalizeGetBlocksBatchSize(cfg.GetBlocksBatchSize, cfg.SyncConfig.HeaderBatchLimit)
	cfg.PeerRuntimeConfig = normalizeServicePeerRuntimeConfig(cfg.PeerRuntimeConfig, cfg.SyncConfig.Network)
	if cfg.TxRelayFanout <= 0 {
		cfg.TxRelayFanout = defaultTxRelayFanout
	}
	return cfg
}

func normalizeServiceIdentityConfig(cfg ServiceConfig) ServiceConfig {
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
	return cfg
}

func normalizeGetBlocksBatchSize(configured, headerBatchLimit uint64) uint64 {
	if configured > 0 {
		return configured
	}
	if headerBatchLimit > 0 {
		return headerBatchLimit
	}
	return defaultGetBlocksBatchLimit
}

func normalizeServicePeerRuntimeConfig(cfg node.PeerRuntimeConfig, syncNetwork string) node.PeerRuntimeConfig {
	cfg = mergePeerRuntimeConfig(cfg)
	if cfg.Network == "" {
		cfg.Network = syncNetwork
	}
	return cfg
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
	broadcastErr := s.broadcastAcceptedBlock(nil, blockHash)
	ttlErr := s.advanceDAOrphanTTL()
	if broadcastErr != nil {
		return broadcastErr
	}
	return ttlErr
}

func (s *Service) AnnounceTx(txBytes []byte) error {
	if s == nil {
		return errors.New("nil service")
	}
	_, txid, err := parseCanonicalTx(txBytes)
	if err != nil {
		return err
	}
	admittedTxBytes, admittedTx, err := s.ensureRelayTxAdmitted(txid, txBytes)
	if err != nil {
		return err
	}
	_ = s.stageRelayDATx("", admittedTxBytes, admittedTx)
	if !s.txSeen.Add(txid) {
		return nil
	}
	return s.broadcastInventory(nil, []InventoryVector{{Type: MSG_TX, Hash: txid}})
}

func (s *Service) ensureRelayTxAdmitted(txid [32]byte, txBytes []byte) ([]byte, *consensus.Tx, error) {
	if !s.cfg.TxPool.Has(txid) {
		submittedTx, submittedTxid, err := parseCanonicalTx(txBytes)
		if err != nil {
			return nil, nil, err
		}
		if submittedTxid != txid {
			return nil, nil, fmt.Errorf("submitted txid mismatch: expected=%x got=%x", txid, submittedTxid)
		}
		if err := validateRelayDATxForAdmission(txBytes, submittedTx); err != nil {
			return nil, nil, err
		}
		meta, err := s.relayTxMetadata(txBytes)
		if err != nil {
			return nil, nil, err
		}
		if !s.cfg.TxPool.Put(txid, txBytes, meta.Fee, meta.Size) && !s.cfg.TxPool.Has(txid) {
			return nil, nil, fmt.Errorf("tx not admitted to relay pool: txid=%x", txid)
		}
	}
	admittedTxBytes, ok := s.cfg.TxPool.Get(txid)
	if !ok {
		return nil, nil, fmt.Errorf("admitted tx missing from relay pool: txid=%x", txid)
	}
	admittedTx, admittedTxid, err := parseCanonicalTx(admittedTxBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("admitted tx is non-canonical: txid=%x: %w", txid, err)
	}
	if admittedTxid != txid {
		return nil, nil, fmt.Errorf("admitted txid mismatch: expected=%x got=%x", txid, admittedTxid)
	}
	if err := validateRelayDATxForAdmission(admittedTxBytes, admittedTx); err != nil {
		return nil, nil, fmt.Errorf("admitted tx failed DA relay validation: txid=%x: %w", txid, err)
	}
	return admittedTxBytes, admittedTx, nil
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
