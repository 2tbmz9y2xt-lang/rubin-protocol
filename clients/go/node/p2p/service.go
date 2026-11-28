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
	relayTxAdmissionAttempts          = 2
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
	// EnableImageRequester admits IMAGE replies on handshaken peer workers.
	EnableImageRequester bool
	PeerRuntimeConfig    node.PeerRuntimeConfig
	PeerManager          *node.PeerManager
	SyncConfig           node.SyncConfig
	SyncEngine           *node.SyncEngine
	BlockStore           *node.BlockStore
	TxPool               TxPool
	TxMetadataFunc       func([]byte) (node.RelayTxMetadata, error)
	Now                  func() time.Time
	// InboundBlockBudgetBytes is the byte limit of the Service inbound budget under which peer
	// readers read block message payloads after the handshake. Zero selects 1073741824; any other
	// value outside 1073741824 to 8589934592 inclusive fails NewService with the budget range
	// error, which follows the other configuration checks and precedes the DA relay state claim.
	InboundBlockBudgetBytes uint64
}

type Service struct {
	cfg      ServiceConfig
	ctx      context.Context
	cancel   context.CancelFunc
	listener net.Listener

	// peersMu protects the peer registry and its coupled PeerManager updates.
	peersMu sync.RWMutex
	peers   map[string]*peer
	// peerRegistrations is the last registration order handed out by registerPeer; a newer
	// registration of one logical address owns it, and unregisterPeer hands an exiting owner's
	// address to the live same-address connection with the highest order. Guarded by peersMu.
	peerRegistrations uint64
	// livePeers is the set of registered connections that have not exited (R5): a live
	// connection can hold no Service.peers entry once a newer registration took its logical
	// address and its alias equals that address or another connection's logical address.
	// Mutated only in the registerPeer and unregisterPeer peersMu sections. Guarded by peersMu.
	livePeers        map[*peer]struct{}
	peerQuotaLocksMu sync.Mutex
	peerQuotaLocks   map[string]*peerQuotaLock
	// lifecycleMu serializes lifecycle field updates and snapshots, the closed
	// and closeDone publications, and Start and loop wait group registration.
	lifecycleMu sync.Mutex
	// closed is set to true by Close. A Service instance is single-use: once
	// Close has returned, Start refuses to restart the same Service and the
	// accept/reconnect loops stay stopped. Close stores it under lifecycleMu.
	closed atomic.Bool
	// closeDone is published by the Close that owns the teardown and closed
	// when that teardown completes; every later Close waits on it instead of
	// tearing down again. closed==true with a nil closeDone means the flag
	// was published without a teardown owner, so the next Close still owns
	// the teardown. Guarded by lifecycleMu.
	closeDone chan struct{}
	// boundAddr caches listener.Addr().String() captured when Start
	// successfully publishes the listener. Addr() returns it so that
	// wildcard/ephemeral binds (e.g. ":0") still surface the concrete
	// resolved port after Close, without needing to call Addr() on a
	// closed net.Listener. Guarded by lifecycleMu.
	boundAddr string
	loopWG    sync.WaitGroup
	// startWG counts in-progress Start invocations. Start increments on
	// entry and decrements via defer on exit. Close waits on this before
	// snapshotting s.listener so that a Close that races with a Start call
	// which has already returned from net.Listen but not yet published the
	// listener into s.listener cannot return while the freshly created
	// listener is still bound. Start observes s.closed in its lifecycle
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
	daRelay   *node.DARelayState

	// peerLifecycleExits counts peer lifecycle exits at the single
	// canonical removal boundary inside unregisterPeer. The counter is
	// incremented exactly once per exiting live connection
	// (removePeerEntries reports true, decided by livePeers together
	// with s.peers). Repeated unregisterPeer calls on the same
	// already-removed peer get false from it and do not bump the
	// counter. The metric is intentionally unlabeled: the
	// underlying exit cause (remote EOF, protocol error, local
	// Service.Close ctx cancel, request/send error) is not available
	// at the unregisterPeer site without plumbing it through, and
	// labeled buckets cannot be proven non-overlapping under the
	// current cleanup graph (issue #1307).
	peerLifecycleExits atomic.Uint64
	inboundBudget      *inboundBlockBudget
	imageRequester     *imageRequester
}

type peerQuotaLock struct {
	mu   sync.Mutex
	refs int
}

type peer struct {
	conn    net.Conn
	service *Service
	// The requester mutex guards capture and retirement. Source observation reads imageRetired under peersMu.
	imageSession *imageSession
	imageRetired atomic.Bool

	stateMu sync.Mutex
	state   node.PeerState
	// qualityScore and qualityHeight are COMPETING_SCORE_V1's connection-local state
	// (da_relay_ingest.go) under stateMu: the score and the local tip height of its last
	// consumed normalization interval. handleConn initializes them once before
	// registration; never copied into node.PeerState, so the peer manager, bumpBan,
	// setLastError and sendcmpct never reset them; zero is a valid score.
	qualityScore  uint8
	qualityHeight uint64
	// daQuotaIdentity is the connection's DA quota identity, derived once by handleConn from the
	// actual conn.RemoteAddr() via daQuotaIdentityForEndpoint before registerPeer publishes the peer
	// and immutable for the connection's lifetime. It is never derived from the configured dial
	// name, PeerState.Addr, an alias or an advertised address. DA provenance, ingress serialization,
	// prefetch grouping and disconnect release all key on it; empty means no IP endpoint, so the
	// connection takes no DA admission, DA quota lock, DA cleanup or prefetch candidacy.
	daQuotaIdentity string
	// registrationOrder is this connection's Service.peerRegistrations value, set once by
	// registerPeer under Service.peersMu and read only under it.
	registrationOrder uint64

	writeMu sync.Mutex

	compactMu sync.Mutex
	compact   peerCompactRelayState

	// retry is the peer's single block re-request slot (block_retry.go); nil is no slot.
	retryMu sync.Mutex
	retry   *blockRetrySlot
	// inboundLease is the budget lease of the block frame this peer is handling, nil between
	// frames. Only the peer's run loop goroutine touches it, so no lock guards it.
	inboundLease *inboundBlockLease
}

// NewService validates and normalizes cfg (its nil cfg.PeerManager check refuses with
// "nil peer manager"), builds the Service, claims cfg.PeerManager (a held one is refused with
// "peer manager is already claimed" before any later step), then claims the SyncEngine's DA
// relay state (the first successful claimant keeps the detached-reorg hook; an earlier DA claim
// or binding refuses no later construction) and returns that claim's refusal after releasing the
// PeerManager claim. Its final step publishes this OPEN Service as the current DA TTL binding
// (RUBIN_COMPACT_BLOCKS.md Section 5). Construction and publication change no other DA record,
// count or claim; a failed construction leaves the binding unchanged; Close never clears it.
func NewService(cfg ServiceConfig) (*Service, error) {
	if err := validateServiceConfig(cfg); err != nil {
		return nil, err
	}
	cfg = normalizeServiceConfig(cfg)
	inboundBudget, err := newInboundBlockBudget(cfg.InboundBlockBudgetBytes)
	if err != nil {
		return nil, err
	}
	expectedRelay := cfg.SyncEngine.DARelayState()
	outboundAddrs := normalizeDialTargets(cfg.BootstrapPeers)
	addrMgr := newAddrManager(cfg.Now)
	seedAddrManagerFromBootstrap(addrMgr, outboundAddrs)
	service := &Service{
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
		daRelay:        expectedRelay,
		inboundBudget:  inboundBudget,
		imageRequester: newImageRequester(),
	}
	if err := cfg.PeerManager.Claim(); err != nil {
		return nil, err
	}
	if _, err := cfg.SyncEngine.ClaimDARelayState(expectedRelay, service.admitDetachedReorgDA); err != nil {
		cfg.PeerManager.Release()
		return nil, err
	}
	cfg.SyncEngine.PublishDATTLBinding(service)
	return service, nil
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

// errServiceClosed is the exact rejection a publication-capable public entry
// returns once Close has published the non-OPEN state.
var errServiceClosed = errors.New("service already closed")

// acquireWork registers one Service work lease and reports whether the
// Service was still OPEN. A rejected caller must perform no parsing,
// producer call, state mutation, queueing, or send. The loopWG increment
// happens under the same lifecycleMu section that reads closed, and Close
// publishes closed under that lock before it releases it and waits, so a
// lease can never be added after Close began waiting for it.
func (s *Service) acquireWork() bool {
	if s == nil {
		return false
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.closed.Load() {
		return false
	}
	s.loopWG.Add(1)
	return true
}

// enterDATTLMutationLeased is this Service's own nested DA TTL entry for an apply
// that runs under this Service's worker lease (applyBlockWithReorg passes it): it
// registers and releases nothing and never reads the binding.
func (s *Service) enterDATTLMutationLeased(decrease func() error) error {
	return decrease()
}

// EnterDATTLMutation is this Service's own DA TTL entry under no Service lease
// (RUBIN_L1_P2P_AUX.md Section 5). Called inside the canonical transition's
// exclusive ChainState admission guard, it never reacquires that guard and takes
// no lock any path holds while waiting for it. It registers one call lease, or
// returns "service already closed" with zero effects once Close published the
// non-OPEN state; otherwise it runs decrease once, returns its result unchanged and
// releases the lease once on every exit, unwind included, before a panic in
// decrease propagates unrecovered. It never reads the binding, retries or falls back.
func (s *Service) EnterDATTLMutation(decrease func() error) error {
	if !s.acquireWork() {
		return errServiceClosed
	}
	defer s.releaseWork()
	return decrease()
}

// releaseWork releases exactly one lease taken by acquireWork.
func (s *Service) releaseWork() {
	s.loopWG.Done()
}

// workAuthorized reports whether the Service is still OPEN with one atomic
// read. A peer worker calls it immediately before authorizing one more frame
// read and keeps its existing worker lease. A peer with no Service stays
// authorized.
func (s *Service) workAuthorized() bool {
	if s == nil {
		return true
	}
	return !s.closed.Load()
}

// AnnounceBlock parses a locally accepted block and announces it to the
// current peers. It takes one Service call lease before parsing, seen-set
// mutation or broadcast: once Close has published the non-OPEN state it
// returns exactly "service already closed" with zero effects, and a call that
// won the lease first finishes while Close waits for it. It performs no DA TTL
// decrease; only the canonical transition of an ACCEPTED/NEW apply invokes one.
func (s *Service) AnnounceBlock(blockBytes []byte) error {
	if s == nil {
		return errors.New("nil service")
	}
	if !s.acquireWork() {
		return errServiceClosed
	}
	defer s.releaseWork()
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
	return s.broadcastAcceptedBlock(nil, blockHash)
}

// AnnounceTx admits a locally submitted transaction to the relay pool and
// announces it. It takes one Service call lease before parsing, admission,
// seen-set mutation or inventory send: once Close has published the non-OPEN
// state it returns exactly "service already closed" with zero effects, and a
// call that won the lease first finishes while Close waits. A parsed DA kind
// leaves for announceLocalDA under that same lease, before any standard-pool,
// metadata, seen-set or inventory access; only kind 0x00 reaches the arm below,
// and a CanonicalMempoolTxPool refuses every DA kind anyway.
func (s *Service) AnnounceTx(txBytes []byte) error {
	if s == nil {
		return errors.New("nil service")
	}
	if !s.acquireWork() {
		return errServiceClosed
	}
	defer s.releaseWork()
	tx, txid, err := parseCanonicalTx(txBytes)
	if err != nil {
		return err
	}
	if tx.TxKind == 0x01 || tx.TxKind == 0x02 {
		return s.announceLocalDA(txBytes)
	}
	if _, _, err := s.ensureRelayTxAdmitted(txid, txBytes, tx, false); err != nil {
		return err
	}
	if !s.txSeen.Add(txid) {
		return nil
	}
	return s.broadcastInventory(nil, []InventoryVector{{Type: MSG_TX, Hash: txid}})
}

func (s *Service) ensureRelayTxAdmitted(txid [32]byte, txBytes []byte, submittedTx *consensus.Tx, submittedTxValidated bool) ([]byte, *consensus.Tx, error) {
	if !submittedTxValidated {
		if err := validateRelayDATxForAdmission(txBytes, submittedTx); err != nil {
			return nil, nil, err
		}
	}
	var meta node.RelayTxMetadata
	metaReady := false
	for attempt := 0; attempt < relayTxAdmissionAttempts; attempt++ {
		if admittedTxBytes, admittedTx, ok, err := s.relayTxFromPool(txid); ok || err != nil {
			return admittedTxBytes, admittedTx, err
		}
		if !metaReady {
			var err error
			meta, err = s.relayTxMetadata(txBytes)
			if err != nil {
				return nil, nil, err
			}
			metaReady = true
		}
		s.cfg.TxPool.Put(txid, txBytes, meta.Fee, meta.Size)
		if admittedTxBytes, admittedTx, ok, err := s.relayTxFromPool(txid); ok || err != nil {
			return admittedTxBytes, admittedTx, err
		}
	}
	return nil, nil, fmt.Errorf("tx not admitted to relay pool: txid=%x", txid)
}

func (s *Service) relayTxFromPool(txid [32]byte) ([]byte, *consensus.Tx, bool, error) {
	admittedTxBytes, ok := s.cfg.TxPool.Get(txid)
	if !ok {
		return nil, nil, false, nil
	}
	admittedTx, admittedTxid, err := parseCanonicalTx(admittedTxBytes)
	if err != nil {
		return nil, nil, true, fmt.Errorf("admitted tx is non-canonical: txid=%x: %w", txid, err)
	}
	if admittedTxid != txid {
		return nil, nil, true, fmt.Errorf("admitted txid mismatch: expected=%x got=%x", txid, admittedTxid)
	}
	if err := validateRelayDATxForAdmission(admittedTxBytes, admittedTx); err != nil {
		return nil, nil, true, fmt.Errorf("admitted tx failed DA relay validation: txid=%x: %w", txid, err)
	}
	return admittedTxBytes, admittedTx, true, nil
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
