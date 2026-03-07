package node

import (
	"errors"
	"sync"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	defaultReadDeadline     = 15 * time.Second
	defaultWriteDeadline    = 15 * time.Second
	defaultHandshakeTimeout = 10 * time.Second
	defaultBanThreshold     = 100
	defaultMaxMessageSize   = uint32(consensus.MAX_RELAY_MSG_BYTES)
)

type VersionPayloadV1 struct {
	ProtocolVersion   uint32
	TxRelay           bool
	PrunedBelowHeight uint64
	DaMempoolSize     uint32
	ChainID           [32]byte
	GenesisHash       [32]byte
	BestHeight        uint64
	UserAgent         string
}

type PeerRuntimeConfig struct {
	Network          string
	MaxPeers         int
	ReadDeadline     time.Duration
	WriteDeadline    time.Duration
	HandshakeTimeout time.Duration
	BanThreshold     int
	MaxMessageSize   uint32
}

type PeerState struct {
	Addr              string
	LastError         string
	RemoteVersion     VersionPayloadV1
	BanScore          int
	HandshakeComplete bool
}

type PeerManager struct {
	peers map[string]*PeerState
	cfg   PeerRuntimeConfig
	mu    sync.RWMutex
}

func DefaultPeerRuntimeConfig(network string, maxPeers int) PeerRuntimeConfig {
	if maxPeers <= 0 {
		maxPeers = 64
	}
	return PeerRuntimeConfig{
		Network:          network,
		MaxPeers:         maxPeers,
		ReadDeadline:     defaultReadDeadline,
		WriteDeadline:    defaultWriteDeadline,
		HandshakeTimeout: defaultHandshakeTimeout,
		BanThreshold:     defaultBanThreshold,
		MaxMessageSize:   defaultMaxMessageSize,
	}
}

func NewPeerManager(cfg PeerRuntimeConfig) *PeerManager {
	cfg = normalizePeerRuntimeConfig(cfg)
	return &PeerManager{
		cfg:   cfg,
		peers: make(map[string]*PeerState),
	}
}

func (pm *PeerManager) AddPeer(state *PeerState) error {
	return pm.upsertPeer(state, false)
}

func (pm *PeerManager) UpsertPeer(state *PeerState) error {
	return pm.upsertPeer(state, true)
}

func (pm *PeerManager) upsertPeer(state *PeerState, overwrite bool) error {
	if pm == nil {
		return errors.New("nil peer manager")
	}
	if state == nil {
		return errors.New("nil peer state")
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if _, exists := pm.peers[state.Addr]; !exists && len(pm.peers) >= pm.cfg.MaxPeers {
		return errors.New("max peers reached")
	}
	if !overwrite {
		if _, exists := pm.peers[state.Addr]; exists {
			pm.peers[state.Addr] = clonePeerState(state)
			return nil
		}
	}
	pm.peers[state.Addr] = clonePeerState(state)
	return nil
}

func (pm *PeerManager) RemovePeer(addr string) {
	if pm == nil {
		return
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.peers, addr)
}

func (pm *PeerManager) Count() int {
	if pm == nil {
		return 0
	}
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.peers)
}

func (pm *PeerManager) Snapshot() []PeerState {
	if pm == nil {
		return nil
	}
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	out := make([]PeerState, 0, len(pm.peers))
	for _, p := range pm.peers {
		out = append(out, *clonePeerState(p))
	}
	return out
}

func clonePeerState(in *PeerState) *PeerState {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func normalizePeerRuntimeConfig(cfg PeerRuntimeConfig) PeerRuntimeConfig {
	if cfg.MaxPeers <= 0 {
		cfg.MaxPeers = 64
	}
	if cfg.ReadDeadline <= 0 {
		cfg.ReadDeadline = defaultReadDeadline
	}
	if cfg.WriteDeadline <= 0 {
		cfg.WriteDeadline = defaultWriteDeadline
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.BanThreshold <= 0 {
		cfg.BanThreshold = defaultBanThreshold
	}
	if cfg.MaxMessageSize == 0 {
		cfg.MaxMessageSize = defaultMaxMessageSize
	}
	return cfg
}
