package node

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const defaultIBDLagSeconds = 24 * 60 * 60

type SyncConfig struct {
	ExpectedTarget   *[32]byte
	ChainStatePath   string
	HeaderBatchLimit uint64
	IBDLagSeconds    uint64
	ChainID          [32]byte
	Network          string
}

type HeaderRequest struct {
	FromHash [32]byte
	HasFrom  bool
	Limit    uint64
}

type SyncEngine struct {
	chainState      *ChainState
	blockStore      *BlockStore
	mempool         *Mempool
	cfg             SyncConfig
	mu              sync.RWMutex
	tipTimestamp    uint64
	bestKnownHeight uint64
}

func DefaultSyncConfig(expectedTarget *[32]byte, chainID [32]byte, chainStatePath string) SyncConfig {
	return SyncConfig{
		HeaderBatchLimit: 512,
		IBDLagSeconds:    defaultIBDLagSeconds,
		ExpectedTarget:   expectedTarget,
		ChainID:          chainID,
		ChainStatePath:   chainStatePath,
		Network:          "devnet",
	}
}

func NewSyncEngine(chainState *ChainState, blockStore *BlockStore, cfg SyncConfig) (*SyncEngine, error) {
	if chainState == nil {
		return nil, errors.New("nil chainstate")
	}
	cfg = normalizeSyncConfig(cfg)
	if err := validateMainnetGenesisGuard(cfg); err != nil {
		return nil, err
	}
	engine := &SyncEngine{
		chainState: chainState,
		blockStore: blockStore,
		cfg:        cfg,
	}
	return engine, nil
}

func normalizeSyncConfig(cfg SyncConfig) SyncConfig {
	if cfg.HeaderBatchLimit == 0 {
		cfg.HeaderBatchLimit = 512
	}
	if cfg.IBDLagSeconds == 0 {
		cfg.IBDLagSeconds = defaultIBDLagSeconds
	}
	cfg.Network = normalizedNetworkName(cfg.Network)
	return cfg
}

func normalizedNetworkName(network string) string {
	network = strings.ToLower(strings.TrimSpace(network))
	if network == "" {
		return "devnet"
	}
	return network
}

func validateMainnetGenesisGuard(cfg SyncConfig) error {
	if normalizedNetworkName(cfg.Network) != "mainnet" {
		return nil
	}
	if cfg.ExpectedTarget == nil {
		return errors.New("mainnet requires explicit expected_target")
	}
	if *cfg.ExpectedTarget == consensus.POW_LIMIT {
		return errors.New("mainnet expected_target must not equal devnet POW_LIMIT (all-ff)")
	}
	return nil
}

func (s *SyncEngine) HeaderSyncRequest() HeaderRequest {
	if s == nil || s.chainState == nil {
		return HeaderRequest{}
	}
	return headerSyncRequest(s.chainState, s.cfg.HeaderBatchLimit)
}

func (s *SyncEngine) RecordBestKnownHeight(height uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if height > s.bestKnownHeight {
		s.bestKnownHeight = height
	}
}

func (s *SyncEngine) BestKnownHeight() uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bestKnownHeight
}

func (s *SyncEngine) IsInIBD(nowUnix uint64) bool {
	if s == nil || s.chainState == nil {
		return true
	}
	if !s.chainState.HasTip {
		return true
	}
	s.mu.RLock()
	tipTimestamp := s.tipTimestamp
	ibdLag := s.cfg.IBDLagSeconds
	s.mu.RUnlock()
	return isInIBDWindow(nowUnix, tipTimestamp, ibdLag)
}

func (s *SyncEngine) ApplyBlock(blockBytes []byte, prevTimestamps []uint64) (*ChainStateConnectSummary, error) {
	if s == nil || s.chainState == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	blockHeight, _, err := nextBlockContext(s.chainState)
	if err != nil {
		return nil, err
	}
	if err := validateIncomingChainID(blockHeight, s.cfg.ChainID); err != nil {
		return nil, err
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		return nil, err
	}

	rollbackState, err := s.captureRollbackState()
	if err != nil {
		return nil, err
	}
	summary, err := s.chainState.ConnectBlock(blockBytes, s.cfg.ExpectedTarget, prevTimestamps, s.cfg.ChainID)
	if err != nil {
		return nil, err
	}
	if err := s.persistAppliedBlock(summary, blockHash, pb.HeaderBytes, blockBytes); err != nil {
		return nil, s.rollbackApplyBlock(err, rollbackState)
	}

	s.recordAppliedBlock(summary.BlockHeight, pb.Header.Timestamp)
	if s.mempool != nil {
		_ = s.mempool.EvictConfirmed(blockBytes)
		_ = s.mempool.RemoveConflicting(blockBytes)
	}
	return summary, nil
}

func (s *SyncEngine) SetMempool(mempool *Mempool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mempool = mempool
}

type syncRollbackState struct {
	chainState      chainStateDisk
	tipTimestamp    uint64
	bestKnownHeight uint64
}

func headerSyncRequest(chainState *ChainState, limit uint64) HeaderRequest {
	if chainState == nil || !chainState.HasTip {
		return HeaderRequest{Limit: limit}
	}
	return HeaderRequest{
		FromHash: chainState.TipHash,
		HasFrom:  true,
		Limit:    limit,
	}
}

func isInIBDWindow(nowUnix uint64, tipTimestamp uint64, ibdLag uint64) bool {
	if nowUnix < tipTimestamp {
		return true
	}
	return nowUnix-tipTimestamp > ibdLag
}

func (s *SyncEngine) captureRollbackState() (syncRollbackState, error) {
	snapshot, err := stateToDisk(s.chainState)
	if err != nil {
		return syncRollbackState{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return syncRollbackState{
		chainState:      snapshot,
		tipTimestamp:    s.tipTimestamp,
		bestKnownHeight: s.bestKnownHeight,
	}, nil
}

func (s *SyncEngine) rollbackApplyBlock(cause error, state syncRollbackState) error {
	restoreErr := restoreChainState(s.chainState, state.chainState)
	s.mu.Lock()
	s.tipTimestamp = state.tipTimestamp
	s.bestKnownHeight = state.bestKnownHeight
	s.mu.Unlock()
	if restoreErr != nil {
		return fmt.Errorf("%w (rollback failed: %v)", cause, restoreErr)
	}
	return cause
}

func (s *SyncEngine) persistAppliedBlock(summary *ChainStateConnectSummary, blockHash [32]byte, headerBytes []byte, blockBytes []byte) error {
	if s.blockStore != nil {
		if err := s.blockStore.PutBlock(summary.BlockHeight, blockHash, headerBytes, blockBytes); err != nil {
			return err
		}
	}
	if s.cfg.ChainStatePath != "" {
		if err := s.chainState.Save(s.cfg.ChainStatePath); err != nil {
			return err
		}
	}
	return nil
}

func (s *SyncEngine) recordAppliedBlock(height uint64, timestamp uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tipTimestamp = timestamp
	if height > s.bestKnownHeight {
		s.bestKnownHeight = height
	}
}

func validateIncomingChainID(blockHeight uint64, chainID [32]byte) error {
	var zeroID [32]byte
	if blockHeight == 0 && chainID != zeroID {
		if chainID != devnetGenesisChainID {
			return errors.New("genesis chain_id mismatch")
		}
	}
	return nil
}

func restoreChainState(dst *ChainState, snapshot chainStateDisk) error {
	if dst == nil {
		return errors.New("nil chainstate destination")
	}
	recovered, err := chainStateFromDisk(snapshot)
	if err != nil {
		return err
	}
	*dst = *recovered
	return nil
}
