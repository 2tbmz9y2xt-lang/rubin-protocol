package node

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const defaultIBDLagSeconds = 24 * 60 * 60

type SyncConfig struct {
	HeaderBatchLimit uint64
	IBDLagSeconds    uint64
	ExpectedTarget   *[32]byte
	ChainID          [32]byte
	ChainStatePath   string
}

type HeaderRequest struct {
	FromHash [32]byte
	HasFrom  bool
	Limit    uint64
}

type SyncEngine struct {
	chainState      *ChainState
	blockStore      *BlockStore
	cfg             SyncConfig
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
	}
}

func NewSyncEngine(chainState *ChainState, blockStore *BlockStore, cfg SyncConfig) (*SyncEngine, error) {
	if chainState == nil {
		return nil, errors.New("nil chainstate")
	}
	if cfg.HeaderBatchLimit == 0 {
		cfg.HeaderBatchLimit = 512
	}
	if cfg.IBDLagSeconds == 0 {
		cfg.IBDLagSeconds = defaultIBDLagSeconds
	}
	engine := &SyncEngine{
		chainState: chainState,
		blockStore: blockStore,
		cfg:        cfg,
	}
	return engine, nil
}

func (s *SyncEngine) HeaderSyncRequest() HeaderRequest {
	if s == nil || s.chainState == nil {
		return HeaderRequest{}
	}
	if !s.chainState.HasTip {
		return HeaderRequest{
			HasFrom: false,
			Limit:   s.cfg.HeaderBatchLimit,
		}
	}
	return HeaderRequest{
		FromHash: s.chainState.TipHash,
		HasFrom:  true,
		Limit:    s.cfg.HeaderBatchLimit,
	}
}

func (s *SyncEngine) RecordBestKnownHeight(height uint64) {
	if s == nil {
		return
	}
	if height > s.bestKnownHeight {
		s.bestKnownHeight = height
	}
}

func (s *SyncEngine) BestKnownHeight() uint64 {
	if s == nil {
		return 0
	}
	return s.bestKnownHeight
}

func (s *SyncEngine) IsInIBD(nowUnix uint64) bool {
	if s == nil || s.chainState == nil {
		return true
	}
	if !s.chainState.HasTip {
		return true
	}
	if nowUnix < s.tipTimestamp {
		return true
	}
	return nowUnix-s.tipTimestamp > s.cfg.IBDLagSeconds
}

func (s *SyncEngine) ApplyBlock(blockBytes []byte, prevTimestamps []uint64) (*ChainStateConnectSummary, error) {
	if s == nil || s.chainState == nil {
		return nil, errors.New("sync engine is not initialized")
	}

	snapshot, err := stateToDisk(s.chainState)
	if err != nil {
		return nil, err
	}
	oldTipTimestamp := s.tipTimestamp
	oldBestKnown := s.bestKnownHeight

	summary, err := s.chainState.ConnectBlock(blockBytes, s.cfg.ExpectedTarget, prevTimestamps, s.cfg.ChainID)
	if err != nil {
		return nil, err
	}
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		restoreChainState(s.chainState, snapshot)
		return nil, err
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		restoreChainState(s.chainState, snapshot)
		return nil, err
	}

	if s.blockStore != nil {
		if err := s.blockStore.PutBlock(summary.BlockHeight, blockHash, pb.HeaderBytes, blockBytes); err != nil {
			restoreChainState(s.chainState, snapshot)
			s.tipTimestamp = oldTipTimestamp
			s.bestKnownHeight = oldBestKnown
			return nil, err
		}
	}
	if s.cfg.ChainStatePath != "" {
		if err := s.chainState.Save(s.cfg.ChainStatePath); err != nil {
			restoreChainState(s.chainState, snapshot)
			s.tipTimestamp = oldTipTimestamp
			s.bestKnownHeight = oldBestKnown
			return nil, err
		}
	}

	s.tipTimestamp = pb.Header.Timestamp
	if summary.BlockHeight > s.bestKnownHeight {
		s.bestKnownHeight = summary.BlockHeight
	}
	return summary, nil
}

func restoreChainState(dst *ChainState, snapshot chainStateDisk) {
	if dst == nil {
		return
	}
	recovered, err := chainStateFromDisk(snapshot)
	if err != nil {
		return
	}
	*dst = *recovered
}
