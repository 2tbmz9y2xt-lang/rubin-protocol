package node

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const defaultIBDLagSeconds = 24 * 60 * 60

var ErrParentNotFound = errors.New("parent block not found")

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
	lastReorgDepth  uint64
	reorgCount      uint64
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

func (s *SyncEngine) LastReorgDepth() uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastReorgDepth
}

func (s *SyncEngine) ReorgCount() uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.reorgCount
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
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	return s.applyCanonicalParsedBlock(pb, blockBytes, prevTimestamps)
}

func (s *SyncEngine) ApplyBlockWithReorg(blockBytes []byte, prevTimestamps []uint64) (*ChainStateConnectSummary, error) {
	if s == nil || s.chainState == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		return nil, err
	}

	var zero [32]byte
	if !s.chainState.HasTip {
		if pb.Header.PrevBlockHash != zero {
			return nil, ErrParentNotFound
		}
		return s.applyCanonicalParsedBlock(pb, blockBytes, prevTimestamps)
	}
	if pb.Header.PrevBlockHash == s.chainState.TipHash {
		return s.applyCanonicalParsedBlock(pb, blockBytes, prevTimestamps)
	}
	if s.blockStore == nil {
		return nil, &consensus.TxError{Code: consensus.BLOCK_ERR_LINKAGE_INVALID, Msg: "missing blockstore for side-chain block"}
	}

	branch, commonAncestorHash, commonAncestorHeight, err := s.collectBranchToCanonical(blockHash, blockBytes, pb)
	if err != nil {
		return nil, err
	}
	currentTipHeight, currentTipHash, ok, err := s.blockStore.Tip()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("blockstore has no canonical tip")
	}

	currentWork, err := s.blockStore.ChainWork(currentTipHash)
	if err != nil {
		return nil, err
	}
	ancestorWork, err := s.blockStore.ChainWork(commonAncestorHash)
	if err != nil {
		return nil, err
	}
	branchTargets := make([][32]byte, 0, len(branch))
	for _, item := range branch {
		branchTargets = append(branchTargets, item.header.Target)
	}
	branchWork, err := consensus.ChainWorkFromTargets(branchTargets)
	if err != nil {
		return nil, err
	}
	candidateWork := new(big.Int).Add(new(big.Int).Set(ancestorWork), branchWork)
	candidateHeight := commonAncestorHeight + uint64(len(branch))
	if candidateWork.Cmp(currentWork) <= 0 {
		if err := s.blockStore.StoreBlock(blockHash, pb.HeaderBytes, blockBytes); err != nil {
			return nil, err
		}
		return s.syntheticSideChainSummary(candidateHeight, blockHash), nil
	}

	rollbackState, err := s.captureRollbackState()
	if err != nil {
		return nil, err
	}
	reorgDepth := currentTipHeight - commonAncestorHeight
	for currentTipHeight > commonAncestorHeight {
		if _, err := s.DisconnectTip(); err != nil {
			return nil, s.rollbackApplyBlock(err, rollbackState)
		}
		currentTipHeight--
	}

	var summary *ChainStateConnectSummary
	for _, item := range branch {
		summary, err = s.applyCanonicalParsedBlock(item.parsed, item.blockBytes, prevTimestamps)
		if err != nil {
			return nil, s.rollbackApplyBlock(err, rollbackState)
		}
	}
	s.noteReorg(reorgDepth)
	return summary, nil
}

func (s *SyncEngine) DisconnectTip() (*ChainStateDisconnectSummary, error) {
	if s == nil || s.chainState == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	if s.blockStore == nil {
		return nil, errors.New("sync engine has no blockstore")
	}

	tipHeight, tipHash, ok, err := s.blockStore.Tip()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("blockstore has no tip")
	}
	if !s.chainState.HasTip || s.chainState.Height != tipHeight || s.chainState.TipHash != tipHash {
		return nil, errors.New("chainstate tip does not match blockstore tip")
	}

	blockBytes, err := s.blockStore.GetBlockByHash(tipHash)
	if err != nil {
		return nil, err
	}
	undo, err := s.blockStore.GetUndo(tipHash)
	if err != nil {
		return nil, err
	}
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}

	rollbackState, err := s.captureRollbackState()
	if err != nil {
		return nil, err
	}
	newTipTimestamp, err := parentTipTimestamp(s.blockStore, tipHeight, pb.Header.PrevBlockHash)
	if err != nil {
		return nil, err
	}

	summary, err := s.chainState.DisconnectBlock(blockBytes, undo)
	if err != nil {
		return nil, err
	}
	if err := s.blockStore.TruncateCanonical(rollbackState.canonicalCount - 1); err != nil {
		return nil, s.rollbackApplyBlock(err, rollbackState)
	}
	if s.cfg.ChainStatePath != "" {
		if err := s.chainState.Save(s.cfg.ChainStatePath); err != nil {
			return nil, s.rollbackApplyBlock(err, rollbackState)
		}
	}

	s.mu.Lock()
	s.tipTimestamp = newTipTimestamp
	s.bestKnownHeight = rollbackState.bestKnownHeight
	s.mu.Unlock()
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
	canonicalCount  uint64
	tipTimestamp    uint64
	bestKnownHeight uint64
	lastReorgDepth  uint64
	reorgCount      uint64
}

type reorgBranchBlock struct {
	hash       [32]byte
	blockBytes []byte
	parsed     *consensus.ParsedBlock
	header     consensus.BlockHeader
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
	canonicalCount, err := blockStoreCanonicalCount(s.blockStore)
	if err != nil {
		return syncRollbackState{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return syncRollbackState{
		chainState:      snapshot,
		canonicalCount:  canonicalCount,
		tipTimestamp:    s.tipTimestamp,
		bestKnownHeight: s.bestKnownHeight,
		lastReorgDepth:  s.lastReorgDepth,
		reorgCount:      s.reorgCount,
	}, nil
}

func (s *SyncEngine) rollbackApplyBlock(cause error, state syncRollbackState) error {
	restoreErr := restoreChainState(s.chainState, state.chainState)
	if s.blockStore != nil {
		if bsErr := s.blockStore.TruncateCanonical(state.canonicalCount); bsErr != nil && restoreErr == nil {
			restoreErr = bsErr
		}
	}
	s.mu.Lock()
	s.tipTimestamp = state.tipTimestamp
	s.bestKnownHeight = state.bestKnownHeight
	s.lastReorgDepth = state.lastReorgDepth
	s.reorgCount = state.reorgCount
	s.mu.Unlock()
	if restoreErr != nil {
		return fmt.Errorf("%w (rollback failed: %v)", cause, restoreErr)
	}
	return cause
}

func (s *SyncEngine) applyCanonicalParsedBlock(
	pb *consensus.ParsedBlock,
	blockBytes []byte,
	prevTimestamps []uint64,
) (*ChainStateConnectSummary, error) {
	if s == nil || s.chainState == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	if pb == nil {
		return nil, errors.New("nil parsed block")
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
	prevState, err := chainStateFromDisk(rollbackState.chainState)
	if err != nil {
		return nil, err
	}
	summary, err := s.chainState.ConnectBlock(blockBytes, s.cfg.ExpectedTarget, prevTimestamps, s.cfg.ChainID)
	if err != nil {
		return nil, err
	}
	if err := s.persistAppliedBlock(summary, blockHash, pb, blockBytes, prevState); err != nil {
		return nil, s.rollbackApplyBlock(err, rollbackState)
	}

	s.recordAppliedBlock(summary.BlockHeight, pb.Header.Timestamp)
	if s.mempool != nil {
		_ = s.mempool.EvictConfirmed(blockBytes)
		_ = s.mempool.RemoveConflicting(blockBytes)
	}
	return summary, nil
}

func (s *SyncEngine) collectBranchToCanonical(
	blockHash [32]byte,
	blockBytes []byte,
	pb *consensus.ParsedBlock,
) ([]reorgBranchBlock, [32]byte, uint64, error) {
	branch := []reorgBranchBlock{{
		hash:       blockHash,
		blockBytes: append([]byte(nil), blockBytes...),
		parsed:     pb,
		header:     pb.Header,
	}}
	parentHash := pb.Header.PrevBlockHash
	for {
		height, found, err := s.blockStore.FindCanonicalHeight(parentHash)
		if err != nil {
			return nil, [32]byte{}, 0, err
		}
		if found {
			reverseBranchBlocks(branch)
			return branch, parentHash, height, nil
		}
		parentBlockBytes, err := s.blockStore.GetBlockByHash(parentHash)
		if err != nil {
			return nil, [32]byte{}, 0, ErrParentNotFound
		}
		parentParsed, err := consensus.ParseBlockBytes(parentBlockBytes)
		if err != nil {
			return nil, [32]byte{}, 0, err
		}
		branch = append(branch, reorgBranchBlock{
			hash:       parentHash,
			blockBytes: parentBlockBytes,
			parsed:     parentParsed,
			header:     parentParsed.Header,
		})
		parentHash = parentParsed.Header.PrevBlockHash
	}
}

func (s *SyncEngine) syntheticSideChainSummary(height uint64, blockHash [32]byte) *ChainStateConnectSummary {
	utxoCount := uint64(0)
	alreadyGenerated := uint64(0)
	if s != nil && s.chainState != nil {
		utxoCount = uint64(len(s.chainState.Utxos))
		alreadyGenerated = s.chainState.AlreadyGenerated
	}
	return &ChainStateConnectSummary{
		BlockHeight:        height,
		BlockHash:          blockHash,
		AlreadyGenerated:   alreadyGenerated,
		AlreadyGeneratedN1: alreadyGenerated,
		UtxoCount:          utxoCount,
	}
}

func (s *SyncEngine) persistAppliedBlock(summary *ChainStateConnectSummary, blockHash [32]byte, pb *consensus.ParsedBlock, blockBytes []byte, prevState *ChainState) error {
	if s.blockStore != nil {
		undo, err := buildBlockUndo(prevState, pb, summary.BlockHeight)
		if err != nil {
			return err
		}
		if err := s.blockStore.PutBlock(summary.BlockHeight, blockHash, pb.HeaderBytes, blockBytes); err != nil {
			return err
		}
		if err := s.blockStore.PutUndo(blockHash, undo); err != nil {
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
	s.lastReorgDepth = 0
}

func (s *SyncEngine) noteReorg(depth uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastReorgDepth = depth
	if depth > 0 {
		s.reorgCount++
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

func blockStoreCanonicalCount(store *BlockStore) (uint64, error) {
	if store == nil {
		return 0, nil
	}
	height, _, ok, err := store.Tip()
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, nil
	}
	return height + 1, nil
}

func parentTipTimestamp(store *BlockStore, tipHeight uint64, prevBlockHash [32]byte) (uint64, error) {
	if tipHeight == 0 {
		return 0, nil
	}
	parentHeaderBytes, err := store.GetHeaderByHash(prevBlockHash)
	if err != nil {
		return 0, err
	}
	parentHeader, err := consensus.ParseBlockHeaderBytes(parentHeaderBytes)
	if err != nil {
		return 0, err
	}
	return parentHeader.Timestamp, nil
}

func reverseBranchBlocks(branch []reorgBranchBlock) {
	for left, right := 0, len(branch)-1; left < right; left, right = left+1, right-1 {
		branch[left], branch[right] = branch[right], branch[left]
	}
}
