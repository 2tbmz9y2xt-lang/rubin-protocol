package node

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
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

func (s *SyncEngine) ApplyBlock(blockBytes []byte, prevTimestamps []uint64) (*ChainStateConnectSummary, error) {
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	return s.applyCanonicalParsedBlock(pb, blockBytes, prevTimestamps)
}

func (s *SyncEngine) SetMempool(mempool *Mempool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mempool = mempool
}

func (s *SyncEngine) HeaderSyncRequest() HeaderRequest {
	if s == nil || s.chainState == nil {
		return HeaderRequest{}
	}
	if !s.chainState.HasTip {
		return HeaderRequest{Limit: s.cfg.HeaderBatchLimit}
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
	if nowUnix < tipTimestamp {
		return true
	}
	return nowUnix-tipTimestamp > ibdLag
}

type mempoolSnapshot struct {
	entries []mempoolEntry
}

type syncRollbackState struct {
	chainState      chainStateDisk
	canonicalIndex  []string
	mempool         mempoolSnapshot
	tipTimestamp    uint64
	bestKnownHeight uint64
	lastReorgDepth  uint64
	reorgCount      uint64
}

func (s *SyncEngine) captureRollbackState() (syncRollbackState, error) {
	snapshot, err := stateToDisk(s.chainState)
	if err != nil {
		return syncRollbackState{}, err
	}
	var canonicalIndex []string
	if s.blockStore != nil {
		canonicalIndex, err = s.blockStore.CanonicalIndexSnapshot()
		if err != nil {
			return syncRollbackState{}, err
		}
	}
	mempoolState, err := snapshotMempool(s.mempool)
	if err != nil {
		return syncRollbackState{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return syncRollbackState{
		chainState:      snapshot,
		canonicalIndex:  canonicalIndex,
		mempool:         mempoolState,
		tipTimestamp:    s.tipTimestamp,
		bestKnownHeight: s.bestKnownHeight,
		lastReorgDepth:  s.lastReorgDepth,
		reorgCount:      s.reorgCount,
	}, nil
}

func (s *SyncEngine) rollbackApplyBlock(cause error, state syncRollbackState) error {
	restoreErr := func() error {
		if s.chainState == nil {
			return errors.New("nil chainstate destination")
		}
		recovered, err := chainStateFromDisk(state.chainState)
		if err != nil {
			return err
		}
		*s.chainState = *recovered
		return nil
	}()
	if s.blockStore != nil {
		if bsErr := s.blockStore.RestoreCanonicalIndex(state.canonicalIndex); bsErr != nil && restoreErr == nil {
			restoreErr = bsErr
		}
	}
	if mpErr := restoreMempoolSnapshot(s.mempool, state.mempool); mpErr != nil && restoreErr == nil {
		restoreErr = mpErr
	}
	if restoreErr == nil && s.cfg.ChainStatePath != "" {
		if saveErr := s.chainState.Save(s.cfg.ChainStatePath); saveErr != nil {
			restoreErr = saveErr
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
	var zeroID [32]byte
	if blockHeight == 0 && s.cfg.ChainID != zeroID && s.cfg.ChainID != devnetGenesisChainID {
		return nil, errors.New("genesis chain_id mismatch")
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

func snapshotMempool(m *Mempool) (mempoolSnapshot, error) {
	if m == nil {
		return mempoolSnapshot{}, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := make([]mempoolEntry, 0, len(m.txs))
	for _, entry := range m.txs {
		entries = append(entries, cloneMempoolEntry(entry))
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].txid[:], entries[j].txid[:]) < 0
	})
	return mempoolSnapshot{entries: entries}, nil
}

func restoreMempoolSnapshot(m *Mempool, snapshot mempoolSnapshot) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.txs = make(map[[32]byte]*mempoolEntry, len(snapshot.entries))
	m.spenders = make(map[consensus.Outpoint][32]byte)
	for _, item := range snapshot.entries {
		entry := cloneMempoolEntry(&item)
		m.txs[entry.txid] = &entry
		for _, op := range entry.inputs {
			m.spenders[op] = entry.txid
		}
	}
	return nil
}

func cloneMempoolEntry(entry *mempoolEntry) mempoolEntry {
	if entry == nil {
		return mempoolEntry{}
	}
	return mempoolEntry{
		raw:    append([]byte(nil), entry.raw...),
		txid:   entry.txid,
		inputs: append([]consensus.Outpoint(nil), entry.inputs...),
		fee:    entry.fee,
		weight: entry.weight,
		size:   entry.size,
	}
}

func (s *SyncEngine) prepareHeavierBranch(
	branch []reorgBranchBlock,
	commonAncestorHeight uint64,
	prevTimestamps []uint64,
	rollbackState syncRollbackState,
) ([][]byte, uint64, error) {
	previewState, err := chainStateFromDisk(rollbackState.chainState)
	if err != nil {
		return nil, 0, err
	}
	disconnectedBlocks, reorgDepth, err := s.previewDisconnectCanonicalToAncestor(previewState, commonAncestorHeight)
	if err != nil {
		return nil, 0, err
	}
	for _, item := range branch {
		if _, err := previewState.ConnectBlock(item.blockBytes, s.cfg.ExpectedTarget, prevTimestamps, s.cfg.ChainID); err != nil {
			return nil, 0, err
		}
	}
	return disconnectedBlocks, reorgDepth, nil
}

func (s *SyncEngine) previewDisconnectCanonicalToAncestor(previewState *ChainState, commonAncestorHeight uint64) ([][]byte, uint64, error) {
	if previewState == nil {
		return nil, 0, nil
	}
	currentTipHeight := previewState.Height
	reorgDepth := currentTipHeight - commonAncestorHeight
	disconnectedBlocks := make([][]byte, 0, reorgDepth)
	for currentTipHeight > commonAncestorHeight {
		tipHash := previewState.TipHash
		blockBytes, err := s.blockStore.GetBlockByHash(tipHash)
		if err != nil {
			return nil, 0, err
		}
		undo, err := s.blockStore.GetUndo(tipHash)
		if err != nil {
			return nil, 0, err
		}
		if _, err := previewState.DisconnectBlock(blockBytes, undo); err != nil {
			return nil, 0, err
		}
		disconnectedBlocks = append(disconnectedBlocks, append([]byte(nil), blockBytes...))
		currentTipHeight--
	}
	return disconnectedBlocks, reorgDepth, nil
}

type reorgBranchBlock struct {
	hash       [32]byte
	blockBytes []byte
	parsed     *consensus.ParsedBlock
	header     consensus.BlockHeader
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

	if summary, handled, err := s.applyDirectBlockIfPossible(pb, blockBytes, prevTimestamps); handled {
		return summary, err
	}
	if s.blockStore == nil {
		return nil, &consensus.TxError{Code: consensus.BLOCK_ERR_LINKAGE_INVALID, Msg: "missing blockstore for side-chain block"}
	}

	branch, commonAncestorHash, commonAncestorHeight, err := s.collectBranchToCanonical(blockHash, blockBytes, pb)
	if err != nil {
		return nil, err
	}
	switchToBranch, candidateHeight, err := s.shouldSwitchToBranch(branch, commonAncestorHash, commonAncestorHeight)
	if err != nil {
		return nil, err
	}
	if !switchToBranch {
		if _, err := consensus.ValidateBlockBasicWithContextAtHeight(blockBytes, &pb.Header.PrevBlockHash, s.cfg.ExpectedTarget, candidateHeight, prevTimestamps); err != nil {
			return nil, err
		}
		if err := s.blockStore.StoreBlock(blockHash, pb.HeaderBytes, blockBytes); err != nil {
			return nil, err
		}
		return s.syntheticSideChainSummary(candidateHeight, blockHash), nil
	}
	return s.applyHeavierBranch(branch, commonAncestorHeight, prevTimestamps)
}

func (s *SyncEngine) applyDirectBlockIfPossible(
	pb *consensus.ParsedBlock,
	blockBytes []byte,
	prevTimestamps []uint64,
) (*ChainStateConnectSummary, bool, error) {
	var zero [32]byte
	switch {
	case !s.chainState.HasTip:
		if pb.Header.PrevBlockHash != zero {
			return nil, true, ErrParentNotFound
		}
		summary, err := s.applyCanonicalParsedBlock(pb, blockBytes, prevTimestamps)
		return summary, true, err
	case pb.Header.PrevBlockHash == s.chainState.TipHash:
		summary, err := s.applyCanonicalParsedBlock(pb, blockBytes, prevTimestamps)
		return summary, true, err
	default:
		return nil, false, nil
	}
}

func (s *SyncEngine) shouldSwitchToBranch(
	branch []reorgBranchBlock,
	commonAncestorHash [32]byte,
	commonAncestorHeight uint64,
) (bool, uint64, error) {
	_, currentTipHash, err := s.currentCanonicalTip()
	if err != nil {
		return false, 0, err
	}

	currentWork, err := s.blockStore.ChainWork(currentTipHash)
	if err != nil {
		return false, 0, err
	}
	ancestorWork, err := s.blockStore.ChainWork(commonAncestorHash)
	if err != nil {
		return false, 0, err
	}
	branchTargets := make([][32]byte, 0, len(branch))
	for _, item := range branch {
		branchTargets = append(branchTargets, item.header.Target)
	}
	branchWork, err := consensus.ChainWorkFromTargets(branchTargets)
	if err != nil {
		return false, 0, err
	}
	candidateWork := new(big.Int).Add(new(big.Int).Set(ancestorWork), branchWork)
	candidateHeight := commonAncestorHeight + uint64(len(branch))
	return candidateWork.Cmp(currentWork) > 0, candidateHeight, nil
}

func (s *SyncEngine) applyHeavierBranch(
	branch []reorgBranchBlock,
	commonAncestorHeight uint64,
	prevTimestamps []uint64,
) (*ChainStateConnectSummary, error) {
	rollbackState, err := s.captureRollbackState()
	if err != nil {
		return nil, err
	}
	disconnectedBlocks, reorgDepth, err := s.prepareHeavierBranch(branch, commonAncestorHeight, prevTimestamps, rollbackState)
	if err != nil {
		return nil, err
	}
	if _, _, err := s.disconnectCanonicalToAncestor(commonAncestorHeight); err != nil {
		return nil, s.rollbackApplyBlock(err, rollbackState)
	}

	var summary *ChainStateConnectSummary
	for _, item := range branch {
		summary, err = s.applyCanonicalParsedBlock(item.parsed, item.blockBytes, prevTimestamps)
		if err != nil {
			return nil, s.rollbackApplyBlock(err, rollbackState)
		}
	}
	s.requeueDisconnectedTransactions(disconnectedBlocks)
	s.noteReorg(reorgDepth)
	return summary, nil
}

func (s *SyncEngine) disconnectCanonicalToAncestor(commonAncestorHeight uint64) ([][]byte, uint64, error) {
	currentTipHeight, _, err := s.currentCanonicalTip()
	if err != nil {
		return nil, 0, err
	}
	reorgDepth := currentTipHeight - commonAncestorHeight
	disconnectedBlocks := make([][]byte, 0, reorgDepth)
	for currentTipHeight > commonAncestorHeight {
		_, tipHash, err := s.currentCanonicalTip()
		if err != nil {
			return nil, 0, err
		}
		disconnectedBlockBytes, err := s.blockStore.GetBlockByHash(tipHash)
		if err != nil {
			return nil, 0, err
		}
		disconnectedBlocks = append(disconnectedBlocks, append([]byte(nil), disconnectedBlockBytes...))
		if _, err := s.DisconnectTip(); err != nil {
			return nil, 0, err
		}
		currentTipHeight--
	}
	return disconnectedBlocks, reorgDepth, nil
}

func (s *SyncEngine) DisconnectTip() (*ChainStateDisconnectSummary, error) {
	if s == nil || s.chainState == nil {
		return nil, errors.New("sync engine is not initialized")
	}
	if s.blockStore == nil {
		return nil, errors.New("sync engine has no blockstore")
	}

	tipHeight, tipHash, err := s.currentCanonicalTip()
	if err != nil {
		return nil, err
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
	newTipTimestamp := uint64(0)
	if tipHeight > 0 {
		parentHeaderBytes, err := s.blockStore.GetHeaderByHash(pb.Header.PrevBlockHash)
		if err != nil {
			return nil, err
		}
		parentHeader, err := consensus.ParseBlockHeaderBytes(parentHeaderBytes)
		if err != nil {
			return nil, err
		}
		newTipTimestamp = parentHeader.Timestamp
	}

	summary, err := s.chainState.DisconnectBlock(blockBytes, undo)
	if err != nil {
		return nil, err
	}
	if err := s.blockStore.TruncateCanonical(uint64(len(rollbackState.canonicalIndex)) - 1); err != nil {
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
			if errors.Is(err, os.ErrNotExist) {
				return nil, [32]byte{}, 0, ErrParentNotFound
			}
			return nil, [32]byte{}, 0, err
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

func (s *SyncEngine) requeueDisconnectedTransactions(disconnectedBlocks [][]byte) {
	if s == nil || s.mempool == nil || len(disconnectedBlocks) == 0 {
		return
	}
	for blockIndex := len(disconnectedBlocks) - 1; blockIndex >= 0; blockIndex-- {
		txs, err := nonCoinbaseBlockTransactions(disconnectedBlocks[blockIndex])
		if err != nil {
			continue
		}
		for _, txBytes := range txs {
			_ = s.mempool.AddTx(txBytes)
		}
	}
}

func nonCoinbaseBlockTransactions(blockBytes []byte) ([][]byte, error) {
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	if len(pb.Txs) <= 1 {
		return nil, nil
	}
	txs := make([][]byte, 0, len(pb.Txs)-1)
	for txIndex := 1; txIndex < len(pb.Txs); txIndex++ {
		txBytes, err := consensus.MarshalTx(pb.Txs[txIndex])
		if err != nil {
			return nil, err
		}
		txs = append(txs, txBytes)
	}
	return txs, nil
}

func reverseBranchBlocks(branch []reorgBranchBlock) {
	for left, right := 0, len(branch)-1; left < right; left, right = left+1, right-1 {
		branch[left], branch[right] = branch[right], branch[left]
	}
}

func (s *SyncEngine) currentCanonicalTip() (uint64, [32]byte, error) {
	height, tipHash, ok, err := s.blockStore.Tip()
	if err != nil {
		return 0, [32]byte{}, err
	}
	if !ok {
		return 0, [32]byte{}, errors.New("blockstore has no canonical tip")
	}
	return height, tipHash, nil
}
