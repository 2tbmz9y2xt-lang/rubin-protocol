package node

import (
	"errors"
	"math/big"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func (s *ChainState) ConnectBlock(
	blockBytes []byte,
	expectedTarget *[32]byte,
	prevTimestamps []uint64,
	chainID [32]byte,
) (*ChainStateConnectSummary, error) {
	return s.ConnectBlockWithCoreExtProfiles(blockBytes, expectedTarget, prevTimestamps, chainID, nil)
}

func (s *ChainState) ConnectBlockWithCoreExtProfiles(
	blockBytes []byte,
	expectedTarget *[32]byte,
	prevTimestamps []uint64,
	chainID [32]byte,
	coreExtProfiles any,
) (*ChainStateConnectSummary, error) {
	return s.ConnectBlockWithCoreExtProfilesAndSuiteContext(
		blockBytes,
		expectedTarget,
		prevTimestamps,
		chainID,
		coreExtProfiles,
		s.rotationOrNil(),
		s.registryOrNil(),
	)
}

func (s *ChainState) ConnectBlockWithCoreExtProfilesAndSuiteContext(
	blockBytes []byte,
	expectedTarget *[32]byte,
	prevTimestamps []uint64,
	chainID [32]byte,
	coreExtProfiles any,
	rotation consensus.RotationProvider,
	registry *consensus.SuiteRegistry,
) (*ChainStateConnectSummary, error) {
	if s == nil {
		return nil, errors.New("nil chainstate")
	}
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	blockHeight, expectedPrevHash, workState, err := s.connectBlockWorkStateLocked(false)
	if err != nil {
		return nil, err
	}
	summary, err := consensus.ConnectBlockBasicInMemoryAtHeightAndCoreExtProfilesAndSuiteContext(
		blockBytes,
		expectedPrevHash,
		expectedTarget,
		blockHeight,
		prevTimestamps,
		&workState,
		chainID,
		coreExtProfiles,
		rotation,
		registry,
	)
	if err != nil {
		return nil, err
	}

	blockHash, err := connectedBlockHash(blockBytes)
	if err != nil {
		return nil, err
	}
	if err := s.applyConnectedBlockLocked(blockHeight, blockHash, &workState); err != nil {
		return nil, err
	}
	return chainStateConnectSummary(blockHeight, blockHash, blockBytes, summary), nil
}

// ConnectBlockParallelSigs connects a block using parallel signature
// verification. This is an IBD optimization: pre-checks are sequential,
// ML-DSA-87 signature verifications are batched and executed across a
// goroutine pool. See consensus.ConnectBlockParallelSigVerify for details.
//
// workers controls the goroutine pool size. If <= 0, defaults to GOMAXPROCS.
func (s *ChainState) ConnectBlockParallelSigs(
	blockBytes []byte,
	expectedTarget *[32]byte,
	prevTimestamps []uint64,
	chainID [32]byte,
	coreExtProfiles any,
	workers int,
) (*ChainStateConnectSummary, error) {
	return s.ConnectBlockParallelSigsWithSuiteContext(
		blockBytes,
		expectedTarget,
		prevTimestamps,
		chainID,
		coreExtProfiles,
		s.rotationOrNil(),
		s.registryOrNil(),
		workers,
	)
}

func (s *ChainState) ConnectBlockParallelSigsWithSuiteContext(
	blockBytes []byte,
	expectedTarget *[32]byte,
	prevTimestamps []uint64,
	chainID [32]byte,
	coreExtProfiles any,
	rotation consensus.RotationProvider,
	registry *consensus.SuiteRegistry,
	workers int,
) (*ChainStateConnectSummary, error) {
	if s == nil {
		return nil, errors.New("nil chainstate")
	}
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	blockHeight, expectedPrevHash, workState, err := s.connectBlockWorkStateLocked(true)
	if err != nil {
		return nil, err
	}
	summary, err := consensus.ConnectBlockParallelSigVerifyWithCoreExtProfilesAndSuiteContext(
		blockBytes,
		expectedPrevHash,
		expectedTarget,
		blockHeight,
		prevTimestamps,
		&workState,
		chainID,
		coreExtProfiles,
		rotation,
		registry,
		workers,
	)
	if err != nil {
		return nil, err
	}

	blockHash, err := connectedBlockHash(blockBytes)
	if err != nil {
		return nil, err
	}
	if err := s.applyConnectedBlockLocked(blockHeight, blockHash, &workState); err != nil {
		return nil, err
	}
	out := chainStateConnectSummary(blockHeight, blockHash, blockBytes, summary)
	out.SigTaskCount = summary.SigTaskCount
	out.WorkerPanics = summary.WorkerPanics
	return out, nil
}

func (s *ChainState) connectBlockWorkStateLocked(copyUtxos bool) (uint64, *[32]byte, consensus.InMemoryChainState, error) {
	blockHeight, expectedPrevHash, err := nextBlockContextFromFields(s.HasTip, s.Height, s.TipHash)
	if err != nil {
		return 0, nil, consensus.InMemoryChainState{}, err
	}
	if s.Utxos == nil {
		s.Utxos = make(map[consensus.Outpoint]consensus.UtxoEntry)
	}
	utxos := s.Utxos
	if copyUtxos {
		utxos = copyUtxoSet(s.Utxos)
	}
	return blockHeight, expectedPrevHash, consensus.InMemoryChainState{
		Utxos:            utxos,
		AlreadyGenerated: new(big.Int).SetUint64(s.AlreadyGenerated),
	}, nil
}

func connectedBlockHash(blockBytes []byte) ([32]byte, error) {
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return [32]byte{}, err
	}
	return consensus.BlockHash(pb.HeaderBytes)
}

func (s *ChainState) applyConnectedBlockLocked(blockHeight uint64, blockHash [32]byte, workState *consensus.InMemoryChainState) error {
	// Fail-atomic: check overflow BEFORE any state mutation so that an error
	// does not leave ChainState partially updated.
	if !workState.AlreadyGenerated.IsUint64() {
		return errors.New("already_generated overflow")
	}
	s.HasTip = true
	s.Height = blockHeight
	s.TipHash = blockHash
	s.AlreadyGenerated = workState.AlreadyGenerated.Uint64()
	s.Utxos = workState.Utxos
	return nil
}

// chainStateConnectSummary builds the connect summary for a block that has just
// been applied to the canonical tip. A successful ConnectBlock* call always
// advances the canonical chain by exactly this block, so the summary reports it
// as the single canonical-applied block (RUB-431). Reorg accumulation across a
// branch is layered on top in applyPreferredBranch.
func chainStateConnectSummary(blockHeight uint64, blockHash [32]byte, blockBytes []byte, summary *consensus.ConnectBlockBasicSummary) *ChainStateConnectSummary {
	return &ChainStateConnectSummary{
		BlockHeight:        blockHeight,
		BlockHash:          blockHash,
		SumFees:            summary.SumFees,
		AlreadyGenerated:   summary.AlreadyGenerated,
		AlreadyGeneratedN1: summary.AlreadyGeneratedN1,
		UtxoCount:          summary.UtxoCount,
		CanonicalAppliedBlocks: []CanonicalAppliedBlock{{
			Hash:       blockHash,
			BlockBytes: append([]byte(nil), blockBytes...),
		}},
		PostStateDigest: summary.PostStateDigest,
	}
}
