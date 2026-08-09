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
	return s.ConnectBlockWithSuiteContext(
		blockBytes,
		expectedTarget,
		prevTimestamps,
		chainID,
		s.rotationOrNil(),
		s.registryOrNil(),
	)
}

func (s *ChainState) ConnectBlockWithSuiteContext(
	blockBytes []byte,
	expectedTarget *[32]byte,
	prevTimestamps []uint64,
	chainID [32]byte,
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
	summary, err := consensus.ConnectBlockBasicInMemoryAtHeightAndSuiteContext(
		blockBytes,
		expectedPrevHash,
		expectedTarget,
		blockHeight,
		prevTimestamps,
		&workState,
		chainID,
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
	return s.applyConnectedBlockLocked(blockHeight, blockHash, &workState, summary)
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
	workers int,
) (*ChainStateConnectSummary, error) {
	return s.ConnectBlockParallelSigsWithSuiteContext(
		blockBytes,
		expectedTarget,
		prevTimestamps,
		chainID,
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
	summary, err := consensus.ConnectBlockParallelSigVerifyWithSuiteContext(
		blockBytes,
		expectedPrevHash,
		expectedTarget,
		blockHeight,
		prevTimestamps,
		&workState,
		chainID,
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
	return s.applyConnectedBlockLocked(blockHeight, blockHash, &workState, summary)
}

func (s *ChainState) connectBlockWorkStateLocked(copyUtxos bool) (uint64, *[32]byte, consensus.InMemoryChainState, error) {
	blockHeight, expectedPrevHash, err := nextBlockContextFromFields(s.HasTip, s.Height, s.TipHash)
	if err != nil {
		return 0, nil, consensus.InMemoryChainState{}, err
	}
	utxos := s.Utxos
	if utxos == nil {
		utxos = make(map[consensus.Outpoint]consensus.UtxoEntry)
	}
	if copyUtxos {
		utxos = copyUtxoSet(s.Utxos)
	}
	return blockHeight, expectedPrevHash, consensus.InMemoryChainState{
		Utxos:            utxos,
		AlreadyGenerated: s.AlreadyGenerated.Big(),
	}, nil
}

func connectedBlockHash(blockBytes []byte) ([32]byte, error) {
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return [32]byte{}, err
	}
	return consensus.BlockHash(pb.HeaderBytes)
}

func (s *ChainState) applyConnectedBlockLocked(blockHeight uint64, blockHash [32]byte, workState *consensus.InMemoryChainState, summary *consensus.ConnectBlockBasicSummary) (*ChainStateConnectSummary, error) {
	alreadyGeneratedState, err := bigIntToUint128Exact(workState.AlreadyGenerated)
	if err != nil {
		return nil, err
	}
	out := &ChainStateConnectSummary{
		BlockHeight:        blockHeight,
		BlockHash:          blockHash,
		SumFees:            summary.SumFees,
		AlreadyGenerated:   summary.AlreadyGenerated,
		AlreadyGeneratedN1: summary.AlreadyGeneratedN1,
		UtxoCount:          summary.UtxoCount,
		PostStateDigest:    summary.PostStateDigest,
		SigTaskCount:       summary.SigTaskCount,
		WorkerPanics:       summary.WorkerPanics,
	}

	s.HasTip = true
	s.Height = blockHeight
	s.TipHash = blockHash
	s.AlreadyGenerated = alreadyGeneratedState
	s.Utxos = workState.Utxos
	return out, nil
}

func bigIntToUint128Exact(value *big.Int) (consensus.Uint128, error) {
	if value == nil || value.Sign() < 0 || value.BitLen() > 128 {
		return consensus.Uint128{}, errors.New("already_generated overflow")
	}
	out, err := consensus.ParseUint128Decimal(value.String())
	if err != nil {
		return consensus.Uint128{}, errors.New("already_generated overflow")
	}
	return out, nil
}
