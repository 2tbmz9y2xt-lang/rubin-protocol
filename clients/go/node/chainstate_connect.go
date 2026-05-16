package node

import (
	"errors"
	"math"
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
	coreExtProfiles consensus.CoreExtProfileProvider,
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
	coreExtProfiles consensus.CoreExtProfileProvider,
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
	return chainStateConnectSummary(blockHeight, blockHash, summary), nil
}

// UtxoSetHash returns the deterministic SHA3-256 digest over the current UTXO
// set. It is bit-identical with the Rust node ChainState::utxo_set_hash() and
// uses the same canonical encoding as consensus.UtxoSetHash (which produces
// PostStateDigest in ConnectBlock summaries). On a nil receiver returns the
// digest of an empty UTXO map for definedness.
//
// Cost: O(n log n) over the entire UTXO set (sort by outpoint canonical key)
// plus one SHA3-256 hash + per-entry allocations for the canonical encoding.
// Intended for low-frequency inspection / parity-vector verification — do
// NOT call from hot paths or polling loops. If a caller needs incremental
// digest updates, fold the maintenance into ConnectBlock / DisconnectTip
// instead of calling this.
func (s *ChainState) UtxoSetHash() [32]byte {
	if s == nil {
		return consensus.UtxoSetHash(nil)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return consensus.UtxoSetHash(s.Utxos)
}

// StateDigest is an alias for UtxoSetHash that mirrors the Rust node
// ChainState::state_digest() surface. Today the chain state digest is exactly
// the UTXO set hash; the two names are kept in parity with Rust so that
// inspection callers can reach for either spelling.
func (s *ChainState) StateDigest() [32]byte {
	return s.UtxoSetHash()
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
	coreExtProfiles consensus.CoreExtProfileProvider,
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
	coreExtProfiles consensus.CoreExtProfileProvider,
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
	return chainStateParallelConnectSummary(blockHeight, blockHash, summary), nil
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

func chainStateConnectSummary(blockHeight uint64, blockHash [32]byte, summary *consensus.ConnectBlockBasicSummary) *ChainStateConnectSummary {
	return &ChainStateConnectSummary{
		BlockHeight:        blockHeight,
		BlockHash:          blockHash,
		SumFees:            summary.SumFees,
		AlreadyGenerated:   summary.AlreadyGenerated,
		AlreadyGeneratedN1: summary.AlreadyGeneratedN1,
		UtxoCount:          summary.UtxoCount,
		PostStateDigest:    summary.PostStateDigest,
	}
}

func chainStateParallelConnectSummary(blockHeight uint64, blockHash [32]byte, summary *consensus.ConnectBlockBasicSummary) *ChainStateConnectSummary {
	out := chainStateConnectSummary(blockHeight, blockHash, summary)
	out.SigTaskCount = summary.SigTaskCount
	out.WorkerPanics = summary.WorkerPanics
	return out
}

func nextBlockContext(s *ChainState) (uint64, *[32]byte, error) {
	if s == nil {
		return 0, nil, errors.New("nil chainstate")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return nextBlockContextFromFields(s.HasTip, s.Height, s.TipHash)
}

func nextBlockContextFromFields(hasTip bool, height uint64, tipHash [32]byte) (uint64, *[32]byte, error) {
	if !hasTip {
		return 0, nil, nil
	}
	if height == math.MaxUint64 {
		return 0, nil, errors.New("height overflow")
	}
	nextHeight := height + 1
	prev := tipHash
	return nextHeight, &prev, nil
}
