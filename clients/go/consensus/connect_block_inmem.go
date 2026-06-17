package consensus

import "math/big"

// InMemoryChainState is a minimal, non-persistent chainstate container intended for
// conformance tests and audit/repro tooling.
//
// It is NOT a full node database: it provides deterministic inputs for stateful checks
// (fee computation, coinbase bound, maturity rules) without any disk persistence.
type InMemoryChainState struct {
	Utxos            map[Outpoint]UtxoEntry
	AlreadyGenerated *big.Int // already_generated(h): subsidy-only, excluding fees
}

type ConnectBlockBasicSummary struct {
	SumFees            uint64
	AlreadyGenerated   uint64
	AlreadyGeneratedN1 uint64
	UtxoCount          uint64
	PostStateDigest    [32]byte

	// SigTaskCount is the number of signature verification tasks dispatched
	// to the worker pool during parallel validation. Zero for sequential path.
	SigTaskCount uint64
	// WorkerPanics is the number of panics recovered in worker goroutines
	// during parallel validation. Zero for sequential path.
	WorkerPanics uint64
}

type connectBlockBasicInMemorySuiteContext struct {
	BlockBytes       []byte
	ExpectedPrevHash *[32]byte
	ExpectedTarget   *[32]byte
	BlockHeight      uint64
	PrevTimestamps   []uint64
	State            *InMemoryChainState
	ChainID          [32]byte
	CoreExtProfiles  CoreExtProfileProvider
	Rotation         RotationProvider
	Registry         *SuiteRegistry
}

type connectBlockInMemoryValidationContext struct {
	chainID         [32]byte
	coreExtProfiles CoreExtProfileProvider
	rotation        RotationProvider
	registry        *SuiteRegistry
}

// ConnectBlockBasicInMemoryAtHeight connects a block against an in-memory UTXO snapshot and an
// in-memory subsidy counter, and enforces the coinbase subsidy/value bound (CANONICAL §19.2)
// using locally computed fees.
//
// This closes the "partial" nature of F-05: sum_fees is computed internally as
// Σ(sum_in - sum_out) over all non-coinbase transactions in the block.
//
// Persistence (writing chainstate to disk) is intentionally out of scope here.
func ConnectBlockBasicInMemoryAtHeight(
	blockBytes []byte,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
	state *InMemoryChainState,
	chainID [32]byte,
) (*ConnectBlockBasicSummary, error) {
	return ConnectBlockBasicInMemoryAtHeightAndCoreExtProfiles(
		blockBytes,
		expectedPrevHash,
		expectedTarget,
		blockHeight,
		prevTimestamps,
		state,
		chainID,
		EmptyCoreExtProfileProvider(),
	)
}

func ConnectBlockBasicInMemoryAtHeightAndCoreExtProfiles(
	blockBytes []byte,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
	state *InMemoryChainState,
	chainID [32]byte,
	coreExtProfiles CoreExtProfileProvider,
) (*ConnectBlockBasicSummary, error) {
	if coreExtProfiles == nil {
		coreExtProfiles = EmptyCoreExtProfileProvider()
	}
	return ConnectBlockBasicInMemoryAtHeightAndCoreExtProfilesAndSuiteContext(
		blockBytes,
		expectedPrevHash,
		expectedTarget,
		blockHeight,
		prevTimestamps,
		state,
		chainID,
		coreExtProfiles,
		nil,
		nil,
	)
}

// #lizard forgive
func ConnectBlockBasicInMemoryAtHeightAndCoreExtProfilesAndSuiteContext(
	blockBytes []byte,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
	state *InMemoryChainState,
	chainID [32]byte,
	coreExtProfiles CoreExtProfileProvider,
	rotation RotationProvider,
	registry *SuiteRegistry,
) (*ConnectBlockBasicSummary, error) {
	return connectBlockBasicInMemoryAtHeightAndCoreExtProfilesAndSuiteContext(connectBlockBasicInMemorySuiteContext{
		BlockBytes:       blockBytes,
		ExpectedPrevHash: expectedPrevHash,
		ExpectedTarget:   expectedTarget,
		BlockHeight:      blockHeight,
		PrevTimestamps:   prevTimestamps,
		State:            state,
		ChainID:          chainID,
		CoreExtProfiles:  normalizedCoreExtProfiles(coreExtProfiles),
		Rotation:         rotation,
		Registry:         registry,
	})
}

func connectBlockBasicInMemoryAtHeightAndCoreExtProfilesAndSuiteContext(
	input connectBlockBasicInMemorySuiteContext,
) (*ConnectBlockBasicSummary, error) {
	if err := prepareInMemoryChainState(input.State); err != nil {
		return nil, err
	}

	pb, err := parseInMemoryConnectBlock(input)
	if err != nil {
		return nil, err
	}

	alreadyGenerated := new(big.Int).Set(input.State.AlreadyGenerated)
	blockMTP, err := inMemoryConnectBlockMTP(input.BlockHeight, input.PrevTimestamps, pb.Header.Timestamp)
	if err != nil {
		return nil, err
	}

	validation := connectBlockInMemoryValidationContext{
		chainID:         input.ChainID,
		coreExtProfiles: input.CoreExtProfiles,
		rotation:        input.Rotation,
		registry:        input.Registry,
	}
	workUtxos, sumFees, err := applyInMemoryNonCoinbaseTxs(
		pb,
		cloneUtxoSet(input.State.Utxos),
		input.BlockHeight,
		blockMTP,
		validation,
	)
	if err != nil {
		return nil, err
	}

	if err := validateCoinbaseValueBound(pb, input.BlockHeight, alreadyGenerated, sumFees); err != nil {
		return nil, err
	}
	if err := validateCoinbaseApplyOutputs(pb.Txs[0]); err != nil {
		return nil, err
	}

	applyInMemoryCoinbaseOutputs(pb, workUtxos, input.BlockHeight)
	alreadyGeneratedN1 := advanceAlreadyGenerated(input.BlockHeight, alreadyGenerated)
	return commitInMemoryConnectSummary(input.State, workUtxos, input.BlockHeight, alreadyGenerated, alreadyGeneratedN1, sumFees)
}

func normalizedCoreExtProfiles(coreExtProfiles CoreExtProfileProvider) CoreExtProfileProvider {
	if coreExtProfiles == nil {
		return EmptyCoreExtProfileProvider()
	}
	return coreExtProfiles
}

func prepareInMemoryChainState(state *InMemoryChainState) error {
	if state == nil {
		return txerr(BLOCK_ERR_PARSE, "nil chainstate")
	}
	if state.Utxos == nil {
		state.Utxos = make(map[Outpoint]UtxoEntry)
	}
	if state.AlreadyGenerated == nil {
		state.AlreadyGenerated = new(big.Int)
	}
	if state.AlreadyGenerated.Sign() < 0 {
		return txerr(BLOCK_ERR_PARSE, "already_generated must be unsigned")
	}
	return nil
}

func parseInMemoryConnectBlock(input connectBlockBasicInMemorySuiteContext) (*ParsedBlock, error) {
	pb, _, err := parseAndValidateBlockBasicWithContextAtHeight(
		input.BlockBytes,
		input.ExpectedPrevHash,
		input.ExpectedTarget,
		input.BlockHeight,
		input.PrevTimestamps,
		input.Rotation,
	)
	if err != nil {
		return nil, err
	}
	if pb == nil || len(pb.Txs) == 0 || len(pb.Txids) != len(pb.Txs) {
		return nil, txerr(BLOCK_ERR_PARSE, "invalid parsed block")
	}
	return pb, nil
}

func inMemoryConnectBlockMTP(blockHeight uint64, prevTimestamps []uint64, headerTimestamp uint64) (uint64, error) {
	median, ok, err := medianTimePast(blockHeight, prevTimestamps)
	if err != nil {
		return 0, err
	}
	if ok {
		return median, nil
	}
	return headerTimestamp, nil
}

func applyInMemoryNonCoinbaseTxs(
	pb *ParsedBlock,
	workUtxos map[Outpoint]UtxoEntry,
	blockHeight uint64,
	blockMTP uint64,
	validation connectBlockInMemoryValidationContext,
) (map[Outpoint]UtxoEntry, uint64, error) {
	var sumFees uint64
	for i := 1; i < len(pb.Txs); i++ {
		nextUtxos, fee, err := applyNonCoinbaseTxBasicWork(nonCoinbaseApplyWorkInput{
			tx:              pb.Txs[i],
			txid:            pb.Txids[i],
			utxoSet:         workUtxos,
			height:          blockHeight,
			blockMTP:        blockMTP,
			chainID:         validation.chainID,
			coreExtProfiles: validation.coreExtProfiles,
			rotation:        validation.rotation,
			registry:        validation.registry,
		})
		if err != nil {
			return nil, 0, err
		}
		workUtxos = nextUtxos
		sumFees, err = addU64(sumFees, fee)
		if err != nil {
			return nil, 0, txerr(BLOCK_ERR_PARSE, "sum_fees overflow")
		}
	}
	return workUtxos, sumFees, nil
}

func applyInMemoryCoinbaseOutputs(pb *ParsedBlock, workUtxos map[Outpoint]UtxoEntry, blockHeight uint64) {
	coinbase := pb.Txs[0]
	coinbaseTxid := pb.Txids[0]
	for i, out := range coinbase.Outputs {
		if out.CovenantType == COV_TYPE_ANCHOR || out.CovenantType == COV_TYPE_DA_COMMIT {
			continue
		}
		op := Outpoint{Txid: coinbaseTxid, Vout: uint32(i)}
		workUtxos[op] = UtxoEntry{
			Value:             out.Value,
			CovenantType:      out.CovenantType,
			CovenantData:      append([]byte(nil), out.CovenantData...),
			CreationHeight:    blockHeight,
			CreatedByCoinbase: true,
		}
	}
}

func advanceAlreadyGenerated(blockHeight uint64, alreadyGenerated *big.Int) *big.Int {
	alreadyGeneratedN1 := new(big.Int).Set(alreadyGenerated)
	if blockHeight != 0 {
		subsidy := BlockSubsidyBig(blockHeight, alreadyGenerated)
		alreadyGeneratedN1 = new(big.Int).Add(alreadyGeneratedN1, new(big.Int).SetUint64(subsidy))
	}
	return alreadyGeneratedN1
}

func commitInMemoryConnectSummary(
	state *InMemoryChainState,
	workUtxos map[Outpoint]UtxoEntry,
	blockHeight uint64,
	alreadyGenerated *big.Int,
	alreadyGeneratedN1 *big.Int,
	sumFees uint64,
) (*ConnectBlockBasicSummary, error) {
	alreadyGeneratedU64, err := bigIntToUint64(alreadyGenerated)
	if err != nil {
		return nil, txerr(BLOCK_ERR_PARSE, "already_generated overflow")
	}
	alreadyGeneratedN1U64, err := bigIntToUint64(alreadyGeneratedN1)
	if err != nil {
		return nil, txerr(BLOCK_ERR_PARSE, "already_generated overflow")
	}

	state.Utxos = workUtxos
	if blockHeight != 0 {
		state.AlreadyGenerated = new(big.Int).Set(alreadyGeneratedN1)
	}
	return &ConnectBlockBasicSummary{
		SumFees:            sumFees,
		AlreadyGenerated:   alreadyGeneratedU64,
		AlreadyGeneratedN1: alreadyGeneratedN1U64,
		UtxoCount:          uint64(len(state.Utxos)),
		PostStateDigest:    UtxoSetHash(state.Utxos),
	}, nil
}

func bigIntToUint64(v *big.Int) (uint64, error) {
	if v == nil {
		return 0, nil
	}
	if v.Sign() < 0 || !v.IsUint64() {
		return 0, txerr(BLOCK_ERR_PARSE, "u64 overflow")
	}
	return v.Uint64(), nil
}
