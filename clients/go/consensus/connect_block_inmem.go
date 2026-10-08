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
	SumFees            Uint128
	AlreadyGenerated   Uint128
	AlreadyGeneratedN1 Uint128
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
	Rotation         RotationProvider
	Registry         *SuiteRegistry
}

type connectBlockInMemoryValidationContext struct {
	chainID   [32]byte
	rotation  RotationProvider
	registry  *SuiteRegistry
	inputView *blockInputViewState
}

type connectBlockInputViewResult struct {
	sumFees            Uint128
	alreadyGenerated   Uint128
	alreadyGeneratedN1 Uint128
	spentInputs        *blockSpentInputSource
	createdUtxos       map[Outpoint]UtxoEntry
}

// connectBlockBasicWithInputView is a dormant continuation for storage callers.
// The caller has completed ValidateBlockSteps1To12 on these identical frozen
// bytes and positive-height parent/target/timestamp context. ChainID, Registry,
// Rotation and the view remain frozen through consuming or discarding the result.
// input.State is unused. This continuation adds no qualification or publication.
func connectBlockBasicWithInputView(
	input connectBlockBasicInMemorySuiteContext,
	view logicalStateView,
	alreadyGenerated Uint128,
) (*connectBlockInputViewResult, error) {
	if view == nil {
		return nil, localLogicalStateFailure("nil logical state view")
	}
	header, off, count, err := storedCommitmentFrame(input.BlockBytes)
	if err != nil {
		return nil, err
	}
	if err := validateInputViewPlacement(input.BlockBytes, off, count); err != nil {
		return nil, err
	}
	blockMTP, err := inMemoryConnectBlockMTP(input.BlockHeight, input.PrevTimestamps, header.Timestamp)
	if err != nil {
		return nil, err
	}
	work := blockInputViewConnectWork{
		raw: input.BlockBytes, offset: off, count: count, height: input.BlockHeight, blockMTP: blockMTP,
		created: make(map[Outpoint]UtxoEntry), seenNonces: make(map[uint64]struct{}),
		validation: connectBlockInMemoryValidationContext{
			chainID: input.ChainID, rotation: input.Rotation, registry: input.Registry,
			inputView: &blockInputViewState{view: view, height: input.BlockHeight, spent: make(map[Outpoint]uint32)},
		},
	}
	if err := work.applyCoinbase(); err != nil {
		return nil, err
	}
	suffixStart := work.offset
	if err := work.applySuffix(); err != nil {
		return nil, err
	}
	return work.finish(alreadyGenerated, suffixStart)
}

func (work *blockInputViewConnectWork) finish(alreadyGenerated Uint128, suffixStart int) (*connectBlockInputViewResult, error) {
	alreadyGeneratedBig := alreadyGenerated.Big()
	if err := validateCoinbaseValueTotal(work.coinbaseTotal, work.coinbaseError, work.height, alreadyGeneratedBig, work.sumFees); err != nil {
		return nil, err
	}
	alreadyGeneratedN1, err := checkedAdvanceAlreadyGenerated(work.height, alreadyGenerated, alreadyGeneratedBig)
	if err != nil {
		return nil, err
	}
	spent := work.validation.inputView.spent
	work.seenNonces, work.validation = nil, connectBlockInMemoryValidationContext{}
	return &connectBlockInputViewResult{
		sumFees: work.sumFees, alreadyGenerated: alreadyGenerated, alreadyGeneratedN1: alreadyGeneratedN1,
		spentInputs:  &blockSpentInputSource{raw: work.raw, spent: spent, offset: suffixStart, count: work.count, nextTx: 1},
		createdUtxos: work.created,
	}, nil
}

// validateInputViewPlacement is a pure one-current-Tx prepass. Q has already
// parsed all P0, including trailing bytes, before this first-result decision.
func validateInputViewPlacement(raw []byte, off int, count uint64) error {
	for ordinal := uint64(0); ordinal < count; ordinal++ {
		tx, _, _, _, err := parseBlockTx(raw, &off)
		if err != nil {
			return err
		}
		if err := validateInputViewPlacementTx(tx, ordinal); err != nil {
			return err
		}
	}
	return nil
}

func validateInputViewPlacementTx(tx *Tx, ordinal uint64) error {
	if ordinal == 0 {
		if !isCoinbaseTx(tx) {
			return txerr(BLOCK_ERR_COINBASE_INVALID, "first tx must be canonical coinbase")
		}
		if len(tx.Outputs) == 0 {
			return txerr(BLOCK_ERR_COINBASE_INVALID, "coinbase must have at least one output")
		}
		return nil
	}
	if isCoinbaseTx(tx) && len(tx.Outputs) > 0 {
		return txerr(BLOCK_ERR_COINBASE_INVALID, "coinbase-like tx is only allowed at index 0")
	}
	return nil
}

type blockInputViewConnectWork struct {
	raw           []byte
	created       map[Outpoint]UtxoEntry
	seenNonces    map[uint64]struct{}
	validation    connectBlockInMemoryValidationContext
	sumFees       Uint128
	coinbaseTotal u128
	coinbaseError error
	height        uint64
	blockMTP      uint64
	count         uint64
	offset        int
}

func (work *blockInputViewConnectWork) applyCoinbase() error {
	coinbase, txid, _, _, err := parseBlockTx(work.raw, &work.offset)
	if err != nil {
		return err
	}
	if err := validateCoinbaseTxStructure(coinbase, work.height); err != nil {
		return err
	}
	if err := applyInMemoryCoinbaseTxOutputs(coinbase, txid, work.created, work.height, work.validation.chainID, work.validation.rotation); err != nil {
		return err
	}
	work.coinbaseTotal, work.coinbaseError = sumCoinbaseOutputValues(coinbase.Outputs)
	return nil
}

func (work *blockInputViewConnectWork) applySuffix() error {
	for ordinal := uint64(1); ordinal < work.count; ordinal++ {
		if err := work.applyTransaction(ordinal); err != nil {
			return err
		}
	}
	return nil
}

func (work *blockInputViewConnectWork) applyTransaction(ordinal uint64) error {
	tx, txid, _, _, err := parseBlockTx(work.raw, &work.offset)
	if err != nil {
		return err
	}
	if err := validateNonCoinbaseBlockTx(tx, work.seenNonces); err != nil {
		return err
	}
	// Q's <=68,000,125-byte body bounds ordinal below 2^31; the mask is
	// identity on that domain and makes the platform-independent int bound explicit.
	work.validation.inputView.txIndex = int(ordinal & 0x7fffffff)
	next, fee, err := applyNonCoinbaseTxBasicWork(nonCoinbaseApplyWorkInput{
		tx: tx, txid: txid, utxoSet: work.created, height: work.height, blockMTP: work.blockMTP,
		chainID: work.validation.chainID, rotation: work.validation.rotation, registry: work.validation.registry,
		inputView: work.validation.inputView,
	})
	if err != nil {
		return err
	}
	work.created = next
	sum, ok := work.sumFees.CheckedAdd(fee)
	if !ok {
		return txerr(BLOCK_ERR_PARSE, "sum_fees overflow")
	}
	work.sumFees = sum
	return nil
}

// blockSpentInputSource owns the same compact map after successful connect.
// It performs metadata parsing only: no view, consensus result or full OLD row.
// Each returned tuple is a value (48 logical bytes) consumed before advancing.
type blockSpentInputSource struct {
	raw        []byte
	spent      map[Outpoint]uint32
	current    *Tx
	count      uint64
	nextTx     uint64
	offset     int
	inputIndex int
	txIndex    uint32
}

func (source *blockSpentInputSource) next() (blockSpentInput, bool) {
	for source.raw != nil {
		if !source.loadTransaction() {
			source.discard()
			return blockSpentInput{}, false
		}
		for source.inputIndex < len(source.current.Inputs) {
			index := source.inputIndex
			in := source.current.Inputs[index]
			source.inputIndex++
			op := Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
			length := source.spent[op]
			delete(source.spent, op)
			if length != 0 {
				// ParseTx bounds inputs by MAX_TX_INPUTS (1,024), so this
				// nonnegative-width mask preserves the exact input index.
				return blockSpentInput{outpoint: op, txIndex: source.txIndex, inputIndex: uint32(index & 0x7fffffff), logicalEntryLength: length}, true
			}
		}
		source.current = nil
	}
	return blockSpentInput{}, false
}

func (source *blockSpentInputSource) loadTransaction() bool {
	if source.current != nil {
		return true
	}
	if source.nextTx >= source.count {
		return false
	}
	// Identical frozen Q-qualified bytes and the same pinned parser make success
	// a preserved precondition, not a second consensus decision or new error.
	source.current, _, _, _, _ = parseBlockTx(source.raw, &source.offset)
	// The qualified <=68,000,125-byte body bounds every ordinal below 2^32;
	// each input index is additionally bounded by MAX_TX_INPUTS (1,024).
	// The mask is identity on that qualified ordinal domain.
	source.txIndex = uint32(source.nextTx & 0xffffffff)
	source.nextTx++
	source.inputIndex = 0
	return true
}

// discard is the same terminal release for exhaustion, unused handoff and
// caller rollback. A retry must obtain a fresh result from a fresh connect.
func (source *blockSpentInputSource) discard() {
	*source = blockSpentInputSource{}
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
	return ConnectBlockBasicInMemoryAtHeightAndSuiteContext(
		blockBytes,
		expectedPrevHash,
		expectedTarget,
		blockHeight,
		prevTimestamps,
		state,
		chainID,
		nil, /*rotation*/
		nil, /*registry*/
	)
}

// #lizard forgive
func ConnectBlockBasicInMemoryAtHeightAndSuiteContext(
	blockBytes []byte,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
	state *InMemoryChainState,
	chainID [32]byte,
	rotation RotationProvider,
	registry *SuiteRegistry,
) (*ConnectBlockBasicSummary, error) {
	return connectBlockBasicInMemoryAtHeightAndSuiteContext(connectBlockBasicInMemorySuiteContext{
		BlockBytes:       blockBytes,
		ExpectedPrevHash: expectedPrevHash,
		ExpectedTarget:   expectedTarget,
		BlockHeight:      blockHeight,
		PrevTimestamps:   prevTimestamps,
		State:            state,
		ChainID:          chainID,
		Rotation:         rotation,
		Registry:         registry,
	})
}

func connectBlockBasicInMemoryAtHeightAndSuiteContext(
	input connectBlockBasicInMemorySuiteContext,
) (*ConnectBlockBasicSummary, error) {
	alreadyGenerated, alreadyGeneratedU128, err := preflightInMemoryChainState(input.State)
	if err != nil {
		return nil, err
	}

	pb, err := parseInMemoryConnectBlock(input)
	if err != nil {
		return nil, err
	}

	blockMTP, err := inMemoryConnectBlockMTP(input.BlockHeight, input.PrevTimestamps, pb.Header.Timestamp)
	if err != nil {
		return nil, err
	}

	validation := connectBlockInMemoryValidationContext{
		chainID:  input.ChainID,
		rotation: input.Rotation,
		registry: input.Registry,
	}
	workUtxos := cloneUtxoSet(input.State.Utxos)
	workUtxos, sumFees, err := applyInMemorySequentialConnect(
		pb,
		workUtxos,
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

	alreadyGeneratedN1, err := checkedAdvanceAlreadyGenerated(input.BlockHeight, alreadyGeneratedU128, alreadyGenerated)
	if err != nil {
		return nil, err
	}
	return commitInMemoryConnectSummary(input.State, workUtxos, alreadyGeneratedU128, alreadyGeneratedN1, sumFees, 0, 0), nil
}

// applyInMemorySequentialConnect is the sequential production continuation
// after parsed-block preflight. It makes the coinbase outputs visible to every
// non-coinbase transaction while retaining all effects in the caller's local
// working UTXO set until final commit.
func applyInMemorySequentialConnect(
	pb *ParsedBlock,
	workUtxos map[Outpoint]UtxoEntry,
	blockHeight uint64,
	blockMTP uint64,
	validation connectBlockInMemoryValidationContext,
) (map[Outpoint]UtxoEntry, Uint128, error) {
	if err := applyInMemoryCoinbaseOutputs(
		pb,
		workUtxos,
		blockHeight,
		validation.chainID,
		validation.rotation,
	); err != nil {
		return nil, Uint128{}, err
	}
	return applyInMemoryNonCoinbaseTxs(
		pb,
		workUtxos,
		blockHeight,
		blockMTP,
		validation,
	)
}

func preflightInMemoryChainState(state *InMemoryChainState) (*big.Int, Uint128, error) {
	if state == nil {
		return nil, Uint128{}, txerr(BLOCK_ERR_PARSE, "nil chainstate")
	}
	alreadyGenerated := new(big.Int)
	if state.AlreadyGenerated != nil {
		alreadyGenerated.Set(state.AlreadyGenerated)
	}
	if alreadyGenerated.Sign() < 0 {
		return nil, Uint128{}, txerr(BLOCK_ERR_PARSE, "already_generated must be unsigned")
	}
	if alreadyGenerated.BitLen() > 128 {
		return nil, Uint128{}, txerr(BLOCK_ERR_PARSE, "already_generated overflow")
	}
	return alreadyGenerated, uint128FromBigInt(alreadyGenerated), nil
}

func parseInMemoryConnectBlock(input connectBlockBasicInMemorySuiteContext) (*ParsedBlock, error) {
	pb, err := parseAndValidateBlockBasicForConnectWithContextAtHeight(
		input.BlockBytes,
		input.ExpectedPrevHash,
		input.ExpectedTarget,
		input.BlockHeight,
		input.PrevTimestamps,
		input.ChainID,
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
) (map[Outpoint]UtxoEntry, Uint128, error) {
	var sumFees Uint128
	seenNonces := make(map[uint64]struct{}, len(pb.Txs))
	for i := 1; i < len(pb.Txs); i++ {
		if err := validateNonCoinbaseBlockTx(pb.Txs[i], seenNonces); err != nil {
			return nil, Uint128{}, err
		}
		nextUtxos, fee, err := applyNonCoinbaseTxBasicWork(nonCoinbaseApplyWorkInput{
			tx:       pb.Txs[i],
			txid:     pb.Txids[i],
			utxoSet:  workUtxos,
			height:   blockHeight,
			blockMTP: blockMTP,
			chainID:  validation.chainID,
			rotation: validation.rotation,
			registry: validation.registry,
		})
		if err != nil {
			return nil, Uint128{}, err
		}
		workUtxos = nextUtxos
		next, ok := sumFees.CheckedAdd(fee)
		if !ok {
			return nil, Uint128{}, txerr(BLOCK_ERR_PARSE, "sum_fees overflow")
		}
		sumFees = next
	}
	return workUtxos, sumFees, nil
}

// applyInMemoryCoinbaseOutputs validates and applies coinbase outputs in vout
// order before transaction index one. Every output passes the coinbase-only
// VAULT guard and the existing creation validator before its spendable UTXO is
// inserted. The same-CMR cap runs only after every output is processed.
func applyInMemoryCoinbaseOutputs(
	pb *ParsedBlock,
	workUtxos map[Outpoint]UtxoEntry,
	blockHeight uint64,
	chainID [32]byte,
	rotation RotationProvider,
) error {
	return applyInMemoryCoinbaseTxOutputs(pb.Txs[0], pb.Txids[0], workUtxos, blockHeight, chainID, rotation)
}

func applyInMemoryCoinbaseTxOutputs(
	coinbase *Tx,
	coinbaseTxid [32]byte,
	workUtxos map[Outpoint]UtxoEntry,
	blockHeight uint64,
	chainID [32]byte,
	rotation RotationProvider,
) error {
	if rotation == nil {
		rotation = DefaultRotationProvider{}
	}
	simplicityDeployment := simplicityDeploymentFromRotation(rotation)
	simplicityOutputCMRs := make([][32]byte, 0, len(coinbase.Outputs))
	for i, out := range coinbase.Outputs {
		if err := validateCoinbaseApplyOutput(out); err != nil {
			return err
		}
		programCMR, isCoreSimplicity, err := validateTxOutputCovenantGenesis(
			coinbase.TxKind,
			out,
			chainID,
			blockHeight,
			rotation,
			simplicityDeployment,
		)
		if err != nil {
			return err
		}
		if isCoreSimplicity {
			simplicityOutputCMRs = append(simplicityOutputCMRs, programCMR)
		}
		if isNonSpendableInputCovenant(out.CovenantType) {
			continue
		}
		vout, err := coinbaseOutputVout(i)
		if err != nil {
			return err
		}
		op := Outpoint{Txid: coinbaseTxid, Vout: vout}
		workUtxos[op] = UtxoEntry{
			Value:             out.Value,
			CovenantType:      out.CovenantType,
			CovenantData:      append([]byte(nil), out.CovenantData...),
			CreationHeight:    blockHeight,
			CreatedByCoinbase: true,
		}
	}
	return validateSimplicityOutputGroupCap(simplicityOutputCMRs)
}

func coinbaseOutputVout(index int) (uint32, error) {
	if index < 0 || uint64(index) > uint64(^uint32(0)) {
		return 0, txerr(BLOCK_ERR_PARSE, "coinbase output index exceeds u32")
	}
	return uint32(index), nil
}

func checkedAdvanceAlreadyGenerated(blockHeight uint64, alreadyGenerated Uint128, alreadyGeneratedBig *big.Int) (Uint128, error) {
	if blockHeight == 0 {
		return alreadyGenerated, nil
	}
	alreadyGeneratedN1, ok := alreadyGenerated.CheckedAdd(Uint128FromU64(BlockSubsidyBig(blockHeight, alreadyGeneratedBig)))
	if !ok {
		return Uint128{}, txerr(BLOCK_ERR_PARSE, "already_generated overflow")
	}
	return alreadyGeneratedN1, nil
}

func commitInMemoryConnectSummary(
	state *InMemoryChainState,
	workUtxos map[Outpoint]UtxoEntry,
	alreadyGenerated Uint128,
	alreadyGeneratedN1 Uint128,
	sumFees Uint128,
	sigTaskCount uint64,
	workerPanics uint64,
) *ConnectBlockBasicSummary {
	summary := &ConnectBlockBasicSummary{
		SumFees:            sumFees,
		AlreadyGenerated:   alreadyGenerated,
		AlreadyGeneratedN1: alreadyGeneratedN1,
		UtxoCount:          uint64(len(workUtxos)),
		PostStateDigest:    UtxoSetHash(workUtxos),
		SigTaskCount:       sigTaskCount,
		WorkerPanics:       workerPanics,
	}
	state.Utxos = workUtxos
	state.AlreadyGenerated = alreadyGeneratedN1.Big()
	return summary
}

func uint128FromBigInt(v *big.Int) Uint128 {
	hi := new(big.Int).Rsh(new(big.Int).Set(v), 64)
	return Uint128{Lo: v.Uint64(), Hi: hi.Uint64()}
}
