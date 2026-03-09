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
		nil,
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
	if state == nil {
		return nil, txerr(BLOCK_ERR_PARSE, "nil chainstate")
	}
	if state.Utxos == nil {
		state.Utxos = make(map[Outpoint]UtxoEntry)
	}
	if state.AlreadyGenerated == nil {
		state.AlreadyGenerated = new(big.Int)
	}
	if state.AlreadyGenerated.Sign() < 0 {
		return nil, txerr(BLOCK_ERR_PARSE, "already_generated must be unsigned")
	}

	// Stateless checks first (wire, merkle root, PoW/target, covenant creation, etc).
	if _, err := ValidateBlockBasicWithContextAtHeight(blockBytes, expectedPrevHash, expectedTarget, blockHeight, prevTimestamps); err != nil {
		return nil, err
	}

	pb, err := ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	if pb == nil || len(pb.Txs) == 0 || len(pb.Txids) != len(pb.Txs) {
		return nil, txerr(BLOCK_ERR_PARSE, "invalid parsed block")
	}

	alreadyGenerated := new(big.Int).Set(state.AlreadyGenerated)
	blockMTP := pb.Header.Timestamp
	if median, ok, err := medianTimePast(blockHeight, prevTimestamps); err != nil {
		return nil, err
	} else if ok {
		blockMTP = median
	}
	workUtxos := state.Utxos

	// Compute fees and update UTXO set by applying all non-coinbase transactions.
	var sumFees uint64
	for i := 1; i < len(pb.Txs); i++ {
		tx := pb.Txs[i]
		txid := pb.Txids[i]

		nextUtxos, s, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(
			tx,
			txid,
			workUtxos,
			blockHeight,
			pb.Header.Timestamp,
			blockMTP,
			chainID,
			coreExtProfiles,
		)
		if err != nil {
			return nil, err
		}
		workUtxos = nextUtxos
		sumFees, err = addU64(sumFees, s.Fee)
		if err != nil {
			return nil, txerr(BLOCK_ERR_PARSE, "sum_fees overflow")
		}
	}

	// Enforce coinbase bound using locally computed fees.
	if err := validateCoinbaseValueBound(pb, blockHeight, alreadyGenerated, sumFees); err != nil {
		return nil, err
	}
	if err := validateCoinbaseApplyOutputs(pb.Txs[0]); err != nil {
		return nil, err
	}

	// Add coinbase outputs to UTXO set (spendable outputs only).
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

	// Update already_generated(h) -> already_generated(h+1) by adding subsidy(h).
	alreadyGeneratedN1 := new(big.Int).Set(alreadyGenerated)
	if blockHeight != 0 {
		subsidy := BlockSubsidyBig(blockHeight, alreadyGenerated)
		alreadyGeneratedN1 = new(big.Int).Add(alreadyGeneratedN1, new(big.Int).SetUint64(subsidy))
	}
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
