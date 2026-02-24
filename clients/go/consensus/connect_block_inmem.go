package consensus

// InMemoryChainState is a minimal, non-persistent chainstate container intended for
// conformance tests and audit/repro tooling.
//
// It is NOT a full node database: it provides deterministic inputs for stateful checks
// (fee computation, coinbase bound, maturity rules) without any disk persistence.
type InMemoryChainState struct {
	Utxos            map[Outpoint]UtxoEntry
	AlreadyGenerated uint64 // already_generated(h): subsidy-only, excluding fees
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
) (*ConnectBlockBasicSummary, error) {
	if state == nil {
		return nil, txerr(BLOCK_ERR_PARSE, "nil chainstate")
	}
	if state.Utxos == nil {
		state.Utxos = make(map[Outpoint]UtxoEntry)
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

	alreadyGenerated := state.AlreadyGenerated

	// Compute fees and update UTXO set by applying all non-coinbase transactions.
	var sumFees uint64
	for i := 1; i < len(pb.Txs); i++ {
		tx := pb.Txs[i]
		txid := pb.Txids[i]

		nextUtxos, s, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, state.Utxos, blockHeight, pb.Header.Timestamp)
		if err != nil {
			return nil, err
		}
		state.Utxos = nextUtxos
		sumFees, err = addU64(sumFees, s.Fee)
		if err != nil {
			return nil, txerr(BLOCK_ERR_PARSE, "sum_fees overflow")
		}
	}

	// Enforce coinbase bound using locally computed fees.
	if err := validateCoinbaseValueBound(pb, blockHeight, alreadyGenerated, sumFees); err != nil {
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
		state.Utxos[op] = UtxoEntry{
			Value:             out.Value,
			CovenantType:      out.CovenantType,
			CovenantData:      append([]byte(nil), out.CovenantData...),
			CreationHeight:    blockHeight,
			CreatedByCoinbase: true,
		}
	}

	// Update already_generated(h) -> already_generated(h+1) by adding subsidy(h).
	alreadyGeneratedN1 := alreadyGenerated
	if blockHeight != 0 {
		subsidy := BlockSubsidy(blockHeight, alreadyGenerated)
		ag, err := addU64(alreadyGenerated, subsidy)
		if err != nil {
			return nil, txerr(BLOCK_ERR_PARSE, "already_generated overflow")
		}
		alreadyGeneratedN1 = ag
		state.AlreadyGenerated = ag
	}

	return &ConnectBlockBasicSummary{
		SumFees:            sumFees,
		AlreadyGenerated:   alreadyGenerated,
		AlreadyGeneratedN1: alreadyGeneratedN1,
		UtxoCount:          uint64(len(state.Utxos)),
	}, nil
}
