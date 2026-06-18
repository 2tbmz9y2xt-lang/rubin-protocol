package consensus

import "math"

const maxInt = int(math.MaxInt)

// addWitnessSlots returns total + slots, or an error if the addition
// would overflow int.
func addWitnessSlots(total, slots int) (int, error) {
	if slots > maxInt-total {
		return 0, txerr(TX_ERR_PARSE, "witness slot count overflow")
	}
	return total + slots, nil
}

// TxValidationContext holds the immutable, precomputed context for a single
// non-coinbase transaction within a block. It is computed once against the
// block-start UTXO snapshot and passed to read-only validation workers.
//
// Fields are intentionally value types or slices of value types to prevent
// accidental aliasing of mutable consensus state.
type TxValidationContext struct {
	// TxIndex is the position of this transaction within the block (1-based,
	// since index 0 is the coinbase).
	TxIndex int

	// Tx is a pointer to the parsed transaction. The Tx struct itself is
	// treated as read-only after parsing.
	Tx *Tx

	// Txid is the canonical transaction ID.
	Txid [32]byte

	// ResolvedInputs contains the UTXO entry for each input, in input order.
	// Each entry is a snapshot taken from the block-start UTXO set. Workers
	// MUST NOT modify these entries.
	ResolvedInputs []UtxoEntry

	// WitnessStart is the starting index into tx.Witness for this
	// transaction's witness data, as determined by the sequential cursor
	// model.
	WitnessStart int

	// WitnessEnd is the exclusive end index into tx.Witness.
	WitnessEnd int

	// SighashCache is the precomputed sighash v1 prehash cache for this
	// transaction.
	SighashCache *SighashV1PrehashCache

	// InputOutpoints records the outpoints consumed by each input, in input
	// order. Used for duplicate-input detection and dependency tracking.
	InputOutpoints []Outpoint

	// Fee is the transaction fee computed during precompute (sumInputs - sumOutputs).
	// Validated during precompute to detect overflow early.
	Fee uint64
}

type precomputeTxInputs struct {
	ResolvedInputs          []UtxoEntry
	InputOutpoints          []Outpoint
	TotalWitnessSlots       int
	SumIn                   u128
	StoppedAtCoreSimplicity bool
}

// PrecomputeTxContexts builds an immutable TxValidationContext slice for all
// non-coinbase transactions in a parsed block. It resolves inputs against the
// provided block-start UTXO snapshot, computes witness slice boundaries using
// the deterministic sequential cursor model, and precomputes sighash caches.
//
// The utxoSnapshot is NOT modified. Same-block output creation is tracked
// internally to support parent-child dependencies (a later tx spending an
// output created by an earlier tx in the same block).
//
// Returns an error if any input resolution, witness assignment, or value
// conservation check fails. Error behavior matches the sequential path
// exactly.
func PrecomputeTxContexts(
	pb *ParsedBlock,
	utxoSnapshot map[Outpoint]UtxoEntry,
	blockHeight uint64,
) ([]TxValidationContext, error) {
	if pb == nil || len(pb.Txs) == 0 {
		return nil, txerr(BLOCK_ERR_PARSE, "nil or empty parsed block")
	}

	if len(pb.Txids) != len(pb.Txs) {
		return nil, txerr(BLOCK_ERR_PARSE, "txids/txs length mismatch")
	}

	txCount := len(pb.Txs) - 1 // exclude coinbase
	if txCount == 0 {
		return nil, nil // coinbase-only block
	}

	overlay := make(map[Outpoint]UtxoEntry, len(utxoSnapshot))
	for k, v := range utxoSnapshot {
		overlay[k] = v
	}
	results := make([]TxValidationContext, txCount)

	for i := 1; i < len(pb.Txs); i++ {
		ctx, err := precomputeTxContext(i, pb.Txs[i], pb.Txids[i], overlay, blockHeight)
		if err != nil {
			return nil, err
		}
		results[i-1] = ctx
		updatePrecomputeOverlay(overlay, ctx, blockHeight)
	}

	return results, nil
}

func precomputeTxContext(
	txIndex int,
	tx *Tx,
	txid [32]byte,
	overlay map[Outpoint]UtxoEntry,
	blockHeight uint64,
) (TxValidationContext, error) {
	if tx == nil {
		return TxValidationContext{}, txerr(TX_ERR_PARSE, "nil tx")
	}
	if len(tx.Inputs) == 0 {
		return TxValidationContext{}, txerr(TX_ERR_PARSE, "non-coinbase must have at least one input")
	}

	inputs, err := collectPrecomputeTxInputs(tx, overlay, blockHeight)
	if err != nil {
		return TxValidationContext{}, err
	}

	witnessStart, witnessEnd, err := precomputeWitnessBounds(tx, inputs.TotalWitnessSlots, inputs.StoppedAtCoreSimplicity)
	if err != nil {
		return TxValidationContext{}, err
	}

	var fee uint64
	if !inputs.StoppedAtCoreSimplicity {
		fee, err = computePrecomputeFee(inputs.SumIn, tx.Outputs)
		if err != nil {
			return TxValidationContext{}, err
		}
	}

	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		return TxValidationContext{}, err
	}

	return TxValidationContext{
		TxIndex:        txIndex,
		Tx:             tx,
		Txid:           txid,
		ResolvedInputs: inputs.ResolvedInputs,
		WitnessStart:   witnessStart,
		WitnessEnd:     witnessEnd,
		SighashCache:   sighashCache,
		InputOutpoints: inputs.InputOutpoints,
		Fee:            fee,
	}, nil
}

func collectPrecomputeTxInputs(
	tx *Tx,
	overlay map[Outpoint]UtxoEntry,
	blockHeight uint64,
) (precomputeTxInputs, error) {
	out := precomputeTxInputs{
		ResolvedInputs: make([]UtxoEntry, 0, len(tx.Inputs)),
		InputOutpoints: make([]Outpoint, 0, len(tx.Inputs)),
	}
	seenInputs := make(map[Outpoint]struct{}, len(tx.Inputs))

	for _, in := range tx.Inputs {
		entry, op, slots, stoppedAtCoreSimplicity, err := resolvePrecomputeInput(in, seenInputs, overlay, blockHeight)
		if err != nil {
			return precomputeTxInputs{}, err
		}
		out.ResolvedInputs = append(out.ResolvedInputs, entry)
		out.InputOutpoints = append(out.InputOutpoints, op)
		if out.SumIn, err = addU64ToU128(out.SumIn, entry.Value); err != nil {
			return precomputeTxInputs{}, err
		}
		if stoppedAtCoreSimplicity {
			out.StoppedAtCoreSimplicity = true
			return out, nil
		}
		if out.TotalWitnessSlots, err = addWitnessSlots(out.TotalWitnessSlots, slots); err != nil {
			return precomputeTxInputs{}, err
		}
	}

	return out, nil
}

func resolvePrecomputeInput(
	in TxInput,
	seenInputs map[Outpoint]struct{},
	overlay map[Outpoint]UtxoEntry,
	blockHeight uint64,
) (UtxoEntry, Outpoint, int, bool, error) {
	var zeroTxid [32]byte
	if in.PrevVout == 0xffff_ffff && in.PrevTxid == zeroTxid {
		return UtxoEntry{}, Outpoint{}, 0, false, txerr(TX_ERR_PARSE, "coinbase prevout encoding forbidden in non-coinbase")
	}

	op := Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
	if err := rememberPrecomputeInput(op, seenInputs); err != nil {
		return UtxoEntry{}, Outpoint{}, 0, false, err
	}

	entry, ok := overlay[op]
	if !ok {
		return UtxoEntry{}, Outpoint{}, 0, false, txerr(TX_ERR_MISSING_UTXO, "utxo not found")
	}
	if err := validatePrecomputeEntry(entry, blockHeight); err != nil {
		return UtxoEntry{}, Outpoint{}, 0, false, err
	}
	if entry.CovenantType == COV_TYPE_CORE_SIMPLICITY {
		return entry, op, 0, true, nil
	}

	slots, err := precomputeWitnessSlots(entry)
	if err != nil {
		return UtxoEntry{}, Outpoint{}, 0, false, err
	}
	return entry, op, slots, false, nil
}

func rememberPrecomputeInput(op Outpoint, seenInputs map[Outpoint]struct{}) error {
	if _, exists := seenInputs[op]; exists {
		return txerr(TX_ERR_PARSE, "duplicate input outpoint")
	}
	seenInputs[op] = struct{}{}
	return nil
}

func validatePrecomputeEntry(entry UtxoEntry, blockHeight uint64) error {
	if entry.CreatedByCoinbase && (blockHeight < entry.CreationHeight || blockHeight-entry.CreationHeight < COINBASE_MATURITY) {
		return txerr(TX_ERR_COINBASE_IMMATURE, "coinbase immature")
	}
	if entry.CovenantType == COV_TYPE_ANCHOR || entry.CovenantType == COV_TYPE_DA_COMMIT {
		return txerr(TX_ERR_MISSING_UTXO, "attempt to spend non-spendable covenant")
	}
	return nil
}

func precomputeWitnessSlots(entry UtxoEntry) (int, error) {
	slots, err := WitnessSlots(entry.CovenantType, entry.CovenantData)
	if err != nil {
		return 0, err
	}
	if slots <= 0 {
		return 0, txerr(TX_ERR_PARSE, "invalid witness slots")
	}
	return slots, nil
}

func precomputeWitnessBounds(tx *Tx, totalWitnessSlots int, stoppedAtCoreSimplicity bool) (int, int, error) {
	// Witness cursor is per-transaction (reset to 0 for each tx), matching
	// the sequential path in applyNonCoinbaseTxBasicWorkQ.
	witnessCursor := 0
	witnessStart := witnessCursor
	witnessEnd := witnessCursor + totalWitnessSlots
	if witnessEnd > len(tx.Witness) {
		return 0, 0, txerr(TX_ERR_PARSE, "witness underflow")
	}
	witnessCursor = witnessEnd
	if !stoppedAtCoreSimplicity && witnessCursor != len(tx.Witness) {
		return 0, 0, txerr(TX_ERR_PARSE, "witness_count mismatch")
	}
	return witnessStart, witnessEnd, nil
}

func computePrecomputeFee(sumIn u128, outputs []TxOutput) (uint64, error) {
	var sumOut u128
	for _, out := range outputs {
		var err error
		sumOut, err = addU64ToU128(sumOut, out.Value)
		if err != nil {
			return 0, err
		}
	}
	if cmpU128(sumIn, sumOut) < 0 {
		return 0, txerr(TX_ERR_VALUE_CONSERVATION, "outputs exceed inputs")
	}
	feeBig, err := subU128(sumIn, sumOut)
	if err != nil {
		return 0, err
	}
	if feeBig.hi != 0 {
		return 0, txerr(TX_ERR_VALUE_CONSERVATION, "fee overflow u64")
	}
	return feeBig.lo, nil
}

func updatePrecomputeOverlay(
	overlay map[Outpoint]UtxoEntry,
	ctx TxValidationContext,
	blockHeight uint64,
) {
	for _, op := range ctx.InputOutpoints {
		delete(overlay, op)
	}
	for j, out := range ctx.Tx.Outputs {
		if out.CovenantType == COV_TYPE_ANCHOR || out.CovenantType == COV_TYPE_DA_COMMIT {
			continue
		}
		op := Outpoint{Txid: ctx.Txid, Vout: uint32(j)}
		overlay[op] = UtxoEntry{
			Value:          out.Value,
			CovenantType:   out.CovenantType,
			CovenantData:   append([]byte(nil), out.CovenantData...),
			CreationHeight: blockHeight,
		}
	}
}
