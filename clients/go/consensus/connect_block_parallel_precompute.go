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
// non-coinbase transaction within a block. The caller must provide a ParsedBlock
// that completed canonical connect preflight, including coinbase structure and
// locktime. The context covers the block-start UTXO snapshot plus the current
// coinbase and earlier transactions and is intended for read-only worker
// validation; PrecomputeTxContexts currently has no production caller.
// The ParsedBlock and referenced Tx objects remain caller-owned and must stay
// immutable for the lifetime of any returned context.
//
// Fields are intentionally value types or slices of value types to prevent
// accidental aliasing of mutable consensus state.
type TxValidationContext struct {
	// TxIndex is the position of this transaction within the block (1-based,
	// since index 0 is the coinbase).
	TxIndex int

	// Tx is a pointer to a caller-owned parsed transaction. It must remain
	// immutable for the lifetime of this context.
	Tx *Tx

	// Txid is the canonical transaction ID.
	Txid [32]byte

	// ResolvedInputs contains the UTXO entry for each input, in input order.
	// Its UTXO bytes are detached from caller-owned storage, so the caller may
	// mutate its snapshot after return. Workers MUST NOT modify these entries.
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

	// Fee is the exact u128 transaction fee computed during precompute
	// (sumInputs - sumOutputs). It equals the fee the sequential and
	// queued-parallel apply paths derive for the same transaction; fee
	// width alone is never a rejection reason.
	Fee Uint128
}

type precomputeTxInputs struct {
	ResolvedInputs    []UtxoEntry
	InputOutpoints    []Outpoint
	TotalWitnessSlots int
	SumIn             u128
}

// PrecomputeTxContexts builds an immutable TxValidationContext slice for all
// non-coinbase transactions in a parsed block. It resolves inputs against the
// provided block-start UTXO snapshot, computes witness slice boundaries using
// the deterministic sequential cursor model, and precomputes sighash caches.
// Precondition: pb completed canonical connect preflight, including coinbase
// structure and locktime.
//
// During this call, the caller retains read-only ownership of utxoSnapshot. A
// local overlay adds the current coinbase and earlier same-block outputs to
// support parent-child dependencies. ParsedBlock and referenced Tx objects
// remain caller-owned and must stay immutable for the lifetime of returned
// contexts. Resolved UTXO bytes are detached, so the caller may mutate
// utxoSnapshot after return. It repeats the connect path's non-coinbase
// coinbase-like, nonce, and replay checks and validates output creation.
// Contexts are intended for read-only workers, which validate resolved inputs;
// this exported API currently has no production caller. Default chain and
// rotation context match standalone.
//
// Returns an error if any input resolution, witness assignment, or value
// conservation check fails. With the default chain and rotation context, errors
// owned by this precompute path (non-coinbase coinbase-like, nonce, and replay
// checks; output creation; input resolution; witness boundaries; and value
// conservation) preserve the corresponding sequential first-error order.
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

	overlay := make(map[Outpoint]UtxoEntry, len(utxoSnapshot))
	for k, v := range utxoSnapshot {
		overlay[k] = v
	}
	if err := applyInMemoryCoinbaseOutputs(pb, overlay, blockHeight, [32]byte{}, nil); err != nil {
		return nil, err
	}

	if len(pb.Txs) == 1 {
		return nil, nil // coinbase-only block
	}
	return precomputeNonCoinbaseTxContexts(pb, overlay, blockHeight)
}

func precomputeNonCoinbaseTxContexts(
	pb *ParsedBlock,
	overlay map[Outpoint]UtxoEntry,
	blockHeight uint64,
) ([]TxValidationContext, error) {
	txCount := len(pb.Txs) - 1
	results := make([]TxValidationContext, txCount)
	seenNonces := make(map[uint64]struct{}, txCount)

	for i := 1; i < len(pb.Txs); i++ {
		if pb.Txs[i] == nil {
			return nil, txerr(TX_ERR_PARSE, "nil tx")
		}
		if err := validateNonCoinbaseBlockTx(pb.Txs[i], seenNonces); err != nil {
			return nil, err
		}
		ctx, err := precomputeTxContext(i, pb.Txs[i], pb.Txids[i], overlay, blockHeight)
		if err != nil {
			return nil, err
		}
		results[i-1] = ctx
		if err := updatePrecomputeOverlay(overlay, ctx, blockHeight); err != nil {
			return nil, err
		}
	}

	return results, nil
}

// precomputeTxPreChecks runs the structural + covenant-genesis pre-validation the
// precompute/worker path must share with the sequential apply path. nil rotation
// carries no SimplicityDeploymentProvider, so the zero chain_id is unused here.
func precomputeTxPreChecks(tx *Tx, blockHeight uint64) error {
	if tx == nil {
		return txerr(TX_ERR_PARSE, "nil tx")
	}
	if tx.TxNonce == 0 {
		return txerr(TX_ERR_TX_NONCE_INVALID, "tx_nonce must be >= 1 for non-coinbase")
	}
	if len(tx.Inputs) == 0 {
		return txerr(TX_ERR_PARSE, "non-coinbase must have at least one input")
	}
	return ValidateTxCovenantsGenesis(tx, [32]byte{}, blockHeight, nil)
}

func precomputeTxContext(
	txIndex int,
	tx *Tx,
	txid [32]byte,
	overlay map[Outpoint]UtxoEntry,
	blockHeight uint64,
) (TxValidationContext, error) {
	if err := precomputeTxPreChecks(tx, blockHeight); err != nil {
		return TxValidationContext{}, err
	}

	inputs, err := collectPrecomputeTxInputs(tx, overlay, blockHeight)
	if err != nil {
		return TxValidationContext{}, err
	}

	witnessStart, witnessEnd, err := precomputeWitnessBounds(tx, inputs.TotalWitnessSlots)
	if err != nil {
		return TxValidationContext{}, err
	}

	var fee Uint128
	fee, err = computePrecomputeFee(inputs.SumIn, tx.Outputs)
	if err != nil {
		return TxValidationContext{}, err
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
		entry, op, slots, err := resolvePrecomputeInput(in, seenInputs, overlay, blockHeight)
		if err != nil {
			return precomputeTxInputs{}, err
		}
		out.ResolvedInputs = append(out.ResolvedInputs, cloneUtxoEntry(entry))
		out.InputOutpoints = append(out.InputOutpoints, op)
		if out.SumIn, err = addU64ToU128(out.SumIn, entry.Value); err != nil {
			return precomputeTxInputs{}, err
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
) (UtxoEntry, Outpoint, int, error) {
	var zeroTxid [32]byte
	if err := validateNonCoinbaseInputEncoding(in, zeroTxid); err != nil {
		return UtxoEntry{}, Outpoint{}, 0, err
	}

	op := Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
	if err := rememberPrecomputeInput(op, seenInputs); err != nil {
		return UtxoEntry{}, Outpoint{}, 0, err
	}

	entry, ok := overlay[op]
	if !ok {
		return UtxoEntry{}, Outpoint{}, 0, txerr(TX_ERR_MISSING_UTXO, "utxo not found")
	}
	if err := validatePrecomputeEntry(entry, blockHeight); err != nil {
		return UtxoEntry{}, Outpoint{}, 0, err
	}

	// CORE_SIMPLICITY is now a normal input (SIMPLICITY_WITNESS_SLOTS=1): witness slots are
	// accumulated like any other covenant so witness bounds cover the whole tx (RUB-615). The
	// former early stop was a reject-only artifact that truncated witness accounting.
	slots, err := precomputeWitnessSlots(entry)
	if err != nil {
		return UtxoEntry{}, Outpoint{}, 0, err
	}
	return entry, op, slots, nil
}

func rememberPrecomputeInput(op Outpoint, seenInputs map[Outpoint]struct{}) error {
	if _, exists := seenInputs[op]; exists {
		return txerr(TX_ERR_PARSE, "duplicate input outpoint")
	}
	seenInputs[op] = struct{}{}
	return nil
}

func validatePrecomputeEntry(entry UtxoEntry, blockHeight uint64) error {
	if entry.CovenantType == COV_TYPE_ANCHOR || entry.CovenantType == COV_TYPE_DA_COMMIT {
		return txerr(TX_ERR_MISSING_UTXO, "attempt to spend non-spendable covenant")
	}
	if entry.CreatedByCoinbase && (blockHeight < entry.CreationHeight || blockHeight-entry.CreationHeight < COINBASE_MATURITY) {
		return txerr(TX_ERR_COINBASE_IMMATURE, "coinbase immature")
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

func precomputeWitnessBounds(tx *Tx, totalWitnessSlots int) (int, int, error) {
	// Witness cursor is per-transaction (reset to 0 for each tx), matching
	// the sequential path in applyNonCoinbaseTxBasicWorkQ.
	witnessCursor := 0
	witnessStart := witnessCursor
	witnessEnd := witnessCursor + totalWitnessSlots
	if witnessEnd > len(tx.Witness) {
		return 0, 0, txerr(TX_ERR_PARSE, "witness underflow")
	}
	witnessCursor = witnessEnd
	if witnessCursor != len(tx.Witness) {
		return 0, 0, txerr(TX_ERR_PARSE, "witness_count mismatch")
	}
	return witnessStart, witnessEnd, nil
}

// computePrecomputeFee derives the same exact u128 fee the sequential and
// queued-parallel apply paths derive. It returns the full u128 difference:
// a fee above u64 is not an error here, so precompute cannot reject a
// transaction the other two paths accept.
func computePrecomputeFee(sumIn u128, outputs []TxOutput) (Uint128, error) {
	var sumOut u128
	for _, out := range outputs {
		var err error
		sumOut, err = addU64ToU128(sumOut, out.Value)
		if err != nil {
			return Uint128{}, err
		}
	}
	if cmpU128(sumIn, sumOut) < 0 {
		return Uint128{}, txerr(TX_ERR_VALUE_CONSERVATION, "outputs exceed inputs")
	}
	fee, err := subU128(sumIn, sumOut)
	if err != nil {
		return Uint128{}, err
	}
	return uint128FromInternal(fee), nil
}

func updatePrecomputeOverlay(
	overlay map[Outpoint]UtxoEntry,
	ctx TxValidationContext,
	blockHeight uint64,
) error {
	for _, op := range ctx.InputOutpoints {
		delete(overlay, op)
	}
	for j, out := range ctx.Tx.Outputs {
		if out.CovenantType == COV_TYPE_ANCHOR || out.CovenantType == COV_TYPE_DA_COMMIT {
			continue
		}
		if uint64(j) > uint64(^uint32(0)) {
			return txerr(TX_ERR_PARSE, "output index exceeds u32")
		}
		op := Outpoint{Txid: ctx.Txid, Vout: uint32(j)}
		overlay[op] = UtxoEntry{
			Value:          out.Value,
			CovenantType:   out.CovenantType,
			CovenantData:   append([]byte(nil), out.CovenantData...),
			CreationHeight: blockHeight,
		}
	}
	return nil
}
