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

	// Build a working UTXO overlay that tracks same-block produced outputs.
	// We start from the immutable snapshot and add outputs created by earlier
	// transactions in the same block. The original snapshot is never modified.
	overlay := make(map[Outpoint]UtxoEntry, len(utxoSnapshot))
	for k, v := range utxoSnapshot {
		overlay[k] = v
	}

	results := make([]TxValidationContext, txCount)

	for i := 1; i < len(pb.Txs); i++ {
		// Witness cursor is per-transaction (reset to 0 for each tx),
		// matching the sequential path in applyNonCoinbaseTxBasicWorkQ.
		witnessCursor := 0
		tx := pb.Txs[i]
		txid := pb.Txids[i]
		idx := i - 1 // 0-based index into results

		if tx == nil {
			return nil, txerr(TX_ERR_PARSE, "nil tx")
		}
		if len(tx.Inputs) == 0 {
			return nil, txerr(TX_ERR_PARSE, "non-coinbase must have at least one input")
		}

		// Resolve inputs and compute witness boundaries.
		resolvedInputs := make([]UtxoEntry, len(tx.Inputs))
		inputOutpoints := make([]Outpoint, len(tx.Inputs))
		seenInputs := make(map[Outpoint]struct{}, len(tx.Inputs))
		var zeroTxid [32]byte
		totalWitnessSlots := 0

		var sumIn u128
		for j, in := range tx.Inputs {
			// Basic input validation (matches sequential path).
			if in.PrevVout == 0xffff_ffff && in.PrevTxid == zeroTxid {
				return nil, txerr(TX_ERR_PARSE, "coinbase prevout encoding forbidden in non-coinbase")
			}
			op := Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
			if _, exists := seenInputs[op]; exists {
				return nil, txerr(TX_ERR_PARSE, "duplicate input outpoint")
			}
			seenInputs[op] = struct{}{}

			entry, ok := overlay[op]
			if !ok {
				return nil, txerr(TX_ERR_MISSING_UTXO, "utxo not found")
			}

			// Early-reject immature coinbase outputs (defense-in-depth;
			// also checked downstream in the sequential validation path).
			if entry.CreatedByCoinbase && (blockHeight < entry.CreationHeight || blockHeight-entry.CreationHeight < COINBASE_MATURITY) {
				return nil, txerr(TX_ERR_COINBASE_IMMATURE, "coinbase immature")
			}

			if entry.CovenantType == COV_TYPE_ANCHOR || entry.CovenantType == COV_TYPE_DA_COMMIT {
				return nil, txerr(TX_ERR_MISSING_UTXO, "attempt to spend non-spendable covenant")
			}

			slots, err := WitnessSlots(entry.CovenantType, entry.CovenantData)
			if err != nil {
				return nil, err
			}
			if slots <= 0 {
				return nil, txerr(TX_ERR_PARSE, "invalid witness slots")
			}
			newTotal, err3 := addWitnessSlots(totalWitnessSlots, slots)
			if err3 != nil {
				return nil, err3
			}
			totalWitnessSlots = newTotal

			resolvedInputs[j] = entry
			inputOutpoints[j] = op
			var err2 error
			sumIn, err2 = addU64ToU128(sumIn, entry.Value)
			if err2 != nil {
				return nil, err2
			}
		}

		// Witness boundary check.
		witnessStart := witnessCursor
		witnessEnd := witnessCursor + totalWitnessSlots
		if witnessEnd > len(tx.Witness) {
			return nil, txerr(TX_ERR_PARSE, "witness underflow")
		}
		witnessCursor = witnessEnd
		if witnessCursor != len(tx.Witness) {
			return nil, txerr(TX_ERR_PARSE, "witness_count mismatch")
		}

		// Compute fee (sumIn - sumOut), matching sequential path value conservation.
		var sumOut u128
		for _, out := range tx.Outputs {
			var err2 error
			sumOut, err2 = addU64ToU128(sumOut, out.Value)
			if err2 != nil {
				return nil, err2
			}
		}
		if cmpU128(sumIn, sumOut) < 0 {
			return nil, txerr(TX_ERR_VALUE_CONSERVATION, "outputs exceed inputs")
		}
		feeBig, err := subU128(sumIn, sumOut)
		if err != nil {
			return nil, err
		}
		if feeBig.hi != 0 {
			return nil, txerr(TX_ERR_VALUE_CONSERVATION, "fee overflow u64")
		}

		// Precompute sighash cache.
		sighashCache, err := NewSighashV1PrehashCache(tx)
		if err != nil {
			return nil, err
		}

		results[idx] = TxValidationContext{
			TxIndex:        i,
			Tx:             tx,
			Txid:           txid,
			ResolvedInputs: resolvedInputs,
			WitnessStart:   witnessStart,
			WitnessEnd:     witnessEnd,
			SighashCache:   sighashCache,
			InputOutpoints: inputOutpoints,
			Fee:            feeBig.lo,
		}

		// Track same-block outputs: remove spent UTXOs, add created outputs.
		// This ensures later transactions can resolve parent-child dependencies.
		for _, op := range inputOutpoints {
			delete(overlay, op)
		}
		for j, out := range tx.Outputs {
			if out.CovenantType == COV_TYPE_ANCHOR || out.CovenantType == COV_TYPE_DA_COMMIT {
				continue
			}
			op := Outpoint{Txid: txid, Vout: uint32(j)}
			overlay[op] = UtxoEntry{
				Value:          out.Value,
				CovenantType:   out.CovenantType,
				CovenantData:   append([]byte(nil), out.CovenantData...),
				CreationHeight: blockHeight,
			}
		}
	}

	return results, nil
}
