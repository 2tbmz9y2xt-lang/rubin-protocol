package consensus

import "context"

// TxValidationResult holds the outcome of validating a single non-coinbase
// transaction in a parallel worker. Workers perform read-only checks against
// precomputed TxValidationContext and do NOT mutate UTXO or consensus state.
type TxValidationResult struct {
	// TxIndex is the block-level index of this transaction (1-based).
	TxIndex int

	// Valid is true if all input-level spend checks and signature
	// verifications passed.
	Valid bool

	// Err is non-nil if validation failed. The error is a canonical
	// TX_ERR_* error suitable for deterministic error reporting.
	Err error

	// SigCount is the number of signature verification operations that
	// were executed (including deferred+flushed).
	SigCount int

	// Fee is the precomputed transaction fee, copied from TxValidationContext.
	Fee uint64
}

// ValidateTxLocal validates a single non-coinbase transaction using read-only
// precomputed context. It creates a per-worker SigCheckQueue to batch ML-DSA-87
// verifications, calls the existing Q-variant spend validators for each input,
// and flushes the queue at the end.
//
// This function does NOT modify any UTXO set or consensus state. It is safe
// to call concurrently from multiple goroutines.
//
// Vault inputs: only the threshold signature is verified here. Full vault
// policy (whitelist, owner lock, output rules) is enforced in the sequential
// commit stage, which has access to block-level context.
func ValidateTxLocal(
	tvc TxValidationContext,
	chainID [32]byte,
	blockHeight uint64,
	blockMTP uint64,
	coreExtProfiles CoreExtProfileProvider,
	sigCache *SigCache,
) TxValidationResult {
	result := TxValidationResult{
		TxIndex: tvc.TxIndex,
		Fee:     tvc.Fee,
	}
	if coreExtProfiles == nil {
		coreExtProfiles = EmptyCoreExtProfileProvider()
	}

	tx := tvc.Tx
	if tx == nil {
		result.Err = txerr(TX_ERR_PARSE, "nil tx in TxValidationContext")
		return result
	}

	// Create per-worker sig queue (rotation-aware so Flush uses verifySigWithRegistry).
	reg := DefaultSuiteRegistry()
	rot := DefaultRotationProvider{}
	sigQueue := NewSigCheckQueue(1).WithRegistry(reg)
	if sigCache != nil {
		sigQueue.WithCache(sigCache)
	}

	witnessCursor := tvc.WitnessStart
	for inputIndex, entry := range tvc.ResolvedInputs {
		slots, err := WitnessSlots(entry.CovenantType, entry.CovenantData)
		if err != nil {
			result.Err = err
			return result
		}
		if witnessCursor+slots > tvc.WitnessEnd {
			result.Err = txerr(TX_ERR_PARSE, "witness underflow in worker")
			return result
		}
		assigned := tx.Witness[witnessCursor : witnessCursor+slots]

		if err := validateInputSpendQ(
			entry, assigned, tx, uint32(inputIndex), entry.Value,
			chainID, blockHeight, blockMTP, tvc.SighashCache,
			coreExtProfiles, sigQueue, rot, reg,
		); err != nil {
			result.Err = err
			return result
		}

		witnessCursor += slots
	}

	result.SigCount = sigQueue.Len()

	// Flush deferred signature verifications.
	if err := sigQueue.Flush(); err != nil {
		result.Err = err
		return result
	}

	result.Valid = true
	return result
}

// validateInputSpendQ dispatches a single input to the appropriate Q-variant
// spend validator based on covenant type. This mirrors the switch in
// applyNonCoinbaseTxBasicWorkQ but without UTXO mutations.
func validateInputSpendQ(
	entry UtxoEntry,
	assigned []WitnessItem,
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
	chainID [32]byte,
	blockHeight uint64,
	blockMTP uint64,
	sighashCache *SighashV1PrehashCache,
	coreExtProfiles CoreExtProfileProvider,
	sigQueue *SigCheckQueue,
	rotation RotationProvider,
	registry *SuiteRegistry,
) error {
	switch entry.CovenantType {
	case COV_TYPE_P2PK:
		if len(assigned) != 1 {
			return txerr(TX_ERR_PARSE, "CORE_P2PK witness_slots must be 1")
		}
		return validateP2PKSpendQ(entry, assigned[0], tx, inputIndex, inputValue, chainID, blockHeight, sighashCache, sigQueue, rotation, registry)

	case COV_TYPE_MULTISIG:
		m, err := ParseMultisigCovenantData(entry.CovenantData)
		if err != nil {
			return err
		}
		return validateThresholdSigSpendQ(
			m.Keys, m.Threshold, assigned, tx, inputIndex, inputValue,
			chainID, blockHeight, sighashCache, sigQueue, "CORE_MULTISIG",
			rotation, registry,
		)

	case COV_TYPE_VAULT:
		// Vault: only verify threshold signature in the worker.
		// Full vault policy (whitelist, owner lock, output checks)
		// is enforced in the sequential commit stage.
		v, err := ParseVaultCovenantDataForSpend(entry.CovenantData)
		if err != nil {
			return err
		}
		return validateThresholdSigSpendQ(
			v.Keys, v.Threshold, assigned, tx, inputIndex, inputValue,
			chainID, blockHeight, sighashCache, sigQueue, "CORE_VAULT",
			rotation, registry,
		)

	case COV_TYPE_HTLC:
		if len(assigned) != 2 {
			return txerr(TX_ERR_PARSE, "CORE_HTLC witness_slots must be 2")
		}
		return validateHTLCSpendQ(
			entry, assigned[0], assigned[1], tx, inputIndex, inputValue,
			chainID, blockHeight, blockMTP, sighashCache, sigQueue,
			rotation, registry,
		)

	case COV_TYPE_CORE_EXT:
		if len(assigned) != CORE_EXT_WITNESS_SLOTS {
			return txerr(TX_ERR_PARSE, "CORE_EXT witness_slots must be 1")
		}
		return validateCoreExtSpendQ(
			entry, assigned[0], tx, inputIndex, inputValue,
			chainID, blockHeight, sighashCache, coreExtProfiles, sigQueue,
			rotation, registry,
		)

	case COV_TYPE_CORE_STEALTH:
		if len(assigned) != CORE_STEALTH_WITNESS_SLOTS {
			return txerr(TX_ERR_PARSE, "CORE_STEALTH witness_slots must be 1")
		}
		return validateCoreStealthSpendQ(entry, assigned[0], tx, inputIndex, inputValue, chainID, blockHeight, sighashCache, sigQueue, rotation, registry)

	default:
		// Other covenant types have no spend-time checks in the genesis set.
		return nil
	}
}

// validateCoreExtSpendQ is the queue-aware CORE_EXT spend validator, extracted
// from the inline logic in applyNonCoinbaseTxBasicWorkQ. ML-DSA-87 signatures
// are deferred to sigQueue; external verifiers (non-ML-DSA suites) are called
// inline because they may not be thread-safe.
func validateCoreExtSpendQ(
	entry UtxoEntry,
	w WitnessItem,
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
	chainID [32]byte,
	blockHeight uint64,
	sighashCache *SighashV1PrehashCache,
	coreExtProfiles CoreExtProfileProvider,
	sigQueue *SigCheckQueue,
	rotation RotationProvider,
	registry *SuiteRegistry,
) error {
	cd, err := ParseCoreExtCovenantData(entry.CovenantData)
	if err != nil {
		return err
	}

	if coreExtProfiles == nil {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT profile provider missing")
	}

	profile := CoreExtProfile{}
	active := false
	resolved, ok, err := coreExtProfiles.LookupCoreExtProfile(cd.ExtID, blockHeight)
	if err != nil {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT profile lookup failure")
	}
	if ok && resolved.Active {
		active = true
		profile = resolved
	}

	if !active {
		return nil
	}
	return validateCoreExtWitnessAtHeight(
		cd,
		profile,
		w,
		tx,
		inputIndex,
		inputValue,
		chainID,
		blockHeight,
		sighashCache,
		rotation,
		registry,
		sigQueue,
	)
}

// RunTxValidationWorkers validates multiple transactions in parallel using
// WorkerPool. Returns results in submission order; use FirstTxError to get
// the first failing transaction.
func RunTxValidationWorkers(
	ctx context.Context,
	maxWorkers int,
	txcs []TxValidationContext,
	chainID [32]byte,
	blockHeight uint64,
	blockMTP uint64,
	coreExtProfiles CoreExtProfileProvider,
	sigCache *SigCache,
) []WorkerResult[TxValidationResult] {
	return RunFunc(ctx, maxWorkers, txcs, func(ctx context.Context, tvc TxValidationContext) (TxValidationResult, error) {
		r := ValidateTxLocal(tvc, chainID, blockHeight, blockMTP, coreExtProfiles, sigCache)
		if r.Err != nil {
			return r, r.Err
		}
		return r, nil
	})
}

// FirstTxError returns the first error by transaction index from validation
// results, or nil if all transactions are valid.
func FirstTxError(results []WorkerResult[TxValidationResult]) error {
	var (
		haveErr    bool
		minTxIndex int
		minErr     error
	)
	for _, r := range results {
		if r.Err == nil {
			continue
		}
		// Prefer the canonical tx index if available.
		txIndex := r.Value.TxIndex
		if txIndex <= 0 {
			// Defensive fallback: if we somehow lost the tx index, preserve
			// deterministic behavior by keeping the first such error seen.
			if !haveErr {
				haveErr = true
				minTxIndex = txIndex
				minErr = r.Err
			}
			continue
		}
		if !haveErr || minTxIndex <= 0 || txIndex < minTxIndex {
			haveErr = true
			minTxIndex = txIndex
			minErr = r.Err
		}
	}
	if !haveErr {
		return nil
	}
	return minErr
}
