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

type txValidationWorkerEnv struct {
	tx              *Tx
	resolvedInputs  []UtxoEntry
	chainID         [32]byte
	blockHeight     uint64
	blockMTP        uint64
	sighashCache    *SighashV1PrehashCache
	coreExtProfiles CoreExtProfileProvider
	sigQueue        *SigCheckQueue
	rotation        RotationProvider
	registry        *SuiteRegistry
	txContext       *TxContextBundle
	simplicityCtx   *SimplicityTxContext
}

type txInputSpendCheck struct {
	entry      UtxoEntry
	assigned   []WitnessItem
	tx         *Tx
	inputIndex uint32
	inputValue uint64
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
	result := TxValidationResult{TxIndex: tvc.TxIndex, Fee: tvc.Fee}
	tx := tvc.Tx
	if tx == nil {
		result.Err = txerr(TX_ERR_PARSE, "nil tx in TxValidationContext")
		return result
	}
	if len(tx.Inputs) != len(tvc.ResolvedInputs) {
		result.Err = txerr(TX_ERR_PARSE, "txcontext resolved input count mismatch")
		return result
	}
	env := newTxValidationWorkerEnv(tvc, chainID, blockHeight, blockMTP, coreExtProfiles, sigCache)

	if !hasCoreSimplicityInput(tvc.ResolvedInputs) {
		txContext, err := buildWorkerTxContext(tx, tvc.ResolvedInputs, env)
		if err != nil {
			result.Err = err
			return result
		}
		env.txContext = txContext
	}

	if err := validateTxLocalInputs(tvc, tx, &env); err != nil {
		result.Err = err
		return result
	}
	finishTxValidationResult(&result, env.sigQueue)
	return result
}

func newTxValidationWorkerEnv(
	tvc TxValidationContext,
	chainID [32]byte,
	blockHeight uint64,
	blockMTP uint64,
	coreExtProfiles CoreExtProfileProvider,
	sigCache *SigCache,
) txValidationWorkerEnv {
	if coreExtProfiles == nil {
		coreExtProfiles = EmptyCoreExtProfileProvider()
	}
	registry := DefaultSuiteRegistry()
	sigQueue := NewSigCheckQueue(1).WithRegistry(registry)
	if sigCache != nil {
		sigQueue.WithCache(sigCache)
	}
	return txValidationWorkerEnv{
		tx:              tvc.Tx,
		resolvedInputs:  tvc.ResolvedInputs,
		chainID:         chainID,
		blockHeight:     blockHeight,
		blockMTP:        blockMTP,
		sighashCache:    tvc.SighashCache,
		coreExtProfiles: coreExtProfiles,
		sigQueue:        sigQueue,
		rotation:        DefaultRotationProvider{},
		registry:        registry,
	}
}

func buildWorkerTxContext(tx *Tx, resolvedInputs []UtxoEntry, env txValidationWorkerEnv) (*TxContextBundle, error) {
	txContextExtIDs, err := collectTxContextExtIDs(resolvedInputs, env.blockHeight, env.coreExtProfiles)
	if err != nil {
		return nil, err
	}
	if len(txContextExtIDs) == 0 {
		return nil, nil
	}
	outputExtIDCache, err := BuildTxContextOutputExtIDCache(tx)
	if err != nil {
		return nil, err
	}
	return BuildTxContext(tx, resolvedInputs, outputExtIDCache, env.blockHeight, env.coreExtProfiles)
}

func (env *txValidationWorkerEnv) ensureCoreExtTxContext() error {
	if env.txContext != nil {
		return nil
	}
	txContext, err := buildWorkerTxContext(env.tx, env.resolvedInputs, *env)
	if err != nil {
		return err
	}
	env.txContext = txContext
	return nil
}

func (env *txValidationWorkerEnv) ensureSimplicityTxContext() (*SimplicityTxContext, error) {
	if env.simplicityCtx != nil {
		return env.simplicityCtx, nil
	}
	txContext, err := BuildSimplicityTxContext(env.tx, env.resolvedInputs, env.blockHeight, env.chainID)
	if err != nil {
		return nil, err
	}
	env.simplicityCtx = txContext
	return txContext, nil
}

func validateTxLocalInputs(tvc TxValidationContext, tx *Tx, env *txValidationWorkerEnv) error {
	witnessCursor := tvc.WitnessStart
	for inputIndex, entry := range tvc.ResolvedInputs {
		assigned, slots, err := assignedWorkerWitness(tx, tvc, entry, witnessCursor)
		if err != nil {
			return err
		}
		check := txInputSpendCheck{
			entry:      entry,
			assigned:   assigned,
			tx:         tx,
			inputIndex: uint32(inputIndex),
			inputValue: entry.Value,
		}
		if err := validateInputSpendQ(check, env); err != nil {
			return err
		}
		witnessCursor += slots
	}
	if witnessCursor != len(tx.Witness) {
		return txerr(TX_ERR_PARSE, "witness_count mismatch")
	}
	return nil
}

func assignedWorkerWitness(tx *Tx, tvc TxValidationContext, entry UtxoEntry, witnessCursor int) ([]WitnessItem, int, error) {
	slots, err := WitnessSlots(entry.CovenantType, entry.CovenantData)
	if err != nil {
		return nil, 0, err
	}
	witnessEnd := min(tvc.WitnessEnd, len(tx.Witness))
	if witnessCursor+slots > witnessEnd {
		return nil, 0, txerr(TX_ERR_PARSE, "witness underflow in worker")
	}
	return tx.Witness[witnessCursor : witnessCursor+slots], slots, nil
}

func finishTxValidationResult(result *TxValidationResult, sigQueue *SigCheckQueue) {
	result.SigCount = sigQueue.Len()
	if err := sigQueue.Flush(); err != nil {
		result.Err = err
		return
	}
	result.Valid = true
}

// validateInputSpendQ dispatches a single input to the appropriate Q-variant
// spend validator based on covenant type. This mirrors the switch in
// applyNonCoinbaseTxBasicWorkQ but without UTXO mutations.
func validateInputSpendQ(check txInputSpendCheck, env *txValidationWorkerEnv) error {
	switch check.entry.CovenantType {
	case COV_TYPE_P2PK:
		return validateP2PKInputSpendQ(check, env)
	case COV_TYPE_MULTISIG:
		return validateMultisigInputSpendQ(check, env)
	case COV_TYPE_VAULT:
		return validateVaultInputSpendQ(check, env)
	case COV_TYPE_HTLC:
		return validateHTLCInputSpendQ(check, env)
	case COV_TYPE_CORE_EXT:
		return validateCoreExtInputSpendQ(check, env)
	case COV_TYPE_CORE_STEALTH:
		return validateCoreStealthInputSpendQ(check, env)
	case COV_TYPE_CORE_SIMPLICITY:
		return validateCoreSimplicityInputSpendQ(check, env)
	default:
		// Other covenant types have no spend-time checks in the genesis set.
		return nil
	}
}

func validateP2PKInputSpendQ(check txInputSpendCheck, env *txValidationWorkerEnv) error {
	if len(check.assigned) != 1 {
		return txerr(TX_ERR_PARSE, "CORE_P2PK witness_slots must be 1")
	}
	return validateP2PKSpendQ(
		check.entry, check.assigned[0], check.tx, check.inputIndex, check.inputValue,
		env.chainID, env.blockHeight, env.sighashCache, env.sigQueue, env.rotation, env.registry,
	)
}

func validateMultisigInputSpendQ(check txInputSpendCheck, env *txValidationWorkerEnv) error {
	m, err := ParseMultisigCovenantData(check.entry.CovenantData)
	if err != nil {
		return err
	}
	return validateThresholdSigSpendQ(
		m.Keys, m.Threshold, check.assigned, check.tx, check.inputIndex,
		check.inputValue, env.chainID, env.blockHeight, env.sighashCache,
		env.sigQueue, "CORE_MULTISIG", env.rotation, env.registry,
	)
}

func validateVaultInputSpendQ(check txInputSpendCheck, env *txValidationWorkerEnv) error {
	// Vault: only verify threshold signature in the worker. Full vault policy
	// (whitelist, owner lock, output checks) is enforced in the commit stage.
	v, err := ParseVaultCovenantDataForSpend(check.entry.CovenantData)
	if err != nil {
		return err
	}
	return validateThresholdSigSpendQ(
		v.Keys, v.Threshold, check.assigned, check.tx, check.inputIndex,
		check.inputValue, env.chainID, env.blockHeight, env.sighashCache,
		env.sigQueue, "CORE_VAULT", env.rotation, env.registry,
	)
}

func validateHTLCInputSpendQ(check txInputSpendCheck, env *txValidationWorkerEnv) error {
	if len(check.assigned) != 2 {
		return txerr(TX_ERR_PARSE, "CORE_HTLC witness_slots must be 2")
	}
	return validateHTLCSpendQ(
		check.entry, check.assigned[0], check.assigned[1], check.tx,
		check.inputIndex, check.inputValue, env.chainID, env.blockHeight,
		env.blockMTP, env.sighashCache, env.sigQueue, env.rotation, env.registry,
	)
}

func validateCoreExtInputSpendQ(check txInputSpendCheck, env *txValidationWorkerEnv) error {
	if len(check.assigned) != CORE_EXT_WITNESS_SLOTS {
		return txerr(TX_ERR_PARSE, "CORE_EXT witness_slots must be 1")
	}
	return validateCoreExtSpendQWithEnv(check, check.assigned[0], env)
}

func validateCoreStealthInputSpendQ(check txInputSpendCheck, env *txValidationWorkerEnv) error {
	if len(check.assigned) != CORE_STEALTH_WITNESS_SLOTS {
		return txerr(TX_ERR_PARSE, "CORE_STEALTH witness_slots must be 1")
	}
	return validateCoreStealthSpendQ(
		check.entry, check.assigned[0], check.tx, check.inputIndex, check.inputValue,
		env.chainID, env.blockHeight, env.sighashCache, env.sigQueue, env.rotation, env.registry,
	)
}

func validateCoreSimplicityInputSpendQ(check txInputSpendCheck, env *txValidationWorkerEnv) error {
	if len(check.assigned) != SIMPLICITY_WITNESS_SLOTS {
		return txerr(TX_ERR_PARSE, "CORE_SIMPLICITY witness_slots must be 1")
	}
	return validateCoreSimplicitySpend(check.entry, check.assigned[0], env.ensureSimplicityTxContext)
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
	args ...any,
) error {
	if len(args) != 8 {
		return txerr(TX_ERR_PARSE, "CORE_EXT validator argument count mismatch")
	}
	env, err := func() (env txValidationWorkerEnv, err error) {
		defer func() {
			if recover() != nil {
				err = txerr(TX_ERR_PARSE, "CORE_EXT validator argument type mismatch")
			}
		}()
		return txValidationWorkerEnv{
			chainID:         args[0].([32]byte),
			blockHeight:     args[1].(uint64),
			sighashCache:    typedArgOrZero[*SighashV1PrehashCache](args[2]),
			coreExtProfiles: typedArgOrZero[CoreExtProfileProvider](args[3]),
			sigQueue:        typedArgOrZero[*SigCheckQueue](args[4]),
			rotation:        typedArgOrZero[RotationProvider](args[5]),
			registry:        typedArgOrZero[*SuiteRegistry](args[6]),
			txContext:       typedArgOrZero[*TxContextBundle](args[7]),
		}, nil
	}()
	if err != nil {
		return err
	}
	check := txInputSpendCheck{
		entry:      entry,
		assigned:   []WitnessItem{w},
		tx:         tx,
		inputIndex: inputIndex,
		inputValue: inputValue,
	}
	return validateCoreExtSpendQWithEnv(check, w, &env)
}

func typedArgOrZero[T any](v any) T {
	if v == nil {
		var zero T
		return zero
	}
	return v.(T)
}

func validateCoreExtSpendQWithEnv(check txInputSpendCheck, w WitnessItem, env *txValidationWorkerEnv) error {
	cd, err := ParseCoreExtCovenantData(check.entry.CovenantData)
	if err != nil {
		return err
	}
	if env.coreExtProfiles == nil {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT profile provider missing")
	}
	profile, ok, err := env.coreExtProfiles.LookupCoreExtProfile(cd.ExtID, env.blockHeight)
	switch {
	case err != nil:
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT profile lookup failure")
	case !ok || !profile.Active:
		return nil
	default:
		if err := env.ensureCoreExtTxContext(); err != nil {
			return err
		}
		return validateCoreExtWitnessAtHeight(coreExtWitnessValidation{
			cd:           cd,
			profile:      profile,
			w:            w,
			tx:           check.tx,
			inputIndex:   check.inputIndex,
			inputValue:   check.inputValue,
			chainID:      env.chainID,
			blockHeight:  env.blockHeight,
			sighashCache: env.sighashCache,
			rotation:     env.rotation,
			registry:     env.registry,
			txContext:    env.txContext,
			sigQueue:     env.sigQueue,
		})
	}
}

// RunTxValidationWorkers validates multiple transactions in parallel using
// WorkerPool. Returns results in submission order; use FirstTxError to get
// the first failing transaction. Returns a run error only if the worker-pool
// substrate itself rejects the batch before task execution starts.
func RunTxValidationWorkers(
	ctx context.Context,
	maxWorkers int,
	txcs []TxValidationContext,
	chainID [32]byte,
	blockHeight uint64,
	blockMTP uint64,
	coreExtProfiles CoreExtProfileProvider,
	sigCache *SigCache,
) ([]WorkerResult[TxValidationResult], error) {
	return RunFunc(ctx, maxWorkers, len(txcs), txcs, func(ctx context.Context, tvc TxValidationContext) (TxValidationResult, error) {
		r := ValidateTxLocal(tvc, chainID, blockHeight, blockMTP, coreExtProfiles, sigCache)
		if r.Err != nil {
			return r, r.Err
		}
		return r, nil
	})
}

type txValidationFailure struct {
	txIndex int
	err     error
}

// FirstTxError returns the first error by transaction index from validation
// results, or nil if all transactions are valid.
func FirstTxError(results []WorkerResult[TxValidationResult]) error {
	var best txValidationFailure
	for _, r := range results {
		if r.Err == nil {
			continue
		}
		candidate := txValidationFailure{txIndex: r.Value.TxIndex, err: r.Err}
		if best.err == nil {
			best = candidate
			continue
		}
		if candidate.isBefore(best) {
			best = candidate
		}
	}
	return best.err
}

func (candidate txValidationFailure) isBefore(best txValidationFailure) bool {
	if candidate.txIndex <= 0 {
		return false
	}
	if best.txIndex <= 0 {
		return true
	}
	return candidate.txIndex < best.txIndex
}
