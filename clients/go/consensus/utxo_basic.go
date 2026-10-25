package consensus

type nonCoinbaseApplyWorkInput struct {
	tx       *Tx
	txid     [32]byte
	utxoSet  map[Outpoint]UtxoEntry
	height   uint64
	blockMTP uint64
	chainID  [32]byte
	rotation RotationProvider
	registry *SuiteRegistry
	// sigCache is the optional caller-owned positive signature cache. Block
	// validation leaves it nil and keeps exact uncached behavior; only the live
	// Mempool owner passes one, through SuiteValidationContext.
	sigCache  *SigCache
	inputView *blockInputViewState
}

func applyNonCoinbaseTxBasicWork(input nonCoinbaseApplyWorkInput) (map[Outpoint]UtxoEntry, Uint128, error) {
	return (&nonCoinbaseApplyContext{
		tx:        input.tx,
		txid:      input.txid,
		work:      input.utxoSet,
		height:    input.height,
		blockMTP:  input.blockMTP,
		chainID:   input.chainID,
		rotation:  input.rotation,
		registry:  input.registry,
		sigCache:  input.sigCache,
		inputView: input.inputView,
	}).apply()
}

func cloneUtxoSet(src map[Outpoint]UtxoEntry) map[Outpoint]UtxoEntry {
	out := make(map[Outpoint]UtxoEntry, len(src))
	for k, v := range src {
		out[k] = cloneUtxoEntry(v)
	}
	return out
}

// ValidateSpendTxS1A checks a parsed non-coinbase transaction; the caller must
// exclude coinbase transactions. It never changes tx or caller state.
// The six families run in order: nonzero nonce, nonempty inputs, forbidden
// coinbase prevouts, empty script_sig, valid sequence, and unique outpoints.
// Each input family scans ascending indices and must pass before the next starts.
// Zero nonce returns TX_ERR_TX_NONCE_INVALID; sequence > 0x7fffffff returns
// TX_ERR_SEQUENCE_INVALID; other structural failures return TX_ERR_PARSE.
// A defensive nil tx refusal also returns TX_ERR_PARSE, outside the parsed domain.
// Rules: https://github.com/2tbmz9y2xt-lang/rubin-spec/blob/main/spec/RUBIN_L1_CANONICAL.md#16-transaction-structural-rules-normative
func ValidateSpendTxS1A(tx *Tx) error {
	if tx == nil {
		return txerr(TX_ERR_PARSE, "nil tx")
	}
	if tx.TxNonce == 0 {
		return txerr(TX_ERR_TX_NONCE_INVALID, "tx_nonce must be >= 1 for non-coinbase")
	}
	if len(tx.Inputs) == 0 {
		return txerr(TX_ERR_PARSE, "non-coinbase must have at least one input")
	}
	if err := validateSpendTxCoinbasePrevouts(tx.Inputs); err != nil {
		return err
	}
	if err := validateSpendTxScriptSigs(tx.Inputs); err != nil {
		return err
	}
	if err := validateSpendTxSequences(tx.Inputs); err != nil {
		return err
	}
	return validateSpendTxUniqueOutpoints(tx.Inputs)
}

func validateSpendTxCoinbasePrevouts(inputs []TxInput) error {
	for _, in := range inputs {
		if in.PrevVout == 0xffff_ffff && in.PrevTxid == ([32]byte{}) {
			return txerr(TX_ERR_PARSE, "coinbase prevout encoding forbidden in non-coinbase")
		}
	}
	return nil
}

func validateSpendTxScriptSigs(inputs []TxInput) error {
	for _, in := range inputs {
		if len(in.ScriptSig) != 0 {
			return txerr(TX_ERR_PARSE, "script_sig must be empty under genesis covenant set")
		}
	}
	return nil
}

func validateSpendTxSequences(inputs []TxInput) error {
	for _, in := range inputs {
		if in.Sequence > 0x7fffffff {
			return txerr(TX_ERR_SEQUENCE_INVALID, "sequence exceeds 0x7fffffff")
		}
	}
	return nil
}

func validateSpendTxUniqueOutpoints(inputs []TxInput) error {
	seen := make(map[Outpoint]struct{}, len(inputs))
	for _, in := range inputs {
		op := Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		if _, exists := seen[op]; exists {
			return txerr(TX_ERR_PARSE, "duplicate input outpoint")
		}
		seen[op] = struct{}{}
	}
	return nil
}

func (ctx *nonCoinbaseApplyContext) lookupInputEntry(in TxInput) (UtxoEntry, Outpoint, error) {
	op := Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
	entry, ok := ctx.work[op]
	if !ok && ctx.inputView != nil {
		var err error
		entry, err = ctx.inputView.lookup(op, len(ctx.resolved))
		if err != nil {
			return UtxoEntry{}, Outpoint{}, err
		}
		return entry, op, nil
	}
	if !ok {
		return UtxoEntry{}, Outpoint{}, txerr(TX_ERR_MISSING_UTXO, "utxo not found")
	}
	return entry, op, nil
}

func (ctx *nonCoinbaseApplyContext) validateResolvedInputEntry(entry UtxoEntry) error {
	if isNonSpendableInputCovenant(entry.CovenantType) {
		return txerrWithCause(TX_ERR_MISSING_UTXO, "attempt to spend non-spendable covenant", TxErrorCausePermanentNonSpendableCovenant)
	}
	if err := ctx.validateCoinbaseInputMaturity(entry); err != nil {
		return err
	}
	if err := checkSpendCovenant(entry.CovenantType, entry.CovenantData); err != nil {
		return err
	}
	return ctx.validateSimplicityInputDeployment(entry)
}

// validateSimplicityInputDeployment is the R1 deployment disposition of a
// CORE_SIMPLICITY input (CANONICAL §16 rule 7: inactive 0x0106 is unknown and
// rejects before witness-slot assignment). The bound surface memoizes the read.
func (ctx *nonCoinbaseApplyContext) validateSimplicityInputDeployment(entry UtxoEntry) error {
	if entry.CovenantType != COV_TYPE_CORE_SIMPLICITY {
		return nil
	}
	return validateCoreSimplicityDeploymentActive(ctx.chainID, ctx.height, simplicityDeploymentFromRotation(ctx.rotation))
}

func isNonSpendableInputCovenant(covType uint16) bool {
	return covType == COV_TYPE_ANCHOR || covType == COV_TYPE_DA_COMMIT
}

func (ctx *nonCoinbaseApplyContext) validateCoinbaseInputMaturity(entry UtxoEntry) error {
	if !entry.CreatedByCoinbase {
		return nil
	}
	// Guard the subtraction first so the maturity check cannot wrap.
	if ctx.height < entry.CreationHeight || ctx.height-entry.CreationHeight < COINBASE_MATURITY {
		return txerr(TX_ERR_COINBASE_IMMATURE, "coinbase immature")
	}
	return nil
}

func (ctx *nonCoinbaseApplyContext) resolvedEntries() []UtxoEntry {
	entries := make([]UtxoEntry, 0, len(ctx.resolved))
	for _, input := range ctx.resolved {
		entries = append(entries, input.entry)
	}
	return entries
}

func (ctx *nonCoinbaseApplyContext) validateInputSpend(inputIndex int, input nonCoinbaseResolvedInput) error {
	entry := input.entry
	assigned := input.witness
	switch entry.CovenantType {
	case COV_TYPE_P2PK:
		return ctx.validateP2PKInput(inputIndex, entry, assigned)
	case COV_TYPE_MULTISIG:
		return ctx.validateMultisigInput(inputIndex, entry, assigned)
	case COV_TYPE_VAULT:
		return ctx.validateVaultInput(inputIndex, entry, assigned)
	case COV_TYPE_HTLC:
		return ctx.validateHTLCInput(inputIndex, entry, assigned)
	case COV_TYPE_CORE_SIMPLICITY:
		return ctx.validateCoreSimplicityInput(inputIndex, entry, assigned)
	default:
		return nil
	}
}

func (ctx *nonCoinbaseApplyContext) validateP2PKInput(inputIndex int, entry UtxoEntry, assigned []WitnessItem) error {
	if len(assigned) != 1 {
		return txerr(TX_ERR_PARSE, "CORE_P2PK witness_slots must be 1")
	}
	if ctx.sigQueue != nil {
		return validateP2PKSpendQ(entry, assigned[0], ctx.tx, uint32(inputIndex), entry.Value, ctx.chainID, ctx.height, ctx.sighashCache, ctx.sigQueue, ctx.rotation, ctx.registry)
	}
	return validateP2PKSpendAtHeight(p2pkSpendCheck{
		entry:       entry,
		witness:     assigned[0],
		blockHeight: ctx.height,
		rotation:    ctx.rotation,
		sig: spendSigContext{
			tx:         ctx.tx,
			inputIndex: uint32(inputIndex),
			inputValue: entry.Value,
			chainID:    ctx.chainID,
			cache:      ctx.sighashCache,
			registry:   ctx.registry,
			sigCache:   ctx.sigCache,
		},
	})
}

func (ctx *nonCoinbaseApplyContext) validateMultisigInput(inputIndex int, entry UtxoEntry, assigned []WitnessItem) error {
	m, err := ParseMultisigCovenantData(entry.CovenantData)
	if err != nil {
		return err
	}
	if ctx.sigQueue != nil {
		return validateThresholdSigSpendQ(m.Keys, m.Threshold, assigned, ctx.tx, uint32(inputIndex), entry.Value, ctx.chainID, ctx.height, ctx.sighashCache, ctx.sigQueue, "CORE_MULTISIG", ctx.rotation, ctx.registry)
	}
	return validateThresholdSigSpendAtHeight(thresholdSigSpendCheck{
		keys:        m.Keys,
		threshold:   m.Threshold,
		witnesses:   assigned,
		blockHeight: ctx.height,
		rotation:    ctx.rotation,
		sig: spendSigContext{
			tx:         ctx.tx,
			inputIndex: uint32(inputIndex),
			inputValue: entry.Value,
			chainID:    ctx.chainID,
			cache:      ctx.sighashCache,
			registry:   ctx.registry,
			sigCache:   ctx.sigCache,
			context:    "CORE_MULTISIG",
		},
	})
}

func (ctx *nonCoinbaseApplyContext) captureVaultInput(inputIndex int, entry UtxoEntry, assigned []WitnessItem) error {
	v, err := ParseVaultCovenantDataForSpend(entry.CovenantData)
	if err != nil {
		return err
	}
	ctx.spend.vaultSigKeys = v.Keys
	ctx.spend.vaultSigThreshold = v.Threshold
	ctx.spend.vaultSigWitness = append([]WitnessItem(nil), assigned...)
	ctx.spend.vaultSigInputIndex = uint32(inputIndex)
	ctx.spend.vaultSigInputValue = entry.Value
	ctx.spend.vaultWhitelist = v.Whitelist
	ctx.spend.vaultOwnerLockID = v.OwnerLockID
	ctx.spend.haveVaultSig = true
	return nil
}

func (ctx *nonCoinbaseApplyContext) validateHTLCInput(inputIndex int, entry UtxoEntry, assigned []WitnessItem) error {
	if len(assigned) != 2 {
		return txerr(TX_ERR_PARSE, "CORE_HTLC witness_slots must be 2")
	}
	if ctx.sigQueue != nil {
		return validateHTLCSpendQ(entry, assigned[0], assigned[1], ctx.tx, uint32(inputIndex), entry.Value, ctx.chainID, ctx.height, ctx.blockMTP, ctx.sighashCache, ctx.sigQueue, ctx.rotation, ctx.registry)
	}
	return validateHTLCSpendAtHeightWithSigCache(htlcSpendCheck{
		entry:       entry,
		pathItem:    assigned[0],
		sigItem:     assigned[1],
		tx:          ctx.tx,
		inputIndex:  uint32(inputIndex),
		inputValue:  entry.Value,
		chainID:     ctx.chainID,
		blockHeight: ctx.height,
		blockMTP:    ctx.blockMTP,
		cache:       ctx.sighashCache,
		rotation:    ctx.rotation,
		registry:    ctx.registry,
		sigCache:    ctx.sigCache,
	})
}

func (ctx *nonCoinbaseApplyContext) validateCoreSimplicityInput(inputIndex int, entry UtxoEntry, assigned []WitnessItem) error {
	if len(assigned) != SIMPLICITY_WITNESS_SLOTS {
		return txerr(TX_ERR_PARSE, "CORE_SIMPLICITY witness_slots must be 1")
	}
	return validateCoreSimplicitySpendAtHeight(coreSimplicitySpendValidation{
		entry:       entry,
		witness:     assigned[0],
		tx:          ctx.tx,
		inputIndex:  uint32(inputIndex),
		inputValue:  entry.Value,
		chainID:     ctx.chainID,
		blockHeight: ctx.height,
		cache:       ctx.sighashCache,
		txContext:   ctx.simplicityCtx,
	})
}
