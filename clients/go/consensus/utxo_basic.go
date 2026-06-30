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
}

func applyNonCoinbaseTxBasicWork(input nonCoinbaseApplyWorkInput) (map[Outpoint]UtxoEntry, uint64, error) {
	return (&nonCoinbaseApplyContext{
		tx:       input.tx,
		txid:     input.txid,
		work:     input.utxoSet,
		height:   input.height,
		blockMTP: input.blockMTP,
		chainID:  input.chainID,
		rotation: input.rotation,
		registry: input.registry,
	}).apply()
}

func (ctx *nonCoinbaseApplyContext) apply() (map[Outpoint]UtxoEntry, uint64, error) {
	if err := ctx.applyPreOutputPhases(); err != nil {
		return nil, 0, err
	}
	if err := ctx.addSpendableOutputs(); err != nil {
		return nil, 0, err
	}
	if err := ctx.applyPostOutputRules(); err != nil {
		return nil, 0, err
	}
	fee, err := ctx.finalizeValueAndFee()
	if err != nil {
		return nil, 0, err
	}
	return ctx.work, fee, nil
}

func (ctx *nonCoinbaseApplyContext) applyPreOutputPhases() error {
	if err := ctx.prepare(); err != nil {
		return err
	}
	if err := ctx.resolveInputs(); err != nil {
		return err
	}
	return ctx.validateInputSpends()
}

func (ctx *nonCoinbaseApplyContext) applyPostOutputRules() error {
	if ctx.createsVault {
		if err := ctx.validateVaultCreations(); err != nil {
			return err
		}
	}
	if ctx.spend.vaultInputCount == 1 {
		if err := ctx.validateVaultSpend(); err != nil {
			return err
		}
	}
	return nil
}

func cloneUtxoSet(src map[Outpoint]UtxoEntry) map[Outpoint]UtxoEntry {
	out := make(map[Outpoint]UtxoEntry, len(src))
	for k, v := range src {
		out[k] = cloneUtxoEntry(v)
	}
	return out
}

func (ctx *nonCoinbaseApplyContext) prepare() error {
	if ctx.tx == nil {
		return txerr(TX_ERR_PARSE, "nil tx")
	}
	if len(ctx.tx.Inputs) == 0 {
		return txerr(TX_ERR_PARSE, "non-coinbase must have at least one input")
	}
	if ctx.tx.TxNonce == 0 {
		return txerr(TX_ERR_TX_NONCE_INVALID, "tx_nonce must be >= 1 for non-coinbase")
	}
	if err := ValidateTxCovenantsGenesis(ctx.tx, ctx.height, ctx.rotation); err != nil {
		return err
	}
	sighashCache, err := NewSighashV1PrehashCache(ctx.tx)
	if err != nil {
		return err
	}
	ctx.sighashCache = sighashCache
	return nil
}

func (ctx *nonCoinbaseApplyContext) resolveInputs() error {
	seenInputs := make(map[Outpoint]struct{}, len(ctx.tx.Inputs))
	var zeroTxid [32]byte
	witnessCursor := 0
	ctx.resolved = make([]nonCoinbaseResolvedInput, 0, len(ctx.tx.Inputs))
	for _, in := range ctx.tx.Inputs {
		entry, op, err := ctx.resolveInput(in, seenInputs, zeroTxid)
		if err != nil {
			return err
		}
		if entry.CovenantType == COV_TYPE_CORE_SIMPLICITY {
			if err := ctx.validateCoinbaseInputMaturity(entry); err != nil {
				return err
			}
			ctx.resolved = append(ctx.resolved, nonCoinbaseResolvedInput{
				entry:    entry,
				outpoint: op,
			})
			return nil
		}
		if err := ctx.validateResolvedInputEntry(entry); err != nil {
			return err
		}
		slots, err := WitnessSlots(entry.CovenantType, entry.CovenantData)
		if err != nil {
			return err
		}
		if slots <= 0 {
			return txerr(TX_ERR_PARSE, "invalid witness slots")
		}
		if witnessCursor+slots > len(ctx.tx.Witness) {
			return txerr(TX_ERR_PARSE, "witness underflow")
		}
		assigned := ctx.tx.Witness[witnessCursor : witnessCursor+slots]
		ctx.resolved = append(ctx.resolved, nonCoinbaseResolvedInput{
			entry:    entry,
			witness:  append([]WitnessItem(nil), assigned...),
			outpoint: op,
		})
		witnessCursor += slots
	}
	if witnessCursor != len(ctx.tx.Witness) {
		return txerr(TX_ERR_PARSE, "witness_count mismatch")
	}
	return nil
}

func (ctx *nonCoinbaseApplyContext) resolveInput(in TxInput, seenInputs map[Outpoint]struct{}, zeroTxid [32]byte) (UtxoEntry, Outpoint, error) {
	if err := validateNonCoinbaseInputEncoding(in, zeroTxid); err != nil {
		return UtxoEntry{}, Outpoint{}, err
	}
	entry, op, err := ctx.lookupInputEntry(in, seenInputs)
	if err != nil {
		return UtxoEntry{}, Outpoint{}, err
	}
	return entry, op, nil
}

func validateNonCoinbaseInputEncoding(in TxInput, zeroTxid [32]byte) error {
	if len(in.ScriptSig) != 0 {
		return txerr(TX_ERR_PARSE, "script_sig must be empty under genesis covenant set")
	}
	if in.Sequence > 0x7fffffff {
		return txerr(TX_ERR_SEQUENCE_INVALID, "sequence exceeds 0x7fffffff")
	}
	if in.PrevVout == 0xffff_ffff && in.PrevTxid == zeroTxid {
		return txerr(TX_ERR_PARSE, "coinbase prevout encoding forbidden in non-coinbase")
	}
	return nil
}

func (ctx *nonCoinbaseApplyContext) lookupInputEntry(in TxInput, seenInputs map[Outpoint]struct{}) (UtxoEntry, Outpoint, error) {
	op := Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
	if _, exists := seenInputs[op]; exists {
		return UtxoEntry{}, Outpoint{}, txerr(TX_ERR_PARSE, "duplicate input outpoint")
	}
	seenInputs[op] = struct{}{}
	entry, ok := ctx.work[op]
	if !ok {
		return UtxoEntry{}, Outpoint{}, txerr(TX_ERR_MISSING_UTXO, "utxo not found")
	}
	return entry, op, nil
}

func (ctx *nonCoinbaseApplyContext) validateResolvedInputEntry(entry UtxoEntry) error {
	if isNonSpendableInputCovenant(entry.CovenantType) {
		return txerr(TX_ERR_MISSING_UTXO, "attempt to spend non-spendable covenant")
	}
	if err := ctx.validateCoinbaseInputMaturity(entry); err != nil {
		return err
	}
	if err := ctx.captureVaultResolvedInput(entry); err != nil {
		return err
	}
	if entry.CovenantType == COV_TYPE_CORE_SIMPLICITY {
		return rejectCoreSimplicitySpend()
	}
	return checkSpendCovenant(entry.CovenantType, entry.CovenantData)
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

func (ctx *nonCoinbaseApplyContext) captureVaultResolvedInput(entry UtxoEntry) error {
	if entry.CovenantType != COV_TYPE_VAULT {
		return nil
	}
	ctx.spend.vaultInputCount++
	if ctx.spend.vaultInputCount > 1 {
		return txerr(TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN, "multiple CORE_VAULT inputs forbidden")
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

func (ctx *nonCoinbaseApplyContext) hasCoreSimplicityResolvedInput() bool {
	for _, input := range ctx.resolved {
		if input.entry.CovenantType == COV_TYPE_CORE_SIMPLICITY {
			return true
		}
	}
	return false
}

func (ctx *nonCoinbaseApplyContext) validateInputSpends() error {
	for inputIndex, input := range ctx.resolved {
		if input.entry.CovenantType == COV_TYPE_CORE_SIMPLICITY {
			return ctx.validateInputSpend(inputIndex, input)
		}
	}
	for inputIndex, input := range ctx.resolved {
		if err := ctx.validateInputSpend(inputIndex, input); err != nil {
			return err
		}
		inputLockID := sha3_256(OutputDescriptorBytes(input.entry.CovenantType, input.entry.CovenantData))
		ctx.spend.inputLockIDs = append(ctx.spend.inputLockIDs, inputLockID)
		ctx.spend.inputCovTypes = append(ctx.spend.inputCovTypes, input.entry.CovenantType)
		var err error
		ctx.spend.sumIn, err = addU64ToU128(ctx.spend.sumIn, input.entry.Value)
		if err != nil {
			return err
		}
		if input.entry.CovenantType == COV_TYPE_VAULT {
			ctx.spend.sumInVault, err = addU64ToU128(ctx.spend.sumInVault, input.entry.Value)
			if err != nil {
				return err
			}
		}
		delete(ctx.work, input.outpoint)
	}
	return nil
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
		return ctx.captureVaultInput(inputIndex, entry, assigned)
	case COV_TYPE_HTLC:
		return ctx.validateHTLCInput(inputIndex, entry, assigned)
	case COV_TYPE_CORE_STEALTH:
		return ctx.validateCoreStealthInput(inputIndex, entry, assigned)
	case COV_TYPE_CORE_SIMPLICITY:
		return ctx.validateCoreSimplicityInput(entry, assigned)
	default:
		return nil
	}
}

func (ctx *nonCoinbaseApplyContext) validateP2PKInput(inputIndex int, entry UtxoEntry, assigned []WitnessItem) error {
	if len(assigned) != 1 {
		return txerr(TX_ERR_PARSE, "CORE_P2PK witness_slots must be 1")
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
		},
	})
}

func (ctx *nonCoinbaseApplyContext) validateMultisigInput(inputIndex int, entry UtxoEntry, assigned []WitnessItem) error {
	m, err := ParseMultisigCovenantData(entry.CovenantData)
	if err != nil {
		return err
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
	return ValidateHTLCSpendAtHeight(entry, assigned[0], assigned[1], ctx.tx, uint32(inputIndex), entry.Value, ctx.chainID, ctx.height, ctx.blockMTP, ctx.sighashCache, ctx.rotation, ctx.registry)
}

func (ctx *nonCoinbaseApplyContext) validateCoreStealthInput(inputIndex int, entry UtxoEntry, assigned []WitnessItem) error {
	if len(assigned) != CORE_STEALTH_WITNESS_SLOTS {
		return txerr(TX_ERR_PARSE, "CORE_STEALTH witness_slots must be 1")
	}
	return validateCoreStealthSpendAtHeight(coreStealthSpendValidation{
		entry:       entry,
		w:           assigned[0],
		tx:          ctx.tx,
		inputIndex:  uint32(inputIndex),
		inputValue:  entry.Value,
		chainID:     ctx.chainID,
		blockHeight: ctx.height,
		cache:       ctx.sighashCache,
		rotation:    ctx.rotation,
		registry:    ctx.registry,
	})
}

func (ctx *nonCoinbaseApplyContext) validateCoreSimplicityInput(_ UtxoEntry, _ []WitnessItem) error {
	return rejectCoreSimplicitySpend()
}

func (ctx *nonCoinbaseApplyContext) addSpendableOutputs() error {
	for i, out := range ctx.tx.Outputs {
		var err error
		ctx.sumOut, err = addU64ToU128(ctx.sumOut, out.Value)
		if err != nil {
			return err
		}
		if out.CovenantType == COV_TYPE_VAULT {
			ctx.createsVault = true
		}
		if out.CovenantType == COV_TYPE_ANCHOR || out.CovenantType == COV_TYPE_DA_COMMIT {
			continue
		}
		op := Outpoint{Txid: ctx.txid, Vout: uint32(i)}
		ctx.work[op] = UtxoEntry{
			Value:             out.Value,
			CovenantType:      out.CovenantType,
			CovenantData:      append([]byte(nil), out.CovenantData...),
			CreationHeight:    ctx.height,
			CreatedByCoinbase: false,
		}
	}
	return nil
}

func (ctx *nonCoinbaseApplyContext) finalizeValueAndFee() (uint64, error) {
	valueBase := &TxContextBase{
		TotalIn:  uint128FromInternal(ctx.spend.sumIn),
		TotalOut: uint128FromInternal(ctx.sumOut),
		Height:   ctx.height,
	}
	if errTx := CheckValueConservationTxWide(valueBase, ctx.spend.vaultInputCount == 1, uint128FromInternal(ctx.spend.sumInVault)); errTx != nil {
		return 0, errTx
	}
	feeU128, err := subU128(ctx.spend.sumIn, ctx.sumOut)
	if err != nil {
		return 0, err
	}
	return u128ToU64(feeU128)
}
