package consensus

func (ctx *nonCoinbaseApplyContext) validateInputSpends() error {
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
	case COV_TYPE_CORE_EXT:
		return ctx.validateCoreExtInput(inputIndex, entry, assigned)
	case COV_TYPE_CORE_STEALTH:
		return ctx.validateCoreStealthInput(inputIndex, entry, assigned)
	default:
		return nil
	}
}

func (ctx *nonCoinbaseApplyContext) validateP2PKInput(inputIndex int, entry UtxoEntry, assigned []WitnessItem) error {
	if len(assigned) != 1 {
		return txerr(TX_ERR_PARSE, "CORE_P2PK witness_slots must be 1")
	}
	return validateP2PKSpendAtHeight(entry, assigned[0], ctx.tx, uint32(inputIndex), entry.Value, ctx.chainID, ctx.height, ctx.sighashCache, ctx.rotation, ctx.registry)
}

func (ctx *nonCoinbaseApplyContext) validateMultisigInput(inputIndex int, entry UtxoEntry, assigned []WitnessItem) error {
	m, err := ParseMultisigCovenantData(entry.CovenantData)
	if err != nil {
		return err
	}
	return validateThresholdSigSpendAtHeight(m.Keys, m.Threshold, assigned, ctx.tx, uint32(inputIndex), entry.Value, ctx.chainID, ctx.height, ctx.sighashCache, ctx.rotation, ctx.registry, "CORE_MULTISIG")
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

func (ctx *nonCoinbaseApplyContext) validateCoreExtInput(inputIndex int, entry UtxoEntry, assigned []WitnessItem) error {
	if len(assigned) != CORE_EXT_WITNESS_SLOTS {
		return txerr(TX_ERR_PARSE, "CORE_EXT witness_slots must be 1")
	}
	return validateCoreExtSpendWithCache(entry, assigned[0], ctx.tx, uint32(inputIndex), entry.Value, ctx.chainID, ctx.height, ctx.sighashCache, ctx.coreExtProfiles, ctx.rotation, ctx.registry, ctx.txContext)
}

func (ctx *nonCoinbaseApplyContext) validateCoreStealthInput(inputIndex int, entry UtxoEntry, assigned []WitnessItem) error {
	if len(assigned) != CORE_STEALTH_WITNESS_SLOTS {
		return txerr(TX_ERR_PARSE, "CORE_STEALTH witness_slots must be 1")
	}
	return validateCoreStealthSpendAtHeight(entry, assigned[0], ctx.tx, uint32(inputIndex), entry.Value, ctx.chainID, ctx.height, ctx.sighashCache, ctx.rotation, ctx.registry)
}
