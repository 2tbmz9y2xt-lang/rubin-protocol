package consensus

func (ctx *nonCoinbaseApplyContext) validateVaultCreations() error {
	for _, out := range ctx.tx.Outputs {
		if out.CovenantType != COV_TYPE_VAULT {
			continue
		}
		v, err := ParseVaultCovenantData(out.CovenantData)
		if err != nil {
			return err
		}
		if !hasVaultOwnerAuthorizedInput(ctx.spend.inputLockIDs, ctx.spend.inputCovTypes, v.OwnerLockID) {
			return txerr(TX_ERR_VAULT_OWNER_AUTH_REQUIRED, "missing owner-authorized input for CORE_VAULT creation")
		}
	}
	return nil
}

func hasVaultOwnerAuthorizedInput(inputLockIDs [][32]byte, inputCovTypes []uint16, ownerLockID [32]byte) bool {
	hasOwnerLockID := false
	hasOwnerLockType := false
	for i := range inputLockIDs {
		if inputLockIDs[i] != ownerLockID {
			continue
		}
		hasOwnerLockID = true
		if inputCovTypes[i] == COV_TYPE_P2PK || inputCovTypes[i] == COV_TYPE_MULTISIG {
			hasOwnerLockType = true
		}
	}
	return hasOwnerLockID && hasOwnerLockType
}

func (ctx *nonCoinbaseApplyContext) validateVaultSpend() error {
	if !ctx.spend.haveVaultSig {
		return txerr(TX_ERR_PARSE, "missing CORE_VAULT signature context")
	}
	if err := ctx.requireVaultOwnerAuthForSpend(); err != nil {
		return err
	}
	if err := ctx.rejectVaultFeeSponsorship(); err != nil {
		return err
	}
	if err := ctx.rejectVaultOutputRecursion(); err != nil {
		return err
	}
	if err := ctx.validateVaultSpendSignature(); err != nil {
		return err
	}
	return ctx.validateVaultOutputWhitelist()
}

func (ctx *nonCoinbaseApplyContext) requireVaultOwnerAuthForSpend() error {
	for i := range ctx.spend.inputLockIDs {
		if ctx.spend.inputLockIDs[i] == ctx.spend.vaultOwnerLockID {
			return nil
		}
	}
	return txerr(TX_ERR_VAULT_OWNER_AUTH_REQUIRED, "missing owner-authorized input for CORE_VAULT spend")
}

func (ctx *nonCoinbaseApplyContext) rejectVaultFeeSponsorship() error {
	for i := range ctx.spend.inputCovTypes {
		if ctx.spend.inputCovTypes[i] == COV_TYPE_VAULT {
			continue
		}
		if ctx.spend.inputLockIDs[i] != ctx.spend.vaultOwnerLockID {
			return txerr(TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN, "non-owner non-vault input forbidden in CORE_VAULT spend")
		}
	}
	return nil
}

func (ctx *nonCoinbaseApplyContext) rejectVaultOutputRecursion() error {
	for _, out := range ctx.tx.Outputs {
		if out.CovenantType == COV_TYPE_VAULT {
			return txerr(TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED, "CORE_VAULT outputs forbidden in CORE_VAULT spend")
		}
	}
	return nil
}

func (ctx *nonCoinbaseApplyContext) validateVaultSpendSignature() error {
	return validateThresholdSigSpendAtHeight(
		ctx.spend.vaultSigKeys,
		ctx.spend.vaultSigThreshold,
		ctx.spend.vaultSigWitness,
		ctx.tx,
		ctx.spend.vaultSigInputIndex,
		ctx.spend.vaultSigInputValue,
		ctx.chainID,
		ctx.height,
		ctx.sighashCache,
		ctx.rotation,
		ctx.registry,
		"CORE_VAULT",
	)
}

func (ctx *nonCoinbaseApplyContext) validateVaultOutputWhitelist() error {
	for _, out := range ctx.tx.Outputs {
		if out.CovenantType != COV_TYPE_P2PK && out.CovenantType != COV_TYPE_MULTISIG && out.CovenantType != COV_TYPE_HTLC {
			return txerr(TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED, "disallowed destination covenant_type for CORE_VAULT spend")
		}
		desc := OutputDescriptorBytes(out.CovenantType, out.CovenantData)
		h := sha3_256(desc)
		if !HashInSorted32(ctx.spend.vaultWhitelist, h) {
			return txerr(TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED, "output not whitelisted for CORE_VAULT")
		}
	}
	return nil
}
