package consensus

// This file owns the non-coinbase spend suffix (CSM §2.4) of the immediate (applyNonCoinbaseTxBasicWork)
// and queued (applyNonCoinbaseTxBasicWorkQ) apply paths: BIND, S2, R1, R2, R3, R4, S3b, S3d, S4 in
// ascending input order, S5, then one private work delta. Both run the same stage sequence; only the S4
// signature sink differs (ctx.sigQueue). No stage mutates ctx.work before S5 succeeds.

// boundSpendSurface is the per-transaction memo of the spend-height surface.
// Each part (create set, spend set, Simplicity deployment set) is read from
// the caller provider at most once, at its first consumer; every later
// consumer receives the stored value, so a provider changed after that read
// cannot change the in-flight result.
type boundSpendSurface struct {
	inner      RotationProvider
	create     *NativeSuiteSet
	spend      *NativeSuiteSet
	height     uint64
	haveCreate bool
	haveSpend  bool
}

// boundSpendSurfaceWithDeployment exists only when the caller provider is a
// SimplicityDeploymentProvider, so a provider without one keeps the
// frozen-inactive cause.
type boundSpendSurfaceWithDeployment struct {
	*boundSpendSurface
	provider    SimplicityDeploymentProvider
	descriptors []SimplicityDeploymentDescriptor
	setAnchor   [32]byte
	err         error
	ok          bool
	have        bool
}

func bindSpendSurface(rotation RotationProvider, height uint64) RotationProvider {
	switch rotation.(type) {
	case *boundSpendSurface, *boundSpendSurfaceWithDeployment:
		return rotation
	}
	if rotation == nil {
		rotation = DefaultRotationProvider{}
	}
	base := &boundSpendSurface{inner: rotation, height: height}
	if provider, ok := rotation.(SimplicityDeploymentProvider); ok {
		return &boundSpendSurfaceWithDeployment{boundSpendSurface: base, provider: provider}
	}
	return base
}

func (s *boundSpendSurface) NativeCreateSuites(height uint64) *NativeSuiteSet {
	if height != s.height {
		return s.inner.NativeCreateSuites(height)
	}
	if !s.haveCreate {
		s.create, s.haveCreate = s.inner.NativeCreateSuites(height), true
	}
	return s.create
}

func (s *boundSpendSurface) NativeSpendSuites(height uint64) *NativeSuiteSet {
	if height != s.height {
		return s.inner.NativeSpendSuites(height)
	}
	if !s.haveSpend {
		s.spend, s.haveSpend = s.inner.NativeSpendSuites(height), true
	}
	return s.spend
}

func (s *boundSpendSurfaceWithDeployment) PublishedSimplicityDeployments() ([]SimplicityDeploymentDescriptor, [32]byte, bool, error) {
	if !s.have {
		descriptors, setAnchor, ok, err := s.provider.PublishedSimplicityDeployments()
		s.descriptors = append([]SimplicityDeploymentDescriptor(nil), descriptors...)
		s.setAnchor, s.ok, s.err, s.have = setAnchor, ok, err, true
	}
	return append([]SimplicityDeploymentDescriptor(nil), s.descriptors...), s.setAnchor, s.ok, s.err
}

func (ctx *nonCoinbaseApplyContext) apply() (map[Outpoint]UtxoEntry, Uint128, error) {
	if err := ctx.applyPreOutputPhases(); err != nil {
		return nil, Uint128{}, err
	}
	fee, err := ctx.finalizeValueAndFee()
	if err != nil {
		return nil, Uint128{}, err
	}
	ctx.applyInputDelta()
	ctx.applyOutputDelta()
	return ctx.work, fee, nil
}

// applyPreOutputPhases runs every stage before S5 and leaves ctx.work unchanged.
func (ctx *nonCoinbaseApplyContext) applyPreOutputPhases() error {
	if err := ctx.prepare(); err != nil {
		return err
	}
	if err := ctx.resolveAndAssignInputs(); err != nil {
		return err
	}
	return ctx.validateSpendStages()
}

// prepare runs S1A, BIND and S2, then builds the sighash prehash cache.
func (ctx *nonCoinbaseApplyContext) prepare() error {
	if err := ValidateSpendTxS1A(ctx.tx); err != nil {
		return err
	}
	ctx.rotation = bindSpendSurface(ctx.rotation, ctx.height)
	if err := ValidateTxCovenantsGenesis(ctx.tx, ctx.chainID, ctx.height, ctx.rotation); err != nil {
		return err
	}
	ctx.createsVault = txCreatesVault(ctx.tx)
	sighashCache, err := NewSighashV1PrehashCache(ctx.tx)
	if err != nil {
		return err
	}
	ctx.sighashCache = sighashCache
	return nil
}

func txCreatesVault(tx *Tx) bool {
	for _, out := range tx.Outputs {
		if out.CovenantType == COV_TYPE_VAULT {
			return true
		}
	}
	return false
}

// resolveAndAssignInputs runs R1 over every input, then R2, then R3 and R4.
func (ctx *nonCoinbaseApplyContext) resolveAndAssignInputs() error {
	if err := ctx.resolveInputs(); err != nil {
		return err
	}
	if err := ctx.checkVaultInputCount(); err != nil {
		return err
	}
	return ctx.assignWitnessSlots()
}

// resolveInputs is R1: lookup, non-spendable, maturity and covenant-type
// disposition in input order, with a detached copy of every entry.
func (ctx *nonCoinbaseApplyContext) resolveInputs() error {
	ctx.resolved = make([]nonCoinbaseResolvedInput, 0, len(ctx.tx.Inputs))
	for _, in := range ctx.tx.Inputs {
		entry, op, err := ctx.lookupInputEntry(in)
		if err != nil {
			return err
		}
		if err := ctx.validateResolvedInputEntry(entry); err != nil {
			return err
		}
		ctx.resolved = append(ctx.resolved, nonCoinbaseResolvedInput{entry: cloneUtxoEntry(entry), outpoint: op})
	}
	return nil
}

// checkVaultInputCount is R2, after complete R1.
func (ctx *nonCoinbaseApplyContext) checkVaultInputCount() error {
	ctx.spend.vaultInputCount = 0
	for _, input := range ctx.resolved {
		if input.entry.CovenantType == COV_TYPE_VAULT {
			ctx.spend.vaultInputCount++
		}
	}
	if ctx.spend.vaultInputCount > 1 {
		return txerr(TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN, "multiple CORE_VAULT inputs forbidden")
	}
	return nil
}

// assignWitnessSlots is R3 in input order followed by the R4 cursor check.
func (ctx *nonCoinbaseApplyContext) assignWitnessSlots() error {
	cursor := 0
	for i := range ctx.resolved {
		next, err := ctx.assignInputWitness(&ctx.resolved[i], cursor)
		if err != nil {
			return err
		}
		cursor = next
	}
	if cursor != len(ctx.tx.Witness) {
		return txerr(TX_ERR_PARSE, "witness_count mismatch")
	}
	return nil
}

func (ctx *nonCoinbaseApplyContext) assignInputWitness(input *nonCoinbaseResolvedInput, cursor int) (int, error) {
	if err := parseWitnessSlotMetadata(input.entry); err != nil {
		return 0, err
	}
	slots, err := WitnessSlots(input.entry.CovenantType, input.entry.CovenantData)
	if err != nil {
		return 0, err
	}
	if slots <= 0 {
		return 0, txerr(TX_ERR_PARSE, "invalid witness slots")
	}
	if cursor+slots > len(ctx.tx.Witness) {
		return 0, txerr(TX_ERR_PARSE, "witness underflow")
	}
	input.witness = append([]WitnessItem(nil), ctx.tx.Witness[cursor:cursor+slots]...)
	return cursor + slots, nil
}

// parseWitnessSlotMetadata parses the covenant data that defines witness_slots
// (CANONICAL §16 rule 7) at R3.
func parseWitnessSlotMetadata(entry UtxoEntry) error {
	var err error
	switch entry.CovenantType {
	case COV_TYPE_VAULT:
		_, err = ParseVaultCovenantDataForSpend(entry.CovenantData)
	case COV_TYPE_MULTISIG:
		_, err = ParseMultisigCovenantData(entry.CovenantData)
	}
	return err
}

// validateSpendStages runs S3b, S3d and S4 in that order.
func (ctx *nonCoinbaseApplyContext) validateSpendStages() error {
	ctx.captureInputLocks()
	if ctx.createsVault {
		if err := ctx.validateVaultCreations(); err != nil {
			return err
		}
	}
	simplicityCtx, err := buildSimplicityStep3dContextWithDescriptors(
		ctx.tx, ctx.resolvedEntries(), ctx.height, ctx.chainID, ctx.rotation, ctx.inputView != nil,
	)
	if err != nil {
		return err
	}
	ctx.simplicityCtx = simplicityCtx
	return ctx.validateInputSpends()
}

func (ctx *nonCoinbaseApplyContext) captureInputLocks() {
	ctx.spend.inputLockIDs = make([][32]byte, 0, len(ctx.resolved))
	ctx.spend.inputCovTypes = make([]uint16, 0, len(ctx.resolved))
	for _, input := range ctx.resolved {
		ctx.spend.inputLockIDs = append(ctx.spend.inputLockIDs, sha3_256(OutputDescriptorBytes(input.entry.CovenantType, input.entry.CovenantData)))
		ctx.spend.inputCovTypes = append(ctx.spend.inputCovTypes, input.entry.CovenantType)
	}
}

// validateInputSpends is S4: each covenant once, in input order; a Vault
// input runs its complete sequence at its own index.
func (ctx *nonCoinbaseApplyContext) validateInputSpends() error {
	for inputIndex, input := range ctx.resolved {
		if err := ctx.validateInputSpend(inputIndex, input); err != nil {
			return err
		}
	}
	return nil
}

func (ctx *nonCoinbaseApplyContext) validateVaultInput(inputIndex int, entry UtxoEntry, assigned []WitnessItem) error {
	if err := ctx.captureVaultInput(inputIndex, entry, assigned); err != nil {
		return err
	}
	return ctx.validateVaultSpend()
}

// finalizeValueAndFee is S5: checked input and output accumulation, the
// tx-wide value rules, then the exact u128 fee sum_in-sum_out (never narrowed).
func (ctx *nonCoinbaseApplyContext) finalizeValueAndFee() (Uint128, error) {
	if err := ctx.accumulateInputValues(); err != nil {
		return Uint128{}, err
	}
	if err := ctx.accumulateOutputValues(); err != nil {
		return Uint128{}, err
	}
	valueBase := &TxContextBase{
		TotalIn:  uint128FromInternal(ctx.spend.sumIn),
		TotalOut: uint128FromInternal(ctx.sumOut),
		Height:   ctx.height,
	}
	if errTx := CheckValueConservationTxWide(valueBase, ctx.spend.vaultInputCount == 1, uint128FromInternal(ctx.spend.sumInVault)); errTx != nil {
		return Uint128{}, errTx
	}
	feeU128, err := subU128(ctx.spend.sumIn, ctx.sumOut)
	if err != nil {
		return Uint128{}, err
	}
	return uint128FromInternal(feeU128), nil
}

func (ctx *nonCoinbaseApplyContext) accumulateInputValues() error {
	ctx.spend.sumIn, ctx.spend.sumInVault = u128{}, u128{}
	for _, input := range ctx.resolved {
		var err error
		ctx.spend.sumIn, err = addU64ToU128(ctx.spend.sumIn, input.entry.Value)
		if err != nil {
			return err
		}
		if input.entry.CovenantType != COV_TYPE_VAULT {
			continue
		}
		ctx.spend.sumInVault, err = addU64ToU128(ctx.spend.sumInVault, input.entry.Value)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ctx *nonCoinbaseApplyContext) accumulateOutputValues() error {
	ctx.sumOut = u128{}
	for _, out := range ctx.tx.Outputs {
		var err error
		ctx.sumOut, err = addU64ToU128(ctx.sumOut, out.Value)
		if err != nil {
			return err
		}
	}
	return nil
}

// applyInputDelta and applyOutputDelta are the private delta after S5.
func (ctx *nonCoinbaseApplyContext) applyInputDelta() {
	for _, input := range ctx.resolved {
		delete(ctx.work, input.outpoint)
		if ctx.inputView == nil {
			continue
		}
		if _, preBlock := ctx.inputView.spent[input.outpoint]; !preBlock {
			ctx.inputView.spent[input.outpoint] = 0
		}
	}
}

func (ctx *nonCoinbaseApplyContext) applyOutputDelta() {
	for i, out := range ctx.tx.Outputs {
		if out.CovenantType == COV_TYPE_ANCHOR || out.CovenantType == COV_TYPE_DA_COMMIT {
			continue
		}
		ctx.work[Outpoint{Txid: ctx.txid, Vout: uint32(i)}] = UtxoEntry{
			Value:             out.Value,
			CovenantType:      out.CovenantType,
			CovenantData:      append([]byte(nil), out.CovenantData...),
			CreationHeight:    ctx.height,
			CreatedByCoinbase: false,
		}
	}
}
