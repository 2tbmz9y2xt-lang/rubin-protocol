package consensus

type nonCoinbaseResolvedInput struct {
	entry    UtxoEntry
	witness  []WitnessItem
	outpoint Outpoint
}

type nonCoinbaseSpendState struct {
	sumIn              u128
	sumInVault         u128
	vaultWhitelist     [][32]byte
	vaultOwnerLockID   [32]byte
	vaultSigKeys       [][32]byte
	vaultSigWitness    []WitnessItem
	inputLockIDs       [][32]byte
	inputCovTypes      []uint16
	vaultSigInputIndex uint32
	vaultSigInputValue uint64
	vaultSigThreshold  uint8
	haveVaultSig       bool
	vaultInputCount    int
}

type nonCoinbaseApplyContext struct {
	tx              *Tx
	txid            [32]byte
	work            map[Outpoint]UtxoEntry
	chainID         [32]byte
	coreExtProfiles CoreExtProfileProvider
	rotation        RotationProvider
	registry        *SuiteRegistry
	sighashCache    *SighashV1PrehashCache
	txContext       *TxContextBundle
	resolved        []nonCoinbaseResolvedInput
	spend           nonCoinbaseSpendState
	sumOut          u128
	height          uint64
	blockMTP        uint64
	createsVault    bool
}

func nonCoinbaseCoreExtProfilesOrEmpty(coreExtProfiles CoreExtProfileProvider) CoreExtProfileProvider {
	if coreExtProfiles == nil {
		return EmptyCoreExtProfileProvider()
	}
	return coreExtProfiles
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
	witnessCursor := 0
	seenInputs := make(map[Outpoint]struct{}, len(ctx.tx.Inputs))
	var zeroTxid [32]byte
	ctx.resolved = make([]nonCoinbaseResolvedInput, 0, len(ctx.tx.Inputs))
	for _, in := range ctx.tx.Inputs {
		entry, op, err := ctx.resolveInput(in, seenInputs, zeroTxid)
		if err != nil {
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
	if err := ctx.validateResolvedInputEntry(entry); err != nil {
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

func (ctx *nonCoinbaseApplyContext) buildTxContext() error {
	txContextExtIDs, err := collectTxContextExtIDs(ctx.resolvedEntries(), ctx.height, ctx.coreExtProfiles)
	if err != nil {
		return err
	}
	if len(txContextExtIDs) == 0 {
		return nil
	}
	outputExtIDCache, err := BuildTxContextOutputExtIDCache(ctx.tx)
	if err != nil {
		return err
	}
	ctx.txContext, err = BuildTxContext(ctx.tx, ctx.resolvedEntries(), outputExtIDCache, ctx.height, ctx.coreExtProfiles)
	return err
}

func (ctx *nonCoinbaseApplyContext) resolvedEntries() []UtxoEntry {
	entries := make([]UtxoEntry, 0, len(ctx.resolved))
	for _, input := range ctx.resolved {
		entries = append(entries, input.entry)
	}
	return entries
}
