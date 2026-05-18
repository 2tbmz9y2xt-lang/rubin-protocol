package consensus

type StealthCovenant struct {
	Ciphertext   []byte
	OneTimeKeyID [32]byte
}

func ParseStealthCovenantData(covData []byte) (*StealthCovenant, error) {
	if len(covData) != MAX_STEALTH_COVENANT_DATA {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_STEALTH covenant_data length mismatch")
	}
	if ML_KEM_1024_CT_BYTES+32 != MAX_STEALTH_COVENANT_DATA {
		return nil, txerr(TX_ERR_PARSE, "CORE_STEALTH constants mismatch")
	}
	var oneTimeKeyID [32]byte
	copy(oneTimeKeyID[:], covData[ML_KEM_1024_CT_BYTES:MAX_STEALTH_COVENANT_DATA])
	return &StealthCovenant{
		Ciphertext:   append([]byte(nil), covData[:ML_KEM_1024_CT_BYTES]...),
		OneTimeKeyID: oneTimeKeyID,
	}, nil
}

func validateCoreStealthSpend(entry UtxoEntry, w WitnessItem, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, blockHeight uint64) error {
	return validateCoreStealthSpendWithCache(entry, w, tx, inputIndex, inputValue, chainID, blockHeight, nil)
}

func validateCoreStealthSpendWithCache(entry UtxoEntry, w WitnessItem, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, blockHeight uint64, cache *SighashV1PrehashCache) error {
	return validateCoreStealthSpendAtHeight(coreStealthSpendValidation{
		entry:       entry,
		w:           w,
		tx:          tx,
		inputIndex:  inputIndex,
		inputValue:  inputValue,
		chainID:     chainID,
		blockHeight: blockHeight,
		cache:       cache,
	})
}

type coreStealthSpendValidation struct {
	entry       UtxoEntry
	w           WitnessItem
	tx          *Tx
	inputIndex  uint32
	inputValue  uint64
	chainID     [32]byte
	blockHeight uint64
	cache       *SighashV1PrehashCache
	rotation    RotationProvider
	registry    *SuiteRegistry
}

// validateCoreStealthSpendAtHeight validates a stealth spend using the suite
// registry and rotation provider. When rotation or registry is nil, defaults
// are used (ML-DSA-87 genesis set).
func validateCoreStealthSpendAtHeight(input coreStealthSpendValidation) error {
	if input.rotation == nil {
		input.rotation = DefaultRotationProvider{}
	}
	if input.registry == nil {
		input.registry = DefaultSuiteRegistry()
	}

	c, err := ParseStealthCovenantData(input.entry.CovenantData)
	if err != nil {
		return err
	}

	nativeSpend := input.rotation.NativeSpendSuites(input.blockHeight)
	if !nativeSpend.Contains(input.w.SuiteID) {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_STEALTH suite not in native spend set")
	}

	params, ok := input.registry.Lookup(input.w.SuiteID)
	if !ok {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_STEALTH suite not registered")
	}

	if len(input.w.Pubkey) != params.PubkeyLen || len(input.w.Signature) != params.SigLen+1 {
		return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical witness item lengths")
	}
	return verifyKeyAndSigWithRegistryCache(input.w, c.OneTimeKeyID, spendSigContext{
		tx:         input.tx,
		inputIndex: input.inputIndex,
		inputValue: input.inputValue,
		chainID:    input.chainID,
		cache:      input.cache,
		registry:   input.registry,
		context:    "CORE_STEALTH",
	})
}
