package consensus

type StealthCovenant struct {
	Ciphertext   []byte
	OneTimeKeyID [32]byte
}

func ParseStealthCovenantData(covData []byte) (*StealthCovenant, error) {
	if covData == nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "nil CORE_STEALTH covenant_data")
	}
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
	return validateCoreStealthSpendAtHeight(entry, w, tx, inputIndex, inputValue, chainID, blockHeight, cache, nil, nil)
}

// validateCoreStealthSpendAtHeight validates a stealth spend using the suite
// registry and rotation provider. When rotation or registry is nil, defaults
// are used (ML-DSA-87 genesis set).
func validateCoreStealthSpendAtHeight(entry UtxoEntry, w WitnessItem, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, blockHeight uint64, cache *SighashV1PrehashCache, rotation RotationProvider, registry *SuiteRegistry) error {
	if rotation == nil {
		rotation = DefaultRotationProvider{}
	}
	if registry == nil {
		registry = DefaultSuiteRegistry()
	}

	c, err := ParseStealthCovenantData(entry.CovenantData)
	if err != nil {
		return err
	}

	nativeSpend := rotation.NativeSpendSuites(blockHeight)
	if !nativeSpend.Contains(w.SuiteID) {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_STEALTH suite not in native spend set")
	}

	params, ok := registry.Lookup(w.SuiteID)
	if !ok {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_STEALTH suite not registered")
	}

	if len(w.Pubkey) != params.PubkeyLen || len(w.Signature) != params.SigLen+1 {
		return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical witness item lengths")
	}
	return verifyKeyAndSigWithRegistryCache(w, c.OneTimeKeyID, tx, inputIndex, inputValue, chainID, cache, registry, "CORE_STEALTH")
}
