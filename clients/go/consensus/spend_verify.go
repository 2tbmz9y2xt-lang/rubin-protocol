package consensus

func extractCryptoSigAndSighash(w WitnessItem) ([]byte, uint8, error) {
	if len(w.Signature) == 0 {
		return nil, 0, txerr(TX_ERR_PARSE, "missing sighash_type byte")
	}
	sighashType := w.Signature[len(w.Signature)-1]
	if !IsValidSighashType(sighashType) {
		return nil, 0, txerr(TX_ERR_SIGHASH_TYPE_INVALID, "invalid sighash_type")
	}
	return w.Signature[:len(w.Signature)-1], sighashType, nil
}

// extractSigAndDigest extracts the cryptographic signature bytes and computes
// the sighash digest from a witness item.
func extractSigAndDigest(w WitnessItem, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte) ([]byte, [32]byte, error) {
	return extractSigAndDigestWithCache(w, tx, inputIndex, inputValue, chainID, nil)
}

func extractSigAndDigestWithCache(w WitnessItem, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, cache *SighashV1PrehashCache) ([]byte, [32]byte, error) {
	cryptoSig, sighashType, err := extractCryptoSigAndSighash(w)
	if err != nil {
		return nil, [32]byte{}, err
	}
	var digest [32]byte
	if cache != nil {
		digest, err = SighashV1DigestWithCache(cache, inputIndex, inputValue, chainID, sighashType)
	} else {
		digest, err = SighashV1DigestWithType(tx, inputIndex, inputValue, chainID, sighashType)
	}
	if err != nil {
		return nil, [32]byte{}, err
	}
	return cryptoSig, digest, nil
}

// verifyMLDSAKeyAndSig verifies an ML-DSA-87 witness item's key binding and
// cryptographic signature. The caller must validate witness item lengths and
// suite ID before calling this function.
func verifyMLDSAKeyAndSig(w WitnessItem, expectedKeyID [32]byte, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, context string) error {
	return verifyMLDSAKeyAndSigWithCache(w, expectedKeyID, tx, inputIndex, inputValue, chainID, nil, context)
}

func verifyMLDSAKeyAndSigWithCache(w WitnessItem, expectedKeyID [32]byte, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, cache *SighashV1PrehashCache, context string) error {
	return verifyKeyAndSigWithRegistryCache(w, expectedKeyID, spendSigContext{
		tx:         tx,
		inputIndex: inputIndex,
		inputValue: inputValue,
		chainID:    chainID,
		cache:      cache,
		context:    context,
	})
}

type spendSigContext struct {
	tx         *Tx
	inputIndex uint32
	inputValue uint64
	chainID    [32]byte
	cache      *SighashV1PrehashCache
	registry   *SuiteRegistry
	context    string
}

// verifyKeyAndSigWithRegistryCache verifies a witness item's key binding and
// cryptographic signature using registry-aware algorithm dispatch. When
// ctx.registry is nil, the canonical default live registry is used; callers do
// not get a separate implicit legacy verifier path.
func verifyKeyAndSigWithRegistryCache(w WitnessItem, expectedKeyID [32]byte, ctx spendSigContext) error {
	if sha3_256(w.Pubkey) != expectedKeyID {
		return txerr(TX_ERR_SIG_INVALID, ctx.context+" key binding mismatch")
	}
	cryptoSig, digest, err := extractSigAndDigestWithCache(w, ctx.tx, ctx.inputIndex, ctx.inputValue, ctx.chainID, ctx.cache)
	if err != nil {
		return err
	}
	ok, err := verifySigWithRegistry(w.SuiteID, w.Pubkey, cryptoSig, digest, ctx.registry)
	if err != nil {
		return err
	}
	if !ok {
		return txerr(TX_ERR_SIG_INVALID, ctx.context+" signature invalid")
	}
	return nil
}

func validateP2PKSpend(entry UtxoEntry, w WitnessItem, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, blockHeight uint64) error {
	return validateP2PKSpendWithCache(entry, w, tx, inputIndex, inputValue, chainID, blockHeight, nil)
}

func validateP2PKSpendWithCache(entry UtxoEntry, w WitnessItem, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, blockHeight uint64, cache *SighashV1PrehashCache) error {
	return validateP2PKSpendAtHeight(p2pkSpendCheck{
		entry:       entry,
		witness:     w,
		blockHeight: blockHeight,
		rotation:    DefaultRotationProvider{},
		sig: spendSigContext{
			tx:         tx,
			inputIndex: inputIndex,
			inputValue: inputValue,
			chainID:    chainID,
			cache:      cache,
			registry:   DefaultSuiteRegistry(),
		},
	})
}

type p2pkSpendCheck struct {
	entry       UtxoEntry
	witness     WitnessItem
	sig         spendSigContext
	blockHeight uint64
	rotation    RotationProvider
}

func defaultSpendProviders(rotation RotationProvider, registry *SuiteRegistry) (RotationProvider, *SuiteRegistry) {
	if rotation == nil {
		rotation = DefaultRotationProvider{}
	}
	if registry == nil {
		registry = DefaultSuiteRegistry()
	}
	return rotation, registry
}

// validateP2PKSpendAtHeight validates a P2PK spend using the suite registry
// and rotation provider for suite validation, length checks, and signature
// dispatch. When rotation or registry is nil, defaults are used (ML-DSA-87
// genesis set).
func validateP2PKSpendAtHeight(check p2pkSpendCheck) error {
	rotation, registry := defaultSpendProviders(check.rotation, check.sig.registry)
	w := check.witness
	nativeSpend := rotation.NativeSpendSuites(check.blockHeight)
	if !nativeSpend.Contains(w.SuiteID) {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_P2PK suite not in native spend set")
	}

	params, ok := registry.Lookup(w.SuiteID)
	if !ok {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_P2PK suite not registered")
	}

	if len(w.Pubkey) != params.PubkeyLen || len(w.Signature) != params.SigLen+1 {
		return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical witness item lengths")
	}

	if len(check.entry.CovenantData) != MAX_P2PK_COVENANT_DATA || check.entry.CovenantData[0] != w.SuiteID {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_P2PK covenant_data invalid")
	}

	var keyID [32]byte
	copy(keyID[:], check.entry.CovenantData[1:33])
	sig := check.sig
	sig.registry = registry
	sig.context = "CORE_P2PK"
	return verifyKeyAndSigWithRegistryCache(w, keyID, sig)
}

type thresholdSigSpendCheck struct {
	keys        [][32]byte
	threshold   uint8
	witnesses   []WitnessItem
	sig         spendSigContext
	blockHeight uint64
	rotation    RotationProvider
}

func validateThresholdSigSpend(check thresholdSigSpendCheck) error {
	if check.rotation == nil {
		check.rotation = DefaultRotationProvider{}
	}
	if check.sig.registry == nil {
		check.sig.registry = DefaultSuiteRegistry()
	}
	return validateThresholdSigSpendAtHeight(check)
}

// validateThresholdSigSpendAtHeight validates a threshold-sig spend using the
// suite registry and rotation provider. When rotation or registry is nil,
// defaults are used (ML-DSA-87 genesis set).
func validateThresholdSigSpendAtHeight(check thresholdSigSpendCheck) error {
	rotation, registry := defaultSpendProviders(check.rotation, check.sig.registry)
	if len(check.witnesses) != len(check.keys) {
		return txerr(TX_ERR_PARSE, "witness slot assignment mismatch")
	}

	nativeSpend := rotation.NativeSpendSuites(check.blockHeight)
	sig := check.sig
	sig.registry = registry
	valid := 0

	for i := range check.keys {
		counted, err := validateThresholdWitness(check.witnesses[i], check.keys[i], nativeSpend, registry, sig)
		if err != nil {
			return err
		}
		if counted {
			valid++
		}
	}

	if valid < int(check.threshold) {
		return txerr(TX_ERR_SIG_INVALID, sig.context+" threshold not met")
	}
	return nil
}

func validateThresholdWitness(w WitnessItem, key [32]byte, nativeSpend *NativeSuiteSet, registry *SuiteRegistry, sig spendSigContext) (bool, error) {
	if sentinel, err := validateSentinelThresholdWitness(w); sentinel || err != nil {
		return false, err
	}

	if !nativeSpend.Contains(w.SuiteID) {
		return false, txerr(TX_ERR_SIG_ALG_INVALID, sig.context+" suite not in native spend set")
	}

	params, ok := registry.Lookup(w.SuiteID)
	if !ok {
		return false, txerr(TX_ERR_SIG_ALG_INVALID, sig.context+" suite not registered")
	}

	if len(w.Pubkey) != params.PubkeyLen || len(w.Signature) != params.SigLen+1 {
		return false, txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical witness item lengths")
	}

	if err := verifyKeyAndSigWithRegistryCache(w, key, sig); err != nil {
		return false, err
	}
	return true, nil
}

func validateSentinelThresholdWitness(w WitnessItem) (bool, error) {
	if w.SuiteID != SUITE_ID_SENTINEL {
		return false, nil
	}
	if len(w.Pubkey) != 0 || len(w.Signature) != 0 {
		return true, txerr(TX_ERR_PARSE, "SENTINEL witness must be keyless")
	}
	return true, nil
}
