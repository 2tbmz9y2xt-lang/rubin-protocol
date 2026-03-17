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
// the sighash digest from a witness item. This is the common preamble shared
// by all signature verification paths (ML-DSA-87 core and CORE_EXT profiles).
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
	return verifyKeyAndSigWithRegistryCache(w, expectedKeyID, tx, inputIndex, inputValue, chainID, cache, nil, context)
}

// verifyKeyAndSigWithRegistryCache verifies a witness item's key binding and
// cryptographic signature using registry-aware algorithm dispatch. When registry
// is nil, falls back to the hardcoded ML-DSA-87 verification path.
func verifyKeyAndSigWithRegistryCache(w WitnessItem, expectedKeyID [32]byte, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, cache *SighashV1PrehashCache, registry *SuiteRegistry, context string) error {
	if sha3_256(w.Pubkey) != expectedKeyID {
		return txerr(TX_ERR_SIG_INVALID, context+" key binding mismatch")
	}
	cryptoSig, digest, err := extractSigAndDigestWithCache(w, tx, inputIndex, inputValue, chainID, cache)
	if err != nil {
		return err
	}
	ok, err := verifySigWithRegistry(w.SuiteID, w.Pubkey, cryptoSig, digest, registry)
	if err != nil {
		return err
	}
	if !ok {
		return txerr(TX_ERR_SIG_INVALID, context+" signature invalid")
	}
	return nil
}

func validateP2PKSpend(entry UtxoEntry, w WitnessItem, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, blockHeight uint64) error {
	return validateP2PKSpendWithCache(entry, w, tx, inputIndex, inputValue, chainID, blockHeight, nil)
}

func validateP2PKSpendWithCache(entry UtxoEntry, w WitnessItem, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, blockHeight uint64, cache *SighashV1PrehashCache) error {
	return validateP2PKSpendAtHeight(entry, w, tx, inputIndex, inputValue, chainID, blockHeight, cache, DefaultRotationProvider{}, DefaultSuiteRegistry())
}

// validateP2PKSpendAtHeight validates a P2PK spend using the suite registry
// and rotation provider for suite validation, length checks, and signature
// dispatch. When rotation or registry is nil, defaults are used (ML-DSA-87
// genesis set).
func validateP2PKSpendAtHeight(entry UtxoEntry, w WitnessItem, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, blockHeight uint64, cache *SighashV1PrehashCache, rotation RotationProvider, registry *SuiteRegistry) error {
	if rotation == nil {
		rotation = DefaultRotationProvider{}
	}
	if registry == nil {
		registry = DefaultSuiteRegistry()
	}

	nativeSpend := rotation.NativeSpendSuites(blockHeight)
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

	if len(entry.CovenantData) != MAX_P2PK_COVENANT_DATA || entry.CovenantData[0] != w.SuiteID {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_P2PK covenant_data invalid")
	}

	var keyID [32]byte
	copy(keyID[:], entry.CovenantData[1:33])
	return verifyKeyAndSigWithRegistryCache(w, keyID, tx, inputIndex, inputValue, chainID, cache, registry, "CORE_P2PK")
}

func validateThresholdSigSpend(
	keys [][32]byte,
	threshold uint8,
	ws []WitnessItem,
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
	chainID [32]byte,
	blockHeight uint64,
	context string,
) error {
	return validateThresholdSigSpendWithCache(keys, threshold, ws, tx, inputIndex, inputValue, chainID, blockHeight, nil, context)
}

func validateThresholdSigSpendWithCache(
	keys [][32]byte,
	threshold uint8,
	ws []WitnessItem,
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
	chainID [32]byte,
	blockHeight uint64,
	cache *SighashV1PrehashCache,
	context string,
) error {
	return validateThresholdSigSpendAtHeight(keys, threshold, ws, tx, inputIndex, inputValue, chainID, blockHeight, cache, DefaultRotationProvider{}, DefaultSuiteRegistry(), context)
}

// validateThresholdSigSpendAtHeight validates a threshold-sig spend using the
// suite registry and rotation provider. When rotation or registry is nil,
// defaults are used (ML-DSA-87 genesis set).
func validateThresholdSigSpendAtHeight(
	keys [][32]byte,
	threshold uint8,
	ws []WitnessItem,
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
	chainID [32]byte,
	blockHeight uint64,
	cache *SighashV1PrehashCache,
	rotation RotationProvider,
	registry *SuiteRegistry,
	context string,
) error {
	if rotation == nil {
		rotation = DefaultRotationProvider{}
	}
	if registry == nil {
		registry = DefaultSuiteRegistry()
	}

	if len(ws) != len(keys) {
		return txerr(TX_ERR_PARSE, "witness slot assignment mismatch")
	}

	nativeSpend := rotation.NativeSpendSuites(blockHeight)
	valid := 0

	for i := range keys {
		w := ws[i]
		if w.SuiteID == SUITE_ID_SENTINEL {
			if len(w.Pubkey) != 0 || len(w.Signature) != 0 {
				return txerr(TX_ERR_PARSE, "SENTINEL witness must be keyless")
			}
			continue
		}

		if !nativeSpend.Contains(w.SuiteID) {
			return txerr(TX_ERR_SIG_ALG_INVALID, context+" suite not in native spend set")
		}

		params, ok := registry.Lookup(w.SuiteID)
		if !ok {
			return txerr(TX_ERR_SIG_ALG_INVALID, context+" suite not registered")
		}

		if len(w.Pubkey) != params.PubkeyLen || len(w.Signature) != params.SigLen+1 {
			return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical witness item lengths")
		}

		if err := verifyKeyAndSigWithRegistryCache(w, keys[i], tx, inputIndex, inputValue, chainID, cache, registry, context); err != nil {
			return err
		}
		valid++
	}

	if valid < int(threshold) {
		return txerr(TX_ERR_SIG_INVALID, context+" threshold not met")
	}
	return nil
}
