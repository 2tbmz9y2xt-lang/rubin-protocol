package consensus

import "encoding/binary"

// This file contains queue-aware variants of signature verification functions
// used by the parallel block connection path (IBD optimization). Each function
// mirrors its sequential counterpart but defers the expensive verifySig call
// to a SigCheckQueue instead of executing it inline.
//
// When sigQueue is nil, these functions fall back to the existing sequential
// verification — making them safe to call unconditionally.
//
// IMPORTANT: These functions produce DIFFERENT ERROR ORDERING than the
// sequential path when sigQueue is non-nil. They are only safe for use
// during IBD (Initial Block Download) where error ordering is not
// consensus-critical.

// verifyMLDSAKeyAndSigQ is the queue-aware variant of verifyMLDSAKeyAndSigWithCache.
// When sigQueue is non-nil, it performs all fast pre-checks (key binding, sighash
// computation) inline and defers the expensive crypto verification to the queue
// (Flush uses registry when set for rotation-aware dispatch). When sigQueue is nil,
// it verifies inline using verifySigWithRegistry if registry is non-nil, else verifySig.
func verifyMLDSAKeyAndSigQ(
	w WitnessItem,
	expectedKeyID [32]byte,
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
	chainID [32]byte,
	cache *SighashV1PrehashCache,
	sigQueue *SigCheckQueue,
	registry *SuiteRegistry,
	context string,
) error {
	if sha3_256(w.Pubkey) != expectedKeyID {
		return txerr(TX_ERR_SIG_INVALID, context+" key binding mismatch")
	}
	cryptoSig, digest, err := extractSigAndDigestWithCache(w, tx, inputIndex, inputValue, chainID, cache)
	if err != nil {
		return err
	}
	if sigQueue != nil {
		sigQueue.Push(w.SuiteID, w.Pubkey, cryptoSig, digest, txerr(TX_ERR_SIG_INVALID, context+" signature invalid"))
		return nil
	}
	var ok bool
	if registry != nil {
		ok, err = verifySigWithRegistry(w.SuiteID, w.Pubkey, cryptoSig, digest, registry)
	} else {
		ok, err = verifySig(w.SuiteID, w.Pubkey, cryptoSig, digest)
	}
	if err != nil {
		return err
	}
	if !ok {
		return txerr(TX_ERR_SIG_INVALID, context+" signature invalid")
	}
	return nil
}

// validateP2PKSpendQ is the queue-aware variant of validateP2PKSpendWithCache.
// When rotation or registry is nil, defaults are used (ML-DSA-87 genesis set).
func validateP2PKSpendQ(
	entry UtxoEntry,
	w WitnessItem,
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
	chainID [32]byte,
	blockHeight uint64,
	cache *SighashV1PrehashCache,
	sigQueue *SigCheckQueue,
	rotation RotationProvider,
	registry *SuiteRegistry,
) error {
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
	return verifyMLDSAKeyAndSigQ(w, keyID, tx, inputIndex, inputValue, chainID, cache, sigQueue, registry, "CORE_P2PK")
}

// validateThresholdSigSpendQ is the queue-aware variant of validateThresholdSigSpendWithCache.
//
// When sigQueue is non-nil, signatures are counted optimistically (valid++)
// and the actual crypto verification is deferred to the queue. If the queue flush
// reveals an invalid signature, the block-level error will be returned.
// When rotation or registry is nil, defaults are used (ML-DSA-87 genesis set).
func validateThresholdSigSpendQ(
	keys [][32]byte,
	threshold uint8,
	ws []WitnessItem,
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
	chainID [32]byte,
	blockHeight uint64,
	cache *SighashV1PrehashCache,
	sigQueue *SigCheckQueue,
	context string,
	rotation RotationProvider,
	registry *SuiteRegistry,
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

		if err := verifyMLDSAKeyAndSigQ(w, keys[i], tx, inputIndex, inputValue, chainID, cache, sigQueue, registry, context); err != nil {
			return err
		}
		valid++
	}
	if valid < int(threshold) {
		return txerr(TX_ERR_SIG_INVALID, context+" threshold not met")
	}
	return nil
}

// validateHTLCSpendQ is the queue-aware variant of ValidateHTLCSpendWithCache.
// When rotation or registry is nil, defaults are used (ML-DSA-87 genesis set).
func validateHTLCSpendQ(
	entry UtxoEntry,
	pathItem WitnessItem,
	sigItem WitnessItem,
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
	chainID [32]byte,
	blockHeight uint64,
	blockMTP uint64,
	cache *SighashV1PrehashCache,
	sigQueue *SigCheckQueue,
	rotation RotationProvider,
	registry *SuiteRegistry,
) error {
	c, err := ParseHTLCCovenantData(entry.CovenantData)
	if err != nil {
		return err
	}

	var expectedKeyID [32]byte
	if pathItem.SuiteID != SUITE_ID_SENTINEL {
		return txerr(TX_ERR_PARSE, "CORE_HTLC selector suite_id invalid")
	}
	pathSig := pathItem.Signature
	if len(pathItem.Pubkey) != 32 {
		return txerr(TX_ERR_PARSE, "CORE_HTLC selector key_id length invalid")
	}
	if len(pathSig) < 1 {
		return txerr(TX_ERR_PARSE, "CORE_HTLC selector payload too short")
	}
	pathID := pathSig[0]
	switch pathID {
	case 0x00: // claim
		var pathKeyID [32]byte
		copy(pathKeyID[:], pathItem.Pubkey)
		if pathKeyID != c.ClaimKeyID {
			return txerr(TX_ERR_SIG_INVALID, "CORE_HTLC claim key_id mismatch")
		}
		if len(pathSig) < 3 {
			return txerr(TX_ERR_PARSE, "CORE_HTLC claim payload too short")
		}
		preLen := int(binary.LittleEndian.Uint16(pathSig[1:3]))
		if preLen < MIN_HTLC_PREIMAGE_BYTES {
			return txerr(TX_ERR_PARSE, "CORE_HTLC preimage_len must be >= 16")
		}
		if preLen > MAX_HTLC_PREIMAGE_BYTES {
			return txerr(TX_ERR_PARSE, "CORE_HTLC preimage length overflow")
		}
		if len(pathSig) != 3+preLen {
			return txerr(TX_ERR_PARSE, "CORE_HTLC claim payload length mismatch")
		}
		preimage := pathSig[3:]
		if sha3_256(preimage) != c.Hash {
			return txerr(TX_ERR_SIG_INVALID, "CORE_HTLC claim preimage hash mismatch")
		}
		expectedKeyID = c.ClaimKeyID

	case 0x01: // refund
		if len(pathSig) != 1 {
			return txerr(TX_ERR_PARSE, "CORE_HTLC refund payload length mismatch")
		}
		var pathKeyID [32]byte
		copy(pathKeyID[:], pathItem.Pubkey)
		if pathKeyID != c.RefundKeyID {
			return txerr(TX_ERR_SIG_INVALID, "CORE_HTLC refund key_id mismatch")
		}
		if c.LockMode == LOCK_MODE_HEIGHT {
			if blockHeight < c.LockValue {
				return txerr(TX_ERR_TIMELOCK_NOT_MET, "CORE_HTLC height lock not met")
			}
		} else if blockMTP < c.LockValue {
			return txerr(TX_ERR_TIMELOCK_NOT_MET, "CORE_HTLC timestamp lock not met")
		}
		expectedKeyID = c.RefundKeyID

	default:
		return txerr(TX_ERR_PARSE, "CORE_HTLC unknown spend path")
	}

	if rotation == nil {
		rotation = DefaultRotationProvider{}
	}
	if registry == nil {
		registry = DefaultSuiteRegistry()
	}

	nativeSpend := rotation.NativeSpendSuites(blockHeight)
	if !nativeSpend.Contains(sigItem.SuiteID) {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_HTLC suite not in native spend set")
	}

	params, ok := registry.Lookup(sigItem.SuiteID)
	if !ok {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_HTLC suite not registered")
	}

	if len(sigItem.Pubkey) != params.PubkeyLen || len(sigItem.Signature) != params.SigLen+1 {
		return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical witness item lengths")
	}

	if sha3_256(sigItem.Pubkey) != expectedKeyID {
		return txerr(TX_ERR_SIG_INVALID, "CORE_HTLC signature key binding mismatch")
	}

	cryptoSig, digest, err := extractSigAndDigestWithCache(sigItem, tx, inputIndex, inputValue, chainID, cache)
	if err != nil {
		return err
	}
	if sigQueue != nil {
		sigQueue.Push(sigItem.SuiteID, sigItem.Pubkey, cryptoSig, digest, txerr(TX_ERR_SIG_INVALID, "CORE_HTLC signature invalid"))
		return nil
	}
	var sigOk bool
	var verifyErr error
	if registry != nil {
		sigOk, verifyErr = verifySigWithRegistry(sigItem.SuiteID, sigItem.Pubkey, cryptoSig, digest, registry)
	} else {
		sigOk, verifyErr = verifySig(sigItem.SuiteID, sigItem.Pubkey, cryptoSig, digest)
	}
	if verifyErr != nil {
		return verifyErr
	}
	if !sigOk {
		return txerr(TX_ERR_SIG_INVALID, "CORE_HTLC signature invalid")
	}
	return nil
}

// validateCoreStealthSpendQ is the queue-aware variant of validateCoreStealthSpendWithCache.
// When rotation or registry is nil, defaults are used (ML-DSA-87 genesis set).
func validateCoreStealthSpendQ(
	entry UtxoEntry,
	w WitnessItem,
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
	chainID [32]byte,
	blockHeight uint64,
	cache *SighashV1PrehashCache,
	sigQueue *SigCheckQueue,
	rotation RotationProvider,
	registry *SuiteRegistry,
) error {
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
	return verifyMLDSAKeyAndSigQ(w, c.OneTimeKeyID, tx, inputIndex, inputValue, chainID, cache, sigQueue, registry, "CORE_STEALTH")
}
