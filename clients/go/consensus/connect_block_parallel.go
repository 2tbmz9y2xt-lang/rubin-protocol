package consensus

import "math/big"

// ConnectBlockParallelSigVerify connects a block against an in-memory UTXO
// snapshot with parallel signature verification. This is an IBD-only
// optimization: all fast pre-checks (UTXO lookup, covenant parse, witness
// assignment, value conservation) are performed sequentially, while the
// expensive ML-DSA-87 signature verifications are collected into a
// SigCheckQueue and executed in parallel using a goroutine pool.
//
// IMPORTANT: This function produces DIFFERENT ERROR ORDERING than
// ConnectBlockBasicInMemoryAtHeight when a block contains both a signature
// failure and a pre-check failure in a later transaction. Specifically,
// pre-check errors from later transactions may be returned instead of
// signature errors from earlier transactions. This is acceptable during IBD
// because:
//   - All blocks being validated are from the canonical chain
//   - Invalid blocks are rejected regardless of error ordering
//   - Conformance vector error-ordering guarantees are not required during IBD
//
// The workers parameter controls the goroutine pool size for signature
// verification. If workers <= 0, defaults to GOMAXPROCS.
func ConnectBlockParallelSigVerify(
	blockBytes []byte,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
	state *InMemoryChainState,
	chainID [32]byte,
	workers int,
) (*ConnectBlockBasicSummary, error) {
	return ConnectBlockParallelSigVerifyWithCoreExtProfiles(
		blockBytes,
		expectedPrevHash,
		expectedTarget,
		blockHeight,
		prevTimestamps,
		state,
		chainID,
		nil,
		workers,
	)
}

// ConnectBlockParallelSigVerifyWithCoreExtProfiles is the full variant with
// CORE_EXT profile support. See ConnectBlockParallelSigVerify for details.
func ConnectBlockParallelSigVerifyWithCoreExtProfiles(
	blockBytes []byte,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
	state *InMemoryChainState,
	chainID [32]byte,
	coreExtProfiles CoreExtProfileProvider,
	workers int,
) (*ConnectBlockBasicSummary, error) {
	if state == nil {
		return nil, txerr(BLOCK_ERR_PARSE, "nil chainstate")
	}
	if state.Utxos == nil {
		state.Utxos = make(map[Outpoint]UtxoEntry)
	}
	if state.AlreadyGenerated == nil {
		state.AlreadyGenerated = new(big.Int)
	}
	if state.AlreadyGenerated.Sign() < 0 {
		return nil, txerr(BLOCK_ERR_PARSE, "already_generated must be unsigned")
	}

	// Stateless checks first (wire, merkle root, PoW/target, covenant creation, etc).
	if _, err := ValidateBlockBasicWithContextAtHeight(blockBytes, expectedPrevHash, expectedTarget, blockHeight, prevTimestamps); err != nil {
		return nil, err
	}

	pb, err := ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	if pb == nil || len(pb.Txs) == 0 || len(pb.Txids) != len(pb.Txs) {
		return nil, txerr(BLOCK_ERR_PARSE, "invalid parsed block")
	}

	alreadyGenerated := new(big.Int).Set(state.AlreadyGenerated)
	blockMTP := pb.Header.Timestamp
	if median, ok, err := medianTimePast(blockHeight, prevTimestamps); err != nil {
		return nil, err
	} else if ok {
		blockMTP = median
	}
	// Clone UTXO set upfront to prevent aliasing state.Utxos. Without this,
	// coinbase-only blocks (no non-coinbase txs) would insert coinbase outputs
	// directly into state.Utxos before all fallible checks complete, leaving
	// the caller's state partially mutated on error paths.
	workUtxos := make(map[Outpoint]UtxoEntry, len(state.Utxos))
	for k, v := range state.Utxos {
		workUtxos[k] = v
	}

	// Create a single sig check queue for the entire block.
	// All signature verifications across all transactions are collected here
	// and executed in parallel after all pre-checks pass.
	sigQueue := NewSigCheckQueue(workers)

	// Apply all non-coinbase transactions with deferred sig verification.
	var sumFees uint64
	for i := 1; i < len(pb.Txs); i++ {
		tx := pb.Txs[i]
		txid := pb.Txids[i]

		nextUtxos, s, err := applyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesQ(
			tx,
			txid,
			workUtxos,
			blockHeight,
			pb.Header.Timestamp,
			blockMTP,
			chainID,
			coreExtProfiles,
			sigQueue,
		)
		if err != nil {
			return nil, err
		}
		workUtxos = nextUtxos
		sumFees, err = addU64(sumFees, s.Fee)
		if err != nil {
			return nil, txerr(BLOCK_ERR_PARSE, "sum_fees overflow")
		}
	}

	// Flush the signature queue: verify all collected signatures in parallel.
	// Returns the first error by submission order (deterministic within the
	// deferred-sig model).
	if err := sigQueue.Flush(); err != nil {
		return nil, err
	}

	// Enforce coinbase bound using locally computed fees.
	if err := validateCoinbaseValueBound(pb, blockHeight, alreadyGenerated, sumFees); err != nil {
		return nil, err
	}
	if err := validateCoinbaseApplyOutputs(pb.Txs[0]); err != nil {
		return nil, err
	}

	// Add coinbase outputs to UTXO set (spendable outputs only).
	coinbase := pb.Txs[0]
	coinbaseTxid := pb.Txids[0]
	for i, out := range coinbase.Outputs {
		if out.CovenantType == COV_TYPE_ANCHOR || out.CovenantType == COV_TYPE_DA_COMMIT {
			continue
		}
		op := Outpoint{Txid: coinbaseTxid, Vout: uint32(i)}
		workUtxos[op] = UtxoEntry{
			Value:             out.Value,
			CovenantType:      out.CovenantType,
			CovenantData:      append([]byte(nil), out.CovenantData...),
			CreationHeight:    blockHeight,
			CreatedByCoinbase: true,
		}
	}

	// Update already_generated(h) -> already_generated(h+1) by adding subsidy(h).
	alreadyGeneratedN1 := new(big.Int).Set(alreadyGenerated)
	if blockHeight != 0 {
		subsidy := BlockSubsidyBig(blockHeight, alreadyGenerated)
		alreadyGeneratedN1 = new(big.Int).Add(alreadyGeneratedN1, new(big.Int).SetUint64(subsidy))
	}
	alreadyGeneratedU64, err := bigIntToUint64(alreadyGenerated)
	if err != nil {
		return nil, txerr(BLOCK_ERR_PARSE, "already_generated overflow")
	}
	alreadyGeneratedN1U64, err := bigIntToUint64(alreadyGeneratedN1)
	if err != nil {
		return nil, txerr(BLOCK_ERR_PARSE, "already_generated overflow")
	}

	state.Utxos = workUtxos
	if blockHeight != 0 {
		state.AlreadyGenerated = new(big.Int).Set(alreadyGeneratedN1)
	}

	return &ConnectBlockBasicSummary{
		SumFees:            sumFees,
		AlreadyGenerated:   alreadyGeneratedU64,
		AlreadyGeneratedN1: alreadyGeneratedN1U64,
		UtxoCount:          uint64(len(state.Utxos)),
	}, nil
}

// applyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesQ is the queue-aware
// wrapper around applyNonCoinbaseTxBasicWorkQ. It mirrors
// ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles but accepts a
// SigCheckQueue for deferred signature verification.
func applyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesQ(
	tx *Tx,
	txid [32]byte,
	utxoSet map[Outpoint]UtxoEntry,
	height uint64,
	blockTimestamp uint64,
	blockMTP uint64,
	chainID [32]byte,
	coreExtProfiles CoreExtProfileProvider,
	sigQueue *SigCheckQueue,
) (map[Outpoint]UtxoEntry, *UtxoApplySummary, error) {
	_ = blockTimestamp
	work, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, txid, utxoSet, height, blockMTP, chainID, coreExtProfiles, sigQueue)
	if err != nil {
		return nil, nil, err
	}
	return work, &UtxoApplySummary{
		Fee:       fee,
		UtxoCount: uint64(len(work)),
	}, nil
}

// applyNonCoinbaseTxBasicWorkQ is the queue-aware variant of
// applyNonCoinbaseTxBasicWork. When sigQueue is non-nil, signature
// verifications are pushed to the queue instead of being executed inline.
//
// All non-crypto pre-checks (UTXO lookup, covenant parse, witness assignment,
// value conservation, vault rules) are performed identically to the sequential
// path. Only the verifySig calls are deferred.
func applyNonCoinbaseTxBasicWorkQ(
	tx *Tx,
	txid [32]byte,
	utxoSet map[Outpoint]UtxoEntry,
	height uint64,
	blockMTP uint64,
	chainID [32]byte,
	coreExtProfiles CoreExtProfileProvider,
	sigQueue *SigCheckQueue,
) (map[Outpoint]UtxoEntry, uint64, error) {
	if tx == nil {
		return nil, 0, txerr(TX_ERR_PARSE, "nil tx")
	}
	if len(tx.Inputs) == 0 {
		return nil, 0, txerr(TX_ERR_PARSE, "non-coinbase must have at least one input")
	}
	if tx.TxNonce == 0 {
		return nil, 0, txerr(TX_ERR_TX_NONCE_INVALID, "tx_nonce must be >= 1 for non-coinbase")
	}

	if err := ValidateTxCovenantsGenesis(tx, height); err != nil {
		return nil, 0, err
	}
	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		return nil, 0, err
	}

	// Clone UTXO set so per-tx mutations (spend/create) don't alias the caller's map.
	// This matches the sequential path (applyNonCoinbaseTxBasicWork). A future
	// optimization may use an overlay/undo journal instead, but correctness requires
	// matching the canonical sequential behavior exactly.
	work := make(map[Outpoint]UtxoEntry, len(utxoSet))
	for k, v := range utxoSet {
		work[k] = v
	}

	var sumIn u128
	var sumInVault u128
	var vaultWhitelist [][32]byte
	var vaultOwnerLockID [32]byte
	var vaultSigKeys [][32]byte
	var vaultSigThreshold uint8
	var vaultSigWitness []WitnessItem
	var vaultSigInputIndex uint32
	var vaultSigInputValue uint64
	haveVaultSig := false
	vaultInputCount := 0
	witnessCursor := 0
	var inputLockIDs [][32]byte
	var inputCovTypes []uint16
	seenInputs := make(map[Outpoint]struct{}, len(tx.Inputs))
	var zeroTxid [32]byte
	for inputIndex, in := range tx.Inputs {
		if len(in.ScriptSig) != 0 {
			return nil, 0, txerr(TX_ERR_PARSE, "script_sig must be empty under genesis covenant set")
		}
		if in.Sequence > 0x7fffffff {
			return nil, 0, txerr(TX_ERR_SEQUENCE_INVALID, "sequence exceeds 0x7fffffff")
		}
		if in.PrevVout == 0xffff_ffff && in.PrevTxid == zeroTxid {
			return nil, 0, txerr(TX_ERR_PARSE, "coinbase prevout encoding forbidden in non-coinbase")
		}
		op := Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		if _, exists := seenInputs[op]; exists {
			return nil, 0, txerr(TX_ERR_PARSE, "duplicate input outpoint")
		}
		seenInputs[op] = struct{}{}
		entry, ok := work[op]
		if !ok {
			return nil, 0, txerr(TX_ERR_MISSING_UTXO, "utxo not found")
		}

		if entry.CovenantType == COV_TYPE_ANCHOR || entry.CovenantType == COV_TYPE_DA_COMMIT {
			return nil, 0, txerr(TX_ERR_MISSING_UTXO, "attempt to spend non-spendable covenant")
		}

		// Overflow-safe maturity check: avoid entry.CreationHeight+COINBASE_MATURITY wrapping.
		if entry.CreatedByCoinbase && (height < entry.CreationHeight || height-entry.CreationHeight < COINBASE_MATURITY) {
			return nil, 0, txerr(TX_ERR_COINBASE_IMMATURE, "coinbase immature")
		}

		if entry.CovenantType == COV_TYPE_VAULT {
			vaultInputCount++
			if vaultInputCount > 1 {
				return nil, 0, txerr(TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN, "multiple CORE_VAULT inputs forbidden")
			}
		}

		if err := checkSpendCovenant(entry.CovenantType, entry.CovenantData); err != nil {
			return nil, 0, err
		}

		slots, err := WitnessSlots(entry.CovenantType, entry.CovenantData)
		if err != nil {
			return nil, 0, err
		}
		if slots <= 0 {
			return nil, 0, txerr(TX_ERR_PARSE, "invalid witness slots")
		}
		if witnessCursor+slots > len(tx.Witness) {
			return nil, 0, txerr(TX_ERR_PARSE, "witness underflow")
		}
		assigned := tx.Witness[witnessCursor : witnessCursor+slots]

		switch entry.CovenantType {
		case COV_TYPE_P2PK:
			if slots != 1 {
				return nil, 0, txerr(TX_ERR_PARSE, "CORE_P2PK witness_slots must be 1")
			}
			if err := validateP2PKSpendQ(entry, assigned[0], tx, uint32(inputIndex), entry.Value, chainID, height, sighashCache, sigQueue); err != nil {
				return nil, 0, err
			}
		case COV_TYPE_MULTISIG:
			m, err := ParseMultisigCovenantData(entry.CovenantData)
			if err != nil {
				return nil, 0, err
			}
			if err := validateThresholdSigSpendQ(
				m.Keys,
				m.Threshold,
				assigned,
				tx,
				uint32(inputIndex),
				entry.Value,
				chainID,
				height,
				sighashCache,
				sigQueue,
				"CORE_MULTISIG",
			); err != nil {
				return nil, 0, err
			}
		case COV_TYPE_VAULT:
			v, err := ParseVaultCovenantDataForSpend(entry.CovenantData)
			if err != nil {
				return nil, 0, err
			}
			vaultSigKeys = v.Keys
			vaultSigThreshold = v.Threshold
			vaultSigWitness = append([]WitnessItem(nil), assigned...)
			vaultSigInputIndex = uint32(inputIndex)
			vaultSigInputValue = entry.Value
			vaultWhitelist = v.Whitelist
			vaultOwnerLockID = v.OwnerLockID
			haveVaultSig = true
		case COV_TYPE_HTLC:
			if slots != 2 {
				return nil, 0, txerr(TX_ERR_PARSE, "CORE_HTLC witness_slots must be 2")
			}
			if err := validateHTLCSpendQ(
				entry,
				assigned[0],
				assigned[1],
				tx,
				uint32(inputIndex),
				entry.Value,
				chainID,
				height,
				blockMTP,
				sighashCache,
				sigQueue,
			); err != nil {
				return nil, 0, err
			}
		case COV_TYPE_CORE_EXT:
			if slots != CORE_EXT_WITNESS_SLOTS {
				return nil, 0, txerr(TX_ERR_PARSE, "CORE_EXT witness_slots must be 1")
			}
			cd, err := ParseCoreExtCovenantData(entry.CovenantData)
			if err != nil {
				return nil, 0, err
			}
			w := assigned[0]

			active := false
			allowedSuites := map[uint8]struct{}(nil)
			verifySigExtFn := CoreExtVerifySigExtFunc(nil)

			if coreExtProfiles != nil {
				profile, ok, err := coreExtProfiles.LookupCoreExtProfile(cd.ExtID, height)
				if err != nil {
					return nil, 0, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT profile lookup failure")
				}
				if ok && profile.Active {
					active = true
					allowedSuites = profile.AllowedSuites
					verifySigExtFn = profile.VerifySigExtFn
				}
			}

			if !active {
				break
			}

			if !hasSuite(allowedSuites, w.SuiteID) {
				return nil, 0, txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT suite disallowed under ACTIVE profile")
			}
			if w.SuiteID == SUITE_ID_SENTINEL {
				return nil, 0, txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT sentinel forbidden under ACTIVE profile")
			}
			extractCoreExtSigDigest := func() ([]byte, [32]byte, error) {
				return extractSigAndDigestWithCache(w, tx, uint32(inputIndex), entry.Value, chainID, sighashCache)
			}

			switch w.SuiteID {
			case SUITE_ID_ML_DSA_87:
				if len(w.Pubkey) != ML_DSA_87_PUBKEY_BYTES || len(w.Signature) != ML_DSA_87_SIG_BYTES+1 {
					return nil, 0, txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical ML-DSA witness item lengths")
				}
				cryptoSig, digest, err := extractCoreExtSigDigest()
				if err != nil {
					return nil, 0, err
				}
				if sigQueue != nil {
					sigQueue.Push(w.SuiteID, w.Pubkey, cryptoSig, digest, txerr(TX_ERR_SIG_INVALID, "CORE_EXT signature invalid"))
				} else {
					ok, err := verifySig(w.SuiteID, w.Pubkey, cryptoSig, digest)
					if err != nil {
						return nil, 0, err
					}
					if !ok {
						return nil, 0, txerr(TX_ERR_SIG_INVALID, "CORE_EXT signature invalid")
					}
				}
			default:
				// CORE_EXT external verifiers are NOT deferred to the queue
				// because they may not be thread-safe.
				if verifySigExtFn == nil {
					return nil, 0, txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT verify_sig_ext unsupported")
				}
				cryptoSig, digest, err := extractCoreExtSigDigest()
				if err != nil {
					return nil, 0, err
				}
				ok, err := verifySigExtFn(cd.ExtID, w.SuiteID, w.Pubkey, cryptoSig, digest, cd.ExtPayload)
				if err != nil {
					return nil, 0, txerr(TX_ERR_SIG_ALG_INVALID, "CORE_EXT verify_sig_ext error")
				}
				if !ok {
					return nil, 0, txerr(TX_ERR_SIG_INVALID, "CORE_EXT signature invalid")
				}
			}
		case COV_TYPE_CORE_STEALTH:
			if slots != CORE_STEALTH_WITNESS_SLOTS {
				return nil, 0, txerr(TX_ERR_PARSE, "CORE_STEALTH witness_slots must be 1")
			}
			if err := validateCoreStealthSpendQ(entry, assigned[0], tx, uint32(inputIndex), entry.Value, chainID, height, sighashCache, sigQueue); err != nil {
				return nil, 0, err
			}
		default:
			// Other covenants have no additional spend-time checks in the genesis set.
		}

		witnessCursor += slots

		inputLockID := sha3_256(OutputDescriptorBytes(entry.CovenantType, entry.CovenantData))
		inputLockIDs = append(inputLockIDs, inputLockID)
		inputCovTypes = append(inputCovTypes, entry.CovenantType)

		sumIn, err = addU64ToU128(sumIn, entry.Value)
		if err != nil {
			return nil, 0, err
		}
		if entry.CovenantType == COV_TYPE_VAULT {
			sumInVault, err = addU64ToU128(sumInVault, entry.Value)
			if err != nil {
				return nil, 0, err
			}
		}

		delete(work, op)
	}
	if witnessCursor != len(tx.Witness) {
		return nil, 0, txerr(TX_ERR_PARSE, "witness_count mismatch")
	}

	var sumOut u128
	createsVault := false
	for i, out := range tx.Outputs {
		var err error
		sumOut, err = addU64ToU128(sumOut, out.Value)
		if err != nil {
			return nil, 0, err
		}

		if out.CovenantType == COV_TYPE_VAULT {
			createsVault = true
		}

		if out.CovenantType == COV_TYPE_ANCHOR || out.CovenantType == COV_TYPE_DA_COMMIT {
			continue
		}

		op := Outpoint{Txid: txid, Vout: uint32(i)}
		work[op] = UtxoEntry{
			Value:             out.Value,
			CovenantType:      out.CovenantType,
			CovenantData:      append([]byte(nil), out.CovenantData...),
			CreationHeight:    height,
			CreatedByCoinbase: false,
		}
	}

	// CORE_VAULT creation rule.
	if createsVault {
		for _, out := range tx.Outputs {
			if out.CovenantType != COV_TYPE_VAULT {
				continue
			}
			v, err := ParseVaultCovenantData(out.CovenantData)
			if err != nil {
				return nil, 0, err
			}
			ownerLockID := v.OwnerLockID

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
			if !hasOwnerLockID || !hasOwnerLockType {
				return nil, 0, txerr(TX_ERR_VAULT_OWNER_AUTH_REQUIRED, "missing owner-authorized input for CORE_VAULT creation")
			}
		}
	}

	// CORE_VAULT spend rules.
	if vaultInputCount == 1 {
		if !haveVaultSig {
			return nil, 0, txerr(TX_ERR_PARSE, "missing CORE_VAULT signature context")
		}
		ownerAuthPresent := false
		for i := range inputLockIDs {
			if inputLockIDs[i] == vaultOwnerLockID {
				ownerAuthPresent = true
				break
			}
		}
		if !ownerAuthPresent {
			return nil, 0, txerr(TX_ERR_VAULT_OWNER_AUTH_REQUIRED, "missing owner-authorized input for CORE_VAULT spend")
		}

		for i := range inputCovTypes {
			if inputCovTypes[i] == COV_TYPE_VAULT {
				continue
			}
			if inputLockIDs[i] != vaultOwnerLockID {
				return nil, 0, txerr(TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN, "non-owner non-vault input forbidden in CORE_VAULT spend")
			}
		}

		for _, out := range tx.Outputs {
			if out.CovenantType == COV_TYPE_VAULT {
				return nil, 0, txerr(TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED, "CORE_VAULT outputs forbidden in CORE_VAULT spend")
			}
		}

		// Vault signature threshold check (CANONICAL §24.1 step 7).
		if err := validateThresholdSigSpendQ(
			vaultSigKeys,
			vaultSigThreshold,
			vaultSigWitness,
			tx,
			vaultSigInputIndex,
			vaultSigInputValue,
			chainID,
			height,
			sighashCache,
			sigQueue,
			"CORE_VAULT",
		); err != nil {
			return nil, 0, err
		}

		for _, out := range tx.Outputs {
			if out.CovenantType != COV_TYPE_P2PK && out.CovenantType != COV_TYPE_MULTISIG && out.CovenantType != COV_TYPE_HTLC {
				return nil, 0, txerr(TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED, "disallowed destination covenant_type for CORE_VAULT spend")
			}
			desc := OutputDescriptorBytes(out.CovenantType, out.CovenantData)
			h := sha3_256(desc)
			if !HashInSorted32(vaultWhitelist, h) {
				return nil, 0, txerr(TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED, "output not whitelisted for CORE_VAULT")
			}
		}
	}

	if cmpU128(sumOut, sumIn) > 0 {
		return nil, 0, txerr(TX_ERR_VALUE_CONSERVATION, "sum_out exceeds sum_in")
	}
	if vaultInputCount == 1 && cmpU128(sumOut, sumInVault) < 0 {
		return nil, 0, txerr(TX_ERR_VALUE_CONSERVATION, "CORE_VAULT value must not fund miner fee")
	}
	feeU128, err := subU128(sumIn, sumOut)
	if err != nil {
		return nil, 0, err
	}
	fee, err := u128ToU64(feeU128)
	if err != nil {
		return nil, 0, err
	}

	return work, fee, nil
}
