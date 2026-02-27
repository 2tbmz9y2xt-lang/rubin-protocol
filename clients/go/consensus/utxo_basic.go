package consensus

import "math/bits"

type Outpoint struct {
	Txid [32]byte
	Vout uint32
}

type UtxoEntry struct {
	Value             uint64
	CovenantType      uint16
	CovenantData      []byte
	CreationHeight    uint64
	CreatedByCoinbase bool
}

type UtxoApplySummary struct {
	Fee       uint64
	UtxoCount uint64
}

func ApplyNonCoinbaseTxBasic(tx *Tx, txid [32]byte, utxoSet map[Outpoint]UtxoEntry, height uint64, blockTimestamp uint64, chainID [32]byte) (*UtxoApplySummary, error) {
	return ApplyNonCoinbaseTxBasicWithMTP(tx, txid, utxoSet, height, blockTimestamp, blockTimestamp, chainID)
}

func ApplyNonCoinbaseTxBasicWithMTP(
	tx *Tx,
	txid [32]byte,
	utxoSet map[Outpoint]UtxoEntry,
	height uint64,
	blockTimestamp uint64,
	blockMTP uint64,
	chainID [32]byte,
) (*UtxoApplySummary, error) {
	work, summary, err := ApplyNonCoinbaseTxBasicUpdateWithMTP(tx, txid, utxoSet, height, blockTimestamp, blockMTP, chainID)
	_ = work
	return summary, err
}

// ApplyNonCoinbaseTxBasicUpdate applies a non-coinbase transaction to the provided UTXO snapshot
// and returns the updated UTXO set. This is a stateful helper for block connection logic.
//
// NOTE: This function implements end-to-end signature verification (verify_sig) as part of spend
// validation, and is used to deterministically compute (sum_in - sum_out) fees and update UTXO
// membership under the "basic" apply ruleset.
func ApplyNonCoinbaseTxBasicUpdate(
	tx *Tx,
	txid [32]byte,
	utxoSet map[Outpoint]UtxoEntry,
	height uint64,
	blockTimestamp uint64,
	chainID [32]byte,
) (map[Outpoint]UtxoEntry, *UtxoApplySummary, error) {
	return ApplyNonCoinbaseTxBasicUpdateWithMTP(tx, txid, utxoSet, height, blockTimestamp, blockTimestamp, chainID)
}

func ApplyNonCoinbaseTxBasicUpdateWithMTP(
	tx *Tx,
	txid [32]byte,
	utxoSet map[Outpoint]UtxoEntry,
	height uint64,
	blockTimestamp uint64,
	blockMTP uint64,
	chainID [32]byte,
) (map[Outpoint]UtxoEntry, *UtxoApplySummary, error) {
	_ = blockTimestamp
	work, fee, err := applyNonCoinbaseTxBasicWork(tx, txid, utxoSet, height, blockMTP, chainID)
	if err != nil {
		return nil, nil, err
	}
	return work, &UtxoApplySummary{
		Fee:       fee,
		UtxoCount: uint64(len(work)),
	}, nil
}

func applyNonCoinbaseTxBasicWork(
	tx *Tx,
	txid [32]byte,
	utxoSet map[Outpoint]UtxoEntry,
	height uint64,
	blockMTP uint64,
	chainID [32]byte,
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
	var vaultSigDigest [32]byte
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

		if entry.CreatedByCoinbase && height < entry.CreationHeight+COINBASE_MATURITY {
			return nil, 0, txerr(TX_ERR_COINBASE_IMMATURE, "coinbase immature")
		}

		digest, err := SighashV1Digest(tx, uint32(inputIndex), entry.Value, chainID)
		if err != nil {
			return nil, 0, err
		}

		if err := checkSpendCovenant(entry.CovenantType, entry.CovenantData); err != nil {
			return nil, 0, err
		}

		slots := WitnessSlots(entry.CovenantType, entry.CovenantData)
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
			if err := validateP2PKSpend(entry, assigned[0], digest, height); err != nil {
				return nil, 0, err
			}
		case COV_TYPE_MULTISIG:
			m, err := ParseMultisigCovenantData(entry.CovenantData)
			if err != nil {
				return nil, 0, err
			}
			if err := validateThresholdSigSpend(m.Keys, m.Threshold, assigned, digest, height, "CORE_MULTISIG"); err != nil {
				return nil, 0, err
			}
		case COV_TYPE_VAULT:
			v, err := ParseVaultCovenantData(entry.CovenantData)
			if err != nil {
				return nil, 0, err
			}
			// CORE_VAULT signature threshold is checked later (CANONICAL §24.1),
			// after owner-authorization and no-fee-sponsorship checks.
			vaultSigKeys = v.Keys
			vaultSigThreshold = v.Threshold
			vaultSigWitness = append([]WitnessItem(nil), assigned...)
			vaultSigDigest = digest
			haveVaultSig = true
		case COV_TYPE_HTLC:
			if slots != 2 {
				return nil, 0, txerr(TX_ERR_PARSE, "CORE_HTLC witness_slots must be 2")
			}
			if err := ValidateHTLCSpend(entry, assigned[0], assigned[1], digest, height, blockMTP); err != nil {
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
			vaultInputCount++
			if vaultInputCount > 1 {
				return nil, 0, txerr(TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN, "multiple CORE_VAULT inputs forbidden")
			}
			v, err := ParseVaultCovenantData(entry.CovenantData)
			if err != nil {
				return nil, 0, err
			}
			vaultWhitelist = v.Whitelist
			vaultOwnerLockID = v.OwnerLockID
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

	// CORE_VAULT creation rule: any tx creating CORE_VAULT outputs must include an owner-authorized input.
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

	// CORE_VAULT spend rules: safe-only model with owner binding and strict whitelist.
	if vaultInputCount == 1 {
		if !haveVaultSig {
			return nil, 0, txerr(TX_ERR_PARSE, "missing CORE_VAULT signature context")
		}
		// Owner input required.
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

		// No fee sponsorship: all non-vault inputs must be owned by the same owner lock.
		for i := range inputCovTypes {
			if inputCovTypes[i] == COV_TYPE_VAULT {
				continue
			}
			if inputLockIDs[i] != vaultOwnerLockID {
				return nil, 0, txerr(TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN, "non-owner non-vault input forbidden in CORE_VAULT spend")
			}
		}

		// Circular-reference hardening: vault spends MUST NOT create new CORE_VAULT outputs.
		for _, out := range tx.Outputs {
			if out.CovenantType == COV_TYPE_VAULT {
				return nil, 0, txerr(TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED, "CORE_VAULT outputs forbidden in CORE_VAULT spend")
			}
		}

		// Signature threshold check (CANONICAL §24.1 step 7).
		if err := validateThresholdSigSpend(vaultSigKeys, vaultSigThreshold, vaultSigWitness, vaultSigDigest, height, "CORE_VAULT"); err != nil {
			return nil, 0, err
		}

		// Whitelist enforcement: all outputs must be whitelisted.
		for _, out := range tx.Outputs {
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

func checkSpendCovenant(
	covType uint16,
	covData []byte,
) error {
	if covType == COV_TYPE_P2PK {
		return nil
	}
	if covType == COV_TYPE_VAULT {
		v, err := ParseVaultCovenantData(covData)
		if err != nil {
			return err
		}
		_ = v
		return nil
	}
	if covType == COV_TYPE_MULTISIG {
		m, err := ParseMultisigCovenantData(covData)
		if err != nil {
			return err
		}
		_ = m
		return nil
	}
	if covType == COV_TYPE_HTLC {
		if _, err := ParseHTLCCovenantData(covData); err != nil {
			return err
		}
		return nil
	}
	// Reserved/unknown are unsupported in basic apply path.
	return txerr(TX_ERR_COVENANT_TYPE_INVALID, "unsupported covenant in basic apply")
}

type u128 struct {
	hi uint64
	lo uint64
}

func addU64ToU128(x u128, v uint64) (u128, error) {
	lo, carry := bits.Add64(x.lo, v, 0)
	hi, carry2 := bits.Add64(x.hi, 0, carry)
	if carry2 != 0 {
		return u128{}, txerr(TX_ERR_PARSE, "u128 overflow")
	}
	return u128{hi: hi, lo: lo}, nil
}

func cmpU128(a u128, b u128) int {
	if a.hi < b.hi {
		return -1
	}
	if a.hi > b.hi {
		return 1
	}
	if a.lo < b.lo {
		return -1
	}
	if a.lo > b.lo {
		return 1
	}
	return 0
}

func subU128(a u128, b u128) (u128, error) {
	if cmpU128(a, b) < 0 {
		return u128{}, txerr(TX_ERR_PARSE, "u128 underflow")
	}
	lo, borrow := bits.Sub64(a.lo, b.lo, 0)
	hi, borrow2 := bits.Sub64(a.hi, b.hi, borrow)
	if borrow2 != 0 {
		return u128{}, txerr(TX_ERR_PARSE, "u128 underflow")
	}
	return u128{hi: hi, lo: lo}, nil
}

func u128ToU64(x u128) (uint64, error) {
	if x.hi != 0 {
		return 0, txerr(TX_ERR_PARSE, "u64 overflow")
	}
	return x.lo, nil
}
