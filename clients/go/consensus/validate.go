package consensus

import (
	"bytes"
	"fmt"

	"rubin.dev/node/crypto"
)

// TxWeight computes an estimated weight for the given transaction.
// It combines a base component (4× the length of the transaction without witnesses), the total witness bytes, and per-input signature-verification costs for witnessed inputs using ML_DSA or SLH_DSA suites.
// Returns the computed total weight, or an error if internal size additions overflow or parsing fails.
func TxWeight(tx *Tx) (uint64, error) {
	base := len(TxNoWitnessBytes(tx))
	witness := len(WitnessBytes(tx.Witness))
	base = base * 4
	sigCost := 0
	for i, item := range tx.Witness.Witnesses {
		if i < len(tx.Inputs) {
			switch item.SuiteID {
			case SUITE_ID_ML_DSA:
				sigCost += VERIFY_COST_ML_DSA
			case SUITE_ID_SLH_DSA:
				sigCost += VERIFY_COST_SLH_DSA
			}
		}
	}
	total, err := addUint64(uint64(base), uint64(witness))
	if err != nil {
		return 0, fmt.Errorf("TX_ERR_PARSE")
	}
	return addUint64(total, uint64(sigCost))
}

// txidFromTx computes the transaction ID for the given transaction using the provided crypto provider.
func txidFromTx(p crypto.CryptoProvider, tx *Tx) [32]byte {
	return TxID(p, tx)
}

// TxID computes the transaction identifier for tx by hashing the transaction bytes without witnesses.
// It returns the 32-byte SHA3-256 digest produced by the provided crypto provider.
func TxID(p crypto.CryptoProvider, tx *Tx) [32]byte {
	return p.SHA3_256(TxNoWitnessBytes(tx))
}

// merkleRootTxIDs computes the Merkle root of the provided transactions using
// leaf and inner-node domain separation (leaf prefix 0x00, inner-node prefix 0x01).
// It returns the 32-byte Merkle root or an error when the input slice is empty.
func merkleRootTxIDs(p crypto.CryptoProvider, txs []*Tx) ([32]byte, error) {
	if len(txs) == 0 {
		return [32]byte{}, fmt.Errorf("BLOCK_ERR_MERKLE_INVALID")
	}
	level := make([][32]byte, 0, len(txs))
	for _, tx := range txs {
		// Leaf domain separation (spec §5.1.1): Leaf = SHA3-256(0x00 || txid)
		txid := TxID(p, tx)
		leaf := make([]byte, 0, 1+len(txid))
		leaf = append(leaf, 0x00)
		leaf = append(leaf, txid[:]...)
		level = append(level, p.SHA3_256(leaf))
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			concat := make([]byte, 0, 1+len(level[i])+len(level[i+1]))
			concat = append(concat, 0x01)
			concat = append(concat, level[i][:]...)
			concat = append(concat, level[i+1][:]...)
			next = append(next, p.SHA3_256(concat))
		}
		level = next
	}
	return level[0], nil
}

// txSums computes the total input value by summing the referenced UTXO outputs and the total output value by summing tx.Outputs.
// It looks up each input's previous outpoint in the provided utxo map to obtain its value.
// Returns the total input value, the total output value, and an error if a referenced UTXO is missing or if any addition overflows.
func txSums(tx *Tx, utxo map[TxOutPoint]UtxoEntry) (uint64, uint64, error) {
	var inputSum uint64
	var outputSum uint64
	for _, input := range tx.Inputs {
		prev := TxOutPoint{
			TxID: input.PrevTxid,
			Vout: input.PrevVout,
		}
		entry, ok := utxo[prev]
		if !ok {
			return 0, 0, fmt.Errorf(TX_ERR_MISSING_UTXO)
		}
		var err error
		inputSum, err = addUint64(inputSum, entry.Output.Value)
		if err != nil {
			return 0, 0, err
		}
	}
	for _, output := range tx.Outputs {
		var err error
		outputSum, err = addUint64(outputSum, output.Value)
		if err != nil {
			return 0, 0, err
		}
	}
	return inputSum, outputSum, nil
}

// validateOutputCovenantConstraints checks covenant-specific structural constraints for a transaction output.
// 
// It enforces required covenant data lengths and value constraints for supported covenant types:
// - CORE_P2PK: CovenantData must be 33 bytes.
// - CORE_TIMELOCK_V1: CovenantData must be 9 bytes.
// - CORE_ANCHOR: Value must be 0 and CovenantData length must be between 1 and MAX_ANCHOR_PAYLOAD_SIZE.
// - CORE_HTLC_V1: CovenantData must be 105 bytes.
// - CORE_HTLC_V2: CovenantData must be 105 bytes and the claim key ID (bytes 41..73) must differ from the refund key ID (bytes 73..105).
// - CORE_VAULT_V1: CovenantData must be either 73 or 81 bytes.
// - CORE_RESERVED_FUTURE and unknown types are rejected.
//
// Returns an error with code "TX_ERR_PARSE" for malformed covenant data, or "TX_ERR_COVENANT_TYPE_INVALID" for invalid covenant types or anchor/value violations.
func validateOutputCovenantConstraints(output TxOutput) error {
	switch output.CovenantType {
	case CORE_P2PK:
		if len(output.CovenantData) != 33 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
	case CORE_TIMELOCK_V1:
		if len(output.CovenantData) != 9 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
	case CORE_ANCHOR:
		if output.Value != 0 {
			return fmt.Errorf("TX_ERR_COVENANT_TYPE_INVALID")
		}
		if len(output.CovenantData) == 0 || len(output.CovenantData) > MAX_ANCHOR_PAYLOAD_SIZE {
			return fmt.Errorf("TX_ERR_COVENANT_TYPE_INVALID")
		}
	case CORE_HTLC_V1:
		if len(output.CovenantData) != 105 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
	case CORE_HTLC_V2:
		// Deployment gate checked at spend time, not output creation time.
		// Output-level constraint: same covenant_data layout as HTLC_V1.
		if len(output.CovenantData) != 105 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		claimKeyID := output.CovenantData[41:73]
		refundKeyID := output.CovenantData[73:105]
		if bytes.Equal(claimKeyID, refundKeyID) {
			return fmt.Errorf("TX_ERR_PARSE")
		}
	case CORE_VAULT_V1:
		if len(output.CovenantData) != 73 && len(output.CovenantData) != 81 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
	case CORE_RESERVED_FUTURE:
		return fmt.Errorf("TX_ERR_COVENANT_TYPE_INVALID")
	default:
		return fmt.Errorf("TX_ERR_COVENANT_TYPE_INVALID")
	}
	return nil
}

// validateCoinbaseTxInputs verifies that tx uses the exact input shape required for a coinbase:
// it must have TxNonce == 0, exactly one input, that input's Sequence equal to TX_COINBASE_PREVOUT_VOUT,
// PrevTxid equal to the zero txid, PrevVout equal to TX_COINBASE_PREVOUT_VOUT, an empty ScriptSig,
// and no witnesses. It returns an error if any of these constraints are violated.
func validateCoinbaseTxInputs(tx *Tx) error {
	if tx.TxNonce != 0 {
		return fmt.Errorf(BLOCK_ERR_COINBASE_INVALID)
	}
	if len(tx.Inputs) != 1 {
		return fmt.Errorf(BLOCK_ERR_COINBASE_INVALID)
	}
	in := tx.Inputs[0]
	if in.Sequence != TX_COINBASE_PREVOUT_VOUT {
		return fmt.Errorf(BLOCK_ERR_COINBASE_INVALID)
	}
	if in.PrevTxid != ([32]byte{}) || in.PrevVout != TX_COINBASE_PREVOUT_VOUT {
		return fmt.Errorf(BLOCK_ERR_COINBASE_INVALID)
	}
	if len(in.ScriptSig) != 0 {
		return fmt.Errorf(BLOCK_ERR_COINBASE_INVALID)
	}
	if len(tx.Witness.Witnesses) != 0 {
		return fmt.Errorf(BLOCK_ERR_COINBASE_INVALID)
	}
	return nil
}

// validateHTLCScriptSigLen enforces allowed scriptSig lengths for HTLC outputs.
// It accepts only lengths of 0 or 32.
// Returns nil if the length is 0 or 32, otherwise an error with code "TX_ERR_PARSE".
func validateHTLCScriptSigLen(scriptSigLen int) error {
	switch scriptSigLen {
	case 0, 32:
		return nil
	default:
		return fmt.Errorf("TX_ERR_PARSE")
	}
}

// checkWitnessFormat validates that a witness item's public key and signature lengths match the expectations for its SuiteID.
// For SUITE_ID_SENTINEL both Pubkey and Signature must be empty. For SUITE_ID_ML_DSA Pubkey and Signature must match exact canonical lengths.
// For SUITE_ID_SLH_DSA the SLH suite must be active and Pubkey must match the canonical length while Signature must be non-zero and not exceed the maximum allowed length.
// Returns an error with a specific consensus error code when the suite is inactive, lengths are non-canonical, or the SuiteID is unrecognized.
func checkWitnessFormat(item WitnessItem, suiteIDSLHActive bool) error {
	switch item.SuiteID {
	case SUITE_ID_SENTINEL:
		if len(item.Pubkey) != 0 || len(item.Signature) != 0 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		return nil
	case SUITE_ID_ML_DSA:
		if len(item.Pubkey) != ML_DSA_PUBKEY_BYTES || len(item.Signature) != ML_DSA_SIG_BYTES {
			return fmt.Errorf("TX_ERR_SIG_NONCANONICAL")
		}
		return nil
	case SUITE_ID_SLH_DSA:
		if !suiteIDSLHActive {
			return fmt.Errorf("TX_ERR_DEPLOYMENT_INACTIVE")
		}
		if len(item.Pubkey) != SLH_DSA_PUBKEY_BYTES || len(item.Signature) == 0 || len(item.Signature) > SLH_DSA_SIG_MAX_BYTES {
			return fmt.Errorf("TX_ERR_SIG_NONCANONICAL")
		}
		return nil
	default:
		return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
	}
}

// satisfyLock verifies a timelock given mode and value against the provided height and timestamp.
// It returns nil if the lock condition is met, an error "TX_ERR_TIMELOCK_NOT_MET" if the lock is not yet met,
// or "TX_ERR_PARSE" for an unrecognized lock mode.
func satisfyLock(lockMode byte, lockValue, height, timestamp uint64) error {
	switch lockMode {
	case TIMELOCK_MODE_HEIGHT:
		if height >= lockValue {
			return nil
		}
		return fmt.Errorf("TX_ERR_TIMELOCK_NOT_MET")
	case TIMELOCK_MODE_TIMESTAMP:
		if timestamp >= lockValue {
			return nil
		}
		return fmt.Errorf("TX_ERR_TIMELOCK_NOT_MET")
	default:
		return fmt.Errorf("TX_ERR_PARSE")
	}
}

// ApplyBlock validates all block-level consensus rules for block B and mutates utxo on success.
// ApplyBlock validates and applies a full block against consensus rules, updating the provided UTXO map on success.
// It verifies header linkage, target and PoW, merkle root, and timestamps; ensures exactly one coinbase transaction;
// computes transaction weights and fees, enforces per-block limits (weight, anchor bytes, subsidy), and validates and
// applies each transaction (including coinbase rules) using the working UTXO set. On success the provided utxo map is
// replaced with the updated state; on any error the original utxo map is left unmodified.
func ApplyBlock(
	p crypto.CryptoProvider,
	chainID [32]byte,
	block *Block,
	utxo map[TxOutPoint]UtxoEntry,
	ctx BlockValidationContext,
) error {
	if block == nil || len(block.Transactions) == 0 {
		return fmt.Errorf(BLOCK_ERR_COINBASE_INVALID)
	}

	if ctx.Height > 0 && len(ctx.AncestorHeaders) == 0 {
		return fmt.Errorf(BLOCK_ERR_LINKAGE_INVALID)
	}

	if ctx.Height == 0 {
		var zero [32]byte
		if block.Header.PrevBlockHash != zero {
			return fmt.Errorf(BLOCK_ERR_LINKAGE_INVALID)
		}
	} else {
		parent := ctx.AncestorHeaders[len(ctx.AncestorHeaders)-1]
		if block.Header.PrevBlockHash != blockHeaderHash(p, &parent) {
			return fmt.Errorf(BLOCK_ERR_LINKAGE_INVALID)
		}
	}

	expectedTarget, err := blockExpectedTarget(ctx.AncestorHeaders, ctx.Height, block.Header.Target)
	if err != nil {
		return err
	}
	if !bytes.Equal(block.Header.Target[:], expectedTarget[:]) {
		return fmt.Errorf(BLOCK_ERR_TARGET_INVALID)
	}

	blockHash := blockHeaderHash(p, &block.Header)
	if bytes.Compare(blockHash[:], block.Header.Target[:]) >= 0 {
		return fmt.Errorf(BLOCK_ERR_POW_INVALID)
	}

	headerTxs := make([]*Tx, len(block.Transactions))
	for i := range block.Transactions {
		headerTxs[i] = &block.Transactions[i]
	}
	merkleRoot, err := merkleRootTxIDs(p, headerTxs)
	if err != nil {
		return fmt.Errorf(BLOCK_ERR_MERKLE_INVALID)
	}
	if merkleRoot != block.Header.MerkleRoot {
		return fmt.Errorf(BLOCK_ERR_MERKLE_INVALID)
	}

	if ctx.Height > 0 {
		medianTs, err := medianPastTimestamp(ctx.AncestorHeaders, ctx.Height)
		if err != nil {
			return err
		}
		if block.Header.Timestamp <= medianTs {
			return fmt.Errorf(BLOCK_ERR_TIMESTAMP_OLD)
		}
		if ctx.LocalTimeSet && block.Header.Timestamp > ctx.LocalTime+MAX_FUTURE_DRIFT {
			return fmt.Errorf(BLOCK_ERR_TIMESTAMP_FUTURE)
		}
	}

	coinbaseCount := 0
	for i := range block.Transactions {
		if isCoinbaseTx(&block.Transactions[i], ctx.Height) {
			coinbaseCount++
			if i != 0 {
				return fmt.Errorf(BLOCK_ERR_COINBASE_INVALID)
			}
		}
	}
	if coinbaseCount != 1 {
		return fmt.Errorf(BLOCK_ERR_COINBASE_INVALID)
	}

	workingUTXO := make(map[TxOutPoint]UtxoEntry, len(utxo))
	for point, entry := range utxo {
		workingUTXO[point] = entry
	}

	var totalWeight uint64
	var totalAnchorBytes uint64
	var totalFees uint64
	seenNonces := make(map[uint64]struct{}, len(block.Transactions))

	for _, tx := range block.Transactions {
		weight, err := TxWeight(&tx)
		if err != nil {
			return err
		}
		totalWeight, err = addUint64(totalWeight, weight)
		if err != nil {
			return err
		}

		isCoinbase := isCoinbaseTx(&tx, ctx.Height)
		if !isCoinbase {
			if tx.TxNonce == TX_NONCE_ZERO {
				return fmt.Errorf(TX_ERR_TX_NONCE_INVALID)
			}
			if _, exists := seenNonces[tx.TxNonce]; exists {
				return fmt.Errorf(TX_ERR_NONCE_REPLAY)
			}
			seenNonces[tx.TxNonce] = struct{}{}
		}

		// HTLC_V2 is VERSION_BITS deployment-gated; wire activation through ctx when deployments are implemented.
		if err := ApplyTx(p, chainID, &tx, workingUTXO, ctx.Height, block.Header.Timestamp, ctx.SuiteIDSLHActive, false); err != nil {
			return err
		}

		if !isCoinbase {
			inputSum, outputSum, err := txSums(&tx, workingUTXO)
			if err != nil {
				return err
			}
			fee, err := subUint64(inputSum, outputSum)
			if err != nil {
				return err
			}
			totalFees, err = addUint64(totalFees, fee)
			if err != nil {
				return err
			}
			for _, input := range tx.Inputs {
				delete(workingUTXO, TxOutPoint{TxID: input.PrevTxid, Vout: input.PrevVout})
			}
		}

		txID := TxID(p, &tx)
		for i, output := range tx.Outputs {
			if output.CovenantType == CORE_ANCHOR {
				totalAnchorBytes, err = addUint64(totalAnchorBytes, uint64(len(output.CovenantData)))
				if err != nil {
					return err
				}
				continue
			}
			workingUTXO[TxOutPoint{TxID: txID, Vout: uint32(i)}] = UtxoEntry{
				Output:            output,
				CreationHeight:    ctx.Height,
				CreatedByCoinbase: isCoinbase,
			}
		}
	}

	if totalWeight > MAX_BLOCK_WEIGHT {
		return fmt.Errorf(BLOCK_ERR_WEIGHT_EXCEEDED)
	}
	if totalAnchorBytes > MAX_ANCHOR_BYTES_PER_BLOCK {
		return fmt.Errorf(BLOCK_ERR_ANCHOR_BYTES_EXCEEDED)
	}

	var coinbaseValue uint64
	for _, output := range block.Transactions[0].Outputs {
		var err error
		coinbaseValue, err = addUint64(coinbaseValue, output.Value)
		if err != nil {
			return err
		}
	}
	maxCoinbase, err := addUint64(blockRewardForHeight(ctx.Height), totalFees)
	if err != nil {
		return err
	}
	if ctx.Height != 0 {
		if coinbaseValue > maxCoinbase {
			return fmt.Errorf(BLOCK_ERR_SUBSIDY_EXCEEDED)
		}
	}

	for prev := range utxo {
		delete(utxo, prev)
	}
	for point, entry := range workingUTXO {
		utxo[point] = entry
	}
	return nil
}

// ApplyTx validates a single transaction against consensus rules using the provided UTXO set and chain context.
// 
// It performs structural checks (limits on inputs/outputs and witness sizes), enforces coinbase-specific rules,
// validates covenant constraints for outputs, enforces nonces and witness/input count consistency for non-coinbase
// transactions, checks input sequence values and duplicate/zero prevouts, verifies input authorization against
// the referenced UTXOs, enforces coinbase maturity, and ensures input value is greater than or equal to output value.
// The function does not mutate the provided UTXO map.
//
// Returns an error if the transaction fails validation, nil otherwise.
func ApplyTx(
	p crypto.CryptoProvider,
	chainID [32]byte,
	tx *Tx,
	utxo map[TxOutPoint]UtxoEntry,
	chainHeight uint64,
	chainTimestamp uint64,
	suiteIDSLHActive bool,
	htlcV2Active bool,
) error {
	if tx == nil {
		return fmt.Errorf("TX_ERR_PARSE")
	}

	if len(tx.Inputs) > MAX_TX_INPUTS || len(tx.Outputs) > MAX_TX_OUTPUTS {
		return fmt.Errorf("TX_ERR_PARSE")
	}
	if len(tx.Witness.Witnesses) > MAX_WITNESS_ITEMS {
		return fmt.Errorf(TX_ERR_WITNESS_OVERFLOW)
	}
	if len(WitnessBytes(tx.Witness)) > MAX_WITNESS_BYTES_PER_TX {
		return fmt.Errorf(TX_ERR_WITNESS_OVERFLOW)
	}

	if isCoinbaseTx(tx, chainHeight) {
		if err := validateCoinbaseTxInputs(tx); err != nil {
			return err
		}
		for _, output := range tx.Outputs {
			if err := validateOutputCovenantConstraints(output); err != nil {
				return err
			}
		}
		return nil
	}

	if tx.TxNonce == TX_NONCE_ZERO {
		return fmt.Errorf(TX_ERR_TX_NONCE_INVALID)
	}
	if len(tx.Inputs) != len(tx.Witness.Witnesses) {
		return fmt.Errorf("TX_ERR_PARSE")
	}

	for _, output := range tx.Outputs {
		if err := validateOutputCovenantConstraints(output); err != nil {
			return err
		}
	}

	seen := make(map[TxOutPoint]struct{}, len(tx.Inputs))
	var totalInputs uint64
	var totalOutputs uint64

	for i, input := range tx.Inputs {
		if input.Sequence == TX_COINBASE_PREVOUT_VOUT || input.Sequence > TX_MAX_SEQUENCE {
			return fmt.Errorf(TX_ERR_SEQUENCE_INVALID)
		}

		prevout := TxOutPoint{
			TxID: input.PrevTxid,
			Vout: input.PrevVout,
		}
		if isZeroOutPoint(prevout) {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		if _, dup := seen[prevout]; dup {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		seen[prevout] = struct{}{}

		prevEntry, ok := utxo[prevout]
		if !ok {
			return fmt.Errorf("TX_ERR_MISSING_UTXO")
		}
		if err := ValidateInputAuthorization(
			p,
			chainID,
			tx,
			uint32(i),
			prevEntry.Output.Value,
			&prevEntry.Output,
			prevEntry.CreationHeight,
			chainHeight,
			chainTimestamp,
			suiteIDSLHActive,
			htlcV2Active,
		); err != nil {
			return err
		}
		if prevEntry.CreatedByCoinbase && chainHeight < prevEntry.CreationHeight+COINBASE_MATURITY {
			return fmt.Errorf(TX_ERR_COINBASE_IMMATURE)
		}

		var sumErr error
		totalInputs, sumErr = addUint64(totalInputs, prevEntry.Output.Value)
		if sumErr != nil {
			return sumErr
		}
	}

	for _, output := range tx.Outputs {
		var sumErr error
		totalOutputs, sumErr = addUint64(totalOutputs, output.Value)
		if sumErr != nil {
			return sumErr
		}
	}
	if totalOutputs > totalInputs {
		return fmt.Errorf("TX_ERR_VALUE_CONSERVATION")
	}
	return nil
}

// ValidateInputAuthorization validates that the transaction input at inputIndex is authorized to spend
// the provided previous output (prevout) according to the prevout's covenant, the corresponding witness,
// and the chain context (height, timestamp, chainID). It enforces covenant-specific constraints and lock
// semantics (P2PK, TIMELOCK_V1, HTLC_V1, VAULT_V1, HTLC_V2), checks witness format and key-id matching,
// validates timelocks and spend-delays, and verifies the input signature using the witness suite.
//
// The function returns nil on successful authorization. It returns an error (with domain-specific codes such
// as TX_ERR_PARSE, TX_ERR_SIG_INVALID, TX_ERR_TIMELOCK_NOT_MET, TX_ERR_DEPLOYMENT_INACTIVE,
// TX_ERR_MISSING_UTXO, TX_ERR_COVENANT_TYPE_INVALID, TX_ERR_SIG_ALG_INVALID) when validation fails.
func ValidateInputAuthorization(
	p crypto.CryptoProvider,
	chainID [32]byte,
	tx *Tx,
	inputIndex uint32,
	prevValue uint64,
	prevout *TxOutput,
	prevCreationHeight uint64,
	chainHeight uint64,
	chainTimestamp uint64,
	suiteIDSLHActive bool,
	htlcV2Active bool,
) error {
	if int(inputIndex) >= len(tx.Inputs) {
		return fmt.Errorf("TX_ERR_PARSE")
	}
	if int(inputIndex) >= len(tx.Witness.Witnesses) {
		return fmt.Errorf("TX_ERR_PARSE")
	}
	if prevout == nil {
		return fmt.Errorf("TX_ERR_PARSE")
	}

	inputIndexInt, err := u32ToInt(inputIndex, "input_index", len(tx.Inputs))
	if err != nil {
		return err
	}
	input := tx.Inputs[inputIndexInt]
	witness := tx.Witness.Witnesses[inputIndexInt]

	switch prevout.CovenantType {
	case CORE_P2PK:
		if err := isScriptSigZeroLen("CORE_P2PK", len(input.ScriptSig)); err != nil {
			return err
		}
		if witness.SuiteID == SUITE_ID_SENTINEL {
			return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
		}
		if err := checkWitnessFormat(witness, suiteIDSLHActive); err != nil {
			return err
		}

		if len(prevout.CovenantData) != 33 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		suiteID := prevout.CovenantData[0]
		if suiteID != witness.SuiteID {
			return fmt.Errorf("TX_ERR_SIG_INVALID")
		}
		actualKeyID := p.SHA3_256(witness.Pubkey)
		if expected := prevout.CovenantData[1:33]; !bytes.Equal(actualKeyID[:], expected) {
			return fmt.Errorf("TX_ERR_SIG_INVALID")
		}
	case CORE_TIMELOCK_V1:
		if err := isScriptSigZeroLen("CORE_TIMELOCK_V1", len(input.ScriptSig)); err != nil {
			return err
		}
		if witness.SuiteID != SUITE_ID_SENTINEL {
			return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
		}
		if len(prevout.CovenantData) != 9 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		lockMode := prevout.CovenantData[0]
		lockValue, err := parseU64LE(prevout.CovenantData, 1, "covenant_lock_value")
		if err != nil {
			return err
		}
		if err := satisfyLock(lockMode, lockValue, chainHeight, chainTimestamp); err != nil {
			return err
		}
	case CORE_HTLC_V1:
		if err := validateHTLCScriptSigLen(len(input.ScriptSig)); err != nil {
			return err
		}
		if witness.SuiteID == SUITE_ID_SENTINEL {
			return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
		}
		if err := checkWitnessFormat(witness, suiteIDSLHActive); err != nil {
			return err
		}
		if len(prevout.CovenantData) != 105 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		lockMode := prevout.CovenantData[32]
		lockValue, err := parseU64LE(prevout.CovenantData, 33, "htlc_lock_value")
		if err != nil {
			return err
		}
		// Enforce lock_mode domain even on claim path (refund path uses satisfyLock, but
		// claim path must also reject invalid lock_mode deterministically).
		if lockMode != TIMELOCK_MODE_HEIGHT && lockMode != TIMELOCK_MODE_TIMESTAMP {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		claimKeyID := prevout.CovenantData[41:73]
		refundKeyID := prevout.CovenantData[73:105]
		if bytes.Equal(claimKeyID, refundKeyID) {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		if len(input.ScriptSig) == 32 {
			expectedHash := prevout.CovenantData[:32]
			scriptHash := p.SHA3_256(input.ScriptSig)
			if !bytes.Equal(scriptHash[:], expectedHash) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
			actualKeyID := p.SHA3_256(witness.Pubkey)
			if !bytes.Equal(actualKeyID[:], claimKeyID) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
		} else {
			actualKeyID := p.SHA3_256(witness.Pubkey)
			if !bytes.Equal(actualKeyID[:], refundKeyID) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
			if err := satisfyLock(lockMode, lockValue, chainHeight, chainTimestamp); err != nil {
				return err
			}
		}
	case CORE_VAULT_V1:
		if err := isScriptSigZeroLen("CORE_VAULT_V1", len(input.ScriptSig)); err != nil {
			return err
		}
		if witness.SuiteID == SUITE_ID_SENTINEL {
			return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
		}
		if err := checkWitnessFormat(witness, suiteIDSLHActive); err != nil {
			return err
		}
		var ownerKeyID []byte
		var recoveryKeyID []byte
		var spendDelay uint64
		var lockMode byte
		var lockValue uint64
		switch len(prevout.CovenantData) {
		case 73:
			ownerKeyID = prevout.CovenantData[:32]
			spendDelay = 0
			lockMode = prevout.CovenantData[32]
			var err error
			lockValue, err = parseU64LE(prevout.CovenantData, 33, "vault_lock_value")
			if err != nil {
				return err
			}
			recoveryKeyID = prevout.CovenantData[41:73]
		case 81:
			ownerKeyID = prevout.CovenantData[:32]
			var err error
			spendDelay, err = parseU64LE(prevout.CovenantData, 32, "vault_spend_delay")
			if err != nil {
				return err
			}
			lockMode = prevout.CovenantData[40]
			lockValue, err = parseU64LE(prevout.CovenantData, 41, "vault_lock_value")
			if err != nil {
				return err
			}
			recoveryKeyID = prevout.CovenantData[49:81]
		default:
			return fmt.Errorf("TX_ERR_PARSE")
		}
		if lockMode != TIMELOCK_MODE_HEIGHT && lockMode != TIMELOCK_MODE_TIMESTAMP {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		if bytes.Equal(ownerKeyID, recoveryKeyID) {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		actualKeyID := p.SHA3_256(witness.Pubkey)
		if !bytes.Equal(actualKeyID[:], ownerKeyID) && !bytes.Equal(actualKeyID[:], recoveryKeyID) {
			return fmt.Errorf("TX_ERR_SIG_INVALID")
		}
		if bytes.Equal(actualKeyID[:], ownerKeyID) && spendDelay > 0 {
			if chainHeight < prevCreationHeight+spendDelay {
				return fmt.Errorf("TX_ERR_TIMELOCK_NOT_MET")
			}
		}
		if bytes.Equal(actualKeyID[:], recoveryKeyID) {
			if err := satisfyLock(lockMode, lockValue, chainHeight, chainTimestamp); err != nil {
				return err
			}
		}
	case CORE_HTLC_V2:
		// Deployment gate
		if !htlcV2Active {
			return fmt.Errorf("TX_ERR_DEPLOYMENT_INACTIVE")
		}
		if len(input.ScriptSig) != 0 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		if witness.SuiteID == SUITE_ID_SENTINEL {
			return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
		}
		if err := checkWitnessFormat(witness, suiteIDSLHActive); err != nil {
			return err
		}
		if len(prevout.CovenantData) != 105 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		claimKeyID2 := prevout.CovenantData[41:73]
		refundKeyID2 := prevout.CovenantData[73:105]
		if bytes.Equal(claimKeyID2, refundKeyID2) {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		hash2 := prevout.CovenantData[:32]
		lockMode2 := prevout.CovenantData[32]
		lockValue2, err := parseU64LE(prevout.CovenantData, 33, "htlc2_lock_value")
		if err != nil {
			return err
		}
		// Scan ANCHOR outputs for matching HTLC_V2 envelope
		// prefix = ASCII("RUBINv1-htlc-preimage/") — 22 bytes, total envelope = 54 bytes
		const htlcV2Prefix = "RUBINv1-htlc-preimage/"
		const htlcV2EnvelopeLen = 54
		var matchingAnchors [][]byte
		for _, out := range tx.Outputs {
			if out.CovenantType == CORE_ANCHOR &&
				len(out.CovenantData) == htlcV2EnvelopeLen &&
				string(out.CovenantData[:len(htlcV2Prefix)]) == htlcV2Prefix {
				matchingAnchors = append(matchingAnchors, out.CovenantData)
			}
		}
		switch len(matchingAnchors) {
		case 0:
			// Refund path
			actualKeyID2 := p.SHA3_256(witness.Pubkey)
			if !bytes.Equal(actualKeyID2[:], refundKeyID2) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
			if err := satisfyLock(lockMode2, lockValue2, chainHeight, chainTimestamp); err != nil {
				return err
			}
		case 1:
			// Claim path
			preimage32 := matchingAnchors[0][len(htlcV2Prefix):]
			preimageHash := p.SHA3_256(preimage32)
			if !bytes.Equal(preimageHash[:], hash2) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
			actualKeyID2 := p.SHA3_256(witness.Pubkey)
			if !bytes.Equal(actualKeyID2[:], claimKeyID2) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
		default:
			// Two or more matching envelopes — non-deterministic, reject
			return fmt.Errorf("TX_ERR_PARSE")
		}
	case CORE_ANCHOR:
		return fmt.Errorf("TX_ERR_MISSING_UTXO")
	case CORE_RESERVED_FUTURE:
		return fmt.Errorf("TX_ERR_COVENANT_TYPE_INVALID")
	default:
		return fmt.Errorf("TX_ERR_COVENANT_TYPE_INVALID")
	}

	digest, err := SighashV1Digest(p, chainID, tx, inputIndex, prevValue)
	if err != nil {
		return err
	}

	switch witness.SuiteID {
	case SUITE_ID_ML_DSA:
		if p.VerifyMLDSA87(witness.Pubkey, witness.Signature, digest) {
			return nil
		}
		return fmt.Errorf("TX_ERR_SIG_INVALID")
	case SUITE_ID_SLH_DSA:
		if p.VerifySLHDSASHAKE_256f(witness.Pubkey, witness.Signature, digest) {
			return nil
		}
		return fmt.Errorf("TX_ERR_SIG_INVALID")
	case SUITE_ID_SENTINEL:
		// Timelock-only covenants are already validated above.
		return nil
	default:
		return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
	}
}