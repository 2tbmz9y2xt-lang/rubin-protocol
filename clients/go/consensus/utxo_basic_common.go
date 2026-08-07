package consensus

type Outpoint struct {
	Txid [32]byte
	Vout uint32
}

type UtxoEntry struct {
	CovenantData      []byte
	Value             uint64
	CreationHeight    uint64
	CovenantType      uint16
	CreatedByCoinbase bool
}

// UtxoApplySummary carries the public result of a non-coinbase apply.
//
// Fee is the exact u128 value sum_in-sum_out. Per-output and per-UTXO values
// remain u64, but a transaction may legitimately spend up to MAX_TX_INPUTS
// u64-max inputs, so the fee itself is not bounded by u64 and is never
// narrowed, rounded, or saturated on the way out of this struct.
type UtxoApplySummary struct {
	Fee       Uint128
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
	_ uint64,
	blockMTP uint64,
	chainID [32]byte,
) (map[Outpoint]UtxoEntry, *UtxoApplySummary, error) {
	return ApplyNonCoinbaseTxBasicUpdateWithMTPAndSuiteContext(
		tx,
		txid,
		utxoSet,
		height,
		blockMTP,
		chainID,
		nil, /*rotation*/
		nil, /*registry*/
	)
}

// ApplyNonCoinbaseTxBasicUpdateWithMTPAndSuiteContext is the
// suite-aware variant for deterministic tooling that needs explicit native-suite
// rotation/registry context.
func ApplyNonCoinbaseTxBasicUpdateWithMTPAndSuiteContext(
	tx *Tx,
	txid [32]byte,
	utxoSet map[Outpoint]UtxoEntry,
	height uint64,
	blockMTP uint64,
	chainID [32]byte,
	rotation RotationProvider,
	registry *SuiteRegistry,
) (map[Outpoint]UtxoEntry, *UtxoApplySummary, error) {
	work := cloneUtxoSet(utxoSet)
	work, fee, err := applyNonCoinbaseTxBasicWork(nonCoinbaseApplyWorkInput{
		tx:       tx,
		txid:     txid,
		utxoSet:  work,
		height:   height,
		blockMTP: blockMTP,
		chainID:  chainID,
		rotation: rotation,
		registry: registry,
	})
	if err != nil {
		return nil, nil, err
	}
	return work, &UtxoApplySummary{
		Fee:       fee,
		UtxoCount: uint64(len(work)),
	}, nil
}

func cloneUtxoEntry(entry UtxoEntry) UtxoEntry {
	return UtxoEntry{
		Value:             entry.Value,
		CovenantType:      entry.CovenantType,
		CovenantData:      append([]byte(nil), entry.CovenantData...),
		CreationHeight:    entry.CreationHeight,
		CreatedByCoinbase: entry.CreatedByCoinbase,
	}
}

func checkSpendCovenant(
	covType uint16,
	covData []byte,
) error {
	switch covType {
	case COV_TYPE_P2PK:
		return nil
	case COV_TYPE_VAULT:
		_, err := ParseVaultCovenantDataForSpend(covData)
		return err
	case COV_TYPE_MULTISIG:
		_, err := ParseMultisigCovenantData(covData)
		return err
	case COV_TYPE_HTLC:
		_, err := ParseHTLCCovenantData(covData)
		return err
	case COV_TYPE_CORE_STEALTH:
		_, err := ParseStealthCovenantData(covData)
		return err
	case COV_TYPE_CORE_SIMPLICITY:
		// Resolve-phase accept (like P2PK): the full §14.3 covenant-data + spend validation runs at
		// spend time (validateCoreSimplicitySpend -> parseCoreSimplicityCovenantData with value).
		return nil
	default:
		// Reserved/unknown are unsupported in basic apply path.
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "unsupported covenant in basic apply")
	}
}

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

type u128 struct {
	hi uint64
	lo uint64
}

func addU64ToU128(x u128, v uint64) (u128, error) {
	return addU64ToU128WithCode(x, v, TX_ERR_PARSE)
}

// u128ToU64 is a bounded conversion helper for u64-domain quantities only.
// It MUST NOT be applied to a transaction fee or a block sum_fees: those are
// exact u128 values whose protocol-valid range exceeds u64, and narrowing one
// here would reject a valid transaction on width alone.
func u128ToU64(x u128) (uint64, error) {
	if x.hi != 0 {
		return 0, txerr(TX_ERR_PARSE, "u64 overflow")
	}
	return x.lo, nil
}

type nonCoinbaseApplyContext struct {
	tx            *Tx
	txid          [32]byte
	work          map[Outpoint]UtxoEntry
	chainID       [32]byte
	rotation      RotationProvider
	registry      *SuiteRegistry
	sighashCache  *SighashV1PrehashCache
	sigCache      *SigCache
	resolved      []nonCoinbaseResolvedInput
	simplicityCtx *SimplicityTxContext
	spend         nonCoinbaseSpendState
	sumOut        u128
	height        uint64
	blockMTP      uint64
	createsVault  bool
}
