package consensus

import "math/bits"

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
	return ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(
		tx,
		txid,
		utxoSet,
		height,
		blockTimestamp,
		blockMTP,
		chainID,
		nil,
	)
}

// ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles is a helper for deterministic tooling
// (conformance/CLI) that need to inject CORE_EXT deployment profiles (CANONICAL §23.2.2).
//
// Consensus validity depends on the resolved profile(ext_id, height). Nodes MUST ensure they use
// the canonical chain-config source for this mapping.
func ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(
	tx *Tx,
	txid [32]byte,
	utxoSet map[Outpoint]UtxoEntry,
	height uint64,
	_ uint64,
	blockMTP uint64,
	chainID [32]byte,
	coreExtProfiles CoreExtProfileProvider,
) (map[Outpoint]UtxoEntry, *UtxoApplySummary, error) {
	if coreExtProfiles == nil {
		coreExtProfiles = EmptyCoreExtProfileProvider()
	}
	return ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesAndSuiteContext(
		tx,
		txid,
		utxoSet,
		height,
		0,
		blockMTP,
		chainID,
		coreExtProfiles,
		nil,
		nil,
	)
}

// ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesAndSuiteContext is the
// suite-aware variant for deterministic tooling that needs CORE_EXT profiles plus
// explicit native-suite rotation/registry context for ACTIVE-profile spend checks.
func ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesAndSuiteContext(
	tx *Tx,
	txid [32]byte,
	utxoSet map[Outpoint]UtxoEntry,
	height uint64,
	_ uint64,
	blockMTP uint64,
	chainID [32]byte,
	coreExtProfiles CoreExtProfileProvider,
	rotation RotationProvider,
	registry *SuiteRegistry,
) (map[Outpoint]UtxoEntry, *UtxoApplySummary, error) {
	if coreExtProfiles == nil {
		coreExtProfiles = EmptyCoreExtProfileProvider()
	}
	work := cloneUtxoSet(utxoSet)
	work, fee, err := applyNonCoinbaseTxBasicWork(tx, txid, work, height, blockMTP, chainID, coreExtProfiles, rotation, registry)
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
	coreExtProfiles CoreExtProfileProvider,
	rotation RotationProvider,
	registry *SuiteRegistry,
) (map[Outpoint]UtxoEntry, uint64, error) {
	return (&nonCoinbaseApplyContext{
		tx:              tx,
		txid:            txid,
		work:            utxoSet,
		height:          height,
		blockMTP:        blockMTP,
		chainID:         chainID,
		coreExtProfiles: nonCoinbaseCoreExtProfilesOrEmpty(coreExtProfiles),
		rotation:        rotation,
		registry:        registry,
	}).apply()
}

func (ctx *nonCoinbaseApplyContext) apply() (map[Outpoint]UtxoEntry, uint64, error) {
	if err := ctx.applyPreOutputPhases(); err != nil {
		return nil, 0, err
	}
	if err := ctx.addSpendableOutputs(); err != nil {
		return nil, 0, err
	}
	if err := ctx.applyPostOutputRules(); err != nil {
		return nil, 0, err
	}
	fee, err := ctx.finalizeValueAndFee()
	if err != nil {
		return nil, 0, err
	}
	return ctx.work, fee, nil
}

func (ctx *nonCoinbaseApplyContext) applyPreOutputPhases() error {
	if err := ctx.prepare(); err != nil {
		return err
	}
	if err := ctx.resolveInputs(); err != nil {
		return err
	}
	if err := ctx.buildTxContext(); err != nil {
		return err
	}
	return ctx.validateInputSpends()
}

func (ctx *nonCoinbaseApplyContext) applyPostOutputRules() error {
	if ctx.createsVault {
		if err := ctx.validateVaultCreations(); err != nil {
			return err
		}
	}
	if ctx.spend.vaultInputCount == 1 {
		if err := ctx.validateVaultSpend(); err != nil {
			return err
		}
	}
	return nil
}

func cloneUtxoSet(src map[Outpoint]UtxoEntry) map[Outpoint]UtxoEntry {
	out := make(map[Outpoint]UtxoEntry, len(src))
	for k, v := range src {
		out[k] = cloneUtxoEntry(v)
	}
	return out
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
	case COV_TYPE_CORE_EXT:
		_, err := ParseCoreExtCovenantData(covData)
		return err
	case COV_TYPE_CORE_STEALTH:
		_, err := ParseStealthCovenantData(covData)
		return err
	default:
		// Reserved/unknown are unsupported in basic apply path.
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "unsupported covenant in basic apply")
	}
}

type u128 struct {
	hi uint64
	lo uint64
}

func addU64ToU128(x u128, v uint64) (u128, error) {
	return addU64ToU128WithCode(x, v, TX_ERR_PARSE)
}

func addU64ToU128WithCode(x u128, v uint64, code ErrorCode) (u128, error) {
	lo, carry := bits.Add64(x.lo, v, 0)
	hi, carry2 := bits.Add64(x.hi, 0, carry)
	if carry2 != 0 {
		return u128{}, txerr(code, "u128 overflow")
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
